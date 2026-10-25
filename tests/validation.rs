//! Tests for consensus block validation and atomic chain acceptance.
//!
//! Every expectation here is derived from `docs/protocol-v1.md`; the tests
//! check the observable behaviour of a candidate block against the
//! specification rather than re-implementing the validation code.

use std::sync::OnceLock;

use orchard::builder::{Builder, BundleType, InProgress, Unauthorized};
use orchard::bundle::{BundleVersion, Flags};
use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{Bundle, Proof};
use rand::SeedableRng;

use ownchain::block::{Block, MAX_BLOCK_SIZE, MAX_TRANSACTION_SIZE};
use ownchain::chain::{ChainError, ChainState};
use ownchain::genesis;
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::orchard_root::empty_commitment_root;
use ownchain::orchard_tx::{
    compute_action_effect_from_action, compute_tx_auth_digest, serialize_bundle, BundleCodecError,
    OrchardValidationError,
};
use ownchain::tx::{TX_TYPE_COINBASE, TX_TYPE_ORCHARD_TRANSFER, TX_VERSION};
use ownchain::validation::{upper_median, validate_block, ValidationContext, ValidationError};

/// The 32 empty tree roots at depth 32 from ZIP 224 / orchard test vectors.
const EMPTY_ROOTS: [[u8; 32]; 32] = [
    [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xd1, 0xab, 0x25, 0x07, 0xc8, 0x09, 0xc2, 0x71, 0x3c, 0x00, 0x0f, 0x52, 0x5e, 0x9f, 0xbd,
        0xcb, 0x06, 0xc9, 0x58, 0x38, 0x4e, 0x51, 0xb9, 0xcc, 0x7f, 0x79, 0x2d, 0xde, 0x6c, 0x97,
        0xf4, 0x11,
    ],
    [
        0xc7, 0x41, 0x3f, 0x46, 0x14, 0xcd, 0x64, 0x04, 0x3a, 0xbb, 0xab, 0x7c, 0xc1, 0x09, 0x5c,
        0x9b, 0xb1, 0x04, 0x23, 0x1c, 0xea, 0x89, 0xe2, 0xc3, 0xe0, 0xdf, 0x83, 0x76, 0x95, 0x56,
        0xd0, 0x30,
    ],
    [
        0x21, 0x11, 0xfc, 0x39, 0x77, 0x53, 0xe5, 0xfd, 0x50, 0xec, 0x74, 0x81, 0x6d, 0xf2, 0x7d,
        0x6a, 0xda, 0x7e, 0xd2, 0xa9, 0xac, 0x38, 0x16, 0xaa, 0xb2, 0x57, 0x3c, 0x8f, 0xac, 0x79,
        0x42, 0x04,
    ],
    [
        0x80, 0x6a, 0xfb, 0xfe, 0xb4, 0x5c, 0x64, 0xd4, 0xf2, 0x38, 0x4c, 0x51, 0xef, 0xf3, 0x07,
        0x64, 0xb8, 0x45, 0x99, 0xae, 0x56, 0xa7, 0xab, 0x3d, 0x4a, 0x46, 0xd9, 0xce, 0x3a, 0xea,
        0xb4, 0x31,
    ],
    [
        0x87, 0x3e, 0x41, 0x57, 0xf2, 0xc0, 0xf0, 0xc6, 0x45, 0xe8, 0x99, 0x36, 0x00, 0x69, 0xfc,
        0xc9, 0xd2, 0xed, 0x9b, 0xc1, 0x1b, 0xf5, 0x98, 0x27, 0xaf, 0x02, 0x30, 0xed, 0x52, 0xed,
        0xab, 0x18,
    ],
    [
        0x27, 0xab, 0x13, 0x20, 0x95, 0x3a, 0xe1, 0xad, 0x70, 0xc8, 0xc1, 0x5a, 0x12, 0x53, 0xa0,
        0xa8, 0x6f, 0xbc, 0x8a, 0x0a, 0xa3, 0x6a, 0x84, 0x20, 0x72, 0x93, 0xf8, 0xa4, 0x95, 0xff,
        0xc4, 0x02,
    ],
    [
        0x4e, 0x14, 0x56, 0x3d, 0xf1, 0x91, 0xa2, 0xa6, 0x5b, 0x4b, 0x37, 0x11, 0x3b, 0x52, 0x30,
        0x68, 0x05, 0x55, 0x05, 0x1b, 0x22, 0xd7, 0x4a, 0x8e, 0x1f, 0x1d, 0x70, 0x6f, 0x90, 0xf3,
        0x13, 0x3b,
    ],
    [
        0xb3, 0xbb, 0xe4, 0xf9, 0x93, 0xd1, 0x8a, 0x0f, 0x4e, 0xb7, 0xf4, 0x17, 0x4b, 0x1d, 0x85,
        0x55, 0xce, 0x33, 0x96, 0x85, 0x5d, 0x04, 0x67, 0x6f, 0x1c, 0xe4, 0xf0, 0x6d, 0xda, 0x07,
        0x37, 0x1f,
    ],
    [
        0x4e, 0xf5, 0xbd, 0xe9, 0xc6, 0xf0, 0xd7, 0x6a, 0xeb, 0x9e, 0x27, 0xe9, 0x3f, 0xba, 0x28,
        0xc6, 0x79, 0xdf, 0xcb, 0x99, 0x1c, 0xbc, 0xb8, 0x39, 0x5a, 0x2b, 0x57, 0x92, 0x4c, 0xbd,
        0x17, 0x0e,
    ],
    [
        0xa3, 0xc0, 0x25, 0x68, 0xac, 0xeb, 0xf5, 0xca, 0x1e, 0xc3, 0x0d, 0x6a, 0x7d, 0x7c, 0xd2,
        0x17, 0xa4, 0x7d, 0x6a, 0x1b, 0x83, 0x11, 0xbf, 0x94, 0x62, 0xa5, 0xf9, 0x39, 0xc6, 0xb7,
        0x43, 0x07,
    ],
    [
        0x3e, 0xf9, 0xb3, 0x0b, 0xae, 0x61, 0x22, 0xda, 0x16, 0x05, 0xba, 0xd6, 0xec, 0x5d, 0x49,
        0xb4, 0x1d, 0x4d, 0x40, 0xca, 0xa9, 0x6c, 0x1c, 0xf6, 0x30, 0x2b, 0x66, 0xc5, 0xd2, 0xd1,
        0x0d, 0x39,
    ],
    [
        0x22, 0xae, 0x28, 0x00, 0xcb, 0x93, 0xab, 0xe6, 0x3b, 0x70, 0xc1, 0x72, 0xde, 0x70, 0x36,
        0x2d, 0x98, 0x30, 0xe5, 0x38, 0x00, 0x39, 0x88, 0x84, 0xa7, 0xa6, 0x4f, 0xf6, 0x8e, 0xd9,
        0x9e, 0x0b,
    ],
    [
        0x18, 0x71, 0x10, 0xd9, 0x26, 0x72, 0xc2, 0x4c, 0xed, 0xb0, 0x97, 0x9c, 0xdf, 0xc9, 0x17,
        0xa6, 0x05, 0x3b, 0x31, 0x0d, 0x14, 0x5c, 0x03, 0x1c, 0x72, 0x92, 0xbb, 0x1d, 0x65, 0xb7,
        0x66, 0x1b,
    ],
    [
        0x3f, 0x98, 0xad, 0xbe, 0x36, 0x4f, 0x14, 0x8b, 0x0c, 0xc2, 0x04, 0x2c, 0xaf, 0xc6, 0xbe,
        0x11, 0x66, 0xfa, 0xe3, 0x90, 0x90, 0xab, 0x4b, 0x35, 0x4b, 0xfb, 0x62, 0x17, 0xb9, 0x64,
        0x45, 0x3b,
    ],
    [
        0x63, 0xf8, 0xdb, 0xd1, 0x0d, 0xf9, 0x36, 0xf1, 0x73, 0x49, 0x73, 0xe0, 0xb3, 0xbd, 0x25,
        0xf4, 0xed, 0x44, 0x05, 0x66, 0xc9, 0x23, 0x08, 0x59, 0x03, 0xf6, 0x96, 0xbc, 0x63, 0x47,
        0xec, 0x0f,
    ],
    [
        0x21, 0x82, 0x16, 0x3e, 0xac, 0x40, 0x61, 0x88, 0x5a, 0x31, 0x35, 0x68, 0x14, 0x8d, 0xfa,
        0xe5, 0x64, 0xe4, 0x78, 0x06, 0x6d, 0xcb, 0xe3, 0x89, 0xa0, 0xdd, 0xb1, 0xec, 0xb7, 0xf5,
        0xdc, 0x34,
    ],
    [
        0xbd, 0x9d, 0xc0, 0x68, 0x19, 0x18, 0xa3, 0xf3, 0xf9, 0xcd, 0x1f, 0x9e, 0x06, 0xaa, 0x1a,
        0xd6, 0x89, 0x27, 0xda, 0x63, 0xac, 0xc1, 0x3b, 0x92, 0xa2, 0x57, 0x8b, 0x27, 0x38, 0xa6,
        0xd3, 0x31,
    ],
    [
        0xca, 0x2c, 0xed, 0x95, 0x3b, 0x7f, 0xb9, 0x5e, 0x3b, 0xa9, 0x86, 0x33, 0x3d, 0xa9, 0xe6,
        0x9c, 0xd3, 0x55, 0x22, 0x3c, 0x92, 0x97, 0x31, 0x09, 0x4b, 0x6c, 0x21, 0x74, 0xc7, 0x63,
        0x8d, 0x2e,
    ],
    [
        0x55, 0x35, 0x4b, 0x96, 0xb5, 0x6f, 0x9e, 0x45, 0xaa, 0xe1, 0xe0, 0x09, 0x4d, 0x71, 0xee,
        0x24, 0x8d, 0xab, 0xf6, 0x68, 0x11, 0x77, 0x78, 0xbd, 0xc3, 0xc1, 0x9c, 0xa5, 0x33, 0x1a,
        0x4e, 0x1a,
    ],
    [
        0x70, 0x97, 0xb0, 0x4c, 0x2a, 0xa0, 0x45, 0xa0, 0xde, 0xff, 0xca, 0xca, 0x41, 0xc5, 0xac,
        0x92, 0xe6, 0x94, 0x46, 0x65, 0x78, 0xf5, 0x90, 0x9e, 0x72, 0xbb, 0x78, 0xd3, 0x33, 0x10,
        0xf7, 0x05,
    ],
    [
        0xe8, 0x1d, 0x68, 0x21, 0xff, 0x81, 0x3b, 0xd4, 0x10, 0x86, 0x7a, 0x3f, 0x22, 0xe8, 0xe5,
        0xcb, 0x7a, 0xc5, 0x59, 0x9a, 0x61, 0x0a, 0xf5, 0xc3, 0x54, 0xeb, 0x39, 0x28, 0x77, 0x36,
        0x2e, 0x01,
    ],
    [
        0x15, 0x7d, 0xe8, 0x56, 0x7f, 0x7c, 0x49, 0x96, 0xb8, 0xc4, 0xfd, 0xc9, 0x49, 0x38, 0xfd,
        0x80, 0x8c, 0x3b, 0x2a, 0x5c, 0xcb, 0x79, 0xd1, 0xa6, 0x38, 0x58, 0xad, 0xaa, 0x9a, 0x6d,
        0xd8, 0x24,
    ],
    [
        0xfe, 0x1f, 0xce, 0x51, 0xcd, 0x61, 0x20, 0xc1, 0x2c, 0x12, 0x46, 0x95, 0xc4, 0xf9, 0x8b,
        0x27, 0x59, 0x18, 0xfc, 0xea, 0xe6, 0xeb, 0x20, 0x98, 0x73, 0xed, 0x73, 0xfe, 0x73, 0x77,
        0x5d, 0x0b,
    ],
    [
        0x1f, 0x91, 0x98, 0x29, 0x12, 0x01, 0x26, 0x69, 0xf7, 0x4d, 0x0c, 0xfa, 0x10, 0x30, 0xff,
        0x37, 0xb1, 0x52, 0x32, 0x4e, 0x5b, 0x83, 0x46, 0xb3, 0x33, 0x5a, 0x0a, 0xae, 0xb6, 0x3a,
        0x0a, 0x2d,
    ],
    [
        0x5d, 0xec, 0x15, 0xf5, 0x2a, 0xf1, 0x7d, 0xa3, 0x93, 0x13, 0x96, 0x18, 0x3c, 0xbb, 0xbf,
        0xbe, 0xa7, 0xed, 0x95, 0x07, 0x14, 0x54, 0x0a, 0xec, 0x06, 0xc6, 0x45, 0xc7, 0x54, 0x97,
        0x55, 0x22,
    ],
    [
        0xe8, 0xae, 0x2a, 0xd9, 0x1d, 0x46, 0x3b, 0xab, 0x75, 0xee, 0x94, 0x1d, 0x33, 0xcc, 0x58,
        0x17, 0xb6, 0x13, 0xc6, 0x3c, 0xda, 0x94, 0x3a, 0x4c, 0x07, 0xf6, 0x00, 0x59, 0x1b, 0x08,
        0x8a, 0x25,
    ],
    [
        0xd5, 0x3f, 0xde, 0xe3, 0x71, 0xce, 0xf5, 0x96, 0x76, 0x68, 0x23, 0xf4, 0xa5, 0x18, 0xa5,
        0x83, 0xb1, 0x15, 0x82, 0x43, 0xaf, 0xe8, 0x97, 0x00, 0xf0, 0xda, 0x76, 0xda, 0x46, 0xd0,
        0x06, 0x0f,
    ],
    [
        0x15, 0xd2, 0x44, 0x4c, 0xef, 0xe7, 0x91, 0x4c, 0x9a, 0x61, 0xe8, 0x29, 0xc7, 0x30, 0xec,
        0xeb, 0x21, 0x62, 0x88, 0xfe, 0xe8, 0x25, 0xf6, 0xb3, 0xb6, 0x29, 0x8f, 0x6f, 0x6b, 0x6b,
        0xd6, 0x2e,
    ],
    [
        0x4c, 0x57, 0xa6, 0x17, 0xa0, 0xaa, 0x10, 0xea, 0x7a, 0x83, 0xaa, 0x6b, 0x6b, 0x0e, 0xd6,
        0x85, 0xb6, 0xa3, 0xd9, 0xe5, 0xb8, 0xfd, 0x14, 0xf5, 0x6c, 0xdc, 0x18, 0x02, 0x1b, 0x12,
        0x25, 0x3f,
    ],
    [
        0x3f, 0xd4, 0x91, 0x5c, 0x19, 0xbd, 0x83, 0x1a, 0x79, 0x20, 0xbe, 0x55, 0xd9, 0x69, 0xb2,
        0xac, 0x23, 0x35, 0x9e, 0x25, 0x59, 0xda, 0x77, 0xde, 0x23, 0x73, 0xf0, 0x6c, 0xa0, 0x14,
        0xba, 0x27,
    ],
    [
        0x87, 0xd0, 0x63, 0xcd, 0x07, 0xee, 0x49, 0x44, 0x22, 0x2b, 0x77, 0x62, 0x84, 0x0e, 0xb9,
        0x4c, 0x68, 0x8b, 0xec, 0x74, 0x3f, 0xa8, 0xbd, 0xf7, 0x71, 0x5c, 0x8f, 0xe2, 0x9f, 0x10,
        0x4c, 0x2a,
    ],
];

/// Constructs a Merkle witness for position 0 in an otherwise empty tree.
fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

struct TestFixtures {
    miner_sk: SpendingKey,
    cb_proven: Bundle<InProgress<Proof, Unauthorized>, i64>,
    cb_action_effect: [u8; 32],
    tx_proven_7028: Bundle<InProgress<Proof, Unauthorized>, i64>,
    tx_action_effect_7028: [u8; 32],
    tx_proven_5000: Bundle<InProgress<Proof, Unauthorized>, i64>,
    tx_action_effect_5000: [u8; 32],
}

static FIXTURES: OnceLock<TestFixtures> = OnceLock::new();

fn get_fixtures() -> &'static TestFixtures {
    FIXTURES.get_or_init(|| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);

        let miner_sk = SpendingKey::from_bytes([1u8; 32]).unwrap();
        let miner_fvk = FullViewingKey::from(&miner_sk);
        let miner_address = miner_fvk.address_at(0u32, Scope::External);

        let user_sk = SpendingKey::from_bytes([2u8; 32]).unwrap();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);

        // 1. Output-only coinbase bundle (10 OWN payout)
        let zero_ovk = OutgoingViewingKey::from([0u8; 32]);
        let payout_atoms = 1_000_000_000u64;
        let mut cb_builder = Builder::new(
            BundleType::Coinbase,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .unwrap();

        cb_builder
            .add_output(
                Some(zero_ovk.clone()),
                miner_address,
                NoteValue::from_raw(payout_atoms),
                [0u8; 512],
            )
            .unwrap();

        let (cb_unauth, cb_meta) = cb_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let cb_note = cb_unauth
            .recover_output_with_ovk(cb_meta.output_action_index(0).unwrap(), &zero_ovk)
            .unwrap()
            .0;
        let cb_action_effect = compute_action_effect_from_action(&cb_unauth.actions()[0]);
        let cb_proven = cb_unauth.create_proof(&pk, &mut rng).unwrap();

        // 2. Transfer bundle with exact consensus fee 7,028
        let cmx: ExtractedNoteCommitment = cb_note.commitment().into();
        let (anchor, merkle_path) = single_leaf_witness(&cmx);

        let fee_7028 = 7_028u64;
        let transfer_value_7028 = payout_atoms - fee_7028;
        let mut tx_builder_7028 = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v2().default_flags(),
            anchor,
        )
        .unwrap();

        tx_builder_7028
            .add_spend(miner_fvk.clone(), cb_note, merkle_path.clone())
            .unwrap();
        tx_builder_7028
            .add_output(
                None,
                user_address,
                NoteValue::from_raw(transfer_value_7028),
                [0u8; 512],
            )
            .unwrap();

        let (tx_unauth_7028, _) = tx_builder_7028.build::<i64>(&mut rng).unwrap().unwrap();
        let tx_action_effect_7028 = compute_action_effect_from_action(&tx_unauth_7028.actions()[0]);
        let tx_proven_7028 = tx_unauth_7028.create_proof(&pk, &mut rng).unwrap();

        // 3. Transfer bundle with fee 5,000 (for testing consensus fee formula mismatch)
        let fee_5000 = 5_000u64;
        let transfer_value_5000 = payout_atoms - fee_5000;
        let mut tx_builder_5000 = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v2().default_flags(),
            anchor,
        )
        .unwrap();

        tx_builder_5000
            .add_spend(miner_fvk, cb_note, merkle_path)
            .unwrap();
        tx_builder_5000
            .add_output(
                None,
                user_address,
                NoteValue::from_raw(transfer_value_5000),
                [0u8; 512],
            )
            .unwrap();

        let (tx_unauth_5000, _) = tx_builder_5000.build::<i64>(&mut rng).unwrap().unwrap();
        let tx_action_effect_5000 = compute_action_effect_from_action(&tx_unauth_5000.actions()[0]);
        let tx_proven_5000 = tx_unauth_5000.create_proof(&pk, &mut rng).unwrap();

        TestFixtures {
            miner_sk,
            cb_proven,
            cb_action_effect,
            tx_proven_7028,
            tx_action_effect_7028,
            tx_proven_5000,
            tx_action_effect_5000,
        }
    })
}

/// Constructs a 100% genuine, cryptographically valid Orchard V2 coinbase transaction for the given height.
fn genuine_coinbase(chain_id: Hash, height: u64) -> Vec<u8> {
    let f = get_fixtures();
    let sighash = compute_tx_auth_digest(
        *chain_id.as_bytes(),
        0, // Coinbase
        1, // tx_version
        height,
        f.cb_proven.flag_byte(),
        *f.cb_proven.value_balance(),
        f.cb_proven.anchor().to_bytes(),
        &[f.cb_action_effect],
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(height);
    let bundle = f
        .cb_proven
        .clone()
        .apply_signatures(&mut rng, sighash, &[])
        .unwrap();
    let serialized_bundle = serialize_bundle(&bundle);

    let mut raw_tx =
        Vec::with_capacity(ownchain::tx::TX_ENVELOPE_LEN + 8 + serialized_bundle.len());
    raw_tx.push(TX_TYPE_COINBASE);
    raw_tx.extend_from_slice(&TX_VERSION.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());
    raw_tx.extend_from_slice(&height.to_le_bytes());
    raw_tx.extend_from_slice(&serialized_bundle);
    raw_tx
}

/// Constructs a genuine, cryptographically valid Orchard V2 transfer transaction with exact consensus fee 7,028.
fn genuine_transfer(chain_id: Hash) -> Vec<u8> {
    let f = get_fixtures();
    let fee_atoms = 7_028u64;
    let sighash = compute_tx_auth_digest(
        *chain_id.as_bytes(),
        1, // OrchardTransfer
        1, // tx_version
        fee_atoms,
        f.tx_proven_7028.flag_byte(),
        *f.tx_proven_7028.value_balance(),
        f.tx_proven_7028.anchor().to_bytes(),
        &[f.tx_action_effect_7028],
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let bundle = f
        .tx_proven_7028
        .clone()
        .apply_signatures(&mut rng, sighash, &[SpendAuthorizingKey::from(&f.miner_sk)])
        .unwrap();
    let serialized_bundle = serialize_bundle(&bundle);

    let mut raw_tx =
        Vec::with_capacity(ownchain::tx::TX_ENVELOPE_LEN + 8 + serialized_bundle.len());
    raw_tx.push(TX_TYPE_ORCHARD_TRANSFER);
    raw_tx.extend_from_slice(&TX_VERSION.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&serialized_bundle);
    raw_tx
}

/// Constructs a transfer transaction with value balance 5,000 and declared fee 5,000.
fn transfer_with_fee_5000(chain_id: Hash) -> Vec<u8> {
    let f = get_fixtures();
    let fee_atoms = 5_000u64;
    let sighash = compute_tx_auth_digest(
        *chain_id.as_bytes(),
        1, // OrchardTransfer
        1, // tx_version
        fee_atoms,
        f.tx_proven_5000.flag_byte(),
        *f.tx_proven_5000.value_balance(),
        f.tx_proven_5000.anchor().to_bytes(),
        &[f.tx_action_effect_5000],
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let bundle = f
        .tx_proven_5000
        .clone()
        .apply_signatures(&mut rng, sighash, &[SpendAuthorizingKey::from(&f.miner_sk)])
        .unwrap();
    let serialized_bundle = serialize_bundle(&bundle);

    let mut raw_tx =
        Vec::with_capacity(ownchain::tx::TX_ENVELOPE_LEN + 8 + serialized_bundle.len());
    raw_tx.push(TX_TYPE_ORCHARD_TRANSFER);
    raw_tx.extend_from_slice(&TX_VERSION.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&serialized_bundle);
    raw_tx
}

/// The chain ID used throughout the tests.
fn chain_id() -> Hash {
    hash::chain_id(genesis::DEVNET)
}

/// Builds a canonical transaction envelope with the given type and payload.
fn envelope(tx_type: u8, chain_id: Hash, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ownchain::tx::TX_ENVELOPE_LEN + payload.len());
    out.push(tx_type);
    out.extend_from_slice(&TX_VERSION.to_le_bytes());
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Builds a coinbase transaction declaring the given height.
fn coinbase(chain_id: Hash, height: u64) -> Vec<u8> {
    genuine_coinbase(chain_id, height)
}

/// Builds an ordinary Orchard transfer transaction.
fn transfer(chain_id: Hash, fee_atoms: u64) -> Vec<u8> {
    if fee_atoms == 7_028 {
        genuine_transfer(chain_id)
    } else if fee_atoms == 5_000 {
        transfer_with_fee_5000(chain_id)
    } else {
        let mut tx = genuine_transfer(chain_id);
        tx[ownchain::tx::TX_ENVELOPE_LEN..ownchain::tx::TX_ENVELOPE_LEN + 8]
            .copy_from_slice(&fee_atoms.to_le_bytes());
        tx
    }
}

/// Constructs an OrchardTransfer transaction claiming 50 actions to test block action limits (§6.3).
fn make_fifty_action_tx(chain_id: Hash, seed: u64) -> Vec<u8> {
    let mut bundle_bytes = Vec::new();
    ownchain::orchard_tx::encode_compact_size(50, &mut bundle_bytes);
    // Bounded bundle payload carrying 50 action slots
    bundle_bytes.resize(
        1 + 50 * 820 + 41 + 3 + 2160 + 50 * 64 + 64,
        (seed & 0xff) as u8,
    );

    let fee_atoms = 96_509u64;
    let mut raw_tx = Vec::with_capacity(ownchain::tx::TX_ENVELOPE_LEN + 8 + bundle_bytes.len());
    raw_tx.push(TX_TYPE_ORCHARD_TRANSFER);
    raw_tx.extend_from_slice(&TX_VERSION.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);
    raw_tx
}

/// Builds a block whose header commits to `transactions`.
///
/// The transaction root is computed from the transactions, so the block is
/// internally consistent unless a test deliberately breaks it.
fn make_block(chain_id: Hash, parent: &Block, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    Block {
        header: Header {
            version: 1,
            chain_id,
            height,
            parent_block_id: parent.block_id(),
            transaction_root: merkle::tx_root(&ids),
            orchard_commitment_root: empty_commitment_root(),
            timestamp,
            difficulty: 1,
            nonce: 0,
        },
        transactions,
    }
}

/// Builds a valid child block with a single coinbase transaction.
fn child_block(chain_id: Hash, parent: &Block, timestamp: u64) -> Block {
    let height = parent.header.height + 1;
    make_block(
        chain_id,
        parent,
        timestamp,
        vec![coinbase(chain_id, height)],
    )
}

/// A chain state holding only the genesis block.
fn chain_with_genesis() -> ChainState {
    let id = chain_id();
    ChainState::from_genesis(&genesis::genesis_block(id)).expect("genesis is valid")
}

// ---------------------------------------------------------------------------
// Genesis (§6.4)
// ---------------------------------------------------------------------------

#[test]
fn canonical_genesis_is_valid() {
    let id = chain_id();
    let block = genesis::genesis_block(id);
    let context = ValidationContext::genesis(id);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn genesis_must_match_the_canonical_block_exactly() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);

    // §6.4: genesis has difficulty 1.
    block.header.difficulty = 2;
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_must_have_zero_parent_id() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.parent_block_id = Hash::new([0x01; 32]);
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::NonZeroGenesisParent)
    ));
}

#[test]
fn genesis_must_have_no_transactions() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.transactions = vec![coinbase(id, 0)];
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_must_have_the_canonical_empty_orchard_root() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.orchard_commitment_root = Hash::new([0x02; 32]);
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_must_have_the_canonical_timestamp() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.timestamp = genesis::GENESIS_TIMESTAMP + 1;
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_of_another_network_is_rejected() {
    let id = chain_id();
    let other = hash::chain_id("testnet");
    let block = genesis::genesis_block(other);
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::WrongChainId { .. })
    ));
}

// ---------------------------------------------------------------------------
// Header linkage (§6.1)
// ---------------------------------------------------------------------------

#[test]
fn unsupported_header_version_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.version = 2;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::UnsupportedVersion {
            found: 2,
            expected: 1
        })
    ));
}

#[test]
fn wrong_chain_id_in_header_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.chain_id = hash::chain_id("testnet");

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::WrongChainId { .. })
    ));
}

#[test]
fn wrong_parent_id_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.parent_block_id = Hash::new([0x03; 32]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::UnknownParent { .. })
    ));
}

#[test]
fn zero_parent_id_on_a_non_genesis_block_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.parent_block_id = Hash::ZERO;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::ZeroParentBlockId)
    ));
}

#[test]
fn wrong_height_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.height = 7;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::HeightMismatch {
            found: 7,
            expected: 1
        })
    ));
}

// ---------------------------------------------------------------------------
// Transactions (§6.2, §6.3, §7.0, §7.1)
// ---------------------------------------------------------------------------

#[test]
fn a_valid_child_block_with_coinbase_and_transfer_is_accepted() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), transfer(id, 7028)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn a_block_without_a_coinbase_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![transfer(id, 7028)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidCoinbase { .. })
    ));
}

#[test]
fn an_empty_non_genesis_block_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, vec![]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidCoinbase { .. })
    ));
}

#[test]
fn a_second_coinbase_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), coinbase(id, 1)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidCoinbase { .. })
    ));
}

#[test]
fn a_coinbase_declaring_the_wrong_height_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // The block is at height 1 but the coinbase declares height 2.
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 2)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::CoinbaseHeightMismatch {
            found: 2,
            expected: 1
        })
    ));
}

#[test]
fn a_transaction_with_the_wrong_chain_id_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), transfer(hash::chain_id("testnet"), 7028)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 1, .. })
    ));
}

#[test]
fn a_transaction_with_an_unsupported_version_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut tx = transfer(id, 7028);
    tx[1] = 9; // tx_version is u16_le; this sets it to 9.
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 1, .. })
    ));
}

#[test]
fn a_transaction_with_an_unknown_type_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut tx = transfer(id, 7028);
    tx[0] = 7; // Not a known transaction type.
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 1, .. })
    ));
}

#[test]
fn a_transaction_without_a_payload_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // A coinbase whose payload is exactly the 8-byte height and nothing
    // else: there is no Orchard bundle.
    let tx = envelope(TX_TYPE_COINBASE, id, &1u64.to_le_bytes());
    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, vec![tx]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 0, .. })
    ));
}

#[test]
fn a_wrong_transaction_root_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);
    block.header.transaction_root = merkle::empty_root();

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TransactionRootMismatch { .. })
    ));
}

#[test]
fn the_orchard_root_of_a_transaction_bearing_block_is_deferred() {
    // M1-B does not parse Orchard bundles, so the commitment tree state of a
    // block that carries transactions cannot be computed. The check is
    // therefore deferred to the Orchard compatibility gate (§12) rather
    // than being silently applied with a wrong expected value.
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    block.header.orchard_commitment_root = Hash::new([0x04; 32]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn duplicate_transaction_ids_in_a_block_are_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let dup = transfer(id, 7028);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), dup.clone(), dup],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::DuplicateTransaction { index: 2, .. })
    ));
}

#[test]
fn a_transaction_id_already_on_the_chain_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let reused = transfer(id, 7028);

    // Height 1 accepts the transfer.
    let first = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), reused.clone()],
    );
    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&first, &context), Ok(()));

    // Height 2 tries to include the very same transaction again.
    let second = make_block(
        id,
        &first,
        genesis::GENESIS_TIMESTAMP + 20,
        vec![coinbase(id, 2), reused.clone()],
    );
    let accepted = [hash::transaction_id(&reused)];
    let ancestors = [genesis::GENESIS_TIMESTAMP, genesis::GENESIS_TIMESTAMP + 10];
    let context =
        ValidationContext::new(id, &first, &ancestors).with_accepted_transaction_ids(&accepted);
    assert!(matches!(
        validate_block(&second, &context),
        Err(ValidationError::DuplicateTransaction { index: 1, .. })
    ));
}

#[test]
fn an_oversized_transaction_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // A transfer larger than the 1,000,000-byte non-coinbase cap.
    let mut big = transfer(id, 7028);
    big.resize(MAX_TRANSACTION_SIZE + 1, 0xCC);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), big],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TransactionTooLarge {
            limit: MAX_TRANSACTION_SIZE,
            ..
        })
    ));
}

#[test]
fn an_oversized_block_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // Three transactions of ~900 KB each exceed the 2,000,000-byte block cap.
    let mut txs = vec![coinbase(id, 1)];
    for i in 0..3u64 {
        let mut tx = transfer(id, i);
        tx.resize(900_000, 0xDD);
        txs.push(tx);
    }
    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, txs);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::BlockTooLarge {
            limit: MAX_BLOCK_SIZE,
            ..
        })
    ));
}

#[test]
fn a_transaction_at_the_size_cap_passes_size_check_and_fails_bundle_codec() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut tx = transfer(id, 7028);
    tx.resize(MAX_TRANSACTION_SIZE, 0xDD);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    // The transaction is within the 1,000,000-byte cap (so TransactionTooLarge does
    // not fire), but fails bundle decoding because arbitrary trailing bytes are rejected.
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidOrchardTransaction {
            index: 1,
            error: OrchardValidationError::Codec(BundleCodecError::TrailingBytes)
        })
    ));
}

// ---------------------------------------------------------------------------
// Timestamps (§4)
// ---------------------------------------------------------------------------

#[test]
fn upper_median_picks_the_middle_sample() {
    // Odd count: index len / 2 of the ascending sort.
    assert_eq!(upper_median(&[10, 20, 30]), Some(20));
    // Even count: index len / 2 of the ascending sort, i.e. the *upper* of
    // the two middle samples.
    assert_eq!(upper_median(&[10, 20, 30, 40]), Some(30));
    // Unsorted input is sorted first.
    assert_eq!(upper_median(&[30, 10, 20]), Some(20));
    // A single sample is its own median.
    assert_eq!(upper_median(&[7]), Some(7));
    // No samples: nothing to compare against.
    assert_eq!(upper_median(&[]), None);
}

#[test]
fn a_timestamp_equal_to_the_median_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // The ancestor timestamp is the median, and the rule is "greater than".
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TimestampNotIncreasing { .. })
    ));
}

#[test]
fn a_timestamp_below_the_median_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP - 1);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TimestampNotIncreasing { .. })
    ));
}

#[test]
fn a_timestamp_above_the_median_is_accepted() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn the_median_is_the_upper_median_of_the_last_eleven_ancestors() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // Twelve ancestor timestamps; only the last eleven are considered.
    let ancestors: Vec<u64> = (0..12u64).map(|i| 1000 + i).collect();
    // The last eleven are 1001..=1011; the upper median is index 11/2 = 5,
    // i.e. 1001 + 5 = 1006.
    let expected_median = 1006;

    // A timestamp exactly at the median does not satisfy the "greater than"
    // rule.
    let block = child_block(id, &genesis, expected_median);
    let context = ValidationContext::new(id, &genesis, &ancestors);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TimestampNotIncreasing { median, .. })
            if median == expected_median
    ));

    // One second above the median passes.
    let block = child_block(id, &genesis, expected_median + 1);
    let context = ValidationContext::new(id, &genesis, &ancestors);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

// ---------------------------------------------------------------------------
// Chain state and atomicity (§6.1, §7.3.6)
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_chain_is_empty() {
    let state = ChainState::new(chain_id());
    assert!(state.is_empty());
    assert_eq!(state.len(), 0);
    assert!(state.tip().is_none());
    assert!(state.tip_height().is_none());
    assert!(state.tip_block_id().is_none());
}

#[test]
fn genesis_can_be_accepted_as_the_first_block() {
    let id = chain_id();
    let mut state = ChainState::new(id);
    let block = genesis::genesis_block(id);
    assert_eq!(state.apply_block(&block), Ok(()));
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));
    assert_eq!(state.tip_block_id(), Some(block.block_id()));
}

#[test]
fn from_genesis_starts_with_an_empty_accepted_transaction_set() {
    let id = chain_id();
    let state = ChainState::from_genesis(&genesis::genesis_block(id)).expect("genesis is valid");
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));
    // Genesis carries no transactions, so nothing is in the accepted set.
    assert!(state.accepted_transaction_ids().is_empty());
    assert_eq!(
        state.ancestor_timestamps(),
        vec![genesis::GENESIS_TIMESTAMP]
    );
}

#[test]
fn from_genesis_rejects_a_non_canonical_genesis_block() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.difficulty = 2;
    assert!(matches!(
        ChainState::from_genesis(&block),
        Err(ChainError::Invalid(ValidationError::InvalidGenesis { .. }))
    ));
}

#[test]
fn a_non_genesis_block_cannot_be_the_first_block() {
    let id = chain_id();
    let mut state = ChainState::new(id);
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);

    assert!(matches!(
        state.apply_block(&block),
        Err(ChainError::Invalid(ValidationError::InvalidGenesis { .. }))
    ));
    assert!(state.is_empty());
}

#[test]
fn a_valid_block_extends_the_chain() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);

    assert_eq!(state.apply_block(&block), Ok(()));
    assert_eq!(state.len(), 2);
    assert_eq!(state.tip_height(), Some(1));
    assert_eq!(state.tip_block_id(), Some(block.block_id()));
    assert_eq!(state.block_at(1), Some(&block));
}

#[test]
fn a_rejected_block_leaves_the_state_untouched() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let before = state.clone();

    let genesis = genesis::genesis_block(id);
    // A block whose transaction root does not match its transactions.
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);
    block.header.transaction_root = merkle::empty_root();

    assert!(matches!(
        state.apply_block(&block),
        Err(ChainError::Invalid(
            ValidationError::TransactionRootMismatch { .. }
        ))
    ));
    assert_eq!(state, before);
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));
}

#[test]
fn a_rejected_block_leaves_a_populated_state_untouched() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    // Accept one block with a transaction, so the state has a non-empty
    // accepted-transaction set and a non-trivial timestamp window.
    let tx = transfer(id, 7028);
    let good = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx.clone()],
    );
    state.apply_block(&good).expect("block is valid");

    let before = state.clone();

    // Now reject a block for a different reason: a wrong parent height.
    let mut bad = child_block(id, &good, genesis::GENESIS_TIMESTAMP + 20);
    bad.header.height = 5;
    assert!(matches!(
        state.apply_block(&bad),
        Err(ChainError::Invalid(ValidationError::HeightMismatch { .. }))
    ));

    // Every field of the state must be exactly as it was.
    assert_eq!(state, before);
    assert_eq!(state.len(), 2);
    assert_eq!(state.tip_height(), Some(1));
    assert_eq!(state.tip_block_id(), Some(good.block_id()));
    assert_eq!(state.accepted_transaction_ids().len(), 2);
    assert!(state
        .accepted_transaction_ids()
        .contains(&hash::transaction_id(&tx)));
    assert_eq!(
        state.ancestor_timestamps(),
        vec![genesis::GENESIS_TIMESTAMP, genesis::GENESIS_TIMESTAMP + 10]
    );
}

#[test]
fn a_rejected_block_does_not_extend_the_accepted_transaction_set() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    // A block with a duplicate transaction ID is rejected; the rejected
    // transaction must not enter the accepted set.
    let dup = transfer(id, 7028);
    let bad = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), dup.clone(), dup.clone()],
    );

    let before = state.clone();
    assert!(matches!(
        state.apply_block(&bad),
        Err(ChainError::Invalid(
            ValidationError::DuplicateTransaction { .. }
        ))
    ));
    assert_eq!(state, before);
    assert!(state.accepted_transaction_ids().is_empty());
}

#[test]
fn a_rejected_block_does_not_advance_the_timestamp_window() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    // A block with a timestamp that does not beat the median.
    let bad = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP);
    assert!(matches!(
        state.apply_block(&bad),
        Err(ChainError::Invalid(
            ValidationError::TimestampNotIncreasing { .. }
        ))
    ));

    assert_eq!(
        state.ancestor_timestamps(),
        vec![genesis::GENESIS_TIMESTAMP]
    );
    assert_eq!(
        state.ancestor_median_timestamp(),
        Some(genesis::GENESIS_TIMESTAMP)
    );
}

#[test]
fn validation_does_not_mutate_the_state() {
    let id = chain_id();
    let state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);

    let before = state.clone();
    assert_eq!(state.validate(&block), Ok(()));
    assert_eq!(state, before);
    assert_eq!(state.len(), 1);
}

#[test]
fn the_timestamp_window_covers_at_most_eleven_ancestors() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    let mut parent = genesis.clone();
    for i in 1..=15u64 {
        let block = child_block(id, &parent, genesis::GENESIS_TIMESTAMP + i * 10);
        state.apply_block(&block).expect("block is valid");
        parent = block;
    }

    // 16 accepted blocks (genesis + 15), but only the last 11 timestamps.
    assert_eq!(state.len(), 16);
    assert_eq!(state.ancestor_timestamps().len(), 11);
    assert_eq!(
        state.ancestor_timestamps().first(),
        Some(&(genesis::GENESIS_TIMESTAMP + 50))
    );
    assert_eq!(
        state.ancestor_timestamps().last(),
        Some(&(genesis::GENESIS_TIMESTAMP + 150))
    );
}

#[test]
fn a_chain_of_blocks_is_accepted_in_order() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    let mut parent = genesis.clone();
    for i in 1..=5u64 {
        let block = child_block(id, &parent, genesis::GENESIS_TIMESTAMP + i * 10);
        state.apply_block(&block).expect("block is valid");
        parent = block;
    }

    assert_eq!(state.len(), 6);
    assert_eq!(state.tip_height(), Some(5));
    for height in 0..6u64 {
        let block = state.block_at(height).expect("block is present");
        assert_eq!(block.header.height, height);
    }
}

#[test]
fn accepted_transaction_ids_are_tracked() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    let tx = transfer(id, 7028);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx.clone()],
    );
    state.apply_block(&block).expect("block is valid");

    assert_eq!(state.accepted_transaction_ids().len(), 2);
    assert!(state
        .accepted_transaction_ids()
        .contains(&hash::transaction_id(&tx)));
}

// ============================================================================
// Proof-of-work validation tests (M1-C2 integration)
// ============================================================================

#[test]
fn pow_valid_proof_of_work_passes_validation() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn pow_hash_above_target_fails_validation() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    // Setting difficulty to u128::MAX sets target to 2^128 + 1.
    // An un-mined block with nonce 0 will exceed this target with overwhelming probability.
    block.header.difficulty = u128::MAX;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP])
        .with_expected_difficulty(u128::MAX);
    let result = validate_block(&block, &context);
    assert!(
        matches!(result, Err(ValidationError::HashAboveTarget { .. })),
        "expected HashAboveTarget, got {result:?}"
    );
}

#[test]
fn pow_incorrect_key_block_id_fails_validation() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    // Use difficulty 100 so target is ~ 2^249
    block.header.difficulty = 100;

    // Mine a nonce that succeeds under the correct key (genesis)
    let key_correct = genesis.block_id();
    let mut mined = false;
    for nonce in 0..10_000u64 {
        block.header.nonce = nonce;
        let header_bytes = block.header.to_bytes();
        let hash = ownchain::randomx::randomx_hash(
            key_correct.as_bytes(),
            &header_bytes,
            ownchain::randomx::RandomxMode::Light,
        )
        .unwrap();
        if ownchain::randomx::check_pow_target(&hash, block.header.difficulty).unwrap() {
            mined = true;
            break;
        }
    }
    assert!(
        mined,
        "mining a low difficulty block should succeed quickly"
    );

    // Validates under the correct key
    let context_correct = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP])
        .with_key_block_id(key_correct)
        .with_expected_difficulty(100);
    assert_eq!(validate_block(&block, &context_correct), Ok(()));

    // Fails under an incorrect key block ID
    let wrong_key = Hash::new([0xEE; 32]);
    let context_wrong = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP])
        .with_key_block_id(wrong_key)
        .with_expected_difficulty(100);
    let result = validate_block(&block, &context_wrong);
    assert!(
        matches!(result, Err(ValidationError::HashAboveTarget { .. })),
        "validation under incorrect key block ID should produce an invalid hash above target"
    );
}

#[test]
fn pow_genesis_rules_remain_enforced() {
    let id = chain_id();
    let mut genesis = genesis::genesis_block(id);

    // Non-zero nonce on genesis must fail
    genesis.header.nonce = 1;
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&genesis, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));

    // Non-zero difficulty != 1 on genesis must fail
    genesis.header.nonce = 0;
    genesis.header.difficulty = 2;
    assert!(matches!(
        validate_block(&genesis, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));

    // Difficulty 0 on genesis must fail
    genesis.header.difficulty = 0;
    assert!(matches!(
        validate_block(&genesis, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn pow_context_without_required_ancestor_history_fails_cleanly() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // Construct a parent block at height 2111
    let mut parent = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 50,
        vec![coinbase(id, 2111)],
    );
    parent.header.height = 2111;

    // Construct a candidate block at height 2112 building on parent at 2111
    let block = make_block(
        id,
        &parent,
        genesis::GENESIS_TIMESTAMP + 100,
        vec![coinbase(id, 2112)],
    );

    // Context without key_block_id at height 2112 (kh = 2048) must fail cleanly with MissingKeyBlock
    let mut context = ValidationContext::new(id, &parent, &[genesis::GENESIS_TIMESTAMP + 50])
        .with_expected_difficulty(1);
    context.key_block_id = None; // ensure no key block is provided

    let result = validate_block(&block, &context);
    assert_eq!(
        result,
        Err(ValidationError::MissingKeyBlock {
            height: 2112,
            key_height: 2048,
        })
    );
}

// ============================================================================
// Network-computed expected difficulty enforcement tests
// ============================================================================

#[test]
fn difficulty_startup_boundaries_and_first_retarget_height() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).expect("genesis is valid");

    // Genesis cumulative work is zero (§4)
    assert_eq!(state.cumulative_work(), ownchain::difficulty::U256::zero());
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));

    // Height 1: expected difficulty is 1 (§4.1: fewer than 2 samples after 15-block lag)
    assert_eq!(state.expected_difficulty_for_next_block(), Ok(1));

    // Candidate at height 1 declaring difficulty 2 must be rejected
    let mut bad_diff_block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    bad_diff_block.header.difficulty = 2;
    assert_eq!(
        state.apply_block(&bad_diff_block),
        Err(ChainError::Invalid(ValidationError::DifficultyMismatch {
            found: 2,
            expected: 1,
        }))
    );
    // State is untouched
    assert_eq!(state.len(), 1);
    assert_eq!(state.cumulative_work(), ownchain::difficulty::U256::zero());

    // Candidate at height 1 declaring difficulty 0 must be rejected
    bad_diff_block.header.difficulty = 0;
    assert_eq!(
        state.apply_block(&bad_diff_block),
        Err(ChainError::Invalid(ValidationError::ZeroDifficulty))
    );

    // Honest block 1 at difficulty 1 passes
    let block1 = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    state.apply_block(&block1).expect("block 1 is accepted");
    assert_eq!(state.len(), 2);
    assert_eq!(state.tip_height(), Some(1));
    assert_eq!(
        state.cumulative_work(),
        ownchain::difficulty::U256::from_u128(1)
    );

    // Mine/apply blocks 2 through 16 at 10-second intervals (fast blocks).
    // For all heights <= 16, h - 16 <= 0, so fewer than 2 samples exist.
    // Expected difficulty must remain 1 throughout the lag window.
    for h in 2..=16u64 {
        assert_eq!(state.expected_difficulty_for_next_block(), Ok(1));
        let parent = state.tip().unwrap().clone();
        let blk = make_block(
            id,
            &parent,
            genesis::GENESIS_TIMESTAMP + 10 * h,
            vec![coinbase(id, h)],
        );
        state.apply_block(&blk).expect("startup block is accepted");
        assert_eq!(
            state.cumulative_work(),
            ownchain::difficulty::U256::from_u128(h as u128)
        );
    }

    assert_eq!(state.len(), 17);
    assert_eq!(state.tip_height(), Some(16));
    assert_eq!(
        state.cumulative_work(),
        ownchain::difficulty::U256::from_u128(16)
    );

    // Height 17: FIRST RETARGET HEIGHT!
    // Window: max(0, 17 - 735)..=17 - 16 => heights 0..=1 (2 samples: genesis and block 1).
    // time_span = timestamp[1] - timestamp[0] = 10s (fast blocks!).
    // total_work = C_1 - C_0 = 1 - 0 = 1.
    // expected difficulty = ceil(1 * 120 / 10) = 12.
    let expected_diff_17 = state
        .expected_difficulty_for_next_block()
        .expect("expected difficulty at 17");
    assert_eq!(expected_diff_17, 12);

    let parent_16 = state.tip().unwrap().clone();

    // Attacker test: Miner attempts to submit candidate at height 17 declaring difficulty 1
    // (attempting to keep difficulty at 1 after expected difficulty has risen to 12).
    let attacker_block = make_block(
        id,
        &parent_16,
        genesis::GENESIS_TIMESTAMP + 170,
        vec![coinbase(id, 17)],
    );
    assert_eq!(attacker_block.header.difficulty, 1);
    let attack_err = state.apply_block(&attacker_block);
    assert_eq!(
        attack_err,
        Err(ChainError::Invalid(ValidationError::DifficultyMismatch {
            found: 1,
            expected: 12,
        }))
    );
    // Atomicity check: ChainState was not mutated
    assert_eq!(state.len(), 17);
    assert_eq!(state.tip_height(), Some(16));
    assert_eq!(
        state.cumulative_work(),
        ownchain::difficulty::U256::from_u128(16)
    );

    // Incorrect declared difficulty test (e.g. 13 instead of 12)
    let mut wrong_diff_block = make_block(
        id,
        &parent_16,
        genesis::GENESIS_TIMESTAMP + 170,
        vec![coinbase(id, 17)],
    );
    wrong_diff_block.header.difficulty = 13;
    assert_eq!(
        state.apply_block(&wrong_diff_block),
        Err(ChainError::Invalid(ValidationError::DifficultyMismatch {
            found: 13,
            expected: 12,
        }))
    );

    // Honest miner: declares expected difficulty 12 and mines valid PoW
    let mut honest_block = make_block(
        id,
        &parent_16,
        genesis::GENESIS_TIMESTAMP + 170,
        vec![coinbase(id, 17)],
    );
    honest_block.header.difficulty = 12;

    // Mine nonce targeting difficulty 12 under key block (genesis at height 0)
    let key_id = genesis.block_id();
    let mut mined = false;
    for nonce in 0..10_000u64 {
        honest_block.header.nonce = nonce;
        let header_bytes = honest_block.header.to_bytes();
        let hash = ownchain::randomx::randomx_hash(
            key_id.as_bytes(),
            &header_bytes,
            ownchain::randomx::RandomxMode::Light,
        )
        .unwrap();
        if ownchain::randomx::check_pow_target(&hash, 12).unwrap() {
            mined = true;
            break;
        }
    }
    assert!(
        mined,
        "mining difficulty 12 should succeed within 10,000 hashes"
    );

    // Block 17 is validated and accepted!
    state
        .apply_block(&honest_block)
        .expect("honest block 17 accepted");
    assert_eq!(state.len(), 18);
    assert_eq!(state.tip_height(), Some(17));
    // Cumulative work increases by validated expected difficulty 12: 16 + 12 = 28
    assert_eq!(
        state.cumulative_work(),
        ownchain::difficulty::U256::from_u128(28)
    );
}

#[test]
fn missing_expected_difficulty_fails_on_standalone_context() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // Block at height 17
    let mut parent = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 16)],
    );
    parent.header.height = 16;
    let block = make_block(
        id,
        &parent,
        genesis::GENESIS_TIMESTAMP + 20,
        vec![coinbase(id, 17)],
    );

    // Standalone ValidationContext with parent height 16 defaults expected_difficulty to None
    let context = ValidationContext::new(id, &parent, &[genesis::GENESIS_TIMESTAMP + 10]);
    assert_eq!(context.expected_difficulty, None);

    let result = validate_block(&block, &context);
    assert_eq!(
        result,
        Err(ValidationError::MissingExpectedDifficulty { height: 17 })
    );
}

#[test]
fn rejected_block_does_not_mutate_cumulative_work_or_difficulty_history() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).expect("genesis is valid");

    let initial_work = state.cumulative_work();
    let initial_samples_len = state.difficulty_samples().len();
    let initial_cw_len = state.cumulative_work_history().len();

    // Create an invalid block (timestamp below median)
    let bad_block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP, // not greater than median
        vec![coinbase(id, 1)],
    );
    assert!(state.apply_block(&bad_block).is_err());

    // Cumulative work and difficulty history must remain untouched
    assert_eq!(state.cumulative_work(), initial_work);
    assert_eq!(state.difficulty_samples().len(), initial_samples_len);
    assert_eq!(state.cumulative_work_history().len(), initial_cw_len);
}

// ============================================================================
// Milestone M1-E Stage 2: Consensus Orchard Validation & Fee Rules
// ============================================================================

#[test]
fn test_block_rejects_invalid_halo2_proof_in_tx() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut bad_tx = transfer(id, 7028);

    // Byte 1000 is squarely within the 2,160-byte Halo2 proof (offset 908..3068)
    bad_tx[1000] ^= 0x55;

    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let err = validate_block(&block, &context).unwrap_err();
    assert!(matches!(
        err,
        ValidationError::InvalidOrchardTransaction {
            index: 1,
            error: OrchardValidationError::ProofVerificationFailed(_),
        }
    ));
}

#[test]
fn test_block_rejects_invalid_spend_auth_sig_in_tx() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut bad_tx = transfer(id, 7028);

    // In a 6,028-byte transfer transaction:
    // envelope (35) + fee (8) + action count compactSize (1) + actions (820) + flags (1)
    // + value balance (8) + anchor (32) + proof len compactSize (3) + proof (4992) = 5900.
    // Spend auth signature for action 0 is at offset 5900..5964.
    bad_tx[5910] ^= 0x55;

    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let err = validate_block(&block, &context).unwrap_err();
    assert_eq!(
        err,
        ValidationError::InvalidOrchardTransaction {
            index: 1,
            error: OrchardValidationError::SpendAuthSignatureInvalid { action_index: 0 },
        }
    );
}

#[test]
fn test_block_rejects_invalid_binding_sig_in_tx() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut bad_tx = transfer(id, 7028);

    // Last byte is within the RedPallas binding signature
    let last = bad_tx.len() - 1;
    bad_tx[last] ^= 0x55;

    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let err = validate_block(&block, &context).unwrap_err();
    assert_eq!(
        err,
        ValidationError::InvalidOrchardTransaction {
            index: 1,
            error: OrchardValidationError::BindingSignatureInvalid,
        }
    );
}

#[test]
fn test_block_rejects_malformed_bundle_in_tx() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut bad_tx = transfer(id, 7028);

    // Truncate bundle data
    bad_tx.truncate(bad_tx.len() - 20);

    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let err = validate_block(&block, &context).unwrap_err();
    assert_eq!(
        err,
        ValidationError::InvalidOrchardTransaction {
            index: 1,
            error: OrchardValidationError::Codec(BundleCodecError::UnexpectedEof),
        }
    );
}

#[test]
fn test_block_rejects_incorrect_fee_formula() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // transfer_with_fee_5000 has value balance 5000 and declared fee 5000,
    // which has valid Halo2 proof & valid RedPallas signatures, but fee 5000 != expected 7028.
    let bad_fee_tx = transfer(id, 5000);

    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_fee_tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let err = validate_block(&block, &context).unwrap_err();
    assert_eq!(
        err,
        ValidationError::IncorrectTransactionFee {
            index: 1,
            declared: 5000,
            expected: 7028,
        }
    );
}

#[test]
fn test_block_rejects_exceeded_aggregate_action_count() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // 40 transactions of 50 actions each + 1 coinbase of 1 action = 2,001 actions (> 2,000 limit).
    // Each transaction is canonically serialized (~46.5 KB), so 40 transactions total ~1.86 MB (< 2.0 MB block limit).
    let mut txs = Vec::with_capacity(41);
    txs.push(coinbase(id, 1));
    for i in 0..40u64 {
        txs.push(make_fifty_action_tx(id, 1000 + i));
    }

    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, txs);
    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let err = validate_block(&block, &context).unwrap_err();
    assert_eq!(
        err,
        ValidationError::TooManyBlockActions {
            actual: 2001,
            limit: ownchain::orchard_tx::MAX_ACTIONS_PER_BLOCK,
        }
    );
}

#[test]
fn test_chain_state_atomicity_preserved_on_orchard_failure() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);
    let state_before = state.clone();

    // 1. Try applying a block with invalid proof
    let mut bad_proof_tx = transfer(id, 7028);
    bad_proof_tx[1000] ^= 0xff;
    let bad_block_proof = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_proof_tx],
    );
    let res1 = state.apply_block(&bad_block_proof);
    assert!(matches!(
        res1,
        Err(ChainError::Invalid(
            ValidationError::InvalidOrchardTransaction {
                index: 1,
                error: OrchardValidationError::ProofVerificationFailed(_),
            }
        ))
    ));
    assert_eq!(state, state_before);

    // 2. Try applying a block with incorrect fee
    let bad_fee_tx = transfer(id, 5000);
    let bad_block_fee = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), bad_fee_tx],
    );
    let res2 = state.apply_block(&bad_block_fee);
    assert_eq!(
        res2,
        Err(ChainError::Invalid(
            ValidationError::IncorrectTransactionFee {
                index: 1,
                declared: 5000,
                expected: 7028,
            }
        ))
    );
    assert_eq!(state, state_before);
}
