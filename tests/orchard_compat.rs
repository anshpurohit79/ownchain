//! OwnChain M1-D — Orchard V2 Compatibility Gate Harness
//!
//! Validates `orchard = 0.16.0` APIs under protocol rules:
//! - `BundleVersion::orchard_v2()`
//! - `OrchardCircuitVersion::FixedPostNu6_2`
//! - RedPallas signature authorization and binding key verification
//! - Canonical serialization and round-trip parsing
//! - Output-only single-action coinbase with all-zero OVK recovery
//! - Valid shielded transfer with fee handling
//! - Comprehensive negative cases and chain-state vs bundle-level separation

use std::collections::HashSet;
use std::sync::OnceLock;

use blake2::{Blake2b256, Digest};
use nonempty::NonEmpty;
use orchard::{
    builder::{Builder, BundleType},
    bundle::{Authorized, BatchValidator, BundleError, BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::{NoteBytesData, NoteCiphertextBytes},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Action, ActionFromPartsError, Address, Bundle, Proof,
};
use rand::SeedableRng;

// ---------------------------------------------------------------------------
// Circuit Key Cache (Cached across tests to avoid expensive repeated setup)
// ---------------------------------------------------------------------------

struct CachedKeys {
    proving_key: OnceLock<ProvingKey>,
    verifying_key: OnceLock<VerifyingKey>,
}

static KEYS: CachedKeys = CachedKeys {
    proving_key: OnceLock::new(),
    verifying_key: OnceLock::new(),
};

fn get_proving_key() -> &'static ProvingKey {
    KEYS.proving_key
        .get_or_init(|| ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
}

fn get_verifying_key() -> &'static VerifyingKey {
    KEYS.verifying_key
        .get_or_init(|| get_proving_key().verifying_key())
}

// ---------------------------------------------------------------------------
// Protocol Constants and Helpers
// ---------------------------------------------------------------------------

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

/// Constructs a Merkle witness for position 0 in an otherwise empty tree,
/// returning the tree anchor and the Merkle path.
fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

// ---------------------------------------------------------------------------
// Canonical CompactSize and Bundle Serialization / Deserialization (ZIP-225)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum BundleCodecError {
    EmptyActions,
    TooManyActions,
    UnexpectedEof,
    TrailingBytes,
    NonCanonicalCompactSize,
    InvalidFlags,
    InvalidAnchor,
    InvalidValueCommitment,
    InvalidNullifier,
    InvalidRk,
    InvalidCmx,
    Action(ActionFromPartsError),
    Bundle(BundleError),
}

fn encode_compact_size(val: usize, buf: &mut Vec<u8>) {
    if val <= 252 {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(val as u64).to_le_bytes());
    }
}

fn decode_compact_size(data: &mut &[u8]) -> Result<usize, BundleCodecError> {
    if data.is_empty() {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let first = data[0];
    *data = &data[1..];
    match first {
        0..=252 => Ok(first as usize),
        0xfd => {
            if data.len() < 2 {
                return Err(BundleCodecError::UnexpectedEof);
            }
            let val = u16::from_le_bytes([data[0], data[1]]);
            if val < 253 {
                return Err(BundleCodecError::NonCanonicalCompactSize);
            }
            *data = &data[2..];
            Ok(val as usize)
        }
        0xfe => {
            if data.len() < 4 {
                return Err(BundleCodecError::UnexpectedEof);
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if val < 0x10000 {
                return Err(BundleCodecError::NonCanonicalCompactSize);
            }
            *data = &data[4..];
            usize::try_from(val).map_err(|_| BundleCodecError::NonCanonicalCompactSize)
        }
        0xff => {
            if data.len() < 8 {
                return Err(BundleCodecError::UnexpectedEof);
            }
            let val = u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            if val < 0x1_0000_0000 {
                return Err(BundleCodecError::NonCanonicalCompactSize);
            }
            *data = &data[8..];
            usize::try_from(val).map_err(|_| BundleCodecError::NonCanonicalCompactSize)
        }
    }
}

/// Serializes an Orchard V2 bundle in official ZIP-225 Section 7 order:
/// 1. actionCount: CompactSize
/// 2. actions: [actionDescription; actionCount] (each: cv_net, nullifier, rk, cmx, epk, enc_ciphertext, out_ciphertext)
/// 3. flags: 1 byte
/// 4. valueBalanceOrchard: 8 bytes (i64 little-endian)
/// 5. anchorOrchard: 32 bytes
/// 6. sizeProofsOrchard: CompactSize
/// 7. proofsOrchard: proof bytes
/// 8. spendAuthSigsOrchard: [64 bytes; actionCount]
/// 9. bindingSigOrchard: 64 bytes
pub fn serialize_bundle(bundle: &Bundle<Authorized, i64>) -> Vec<u8> {
    let mut buf = Vec::new();
    let actions = bundle.actions();
    encode_compact_size(actions.len(), &mut buf);

    for action in actions.iter() {
        buf.extend_from_slice(&action.cv_net().to_bytes());
        buf.extend_from_slice(&action.nullifier().to_bytes());
        buf.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        buf.extend_from_slice(&action.cmx().to_bytes());
        buf.extend_from_slice(&action.encrypted_note().epk_bytes);
        buf.extend_from_slice(&action.encrypted_note().enc_ciphertext.0);
        buf.extend_from_slice(&action.encrypted_note().out_ciphertext);
    }

    buf.push(bundle.flag_byte());
    buf.extend_from_slice(&bundle.value_balance().to_le_bytes());
    buf.extend_from_slice(&bundle.anchor().to_bytes());

    let proof_bytes = bundle.authorization().proof().as_ref();
    encode_compact_size(proof_bytes.len(), &mut buf);
    buf.extend_from_slice(proof_bytes);

    for action in actions.iter() {
        buf.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
    }

    buf.extend_from_slice(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));

    buf
}

/// Deserializes an Orchard V2 bundle in official ZIP-225 Section 7 order.
pub fn deserialize_bundle(mut data: &[u8]) -> Result<Bundle<Authorized, i64>, BundleCodecError> {
    let n_actions = decode_compact_size(&mut data)?;
    if n_actions == 0 {
        return Err(BundleCodecError::EmptyActions);
    }
    if n_actions > 50 {
        return Err(BundleCodecError::TooManyActions);
    }

    struct ActionDesc {
        cv_net: orchard::value::ValueCommitment,
        nf: Nullifier,
        rk: redpallas::VerificationKey<SpendAuth>,
        cmx: ExtractedNoteCommitment,
        epk_bytes: [u8; 32],
        enc_ciphertext: NoteCiphertextBytes,
        out_ciphertext: [u8; 80],
    }

    let mut descs = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        if data.len() < 32 * 5 + 580 + 80 {
            return Err(BundleCodecError::UnexpectedEof);
        }
        let mut cv_bytes = [0u8; 32];
        cv_bytes.copy_from_slice(&data[..32]);
        let cv_net = orchard::value::ValueCommitment::from_bytes(&cv_bytes)
            .into_option()
            .ok_or(BundleCodecError::InvalidValueCommitment)?;
        data = &data[32..];

        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(&data[..32]);
        let nf = Nullifier::from_bytes(&nf_bytes)
            .into_option()
            .ok_or(BundleCodecError::InvalidNullifier)?;
        data = &data[32..];

        let mut rk_bytes = [0u8; 32];
        rk_bytes.copy_from_slice(&data[..32]);
        let rk: redpallas::VerificationKey<SpendAuth> = rk_bytes
            .try_into()
            .map_err(|_| BundleCodecError::InvalidRk)?;
        data = &data[32..];

        let mut cmx_bytes = [0u8; 32];
        cmx_bytes.copy_from_slice(&data[..32]);
        let cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes)
            .into_option()
            .ok_or(BundleCodecError::InvalidCmx)?;
        data = &data[32..];

        let mut epk_bytes = [0u8; 32];
        epk_bytes.copy_from_slice(&data[..32]);
        data = &data[32..];

        let mut enc_bytes = [0u8; 580];
        enc_bytes.copy_from_slice(&data[..580]);
        let enc_ciphertext = NoteBytesData(enc_bytes);
        data = &data[580..];

        let mut out_ciphertext = [0u8; 80];
        out_ciphertext.copy_from_slice(&data[..80]);
        data = &data[80..];

        descs.push(ActionDesc {
            cv_net,
            nf,
            rk,
            cmx,
            epk_bytes,
            enc_ciphertext,
            out_ciphertext,
        });
    }

    if data.len() < 1 + 8 + 32 {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let flag_byte = data[0];
    let flags = Flags::from_byte(flag_byte, BundleVersion::orchard_v2())
        .ok_or(BundleCodecError::InvalidFlags)?;
    data = &data[1..];

    let mut vb_bytes = [0u8; 8];
    vb_bytes.copy_from_slice(&data[..8]);
    let value_balance = i64::from_le_bytes(vb_bytes);
    data = &data[8..];

    let mut anchor_bytes = [0u8; 32];
    anchor_bytes.copy_from_slice(&data[..32]);
    let anchor: Anchor = Anchor::from_bytes(anchor_bytes)
        .into_option()
        .ok_or(BundleCodecError::InvalidAnchor)?;
    data = &data[32..];

    let proof_len = decode_compact_size(&mut data)?;
    if data.len() < proof_len {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let proof_bytes = data[..proof_len].to_vec();
    data = &data[proof_len..];

    let mut spend_auth_sigs = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        if data.len() < 64 {
            return Err(BundleCodecError::UnexpectedEof);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&data[..64]);
        spend_auth_sigs.push(redpallas::Signature::<SpendAuth>::from(sig_bytes));
        data = &data[64..];
    }

    if data.len() < 64 {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let mut binding_sig_bytes = [0u8; 64];
    binding_sig_bytes.copy_from_slice(&data[..64]);
    let binding_sig = redpallas::Signature::<Binding>::from(binding_sig_bytes);
    data = &data[64..];

    if !data.is_empty() {
        return Err(BundleCodecError::TrailingBytes);
    }

    let mut actions = Vec::with_capacity(n_actions);
    for (desc, sig) in descs.into_iter().zip(spend_auth_sigs) {
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: desc.epk_bytes,
            enc_ciphertext: desc.enc_ciphertext,
            out_ciphertext: desc.out_ciphertext,
        };
        let action =
            Action::from_parts(desc.nf, desc.rk, desc.cmx, encrypted_note, desc.cv_net, sig)
                .map_err(BundleCodecError::Action)?;
        actions.push(action);
    }

    let non_empty_actions = NonEmpty::from_vec(actions).unwrap();
    let auth = Authorized::from_parts(Proof::new(proof_bytes), binding_sig);

    Bundle::try_from_parts(
        non_empty_actions,
        flags,
        value_balance,
        anchor,
        auth,
        BundleVersion::orchard_v2(),
    )
    .map_err(BundleCodecError::Bundle)
}

// ---------------------------------------------------------------------------
// Transaction Authorization Digest & Action Effects (§7.3)
// ---------------------------------------------------------------------------

/// Computes the 32-byte action effect digest for an Orchard action over the complete
/// canonical 820-byte action description in ZIP-225 order:
/// `BLAKE2b-256("OwnChain/ActionEffect/v1" || cv_net || nullifier || rk || cmx || epk || enc_ciphertext || out_ciphertext)`
pub fn compute_action_effect(
    cv_net: &[u8; 32],
    nullifier: &[u8; 32],
    rk: &[u8; 32],
    cmx: &[u8; 32],
    epk: &[u8; 32],
    enc_ciphertext: &[u8; 580],
    out_ciphertext: &[u8; 80],
) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(b"OwnChain/ActionEffect/v1");
    hasher.update(cv_net);
    hasher.update(nullifier);
    hasher.update(rk);
    hasher.update(cmx);
    hasher.update(epk);
    hasher.update(enc_ciphertext);
    hasher.update(out_ciphertext);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Computes the 32-byte action effect digest directly from an Orchard `Action`.
pub fn compute_action_effect_from_action<A>(action: &Action<A>) -> [u8; 32] {
    compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    )
}

/// Computes the domain-separated authorization digest for an OwnChain transaction:
/// `BLAKE2b-256("OwnChain/TxAuth/v1" || chain_id || tx_type || tx_version || payload_prefix || bundle_flags || bundle_value_balance || bundle_anchor || repeated(action_effect_i))`
#[allow(clippy::too_many_arguments)]
pub fn compute_tx_auth_digest(
    chain_id: [u8; 32],
    tx_type: u8,
    tx_version: u16,
    payload_prefix: u64,
    bundle_flag_byte: u8,
    bundle_value_balance: i64,
    bundle_anchor: [u8; 32],
    action_effects: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(b"OwnChain/TxAuth/v1");
    hasher.update(chain_id);
    hasher.update([tx_type]);
    hasher.update(tx_version.to_le_bytes());
    hasher.update(payload_prefix.to_le_bytes());
    hasher.update([bundle_flag_byte]);
    hasher.update(bundle_value_balance.to_le_bytes());
    hasher.update(bundle_anchor);
    for effect in action_effects {
        hasher.update(effect);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

// ---------------------------------------------------------------------------
// Deterministic Fixture Generation (Reused across tests for fast execution)
// ---------------------------------------------------------------------------

struct TestFixtures {
    miner_address: Address,
    user_address: Address,
    coinbase_bundle: Bundle<Authorized, i64>,
    coinbase_sighash: [u8; 32],
    transfer_bundle: Bundle<Authorized, i64>,
    transfer_sighash: [u8; 32],
    devnet_chain_id: [u8; 32],
    testnet_chain_id: [u8; 32],
}

static FIXTURES: OnceLock<TestFixtures> = OnceLock::new();

fn get_fixtures() -> &'static TestFixtures {
    FIXTURES.get_or_init(|| {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
        let pk = get_proving_key();

        let miner_sk = SpendingKey::from_bytes([1u8; 32]).unwrap();
        let miner_fvk = FullViewingKey::from(&miner_sk);
        let miner_address = miner_fvk.address_at(0u32, Scope::External);

        let user_sk = SpendingKey::from_bytes([2u8; 32]).unwrap();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);

        // Chain IDs
        let devnet_chain_id = *ownchain::hash::chain_id("devnet").as_bytes();
        let testnet_chain_id = *ownchain::hash::chain_id("testnet").as_bytes();

        // 1. Construct Output-Only Coinbase Bundle
        let zero_ovk = OutgoingViewingKey::from([0u8; 32]);
        let payout_atoms = 1_000_000_000u64; // 10 OWN
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
        let cb_sighash = compute_tx_auth_digest(
            devnet_chain_id,
            0, // Coinbase
            1, // tx_version
            1, // block height 1
            cb_unauth.flag_byte(),
            *cb_unauth.value_balance(),
            cb_unauth.anchor().to_bytes(),
            &[cb_action_effect],
        );

        let cb_proven = cb_unauth.create_proof(pk, &mut rng).unwrap();
        let coinbase_bundle = cb_proven
            .apply_signatures(&mut rng, cb_sighash, &[])
            .unwrap();

        // 2. Construct Valid Transfer Bundle spending the coinbase note
        let cmx: ExtractedNoteCommitment = cb_note.commitment().into();
        let (anchor, merkle_path) = single_leaf_witness(&cmx);

        let fee_atoms = 5_000u64;
        let transfer_value = payout_atoms - fee_atoms; // 999_995_000

        let mut tx_builder = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v2().default_flags(),
            anchor,
        )
        .unwrap();

        tx_builder
            .add_spend(miner_fvk.clone(), cb_note, merkle_path)
            .unwrap();
        tx_builder
            .add_output(
                None,
                user_address,
                NoteValue::from_raw(transfer_value),
                [0u8; 512],
            )
            .unwrap();

        let (tx_unauth, _) = tx_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let tx_action_effect = compute_action_effect_from_action(&tx_unauth.actions()[0]);
        let transfer_sighash = compute_tx_auth_digest(
            devnet_chain_id,
            1, // OrchardTransfer
            1, // tx_version
            fee_atoms,
            tx_unauth.flag_byte(),
            *tx_unauth.value_balance(),
            tx_unauth.anchor().to_bytes(),
            &[tx_action_effect],
        );

        let tx_proven = tx_unauth.create_proof(pk, &mut rng).unwrap();
        let transfer_bundle = tx_proven
            .apply_signatures(
                &mut rng,
                transfer_sighash,
                &[SpendAuthorizingKey::from(&miner_sk)],
            )
            .unwrap();

        TestFixtures {
            miner_address,
            user_address,
            coinbase_bundle,
            coinbase_sighash: cb_sighash,
            transfer_bundle,
            transfer_sighash,
            devnet_chain_id,
            testnet_chain_id,
        }
    })
}

// ---------------------------------------------------------------------------
// Phase 2A — Valid Orchard V2 Transfer
// ---------------------------------------------------------------------------

#[test]
fn test_valid_orchard_v2_transfer() {
    let f = get_fixtures();
    let vk = get_verifying_key();
    let bundle = &f.transfer_bundle;

    // 1. Proof validity under FixedPostNu6_2
    assert!(bundle.verify_proof(vk).is_ok());

    // 2. Spend authorization signature verification
    for action in bundle.actions() {
        assert_eq!(
            action
                .rk()
                .verify(&f.transfer_sighash, action.authorization()),
            Ok(())
        );
    }

    // 3. Binding signature verification
    let bvk = bundle.binding_validating_key();
    assert_eq!(
        bvk.verify(
            &f.transfer_sighash,
            bundle.authorization().binding_signature()
        ),
        Ok(())
    );

    // 4. BatchValidator pass
    let mut rng = rand::rngs::StdRng::seed_from_u64(999);
    let mut batch = BatchValidator::new(vk);
    batch
        .add_bundle(bundle, f.transfer_sighash)
        .expect("Batch add");
    assert!(batch.validate(&mut rng));

    // 5. Canonical serialization and round trip
    let raw = serialize_bundle(bundle);
    let roundtrip = deserialize_bundle(&raw).expect("Round trip deserialization");

    assert_eq!(roundtrip.actions().len(), bundle.actions().len());
    assert_eq!(*roundtrip.flags(), *bundle.flags());
    assert_eq!(*roundtrip.value_balance(), *bundle.value_balance());
    assert_eq!(*roundtrip.anchor(), *bundle.anchor());
    assert_eq!(roundtrip.bundle_version(), bundle.bundle_version());
    assert_eq!(
        roundtrip.authorization().proof().as_ref(),
        bundle.authorization().proof().as_ref()
    );

    // Proof and signatures on round-tripped bundle remain completely valid
    assert!(roundtrip.verify_proof(vk).is_ok());
    assert_eq!(
        roundtrip.binding_validating_key().verify(
            &f.transfer_sighash,
            roundtrip.authorization().binding_signature()
        ),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Phase 2B — Output-only Shielded Coinbase
// ---------------------------------------------------------------------------

#[test]
fn test_output_only_shielded_coinbase() {
    let f = get_fixtures();
    let vk = get_verifying_key();
    let bundle = &f.coinbase_bundle;

    // 1. Spends disabled
    assert_eq!(*bundle.flags(), Flags::SPENDS_DISABLED);
    assert!(!bundle.flags().spends_enabled());
    assert!(bundle.flags().outputs_enabled());

    // 2. Exactly 1 action without padding
    assert_eq!(bundle.actions().len(), 1);

    // 3. Proof validity with FixedPostNu6_2
    assert!(bundle.verify_proof(vk).is_ok());

    // Binding signature check under coinbase authorization digest
    assert_eq!(
        bundle.binding_validating_key().verify(
            &f.coinbase_sighash,
            bundle.authorization().binding_signature()
        ),
        Ok(())
    );

    // Miner address matches expected key derivation
    assert_ne!(f.miner_address, f.user_address);

    // 4. Value balance = -1_000_000_000 (negative of payout)
    assert_eq!(*bundle.value_balance(), -1_000_000_000i64);

    // 5. All-zero OVK recovery
    let zero_ovk = OutgoingViewingKey::from([0u8; 32]);
    let (recovered_note, recovered_addr, _) = bundle
        .recover_output_with_ovk(0, &zero_ovk)
        .expect("Recovery with all-zero OVK");
    assert_eq!(recovered_note.value(), NoteValue::from_raw(1_000_000_000));
    assert_eq!(recovered_addr, f.miner_address);

    // 6. Roundtrip serialization
    let raw = serialize_bundle(bundle);
    let roundtrip = deserialize_bundle(&raw).expect("Coinbase roundtrip");
    assert_eq!(roundtrip.actions().len(), 1);
    assert_eq!(*roundtrip.value_balance(), -1_000_000_000i64);
    assert_eq!(*roundtrip.flags(), Flags::SPENDS_DISABLED);
    assert!(roundtrip.verify_proof(vk).is_ok());
}

// ---------------------------------------------------------------------------
// Phase 2C — Required Negative Cases
// ---------------------------------------------------------------------------

#[test]
fn test_negative_tampered_proof_data() {
    let f = get_fixtures();
    let vk = get_verifying_key();
    let raw = serialize_bundle(&f.transfer_bundle);

    // Mutate one byte in the proof body
    // In ZIP-225 Section 7 order: 1 (action count) + 820 (actions) + 1 (flags) + 8 (value_balance) + 32 (anchor) + 3 (proof length compactSize) = 865
    let mut tampered = raw.clone();
    let proof_offset = 865;
    tampered[proof_offset + 10] ^= 0x55;

    let bundle = deserialize_bundle(&tampered).expect("Deserialization of payload succeeds");
    // Proof verification MUST fail at crate circuit level
    assert!(bundle.verify_proof(vk).is_err());

    // Batch validation MUST fail
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let mut batch = BatchValidator::new(vk);
    batch
        .add_bundle(&bundle, f.transfer_sighash)
        .expect("Add bundle");
    assert!(!batch.validate(&mut rng));
}

#[test]
fn test_negative_non_canonical_proof_length() {
    let f = get_fixtures();
    let raw = serialize_bundle(&f.transfer_bundle);

    // Tamper proof length by appending 1 byte (4993 instead of 4992)
    // Proof length CompactSize is at offset 1 + 820 + 1 + 8 + 32 = 862
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&raw[..862]);
    encode_compact_size(4993, &mut tampered);
    tampered.extend_from_slice(&raw[865..865 + 4992]);
    tampered.push(0x00); // 1 extra byte
    tampered.extend_from_slice(&raw[865 + 4992..]);

    let err = deserialize_bundle(&tampered).unwrap_err();
    assert_eq!(
        err,
        BundleCodecError::Bundle(BundleError::NonCanonicalProofSize {
            expected: 4992,
            actual: 4993,
        })
    );
}

#[test]
fn test_negative_identity_and_invalid_authorization_keys() {
    let f = get_fixtures();
    let bundle = &f.transfer_bundle;
    let action = &bundle.actions()[0];

    // 1. Identity rk point check in Action::from_parts
    let identity_rk = redpallas::VerificationKey::<SpendAuth>::try_from([0u8; 32]).unwrap();
    assert!(identity_rk.is_identity());

    let err = Action::from_parts(
        *action.nullifier(),
        identity_rk,
        *action.cmx(),
        action.encrypted_note().clone(),
        action.cv_net().clone(),
        action.authorization().clone(),
    )
    .unwrap_err();

    assert_eq!(err, ActionFromPartsError::IdentityRk);

    // 2. Invalid non-canonical point encoding for rk
    let invalid_bytes = [0xff; 32];
    assert!(redpallas::VerificationKey::<SpendAuth>::try_from(invalid_bytes).is_err());

    // 3. Valid but mismatched authorization key fails signature verification
    let dummy_rk = f.coinbase_bundle.actions()[0].rk();
    assert_ne!(<[u8; 32]>::from(dummy_rk), <[u8; 32]>::from(action.rk()));
    assert!(dummy_rk
        .verify(&f.transfer_sighash, action.authorization())
        .is_err());
}

#[test]
fn test_negative_duplicate_nullifier_chain_state() {
    let f = get_fixtures();
    let vk = get_verifying_key();
    let bundle = &f.transfer_bundle;
    let nf_bytes = bundle.actions()[0].nullifier().to_bytes();

    // 1. ISOLATED CRATE BEHAVIOR:
    // The Orchard crate's cryptographic proof verifier is completely stateless.
    // If presented with the same valid bundle twice, verify_proof succeeds both times.
    assert!(bundle.verify_proof(vk).is_ok());
    assert!(bundle.verify_proof(vk).is_ok());

    // 2. CHAIN-STATE RULE (HARNESS SIMULATION):
    // NOTE (M1-D gate boundary): This is a harness-level policy simulation.
    // Actual production nullifier set tracking and persistence in ChainState is deferred to M1-E.
    let mut simulated_seen_nullifiers: HashSet<[u8; 32]> = HashSet::new();

    // First block inclusion succeeds
    assert!(simulated_seen_nullifiers.insert(nf_bytes));

    // Attempting to include the same nullifier again MUST be rejected by chain-state rule
    let is_duplicate = !simulated_seen_nullifiers.insert(nf_bytes);
    assert!(
        is_duplicate,
        "Chain-state policy must reject duplicate nullifier"
    );
}

#[test]
fn test_negative_unknown_historical_anchor() {
    let f = get_fixtures();
    let vk = get_verifying_key();
    let bundle = &f.transfer_bundle;
    let valid_anchor_bytes = bundle.anchor().to_bytes();

    // 1. ISOLATED CRATE BEHAVIOR:
    // The Orchard proof verifier only verifies consistency against the anchor in the bundle.
    // It does NOT know which block headers have occurred on the blockchain.
    assert!(bundle.verify_proof(vk).is_ok());

    // 2. CHAIN-STATE RULE (HARNESS SIMULATION):
    // NOTE (M1-D gate boundary): This is a harness-level policy simulation.
    // Actual production commitment tree root tracking and ancestor anchor checks in ChainState are deferred to M1-E.
    let mut simulated_historical_anchors: HashSet<[u8; 32]> = HashSet::new();
    simulated_historical_anchors.insert(valid_anchor_bytes);

    // Stale or unknown anchor (such as empty tree root for a spend)
    let unknown_anchor_bytes = Anchor::empty_tree().to_bytes();
    assert!(
        !simulated_historical_anchors.contains(&unknown_anchor_bytes),
        "Chain-state policy must reject unknown / non-historical anchor"
    );
}

#[test]
fn test_negative_cross_chain_replay_rejected() {
    let f = get_fixtures();
    let bundle = &f.transfer_bundle;
    let action = &bundle.actions()[0];

    // Transaction was authorized on devnet
    assert_ne!(f.devnet_chain_id, f.testnet_chain_id);

    let action_effect = compute_action_effect_from_action(action);

    // Compute sighash under testnet chain ID
    let testnet_sighash = compute_tx_auth_digest(
        f.testnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(f.transfer_sighash, testnet_sighash);

    // Verification against testnet sighash MUST fail
    assert!(action
        .rk()
        .verify(&testnet_sighash, action.authorization())
        .is_err());
    assert!(bundle
        .binding_validating_key()
        .verify(&testnet_sighash, bundle.authorization().binding_signature())
        .is_err());

    // Batch validation MUST fail
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    let vk = get_verifying_key();
    let mut batch = BatchValidator::new(vk);
    batch
        .add_bundle(bundle, testnet_sighash)
        .expect("Add bundle");
    assert!(!batch.validate(&mut rng));
}

#[test]
fn test_negative_incorrect_fee_value_balance_sign() {
    let f = get_fixtures();
    let bundle = &f.transfer_bundle;

    // Protocol rule: transfer with fee 5_000 has valueBalanceOrchard = +5_000
    assert_eq!(*bundle.value_balance(), 5_000i64);

    // If an attacker negates value balance to -5_000 (claiming value entered pool instead of paying fee):
    // 1. Transaction envelope validation rejects: valueBalanceOrchard != +fee_atoms
    let claimed_fee_atoms = 5_000u64;
    let tampered_vb = -5_000i64;
    assert_ne!(tampered_vb, claimed_fee_atoms as i64);

    // 2. Cryptographic binding check fails:
    // With tampered value balance, the derived BVK fails to verify the existing binding signature!
    let tampered_bundle = Bundle::try_from_parts(
        bundle.actions().clone(),
        *bundle.flags(),
        tampered_vb,
        *bundle.anchor(),
        bundle.authorization().clone(),
        bundle.bundle_version(),
    )
    .expect("Bundle try_from_parts succeeds with valid flags and proof size");

    let tampered_bvk = tampered_bundle.binding_validating_key();
    assert!(tampered_bvk
        .verify(
            &f.transfer_sighash,
            bundle.authorization().binding_signature()
        )
        .is_err());
}

// ---------------------------------------------------------------------------
// Phase 2D — Fee and Pool-Balance Convention
// ---------------------------------------------------------------------------

#[test]
fn test_fee_and_pool_balance_convention() {
    let f = get_fixtures();

    // 1. Transfer value balance rule: valueBalanceOrchard == +fee_atoms
    let transfer_fee = 5_000u64;
    assert_eq!(*f.transfer_bundle.value_balance(), transfer_fee as i64);

    // 2. Coinbase value balance rule: valueBalanceOrchard == -payout_atoms
    let coinbase_payout = 1_000_000_000u64;
    assert_eq!(
        *f.coinbase_bundle.value_balance(),
        -(coinbase_payout as i64)
    );

    // 3. Pool balance calculation: pool_balance = -sum(valueBalanceOrchard)
    let mut pool_balance = 0i64; // Genesis is 0

    // Block 1: Coinbase
    pool_balance = pool_balance
        .checked_sub(*f.coinbase_bundle.value_balance())
        .unwrap();
    assert_eq!(pool_balance, 1_000_000_000i64); // 10 OWN in pool

    // Block 2: Transfer with 5000 fee
    pool_balance = pool_balance
        .checked_sub(*f.transfer_bundle.value_balance())
        .unwrap();
    assert_eq!(pool_balance, 999_995_000i64); // 5000 left pool for fee

    // Invariants: 0 <= pool_balance <= 2_102_400_000_000_000
    const MAX_POOL_ATOMS: i64 = 2_102_400_000_000_000;
    assert!(pool_balance >= 0);
    assert!(pool_balance <= MAX_POOL_ATOMS);

    // Underflow check: attempting to extract more value than exists in pool
    let invalid_extraction_vb = 2_000_000_000i64; // +20 OWN leaving pool
    let invalid_pool = pool_balance.checked_sub(invalid_extraction_vb).unwrap();
    assert!(
        invalid_pool < 0,
        "Negative pool balance must be rejected by consensus"
    );
}

// ---------------------------------------------------------------------------
// M1-D.1 — Corrected Wire Encoding, Offsets, CompactSize & Digest Tests
// ---------------------------------------------------------------------------

#[test]
fn test_zip225_field_order_and_byte_offsets() {
    let f = get_fixtures();
    let bundle = &f.transfer_bundle;
    let bytes = serialize_bundle(bundle);

    // For 1 action: 1 + 820 + 1 + 8 + 32 + 3 + 4992 + 64 + 64 = 5985 bytes
    assert_eq!(bytes.len(), 5985);

    // 1. Action count as canonical CompactSize (offset 0..1)
    assert_eq!(bytes[0], 0x01);

    // 2. Action descriptions immediately follow action count (offset 1..821)
    let act = &bundle.actions()[0];
    assert_eq!(&bytes[1..33], &act.cv_net().to_bytes());
    assert_eq!(&bytes[33..65], &act.nullifier().to_bytes());
    assert_eq!(&bytes[65..97], &<[u8; 32]>::from(act.rk()));
    assert_eq!(&bytes[97..129], &act.cmx().to_bytes());
    assert_eq!(&bytes[129..161], &act.encrypted_note().epk_bytes);
    assert_eq!(&bytes[161..741], &act.encrypted_note().enc_ciphertext.0);
    assert_eq!(&bytes[741..821], &act.encrypted_note().out_ciphertext);

    // 3. Flags byte (offset 821)
    assert_eq!(bytes[821], bundle.flag_byte());
    assert_eq!(bytes[821], 0x03);

    // 4. valueBalanceOrchard (offset 822..830)
    assert_eq!(&bytes[822..830], &bundle.value_balance().to_le_bytes());
    let vb = i64::from_le_bytes(bytes[822..830].try_into().unwrap());
    assert_eq!(vb, 5_000i64);

    // 5. Anchor (offset 830..862)
    assert_eq!(&bytes[830..862], &bundle.anchor().to_bytes());

    // 6. sizeProofsOrchard CompactSize (offset 862..865)
    // 4992 = 0x1380, canonically encoded as [0xfd, 0x80, 0x13]
    assert_eq!(&bytes[862..865], &[0xfd, 0x80, 0x13]);

    // 7. proofsOrchard (offset 865..5857)
    assert_eq!(&bytes[865..5857], bundle.authorization().proof().as_ref());

    // 8. spendAuthSigsOrchard (offset 5857..5921)
    assert_eq!(&bytes[5857..5921], &<[u8; 64]>::from(act.authorization()));

    // 9. bindingSigOrchard (offset 5921..5985)
    assert_eq!(
        &bytes[5921..5985],
        &<[u8; 64]>::from(bundle.authorization().binding_signature())
    );

    // Deterministic layout verification:
    // If fields are swapped (e.g. putting flags/vb/anchor before action descriptions),
    // deserialization MUST fail.
    let mut permuted_order = Vec::new();
    permuted_order.push(0x01); // action count
    permuted_order.push(bytes[821]); // flags placed prematurely
    permuted_order.extend_from_slice(&bytes[822..830]); // vb
    permuted_order.extend_from_slice(&bytes[830..862]); // anchor
    permuted_order.extend_from_slice(&bytes[1..821]); // actions
    permuted_order.extend_from_slice(&bytes[862..]); // proof and sigs
    assert!(deserialize_bundle(&permuted_order).is_err());
}

#[test]
fn test_compact_size_rejections() {
    let f = get_fixtures();
    let raw = serialize_bundle(&f.transfer_bundle);

    // 1. Non-minimal 3-byte encoding of value < 253 (e.g. 1 encoded as [0xfd, 0x01, 0x00])
    let mut non_minimal_action_count = Vec::new();
    non_minimal_action_count.extend_from_slice(&[0xfd, 0x01, 0x00]);
    non_minimal_action_count.extend_from_slice(&raw[1..]);
    assert_eq!(
        deserialize_bundle(&non_minimal_action_count).unwrap_err(),
        BundleCodecError::NonCanonicalCompactSize
    );

    // Non-minimal 3-byte encoding of 252: [0xfd, 0xfc, 0x00]
    let mut mut_slice = &[0xfd, 0xfc, 0x00][..];
    assert_eq!(
        decode_compact_size(&mut mut_slice).unwrap_err(),
        BundleCodecError::NonCanonicalCompactSize
    );

    // Minimal 3-byte encoding of 253: [0xfd, 0xfd, 0x00] is valid
    let mut valid_253 = &[0xfd, 0xfd, 0x00][..];
    assert_eq!(decode_compact_size(&mut valid_253).unwrap(), 253);

    // Non-minimal 5-byte encoding of value <= 0xffff: [0xfe, 0xff, 0xff, 0x00, 0x00]
    let mut non_min_fe = &[0xfe, 0xff, 0xff, 0x00, 0x00][..];
    assert_eq!(
        decode_compact_size(&mut non_min_fe).unwrap_err(),
        BundleCodecError::NonCanonicalCompactSize
    );

    // Minimal 5-byte encoding of 0x10000: [0xfe, 0x00, 0x00, 0x01, 0x00] is valid
    let mut valid_65536 = &[0xfe, 0x00, 0x00, 0x01, 0x00][..];
    assert_eq!(decode_compact_size(&mut valid_65536).unwrap(), 65536);

    // Non-minimal 9-byte encoding of value <= 0xffffffff: [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]
    let mut non_min_ff = &[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00][..];
    assert_eq!(
        decode_compact_size(&mut non_min_ff).unwrap_err(),
        BundleCodecError::NonCanonicalCompactSize
    );

    // 2. Non-canonical proof-length encoding:
    // The proof is 4992 bytes (0x1380). Canonical encoding is [0xfd, 0x80, 0x13].
    // If encoded with 5-byte prefix 0xfe: [0xfe, 0x80, 0x13, 0x00, 0x00]
    let mut non_min_proof_len = Vec::new();
    non_min_proof_len.extend_from_slice(&raw[..862]);
    non_min_proof_len.extend_from_slice(&[0xfe, 0x80, 0x13, 0x00, 0x00]);
    non_min_proof_len.extend_from_slice(&raw[865..]);
    assert_eq!(
        deserialize_bundle(&non_min_proof_len).unwrap_err(),
        BundleCodecError::NonCanonicalCompactSize
    );

    // 3. Truncated CompactSize encodings
    let mut trunc_fd = &[0xfd, 0x01][..]; // needs 2 bytes
    assert_eq!(
        decode_compact_size(&mut trunc_fd).unwrap_err(),
        BundleCodecError::UnexpectedEof
    );
    let mut trunc_fe = &[0xfe, 0x01, 0x02][..]; // needs 4 bytes
    assert_eq!(
        decode_compact_size(&mut trunc_fe).unwrap_err(),
        BundleCodecError::UnexpectedEof
    );
    let mut trunc_ff = &[0xff, 0x01, 0x02, 0x03][..]; // needs 8 bytes
    assert_eq!(
        decode_compact_size(&mut trunc_ff).unwrap_err(),
        BundleCodecError::UnexpectedEof
    );

    // 4. Truncated bundle
    assert_eq!(
        deserialize_bundle(&raw[..raw.len() - 10]).unwrap_err(),
        BundleCodecError::UnexpectedEof
    );

    // 5. Trailing bytes
    let mut trailing = raw.clone();
    trailing.push(0xee);
    assert_eq!(
        deserialize_bundle(&trailing).unwrap_err(),
        BundleCodecError::TrailingBytes
    );
}

#[test]
fn test_authorization_digest_mutations_and_invalidation() {
    let f = get_fixtures();
    let bundle = &f.transfer_bundle;
    let action = &bundle.actions()[0];

    let action_effect = compute_action_effect_from_action(action);

    let baseline_sighash = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,     // OrchardTransfer
        1,     // tx_version
        5_000, // fee_atoms
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );

    assert_eq!(baseline_sighash, f.transfer_sighash);
    // Baseline verifies successfully
    assert!(action
        .rk()
        .verify(&baseline_sighash, action.authorization())
        .is_ok());
    assert!(bundle
        .binding_validating_key()
        .verify(
            &baseline_sighash,
            bundle.authorization().binding_signature()
        )
        .is_ok());

    // 1. Mutate chain_id
    let mut mut_chain_id = f.devnet_chain_id;
    mut_chain_id[0] ^= 0x01;
    let sig_mut_chain = compute_tx_auth_digest(
        mut_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_chain);
    assert!(action
        .rk()
        .verify(&sig_mut_chain, action.authorization())
        .is_err());
    assert!(bundle
        .binding_validating_key()
        .verify(&sig_mut_chain, bundle.authorization().binding_signature())
        .is_err());

    // 2. Mutate tx_type (e.g. 0 Coinbase instead of 1 OrchardTransfer)
    let sig_mut_type = compute_tx_auth_digest(
        f.devnet_chain_id,
        0,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_type);
    assert!(action
        .rk()
        .verify(&sig_mut_type, action.authorization())
        .is_err());

    // 3. Mutate tx_version (e.g. 2 instead of 1)
    let sig_mut_ver = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        2,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_ver);
    assert!(action
        .rk()
        .verify(&sig_mut_ver, action.authorization())
        .is_err());

    // 4. Mutate payload_prefix (fee 5_001 instead of 5_000)
    let sig_mut_prefix = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_001,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_prefix);
    assert!(action
        .rk()
        .verify(&sig_mut_prefix, action.authorization())
        .is_err());

    // 5. Mutate bundle_flag_byte (0x02 instead of 0x03)
    let sig_mut_flags = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        0x02,
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_flags);
    assert!(action
        .rk()
        .verify(&sig_mut_flags, action.authorization())
        .is_err());

    // 6. Mutate bundle_value_balance (4_999 instead of 5_000)
    let sig_mut_vb = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        4_999,
        bundle.anchor().to_bytes(),
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_vb);
    assert!(action
        .rk()
        .verify(&sig_mut_vb, action.authorization())
        .is_err());

    // 7. Mutate bundle_anchor
    let mut mut_anchor = bundle.anchor().to_bytes();
    mut_anchor[0] ^= 0x01;
    let sig_mut_anchor = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        mut_anchor,
        &[action_effect],
    );
    assert_ne!(baseline_sighash, sig_mut_anchor);
    assert!(action
        .rk()
        .verify(&sig_mut_anchor, action.authorization())
        .is_err());

    // 8. Mutate committed action-effect fields individually:
    // 8a. Mutate cv_net
    let mut mut_cv = action.cv_net().to_bytes();
    mut_cv[0] ^= 0xff;
    let effect_mut_cv = compute_action_effect(
        &mut_cv,
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_cv);
    let sig_mut_cv = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_cv],
    );
    assert_ne!(baseline_sighash, sig_mut_cv);
    assert!(action
        .rk()
        .verify(&sig_mut_cv, action.authorization())
        .is_err());

    // 8b. Mutate nullifier
    let mut mut_nf = action.nullifier().to_bytes();
    mut_nf[0] ^= 0xff;
    let effect_mut_nf = compute_action_effect(
        &action.cv_net().to_bytes(),
        &mut_nf,
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_nf);
    let sig_mut_nf = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_nf],
    );
    assert_ne!(baseline_sighash, sig_mut_nf);
    assert!(action
        .rk()
        .verify(&sig_mut_nf, action.authorization())
        .is_err());

    // 8c. Mutate rk
    let mut mut_rk = <[u8; 32]>::from(action.rk());
    mut_rk[0] ^= 0xff;
    let effect_mut_rk = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &mut_rk,
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_rk);
    let sig_mut_rk = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_rk],
    );
    assert_ne!(baseline_sighash, sig_mut_rk);
    assert!(action
        .rk()
        .verify(&sig_mut_rk, action.authorization())
        .is_err());

    // 8d. Mutate cmx
    let mut mut_cmx = action.cmx().to_bytes();
    mut_cmx[0] ^= 0xff;
    let effect_mut_cmx = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &mut_cmx,
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_cmx);
    let sig_mut_cmx = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_cmx],
    );
    assert_ne!(baseline_sighash, sig_mut_cmx);
    assert!(action
        .rk()
        .verify(&sig_mut_cmx, action.authorization())
        .is_err());

    // 8e. Mutate epk (valid-point mutation using coinbase action's epk)
    let cb_epk = f.coinbase_bundle.actions()[0].encrypted_note().epk_bytes;
    assert_ne!(cb_epk, action.encrypted_note().epk_bytes);
    let effect_mut_epk = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &cb_epk,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_epk);
    let sig_mut_epk = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_epk],
    );
    assert_ne!(baseline_sighash, sig_mut_epk);
    assert!(action
        .rk()
        .verify(&sig_mut_epk, action.authorization())
        .is_err());

    // 8f. Mutate enc_ciphertext (lead byte)
    let mut mut_enc_lead = action.encrypted_note().enc_ciphertext.0;
    mut_enc_lead[0] ^= 0xff;
    let effect_mut_enc_lead = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &mut_enc_lead,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_enc_lead);
    let sig_mut_enc_lead = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_enc_lead],
    );
    assert_ne!(baseline_sighash, sig_mut_enc_lead);
    assert!(action
        .rk()
        .verify(&sig_mut_enc_lead, action.authorization())
        .is_err());

    // 8g. Mutate enc_ciphertext memo portion (byte 100 within memo range 52..564)
    let mut mut_enc_memo = action.encrypted_note().enc_ciphertext.0;
    mut_enc_memo[100] ^= 0x55;
    let effect_mut_enc_memo = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &mut_enc_memo,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_enc_memo);
    let sig_mut_enc_memo = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_enc_memo],
    );
    assert_ne!(baseline_sighash, sig_mut_enc_memo);
    assert!(action
        .rk()
        .verify(&sig_mut_enc_memo, action.authorization())
        .is_err());

    // 8h. Mutate enc_ciphertext authentication tag portion (byte 570 within 564..580)
    let mut mut_enc_tag = action.encrypted_note().enc_ciphertext.0;
    mut_enc_tag[570] ^= 0xaa;
    let effect_mut_enc_tag = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &mut_enc_tag,
        &action.encrypted_note().out_ciphertext,
    );
    assert_ne!(action_effect, effect_mut_enc_tag);
    let sig_mut_enc_tag = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_enc_tag],
    );
    assert_ne!(baseline_sighash, sig_mut_enc_tag);
    assert!(action
        .rk()
        .verify(&sig_mut_enc_tag, action.authorization())
        .is_err());

    // 8i. Mutate out_ciphertext (byte 10)
    let mut mut_out = action.encrypted_note().out_ciphertext;
    mut_out[10] ^= 0xff;
    let effect_mut_out = compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &mut_out,
    );
    assert_ne!(action_effect, effect_mut_out);
    let sig_mut_out = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[effect_mut_out],
    );
    assert_ne!(baseline_sighash, sig_mut_out);
    assert!(action
        .rk()
        .verify(&sig_mut_out, action.authorization())
        .is_err());
}

#[test]
fn test_ciphertexts_not_covered_by_halo2_proof_alone() {
    let f = get_fixtures();
    let vk = get_verifying_key();
    let bundle = &f.transfer_bundle;
    let action = &bundle.actions()[0];

    // 1. Reconstruct action with mutated enc_ciphertext (e.g. memo portion tampered)
    let mut tampered_enc = action.encrypted_note().enc_ciphertext.0;
    tampered_enc[100] ^= 0x42;
    let tampered_note = TransmittedNoteCiphertext {
        epk_bytes: action.encrypted_note().epk_bytes,
        enc_ciphertext: NoteBytesData(tampered_enc),
        out_ciphertext: action.encrypted_note().out_ciphertext,
    };

    let tampered_action = Action::from_parts(
        *action.nullifier(),
        action.rk().clone(),
        *action.cmx(),
        tampered_note,
        action.cv_net().clone(),
        action.authorization().clone(),
    )
    .expect("Action::from_parts succeeds with valid curve elements");

    let tampered_bundle = Bundle::try_from_parts(
        nonempty::NonEmpty::new(tampered_action),
        *bundle.flags(),
        *bundle.value_balance(),
        *bundle.anchor(),
        bundle.authorization().clone(),
        bundle.bundle_version(),
    )
    .expect("Bundle::try_from_parts succeeds");

    // 2. CRITICAL PROOF: Halo2 circuit proof verification alone DOES NOT detect ciphertext tampering!
    // The Halo2 proof verifies the mathematical relations over commitments, values, and nullifiers,
    // but the ciphertext encryption is external to the circuit.
    assert!(
        tampered_bundle.verify_proof(vk).is_ok(),
        "Halo2 proof verification alone passes despite tampered ciphertext"
    );

    // 3. OwnChain's complete ActionEffect digest binds the ciphertext to authorization:
    let tampered_effect = compute_action_effect_from_action(&tampered_bundle.actions()[0]);
    let baseline_effect = compute_action_effect_from_action(action);
    assert_ne!(
        tampered_effect, baseline_effect,
        "Mutating enc_ciphertext alters the 32-byte action effect digest"
    );

    let tampered_sighash = compute_tx_auth_digest(
        f.devnet_chain_id,
        1,
        1,
        5_000,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &[tampered_effect],
    );
    assert_ne!(tampered_sighash, f.transfer_sighash);

    // 4. Therefore, the original spend authorization signature is cryptographically rejected
    // against the tampered transaction authorization digest:
    assert!(
        action
            .rk()
            .verify(&tampered_sighash, action.authorization())
            .is_err(),
        "Spend authorization signature rejects tampered ciphertext digest"
    );

    // 5. And the binding signature is also rejected against the tampered digest:
    assert!(
        tampered_bundle
            .binding_validating_key()
            .verify(
                &tampered_sighash,
                bundle.authorization().binding_signature()
            )
            .is_err(),
        "Binding signature rejects tampered ciphertext digest"
    );

    // 6. Separate check for invalid-point encoding for epk:
    let invalid_epk_bytes = [0xff; 32];
    let invalid_epk_note = TransmittedNoteCiphertext {
        epk_bytes: invalid_epk_bytes,
        enc_ciphertext: action.encrypted_note().enc_ciphertext,
        out_ciphertext: action.encrypted_note().out_ciphertext,
    };
    let epk_err = Action::from_parts(
        *action.nullifier(),
        action.rk().clone(),
        *action.cmx(),
        invalid_epk_note,
        action.cv_net().clone(),
        action.authorization().clone(),
    )
    .unwrap_err();
    assert_eq!(epk_err, ActionFromPartsError::InvalidEpk);
}
