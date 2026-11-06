//! Production stateful execution and consensus integration test suite
//! for OwnChain Protocol v1 Type 7: ShieldedToTransparent (Deshielding / Withdrawal).
//!
//! Validates:
//! - Complete stateful execution of Type 7 (ShieldedToTransparent)
//! - Pinned FixedPostNu6_2 Halo2 proof verification
//! - RedPallas SpendAuth and binding signature verification over canonical auth_digest
//! - Anchor verification against the active 10-block ancestor window [max(0, H-10), H-1]
//! - Real and dummy action nullifier processing and double-spend prevention
//! - Shielded pool debit: candidate_pool_balance -= (release_amount + fee_atoms)
//! - Transparent recipient credit: recipient.balance += release_amount
//! - One-block ordinary transfer maturity (same_block_incoming locked)
//! - Recipient guardian protection non-interference on inbound credits
//! - Commitment tree updates for change outputs (Flags::ENABLED vs Flags::OUTPUTS_DISABLED)
//! - Miner fee accumulation and coinbase subsidy accounting
//! - Strict global monetary conservation: T + S = I
//! - Candidate state atomicity and reorganization rollback

use ed25519_dalek::{Signer, SigningKey};
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::{BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Bundle, Proof,
};
use ownchain::{
    account::{derive_address, AccountState},
    block::Block,
    chain::{ChainError, ChainState},
    genesis,
    hash::{self, Hash},
    header::Header,
    merkle,
    orchard_root::empty_commitment_root,
    orchard_tree::EMPTY_ROOTS,
    orchard_tx::{
        compute_type6_bundle_auth_digest, compute_type7_bundle_auth_digest, serialize_bundle,
        OrchardValidationError,
    },
    tx::TX_ENVELOPE_LEN,
    validation::ValidationError,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Test Keypair and Utilities
// ---------------------------------------------------------------------------

fn devnet_chain_id() -> Hash {
    Hash::new([0x42; 32])
}

#[derive(Clone)]
struct TestKeypair {
    signing_key: SigningKey,
    pubkey: [u8; 32],
    address: Hash,
}

impl TestKeypair {
    fn from_seed(seed: u8) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        key_bytes[31] = 0x01; // ensure valid non-weak key
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = derive_address(&pubkey);
        Self {
            signing_key,
            pubkey,
            address,
        }
    }
}

fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

fn make_coinbase(chain_id: Hash, height: u64, miner_addr: Hash, payout: u64) -> Vec<u8> {
    let mut tx = Vec::with_capacity(83);
    tx.push(0); // Type 0: Coinbase
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(&height.to_le_bytes());
    tx.extend_from_slice(miner_addr.as_bytes());
    tx.extend_from_slice(&payout.to_le_bytes());
    tx
}

fn make_transparent_transfer(
    chain_id: Hash,
    sender: &TestKeypair,
    recipient: Hash,
    amount: u128,
    fee_atoms: u64,
    nonce: u64,
) -> Vec<u8> {
    let mut unsigned = Vec::with_capacity(131);
    unsigned.push(1); // Type 1: TransparentTransfer
    unsigned.extend_from_slice(&1u16.to_le_bytes());
    unsigned.extend_from_slice(chain_id.as_bytes());
    unsigned.extend_from_slice(&sender.pubkey);
    unsigned.extend_from_slice(recipient.as_bytes());
    unsigned.extend_from_slice(&amount.to_le_bytes());
    unsigned.extend_from_slice(&fee_atoms.to_le_bytes());
    unsigned.extend_from_slice(&nonce.to_le_bytes());

    let preimage = ownchain::auth::compute_signing_preimage(chain_id, &unsigned);
    let sig = sender.signing_key.sign(&preimage);

    let mut tx = unsigned;
    tx.extend_from_slice(&sig.to_bytes());
    tx
}

fn make_candidate_block(state: &ChainState, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let parent = state.tip().expect("must have parent");
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    let tx_root = merkle::tx_root(&ids);
    let diff = state.expected_difficulty_for_next_block().unwrap_or(1);

    Block {
        header: Header {
            version: 1,
            chain_id: state.chain_id(),
            height,
            parent_block_id: parent.block_id(),
            transaction_root: tx_root,
            orchard_commitment_root: empty_commitment_root(),
            timestamp,
            difficulty: diff,
            nonce: 0,
        },
        transactions,
    }
}

fn make_hybrid_block(state: &ChainState, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let mut dummy_block = make_candidate_block(state, timestamp, transactions);
    let state_root = state
        .simulate_candidate_state_root(&dummy_block)
        .expect("simulation must succeed");
    dummy_block.header.orchard_commitment_root = state_root;
    dummy_block
}

/// Sets up a funded chain at height 101:
/// - Miner has mature coinbase balance
/// - Alice is credited with 800,000,000 atoms at height 101
/// - Alice's funds mature at height 102
fn setup_funded_chain() -> (ChainState, TestKeypair, TestKeypair, u64) {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    let cb1 = make_coinbase(id, 1, miner.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }

    // Fund Alice with 800M atoms at height 101
    ts += 120;
    let fund_tx = make_transparent_transfer(id, &miner, alice.address, 800_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund_tx]);
    state.apply_block(&b101).unwrap();

    (state, miner, alice, ts)
}

// ---------------------------------------------------------------------------
// Shared Fixtures for Fast Cryptographic Proving
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct TestFixtures {
    pk: ProvingKey,
    vk: VerifyingKey,
    user_sk: SpendingKey,
    user_fvk: FullViewingKey,
    user_address: orchard::Address,
    user_ovk: OutgoingViewingKey,

    // 100M note fixtures (for Type 7 with change)
    seed_note_100m: Note,
    seed_cmx_100m: ExtractedNoteCommitment,
    seed_anchor_100m: Anchor,
    seed_path_100m: MerklePath,
    type6_proven_100m: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type7_proven_with_change: Bundle<InProgress<Proof, Unauthorized>, i64>,

    // 50M note fixtures (for Type 7 outputs disabled)
    seed_note_50m: Note,
    seed_cmx_50m: ExtractedNoteCommitment,
    seed_anchor_50m: Anchor,
    seed_path_50m: MerklePath,
    type6_proven_50m: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type7_proven_outputs_disabled: Bundle<InProgress<Proof, Unauthorized>, i64>,

    // 2-action bundle with duplicate spends
    type7_proven_dup_spends: Bundle<InProgress<Proof, Unauthorized>, i64>,
}

static FIXTURES: OnceLock<TestFixtures> = OnceLock::new();

fn get_fixtures() -> &'static TestFixtures {
    FIXTURES.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(1337);
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);

        let user_sk = SpendingKey::from_bytes([0xbb; 32]).unwrap();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);
        let user_ovk = OutgoingViewingKey::from([0x11; 32]);

        // 1. Build 100M Type 6 seed bundle
        let mut b6_100m = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .unwrap();
        b6_100m
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(100_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth6_100m, meta6_100m) = b6_100m.build::<i64>(&mut rng).unwrap().unwrap();
        let seed_note_100m = unauth6_100m
            .recover_output_with_ovk(meta6_100m.output_action_index(0).unwrap(), &user_ovk)
            .unwrap()
            .0;
        let seed_cmx_100m: ExtractedNoteCommitment = seed_note_100m.commitment().into();
        let (seed_anchor_100m, seed_path_100m) = single_leaf_witness(&seed_cmx_100m);
        let type6_proven_100m = unauth6_100m.create_proof(&pk, &mut rng).unwrap();

        // 2. Build Type 7 bundle with change:
        // Spends 100M note, releases 60M + 1M fee, returns 39_000_000 change
        let mut b7_change = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            seed_anchor_100m,
        )
        .unwrap();
        b7_change
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m.clone())
            .unwrap();
        b7_change
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(39_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth7_change, _) = b7_change.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_proven_with_change = unauth7_change.create_proof(&pk, &mut rng).unwrap();

        // 3. Build 50M Type 6 seed bundle
        let mut b6_50m = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .unwrap();
        b6_50m
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(50_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth6_50m, meta6_50m) = b6_50m.build::<i64>(&mut rng).unwrap().unwrap();
        let seed_note_50m = unauth6_50m
            .recover_output_with_ovk(meta6_50m.output_action_index(0).unwrap(), &user_ovk)
            .unwrap()
            .0;
        let seed_cmx_50m: ExtractedNoteCommitment = seed_note_50m.commitment().into();
        let (seed_anchor_50m, seed_path_50m) = single_leaf_witness(&seed_cmx_50m);
        let type6_proven_50m = unauth6_50m.create_proof(&pk, &mut rng).unwrap();

        // 4. Build Type 7 bundle with outputs disabled:
        // Spends 50M note, releases 49_000_000 + 1M fee, NO outputs added
        let mut b7_no_out = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::OUTPUTS_DISABLED,
            seed_anchor_50m,
        )
        .unwrap();
        b7_no_out
            .add_spend(user_fvk.clone(), seed_note_50m, seed_path_50m.clone())
            .unwrap();
        let (unauth7_no_out, _) = b7_no_out.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_proven_outputs_disabled = unauth7_no_out.create_proof(&pk, &mut rng).unwrap();

        // 5. Build 2-action bundle spending seed_note_100m twice (duplicate nullifiers)
        let mut b7_dup = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            seed_anchor_100m,
        )
        .unwrap();
        b7_dup
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m.clone())
            .unwrap();
        b7_dup
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m.clone())
            .unwrap();
        b7_dup
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(139_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth7_dup, _) = b7_dup.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_proven_dup_spends = unauth7_dup.create_proof(&pk, &mut rng).unwrap();

        TestFixtures {
            pk,
            vk,
            user_sk,
            user_fvk,
            user_address,
            user_ovk,
            seed_note_100m,
            seed_cmx_100m,
            seed_anchor_100m,
            seed_path_100m,
            type6_proven_100m,
            type7_proven_with_change,
            seed_note_50m,
            seed_cmx_50m,
            seed_anchor_50m,
            seed_path_50m,
            type6_proven_50m,
            type7_proven_outputs_disabled,
            type7_proven_dup_spends,
        }
    })
}

// ---------------------------------------------------------------------------
// Transaction Constructors
// ---------------------------------------------------------------------------

fn make_type6_tx(
    chain_id: Hash,
    sender: &TestKeypair,
    nonce: u64,
    shielded_amount: u64,
    fee_atoms: u64,
    proven_bundle: &Bundle<InProgress<Proof, Unauthorized>, i64>,
) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(42);
    let auth_digest = compute_type6_bundle_auth_digest(
        *chain_id.as_bytes(),
        1u16,
        sender.pubkey,
        nonce,
        shielded_amount as u128,
        fee_atoms,
        proven_bundle,
    );
    let authorized_bundle = proven_bundle
        .clone()
        .apply_signatures(&mut rng, auth_digest, &[])
        .unwrap();
    let bundle_bytes = serialize_bundle(&authorized_bundle);
    let sender_sig = sender.signing_key.sign(&auth_digest).to_bytes();

    let mut raw_tx = Vec::new();
    raw_tx.push(6u8); // Type 6
    raw_tx.extend_from_slice(&1u16.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());

    raw_tx.extend_from_slice(&sender.pubkey);
    raw_tx.extend_from_slice(&nonce.to_le_bytes());
    raw_tx.extend_from_slice(&(shielded_amount as u128).to_le_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);
    raw_tx.extend_from_slice(&sender_sig);
    raw_tx.push(0); // 0 guardian signatures for unprotected sender
    raw_tx
}

fn make_type7_tx(
    chain_id: Hash,
    user_sk: &SpendingKey,
    recipient: Hash,
    release_amount: u128,
    fee_atoms: u64,
    proven_bundle: &Bundle<InProgress<Proof, Unauthorized>, i64>,
) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(99);
    let auth_digest = compute_type7_bundle_auth_digest(
        *chain_id.as_bytes(),
        1u16,
        *recipient.as_bytes(),
        release_amount,
        fee_atoms,
        proven_bundle,
    );
    let spend_auth_key = SpendAuthorizingKey::from(user_sk);
    let spend_auth_keys: Vec<SpendAuthorizingKey> = (0..proven_bundle.actions().len())
        .map(|_| spend_auth_key.clone())
        .collect();
    let authorized_bundle = proven_bundle
        .clone()
        .apply_signatures(&mut rng, auth_digest, &spend_auth_keys)
        .unwrap();
    let bundle_bytes = serialize_bundle(&authorized_bundle);

    let mut raw_tx = Vec::new();
    raw_tx.push(7u8); // Type 7
    raw_tx.extend_from_slice(&1u16.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());

    raw_tx.extend_from_slice(recipient.as_bytes());
    raw_tx.extend_from_slice(&release_amount.to_le_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);
    raw_tx
}

// ---------------------------------------------------------------------------
// 1. Positive Tests: Valid Type 7 Withdrawal
// ---------------------------------------------------------------------------

#[test]
fn test_1_valid_type7_withdrawal_with_change() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Block 102: Alice shields 100M atoms via Type 6
    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t6]);
    state.apply_block(&b102).unwrap();

    assert_eq!(state.shielded_pool_balance(), 100_000_000);
    assert_eq!(
        state.orchard_tree().root(),
        Hash::new(fixtures.seed_anchor_100m.to_bytes())
    );

    // Block 103: Type 7 withdrawal with change output
    ts += 120;
    let release_amount = 60_000_000u128;
    let fee_atoms = 1_000_000u64;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        release_amount,
        fee_atoms,
        &fixtures.type7_proven_with_change,
    );
    let cb103 = make_coinbase(id, 103, miner.address, fee_atoms);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7]);
    state.apply_block(&b103).unwrap();

    // Verify recipient state
    let bob_acc = state.account(&bob.address).unwrap();
    assert_eq!(bob_acc.balance, release_amount);
    assert_eq!(bob_acc.nonce, 0); // Nonce unchanged on receipt

    // Verify shielded pool balance: 100M - (60M + 1M) = 39_000_000
    assert_eq!(state.shielded_pool_balance(), 39_000_000);

    // Verify commitment tree updated with change output (now 2 leaves)
    assert_eq!(state.orchard_tree().count(), 2);

    // Verify nullifier added
    assert_eq!(state.nullifier_set().len(), 1);

    // Verify conservation: T + S = I
    let t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
    let s_total = state.shielded_pool_balance();
    let i_total = state.cumulative_issuance();
    assert_eq!(t_total + s_total, i_total);
}

#[test]
fn test_2_valid_type7_withdrawal_outputs_disabled() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Block 102: Alice shields 50M atoms via Type 6
    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        50_000_000,
        1_000_000,
        &fixtures.type6_proven_50m,
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t6]);
    state.apply_block(&b102).unwrap();

    assert_eq!(state.shielded_pool_balance(), 50_000_000);

    // Block 103: Type 7 withdrawal with OUTPUTS_DISABLED (entire note consumed)
    ts += 120;
    let release_amount = 49_000_000u128;
    let fee_atoms = 1_000_000u64;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        release_amount,
        fee_atoms,
        &fixtures.type7_proven_outputs_disabled,
    );
    let cb103 = make_coinbase(id, 103, miner.address, fee_atoms);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7]);
    state.apply_block(&b103).unwrap();

    // Verify recipient state
    let bob_acc = state.account(&bob.address).unwrap();
    assert_eq!(bob_acc.balance, release_amount);

    // Verify pool balance is 0
    assert_eq!(state.shielded_pool_balance(), 0);

    // Verify commitment tree did NOT append dummy note (leaf count remains 1)
    assert_eq!(state.orchard_tree().count(), 1);

    // Verify conservation: T + S = I
    let t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
    assert_eq!(t_total, state.cumulative_issuance());
}

// ---------------------------------------------------------------------------
// 2. Cryptographic Rejection Tests (Proof, SpendAuth, Binding, Anchor)
// ---------------------------------------------------------------------------

#[test]
fn test_3_invalid_halo2_proof_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    let mut bad_t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // Corrupt Halo2 proof bytes inside bundle (located ~500 bytes before end)
    let bad_idx = bad_t7.len() - 500;
    bad_t7[bad_idx] ^= 0xff;

    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, bad_t7]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(matches!(
        err,
        ChainError::Invalid(ValidationError::InvalidOrchardTransaction {
            error: OrchardValidationError::ProofVerificationFailed(_),
            ..
        })
    ));
}

#[test]
fn test_4_invalid_spend_auth_sig_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    let mut bad_t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // Corrupt spend auth signature (located 64..128 bytes before end)
    let bad_idx = bad_t7.len() - 100;
    bad_t7[bad_idx] ^= 0x01;

    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, bad_t7]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(matches!(
        err,
        ChainError::Invalid(ValidationError::InvalidOrchardTransaction {
            error: OrchardValidationError::SpendAuthSignatureInvalid { action_index: 0 },
            ..
        })
    ));
}

#[test]
fn test_5_invalid_binding_sig_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    let mut bad_t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // Corrupt binding signature (last 64 bytes)
    let bad_idx = bad_t7.len() - 32;
    bad_t7[bad_idx] ^= 0x01;

    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, bad_t7]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(matches!(
        err,
        ChainError::Invalid(ValidationError::InvalidOrchardTransaction {
            error: OrchardValidationError::BindingSignatureInvalid,
            ..
        })
    ));
}

#[test]
fn test_6_invalid_anchor_not_in_tree_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, _alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Directly set shielded pool balance to 100M without adding seed_anchor to tree
    state.shielded_pool_balance = 100_000_000;
    state.cumulative_issuance += 100_000_000;

    ts += 120;
    // type7_proven_with_change references seed_anchor_100m, which was never committed to this state's tree
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t7]);

    let err = state.simulate_candidate_state_root(&b102).unwrap_err();
    assert!(err.to_string().contains("not in 10-block ancestor window"));
}

#[test]
fn test_7_anchor_outside_10_block_window_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Block 102: Anchor committed at height 102
    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    // Block 103: Advance commitment tree root so root changes from seed_anchor_100m
    ts += 120;
    let t6_b = make_type6_tx(
        id,
        &alice,
        1,
        50_000_000,
        1_000_000,
        &fixtures.type6_proven_50m,
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 1_000_000), t6_b],
    );
    state.apply_block(&b103).unwrap();

    // Mine 10 empty blocks (heights 104..=113)
    for h in 104..=113 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }
    assert_eq!(state.tip_height().unwrap(), 113);

    // Attempt to spend at height 114 using height 102 anchor (window is [104, 113])
    ts += 120;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let cb114 = make_coinbase(id, 114, miner.address, 1_000_000);
    let b114 = make_candidate_block(&state, ts, vec![cb114, t7]);

    let err = state.simulate_candidate_state_root(&b114).unwrap_err();
    assert!(err.to_string().contains("not in 10-block ancestor window"));
}

// ---------------------------------------------------------------------------
// 3. Balance and Monetary Overflow Tests
// ---------------------------------------------------------------------------

#[test]
fn test_8_insufficient_shielded_pool_balance_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Block 102: Alice shields 50M (fixtures 50M)
    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        50_000_000,
        1_000_000,
        &fixtures.type6_proven_50m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();
    assert_eq!(state.shielded_pool_balance(), 50_000_000);

    // In block 103, manually reduce pool balance to 10M to test underflow check
    state.shielded_pool_balance = 10_000_000;
    // Keep T + S = I consistent for simulation
    state.cumulative_issuance -= 40_000_000;

    ts += 120;
    // t7 requires 49_000_000 + 1_000_000 = 50_000_000 > 10_000_000
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        49_000_000,
        1_000_000,
        &fixtures.type7_proven_outputs_disabled,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t7]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(err
        .to_string()
        .contains("insufficient shielded pool balance"));
}

#[test]
fn test_9_incorrect_value_balance_rejected() {
    let fixtures = get_fixtures();
    let (_state, _miner, _alice, _ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    let mut t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // Mutate release_amount on wire so it does not match bundle value balance (61M expected)
    t7[TX_ENVELOPE_LEN + 32] ^= 0x01;

    let err = ownchain::orchard_tx::validate_type7_transaction_stateless(&t7, id, &fixtures.vk)
        .unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Type7ValueBalanceMismatch { .. }
    ));
}

#[test]
fn test_10_zero_release_amount_rejected() {
    let fixtures = get_fixtures();
    let (_state, _miner, _alice, _ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    let mut t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // Zero out release_amount
    t7[TX_ENVELOPE_LEN + 32..TX_ENVELOPE_LEN + 48].fill(0);

    let err = ownchain::orchard_tx::validate_type7_transaction_stateless(&t7, id, &fixtures.vk)
        .unwrap_err();
    assert!(matches!(err, OrchardValidationError::ZeroReleaseAmount));
}

#[test]
fn test_11_amount_arithmetic_overflow_rejected() {
    let fixtures = get_fixtures();
    let (_state, _miner, _alice, _ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    let mut t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // Set release_amount to u128::MAX
    t7[TX_ENVELOPE_LEN + 32..TX_ENVELOPE_LEN + 48].fill(0xff);

    let err = ownchain::orchard_tx::validate_type7_transaction_stateless(&t7, id, &fixtures.vk)
        .unwrap_err();
    assert!(matches!(err, OrchardValidationError::MonetaryOverflow));
}

#[test]
fn test_12_recipient_balance_overflow_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    // Set Bob's balance to near u128::MAX so adding 60M overflows
    state.accounts.entry(bob.address).or_default().balance = u128::MAX - 1000;

    ts += 120;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t7]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(err.to_string().contains("recipient balance overflow"));
}

// ---------------------------------------------------------------------------
// 4. Nullifier Double-Spend and Tracking Tests
// ---------------------------------------------------------------------------

#[test]
fn test_13_duplicate_nullifiers_within_tx_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    // Fund additional pool balance for 2-action bundle
    state.shielded_pool_balance += 100_000_000;
    state.cumulative_issuance += 100_000_000;

    ts += 120;
    let t7_dup = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_dup_spends,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t7_dup]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(err
        .to_string()
        .contains("duplicate nullifier within transaction"));
}

#[test]
fn test_14_nullifier_already_consumed_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    // Block 103: Consume the nullifier
    ts += 120;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 1_000_000), t7.clone()],
    );
    state.apply_block(&b103).unwrap();

    // Block 104: Attempt to reuse the consumed nullifier in a new transaction to Charlie
    ts += 120;
    let t7_double_spend = make_type7_tx(
        id,
        &fixtures.user_sk,
        charlie.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let cb104 = make_coinbase(id, 104, miner.address, 1_000_000);
    let b104 = make_candidate_block(&state, ts, vec![cb104, t7_double_spend]);

    let err = state.simulate_candidate_state_root(&b104).unwrap_err();
    assert!(err.to_string().contains("nullifier double-spend"));
}

#[test]
fn test_15_duplicate_nullifiers_across_txs_in_block_rejected() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    // Two distinct txs with different recipients, but identical nullifiers
    let t7_a = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let t7_b = make_type7_tx(
        id,
        &fixtures.user_sk,
        charlie.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );

    let cb103 = make_coinbase(id, 103, miner.address, 2_000_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t7_a, t7_b]);

    let err = state.simulate_candidate_state_root(&b103).unwrap_err();
    assert!(err.to_string().contains("nullifier double-spend"));
}

#[test]
fn test_16_dummy_spend_nullifier_handling() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        50_000_000,
        1_000_000,
        &fixtures.type6_proven_50m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        49_000_000,
        1_000_000,
        &fixtures.type7_proven_outputs_disabled,
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 1_000_000), t7],
    );
    state.apply_block(&b103).unwrap();

    // Verify nullifier is tracked in chain state
    let action_nf = Hash::new(
        fixtures.type7_proven_outputs_disabled.actions()[0]
            .nullifier()
            .to_bytes(),
    );
    assert!(state.nullifier_set().contains(&action_nf));
}

// ---------------------------------------------------------------------------
// 5. Commitment Tree, Fees, and Maturity Accounting Tests
// ---------------------------------------------------------------------------

#[test]
fn test_17_commitment_tree_and_anchor_update() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    // Tree before Type 7 has 1 leaf
    assert_eq!(state.orchard_tree().count(), 1);

    ts += 120;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 1_000_000), t7],
    );
    state.apply_block(&b103).unwrap();

    // Tree after Type 7 with change output has 2 leaves
    assert_eq!(state.orchard_tree().count(), 2);

    // Anchor at height 103 matches the new tree root
    let root103 = state.orchard_tree().root();
    assert_eq!(
        state.historical_anchors().get(&103).copied().unwrap(),
        root103
    );
}

#[test]
fn test_18_fee_and_miner_accounting() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    let miner_bal_before = state.account(&miner.address).unwrap().balance;

    ts += 120;
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );

    // Miner claims scheduled subsidy (0 at h>100) + 1_000_000 fee
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7]);
    state.apply_block(&b103).unwrap();

    let miner_bal_after = state.account(&miner.address).unwrap().balance;
    assert_eq!(miner_bal_after - miner_bal_before, 1_000_000);
}

#[test]
fn test_19_same_block_received_funds_cannot_be_spent() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    // 1. Bob receives 60M via Type 7 in block 103 (fee 1M)
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    // 2. Bob attempts to spend 10M via Type 1 in the SAME block 103 (fee 20k)
    let t1_bad = make_transparent_transfer(id, &bob, charlie.address, 10_000_000, 20_000, 0);

    let cb103 = make_coinbase(id, 103, miner.address, 1_020_000);
    let b103_invalid = make_candidate_block(&state, ts, vec![cb103, t7.clone(), t1_bad]);

    let err = state
        .simulate_candidate_state_root(&b103_invalid)
        .unwrap_err();
    assert!(err.to_string().contains("insufficient spendable balance"));

    // Apply valid block 103 with only Type 7
    let cb103_valid = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103_valid = make_hybrid_block(&state, ts, vec![cb103_valid, t7]);
    state.apply_block(&b103_valid).unwrap();

    // At block 104, Bob CAN spend the funds
    ts += 120;
    let t1_ok = make_transparent_transfer(id, &bob, charlie.address, 10_000_000, 20_000, 0);
    let cb104 = make_coinbase(id, 104, miner.address, 20_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104, t1_ok]);
    state.apply_block(&b104).unwrap();

    assert_eq!(state.account(&charlie.address).unwrap().balance, 10_000_000);
    assert_eq!(state.account(&bob.address).unwrap().balance, 49_980_000);
}

#[test]
fn test_20_recipient_guardian_protection_does_not_block_inbound() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Setup Bob as a protected account
    let bob_acc = AccountState {
        guardian_enabled: true,
        new_recipient_delay: 10,
        withdrawal_delay: 144,
        ..Default::default()
    };
    state.accounts.insert(bob.address, bob_acc);

    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    // Type 7 credits Bob without any guardian signatures
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7]);

    // Inbound credit succeeds immediately
    state.apply_block(&b103).unwrap();
    let bob_state = state.account(&bob.address).unwrap();
    assert_eq!(bob_state.balance, 60_000_000);
    assert_eq!(bob_state.pending_transfers.len(), 0);
}

// ---------------------------------------------------------------------------
// 6. Conservation, Atomicity, and Rollback Tests
// ---------------------------------------------------------------------------

#[test]
fn test_21_full_monetary_conservation_t_plus_s_equals_i() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    let verify_conservation = |state: &ChainState| {
        let t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
        let s_total = state.shielded_pool_balance();
        let i_total = state.cumulative_issuance();
        assert_eq!(
            t_total + s_total,
            i_total,
            "Conservation violated: T({t_total}) + S({s_total}) != I({i_total})"
        );
    };

    verify_conservation(&state);

    // Block 102: Alice shields 100M via Type 6
    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();
    verify_conservation(&state);

    // Block 103: Deshield 60M via Type 7 with change
    ts += 120;
    let t7_a = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 1_000_000), t7_a],
    );
    state.apply_block(&b103).unwrap();
    verify_conservation(&state);
}

#[test]
fn test_22_state_atomicity_and_reorg_rollback() {
    let fixtures = get_fixtures();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Block 102: Alice shields 100M via Type 6
    ts += 120;
    let t6 = make_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fixtures.type6_proven_100m,
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 1_000_000), t6],
    );
    state.apply_block(&b102).unwrap();

    let snap102 = state.snapshot();
    let pool_before = state.shielded_pool_balance();
    let tip_before = state.tip_height().unwrap();

    // 1. Invalid execution leaves state completely unmodified
    ts += 120;
    let mut bad_t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    bad_t7[TX_ENVELOPE_LEN + 32] ^= 0x01; // corrupt release_amount

    let cb103_invalid = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103_invalid = make_candidate_block(&state, ts, vec![cb103_invalid, bad_t7]);

    assert!(state.apply_block(&b103_invalid).is_err());
    assert_eq!(state.shielded_pool_balance(), pool_before);
    assert_eq!(state.tip_height().unwrap(), tip_before);
    assert_eq!(state.account(&bob.address), None);

    // 2. Valid block 103 applied
    let t7 = make_type7_tx(
        id,
        &fixtures.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fixtures.type7_proven_with_change,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7]);
    state.apply_block(&b103).unwrap();

    assert_eq!(state.tip_height().unwrap(), 103);
    assert_eq!(state.account(&bob.address).unwrap().balance, 60_000_000);
    assert_eq!(state.nullifier_set().len(), 1);

    // 3. Rollback to height 102
    state.rollback_to(102).unwrap();
    assert_eq!(state.tip_height().unwrap(), 102);
    assert_eq!(state.shielded_pool_balance(), snap102.shielded_pool_balance);
    assert_eq!(state.nullifier_set().len(), 0);
    assert_eq!(state.account(&bob.address), None);
    assert_eq!(state.orchard_tree().root(), snap102.orchard_tree.root());
}
