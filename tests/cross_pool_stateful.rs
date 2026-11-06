//! Production stateful execution and consensus integration test suite
//! for OwnChain Protocol v1 Type 6: TransparentToShielded (Shielding).
//!
//! Validates:
//! - Account verification, nonces, freeze states, allowances, and spendable balances
//! - Strict 4-of-7 guardian quorum authorization
//! - Monetary balance conservation: sender debited A + F, pool credited A, fee accumulated F, T + S = I
//! - Orchard commitment tree updates and composite state root binding
//! - Tracking and uniqueness enforcement of action dummy nullifiers
//! - State atomicity on invalid execution
//! - Chain reorg / rollback correctness

use ed25519_dalek::{Signer, SigningKey};
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::{BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendingKey},
    tree::Anchor,
    value::NoteValue,
    Proof,
};
use ownchain::{
    account::derive_address,
    block::Block,
    chain::ChainState,
    genesis,
    hash::{self, Hash},
    header::Header,
    merkle,
    orchard_root::empty_commitment_root,
    orchard_tx::{compute_type6_bundle_auth_digest, serialize_bundle},
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::OnceLock;

static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();

fn get_proving_key() -> &'static ProvingKey {
    PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
}

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

#[allow(clippy::too_many_arguments)]
fn make_configure_guardians(
    chain_id: Hash,
    account: &TestKeypair,
    nonce: u64,
    fee_atoms: u64,
    guardians: &[[u8; 32]; 7],
    new_recipient_delay: u32,
    withdrawal_delay: u32,
    allowance_limit: u128,
    allowance_window_len: u64,
    recovery_key: &[u8; 32],
    guardian_signers: &[(u8, &TestKeypair)],
) -> Vec<u8> {
    let mut unsigned_prefix = Vec::with_capacity(371);
    unsigned_prefix.push(2); // Type 2: ConfigureGuardians
    unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
    unsigned_prefix.extend_from_slice(chain_id.as_bytes());
    unsigned_prefix.extend_from_slice(&account.pubkey);
    unsigned_prefix.extend_from_slice(&nonce.to_le_bytes());
    unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
    for g in guardians {
        unsigned_prefix.extend_from_slice(g);
    }
    unsigned_prefix.extend_from_slice(&new_recipient_delay.to_le_bytes());
    unsigned_prefix.extend_from_slice(&withdrawal_delay.to_le_bytes());
    unsigned_prefix.extend_from_slice(&allowance_limit.to_le_bytes());
    unsigned_prefix.extend_from_slice(&allowance_window_len.to_le_bytes());
    unsigned_prefix.extend_from_slice(recovery_key);

    let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
    let unsigned_tx =
        ownchain::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = ownchain::auth::compute_signing_preimage(chain_id, &unsigned_tx);
    let owner_sig = account.signing_key.sign(&preimage);

    let mut tx = unsigned_prefix;
    tx.extend_from_slice(&owner_sig.to_bytes());
    tx.push(guardian_signers.len() as u8);
    for (idx, signer) in guardian_signers {
        tx.push(*idx);
        let g_sig = signer.signing_key.sign(&preimage);
        tx.extend_from_slice(&g_sig.to_bytes());
    }
    tx
}

fn make_guardian_action(
    chain_id: Hash,
    target: Hash,
    action_type: u8,
    fee_atoms: u64,
    params: &[u8],
    guardian_signers: &[(u8, &TestKeypair)],
) -> Vec<u8> {
    let mut unsigned_prefix = Vec::new();
    unsigned_prefix.push(3); // Type 3: GuardianAction
    unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
    unsigned_prefix.extend_from_slice(chain_id.as_bytes());
    unsigned_prefix.extend_from_slice(target.as_bytes());
    unsigned_prefix.push(action_type);
    unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
    unsigned_prefix.extend_from_slice(&(params.len() as u32).to_le_bytes());
    unsigned_prefix.extend_from_slice(params);

    let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
    let unsigned_tx =
        ownchain::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = ownchain::auth::compute_signing_preimage(chain_id, &unsigned_tx);

    let mut tx = unsigned_prefix;
    tx.push(guardian_signers.len() as u8);
    for (idx, signer) in guardian_signers {
        tx.push(*idx);
        let g_sig = signer.signing_key.sign(&preimage);
        tx.extend_from_slice(&g_sig.to_bytes());
    }
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

fn build_proven_type6_bundle(
    shielded_amount: u64,
    seed: u8,
) -> (
    orchard::Bundle<InProgress<Proof, Unauthorized>, i64>,
    orchard::note::Nullifier,
) {
    let mut rng = StdRng::from_seed([seed; 32]);
    let pk = get_proving_key();

    let recipient_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
    let recipient_fvk = FullViewingKey::from(&recipient_sk);
    let recipient_address = recipient_fvk.address_at(0u32, Scope::External);

    let mut builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .unwrap();

    let ovk = OutgoingViewingKey::from([0x55; 32]);
    builder
        .add_output(
            Some(ovk),
            recipient_address,
            NoteValue::from_raw(shielded_amount),
            [0u8; 512],
        )
        .unwrap();

    let (unauth_bundle, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let nf = *unauth_bundle.actions()[0].nullifier();
    let proven_bundle = unauth_bundle.create_proof(pk, &mut rng).unwrap();
    (proven_bundle, nf)
}

fn build_type6_tx_from_proven(
    chain_id: Hash,
    sender: &TestKeypair,
    nonce: u64,
    shielded_amount: u64,
    fee_atoms: u64,
    proven_bundle: &orchard::Bundle<InProgress<Proof, Unauthorized>, i64>,
    guardian_signers: &[(u8, &TestKeypair)],
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

    raw_tx.push(guardian_signers.len() as u8);
    for (idx, g_kp) in guardian_signers {
        raw_tx.push(*idx);
        let g_sig = g_kp.signing_key.sign(&auth_digest).to_bytes();
        raw_tx.extend_from_slice(&g_sig);
    }

    raw_tx
}

#[allow(clippy::too_many_arguments)]
fn build_valid_type6_tx(
    chain_id: Hash,
    sender: &TestKeypair,
    nonce: u64,
    shielded_amount: u64,
    fee_atoms: u64,
    seed: u8,
    guardian_signers: &[(u8, &TestKeypair)],
) -> Vec<u8> {
    let (proven, _) = build_proven_type6_bundle(shielded_amount, seed);
    build_type6_tx_from_proven(
        chain_id,
        sender,
        nonce,
        shielded_amount,
        fee_atoms,
        &proven,
        guardian_signers,
    )
}

// ===========================================================================
// Test 1: Valid Type 6 Execution on Unprotected Account
// ===========================================================================
#[test]
fn test_valid_type6_execution_unprotected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    // At height 102, Alice's 800M atoms are mature and spendable
    ts += 120;
    let shielded_amount = 50_000_000u64;
    let fee_atoms = 1_000_000u64;

    let (proven_102, nf_102) = build_proven_type6_bundle(shielded_amount, 0x11);
    let t2s =
        build_type6_tx_from_proven(id, &alice, 0, shielded_amount, fee_atoms, &proven_102, &[]);

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t2s]);

    let pre_tree_root = state.orchard_tree().root();
    let pre_issuance = state.cumulative_issuance();
    assert_eq!(state.shielded_pool_balance(), 0);

    state
        .apply_block(&b102)
        .expect("valid Type 6 block must apply");

    // Check Alice account state
    let alice_acc = state.account(&alice.address).expect("Alice must exist");
    assert_eq!(
        alice_acc.balance,
        800_000_000 - (shielded_amount as u128 + fee_atoms as u128)
    );
    assert_eq!(alice_acc.nonce, 1);

    // Check Shielded Pool Balance
    assert_eq!(state.shielded_pool_balance(), shielded_amount as u128);

    // Check Orchard Commitment Tree: root updated with newly appended note commitment
    assert_ne!(state.orchard_tree().root(), pre_tree_root);

    // Check Action Dummy Nullifier Tracking: dummy nullifier from Type 6 is tracked in active nullifier set
    assert_eq!(state.nullifier_set().len(), 1);
    let action_nf = Hash::new(nf_102.to_bytes());
    assert!(state.nullifier_set().contains(&action_nf));

    // Verify nullifier root participates in composite state root
    let expected_nf_root = merkle::nullifier_merkle_root(&[action_nf]);
    assert_eq!(state.nullifier_state_root(), expected_nf_root);
    assert_ne!(state.nullifier_state_root(), merkle::state_empty_root());
    assert_eq!(
        state.composite_state_root(),
        b102.header.orchard_commitment_root
    );

    // Check Global Monetary Conservation: T + S == I
    let mut t_sum = 0u128;
    for acc in state.accounts().values() {
        t_sum += acc.balance;
    }
    let s_sum = state.shielded_pool_balance();
    let i_sum = state.cumulative_issuance();
    assert_eq!(t_sum + s_sum, i_sum);
    assert_eq!(i_sum, pre_issuance); // claimed subsidy was 0 beyond fees
}

// ===========================================================================
// Test 2: Valid Type 6 Execution with 4-of-7 Guardian Protection
// ===========================================================================
#[test]
fn test_valid_type6_execution_guardian_protected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(99);

    // Height 102: Configure guardians on Alice (Type 2)
    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config]);
    state.apply_block(&b102).unwrap();
    assert!(state.account(&alice.address).unwrap().guardian_enabled);
    assert_eq!(state.account(&alice.address).unwrap().nonce, 1);

    // Height 103: Protected Type 6 execution with 4-of-7 guardian signatures
    ts += 120;
    let shielded_amount = 30_000_000u64;
    let fee_atoms = 1_000_000u64;

    let signers = vec![
        (0, &guardian_keys[0]),
        (2, &guardian_keys[2]),
        (4, &guardian_keys[4]),
        (6, &guardian_keys[6]),
    ];
    let t2s = build_valid_type6_tx(id, &alice, 1, shielded_amount, fee_atoms, 0x22, &signers);

    let cb103 = make_coinbase(id, 103, miner.address, fee_atoms);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t2s]);
    state
        .apply_block(&b103)
        .expect("protected Type 6 must apply successfully");

    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.nonce, 2);
    assert_eq!(state.shielded_pool_balance(), shielded_amount as u128);
}

// ===========================================================================
// Test 3: Insufficient Transparent Balance
// ===========================================================================
#[test]
fn test_type6_insufficient_transparent_balance() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    // Alice has 800M atoms; attempts to shield 800M + 1M fee = 801M total cost
    let shielded_amount = 800_000_000u64;
    let fee_atoms = 1_000_000u64;

    let t2s = build_valid_type6_tx(id, &alice, 0, shielded_amount, fee_atoms, 0x33, &[]);

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t2s]);

    let err = state.apply_block(&b102).unwrap_err();
    assert!(err.to_string().contains("insufficient spendable balance"));

    // State Atomicity: Alice balance, nonce, and pool balance must be unchanged
    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.balance, 800_000_000);
    assert_eq!(alice_acc.nonce, 0);
    assert_eq!(state.shielded_pool_balance(), 0);
    assert_eq!(state.tip_height(), Some(101));
}

// ===========================================================================
// Test 4: Incorrect Account Nonce
// ===========================================================================
#[test]
fn test_type6_incorrect_nonce_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let shielded_amount = 20_000_000u64;
    let fee_atoms = 1_000_000u64;

    // Alice nonce is 0, but tx declares nonce 5
    let t2s = build_valid_type6_tx(id, &alice, 5, shielded_amount, fee_atoms, 0x44, &[]);

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t2s]);

    let err = state.apply_block(&b102).unwrap_err();
    assert!(err.to_string().contains("nonce mismatch"));

    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.nonce, 0);
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 5: Frozen Account Rejected
// ===========================================================================
#[test]
fn test_type6_frozen_account_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (20..27).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(98);

    // Height 102: Configure guardians
    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config]);
    state.apply_block(&b102).unwrap();

    // Height 103: Freeze Alice via Type 3 action (action 5 = Freeze, requires 4 guardians)
    ts += 120;
    let freeze_signers = vec![
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
        (3, &guardian_keys[3]),
    ];
    let freeze_action = make_guardian_action(
        id,
        alice.address,
        ownchain::auth::ACTION_FREEZE, // 5: Freeze
        50_000,
        &[],
        &freeze_signers,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 50_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, freeze_action]);
    state.apply_block(&b103).unwrap();
    assert!(state.account(&alice.address).unwrap().is_frozen);

    // Height 104: Frozen Alice attempts Type 6 transaction
    ts += 120;
    let shielded_amount = 10_000_000u64;
    let fee_atoms = 1_000_000u64;
    let signers = vec![
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
        (3, &guardian_keys[3]),
    ];
    let t2s = build_valid_type6_tx(id, &alice, 1, shielded_amount, fee_atoms, 0x55, &signers);

    let cb104 = make_coinbase(id, 104, miner.address, fee_atoms);
    let b104 = make_candidate_block(&state, ts, vec![cb104, t2s]);

    let err = state.apply_block(&b104).unwrap_err();
    assert!(err.to_string().contains("sender account is frozen"));
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 6: Allowance Limit Exhaustion
// ===========================================================================
#[test]
fn test_type6_allowance_limit_exhaustion() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (30..37).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(97);

    // Height 102: Configure guardians with 10M atoms allowance per 10-block window
    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        10_000_000, // 10M allowance limit
        10,         // 10 blocks window
        &recovery.pubkey,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config]);
    state.apply_block(&b102).unwrap();

    // Height 103: Attempt to shield 15M atoms (total cost 16M > 10M limit)
    ts += 120;
    let shielded_amount = 15_000_000u64;
    let fee_atoms = 1_000_000u64;

    let signers = vec![
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
        (3, &guardian_keys[3]),
    ];
    let t2s = build_valid_type6_tx(id, &alice, 1, shielded_amount, fee_atoms, 0x66, &signers);

    let cb103 = make_coinbase(id, 103, miner.address, fee_atoms);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t2s]);

    let err = state.apply_block(&b103).unwrap_err();
    assert!(err.to_string().contains("allowance limit exceeded"));
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 7: Invalid Sender Signature
// ===========================================================================
#[test]
fn test_type6_invalid_sender_signature_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let shielded_amount = 25_000_000u64;
    let fee_atoms = 1_000_000u64;

    let mut t2s = build_valid_type6_tx(id, &alice, 0, shielded_amount, fee_atoms, 0x77, &[]);

    // Corrupt sender signature (sender_sig is immediately before guardian count byte)
    let sig_end = t2s.len() - 1;
    let sig_start = sig_end - 64;
    t2s[sig_start] ^= 0xff; // Flip byte in sender Ed25519 signature

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t2s]);

    let err = state.apply_block(&b102).unwrap_err();
    assert!(
        err.to_string().contains("sender signature")
            || err.to_string().contains("Ed25519")
            || err.to_string().contains("invalid")
    );
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 8: Missing or Insufficient Guardian Quorum (< 4)
// ===========================================================================
#[test]
fn test_type6_insufficient_guardian_quorum_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (40..47).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(96);

    // Height 102: Configure guardians
    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config]);
    state.apply_block(&b102).unwrap();

    // Height 103: Provide only 3 guardian signatures (requires 4)
    ts += 120;
    let shielded_amount = 20_000_000u64;
    let fee_atoms = 1_000_000u64;

    let only_three_signers = vec![
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
    ];
    let t2s = build_valid_type6_tx(
        id,
        &alice,
        1,
        shielded_amount,
        fee_atoms,
        0x88,
        &only_three_signers,
    );

    let cb103 = make_coinbase(id, 103, miner.address, fee_atoms);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t2s]);

    let err = state.apply_block(&b103).unwrap_err();
    assert!(err.to_string().contains("guardian") || err.to_string().contains("quorum"));
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 9: Invalid Guardian Signature
// ===========================================================================
#[test]
fn test_type6_invalid_guardian_signature_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (50..57).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(95);

    // Height 102: Configure guardians
    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config]);
    state.apply_block(&b102).unwrap();

    // Height 103: 4 guardian signatures declared, but one signature is corrupted
    ts += 120;
    let shielded_amount = 20_000_000u64;
    let fee_atoms = 1_000_000u64;

    let signers = vec![
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
        (3, &guardian_keys[3]),
    ];
    let mut t2s = build_valid_type6_tx(id, &alice, 1, shielded_amount, fee_atoms, 0x99, &signers);

    // Corrupt the last guardian signature (last 64 bytes of tx)
    let len = t2s.len();
    t2s[len - 10] ^= 0xaa;

    let cb103 = make_coinbase(id, 103, miner.address, fee_atoms);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t2s]);

    let err = state.apply_block(&b103).unwrap_err();
    assert!(
        err.to_string().contains("guardian") || err.to_string().contains("verification failed")
    );
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 10: Invalid Orchard Halo2 Proof or Binding Signature
// ===========================================================================
#[test]
fn test_type6_invalid_proof_or_binding_sig_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let shielded_amount = 35_000_000u64;
    let fee_atoms = 1_000_000u64;

    let mut t2s = build_valid_type6_tx(id, &alice, 0, shielded_amount, fee_atoms, 0xaa, &[]);

    // Corrupt proof inside bundle slice:
    // Payload starts at 35; bundle length is at 35+64..35+68; bundle bytes follow.
    let bundle_len = u32::from_le_bytes(t2s[35 + 64..35 + 68].try_into().unwrap()) as usize;
    let bundle_slice_start = 35 + 68;
    // Corrupt within proof area
    t2s[bundle_slice_start + bundle_len / 2] ^= 0x55;

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t2s]);

    let err = state.apply_block(&b102).unwrap_err();
    assert!(
        err.to_string().contains("halo2")
            || err.to_string().contains("proof")
            || err.to_string().contains("invalid")
            || err.to_string().contains("bundle")
    );
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 11: Value Balance Mismatch vs Shielded Amount
// ===========================================================================
#[test]
fn test_type6_value_balance_mismatch_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let actual_bundle_amount = 40_000_000u64;
    let fee_atoms = 1_000_000u64;

    // Build valid tx with 40M atoms
    let mut t2s = build_valid_type6_tx(id, &alice, 0, actual_bundle_amount, fee_atoms, 0xbb, &[]);

    // Tamper the declared shielded_amount field in payload from 40M to 50M
    // Payload starts at 35. sender_pubkey: 32 bytes (35..67), nonce: 8 bytes (67..75),
    // shielded_amount: 16 bytes (75..91)
    let fake_amount: u128 = 50_000_000;
    t2s[75..91].copy_from_slice(&fake_amount.to_le_bytes());

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t2s]);

    let err = state.apply_block(&b102).unwrap_err();
    assert!(
        err.to_string().contains("value balance")
            || err.to_string().contains("mismatch")
            || err.to_string().contains("Type6AmountMismatch")
            || err.to_string().contains("signature")
    );
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 12: Commitment Tree Update & Header Root Binding
// ===========================================================================
#[test]
fn test_type6_commitment_tree_and_header_root_binding() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let shielded_amount = 45_000_000u64;
    let fee_atoms = 1_000_000u64;

    let t2s = build_valid_type6_tx(id, &alice, 0, shielded_amount, fee_atoms, 0xcc, &[]);

    let cb102 = make_coinbase(id, 102, miner.address, fee_atoms);
    let mut b102 = make_hybrid_block(&state, ts, vec![cb102, t2s]);

    // 1. Tampered header orchard_commitment_root causes OrchardRootMismatch rejection
    let true_root = b102.header.orchard_commitment_root;
    b102.header.orchard_commitment_root = Hash::new([0xee; 32]);
    let err = state.apply_block(&b102).unwrap_err();
    assert!(
        err.to_string().contains("mismatch") || err.to_string().contains("OrchardRootMismatch")
    );

    // 2. Untampered block applies cleanly
    b102.header.orchard_commitment_root = true_root;
    state
        .apply_block(&b102)
        .expect("correctly committed block must apply");

    // 3. Post-state composite state root strictly matches header
    assert_eq!(state.composite_state_root(), true_root);
}

// ===========================================================================
// Test 13: Pool Accounting & Global Monetary Conservation (T + S = I)
// ===========================================================================
#[test]
fn test_type6_pool_accounting_and_monetary_conservation() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let initial_issuance = state.cumulative_issuance();
    let initial_pool = state.shielded_pool_balance();
    assert_eq!(initial_pool, 0);

    // Block 102: Alice shields 30M atoms
    ts += 120;
    let amount1 = 30_000_000u64;
    let fee1 = 1_000_000u64;
    let t2s_1 = build_valid_type6_tx(id, &alice, 0, amount1, fee1, 0xd1, &[]);
    let cb102 = make_coinbase(id, 102, miner.address, fee1);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t2s_1]);
    state.apply_block(&b102).unwrap();

    assert_eq!(state.shielded_pool_balance(), amount1 as u128);

    // Verify T + S == I after Block 102
    let mut t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
    assert_eq!(
        t_total + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // Block 103: Alice shields another 40M atoms
    ts += 120;
    let amount2 = 40_000_000u64;
    let fee2 = 1_000_000u64;
    let t2s_2 = build_valid_type6_tx(id, &alice, 1, amount2, fee2, 0xd2, &[]);
    let cb103 = make_coinbase(id, 103, miner.address, fee2);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t2s_2]);
    state.apply_block(&b103).unwrap();

    assert_eq!(state.shielded_pool_balance(), (amount1 + amount2) as u128);

    // Verify T + S == I after Block 103
    t_total = state.accounts().values().map(|a| a.balance).sum();
    assert_eq!(
        t_total + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );
    assert_eq!(state.cumulative_issuance(), initial_issuance);
}

// ===========================================================================
// Test 14: Failed Transaction State Atomicity & Reorg Rollback Verification
// ===========================================================================
#[test]
fn test_type6_state_atomicity_and_reorg_rollback() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let pre_rollback_root = state.composite_state_root();
    let pre_rollback_balance = state.account(&alice.address).unwrap().balance;
    let pre_rollback_pool = state.shielded_pool_balance();
    let pre_rollback_tree_root = state.orchard_tree().root();
    assert_eq!(state.tip_height(), Some(101));

    // Block 102: Valid Type 6 transaction applied
    ts += 120;
    let amount = 50_000_000u64;
    let fee = 1_000_000u64;
    let t2s = build_valid_type6_tx(id, &alice, 0, amount, fee, 0xee, &[]);
    let cb102 = make_coinbase(id, 102, miner.address, fee);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t2s]);
    state.apply_block(&b102).unwrap();

    assert_eq!(state.tip_height(), Some(102));
    assert_eq!(state.shielded_pool_balance(), amount as u128);
    assert_eq!(state.account(&alice.address).unwrap().nonce, 1);

    // Perform rollback_to height 101
    state.rollback_to(101).expect("rollback must succeed");

    // Verify complete state restoration
    assert_eq!(state.tip_height(), Some(101));
    assert_eq!(state.shielded_pool_balance(), pre_rollback_pool);
    assert_eq!(
        state.account(&alice.address).unwrap().balance,
        pre_rollback_balance
    );
    assert_eq!(state.account(&alice.address).unwrap().nonce, 0);
    assert_eq!(state.orchard_tree().root(), pre_rollback_tree_root);
    assert_eq!(state.composite_state_root(), pre_rollback_root);
}

// ===========================================================================
// Test 15: Simulation Produces Expected State Root for Valid Type 6 Candidate
// ===========================================================================
#[test]
fn test_simulation_produces_expected_state_root_for_valid_type6() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let amount = 50_000_000u64;
    let fee = 1_000_000u64;
    let t2s = build_valid_type6_tx(id, &alice, 0, amount, fee, 0x5a, &[]);
    let cb = make_coinbase(id, 102, miner.address, fee);

    let mut cand_block = make_candidate_block(&state, ts, vec![cb, t2s]);

    // Candidate simulation succeeds and produces expected root
    let simulated_root = state
        .simulate_candidate_state_root(&cand_block)
        .expect("simulation must succeed for valid candidate block");

    // Pre-state remains unmutated
    assert_eq!(state.tip_height(), Some(101));
    assert_eq!(state.shielded_pool_balance(), 0);

    // Block with simulated root applies cleanly
    cand_block.header.orchard_commitment_root = simulated_root;
    state
        .apply_block(&cand_block)
        .expect("block committing to simulated root must apply");

    assert_eq!(state.tip_height(), Some(102));
    assert_eq!(state.composite_state_root(), simulated_root);
    assert_eq!(state.shielded_pool_balance(), amount as u128);
}

// ===========================================================================
// Test 16: Simulation Rejects Candidate with Corrupted Halo2 Proof
// ===========================================================================
#[test]
fn test_simulation_rejects_corrupted_halo2_proof() {
    let (state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let amount = 50_000_000u64;
    let fee = 1_000_000u64;
    let t2s = build_valid_type6_tx(id, &alice, 0, amount, fee, 0x5b, &[]);
    let cb = make_coinbase(id, 102, miner.address, fee);

    // Corrupt Halo2 proof bytes inside bundle
    let mut bad_t2s = t2s;
    let bundle_len = u32::from_le_bytes(
        bad_t2s[ownchain::tx::TX_ENVELOPE_LEN + 64..ownchain::tx::TX_ENVELOPE_LEN + 68]
            .try_into()
            .unwrap(),
    ) as usize;
    // Mutate byte in Halo2 proof section (proof ends at bundle_len - 128; mutate at -500)
    let proof_idx = ownchain::tx::TX_ENVELOPE_LEN + 68 + bundle_len - 500;
    bad_t2s[proof_idx] ^= 0xff;

    // Recalculate transaction root for candidate block
    let cand_block = make_candidate_block(&state, ts, vec![cb, bad_t2s]);

    let err = state
        .simulate_candidate_state_root(&cand_block)
        .unwrap_err();

    assert!(
        err.to_string().contains("ProofVerificationFailed")
            || err.to_string().to_lowercase().contains("proof")
            || err.to_string().contains("Orchard")
    );
    // Chain state untouched
    assert_eq!(state.tip_height(), Some(101));
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 17: Simulation Rejects Invalid Chain IDs and Invalid Sender Auth
// ===========================================================================
#[test]
fn test_simulation_rejects_invalid_chain_id_and_sender_authorization() {
    let (state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let amount = 50_000_000u64;
    let fee = 1_000_000u64;
    let t2s = build_valid_type6_tx(id, &alice, 0, amount, fee, 0x5c, &[]);
    let cb = make_coinbase(id, 102, miner.address, fee);

    // 1. Invalid chain ID in header rejected by simulation
    let mut cand_bad_chain = make_candidate_block(&state, ts, vec![cb.clone(), t2s.clone()]);
    cand_bad_chain.header.chain_id = Hash::new([0x99; 32]);
    let err_chain = state
        .simulate_candidate_state_root(&cand_bad_chain)
        .unwrap_err();
    assert!(
        matches!(
            err_chain,
            ownchain::chain::ChainError::Invalid(
                ownchain::validation::ValidationError::WrongChainId { .. }
            )
        ) || err_chain
            .to_string()
            .to_lowercase()
            .contains("wrong chain id")
    );

    // 2. Corrupted sender authorization in Type 6 rejected by simulation
    let mut bad_sig_t2s = t2s;
    let bundle_len = u32::from_le_bytes(
        bad_sig_t2s[ownchain::tx::TX_ENVELOPE_LEN + 64..ownchain::tx::TX_ENVELOPE_LEN + 68]
            .try_into()
            .unwrap(),
    ) as usize;
    let sig_idx = ownchain::tx::TX_ENVELOPE_LEN + 68 + bundle_len;
    bad_sig_t2s[sig_idx] ^= 0xaa;

    let cand_bad_sig = make_candidate_block(&state, ts, vec![cb, bad_sig_t2s]);
    let err_sig = state
        .simulate_candidate_state_root(&cand_bad_sig)
        .unwrap_err();
    assert!(
        err_sig.to_string().contains("SenderSignatureInvalid")
            || err_sig.to_string().contains("Signature")
            || err_sig.to_string().contains("Orchard")
    );

    // Chain state untouched
    assert_eq!(state.tip_height(), Some(101));
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ===========================================================================
// Test 18: apply_block Rejects Invalid Candidates Without Mutating Chain State
// ===========================================================================
#[test]
fn test_apply_block_rejects_invalid_candidates_without_mutating_state() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let snap_height = state.tip_height();
    let snap_root = state.composite_state_root();
    let snap_accounts = state.accounts().clone();
    let snap_pool = state.shielded_pool_balance();
    let snap_tree_root = state.orchard_tree().root();
    let snap_issuance = state.cumulative_issuance();
    let snap_tx_ids = state.accepted_transaction_ids().to_vec();

    ts += 120;
    let amount = 50_000_000u64;
    let fee = 1_000_000u64;
    let t2s = build_valid_type6_tx(id, &alice, 0, amount, fee, 0x5d, &[]);
    let cb = make_coinbase(id, 102, miner.address, fee);

    // Case 1: Corrupted Halo2 proof rejected by apply_block
    let mut bad_proof_t2s = t2s.clone();
    let bundle_len = u32::from_le_bytes(
        bad_proof_t2s[ownchain::tx::TX_ENVELOPE_LEN + 64..ownchain::tx::TX_ENVELOPE_LEN + 68]
            .try_into()
            .unwrap(),
    ) as usize;
    let proof_idx = ownchain::tx::TX_ENVELOPE_LEN + 68 + bundle_len - 80;
    bad_proof_t2s[proof_idx] ^= 0xff;
    let bad_proof_block = make_candidate_block(&state, ts, vec![cb.clone(), bad_proof_t2s]);
    assert!(state.apply_block(&bad_proof_block).is_err());

    assert_eq!(state.tip_height(), snap_height);
    assert_eq!(state.composite_state_root(), snap_root);
    assert_eq!(*state.accounts(), snap_accounts);
    assert_eq!(state.shielded_pool_balance(), snap_pool);

    // Case 2: Wrong chain ID rejected by apply_block
    let mut bad_chain_block = make_candidate_block(&state, ts, vec![cb.clone(), t2s.clone()]);
    bad_chain_block.header.chain_id = Hash::new([0x33; 32]);
    assert!(state.apply_block(&bad_chain_block).is_err());

    assert_eq!(state.tip_height(), snap_height);
    assert_eq!(state.composite_state_root(), snap_root);

    // Case 3: Wrong declared orchard commitment root rejected by apply_block
    let mut bad_root_block = make_candidate_block(&state, ts, vec![cb.clone(), t2s.clone()]);
    bad_root_block.header.orchard_commitment_root = Hash::new([0x77; 32]);
    assert!(state.apply_block(&bad_root_block).is_err());

    assert_eq!(state.tip_height(), snap_height);
    assert_eq!(state.composite_state_root(), snap_root);

    // Case 4: Corrupted sender signature rejected by apply_block
    let mut bad_sig_t2s = t2s.clone();
    let sig_idx = ownchain::tx::TX_ENVELOPE_LEN + 68 + bundle_len;
    bad_sig_t2s[sig_idx] ^= 0xff;
    let bad_sig_block = make_candidate_block(&state, ts, vec![cb.clone(), bad_sig_t2s]);
    assert!(state.apply_block(&bad_sig_block).is_err());

    // Case 5: Corrupted SpendAuth signature in Type 6 rejected by apply_block
    let mut bad_auth_t2s = t2s.clone();
    let spend_auth_offset = ownchain::tx::TX_ENVELOPE_LEN + 68 + bundle_len - 128;
    bad_auth_t2s[spend_auth_offset] ^= 0xff;
    let bad_auth_block = make_candidate_block(&state, ts, vec![cb, bad_auth_t2s]);
    assert!(state.apply_block(&bad_auth_block).is_err());

    // Absolute state preservation
    assert_eq!(state.tip_height(), snap_height);
    assert_eq!(state.composite_state_root(), snap_root);
    assert_eq!(*state.accounts(), snap_accounts);
    assert_eq!(state.shielded_pool_balance(), snap_pool);
    assert_eq!(state.orchard_tree().root(), snap_tree_root);
    assert_eq!(state.cumulative_issuance(), snap_issuance);
    assert_eq!(state.accepted_transaction_ids(), snap_tx_ids.as_slice());
}

// ===========================================================================
// Test 19: Type 6 Action Nullifier Accounting & Double-Spend Protection
// ===========================================================================
#[test]
fn test_type6_nullifier_accounting_and_double_spend_protection() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let amount = 50_000_000u64;
    let fee = 1_000_000u64;
    let (proven_bundle, nf) = build_proven_type6_bundle(amount, 0x7a);
    let t2s_a = build_type6_tx_from_proven(id, &alice, 0, amount, fee, &proven_bundle, &[]);
    let cb102 = make_coinbase(id, 102, miner.address, fee);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t2s_a]);
    state.apply_block(&b102).expect("block 102 must apply");

    let action_nf = Hash::new(nf.to_bytes());
    assert_eq!(state.nullifier_set().len(), 1);
    assert!(state.nullifier_set().contains(&action_nf));

    // Verify composite state root strictly incorporates the nullifier root
    let nf_root = merkle::nullifier_merkle_root(&[action_nf]);
    assert_eq!(state.nullifier_state_root(), nf_root);
    assert_ne!(state.nullifier_state_root(), merkle::state_empty_root());
    assert_eq!(
        state.composite_state_root(),
        b102.header.orchard_commitment_root
    );

    // Block 103 candidate attempting to reuse the exact same bundle nullifier in a new tx
    ts += 120;
    let t2s_b = build_type6_tx_from_proven(id, &alice, 1, amount, fee, &proven_bundle, &[]);
    let cb103 = make_coinbase(id, 103, miner.address, fee);
    let b103_cand = make_candidate_block(&state, ts, vec![cb103, t2s_b]);

    let err = state.simulate_candidate_state_root(&b103_cand).unwrap_err();
    assert!(err.to_string().contains("nullifier double-spend"));

    // State remains unmutated
    assert_eq!(state.tip_height().unwrap(), 102);
    assert_eq!(state.nullifier_set().len(), 1);
}
