//! Comprehensive authentication and guardian quorum verification integration tests.
//!
//! Validates:
//! - Exact signing preimage: UTF8("OwnChain/TxAuth/v1") || chain_id[32] || canonical_unsigned_tx_bytes.
//! - Known transparent address derivation vectors from docs/test-vectors-v1-transparent.json.
//! - Guardian metadata binding (quorum count and indices) into all multi-sig transactions.
//! - All nine GuardianAction IDs and their exact required quorums (3-of-7 or 4-of-7).
//! - Invalid signature rejection for every relevant signer (Types 1, 2, 3, 4, 6).
//! - Duplicate and out-of-range guardian index rejections.
//! - Guardian count and index tampering rejections.
//! - Cross-transaction signature transplant rejection.
//! - Type 2 initial setup and old-guardian reconfiguration.
//! - Type 4 sender signature plus 4-of-7 guardian authorization.
//! - Type 6 sender signature and protected-account quorum.
//! - Type 1 legacy Orchard encoding rejection (wire length must be exactly 195).
//! - State atomicity after failed authorization.

use ed25519_dalek::{Signer, SigningKey};
use ownchain::account::derive_address;
use ownchain::auth::{
    canonical_unsigned_with_indices, compute_signing_preimage, ACTION_EMERGENCY_RECOVERY,
    ACTION_FREEZE, ACTION_REPLACE_GUARDIANS, ACTION_REPLACE_RECOVERY_KEY,
    ACTION_STRENGTHEN_ALLOWANCE, ACTION_STRENGTHEN_DELAYS, ACTION_UNFREEZE,
    ACTION_WEAKEN_ALLOWANCE, ACTION_WEAKEN_DELAYS,
};
use ownchain::block::Block;
use ownchain::chain::ChainState;
use ownchain::genesis;
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::orchard_root::empty_commitment_root;

#[derive(Clone)]
struct TestKeypair {
    signing_key: SigningKey,
    pubkey: [u8; 32],
    address: Hash,
}

impl TestKeypair {
    fn from_seed(seed: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = derive_address(&pubkey);
        Self {
            signing_key,
            pubkey,
            address,
        }
    }
}

fn devnet_chain_id() -> Hash {
    hash::chain_id("devnet")
}

fn make_coinbase(chain_id: Hash, height: u64, recipient: Hash, payout: u64) -> Vec<u8> {
    let mut tx = Vec::with_capacity(83);
    tx.push(0); // Type 0
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(&height.to_le_bytes());
    tx.extend_from_slice(recipient.as_bytes());
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
    let mut tx = Vec::with_capacity(195);
    tx.push(1); // Type 1
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(&sender.pubkey);
    tx.extend_from_slice(recipient.as_bytes());
    tx.extend_from_slice(&amount.to_le_bytes());
    tx.extend_from_slice(&fee_atoms.to_le_bytes());
    tx.extend_from_slice(&nonce.to_le_bytes());
    assert_eq!(tx.len(), 131);
    let preimage = compute_signing_preimage(chain_id, &tx[..131]);
    let sig = sender.signing_key.sign(&preimage);
    tx.extend_from_slice(&sig.to_bytes());
    assert_eq!(tx.len(), 195);
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
    unsigned_prefix.push(2); // Type 2
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
    assert_eq!(unsigned_prefix.len(), 371);

    let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
    let unsigned_tx = canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = compute_signing_preimage(chain_id, &unsigned_tx);
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
    unsigned_prefix.push(3); // Type 3
    unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
    unsigned_prefix.extend_from_slice(chain_id.as_bytes());
    unsigned_prefix.extend_from_slice(target.as_bytes());
    unsigned_prefix.push(action_type);
    unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
    unsigned_prefix.extend_from_slice(&(params.len() as u32).to_le_bytes());
    unsigned_prefix.extend_from_slice(params);

    let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
    let unsigned_tx = canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = compute_signing_preimage(chain_id, &unsigned_tx);

    let mut tx = unsigned_prefix;
    tx.push(guardian_signers.len() as u8);
    for (idx, signer) in guardian_signers {
        tx.push(*idx);
        let g_sig = signer.signing_key.sign(&preimage);
        tx.extend_from_slice(&g_sig.to_bytes());
    }
    tx
}

fn make_cancel_pending(
    chain_id: Hash,
    sender: &TestKeypair,
    transfer_id: Hash,
    fee_atoms: u64,
    nonce: u64,
    guardian_signers: &[(u8, &TestKeypair)],
) -> Vec<u8> {
    let mut unsigned_prefix = Vec::with_capacity(115);
    unsigned_prefix.push(4); // Type 4
    unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
    unsigned_prefix.extend_from_slice(chain_id.as_bytes());
    unsigned_prefix.extend_from_slice(&sender.pubkey);
    unsigned_prefix.extend_from_slice(transfer_id.as_bytes());
    unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
    unsigned_prefix.extend_from_slice(&nonce.to_le_bytes());
    assert_eq!(unsigned_prefix.len(), 115);

    let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
    let unsigned_tx = canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = compute_signing_preimage(chain_id, &unsigned_tx);
    let sender_sig = sender.signing_key.sign(&preimage);

    let mut tx = unsigned_prefix;
    tx.extend_from_slice(&sender_sig.to_bytes());
    tx.push(guardian_signers.len() as u8);
    for (idx, signer) in guardian_signers {
        tx.push(*idx);
        let g_sig = signer.signing_key.sign(&preimage);
        tx.extend_from_slice(&g_sig.to_bytes());
    }
    tx
}

fn make_transparent_to_shielded(
    chain_id: Hash,
    sender: &TestKeypair,
    nonce: u64,
    amount: u128,
    fee_atoms: u64,
    bundle_bytes: &[u8],
    guardian_signers: &[(u8, &TestKeypair)],
) -> Vec<u8> {
    let mut unsigned_prefix = Vec::new();
    unsigned_prefix.push(6); // Type 6
    unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
    unsigned_prefix.extend_from_slice(chain_id.as_bytes());
    unsigned_prefix.extend_from_slice(&sender.pubkey);
    unsigned_prefix.extend_from_slice(&nonce.to_le_bytes());
    unsigned_prefix.extend_from_slice(&amount.to_le_bytes());
    unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
    unsigned_prefix.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    unsigned_prefix.extend_from_slice(bundle_bytes);

    let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
    let unsigned_tx = canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = compute_signing_preimage(chain_id, &unsigned_tx);
    let sender_sig = sender.signing_key.sign(&preimage);

    let mut tx = unsigned_prefix;
    tx.extend_from_slice(&sender_sig.to_bytes());
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

    // Fund Alice with 800M atoms
    ts += 120;
    let fund_tx = make_transparent_transfer(id, &miner, alice.address, 800_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund_tx]);
    state.apply_block(&b101).unwrap();

    (state, miner, alice, ts)
}

// ---------------------------------------------------------------------------
// 1. Transparent Address Derivation Regression Tests (docs/protocol-v1.md §7.2)
// ---------------------------------------------------------------------------

#[test]
fn test_known_address_derivation_vectors() {
    // Vector from docs/test-vectors-v1-transparent.json:
    // Alice:
    //   pubkey = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    //   address = 7e62649584947abab19fb34633e990ce49dbbda3e80e7bb6848d88d4928f40d0
    let alice_pk: [u8; 32] =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();
    let alice_addr_expected =
        hex::decode("7e62649584947abab19fb34633e990ce49dbbda3e80e7bb6848d88d4928f40d0").unwrap();
    let derived_alice = derive_address(&alice_pk);
    assert_eq!(derived_alice.as_bytes(), &alice_addr_expected[..]);

    // Bob:
    //   pubkey = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    //   address = 010b76206e2af1dd1b2f84cb9c9f3ebf7d37f7065f1373a71f244a7790369ab4
    let bob_pk: [u8; 32] =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
            .unwrap()
            .try_into()
            .unwrap();
    let bob_addr_expected =
        hex::decode("010b76206e2af1dd1b2f84cb9c9f3ebf7d37f7065f1373a71f244a7790369ab4").unwrap();
    let derived_bob = derive_address(&bob_pk);
    assert_eq!(derived_bob.as_bytes(), &bob_addr_expected[..]);
}

// ---------------------------------------------------------------------------
// 2. Type 1: TransparentTransfer Authentication Tests
// ---------------------------------------------------------------------------

#[test]
fn test_type1_valid_signature_succeeds() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let tx = make_transparent_transfer(id, &alice, miner.address, 100_000_000, 20_000, 0);
    let cb = make_coinbase(id, 102, miner.address, 20_000);
    let block = make_hybrid_block(&state, ts, vec![cb, tx]);
    assert!(state.apply_block(&block).is_ok());

    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.balance, 800_000_000 - 100_000_000 - 20_000);
    assert_eq!(alice_acc.nonce, 1);
}

#[test]
fn test_type1_all_zero_signature_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let mut tx = make_transparent_transfer(id, &alice, miner.address, 100_000_000, 20_000, 0);
    tx[131..195].copy_from_slice(&[0u8; 64]); // dummy/zero signature

    let cb = make_coinbase(id, 102, miner.address, 20_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type1_modified_amount_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let mut tx = make_transparent_transfer(id, &alice, miner.address, 100_000_000, 20_000, 0);
    // Mutate amount from 100M to 200M after signing
    let mutated_amount = 200_000_000u128;
    tx[99..115].copy_from_slice(&mutated_amount.to_le_bytes());

    let cb = make_coinbase(id, 102, miner.address, 20_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type1_modified_recipient_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let mut tx = make_transparent_transfer(id, &alice, miner.address, 100_000_000, 20_000, 0);
    tx[67] ^= 0xff; // Mutate recipient address

    let cb = make_coinbase(id, 102, miner.address, 20_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type1_modified_fee_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let mut tx = make_transparent_transfer(id, &alice, miner.address, 100_000_000, 20_000, 0);
    tx[115..123].copy_from_slice(&50_000u64.to_le_bytes()); // Mutate fee

    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type1_modified_nonce_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let mut tx = make_transparent_transfer(id, &alice, miner.address, 100_000_000, 20_000, 0);
    tx[123..131].copy_from_slice(&1u64.to_le_bytes()); // Mutate nonce to 1

    let cb = make_coinbase(id, 102, miner.address, 20_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type1_wrong_chain_id_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let wrong_id = hash::chain_id("mainnet");

    // Signed for mainnet instead of devnet
    let tx = make_transparent_transfer(wrong_id, &alice, miner.address, 100_000_000, 20_000, 0);

    let cb = make_coinbase(devnet_chain_id(), 102, miner.address, 20_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx]);
    assert!(state.apply_block(&block).is_err());
}

// ---------------------------------------------------------------------------
// 3. Type 2: ConfigureGuardians Authentication & Reconfiguration
// ---------------------------------------------------------------------------

#[test]
fn test_type2_initial_configuration_and_reconfiguration() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let old_guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let old_guardians: [[u8; 32]; 7] = [
        old_guardian_keys[0].pubkey,
        old_guardian_keys[1].pubkey,
        old_guardian_keys[2].pubkey,
        old_guardian_keys[3].pubkey,
        old_guardian_keys[4].pubkey,
        old_guardian_keys[5].pubkey,
        old_guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

    // Initial setup with owner signature only (quorum_count = 0)
    ts += 120;
    let config_tx = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &old_guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb, config_tx]);
    assert!(state.apply_block(&b102).is_ok());

    let alice_acc = state.account(&alice.address).unwrap();
    assert!(alice_acc.guardian_enabled);
    assert_eq!(alice_acc.guardians, old_guardians);
    assert_eq!(alice_acc.nonce, 1);

    // Reconfiguration with 4-of-7 OLD guardians
    let new_guardian_keys: Vec<TestKeypair> = (0x20..0x27).map(TestKeypair::from_seed).collect();
    let new_guardians: [[u8; 32]; 7] = [
        new_guardian_keys[0].pubkey,
        new_guardian_keys[1].pubkey,
        new_guardian_keys[2].pubkey,
        new_guardian_keys[3].pubkey,
        new_guardian_keys[4].pubkey,
        new_guardian_keys[5].pubkey,
        new_guardian_keys[6].pubkey,
    ];

    ts += 120;
    let reconfig_tx = make_configure_guardians(
        id,
        &alice,
        1, // nonce 1
        70_000,
        &new_guardians,
        20,
        288,
        1_000,
        100,
        &recovery.pubkey,
        &[
            (0, &old_guardian_keys[0]),
            (1, &old_guardian_keys[1]),
            (2, &old_guardian_keys[2]),
            (3, &old_guardian_keys[3]),
        ],
    );
    let cb103 = make_coinbase(id, 103, miner.address, 70_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, reconfig_tx]);
    assert!(state.apply_block(&b103).is_ok());

    let alice_reconfigured = state.account(&alice.address).unwrap();
    assert_eq!(alice_reconfigured.guardians, new_guardians);
    assert_eq!(alice_reconfigured.new_recipient_delay, 20);
    assert_eq!(alice_reconfigured.nonce, 2);
}

#[test]
fn test_type2_invalid_owner_sig_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

    let mut config_tx = make_configure_guardians(
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
    config_tx[371..435].copy_from_slice(&[0u8; 64]); // zero owner sig

    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, config_tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type2_duplicate_guardian_keys_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let mut dupe_guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    dupe_guardians[1] = dupe_guardians[0];
    let recovery = TestKeypair::from_seed(0x99);

    let config_tx = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &dupe_guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );

    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, config_tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type2_initial_setup_with_guardian_sigs_rejected() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

    let config_tx = make_configure_guardians(
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
        &[(0, &guardian_keys[0])],
    );

    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, config_tx]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_type2_reconfig_insufficient_or_duplicate_guardians_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let old_guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let old_guardians: [[u8; 32]; 7] = [
        old_guardian_keys[0].pubkey,
        old_guardian_keys[1].pubkey,
        old_guardian_keys[2].pubkey,
        old_guardian_keys[3].pubkey,
        old_guardian_keys[4].pubkey,
        old_guardian_keys[5].pubkey,
        old_guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

    ts += 120;
    let config_tx = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &old_guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb, config_tx]);
    state.apply_block(&b102).unwrap();

    let new_guardian_keys: Vec<TestKeypair> = (0x20..0x27).map(TestKeypair::from_seed).collect();
    let new_guardians: [[u8; 32]; 7] = [
        new_guardian_keys[0].pubkey,
        new_guardian_keys[1].pubkey,
        new_guardian_keys[2].pubkey,
        new_guardian_keys[3].pubkey,
        new_guardian_keys[4].pubkey,
        new_guardian_keys[5].pubkey,
        new_guardian_keys[6].pubkey,
    ];

    // Case A: Insufficient quorum (only 3 of 7 old guardians)
    ts += 120;
    let insufficient_tx = make_configure_guardians(
        id,
        &alice,
        1,
        50_000,
        &new_guardians,
        20,
        288,
        0,
        0,
        &recovery.pubkey,
        &[
            (0, &old_guardian_keys[0]),
            (1, &old_guardian_keys[1]),
            (2, &old_guardian_keys[2]),
        ],
    );
    let cb103 = make_coinbase(id, 103, miner.address, 50_000);
    let bad_block_a = make_candidate_block(&state, ts, vec![cb103.clone(), insufficient_tx]);
    assert!(state.apply_block(&bad_block_a).is_err());

    // Case B: Duplicate index (4 votes, but index 0 repeated)
    let dupe_index_tx = make_configure_guardians(
        id,
        &alice,
        1,
        50_000,
        &new_guardians,
        20,
        288,
        0,
        0,
        &recovery.pubkey,
        &[
            (0, &old_guardian_keys[0]),
            (0, &old_guardian_keys[0]),
            (1, &old_guardian_keys[1]),
            (2, &old_guardian_keys[2]),
        ],
    );
    let bad_block_b = make_candidate_block(&state, ts, vec![cb103, dupe_index_tx]);
    assert!(state.apply_block(&bad_block_b).is_err());
}

// ---------------------------------------------------------------------------
// 4. Type 3: All 9 GuardianAction IDs and Quorum Tests
// ---------------------------------------------------------------------------

#[test]
fn test_all_nine_guardian_actions_and_quorums() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery1 = TestKeypair::from_seed(0x91);
    let recovery2 = TestKeypair::from_seed(0x92);

    // Initial configuration: 10 new_recipient_delay, 144 withdrawal_delay, recovery1
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
        &recovery1.pubkey,
        &[],
    );
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb, config]);
    state.apply_block(&b102).unwrap();

    let g_3 = &[
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
    ];
    let g_4 = &[
        (0, &guardian_keys[0]),
        (1, &guardian_keys[1]),
        (2, &guardian_keys[2]),
        (3, &guardian_keys[3]),
    ];

    // --- Action 1: Strengthen delays (3-of-7 quorum, delay >= current) ---
    ts += 120;
    // Attempting to decrease delay with 3-of-7 fails
    let act1_dec = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        70_000,
        &5u32.to_le_bytes(),
        g_3,
    );
    let cb_fail = make_coinbase(id, 103, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act1_dec]))
        .is_err());
    // Increasing delay with 3-of-7 succeeds
    let act1_good = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        70_000,
        &25u32.to_le_bytes(),
        g_3,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb103, act1_good]))
        .unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().new_recipient_delay,
        25
    );

    // --- Action 2: Strengthen allowance (3-of-7 quorum) ---
    ts += 120;
    let mut param_allowance_tight = Vec::new();
    param_allowance_tight.extend_from_slice(&1_000_000u128.to_le_bytes()); // limit
    param_allowance_tight.extend_from_slice(&200u64.to_le_bytes()); // window len
    let act2_good = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_ALLOWANCE,
        70_000,
        &param_allowance_tight,
        g_3,
    );
    let cb104 = make_coinbase(id, 104, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb104, act2_good]))
        .unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().allowance_limit,
        1_000_000
    );
    assert_eq!(
        state.account(&alice.address).unwrap().allowance_window_len,
        200
    );

    // --- Action 3: Weaken delays (requires 4-of-7 quorum) ---
    ts += 120;
    // 3-of-7 fails
    let act3_insuf = make_guardian_action(
        id,
        alice.address,
        ACTION_WEAKEN_DELAYS,
        70_000,
        &10u32.to_le_bytes(),
        g_3,
    );
    let cb_fail = make_coinbase(id, 105, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act3_insuf]))
        .is_err());
    // 4-of-7 succeeds
    let act3_good = make_guardian_action(
        id,
        alice.address,
        ACTION_WEAKEN_DELAYS,
        70_000,
        &10u32.to_le_bytes(),
        g_4,
    );
    let cb105 = make_coinbase(id, 105, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb105, act3_good]))
        .unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().new_recipient_delay,
        10
    );

    // --- Action 4: Weaken allowance (requires 4-of-7 quorum) ---
    ts += 120;
    let mut param_allowance_weaken = Vec::new();
    param_allowance_weaken.extend_from_slice(&5_000_000u128.to_le_bytes());
    param_allowance_weaken.extend_from_slice(&50u64.to_le_bytes());
    // 3-of-7 fails
    let act4_insuf = make_guardian_action(
        id,
        alice.address,
        ACTION_WEAKEN_ALLOWANCE,
        70_000,
        &param_allowance_weaken,
        g_3,
    );
    let cb_fail = make_coinbase(id, 106, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act4_insuf]))
        .is_err());
    // 4-of-7 succeeds
    let act4_good = make_guardian_action(
        id,
        alice.address,
        ACTION_WEAKEN_ALLOWANCE,
        70_000,
        &param_allowance_weaken,
        g_4,
    );
    let cb106 = make_coinbase(id, 106, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb106, act4_good]))
        .unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().allowance_limit,
        5_000_000
    );
    assert_eq!(
        state.account(&alice.address).unwrap().allowance_window_len,
        50
    );

    // --- Action 5: Freeze account (requires 4-of-7 quorum) ---
    ts += 120;
    // 3-of-7 fails
    let act5_insuf = make_guardian_action(id, alice.address, ACTION_FREEZE, 70_000, &[], g_3);
    let cb_fail = make_coinbase(id, 107, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act5_insuf]))
        .is_err());
    // 4-of-7 succeeds
    let act5_good = make_guardian_action(id, alice.address, ACTION_FREEZE, 70_000, &[], g_4);
    let cb107 = make_coinbase(id, 107, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb107, act5_good]))
        .unwrap();
    assert!(state.account(&alice.address).unwrap().is_frozen);
    // Frozen account cannot spend
    let spend_tx = make_transparent_transfer(id, &alice, miner.address, 10_000, 20_000, 1);
    let cb_fail = make_coinbase(id, 108, miner.address, 20_000);
    assert!(state
        .apply_block(&make_candidate_block(
            &state,
            ts + 120,
            vec![cb_fail, spend_tx]
        ))
        .is_err());

    // --- Action 6: Unfreeze account (requires 4-of-7 quorum) ---
    ts += 120;
    // 3-of-7 fails
    let act6_insuf = make_guardian_action(id, alice.address, ACTION_UNFREEZE, 70_000, &[], g_3);
    let cb_fail = make_coinbase(id, 108, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act6_insuf]))
        .is_err());
    // 4-of-7 succeeds
    let act6_good = make_guardian_action(id, alice.address, ACTION_UNFREEZE, 70_000, &[], g_4);
    let cb108 = make_coinbase(id, 108, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb108, act6_good]))
        .unwrap();
    assert!(!state.account(&alice.address).unwrap().is_frozen);

    // --- Action 7: Emergency recovery (requires 4-of-7 quorum, sweeps spendable balance) ---
    ts += 120;
    // 3-of-7 fails
    let act7_insuf = make_guardian_action(
        id,
        alice.address,
        ACTION_EMERGENCY_RECOVERY,
        70_000,
        &[],
        g_3,
    );
    let cb_fail = make_coinbase(id, 109, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act7_insuf]))
        .is_err());
    // 4-of-7 succeeds: sweeps balance to recovery1.address
    let alice_bal_before = state.account(&alice.address).unwrap().balance;
    let act7_good = make_guardian_action(
        id,
        alice.address,
        ACTION_EMERGENCY_RECOVERY,
        70_000,
        &[],
        g_4,
    );
    let cb109 = make_coinbase(id, 109, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb109, act7_good]))
        .unwrap();
    let recovered_amount = alice_bal_before - 70_000;
    assert_eq!(state.account(&alice.address).unwrap().balance, 0);
    assert_eq!(
        state.account(&recovery1.address).unwrap().balance,
        recovered_amount
    );

    // Fund Alice again for remaining action tests
    ts += 120;
    let refund_tx = make_transparent_transfer(id, &miner, alice.address, 100_000_000, 20_000, 1);
    let cb110 = make_coinbase(id, 110, miner.address, 20_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb110, refund_tx]))
        .unwrap();

    // --- Action 8: Replace guardian keys (requires 4-of-7 quorum) ---
    let new_guardian_keys: Vec<TestKeypair> = (0x30..0x37).map(TestKeypair::from_seed).collect();
    let mut param_guardians = Vec::with_capacity(224);
    for g in &new_guardian_keys {
        param_guardians.extend_from_slice(&g.pubkey);
    }
    ts += 120;
    // 3-of-7 fails
    let act8_insuf = make_guardian_action(
        id,
        alice.address,
        ACTION_REPLACE_GUARDIANS,
        70_000,
        &param_guardians,
        g_3,
    );
    let cb_fail = make_coinbase(id, 111, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act8_insuf]))
        .is_err());
    // 4-of-7 succeeds
    let act8_good = make_guardian_action(
        id,
        alice.address,
        ACTION_REPLACE_GUARDIANS,
        70_000,
        &param_guardians,
        g_4,
    );
    let cb111 = make_coinbase(id, 111, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb111, act8_good]))
        .unwrap();
    let expected_new_g: [[u8; 32]; 7] = [
        new_guardian_keys[0].pubkey,
        new_guardian_keys[1].pubkey,
        new_guardian_keys[2].pubkey,
        new_guardian_keys[3].pubkey,
        new_guardian_keys[4].pubkey,
        new_guardian_keys[5].pubkey,
        new_guardian_keys[6].pubkey,
    ];
    assert_eq!(
        state.account(&alice.address).unwrap().guardians,
        expected_new_g
    );

    // --- Action 9: Replace recovery key (requires 4-of-7 quorum from NEW guardians) ---
    let new_g_4 = &[
        (0, &new_guardian_keys[0]),
        (1, &new_guardian_keys[1]),
        (2, &new_guardian_keys[2]),
        (3, &new_guardian_keys[3]),
    ];
    let new_g_3 = &[
        (0, &new_guardian_keys[0]),
        (1, &new_guardian_keys[1]),
        (2, &new_guardian_keys[2]),
    ];
    ts += 120;
    // 3-of-7 fails
    let act9_insuf = make_guardian_action(
        id,
        alice.address,
        ACTION_REPLACE_RECOVERY_KEY,
        70_000,
        &recovery2.pubkey,
        new_g_3,
    );
    let cb_fail = make_coinbase(id, 112, miner.address, 70_000);
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb_fail, act9_insuf]))
        .is_err());
    // 4-of-7 succeeds
    let act9_good = make_guardian_action(
        id,
        alice.address,
        ACTION_REPLACE_RECOVERY_KEY,
        70_000,
        &recovery2.pubkey,
        new_g_4,
    );
    let cb112 = make_coinbase(id, 112, miner.address, 70_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb112, act9_good]))
        .unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().recovery_key,
        recovery2.pubkey
    );
}

// ---------------------------------------------------------------------------
// 5. Guardian Metadata Tampering & Anti-Transplant Tests (Requirement 4)
// ---------------------------------------------------------------------------

#[test]
fn test_tampering_guardian_index_invalidates_authorization() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

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
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb, config]);
    state.apply_block(&b102).unwrap();

    // Valid Type 3 with guardians 0, 1, 2
    let mut valid_tx = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &20u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );

    // Tamper guardian index 0 -> change byte to 3 in wire format
    // Wire offset: unsigned prefix len = 35 + 45 + 4 = 84.
    // Offset 84 is quorum_count (3).
    // Offset 85 is index of guardian 0 (value 0).
    assert_eq!(valid_tx[85], 0);
    valid_tx[85] = 3; // tampered index

    ts += 120;
    let cb103 = make_coinbase(id, 103, miner.address, 30_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb103, valid_tx]);
    assert!(state.apply_block(&bad_block).is_err());
}

#[test]
fn test_tampering_quorum_count_invalidates_authorization() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

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
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb, config]);
    state.apply_block(&b102).unwrap();

    // Valid Type 3 with 3 guardians
    let mut valid_tx = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &20u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );

    // Offset 84 is quorum_count (3). Tamper to 2 or 4.
    valid_tx[84] = 4;

    ts += 120;
    let cb103 = make_coinbase(id, 103, miner.address, 30_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb103, valid_tx]);
    assert!(state.apply_block(&bad_block).is_err());
}

#[test]
fn test_tampering_transaction_field_invalidates_authorization() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

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
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb, config]))
        .unwrap();

    // Valid Type 3 action
    let mut tx = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &20u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );

    // Tamper delay parameter: change 20 to 30
    tx[80..84].copy_from_slice(&30u32.to_le_bytes());

    ts += 120;
    let cb103 = make_coinbase(id, 103, miner.address, 30_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb103, tx]);
    assert!(state.apply_block(&bad_block).is_err());
}

#[test]
fn test_signatures_cannot_be_transferred_between_transactions() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

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
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb, config]))
        .unwrap();

    // Create tx1 for 20-block delay
    let tx1 = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &20u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );

    // Create tx2 for 30-block delay with same signers
    let mut tx2 = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &30u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );

    // Graft signatures from tx1 into tx2
    tx2[84..].copy_from_slice(&tx1[84..]);

    ts += 120;
    let cb103 = make_coinbase(id, 103, miner.address, 30_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb103, tx2]);
    assert!(state.apply_block(&bad_block).is_err());
}

// ---------------------------------------------------------------------------
// 6. Duplicate and Out-of-Range Guardian Index Tests
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_and_out_of_range_guardian_indices() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

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
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    state
        .apply_block(&make_hybrid_block(&state, ts, vec![cb, config]))
        .unwrap();

    // 1. Duplicate index in Type 3
    let dupe_tx = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &20u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
        ],
    );
    ts += 120;
    let cb103 = make_coinbase(id, 103, miner.address, 30_000);
    assert!(state
        .apply_block(&make_candidate_block(
            &state,
            ts,
            vec![cb103.clone(), dupe_tx]
        ))
        .is_err());

    // 2. Out-of-bounds index (7) in Type 3
    let oob_tx = make_guardian_action(
        id,
        alice.address,
        ACTION_STRENGTHEN_DELAYS,
        30_000,
        &20u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (7, &guardian_keys[2]),
        ],
    );
    assert!(state
        .apply_block(&make_candidate_block(&state, ts, vec![cb103, oob_tx]))
        .is_err());
}

// ---------------------------------------------------------------------------
// 7. Type 4: CancelPendingTransfer Authentication Tests
// ---------------------------------------------------------------------------

#[test]
fn test_type4_cancel_pending_authentication() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];
    let recovery = TestKeypair::from_seed(0x99);

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
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb, config]);
    state.apply_block(&b102).unwrap();

    // Create a pending transfer
    let bob = TestKeypair::from_seed(3);
    ts += 120;
    let pending_tx = make_transparent_transfer(id, &alice, bob.address, 200_000_000, 20_000, 1);
    let cb103 = make_coinbase(id, 103, miner.address, 20_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, pending_tx]);
    state.apply_block(&b103).unwrap();

    let transfer_id = state.account(&alice.address).unwrap().pending_transfers[0].transfer_id;

    // Case 1: Invalid sender signature rejected
    ts += 120;
    let mut bad_sender_sig = make_cancel_pending(
        id,
        &alice,
        transfer_id,
        50_000,
        2,
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
            (3, &guardian_keys[3]),
        ],
    );
    bad_sender_sig[115..179].copy_from_slice(&[0u8; 64]); // zero sender signature
    let cb104 = make_coinbase(id, 104, miner.address, 50_000);
    let bad_block_sender = make_candidate_block(&state, ts, vec![cb104.clone(), bad_sender_sig]);
    assert!(state.apply_block(&bad_block_sender).is_err());

    // Case 2: Insufficient guardian quorum (only 3 of 7) rejected
    let insufficient_quorum = make_cancel_pending(
        id,
        &alice,
        transfer_id,
        50_000,
        2,
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );
    let bad_block_quorum =
        make_candidate_block(&state, ts, vec![cb104.clone(), insufficient_quorum]);
    assert!(state.apply_block(&bad_block_quorum).is_err());

    // Case 3: Duplicate guardian index rejected
    let dupe_guardian = make_cancel_pending(
        id,
        &alice,
        transfer_id,
        50_000,
        2,
        &[
            (0, &guardian_keys[0]),
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ],
    );
    let bad_block_dupe = make_candidate_block(&state, ts, vec![cb104.clone(), dupe_guardian]);
    assert!(state.apply_block(&bad_block_dupe).is_err());

    // Case 4: Valid cancel succeeds
    let valid_cancel = make_cancel_pending(
        id,
        &alice,
        transfer_id,
        50_000,
        2,
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
            (3, &guardian_keys[3]),
        ],
    );
    let b104 = make_hybrid_block(&state, ts, vec![cb104, valid_cancel]);
    assert!(state.apply_block(&b104).is_ok());
    assert_eq!(
        state
            .account(&alice.address)
            .unwrap()
            .pending_transfers
            .len(),
        0
    );
}

// ---------------------------------------------------------------------------
// 8. Type 6: TransparentToShielded Authentication Tests
// ---------------------------------------------------------------------------

#[test]
fn test_type6_transparent_to_shielded_authentication() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    // Verify authentication helper unit test
    let guardian_keys: Vec<TestKeypair> = (0x10..0x17).map(TestKeypair::from_seed).collect();
    let guardians: [[u8; 32]; 7] = [
        guardian_keys[0].pubkey,
        guardian_keys[1].pubkey,
        guardian_keys[2].pubkey,
        guardian_keys[3].pubkey,
        guardian_keys[4].pubkey,
        guardian_keys[5].pubkey,
        guardian_keys[6].pubkey,
    ];

    // 1. Unprotected account: valid sender signature, 0 guardian sigs
    // Passes authorization check in auth helper
    ts += 120;
    let t2s_unprotected = make_transparent_to_shielded(id, &alice, 0, 50_000_000, 20_000, &[], &[]);
    let auth_info =
        ownchain::auth::verify_type6_authorization(id, &t2s_unprotected, false, &guardians)
            .unwrap();
    assert_eq!(auth_info.sender_address, alice.address);
    assert_eq!(auth_info.shielded_amount, 50_000_000);

    // Consensus execution rejects mock Type 6 with invalid bundle
    let cb102 = make_coinbase(id, 102, miner.address, 20_000);
    let b102 = make_candidate_block(&state, ts, vec![cb102, t2s_unprotected]);
    let err = state.apply_block(&b102).unwrap_err();
    assert!(
        err.to_string().contains("invalid Orchard transaction")
            || err.to_string().contains("bundle")
    );

    // Verify State Atomicity: Alice's balance, nonce, and pool balance must be unchanged
    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.balance, 800_000_000);
    assert_eq!(alice_acc.nonce, 0);
    assert_eq!(state.shielded_pool_balance(), 0);
    assert_eq!(state.tip().unwrap().header.height, 101);

    // 2. Configure guardians on Alice (Type 2 works)
    let recovery = TestKeypair::from_seed(0x99);
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
    let cb102_good = make_coinbase(id, 102, miner.address, 50_000);
    let b102_good = make_hybrid_block(&state, ts, vec![cb102_good, config]);
    state.apply_block(&b102_good).unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().balance,
        800_000_000 - 50_000
    );
    assert_eq!(state.account(&alice.address).unwrap().nonce, 1);

    // 3. Protected account with 4-of-7 guardian signatures
    // Passes authorization check in auth helper
    ts += 120;
    let t2s_protected = make_transparent_to_shielded(
        id,
        &alice,
        1,
        10_000_000,
        50_000,
        &[],
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
            (3, &guardian_keys[3]),
        ],
    );
    let auth_info_prot =
        ownchain::auth::verify_type6_authorization(id, &t2s_protected, true, &guardians).unwrap();
    assert_eq!(auth_info_prot.guardian_entries.len(), 4);

    // Consensus execution rejects mock Type 6 with invalid bundle
    let cb103 = make_coinbase(id, 103, miner.address, 50_000);
    let b103 = make_candidate_block(&state, ts, vec![cb103, t2s_protected]);
    let err_prot = state.apply_block(&b103).unwrap_err();
    assert!(
        err_prot.to_string().contains("invalid Orchard transaction")
            || err_prot.to_string().contains("bundle")
    );

    // Verify State Atomicity: Alice's balance, nonce, and pool balance must be unchanged
    let alice_acc_post = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc_post.balance, 800_000_000 - 50_000);
    assert_eq!(alice_acc_post.nonce, 1);
    assert_eq!(state.shielded_pool_balance(), 0);
    assert_eq!(state.tip().unwrap().header.height, 102);
}

#[test]
fn test_type7_shielded_to_transparent_consensus_gate() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let id = devnet_chain_id();

    ts += 120;
    let mut raw_tx7 = Vec::new();
    raw_tx7.push(7); // Type 7
    raw_tx7.extend_from_slice(&1u16.to_le_bytes());
    raw_tx7.extend_from_slice(id.as_bytes());
    raw_tx7.extend_from_slice(alice.address.as_bytes()); // recipient
    raw_tx7.extend_from_slice(&10_000_000u128.to_le_bytes()); // release_amount
    raw_tx7.extend_from_slice(&20_000u64.to_le_bytes()); // fee_atoms
                                                         // dummy bundle bytes
    raw_tx7.extend_from_slice(&[0u8; 32]);

    let cb102 = make_coinbase(id, 102, miner.address, 20_000);
    let b102 = make_candidate_block(&state, ts, vec![cb102, raw_tx7]);
    let err = state.apply_block(&b102).unwrap_err();
    assert!(matches!(
        err,
        ownchain::chain::ChainError::Invalid(
            ownchain::validation::ValidationError::InvalidOrchardTransaction { .. }
        )
    ));

    // Verify State Atomicity: Alice's balance, pool balance, height unchanged
    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.balance, 800_000_000);
    assert_eq!(alice_acc.nonce, 0);
    assert_eq!(state.shielded_pool_balance(), 0);
    assert_eq!(state.tip().unwrap().header.height, 101);
}

// ---------------------------------------------------------------------------
// 9. Type 1 Legacy Bypass Removal Tests
// ---------------------------------------------------------------------------

#[test]
fn test_legacy_type1_orchard_bypass_completely_removed() {
    let (mut state, miner, _alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    // A Type 1 transaction with a length != 195 (e.g. 194 or 200 bytes) must fail envelope parsing
    let mut truncated_type1 = vec![1u8; 194];
    truncated_type1[1..3].copy_from_slice(&1u16.to_le_bytes());
    truncated_type1[3..35].copy_from_slice(id.as_bytes());

    let cb = make_coinbase(id, 102, miner.address, 20_000);
    let bad_block_trunc = make_candidate_block(&state, ts + 120, vec![cb.clone(), truncated_type1]);
    assert!(state.apply_block(&bad_block_trunc).is_err());

    // A Type 1 transaction claiming an Orchard bundle payload must be rejected
    let mut legacy_bundle_tx = vec![1u8; 1000]; // simulate M1-B Orchard payload with tag 1
    legacy_bundle_tx[1..3].copy_from_slice(&1u16.to_le_bytes());
    legacy_bundle_tx[3..35].copy_from_slice(id.as_bytes());

    let bad_block_bundle = make_candidate_block(&state, ts + 120, vec![cb, legacy_bundle_tx]);
    assert!(state.apply_block(&bad_block_bundle).is_err());
}

// ---------------------------------------------------------------------------
// 10. State Atomicity on Unauthenticated Transaction
// ---------------------------------------------------------------------------

#[test]
fn test_state_atomicity_on_unauthenticated_transaction() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let id = devnet_chain_id();

    let before_state = state.clone();

    // Block with a good coinbase, a valid transfer, but then an unauthenticated transfer
    let good_tx = make_transparent_transfer(id, &alice, miner.address, 10_000_000, 20_000, 0);
    let mut bad_tx = make_transparent_transfer(id, &alice, miner.address, 10_000_000, 20_000, 1);
    bad_tx[131..195].copy_from_slice(&[0xee; 64]); // invalid signature

    let cb = make_coinbase(id, 102, miner.address, 40_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, good_tx, bad_tx]);

    assert!(state.apply_block(&block).is_err());

    // Assert that the chain state was completely restored
    assert_eq!(state, before_state);
    assert_eq!(
        state.account(&alice.address).unwrap().balance,
        before_state.account(&alice.address).unwrap().balance
    );
    assert_eq!(
        state.account(&alice.address).unwrap().nonce,
        before_state.account(&alice.address).unwrap().nonce
    );
    assert_eq!(state.tip_height(), before_state.tip_height());
}

// ---------------------------------------------------------------------------
// 11. Strict Ed25519 Public-Key Registration & Parsing Regression Tests
// ---------------------------------------------------------------------------

#[test]
fn test_strict_pubkey_registration_helpers() {
    use ownchain::auth::{
        parse_strict_pubkey, validate_pubkey, verify_address_derivation, AuthError,
    };

    // 1. Valid ordinary Ed25519 key
    let sk = SigningKey::from_bytes(&[77u8; 32]);
    let valid_vk = sk.verifying_key().to_bytes();
    assert!(parse_strict_pubkey(&valid_vk).is_ok());
    assert!(validate_pubkey(&valid_vk).is_ok());

    let addr = derive_address(&valid_vk);
    assert!(verify_address_derivation(&valid_vk, addr).is_ok());

    // 2. Identity point (order 1): (0, 1) encoded as [1, 0, ..., 0]
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        parse_strict_pubkey(&identity),
        Err(AuthError::InvalidPublicKey)
    );
    assert_eq!(validate_pubkey(&identity), Err(AuthError::InvalidPublicKey));
    let id_addr = derive_address(&identity);
    assert_eq!(
        verify_address_derivation(&identity, id_addr),
        Err(AuthError::InvalidPublicKey)
    );

    // 3. Small-order point: all zeros [0u8; 32]
    let all_zeros = [0u8; 32];
    assert_eq!(
        parse_strict_pubkey(&all_zeros),
        Err(AuthError::InvalidPublicKey)
    );
    assert_eq!(
        validate_pubkey(&all_zeros),
        Err(AuthError::InvalidPublicKey)
    );

    // 4. Order-2 point: (0, -1) encoded as [0xec, 0xff, ..., 0x7f]
    let mut order2 = [0xffu8; 32];
    order2[0] = 0xec;
    order2[31] = 0x7f;
    assert_eq!(
        parse_strict_pubkey(&order2),
        Err(AuthError::InvalidPublicKey)
    );
    assert_eq!(validate_pubkey(&order2), Err(AuthError::InvalidPublicKey));

    // 5. Non-canonical encodings: y >= 2^255 - 19
    // y = 0 + p = 2^255 - 19 => [0xed, 0xff, ..., 0x7f]
    let mut non_canon_0 = [0xffu8; 32];
    non_canon_0[0] = 0xed;
    non_canon_0[31] = 0x7f;
    assert_eq!(
        parse_strict_pubkey(&non_canon_0),
        Err(AuthError::InvalidPublicKey)
    );
    assert_eq!(
        validate_pubkey(&non_canon_0),
        Err(AuthError::InvalidPublicKey)
    );

    // y = 1 + p = 2^255 - 18 => [0xee, 0xff, ..., 0x7f]
    let mut non_canon_1 = [0xffu8; 32];
    non_canon_1[0] = 0xee;
    non_canon_1[31] = 0x7f;
    assert_eq!(
        parse_strict_pubkey(&non_canon_1),
        Err(AuthError::InvalidPublicKey)
    );
    assert_eq!(
        validate_pubkey(&non_canon_1),
        Err(AuthError::InvalidPublicKey)
    );
}

#[test]
fn test_weak_guardian_keys_rejected_in_set_and_consensus() {
    use ownchain::auth::{validate_guardian_keys_set, AuthError};

    let id = devnet_chain_id();
    let (mut state, miner, alice, ts) = setup_funded_chain();

    // 7 valid guardian keys
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }
    assert!(validate_guardian_keys_set(&guardians).is_ok());

    // Replace one guardian key with the identity key
    let mut bad_guardians = guardians;
    let mut identity = [0u8; 32];
    identity[0] = 1;
    bad_guardians[3] = identity;
    assert_eq!(
        validate_guardian_keys_set(&bad_guardians),
        Err(AuthError::InvalidPublicKey)
    );

    // Replace one with order-2 key
    let mut order2 = [0xffu8; 32];
    order2[0] = 0xec;
    order2[31] = 0x7f;
    bad_guardians[3] = order2;
    assert_eq!(
        validate_guardian_keys_set(&bad_guardians),
        Err(AuthError::InvalidPublicKey)
    );

    // Type 2 configuration with weak guardian key is rejected by consensus
    let recovery = TestKeypair::from_seed(99);
    let tx_type2 = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &bad_guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let block = make_candidate_block(&state, ts + 120, vec![cb, tx_type2]);
    assert!(state.apply_block(&block).is_err());
}

#[test]
fn test_weak_recovery_keys_rejected_in_type2_and_type3() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_chain();

    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    // 1. Weak recovery key in Type 2 setup is rejected
    let mut identity = [0u8; 32];
    identity[0] = 1;

    let bad_type2 = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &identity,
        &[],
    );
    ts += 120;
    let cb = make_coinbase(id, 102, miner.address, 50_000);
    let block = make_candidate_block(&state, ts, vec![cb, bad_type2]);
    assert!(state.apply_block(&block).is_err());

    // Successfully configure with valid recovery key
    let valid_recovery = TestKeypair::from_seed(99);
    let good_type2 = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &valid_recovery.pubkey,
        &[],
    );
    let good_block = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), good_type2],
    );
    state.apply_block(&good_block).unwrap();

    // 2. Type 3 Action 9 (Replace Recovery Key) with weak recovery key is rejected
    ts += 120;
    let signers: Vec<(u8, &TestKeypair)> = (0..4).map(|i| (i as u8, &g_keys[i])).collect();
    let bad_replace_rec = make_guardian_action(
        id,
        alice.address,
        ACTION_REPLACE_RECOVERY_KEY,
        50_000,
        &identity, // weak key
        &signers,
    );
    let block_action = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 103, miner.address, 50_000),
            bad_replace_rec,
        ],
    );
    assert!(state.apply_block(&block_action).is_err());
}
