//! Comprehensive integration test suite for the OwnChain Stateful Hybrid Consensus Engine.
//!
//! Validates:
//! 1. Depth-32 Orchard note commitment tree root calculation.
//! 2. 10-block ancestor-anchor window [max(0, H-10), H-1] acceptance and rejection.
//! 3. Nullifier double-spend prevention (intra-block and historical).
//! 4. Cross-pool value conservation ($T + S = I$) across all transaction types.
//! 5. 100-block coinbase maturity tranches and spendable balance isolation.
//! 6. Single-counting of pending transfer principal.
//! 7. Opt-in per-account guardian quorums (3-of-7 strengthen, 4-of-7 weaken/critical).
//! 8. Allowance window tracking (reset-on-first-spend).
//! 9. Atomic state transition and rejection safety.
//! 10. Clean reorganization rollback restoring exact composite state root.
//! 11. 21,000,000 OWN maximum supply cap and halving schedule.

use ed25519_dalek::{Signer, SigningKey};
use ownchain::account::{derive_address, scheduled_subsidy, MAX_SUPPLY_ATOMS};
use ownchain::auth::compute_signing_preimage;
use ownchain::block::Block;
use ownchain::chain::{ChainError, ChainState};
use ownchain::genesis;
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::orchard_root::empty_commitment_root;
use ownchain::validation::ValidationError;

// ---------------------------------------------------------------------------
// Test Keypair & Helpers
// ---------------------------------------------------------------------------

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
    let unsigned_tx =
        ownchain::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
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
    let unsigned_tx =
        ownchain::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
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
    let unsigned_tx =
        ownchain::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
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

// ---------------------------------------------------------------------------
// 1. Invariant 1: Global Monetary Conservation (T + S = I)
// ---------------------------------------------------------------------------

#[test]
fn test_global_monetary_conservation_transparent_blocks() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner_key = [1u8; 32];
    let miner_addr = derive_address(&miner_key);

    assert_eq!(state.shielded_pool_balance(), 0);
    assert_eq!(state.cumulative_issuance(), 0);
    assert_eq!(state.accounts().len(), 0);

    // Height 1: 10 OWN claimed subsidy
    let cb1 = make_coinbase(id, 1, miner_addr, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 10, vec![cb1]);
    state.apply_block(&b1).unwrap();

    assert_eq!(state.cumulative_issuance(), 1_000_000_000);
    assert_eq!(state.account(&miner_addr).unwrap().balance, 1_000_000_000);
    assert_eq!(state.shielded_pool_balance(), 0);
    // T + S = 1_000_000_000 + 0 = I(1_000_000_000)

    // Height 2: Miner claims partial subsidy 8 OWN (underclaim)
    let cb2 = make_coinbase(id, 2, miner_addr, 800_000_000);
    let b2 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 20, vec![cb2]);
    state.apply_block(&b2).unwrap();

    assert_eq!(state.cumulative_issuance(), 1_800_000_000);
    assert_eq!(state.account(&miner_addr).unwrap().balance, 1_800_000_000);
    assert_eq!(state.shielded_pool_balance(), 0);
}

// ---------------------------------------------------------------------------
// 2. Invariant 8: Coinbase Maturity (100 blocks)
// ---------------------------------------------------------------------------

#[test]
fn test_coinbase_maturity_isolation_and_spendability() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    // Block 1: Miner receives 10 OWN
    let cb1 = make_coinbase(id, 1, miner.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    let miner_acc = state.account(&miner.address).unwrap();
    assert_eq!(miner_acc.balance, 1_000_000_000);
    // At height 1, coinbase is immature: spendable balance is 0!
    assert_eq!(miner_acc.spendable_balance(1).unwrap(), 0);

    // Fast-forward to height 100 with empty subsidy blocks (120s interval preserves difficulty 1)
    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }
    assert_eq!(state.tip_height(), Some(100));

    // At height 100, tranche unlocks at height 101, so still immature at 100!
    let miner_at_100 = state.account(&miner.address).unwrap();
    assert_eq!(miner_at_100.spendable_balance(100).unwrap(), 0);

    // At height 101, mature tranche is spendable!
    ts += 120;
    let valid_tx = make_transparent_transfer(id, &miner, alice.address, 500_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000); // claim fee
    let b101 = make_hybrid_block(&state, ts, vec![cb101, valid_tx]);
    state.apply_block(&b101).unwrap();

    let miner_after = state.account(&miner.address).unwrap();
    let alice_after = state.account(&alice.address).unwrap();
    assert_eq!(alice_after.balance, 500_000_000);
    assert_eq!(miner_after.balance, 500_000_000); // 1000M - 500M - 20K + 20K fee = 500M
    assert_eq!(state.cumulative_issuance(), 1_000_000_000);
}

// ---------------------------------------------------------------------------
// 3. Invariant 5: Nonce Replay Protection
// ---------------------------------------------------------------------------

#[test]
fn test_nonce_replay_rejected() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    // Mine block 1
    let cb1 = make_coinbase(id, 1, miner.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    // Fast-forward to height 101
    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }

    // Transfer with nonce 0 succeeds
    ts += 120;
    let tx1 = make_transparent_transfer(id, &miner, alice.address, 100_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, tx1]);
    state.apply_block(&b101).unwrap();

    // Trying to send another transfer with replayed nonce 0 must fail
    ts += 120;
    let replayed = make_transparent_transfer(id, &miner, alice.address, 50_000_000, 20_000, 0);
    let cb102 = make_coinbase(id, 102, miner.address, 20_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb102, replayed]);
    assert!(state.apply_block(&bad_block).is_err());
}

// ---------------------------------------------------------------------------
// 4. Invariant 9: Pending Principal Single Counting & Cancellation
// ---------------------------------------------------------------------------

#[test]
fn test_pending_transfer_lifecycle_and_cancellation() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);
    let bob = TestKeypair::from_seed(3);

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

    // Mine block 1 and mature
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

    // Fund Alice with 800M
    ts += 120;
    let fund_alice = make_transparent_transfer(id, &miner, alice.address, 800_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund_alice]);
    state.apply_block(&b101).unwrap();

    // Alice configures guardians
    ts += 120;
    let config_tx = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10, // 10-block delay for new recipients
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config_tx]);
    state.apply_block(&b102).unwrap();

    let alice_acc = state.account(&alice.address).unwrap();
    assert!(alice_acc.guardian_enabled);
    assert_eq!(alice_acc.new_recipient_delay, 10);
    assert_eq!(alice_acc.balance, 799_950_000); // 800M - 50K fee

    // Alice transfers 300M to unconfirmed recipient Bob (delay applies!)
    ts += 120;
    let tx_to_bob = make_transparent_transfer(id, &alice, bob.address, 300_000_000, 20_000, 1);
    let cb103 = make_coinbase(id, 103, miner.address, 20_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, tx_to_bob.clone()]);
    state.apply_block(&b103).unwrap();

    let alice_after = state.account(&alice.address).unwrap();
    // Balance still includes the 300M principal (single counted!), but spendable excludes it!
    assert_eq!(alice_after.balance, 799_930_000); // 799_950_000 - 20_000 fee
    assert_eq!(alice_after.pending_transfers.len(), 1);
    let pending = &alice_after.pending_transfers[0];
    assert_eq!(pending.amount, 300_000_000);
    assert_eq!(pending.release_height, 103 + 10); // height 113

    // Spendable balance is balance - pending = 799_930_000 - 300_000_000 = 499_930_000
    assert_eq!(alice_after.spendable_balance(103).unwrap(), 499_930_000);

    // Cancel pending transfer with 4-of-7 guardian quorum
    ts += 120;
    let cancel_tx = make_cancel_pending(
        id,
        &alice,
        pending.transfer_id,
        50_000,
        2,
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
            (3, &guardian_keys[3]),
        ],
    );
    let cb104 = make_coinbase(id, 104, miner.address, 50_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104, cancel_tx]);
    state.apply_block(&b104).unwrap();

    let alice_cancelled = state.account(&alice.address).unwrap();
    assert_eq!(alice_cancelled.pending_transfers.len(), 0);
    // Principal was restored to spendable balance immediately!
    assert_eq!(
        alice_cancelled.spendable_balance(104).unwrap(),
        499_930_000 + 300_000_000 - 50_000
    );
}

// ---------------------------------------------------------------------------
// 5. Invariant 10: Guardian Quorums (3-of-7 vs 4-of-7) and Account Recovery
// ---------------------------------------------------------------------------

#[test]
fn test_guardian_quorum_rules_and_recovery() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

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

    // Mine and mature
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

    // Fund Alice and configure guardians
    ts += 120;
    let fund = make_transparent_transfer(id, &miner, alice.address, 600_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund]);
    state.apply_block(&b101).unwrap();

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

    // 1. Strengthen delays: 3-of-7 quorum succeeds
    ts += 120;
    let strengthen_delays = make_guardian_action(
        id,
        alice.address,
        1, // Strengthen delays
        30_000,
        &20u32.to_le_bytes(), // increase from 10 to 20
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ], // 3 votes
    );
    let cb103 = make_coinbase(id, 103, miner.address, 30_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, strengthen_delays]);
    state.apply_block(&b103).unwrap();
    assert_eq!(
        state.account(&alice.address).unwrap().new_recipient_delay,
        20
    );

    // 2. Weaken delays: 3-of-7 quorum FAILS (requires 4-of-7)
    ts += 120;
    let weaken_insufficient = make_guardian_action(
        id,
        alice.address,
        3, // Weaken delays
        30_000,
        &5u32.to_le_bytes(),
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
        ], // only 3 votes!
    );
    let cb104 = make_coinbase(id, 104, miner.address, 30_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb104, weaken_insufficient]);
    assert!(state.apply_block(&bad_block).is_err());

    // 3. Freeze account with 4-of-7 quorum
    ts += 120;
    let freeze_action = make_guardian_action(
        id,
        alice.address,
        5, // Freeze
        35_000,
        &[],
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
            (3, &guardian_keys[3]),
        ],
    );
    let cb104_good = make_coinbase(id, 104, miner.address, 35_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104_good, freeze_action]);
    state.apply_block(&b104).unwrap();
    assert!(state.account(&alice.address).unwrap().is_frozen);

    // Alice cannot transfer while frozen
    ts += 120;
    let transfer_while_frozen =
        make_transparent_transfer(id, &alice, miner.address, 10_000_000, 20_000, 1);
    let cb105 = make_coinbase(id, 105, miner.address, 20_000);
    let bad_frozen_block = make_candidate_block(&state, ts, vec![cb105, transfer_while_frozen]);
    assert!(state.apply_block(&bad_frozen_block).is_err());

    // 4. Recovery: 4-of-7 sweeps balance to recovery key
    ts += 120;
    let recovery_action = make_guardian_action(
        id,
        alice.address,
        7, // Recovery
        35_000,
        &[],
        &[
            (0, &guardian_keys[0]),
            (1, &guardian_keys[1]),
            (2, &guardian_keys[2]),
            (4, &guardian_keys[4]),
        ],
    );
    let cb105_good = make_coinbase(id, 105, miner.address, 35_000);
    let b105 = make_hybrid_block(&state, ts, vec![cb105_good, recovery_action]);
    state.apply_block(&b105).unwrap();

    let alice_swept = state.account(&alice.address).unwrap();
    let recovery_acc = state.account(&recovery.address).unwrap();
    assert_eq!(alice_swept.balance, 0);
    assert!(recovery_acc.balance > 0);
}

// ---------------------------------------------------------------------------
// 6. Invariant 12: Reorganization Rollback & Exact Composite Root Restoration
// ---------------------------------------------------------------------------

#[test]
fn test_reorganization_rollback_restores_exact_state_and_roots() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner_key = [1u8; 32];
    let miner_addr = derive_address(&miner_key);

    // Mine blocks 1, 2, 3 on Branch A
    let mut ts = genesis::GENESIS_TIMESTAMP;
    for h in 1..=3 {
        ts += 10;
        let cb = make_coinbase(id, h, miner_addr, 1_000_000_000);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }
    assert_eq!(state.tip_height(), Some(3));
    let _snapshot_h2 = state.snapshot(); // snapshot at height 3
    let root_at_h2 = state.composite_state_root();

    // Rollback to height 2
    state.rollback_to(2).unwrap();
    assert_eq!(state.tip_height(), Some(2));
    assert_eq!(state.blocks().len(), 3); // 0, 1, 2
    assert_eq!(state.cumulative_issuance(), 2_000_000_000);

    // Mine block 3 again
    let cb3_repeat = make_coinbase(id, 3, miner_addr, 1_000_000_000);
    let b3_repeat = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 30, vec![cb3_repeat]);
    state.apply_block(&b3_repeat).unwrap();

    // State root must match exact value before rollback!
    assert_eq!(state.composite_state_root(), root_at_h2);
}

fn make_block_at_height(
    chain_id: Hash,
    height: u64,
    parent_id: Hash,
    timestamp: u64,
    transactions: Vec<Vec<u8>>,
) -> Block {
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    let tx_root = merkle::tx_root(&ids);
    Block {
        header: Header {
            version: 1,
            chain_id,
            height,
            parent_block_id: parent_id,
            transaction_root: tx_root,
            orchard_commitment_root: empty_commitment_root(),
            timestamp,
            difficulty: 1,
            nonce: 0,
        },
        transactions,
    }
}

// ---------------------------------------------------------------------------
// 7. Invariant 7: Subsidy Cap and Halving Schedule
// ---------------------------------------------------------------------------

#[test]
fn test_subsidy_cap_and_halving_boundaries() {
    // Genesis height 0 has zero subsidy
    assert_eq!(scheduled_subsidy(0), 0);

    // Era 0: 10 OWN (1,000,000,000 atoms)
    assert_eq!(scheduled_subsidy(1), 1_000_000_000);
    assert_eq!(scheduled_subsidy(1_049_999), 1_000_000_000); // Immediately before 1st halving
    assert_eq!(scheduled_subsidy(1_050_000), 1_000_000_000); // At 1st halving boundary

    // Era 1: 5 OWN (500,000,000 atoms)
    assert_eq!(scheduled_subsidy(1_050_001), 500_000_000); // Immediately after 1st halving
    assert_eq!(scheduled_subsidy(2_099_999), 500_000_000); // Immediately before 2nd halving
    assert_eq!(scheduled_subsidy(2_100_000), 500_000_000); // At 2nd halving boundary

    // Era 2: 2.5 OWN (250,000,000 atoms)
    assert_eq!(scheduled_subsidy(2_100_001), 250_000_000); // Immediately after 2nd halving

    // Exhaustion boundary at Era 30 (height 31,500,001)
    assert_eq!(scheduled_subsidy(31_499_999), 1); // Era 29 penultimate block
    assert_eq!(scheduled_subsidy(31_500_000), 1); // Era 29 last block (1 atom)
    assert_eq!(scheduled_subsidy(31_500_001), 0); // Era 30 first block: exhausted!
    assert_eq!(scheduled_subsidy(100_000_000), 0);

    // Exact cumulative integer subsidy across all eras is <= 21M OWN
    let mut total: u128 = 0;
    for era in 0..30 {
        let per_block = 1_000_000_000u128 >> era;
        total += per_block * 1_050_000;
    }
    assert_eq!(total, 2_099_999_986_350_000);
    assert!(total <= MAX_SUPPLY_ATOMS);
}

#[test]
fn test_halving_boundary_consensus_enforcement() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let state = ChainState::from_genesis(&genesis).unwrap();
    let miner_addr = derive_address(&[1u8; 32]);

    // 1. Immediately before 1st halving: height 1,049,999
    // Claiming exact scheduled subsidy (10 OWN) succeeds
    let cb_before = make_coinbase(id, 1_049_999, miner_addr, 1_000_000_000);
    let blk_before = make_block_at_height(id, 1_049_999, genesis.block_id(), 1000, vec![cb_before]);
    assert!(state.evaluate_candidate(&blk_before).is_ok());

    // 2. At 1st halving boundary: height 1,050,000 (last block of Era 0)
    // Claiming exact scheduled subsidy (10 OWN) succeeds
    let cb_at = make_coinbase(id, 1_050_000, miner_addr, 1_000_000_000);
    let blk_at = make_block_at_height(id, 1_050_000, genesis.block_id(), 1000, vec![cb_at]);
    let cand_at = state.evaluate_candidate(&blk_at).unwrap();
    assert_eq!(cand_at.cumulative_issuance, 1_000_000_000);

    // Overclaiming by 1 atom at height 1,050,000 fails
    let cb_at_over = make_coinbase(id, 1_050_000, miner_addr, 1_000_000_001);
    let blk_at_over =
        make_block_at_height(id, 1_050_000, genesis.block_id(), 1000, vec![cb_at_over]);
    let err_at = state.evaluate_candidate(&blk_at_over).unwrap_err();
    assert!(err_at
        .to_string()
        .contains("exceeds scheduled limit 1000000000"));

    // 3. Immediately after 1st halving boundary: height 1,050,001 (first block of Era 1)
    // Claiming exact scheduled subsidy (5 OWN) succeeds
    let cb_after = make_coinbase(id, 1_050_001, miner_addr, 500_000_000);
    let blk_after = make_block_at_height(id, 1_050_001, genesis.block_id(), 1000, vec![cb_after]);
    let cand_after = state.evaluate_candidate(&blk_after).unwrap();
    assert_eq!(cand_after.cumulative_issuance, 500_000_000);

    // Attempting to claim Era 0 subsidy (10 OWN) at height 1,050,001 fails
    let cb_after_era0 = make_coinbase(id, 1_050_001, miner_addr, 1_000_000_000);
    let blk_after_era0 =
        make_block_at_height(id, 1_050_001, genesis.block_id(), 1000, vec![cb_after_era0]);
    let err_era0 = state.evaluate_candidate(&blk_after_era0).unwrap_err();
    assert!(err_era0
        .to_string()
        .contains("exceeds scheduled limit 500000000"));

    // Overclaiming by 1 atom at height 1,050,001 fails
    let cb_after_over = make_coinbase(id, 1_050_001, miner_addr, 500_000_001);
    let blk_after_over =
        make_block_at_height(id, 1_050_001, genesis.block_id(), 1000, vec![cb_after_over]);
    let err_after = state.evaluate_candidate(&blk_after_over).unwrap_err();
    assert!(err_after
        .to_string()
        .contains("exceeds scheduled limit 500000000"));
}

#[test]
fn test_cumulative_issuance_cap_consensus_enforcement() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();
    let miner_addr = derive_address(&[1u8; 32]);

    // Position state near supply cap: MAX_SUPPLY_ATOMS - 500
    let initial_issuance = MAX_SUPPLY_ATOMS - 500;
    state.cumulative_issuance = initial_issuance;
    let miner = state.accounts.entry(miner_addr).or_default();
    miner.balance = initial_issuance; // Preserve T + S = I

    // 1. Claiming exactly remaining 500 atoms reaches 21,000,000 OWN cap exactly
    let cb_exact = make_coinbase(id, 1, miner_addr, 500);
    let blk_exact = make_block_at_height(id, 1, genesis.block_id(), 1000, vec![cb_exact]);
    let cand_exact = state.evaluate_candidate(&blk_exact).unwrap();
    assert_eq!(cand_exact.cumulative_issuance, MAX_SUPPLY_ATOMS);

    // 2. Claiming 501 atoms (exceeding cap by 1 atom) is rejected
    let cb_over = make_coinbase(id, 1, miner_addr, 501);
    let blk_over = make_block_at_height(id, 1, genesis.block_id(), 1000, vec![cb_over]);
    let err_over = state.evaluate_candidate(&blk_over).unwrap_err();
    assert!(err_over
        .to_string()
        .contains("cumulative issuance exceeds 21M OWN cap"));

    // 3. When already at maximum cap, any non-zero subsidy is rejected
    let mut saturated_state = ChainState::from_genesis(&genesis).unwrap();
    saturated_state.cumulative_issuance = MAX_SUPPLY_ATOMS;
    let sat_miner = saturated_state.accounts.entry(miner_addr).or_default();
    sat_miner.balance = MAX_SUPPLY_ATOMS;

    let cb_at_cap = make_coinbase(id, 1, miner_addr, 1);
    let blk_at_cap = make_block_at_height(id, 1, genesis.block_id(), 1000, vec![cb_at_cap]);
    let err_at_cap = saturated_state.evaluate_candidate(&blk_at_cap).unwrap_err();
    assert!(err_at_cap
        .to_string()
        .contains("cumulative issuance exceeds 21M OWN cap"));

    // Claiming zero subsidy at cap succeeds
    let cb_zero = make_coinbase(id, 1, miner_addr, 0);
    let blk_zero = make_block_at_height(id, 1, genesis.block_id(), 1000, vec![cb_zero]);
    let cand_zero = saturated_state.evaluate_candidate(&blk_zero).unwrap();
    assert_eq!(cand_zero.cumulative_issuance, MAX_SUPPLY_ATOMS);
}

#[test]
fn test_fees_are_transfers_not_new_issuance() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    // Block 1: Miner claims initial subsidy 10 OWN (1,000,000,000 atoms)
    let cb1 = make_coinbase(id, 1, miner.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    assert_eq!(state.cumulative_issuance(), 1_000_000_000);
    assert_eq!(
        state.account(&miner.address).unwrap().balance,
        1_000_000_000
    );

    // Fast-forward 100 blocks to mature coinbase tranche (matures at height 101)
    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }
    assert_eq!(state.tip_height(), Some(100));

    // Block 101: Transfer 1 OWN (100,000,000 atoms) with fee 19,500 atoms.
    // Miner claims scheduled subsidy (10 OWN = 1,000,000,000 atoms) PLUS fee (19,500 atoms)
    // Total coinbase payout = 1,000,019,500 atoms.
    ts += 120;
    let fee_atoms = 19_500u64;
    let transfer_amount = 100_000_000u128;
    let tx1 = make_transparent_transfer(id, &miner, alice.address, transfer_amount, fee_atoms, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 1_000_000_000 + fee_atoms);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, tx1]);
    state.apply_block(&b101).unwrap();

    let miner_acc = state.account(&miner.address).unwrap();
    let alice_acc = state.account(&alice.address).unwrap();

    // Alice received 100,000,000 atoms
    assert_eq!(alice_acc.balance, transfer_amount);

    // Miner balance:
    // Block 1: +1,000,000,000
    // Block 101 transfer: -100,000,000 (amount) - 19,500 (fee)
    // Block 101 coinbase: +1,000,000,000 (subsidy) + 19,500 (fee)
    // Net miner balance = 1,900,000,000 atoms
    assert_eq!(miner_acc.balance, 1_900_000_000);

    // CRITICAL: Cumulative issuance increased ONLY by the 10 OWN subsidy claimed!
    // Block 1: 1,000,000,000. Block 101: +1,000,000,000. Total = 2,000,000,000 atoms.
    // The 19,500 fee atoms are a transfer between accounts, NOT newly issued currency!
    assert_eq!(state.cumulative_issuance(), 2_000_000_000);

    // Global monetary conservation invariant T + S = I holds exactly:
    let t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
    let s_total = state.shielded_pool_balance();
    let i_total = state.cumulative_issuance();
    assert_eq!(t_total + s_total, i_total);
    assert_eq!(t_total, 2_000_000_000);
}

// ---------------------------------------------------------------------------
fn mine_pow_block_success(state: &mut ChainState, base_ts: u64, transactions: Vec<Vec<u8>>) {
    for offset in 0..200u64 {
        let mut block = make_candidate_block(state, base_ts + offset, transactions.clone());
        let root = state
            .simulate_candidate_state_root(&block)
            .expect("simulation must succeed for a well-formed block");
        block.header.orchard_commitment_root = root;
        match state.apply_block(&block) {
            Ok(()) => return,
            Err(ChainError::Invalid(ValidationError::HashAboveTarget { .. })) => continue,
            Err(e) => panic!("unexpected block error: {e}"),
        }
    }
    panic!("failed to find a valid proof-of-work block");
}

// ---------------------------------------------------------------------------
// Regression: consensus-critical arithmetic hardening (M1-H source review)
// ---------------------------------------------------------------------------

/// A coinbase payout below aggregate block fees is rejected (underpayment).
/// `checked_sub` replaces the old `saturating_sub` so the block is rejected
/// instead of silently underclaiming. Exercised via `evaluate_candidate`
/// (no PoW required) to target the arithmetic directly.
#[test]
fn test_coinbase_underpayment_below_block_fees_rejected() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();
    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    // Seed the miner with a spendable balance so the fee-paying transfer is valid.
    state.accounts.entry(miner.address).or_default().balance = 1_000_000_000;

    // Block 1: coinbase pays out only 5_000 atoms while a transfer collects a
    // 19_500 atom fee. Payout < fees => underpayment must be rejected.
    let cb = make_coinbase(id, 1, miner.address, 5_000);
    let tx = make_transparent_transfer(id, &miner, alice.address, 100_000_000, 19_500, 0);
    let block = make_candidate_block(&state, genesis::GENESIS_TIMESTAMP + 10, vec![cb, tx]);
    let err = state.evaluate_candidate(&block).unwrap_err();
    assert!(
        err.to_string().contains("coinbase underpayment"),
        "expected coinbase underpayment error, got: {err}"
    );
}

/// Cumulative issuance is checked with `checked_add` against the 21M OWN cap;
/// claiming past the cap is rejected at `evaluate_candidate` time.
#[test]
fn test_cumulative_issuance_cap_rejected_at_evaluate_candidate() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();
    let miner_addr = derive_address(&[1u8; 32]);

    state.cumulative_issuance = MAX_SUPPLY_ATOMS;
    state.accounts.entry(miner_addr).or_default().balance = MAX_SUPPLY_ATOMS;

    let cb = make_coinbase(id, 1, miner_addr, 1);
    let block = make_candidate_block(&state, genesis::GENESIS_TIMESTAMP + 10, vec![cb]);
    let err = state.evaluate_candidate(&block).unwrap_err();
    assert!(
        err.to_string()
            .contains("cumulative issuance exceeds 21M OWN cap"),
        "expected cap error, got: {err}"
    );
}

/// Monetary conservation `T + S = I` holds exactly across a block that mixes a
/// coinbase subsidy, a transparent transfer with fees, and an underclaimed
/// subsidy. Fees move atoms between accounts; they are not new issuance.
/// Exercises the checked balance aggregation, checked payout-minus-fees, and
/// checked `T + S`.
#[test]
fn test_monetary_conservation_mixed_block_with_fees() {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();
    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    // Seed the ledger so conservation holds: T = I = 10 OWN, S = 0.
    state.cumulative_issuance = 1_000_000_000;
    state.accounts.entry(miner.address).or_default().balance = 1_000_000_000;

    let check_conservation = |state: &ChainState| {
        let t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
        let s_total = state.shielded_pool_balance();
        let i_total = state.cumulative_issuance();
        assert_eq!(
            t_total + s_total,
            i_total,
            "monetary conservation violated: T({t_total}) + S({s_total}) != I({i_total})"
        );
    };
    check_conservation(&state);

    // Block 1: coinbase claims 5 OWN (underclaim vs the 10 OWN schedule) and a
    // transfer of 1 OWN with a 19_500 atom fee moves funds miner -> alice.
    // Issuance grows only by `payout - fees` = 499_980_500 atoms.
    let cb = make_coinbase(id, 1, miner.address, 500_000_000);
    let tx = make_transparent_transfer(id, &miner, alice.address, 100_000_000, 19_500, 0);
    mine_pow_block_success(&mut state, genesis::GENESIS_TIMESTAMP + 10, vec![cb, tx]);
    check_conservation(&state);
    assert_eq!(state.cumulative_issuance(), 1_499_980_500);

    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.balance, 100_000_000);
    let t_total: u128 = state.accounts().values().map(|a| a.balance).sum();
    assert_eq!(t_total, 1_499_980_500);
}

// ---------------------------------------------------------------------------
// 12. Transfer Maturity and Confirmed Recipient Semantics (M1-H Review 3)
// ---------------------------------------------------------------------------

fn setup_funded_state() -> (ChainState, TestKeypair, TestKeypair, u64) {
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

#[test]
fn test_transfer_maturity_same_block_spending_rejected() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);

    ts += 120;
    // Alice transfers 100M atoms to Bob in block 102
    let tx_to_bob = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 0);
    // In the SAME block 102, Bob attempts to spend 50M to Charlie
    let tx_bob_spend = make_transparent_transfer(id, &bob, charlie.address, 50_000_000, 20_000, 0);

    let cb102 = make_coinbase(id, 102, miner.address, 40_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb102, tx_to_bob, tx_bob_spend]);

    let err = state.evaluate_candidate(&bad_block).unwrap_err();
    assert!(
        err.to_string().contains("insufficient spendable balance"),
        "expected insufficient spendable balance for same-block spend, got: {err}"
    );
    assert!(state.apply_block(&bad_block).is_err());
}

#[test]
fn test_transfer_maturity_succeeds_at_next_height() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);

    ts += 120;
    // Block 102: Alice transfers 100M atoms to Bob
    let tx_to_bob = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 0);
    let cb102 = make_coinbase(id, 102, miner.address, 20_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, tx_to_bob]);
    state.apply_block(&b102).unwrap();

    // At height 102, Bob has 100M balance; ordinary transfers are NOT stored in coinbase_tranches
    let bob_acc = state.account(&bob.address).unwrap();
    assert_eq!(bob_acc.balance, 100_000_000);
    assert!(bob_acc.coinbase_tranches.is_empty());

    // Block 103: Bob spends 50M atoms to Charlie
    ts += 120;
    let tx_bob_spend = make_transparent_transfer(id, &bob, charlie.address, 50_000_000, 20_000, 0);
    let cb103 = make_coinbase(id, 103, miner.address, 20_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, tx_bob_spend]);
    state.apply_block(&b103).unwrap();

    let bob_after = state.account(&bob.address).unwrap();
    assert_eq!(bob_after.balance, 100_000_000 - 50_000_000 - 20_000);
    let charlie_acc = state.account(&charlie.address).unwrap();
    assert_eq!(charlie_acc.balance, 50_000_000);
}

#[test]
fn test_guardian_protected_new_recipient_delay_and_confirmed_recipient() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Block 102: Alice configures guardians with new_recipient_delay = 10
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

    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Block 103: Alice transfers 100M to Bob (unconfirmed recipient)
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 1);
    let cb103 = make_coinbase(id, 103, miner.address, 20_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, tx1]);
    state.apply_block(&b103).unwrap();

    // Bob has received nothing yet
    assert!(state.account(&bob.address).is_none());
    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.pending_transfers.len(), 1);
    assert_eq!(alice_acc.pending_transfers[0].recipient, bob.address);
    assert_eq!(alice_acc.pending_transfers[0].release_height, 103 + 10);
    assert_eq!(alice_acc.pending_transfers[0].amount, 100_000_000);

    // Single-counting invariant: principal is in alice.balance, deducted from spendable
    let alice_bal = alice_acc.balance;
    let alice_spend = alice_acc.spendable_balance(103).unwrap();
    assert_eq!(alice_bal - alice_spend, 100_000_000);

    // Mine blocks 104..=112 (transfer is still pending)
    for h in 104..=112 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let b = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&b).unwrap();
    }
    assert_eq!(
        state
            .account(&alice.address)
            .unwrap()
            .pending_transfers
            .len(),
        1
    );
    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Block 113: pending transfer releases automatically at start of block
    ts += 120;
    let cb113 = make_coinbase(id, 113, miner.address, 0);
    let b113 = make_hybrid_block(&state, ts, vec![cb113]);
    state.apply_block(&b113).unwrap();

    let alice_113 = state.account(&alice.address).unwrap();
    assert_eq!(alice_113.pending_transfers.len(), 0);
    let bob_113 = state.account(&bob.address).unwrap();
    assert_eq!(bob_113.balance, 100_000_000);

    // Bob is now confirmed!
    assert!(state.is_confirmed_recipient(&alice.address, &bob.address));

    // Block 114: Alice transfers another 50M to Bob (already confirmed recipient)
    ts += 120;
    let tx2 = make_transparent_transfer(id, &alice, bob.address, 50_000_000, 20_000, 2);
    let cb114 = make_coinbase(id, 114, miner.address, 20_000);
    let b114 = make_hybrid_block(&state, ts, vec![cb114, tx2]);
    state.apply_block(&b114).unwrap();

    // Since Bob was confirmed, transfer executed immediately (no new pending transfer!)
    let alice_114 = state.account(&alice.address).unwrap();
    assert_eq!(alice_114.pending_transfers.len(), 0);
    let bob_114 = state.account(&bob.address).unwrap();
    assert_eq!(bob_114.balance, 150_000_000);
    // Ordinary transfers are not stored in coinbase_tranches
    assert!(bob_114.coinbase_tranches.is_empty());

    // Block 115: Bob spends the mature 150M atoms (150M - 20k fee)
    ts += 120;
    let tx3 = make_transparent_transfer(id, &bob, miner.address, 150_000_000 - 20_000, 20_000, 0);
    let b115 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 115, miner.address, 20_000), tx3],
    );
    state.apply_block(&b115).unwrap();
    assert_eq!(state.account(&bob.address).unwrap().balance, 0);
}

#[test]
fn test_cancellation_restores_pending_principal() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let dave = TestKeypair::from_seed(5);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Block 102: Configure guardians
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
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Block 103: Transfer 100M to Dave (pending)
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, dave.address, 100_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    let alice_103 = state.account(&alice.address).unwrap();
    assert_eq!(alice_103.pending_transfers.len(), 1);
    let tid = alice_103.pending_transfers[0].transfer_id;
    let spend_before_cancel = alice_103.spendable_balance(104).unwrap();

    // Block 104: Cancel pending transfer with 4-of-7 guardians
    ts += 120;
    let signers: Vec<(u8, &TestKeypair)> = (0..4).map(|i| (i as u8, &g_keys[i])).collect();
    let cancel_tx = make_cancel_pending(id, &alice, tid, 50_000, 2, &signers);
    let b104 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 104, miner.address, 50_000), cancel_tx],
    );
    state.apply_block(&b104).unwrap();

    let alice_104 = state.account(&alice.address).unwrap();
    assert_eq!(alice_104.pending_transfers.len(), 0);
    // Spendable balance restored by 100M principal minus 50k cancel fee
    assert_eq!(
        alice_104.spendable_balance(104).unwrap(),
        spend_before_cancel + 100_000_000 - 50_000
    );
    assert!(state.account(&dave.address).is_none());
}

#[test]
fn test_reorganization_restores_all_maturity_and_confirmation_state() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

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
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    for h in 104..=112 {
        ts += 120;
        let b = make_hybrid_block(&state, ts, vec![make_coinbase(id, h, miner.address, 0)]);
        state.apply_block(&b).unwrap();
    }

    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Block 113: release occurs, Bob confirmed
    ts += 120;
    let b113 = make_hybrid_block(&state, ts, vec![make_coinbase(id, 113, miner.address, 0)]);
    state.apply_block(&b113).unwrap();
    assert!(state.is_confirmed_recipient(&alice.address, &bob.address));
    assert_eq!(state.account(&bob.address).unwrap().balance, 100_000_000);

    // Rollback to height 112
    state.rollback_to(112).unwrap();

    // Confirmation status restored to unconfirmed!
    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));
    // Bob has balance 0
    assert!(state.account(&bob.address).is_none());
    // Alice has pending transfer restored
    assert_eq!(
        state
            .account(&alice.address)
            .unwrap()
            .pending_transfers
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// 13. Allowance and Nonce Consensus Enforcement (M1-H Review 4)
// ---------------------------------------------------------------------------

#[test]
fn test_allowance_exhaustion_transparent_types_1_to_4() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Configure guardians with allowance limit = 100M atoms, window = 100 blocks
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        100,
        100_000_000,
        100,
        &recovery.pubkey,
        &[],
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Type 1: Spend 90M atoms + 20k fee (90_020_000 total). Allowance remaining = 9_980_000.
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 90_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.allowance_spent, 90_020_000);

    // Type 1 rejection: Attempt to spend 15M atoms (exceeds remaining 9_980_000)
    ts += 120;
    let bad_tx1 = make_transparent_transfer(id, &alice, bob.address, 15_000_000, 20_000, 2);
    let bad_block_1 = make_candidate_block(
        &state,
        ts,
        vec![make_coinbase(id, 104, miner.address, 20_000), bad_tx1],
    );
    let err = state.evaluate_candidate(&bad_block_1).unwrap_err();
    assert!(err.to_string().contains("allowance limit exceeded"));

    // Type 2 rejection: Reconfigure guardians paying 20M fee (> remaining allowance)
    let reconfig_signers: Vec<(u8, &TestKeypair)> = (0..4).map(|i| (i as u8, &g_keys[i])).collect();
    let bad_type2 = make_configure_guardians(
        id,
        &alice,
        2,
        20_000_000,
        &guardians,
        10,
        100,
        100_000_000,
        100,
        &recovery.pubkey,
        &reconfig_signers,
    );
    let bad_block_2 = make_candidate_block(
        &state,
        ts,
        vec![make_coinbase(id, 104, miner.address, 20_000_000), bad_type2],
    );
    let err = state.evaluate_candidate(&bad_block_2).unwrap_err();
    assert!(err.to_string().contains("allowance limit exceeded"));

    // Type 3 rejection: Action fee paying 20M fee (> remaining allowance)
    let bad_action = make_guardian_action(
        id,
        alice.address,
        ownchain::auth::ACTION_FREEZE,
        20_000_000,
        &[],
        &reconfig_signers,
    );
    let bad_block_3 = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 104, miner.address, 20_000_000),
            bad_action,
        ],
    );
    let err = state.evaluate_candidate(&bad_block_3).unwrap_err();
    assert!(err.to_string().contains("allowance limit exceeded"));

    // Type 4 rejection: Cancel fee paying 20M fee (> remaining allowance)
    let tid = alice_acc.pending_transfers[0].transfer_id;
    let bad_cancel = make_cancel_pending(id, &alice, tid, 20_000_000, 2, &reconfig_signers);
    let bad_block_4 = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 104, miner.address, 20_000_000),
            bad_cancel,
        ],
    );
    let err = state.evaluate_candidate(&bad_block_4).unwrap_err();
    assert!(err.to_string().contains("allowance limit exceeded"));
}

#[test]
fn test_fee_inclusion_in_allowance_spending() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Allowance limit = 10_000_000 exactly
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        100,
        10_000_000,
        100,
        &recovery.pubkey,
        &[],
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Transfer amount 9_990_000 <= 10_000_000, but fee is 20_000. Total cost = 10_010_000 > 10_000_000
    ts += 120;
    let tx = make_transparent_transfer(id, &alice, bob.address, 9_990_000, 20_000, 1);
    let bad_block = make_candidate_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx],
    );
    let err = state.evaluate_candidate(&bad_block).unwrap_err();
    assert!(
        err.to_string().contains("allowance limit exceeded"),
        "expected allowance limit exceeded due to fee inclusion, got: {err}"
    );
}

#[test]
fn test_allowance_window_boundary_behavior() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Window length = 10 blocks, limit = 10_000_000
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        100,
        10_000_000,
        10,
        &recovery.pubkey,
        &[],
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Block 103: Exhaust full allowance (9_980_000 + 20_000 = 10_000_000)
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 9_980_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.allowance_window_start, 103);
    assert_eq!(alice_acc.allowance_spent, 10_000_000);

    // Mine blocks 104..=112 (window is [103, 113))
    for h in 104..=112 {
        ts += 120;
        let b = make_hybrid_block(&state, ts, vec![make_coinbase(id, h, miner.address, 0)]);
        state.apply_block(&b).unwrap();
    }

    // At block 112 (height 112 < 113), spend attempt fails
    ts += 120;
    let tx_fail = make_transparent_transfer(id, &alice, bob.address, 100_000, 20_000, 2);
    let b_fail = make_candidate_block(
        &state,
        ts,
        vec![make_coinbase(id, 112, miner.address, 20_000), tx_fail],
    );
    assert!(state.evaluate_candidate(&b_fail).is_err());

    // At block 113 (height 113 >= 113), window resets!
    let tx_success = make_transparent_transfer(id, &alice, bob.address, 1_000_000, 20_000, 2);
    let b113 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 113, miner.address, 20_000), tx_success],
    );
    state.apply_block(&b113).unwrap();

    let alice_113 = state.account(&alice.address).unwrap();
    assert_eq!(alice_113.allowance_window_start, 113);
    assert_eq!(alice_113.allowance_spent, 1_020_000);
}

#[test]
fn test_maximum_nonce_rejection() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);

    // Set Alice's nonce to u64::MAX
    state.accounts.get_mut(&alice.address).unwrap().nonce = u64::MAX;

    let tx = make_transparent_transfer(id, &alice, bob.address, 100_000, 20_000, u64::MAX);
    let block = make_candidate_block(
        &state,
        ts + 120,
        vec![make_coinbase(id, 102, miner.address, 20_000), tx],
    );
    let err = state.evaluate_candidate(&block).unwrap_err();
    assert!(err.to_string().contains("nonce overflow"));
}

#[test]
fn test_allowance_arithmetic_overflow() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);

    // Configure Alice's account with allowance_spent near u128::MAX
    let acc = state.accounts.get_mut(&alice.address).unwrap();
    acc.allowance_limit = u128::MAX;
    acc.allowance_window_len = 1000;
    acc.allowance_window_start = 100;
    acc.allowance_spent = u128::MAX - 10;

    let tx = make_transparent_transfer(id, &alice, bob.address, 20_000, 20_000, 0);
    let block = make_candidate_block(
        &state,
        ts + 120,
        vec![make_coinbase(id, 102, miner.address, 20_000), tx],
    );
    let err = state.evaluate_candidate(&block).unwrap_err();
    assert!(err.to_string().contains("allowance arithmetic overflow"));
}

#[test]
fn test_no_state_mutation_after_failed_checks() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);

    let before = state.clone();

    // Create a transaction that fails due to bad signature
    let mut bad_tx = make_transparent_transfer(id, &alice, bob.address, 100_000, 20_000, 0);
    bad_tx[131..195].copy_from_slice(&[0xee; 64]);

    let block = make_candidate_block(
        &state,
        ts + 120,
        vec![make_coinbase(id, 102, miner.address, 20_000), bad_tx],
    );
    assert!(state.apply_block(&block).is_err());

    // Verify completely unmutated
    assert_eq!(state, before);
}

#[test]
fn test_allowance_exhaustion_state_atomicity() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Configure guardians with allowance limit = 10_000_000 atoms
    let config = make_configure_guardians(
        id,
        &alice,
        0,
        50_000,
        &guardians,
        10,
        100,
        10_000_000,
        100,
        &recovery.pubkey,
        &[],
    );
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    let before_bad = state.clone();

    // Type 1 transfer exceeding allowance (15M > 10M limit)
    ts += 120;
    let bad_tx = make_transparent_transfer(id, &alice, bob.address, 15_000_000, 20_000, 1);
    let bad_block = make_candidate_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), bad_tx],
    );

    let err = state.apply_block(&bad_block).unwrap_err();
    assert!(err.to_string().contains("allowance limit exceeded"));

    // Verify completely unmutated: accounts, tree, anchors, tx_ids, confirmed_recipients, tip
    assert_eq!(state, before_bad);
}

// ---------------------------------------------------------------------------
// 14. Targeted Regression: Confirmed Recipients & Same-Block Incoming Isolation
// ---------------------------------------------------------------------------

#[test]
fn test_unprotected_transfer_followed_by_guardian_config_and_confirmed_transfer() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Step 1: Alice has NO guardians. Alice sends an ordinary transfer to Bob in block 102.
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 0);
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 20_000), tx1],
    );
    state.apply_block(&b102).unwrap();

    // In block 102, Bob is not confirmed yet (confirms after 1-block maturity at h+1)
    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Step 2: In block 103, Alice configures guardians with new_recipient_delay = 10
    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice,
        1,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 50_000), config],
    );
    state.apply_block(&b103).unwrap();

    // At height 103 (h+1 after block 102), Bob IS confirmed!
    assert!(state.is_confirmed_recipient(&alice.address, &bob.address));

    // Step 3: In block 104, Alice (now guardian-protected) sends another transfer to Bob
    ts += 120;
    let tx2 = make_transparent_transfer(id, &alice, bob.address, 50_000_000, 20_000, 2);
    let b104 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 104, miner.address, 20_000), tx2],
    );
    state.apply_block(&b104).unwrap();

    // Because Bob was previously confirmed, transfer executed immediately with no new-recipient delay!
    let alice_acc = state.account(&alice.address).unwrap();
    assert_eq!(alice_acc.pending_transfers.len(), 0);
    let bob_acc = state.account(&bob.address).unwrap();
    assert_eq!(bob_acc.balance, 150_000_000);
}

#[test]
fn test_ordinary_transfer_confirmation_at_h_plus_1() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);

    ts += 120;
    // Alice sends ordinary transfer to Bob at height 102
    let tx = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 0);
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 20_000), tx],
    );
    state.apply_block(&b102).unwrap();

    // At height 102, Bob is NOT confirmed
    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Advance to height 103 (empty block with only coinbase)
    ts += 120;
    let b103 = make_hybrid_block(&state, ts, vec![make_coinbase(id, 103, miner.address, 0)]);
    state.apply_block(&b103).unwrap();

    // At height 103 (h+1), Bob IS confirmed!
    assert!(state.is_confirmed_recipient(&alice.address, &bob.address));
}

#[test]
fn test_protected_pending_transfer_confirmation_at_release_height() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let carol = TestKeypair::from_seed(6);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Configure guardians at height 102 with new_recipient_delay = 10
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
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Send transfer to unconfirmed Carol at height 103 (release_height = 113)
    ts += 120;
    let tx = make_transparent_transfer(id, &alice, carol.address, 100_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx],
    );
    state.apply_block(&b103).unwrap();

    // During heights 103..=112, Carol is NOT confirmed
    for h in 104..=112 {
        ts += 120;
        let b = make_hybrid_block(&state, ts, vec![make_coinbase(id, h, miner.address, 0)]);
        state.apply_block(&b).unwrap();
        assert!(!state.is_confirmed_recipient(&alice.address, &carol.address));
    }

    // At height 113, pending transfer releases at start of block
    ts += 120;
    let b113 = make_hybrid_block(&state, ts, vec![make_coinbase(id, 113, miner.address, 0)]);
    state.apply_block(&b113).unwrap();

    // Carol is confirmed at release height 113!
    assert!(state.is_confirmed_recipient(&alice.address, &carol.address));
}

#[test]
fn test_cancelled_pending_transfer_remains_unconfirmed() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let dave = TestKeypair::from_seed(5);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Configure guardians at height 102 with new_recipient_delay = 10
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
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Transfer to unconfirmed Dave at height 103 (release_height = 113)
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, dave.address, 100_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    let tid = state.account(&alice.address).unwrap().pending_transfers[0].transfer_id;

    // Cancel pending transfer at height 104 with 4-of-7 guardians
    ts += 120;
    let signers: Vec<(u8, &TestKeypair)> = (0..4).map(|i| (i as u8, &g_keys[i])).collect();
    let cancel_tx = make_cancel_pending(id, &alice, tid, 50_000, 2, &signers);
    let b104 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 104, miner.address, 50_000), cancel_tx],
    );
    state.apply_block(&b104).unwrap();

    // Advance past original release height 113
    for h in 105..=115 {
        ts += 120;
        let b = make_hybrid_block(&state, ts, vec![make_coinbase(id, h, miner.address, 0)]);
        state.apply_block(&b).unwrap();
        // Dave remains unconfirmed forever
        assert!(!state.is_confirmed_recipient(&alice.address, &dave.address));
    }
}

#[test]
fn test_reorganization_and_replay_producing_identical_confirmation_state() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Block 102: Configure guardians
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
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Block 103: Transfer to Bob (pending until 113)
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    // Mine blocks 104..=112
    for h in 104..=112 {
        ts += 120;
        let b = make_hybrid_block(&state, ts, vec![make_coinbase(id, h, miner.address, 0)]);
        state.apply_block(&b).unwrap();
    }

    // At height 112: Bob is unconfirmed
    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Block 113: release occurs, Bob confirmed
    ts += 120;
    let b113 = make_hybrid_block(&state, ts, vec![make_coinbase(id, 113, miner.address, 0)]);
    state.apply_block(&b113).unwrap();
    assert!(state.is_confirmed_recipient(&alice.address, &bob.address));

    // Verify replay from genesis produces identical confirmation state
    let replayed = state.reconstruct_confirmed_recipients().unwrap();
    assert_eq!(state.confirmed_recipients, replayed);

    // Rollback to height 112
    state.rollback_to(112).unwrap();
    assert!(!state.is_confirmed_recipient(&alice.address, &bob.address));

    // Verify replay at rolled-back state matches exactly
    let replayed_after_rollback = state.reconstruct_confirmed_recipients().unwrap();
    assert_eq!(state.confirmed_recipients, replayed_after_rollback);
}

#[test]
fn test_same_block_incoming_cannot_fund_types_1_to_4_fees_or_principal() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    // Step 1: Fund Bob with 100k atoms at height 102
    ts += 120;
    let seed_bob = make_transparent_transfer(id, &alice, bob.address, 100_000, 20_000, 0);
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 20_000), seed_bob],
    );
    state.apply_block(&b102).unwrap();

    // Step 2: Bob configures guardians at height 103, paying 100k fee, leaving 0 balance and nonce 1
    ts += 120;
    let config = make_configure_guardians(
        id,
        &bob,
        0,
        100_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 100_000), config],
    );
    state.apply_block(&b103).unwrap();
    assert_eq!(state.account(&bob.address).unwrap().balance, 0);
    assert!(state.account(&bob.address).unwrap().guardian_enabled);

    // Step 3: In block 104 candidate, Alice transfers 100M atoms to Bob.
    // In that SAME candidate block, Bob tries to spend or pay fees for Types 1 to 4 using incoming funds.
    ts += 120;
    let tx_to_bob = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 1);

    // 1. Bob attempts Type 1 spend (principal + fee) in same block: REJECTED
    let tx_type1 = make_transparent_transfer(id, &bob, charlie.address, 50_000_000, 20_000, 1);
    let bad_block_1 = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 104, miner.address, 40_000),
            tx_to_bob.clone(),
            tx_type1,
        ],
    );
    let err1 = state.evaluate_candidate(&bad_block_1).unwrap_err();
    assert!(err1.to_string().contains("insufficient spendable balance"));

    // 2. Bob attempts Type 2 configure guardians (fee) in same block: REJECTED
    let tx_type2 = make_configure_guardians(
        id,
        &bob,
        1,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery.pubkey,
        &[],
    );
    let bad_block_2 = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 104, miner.address, 70_000),
            tx_to_bob.clone(),
            tx_type2,
        ],
    );
    let err2 = state.evaluate_candidate(&bad_block_2).unwrap_err();
    assert!(err2.to_string().contains("insufficient balance for fee"));

    // 3. Bob attempts Type 3 guardian action (fee) in same block: REJECTED
    let signers: Vec<(u8, &TestKeypair)> = (0..4).map(|i| (i as u8, &g_keys[i])).collect();
    let tx_type3 = make_guardian_action(
        id,
        bob.address,
        ownchain::auth::ACTION_FREEZE,
        50_000,
        &[],
        &signers,
    );
    let bad_block_3 = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 104, miner.address, 70_000),
            tx_to_bob.clone(),
            tx_type3,
        ],
    );
    let err3 = state.evaluate_candidate(&bad_block_3).unwrap_err();
    assert!(err3.to_string().contains("insufficient balance for fee"));

    // 4. Bob attempts Type 4 cancel pending (fee) in same block: REJECTED
    let tx_type4 = make_cancel_pending(id, &bob, Hash::ZERO, 50_000, 1, &signers);
    let bad_block_4 = make_candidate_block(
        &state,
        ts,
        vec![
            make_coinbase(id, 104, miner.address, 70_000),
            tx_to_bob,
            tx_type4,
        ],
    );
    let err4 = state.evaluate_candidate(&bad_block_4).unwrap_err();
    assert!(err4.to_string().contains("insufficient balance for fee"));
}

#[test]
fn test_released_pending_transfer_spendable_in_same_block() {
    let id = devnet_chain_id();
    let (mut state, miner, alice, mut ts) = setup_funded_state();
    let bob = TestKeypair::from_seed(3);
    let charlie = TestKeypair::from_seed(4);
    let recovery = TestKeypair::from_seed(99);
    let g_keys: Vec<TestKeypair> = (10..17).map(TestKeypair::from_seed).collect();
    let mut guardians = [[0u8; 32]; 7];
    for (i, k) in g_keys.iter().enumerate() {
        guardians[i] = k.pubkey;
    }

    ts += 120;
    // Configure guardians at height 102 with new_recipient_delay = 10
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
    let b102 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 102, miner.address, 50_000), config],
    );
    state.apply_block(&b102).unwrap();

    // Send transfer to unconfirmed Bob at height 103 (release_height = 113)
    ts += 120;
    let tx1 = make_transparent_transfer(id, &alice, bob.address, 100_000_000, 20_000, 1);
    let b103 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 103, miner.address, 20_000), tx1],
    );
    state.apply_block(&b103).unwrap();

    // Mine blocks 104..=112
    for h in 104..=112 {
        ts += 120;
        let b = make_hybrid_block(&state, ts, vec![make_coinbase(id, h, miner.address, 0)]);
        state.apply_block(&b).unwrap();
    }

    // Block 113: Pending transfer releases at start-of-block.
    // In that SAME block 113, Bob spends 50M to Charlie!
    ts += 120;
    let tx_bob_spend = make_transparent_transfer(id, &bob, charlie.address, 50_000_000, 20_000, 0);
    let b113 = make_hybrid_block(
        &state,
        ts,
        vec![make_coinbase(id, 113, miner.address, 20_000), tx_bob_spend],
    );
    // Must succeed because released pending transfers are already mature!
    state.apply_block(&b113).unwrap();

    assert_eq!(
        state.account(&bob.address).unwrap().balance,
        100_000_000 - 50_000_000 - 20_000
    );
    assert_eq!(state.account(&charlie.address).unwrap().balance, 50_000_000);
}
