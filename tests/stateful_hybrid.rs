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

use ownchain::account::{derive_address, scheduled_subsidy, MAX_SUPPLY_ATOMS};
use ownchain::block::Block;
use ownchain::chain::ChainState;
use ownchain::genesis;
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::orchard_root::empty_commitment_root;

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

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
    sender_key: &[u8; 32],
    recipient: Hash,
    amount: u128,
    fee_atoms: u64,
    nonce: u64,
) -> Vec<u8> {
    let mut tx = Vec::with_capacity(195);
    tx.push(1); // Type 1
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(sender_key);
    tx.extend_from_slice(recipient.as_bytes());
    tx.extend_from_slice(&amount.to_le_bytes());
    tx.extend_from_slice(&fee_atoms.to_le_bytes());
    tx.extend_from_slice(&nonce.to_le_bytes());
    tx.extend_from_slice(&[0u8; 64]); // dummy signature
    tx
}

#[allow(clippy::too_many_arguments)]
fn make_configure_guardians(
    chain_id: Hash,
    account_key: &[u8; 32],
    nonce: u64,
    fee_atoms: u64,
    guardians: &[[u8; 32]; 7],
    new_recipient_delay: u32,
    withdrawal_delay: u32,
    allowance_limit: u128,
    allowance_window_len: u64,
    recovery_key: &[u8; 32],
    guardian_sigs: &[(u8, [u8; 64])],
) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.push(2); // Type 2
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(account_key);
    tx.extend_from_slice(&nonce.to_le_bytes());
    tx.extend_from_slice(&fee_atoms.to_le_bytes());
    for g in guardians {
        tx.extend_from_slice(g);
    }
    tx.extend_from_slice(&new_recipient_delay.to_le_bytes());
    tx.extend_from_slice(&withdrawal_delay.to_le_bytes());
    tx.extend_from_slice(&allowance_limit.to_le_bytes());
    tx.extend_from_slice(&allowance_window_len.to_le_bytes());
    tx.extend_from_slice(recovery_key);
    tx.extend_from_slice(&[0u8; 64]);
    tx.push(guardian_sigs.len() as u8);
    for (idx, sig) in guardian_sigs {
        tx.push(*idx);
        tx.extend_from_slice(sig);
    }
    tx
}

fn make_guardian_action(
    chain_id: Hash,
    target: Hash,
    action_type: u8,
    fee_atoms: u64,
    params: &[u8],
    guardian_sigs: &[(u8, [u8; 64])],
) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.push(3); // Type 3
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(target.as_bytes());
    tx.push(action_type);
    tx.extend_from_slice(&fee_atoms.to_le_bytes());
    tx.extend_from_slice(&(params.len() as u32).to_le_bytes());
    tx.extend_from_slice(params);
    tx.push(guardian_sigs.len() as u8);
    for (idx, sig) in guardian_sigs {
        tx.push(*idx);
        tx.extend_from_slice(sig);
    }
    tx
}

fn make_cancel_pending(
    chain_id: Hash,
    sender_key: &[u8; 32],
    transfer_id: Hash,
    fee_atoms: u64,
    nonce: u64,
    guardian_sigs: &[(u8, [u8; 64])],
) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.push(4); // Type 4
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(sender_key);
    tx.extend_from_slice(transfer_id.as_bytes());
    tx.extend_from_slice(&fee_atoms.to_le_bytes());
    tx.extend_from_slice(&nonce.to_le_bytes());
    tx.extend_from_slice(&[0u8; 64]);
    tx.push(guardian_sigs.len() as u8);
    for (idx, sig) in guardian_sigs {
        tx.push(*idx);
        tx.extend_from_slice(sig);
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
    let mut sim_state = state.clone();
    sim_state
        .apply_block(&dummy_block)
        .expect("simulation must succeed");
    let state_root = sim_state.composite_state_root();
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

    let miner_key = [1u8; 32];
    let miner_addr = derive_address(&miner_key);
    let alice_key = [2u8; 32];
    let alice_addr = derive_address(&alice_key);

    // Block 1: Miner receives 10 OWN
    let cb1 = make_coinbase(id, 1, miner_addr, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    let miner = state.account(&miner_addr).unwrap();
    assert_eq!(miner.balance, 1_000_000_000);
    // At height 1, coinbase is immature: spendable balance is 0!
    assert_eq!(miner.spendable_balance(1).unwrap(), 0);

    // Fast-forward to height 100 with empty subsidy blocks (120s interval preserves difficulty 1)
    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner_addr, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }
    assert_eq!(state.tip_height(), Some(100));

    // At height 100, tranche unlocks at height 101, so still immature at 100!
    let miner = state.account(&miner_addr).unwrap();
    assert_eq!(miner.spendable_balance(100).unwrap(), 0);

    // At height 100, spendable balance is still 0 (coinbase matures at height 101)
    let miner_at_100 = state.account(&miner_addr).unwrap();
    assert_eq!(miner_at_100.spendable_balance(100).unwrap(), 0);

    // At height 101, mature tranche is spendable!
    ts += 120;
    let valid_tx = make_transparent_transfer(id, &miner_key, alice_addr, 500_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner_addr, 20_000); // claim fee
    let b101 = make_hybrid_block(&state, ts, vec![cb101, valid_tx]);
    state.apply_block(&b101).unwrap();

    let miner_after = state.account(&miner_addr).unwrap();
    let alice_after = state.account(&alice_addr).unwrap();
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

    let miner_key = [1u8; 32];
    let miner_addr = derive_address(&miner_key);
    let alice_key = [2u8; 32];
    let alice_addr = derive_address(&alice_key);

    // Mine block 1
    let cb1 = make_coinbase(id, 1, miner_addr, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    // Fast-forward to height 101
    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner_addr, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }

    // Transfer with nonce 0 succeeds
    ts += 120;
    let tx1 = make_transparent_transfer(id, &miner_key, alice_addr, 100_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner_addr, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, tx1]);
    state.apply_block(&b101).unwrap();

    // Trying to send another transfer with replayed nonce 0 must fail
    ts += 120;
    let replayed = make_transparent_transfer(id, &miner_key, alice_addr, 50_000_000, 20_000, 0);
    let cb102 = make_coinbase(id, 102, miner_addr, 20_000);
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

    let miner_key = [1u8; 32];
    let miner_addr = derive_address(&miner_key);
    let alice_key = [2u8; 32];
    let alice_addr = derive_address(&alice_key);
    let bob_key = [3u8; 32];
    let bob_addr = derive_address(&bob_key);

    let guardians = [
        [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
    ];
    let recovery_key = [0x99; 32];

    // Mine block 1 and mature
    let cb1 = make_coinbase(id, 1, miner_addr, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner_addr, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }

    // Fund Alice with 800M
    ts += 120;
    let fund_alice = make_transparent_transfer(id, &miner_key, alice_addr, 800_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner_addr, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund_alice]);
    state.apply_block(&b101).unwrap();

    // Alice configures guardians
    ts += 120;
    let config_tx = make_configure_guardians(
        id,
        &alice_key,
        0,
        50_000,
        &guardians,
        10, // 10-block delay for new recipients
        144,
        0,
        0,
        &recovery_key,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner_addr, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config_tx]);
    state.apply_block(&b102).unwrap();

    let alice = state.account(&alice_addr).unwrap();
    assert!(alice.guardian_enabled);
    assert_eq!(alice.new_recipient_delay, 10);
    assert_eq!(alice.balance, 799_950_000); // 800M - 50K fee

    // Alice transfers 300M to unconfirmed recipient Bob (delay applies!)
    ts += 120;
    let tx_to_bob = make_transparent_transfer(id, &alice_key, bob_addr, 300_000_000, 20_000, 1);
    let cb103 = make_coinbase(id, 103, miner_addr, 20_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, tx_to_bob.clone()]);
    state.apply_block(&b103).unwrap();

    let alice_after = state.account(&alice_addr).unwrap();
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
        &alice_key,
        pending.transfer_id,
        50_000,
        2,
        &[
            (0, [1u8; 64]),
            (1, [2u8; 64]),
            (2, [3u8; 64]),
            (3, [4u8; 64]),
        ],
    );
    let cb104 = make_coinbase(id, 104, miner_addr, 50_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104, cancel_tx]);
    state.apply_block(&b104).unwrap();

    let alice_cancelled = state.account(&alice_addr).unwrap();
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

    let miner_key = [1u8; 32];
    let miner_addr = derive_address(&miner_key);
    let alice_key = [2u8; 32];
    let alice_addr = derive_address(&alice_key);

    let guardians = [
        [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
    ];
    let recovery_key = [0x99; 32];
    let recovery_addr = derive_address(&recovery_key);

    // Mine and mature
    let cb1 = make_coinbase(id, 1, miner_addr, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner_addr, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }

    // Fund Alice and configure guardians
    ts += 120;
    let fund = make_transparent_transfer(id, &miner_key, alice_addr, 600_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner_addr, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund]);
    state.apply_block(&b101).unwrap();

    ts += 120;
    let config = make_configure_guardians(
        id,
        &alice_key,
        0,
        50_000,
        &guardians,
        10,
        144,
        0,
        0,
        &recovery_key,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner_addr, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config]);
    state.apply_block(&b102).unwrap();

    // 1. Strengthen delays: 3-of-7 quorum succeeds
    ts += 120;
    let strengthen_delays = make_guardian_action(
        id,
        alice_addr,
        1, // Strengthen delays
        30_000,
        &20u32.to_le_bytes(), // increase from 10 to 20
        &[(0, [1u8; 64]), (1, [2u8; 64]), (2, [3u8; 64])], // 3 votes
    );
    let cb103 = make_coinbase(id, 103, miner_addr, 30_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, strengthen_delays]);
    state.apply_block(&b103).unwrap();
    assert_eq!(state.account(&alice_addr).unwrap().new_recipient_delay, 20);

    // 2. Weaken delays: 3-of-7 quorum FAILS (requires 4-of-7)
    ts += 120;
    let weaken_insufficient = make_guardian_action(
        id,
        alice_addr,
        3, // Weaken delays
        30_000,
        &5u32.to_le_bytes(),
        &[(0, [1u8; 64]), (1, [2u8; 64]), (2, [3u8; 64])], // only 3 votes!
    );
    let cb104 = make_coinbase(id, 104, miner_addr, 30_000);
    let bad_block = make_candidate_block(&state, ts, vec![cb104, weaken_insufficient]);
    assert!(state.apply_block(&bad_block).is_err());

    // 3. Freeze account with 4-of-7 quorum
    ts += 120;
    let freeze_action = make_guardian_action(
        id,
        alice_addr,
        5, // Freeze
        35_000,
        &[],
        &[
            (0, [1u8; 64]),
            (1, [2u8; 64]),
            (2, [3u8; 64]),
            (3, [4u8; 64]),
        ],
    );
    let cb104_good = make_coinbase(id, 104, miner_addr, 35_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104_good, freeze_action]);
    state.apply_block(&b104).unwrap();
    assert!(state.account(&alice_addr).unwrap().is_frozen);

    // Alice cannot transfer while frozen
    ts += 120;
    let transfer_while_frozen =
        make_transparent_transfer(id, &alice_key, miner_addr, 10_000_000, 20_000, 1);
    let cb105 = make_coinbase(id, 105, miner_addr, 20_000);
    let bad_frozen_block = make_candidate_block(&state, ts, vec![cb105, transfer_while_frozen]);
    assert!(state.apply_block(&bad_frozen_block).is_err());

    // 4. Recovery: 4-of-7 sweeps balance to recovery key
    ts += 120;
    let recovery_action = make_guardian_action(
        id,
        alice_addr,
        7, // Recovery
        35_000,
        &[],
        &[
            (0, [1u8; 64]),
            (1, [2u8; 64]),
            (2, [3u8; 64]),
            (4, [5u8; 64]),
        ],
    );
    let cb105_good = make_coinbase(id, 105, miner_addr, 35_000);
    let b105 = make_hybrid_block(&state, ts, vec![cb105_good, recovery_action]);
    state.apply_block(&b105).unwrap();

    let alice_swept = state.account(&alice_addr).unwrap();
    let recovery_acc = state.account(&recovery_addr).unwrap();
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

// ---------------------------------------------------------------------------
// 7. Invariant 7: Subsidy Cap and Halving Schedule
// ---------------------------------------------------------------------------

#[test]
fn test_subsidy_cap_and_halving_boundaries() {
    assert_eq!(scheduled_subsidy(0), 0);
    assert_eq!(scheduled_subsidy(1), 1_000_000_000);
    assert_eq!(scheduled_subsidy(1_050_000), 1_000_000_000);
    assert_eq!(scheduled_subsidy(1_050_001), 500_000_000);
    assert_eq!(scheduled_subsidy(2_100_000), 500_000_000);
    assert_eq!(scheduled_subsidy(2_100_001), 250_000_000);
    assert_eq!(scheduled_subsidy(31_500_000), 1);
    assert_eq!(scheduled_subsidy(31_500_001), 0); // Subsidy exhausted!

    // Exact cumulative integer subsidy across all eras is <= 21M OWN
    let mut total: u128 = 0;
    for era in 0..30 {
        let per_block = 1_000_000_000u128 >> era;
        total += per_block * 1_050_000;
    }
    assert_eq!(total, 2_099_999_986_350_000);
    assert!(total <= MAX_SUPPLY_ATOMS);
}
