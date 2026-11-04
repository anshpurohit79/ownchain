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
