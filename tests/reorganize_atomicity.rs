//! Failed-reorganization atomicity regression suite for `ChainState::reorganize()`.
//!
//! The protocol state-transition guarantees ("Reorganization rollback",
//! `docs/protocol-v1.md` state-transition invariants) require a reorganization
//! whose replacement-block application fails to fail closed: the accepted
//! chain — tip, block sequence, cumulative work, accounts, nullifiers, shielded
//! pool balance, Orchard commitment tree, historical anchors, and every
//! historical rollback snapshot — must be restored exactly, and the original
//! chain must remain usable for subsequent block application.
//!
//! The tests build an active chain of four post-genesis blocks, clone it,
//! present an alternative branch that forks below the active tip with one valid
//! replacement block followed by one invalid replacement block, and assert that
//! `reorganize()` reports the error without mutating any observable state.
//!
//! The current implementation marks the failure with a post-failure
//! `rollback_to(backup_tip)` repair. After the fork-point rollback that
//! snapshot no longer exists (history entries are truncated by
//! `rollback_to`), and `rollback_to` early-returns once `blocks.len()` is
//! shorter than the target — a silent no-op. The first replacement block is
//! therefore left stranded in the accepted chain, which these tests detect.

use ownchain::account::scheduled_subsidy;
use ownchain::block::Block;
use ownchain::chain::{ChainError, ChainState};
use ownchain::genesis::{genesis_block, DEVNET, GENESIS_TIMESTAMP};
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;

/// The devnet chain ID used by every state in this suite.
fn devnet_chain_id() -> Hash {
    hash::chain_id(DEVNET)
}

/// Builds the 83-byte Type 0 coinbase transaction.
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

/// Builds a validation-consistent child of `state.tip()`, computing the exact
/// composite state root for the header slot.
///
/// All test blocks sit below height 16, where the expected difficulty is
/// unconditionally 1, so no proof-of-work mining is required.
fn make_child_block(state: &ChainState, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let parent = state.tip().expect("state must have a tip");
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    let mut block = Block {
        header: Header {
            version: 1,
            chain_id: state.chain_id(),
            height,
            parent_block_id: parent.block_id(),
            transaction_root: merkle::tx_root(&ids),
            orchard_commitment_root: Hash::ZERO,
            timestamp,
            difficulty: state
                .expected_difficulty_for_next_block()
                .expect("expected difficulty must be computable"),
            nonce: 0,
        },
        transactions,
    };
    let state_root = state
        .simulate_candidate_state_root(&block)
        .expect("candidate must simulate cleanly");
    block.header.orchard_commitment_root = state_root;
    block
}

/// Everything the atomicity tests need: the pristine original chain, the
/// failing alternative branch, and a control proving the original chain still
/// extends cleanly once the failure path is fixed.
struct AtomicityFixture {
    /// Original chain: genesis + 4 blocks, tip at height 4. Pristine.
    original: ChainState,
    /// Height whose remaining prefix survives the failed reorganization.
    fork_height: u64,
    /// Alternative branch: [valid replacement at height 3, invalid at height 4].
    failing_branch: Vec<Block>,
    /// Valid height-5 child of the original tip.
    next_original_block: Block,
    /// Control: pristine original with the height-5 block applied.
    control_extended: ChainState,
}

fn build_fixture() -> AtomicityFixture {
    let chain_id = devnet_chain_id();
    let genesis = genesis_block(chain_id);
    let mut state = ChainState::from_genesis(&genesis).expect("genesis must apply");

    let miner = Hash::new([0x11; 32]);
    let fork_miner = Hash::new([0x22; 32]);

    // Active chain: genesis plus four blocks (tip at height 4).
    let mut blocks = Vec::with_capacity(4);
    for height in 1..=4u64 {
        let cb = make_coinbase(chain_id, height, miner, scheduled_subsidy(height) as u64);
        let block = make_child_block(&state, GENESIS_TIMESTAMP + height * 120, vec![cb]);
        state
            .apply_block(&block)
            .expect("active chain block must apply");
        blocks.push(block);
    }
    assert_eq!(state.tip_height(), Some(4));

    let original = state;
    // Fork below the active tip: the alternative branch replaces heights 3-4.
    let fork_parent_id = blocks[1].block_id();
    assert_eq!(
        original.block_at(2).map(|b| b.block_id()),
        Some(fork_parent_id),
        "the fork parent must be the block at height 2, below the height-4 tip"
    );
    let fork_height = 2u64;

    // Alternative branch built on an exact mirror of the fork point:
    // replacement 1 (height 3) is valid, replacement 2 (height 4) is invalid.
    let mut mirror = original.clone();
    mirror
        .rollback_to(fork_height)
        .expect("the fork-point historical snapshot must exist");
    assert_eq!(mirror.tip_block_id(), Some(fork_parent_id));

    let replacement3 = make_child_block(
        &mirror,
        GENESIS_TIMESTAMP + 3 * 120,
        vec![make_coinbase(
            chain_id,
            3,
            fork_miner,
            scheduled_subsidy(3) as u64,
        )],
    );
    mirror
        .apply_block(&replacement3)
        .expect("valid replacement must apply on the fork mirror");

    let mut replacement4 = make_child_block(
        &mirror,
        GENESIS_TIMESTAMP + 4 * 120,
        vec![make_coinbase(
            chain_id,
            4,
            fork_miner,
            scheduled_subsidy(4) as u64,
        )],
    );
    let honest_root = replacement4.header.orchard_commitment_root;
    replacement4.header.orchard_commitment_root = Hash::new([0xde; 32]);
    assert_ne!(
        replacement4.header.orchard_commitment_root, honest_root,
        "test construction: the corrupted state root must differ from the honest one"
    );
    assert!(
        mirror.apply_block(&replacement4).is_err(),
        "test construction: the corrupted replacement must be invalid"
    );

    // Valid height-5 extension of the ORIGINAL chain (never part of the
    // alternative branch). The control applies it to a pristine clone.
    let next_original_block = make_child_block(
        &original,
        GENESIS_TIMESTAMP + 5 * 120,
        vec![make_coinbase(
            chain_id,
            5,
            miner,
            scheduled_subsidy(5) as u64,
        )],
    );
    let mut control_extended = original.clone();
    control_extended
        .apply_block(&next_original_block)
        .expect("the original chain must extend cleanly on the control");
    assert_eq!(control_extended.tip_height(), Some(5));

    AtomicityFixture {
        original,
        fork_height,
        failing_branch: vec![replacement3, replacement4],
        next_original_block,
        control_extended,
    }
}

/// A failing reorganization must fail closed: it reports the validation error
/// and restores the accepted chain exactly — tip, block sequence, cumulative
/// work, accounts, nullifiers, shielded pool, Orchard tree, anchors, and every
/// historical rollback snapshot.
#[test]
fn failed_reorganize_reports_error_and_restores_exact_original_state() {
    let fixture = build_fixture();
    let mut state = fixture.original.clone();

    let result = state.reorganize(&fixture.failing_branch);
    let error = result
        .expect_err("reorganize must reject a branch whose later replacement block is invalid");
    assert!(
        matches!(error, ChainError::Invalid(_)),
        "the failure must be reported as a permanent validation error, got {error:?}"
    );

    // Full structural equality with the pristine original: this covers every
    // private component, including the historical rollback `history` map.
    assert_eq!(
        state, fixture.original,
        "a failed reorganization must leave the accepted chain untouched"
    );

    // Component-level diagnostics, independently of the full-struct equality:
    assert_eq!(
        state.tip_block_id(),
        fixture.original.tip_block_id(),
        "the original tip must be preserved"
    );
    assert_eq!(
        state.tip_height(),
        fixture.original.tip_height(),
        "the original tip height must be preserved"
    );
    assert_eq!(
        state.blocks(),
        fixture.original.blocks(),
        "the original block sequence must be preserved"
    );
    assert_eq!(
        state.cumulative_work(),
        fixture.original.cumulative_work(),
        "the original cumulative work must be preserved"
    );
    assert_eq!(
        state.cumulative_work_history(),
        fixture.original.cumulative_work_history(),
        "the original cumulative work history must be preserved"
    );
    assert_eq!(
        state.accounts(),
        fixture.original.accounts(),
        "the original account ledger must be preserved"
    );
    assert_eq!(
        state.nullifier_set(),
        fixture.original.nullifier_set(),
        "the original nullifier set must be preserved"
    );
    assert_eq!(
        state.shielded_pool_balance(),
        fixture.original.shielded_pool_balance(),
        "the original shielded pool balance must be preserved"
    );
    assert_eq!(
        state.cumulative_issuance(),
        fixture.original.cumulative_issuance(),
        "the original cumulative issuance must be preserved"
    );
    assert_eq!(
        state.orchard_tree(),
        fixture.original.orchard_tree(),
        "the original Orchard commitment tree must be preserved"
    );
    assert_eq!(
        state.orchard_root(),
        fixture.original.orchard_root(),
        "the original Orchard root must be preserved"
    );
    assert_eq!(
        state.historical_anchors(),
        fixture.original.historical_anchors(),
        "the original historical anchors must be preserved"
    );
    assert_eq!(
        state.accepted_transaction_ids(),
        fixture.original.accepted_transaction_ids(),
        "the original accepted transaction IDs must be preserved"
    );
    assert_eq!(
        state.composite_state_root(),
        fixture.original.composite_state_root(),
        "the original composite state root must be preserved"
    );
    assert_eq!(
        state.snapshot(),
        fixture.original.snapshot(),
        "the original consensus snapshot (including historical rollback data) must be preserved"
    );
}

/// After a failed reorganization the original chain must remain usable: a
/// valid block extending the original tip must apply, and the result must be
/// indistinguishable from a chain that never saw the failed reorganization.
#[test]
fn failed_reorganize_leaves_original_chain_usable_for_valid_blocks() {
    let fixture = build_fixture();
    let mut state = fixture.original.clone();

    state
        .reorganize(&fixture.failing_branch)
        .expect_err("reorganize must reject a branch whose later replacement block is invalid");

    state
        .apply_block(&fixture.next_original_block)
        .expect("the original chain must still extend after a failed reorganization");

    assert_eq!(
        state, fixture.control_extended,
        "post-failure extension must match the clean control exactly"
    );
    assert_eq!(state.tip_height(), Some(5));
}

/// The failed reorganization must preserve the historical rollback snapshots.
/// Rolling back to the original tip height must still work, restore the exact
/// pristine chain, and the rolled-back chain must remain extendable by the
/// original blocks.
#[test]
fn failed_reorganize_preserves_historical_rollback_data() {
    let fixture = build_fixture();
    let mut state = fixture.original.clone();

    state
        .reorganize(&fixture.failing_branch)
        .expect_err("reorganize must reject a branch whose later replacement block is invalid");

    // The snapshot at the ORIGINAL tip height must still exist: rolling back
    // to it is a pure no-op that must restore the pristine chain one-for-one.
    state
        .rollback_to(4)
        .expect("the tip-height historical snapshot must survive a failed reorganization");
    assert_eq!(
        state, fixture.original,
        "rollback to the original tip height must restore the pristine chain exactly"
    );

    // Rolling back to the fork height must restore the exact height-2 state,
    // and the rolled-back chain must remain extendable by the original
    // height-3 block, matching the pristine rollback path one-for-one.
    let mut pristine_path = fixture.original.clone();
    pristine_path
        .rollback_to(fixture.fork_height)
        .expect("the fork-point historical snapshot must survive a failed reorganization");
    pristine_path
        .apply_block(
            fixture
                .original
                .block_at(3)
                .expect("the original chain has a height-3 block"),
        )
        .expect("the original height-3 block must apply after rollback");

    state
        .rollback_to(fixture.fork_height)
        .expect("the fork-point historical snapshot must survive a failed reorganization");
    assert_eq!(state.tip_height(), Some(2));
    assert_eq!(
        state.tip_block_id(),
        fixture.original.block_at(2).map(|b| b.block_id()),
        "rollback must restore the exact original height-2 tip"
    );
    state
        .apply_block(
            fixture
                .original
                .block_at(3)
                .expect("the original chain has a height-3 block"),
        )
        .expect("the original height-3 block must apply after rollback");
    assert_eq!(
        state, pristine_path,
        "rollback after a failed reorganization must match the pristine rollback path exactly"
    );
}
