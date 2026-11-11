//! Deterministic equal-work fork-choice tie-break regression suite.
//!
//! `docs/protocol-v1.md` §4 defines fork choice as the valid chain with the
//! greatest cumulative work; when cumulative work is equal, the block-ID
//! sequences from genesis are compared and the branch whose sequence is
//! lexicographically smaller at the first differing height wins. This suite
//! pins that rule through the node runtime's public block-submission path
//! (`NodeRuntime::submit_block`), which is where the first-seen branch is
//! currently retained on equal cumulative work.
//!
//! Scenarios (every branch block carries a single coinbase at difficulty 1, so
//! both branches have identical cumulative work throughout the comparison):
//! 1. Larger branch first, smaller branch second: the smaller branch must win.
//! 2. Smaller branch first, larger branch second: the smaller branch must stay.
//! 3. Two independent runtimes fed opposite submission orders must converge on
//!    the same tip block ID and composite state root.
//! 4. With a shared prefix, the first differing block ID (not the final tip
//!    block ID) decides the winner.
//!
//! The height-2/height-3 tip block IDs are deliberately constructed to be
//! ordered the *opposite* way from the deciding height-1/height-2 block IDs, so
//! a fork choice that naively compared only final tip block IDs would pick the
//! larger branch and fail these tests.

use tempfile::TempDir;

use ownchain::account::scheduled_subsidy;
use ownchain::block::Block;
use ownchain::chain::ChainState;
use ownchain::genesis::{genesis_block, DEVNET, GENESIS_TIMESTAMP};
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::node::{NodeConfig, NodeRuntime};
use ownchain::orchard_root::empty_commitment_root;

/// The devnet chain ID used by every runtime in this suite.
fn devnet_chain_id() -> Hash {
    hash::chain_id(DEVNET)
}

fn create_node_config(dir: &TempDir) -> NodeConfig {
    let mut config = NodeConfig::default_devnet(dir.path().to_path_buf());
    config.listen_addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    config
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

/// Builds a validation-consistent child of `state.tip()` with the given
/// content, computing the exact composite state root for the header slot.
///
/// All test blocks sit below height 16, where the expected difficulty is
/// unconditionally 1, so no RandomX proof-of-work mining is required.
fn make_child_block(
    state: &ChainState,
    timestamp: u64,
    transactions: Vec<Vec<u8>>,
    nonce: u64,
) -> Block {
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
            orchard_commitment_root: empty_commitment_root(),
            timestamp,
            difficulty: state
                .expected_difficulty_for_next_block()
                .expect("expected difficulty must be computable"),
            nonce,
        },
        transactions,
    };
    let state_root = state
        .simulate_candidate_state_root(&block)
        .expect("candidate must simulate cleanly");
    block.header.orchard_commitment_root = state_root;
    block
}

/// Returns a nonce variant of `base` whose block ID satisfies `want_smaller`
/// against `bound` (i.e. smaller than `bound` when `true`, larger when
/// `false`).
///
/// The simulated composite state root does not depend on the header nonce and
/// difficulty 1 accepts any proof-of-work hash, so every variant is a fully
/// valid block. Under the uniform-hash assumption each candidate satisfies the
/// comparison with probability ~1/2, so exhausting all 1024 attempts has
/// probability ~2^-1024 — negligible, but not impossible.
fn variant_block(base: &Block, bound: Hash, want_smaller: bool) -> Block {
    for nonce in 0u64..1024 {
        let mut candidate = base.clone();
        candidate.header.nonce = nonce;
        let id = candidate.block_id();
        let satisfies = if want_smaller { id < bound } else { id > bound };
        if satisfies {
            return candidate;
        }
    }
    panic!(
        "no nonce in 0..1024 produced a block ID {} than {bound:?}",
        if want_smaller { "smaller" } else { "larger" }
    );
}

/// A pair of equal-work branches forked directly from genesis.
///
/// The smaller branch's height-1 block ID is lexicographically smaller than the
/// larger branch's, while the height-2 tip IDs are ordered the opposite way.
struct DivergentPair {
    larger: [Block; 2],
    smaller: [Block; 2],
    /// ChainState mirror whose tip is the smaller branch's height-2 block.
    mirror_smaller_tip: ChainState,
    /// ChainState mirror whose tip is the larger branch's height-2 block.
    mirror_larger_tip: ChainState,
}

fn build_divergent_pair() -> DivergentPair {
    let chain_id = devnet_chain_id();
    let genesis = genesis_block(chain_id);
    let base = ChainState::from_genesis(&genesis).expect("genesis must apply");

    let miner_smaller = Hash::new([0x5a; 32]);
    let miner_larger = Hash::new([0xb4; 32]);

    let ts1 = GENESIS_TIMESTAMP + 120;
    let smaller1_base = make_child_block(
        &base,
        ts1,
        vec![make_coinbase(
            chain_id,
            1,
            miner_smaller,
            scheduled_subsidy(1) as u64,
        )],
        0,
    );
    let larger1 = make_child_block(
        &base,
        ts1,
        vec![make_coinbase(
            chain_id,
            1,
            miner_larger,
            scheduled_subsidy(1) as u64,
        )],
        0,
    );

    // §4 tie-break anchor: the height-1 block IDs decide the winner.
    let smaller1 = variant_block(&smaller1_base, larger1.block_id(), true);
    assert!(
        smaller1.block_id() < larger1.block_id(),
        "test construction: height-1 ID of the smaller branch must be lexicographically smaller"
    );

    let mut mirror_smaller = ChainState::from_genesis(&genesis).expect("genesis must apply");
    mirror_smaller
        .apply_block(&smaller1)
        .expect("smaller branch height-1 block must apply");
    let mut mirror_larger = ChainState::from_genesis(&genesis).expect("genesis must apply");
    mirror_larger
        .apply_block(&larger1)
        .expect("larger branch height-1 block must apply");

    let ts2 = GENESIS_TIMESTAMP + 240;
    let smaller2_base = make_child_block(
        &mirror_smaller,
        ts2,
        vec![make_coinbase(
            chain_id,
            2,
            miner_smaller,
            scheduled_subsidy(2) as u64,
        )],
        0,
    );
    let larger2 = make_child_block(
        &mirror_larger,
        ts2,
        vec![make_coinbase(
            chain_id,
            2,
            miner_larger,
            scheduled_subsidy(2) as u64,
        )],
        0,
    );

    // Tip IDs are ordered opposite to the deciding height-1 IDs so that a fork
    // choice comparing only the final tip block IDs would elect the larger
    // branch, while §4 (first differing height) must elect the smaller one.
    let smaller2 = variant_block(&smaller2_base, larger2.block_id(), false);
    assert!(
        smaller2.block_id() > larger2.block_id(),
        "test construction: tip IDs must oppose the height-1 ordering"
    );

    mirror_smaller
        .apply_block(&smaller2)
        .expect("smaller branch height-2 block must apply");
    mirror_larger
        .apply_block(&larger2)
        .expect("larger branch height-2 block must apply");

    // Both branches have identical cumulative work: 2 difficulty-1 blocks.
    assert_eq!(
        mirror_smaller.cumulative_work(),
        mirror_larger.cumulative_work(),
        "test construction: branches must carry identical cumulative work"
    );

    DivergentPair {
        larger: [larger1, larger2],
        smaller: [smaller1, smaller2],
        mirror_smaller_tip: mirror_smaller,
        mirror_larger_tip: mirror_larger,
    }
}

/// §4: An equal-work challenger with the lexicographically smaller block-ID
/// sequence must displace the equal-work incumbent branch.
#[tokio::test]
async fn equal_work_fork_choice_selects_lexicographically_smaller_challenger_branch() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let pair = build_divergent_pair();

    // The larger branch arrives first and must become the incumbent tip.
    for block in &pair.larger {
        runtime
            .submit_block(block.clone())
            .await
            .expect("larger branch blocks must be accepted while the tip is genesis");
    }
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(runtime.tip_block_id(), pair.larger[1].block_id());
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        pair.mirror_larger_tip.composite_state_root()
    );
    // Identical cumulative work by construction: this is a pure §4 tie-break.
    assert_eq!(
        runtime.cumulative_work(),
        pair.mirror_smaller_tip.cumulative_work(),
        "test construction: both branches must carry identical cumulative work"
    );

    // The smaller branch arrives second with identical cumulative work: the
    // first differing block-ID sequence (height 1) must win the tie.
    for block in &pair.smaller {
        runtime
            .submit_block(block.clone())
            .await
            .expect("equal-work challenger must be accepted as branch data");
    }
    assert_eq!(
        runtime.tip_block_id(),
        pair.smaller[1].block_id(),
        "§4: equal cumulative work must select the lexicographically smaller block-ID \
         sequence from genesis, regardless of submission order"
    );
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        pair.mirror_smaller_tip.composite_state_root()
    );
}

/// §4: Submission order must not matter: the smaller branch stays active when
/// the larger equal-work branch arrives second.
#[tokio::test]
async fn equal_work_fork_choice_retains_lexicographically_smaller_incumbent_branch() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let pair = build_divergent_pair();

    // The smaller branch arrives first and becomes the active tip.
    for block in &pair.smaller {
        runtime
            .submit_block(block.clone())
            .await
            .expect("first-seen branch blocks must be accepted");
    }
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(runtime.tip_block_id(), pair.smaller[1].block_id());
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        pair.mirror_smaller_tip.composite_state_root()
    );

    // The larger branch arrives second with identical cumulative work: the
    // larger block-ID sequence must not displace the smaller incumbent.
    for block in &pair.larger {
        runtime
            .submit_block(block.clone())
            .await
            .expect("equal-work challenger must be accepted as branch data");
    }
    assert_eq!(
        runtime.tip_block_id(),
        pair.smaller[1].block_id(),
        "§4: the lexicographically smaller branch must be retained against an equal-work challenger"
    );
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        pair.mirror_smaller_tip.composite_state_root()
    );
}

/// §4: Two independent runtimes fed opposite submission orders must converge on
/// the same tip block ID and composite state root.
#[tokio::test]
async fn equal_work_fork_choice_independent_runtimes_converge_on_identical_tip() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut runtime_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    let mut runtime_b = NodeRuntime::init(create_node_config(&dir_b)).unwrap();
    let pair = build_divergent_pair();

    // Runtime A: larger branch first, smaller branch second.
    for block in &pair.larger {
        runtime_a
            .submit_block(block.clone())
            .await
            .expect("larger branch blocks must be accepted while the tip is genesis");
    }
    for block in &pair.smaller {
        runtime_a
            .submit_block(block.clone())
            .await
            .expect("equal-work challenger must be accepted as branch data");
    }

    // Runtime B: smaller branch first, larger branch second.
    for block in &pair.smaller {
        runtime_b
            .submit_block(block.clone())
            .await
            .expect("first-seen branch blocks must be accepted");
    }
    for block in &pair.larger {
        runtime_b
            .submit_block(block.clone())
            .await
            .expect("equal-work challenger must be accepted as branch data");
    }

    // Runtime B elects the smaller branch (the §4 tie-break winner). Asserted
    // first because it must hold on both the incumbent-first implementation
    // (side branch is rejected) and the specification-correct implementation.
    assert_eq!(
        runtime_b.tip_block_id(),
        pair.smaller[1].block_id(),
        "the smaller-first runtime must elect the smaller branch"
    );

    assert_eq!(
        runtime_a.tip_block_id(),
        pair.smaller[1].block_id(),
        "§4: the larger-first runtime must also elect the smaller branch; the tie-break is order-independent"
    );
    assert_eq!(
        runtime_a.tip_block_id(),
        runtime_b.tip_block_id(),
        "independent runtimes must converge on the same tip block ID"
    );
    assert_eq!(
        runtime_a.chain_state().composite_state_root(),
        runtime_b.chain_state().composite_state_root(),
        "independent runtimes must converge on the same composite state root"
    );
    assert_eq!(
        runtime_a.chain_state().composite_state_root(),
        pair.mirror_smaller_tip.composite_state_root()
    );
}

/// A shared-prefix extension of the divergent case: both branches extend a
/// common height-1 block, and carry an additional height-3 tip block so that
/// the deciding height-2 block IDs are not the final tip block IDs.
struct SharedPrefixPair {
    shared: Block,
    larger: [Block; 2],
    smaller: [Block; 2],
    /// ChainState mirror whose tip is the smaller branch's height-3 block.
    mirror_smaller_tip: ChainState,
}

fn build_shared_prefix_pair() -> SharedPrefixPair {
    let chain_id = devnet_chain_id();
    let genesis = genesis_block(chain_id);
    let mut mirror = ChainState::from_genesis(&genesis).expect("genesis must apply");

    let miner_shared = Hash::new([0x66; 32]);
    let miner_smaller = Hash::new([0x5a; 32]);
    let miner_larger = Hash::new([0xb4; 32]);

    let shared = make_child_block(
        &mirror,
        GENESIS_TIMESTAMP + 120,
        vec![make_coinbase(
            chain_id,
            1,
            miner_shared,
            scheduled_subsidy(1) as u64,
        )],
        0,
    );
    mirror
        .apply_block(&shared)
        .expect("shared prefix block must apply");

    let ts2 = GENESIS_TIMESTAMP + 240;
    let smaller2_base = make_child_block(
        &mirror,
        ts2,
        vec![make_coinbase(
            chain_id,
            2,
            miner_smaller,
            scheduled_subsidy(2) as u64,
        )],
        0,
    );
    let larger2 = make_child_block(
        &mirror,
        ts2,
        vec![make_coinbase(
            chain_id,
            2,
            miner_larger,
            scheduled_subsidy(2) as u64,
        )],
        0,
    );

    // §4 decides at the first differing height (height 2, below both tips).
    let smaller2 = variant_block(&smaller2_base, larger2.block_id(), true);
    assert!(
        smaller2.block_id() < larger2.block_id(),
        "test construction: height-2 ID of the smaller branch must be lexicographically smaller"
    );

    let mut mirror_smaller = mirror.clone();
    mirror_smaller
        .apply_block(&smaller2)
        .expect("smaller branch height-2 block must apply");
    let mut mirror_larger = mirror;
    mirror_larger
        .apply_block(&larger2)
        .expect("larger branch height-2 block must apply");

    let ts3 = GENESIS_TIMESTAMP + 360;
    let smaller3_base = make_child_block(
        &mirror_smaller,
        ts3,
        vec![make_coinbase(
            chain_id,
            3,
            miner_smaller,
            scheduled_subsidy(3) as u64,
        )],
        0,
    );
    let larger3 = make_child_block(
        &mirror_larger,
        ts3,
        vec![make_coinbase(
            chain_id,
            3,
            miner_larger,
            scheduled_subsidy(3) as u64,
        )],
        0,
    );

    // Tip IDs (height 3) are ordered opposite to the deciding height-2 IDs: a
    // fork choice comparing only final tip block IDs would elect the larger
    // branch, while §4 must elect the smaller one.
    let smaller3 = variant_block(&smaller3_base, larger3.block_id(), false);
    assert!(
        smaller3.block_id() > larger3.block_id(),
        "test construction: tip IDs must oppose the height-2 ordering"
    );

    mirror_smaller
        .apply_block(&smaller3)
        .expect("smaller branch height-3 block must apply");
    mirror_larger
        .apply_block(&larger3)
        .expect("larger branch height-3 block must apply");

    // Both branches have identical cumulative work: 3 difficulty-1 blocks.
    assert_eq!(
        mirror_smaller.cumulative_work(),
        mirror_larger.cumulative_work(),
        "test construction: branches must carry identical cumulative work"
    );

    SharedPrefixPair {
        shared,
        larger: [larger2, larger3],
        smaller: [smaller2, smaller3],
        mirror_smaller_tip: mirror_smaller,
    }
}

/// §4: With a shared genesis prefix, the first differing block ID (here at
/// height 2, below both height-3 tips) decides the winner — not the final tip
/// block ID, which is deliberately ordered the opposite way.
#[tokio::test]
async fn equal_work_fork_choice_first_differing_block_id_decides_the_tie() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut runtime_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    let mut runtime_b = NodeRuntime::init(create_node_config(&dir_b)).unwrap();
    let pair = build_shared_prefix_pair();

    // Runtime A: larger branch first, smaller branch second.
    runtime_a
        .submit_block(pair.shared.clone())
        .await
        .expect("shared prefix block must be accepted");
    for block in &pair.larger {
        runtime_a
            .submit_block(block.clone())
            .await
            .expect("larger branch blocks must be accepted while extending the shared prefix");
    }
    for block in &pair.smaller {
        runtime_a
            .submit_block(block.clone())
            .await
            .expect("equal-work challenger must be accepted as branch data");
    }

    // Runtime B: smaller branch first, larger branch second.
    runtime_b
        .submit_block(pair.shared.clone())
        .await
        .expect("shared prefix block must be accepted");
    for block in &pair.smaller {
        runtime_b
            .submit_block(block.clone())
            .await
            .expect("first-seen branch blocks must be accepted");
    }
    for block in &pair.larger {
        runtime_b
            .submit_block(block.clone())
            .await
            .expect("equal-work challenger must be accepted as branch data");
    }

    assert_eq!(runtime_b.tip_height(), 3);
    assert_eq!(
        runtime_b.tip_block_id(),
        pair.smaller[1].block_id(),
        "the smaller-first runtime must retain the smaller branch; the larger block-ID sequence \
         must not displace it on equal work"
    );

    assert_eq!(runtime_a.tip_height(), 3);
    assert_eq!(
        runtime_a.tip_block_id(),
        pair.smaller[1].block_id(),
        "§4: the winner is decided by the first differing block ID sequence (height 2), \
         not by the final tip block ID or submission order"
    );
    assert_eq!(
        runtime_a.tip_block_id(),
        runtime_b.tip_block_id(),
        "independent runtimes must converge on the same tip block ID"
    );
    assert_eq!(
        runtime_a.chain_state().composite_state_root(),
        runtime_b.chain_state().composite_state_root(),
        "independent runtimes must converge on the same composite state root"
    );
    assert_eq!(
        runtime_a.chain_state().composite_state_root(),
        pair.mirror_smaller_tip.composite_state_root()
    );
}
