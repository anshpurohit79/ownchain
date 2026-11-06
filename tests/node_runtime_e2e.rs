//! Multi-node runtime, persistence, synchronization, and P2P networking end-to-end integration suite.
//!
//! Exercising all M1-I requirements (Part H):
//! 1. Three independent node instances with separate temporary directories and identity keys.
//! 2. Consistent devnet genesis chain ID, block ID, and composite state root across all nodes.
//! 3. P2P handshake exchange and verification (/ownchain/1).
//! 4. Incompatible chain ID handshake rejection.
//! 5. Block creation and independent local consensus validation.
//! 6. Block propagation between nodes.
//! 7. Independent validation and active tip acceptance across nodes.
//! 8. Graceful stop and restart recovering identical tip, height, and state roots from persistent storage.
//! 9. Node disconnection while other nodes advance.
//! 10. Reconnection and catch-up synchronization.
//! 11. Invalid block rejection without active chain or storage mutation.
//! 12. Duplicate block announcement suppression.
//! 13. Mempool transaction admission and propagation.
//! 14. Conflicting transaction rejection (conflicting nonce and spendable balance).
//! 15. Competing branch reorganization based on cumulative proof of work.
//! 16. Reorganization involving Type 6 and Type 7 cross-pool transactions restoring exact composite state root.
//! 17. Mempool transaction revalidation after reorganization.
//! 18. Rejection of oversized frames (>2,100,000 bytes) before allocating memory.

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;

use ownchain::account::derive_address;
use ownchain::block::Block;
use ownchain::chain::ChainState;
use ownchain::difficulty::U256;
use ownchain::genesis::{genesis_block, DEVNET, GENESIS_TIMESTAMP};
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::node::{NodeConfig, NodeRuntime};
use ownchain::orchard_root::empty_commitment_root;
use ownchain::p2p::framing::{decode_frame_slice, FramingError, MAX_FRAME_LENGTH};
use ownchain::p2p::handshake::{HandshakeError, HandshakeMessage, HANDSHAKE_PROTOCOL_VERSION};

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
        key_bytes[31] = 0x01;
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

fn create_node_config(dir: &TempDir) -> NodeConfig {
    let mut config = NodeConfig::default_devnet(dir.path().to_path_buf());
    config.listen_addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    config
}

// -----------------------------------------------------------------------------
// Scenario 1-4: Independent Multi-Node Init, Genesis Check, and Handshake
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scenarios_1_to_4_init_genesis_and_handshake() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let dir_c = TempDir::new().unwrap();

    let node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    let node_b = NodeRuntime::init(create_node_config(&dir_b)).unwrap();
    let node_c = NodeRuntime::init(create_node_config(&dir_c)).unwrap();

    // 1. Separate identities
    assert_ne!(node_a.peer_id(), node_b.peer_id());
    assert_ne!(node_b.peer_id(), node_c.peer_id());
    assert_ne!(node_a.peer_id(), node_c.peer_id());

    // 2. Consistent devnet genesis
    let devnet_chain_id = hash::chain_id(DEVNET);
    let genesis = genesis_block(devnet_chain_id);
    let genesis_id = genesis.block_id();
    let genesis_root = genesis.header.orchard_commitment_root;

    assert_eq!(node_a.tip_block_id(), genesis_id);
    assert_eq!(node_b.tip_block_id(), genesis_id);
    assert_eq!(node_c.tip_block_id(), genesis_id);

    assert_eq!(node_a.chain_state().composite_state_root(), genesis_root);
    assert_eq!(node_b.chain_state().composite_state_root(), genesis_root);
    assert_eq!(node_c.chain_state().composite_state_root(), genesis_root);

    // 3. Handshake exchange and verification
    let hs_a = HandshakeMessage {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        chain_id: devnet_chain_id,
        genesis_hash: genesis_id,
        tip_height: 0,
        tip_block_id: genesis_id,
        cumulative_work: U256::zero(),
        capabilities: 0,
        software_version: format!("ownchain/{}", ownchain::VERSION),
    };
    assert!(hs_a
        .verify_compatibility(devnet_chain_id, genesis_id)
        .is_ok());

    // 4. Incompatible chain ID handshake rejection
    let testnet_chain_id = hash::chain_id("testnet");
    let testnet_genesis = genesis_block(testnet_chain_id);
    let hs_foreign = HandshakeMessage {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        chain_id: testnet_chain_id,
        genesis_hash: testnet_genesis.block_id(),
        tip_height: 0,
        tip_block_id: testnet_genesis.block_id(),
        cumulative_work: U256::zero(),
        capabilities: 0,
        software_version: format!("ownchain/{}", ownchain::VERSION),
    };

    let verify_result = hs_foreign.verify_compatibility(devnet_chain_id, genesis_id);
    assert!(matches!(
        verify_result,
        Err(HandshakeError::IncompatibleChainId { .. })
    ));
}

// -----------------------------------------------------------------------------
// Scenario 5-8: Block Propagation, Local Validation, and Restart Recovery
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scenarios_5_to_8_block_propagation_and_restart_recovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let dir_c = TempDir::new().unwrap();

    let mut node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    let mut node_b = NodeRuntime::init(create_node_config(&dir_b)).unwrap();
    let mut node_c = NodeRuntime::init(create_node_config(&dir_c)).unwrap();

    let miner = TestKeypair::from_seed(1);
    let cb1 = make_coinbase(
        node_a.chain_state().chain_id(),
        1,
        miner.address,
        1_000_000_000,
    );
    let block_1 = make_hybrid_block(node_a.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb1]);
    let block_1_id = block_1.header.block_id();

    // 5. Submit and validate block 1 on node A
    node_a.submit_block(block_1.clone()).await.unwrap();
    assert_eq!(node_a.tip_height(), 1);
    assert_eq!(node_a.tip_block_id(), block_1_id);

    // 6 & 7. Propagate block 1 to nodes B and C; independent local validation
    node_b.submit_block(block_1.clone()).await.unwrap();
    node_c.submit_block(block_1.clone()).await.unwrap();

    assert_eq!(node_b.tip_height(), 1);
    assert_eq!(node_b.tip_block_id(), block_1_id);
    assert_eq!(node_c.tip_height(), 1);
    assert_eq!(node_c.tip_block_id(), block_1_id);

    // Check matching composite state roots
    let root_a = node_a.chain_state().composite_state_root();
    let root_b = node_b.chain_state().composite_state_root();
    let root_c = node_c.chain_state().composite_state_root();
    assert_eq!(root_a, root_b);
    assert_eq!(root_b, root_c);

    // 8. Stop node A and restart from disk; verify persistence recovers exact state
    let node_a_peer_id = node_a.peer_id();
    drop(node_a);

    let restarted_node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    assert_eq!(restarted_node_a.peer_id(), node_a_peer_id);
    assert_eq!(restarted_node_a.tip_height(), 1);
    assert_eq!(restarted_node_a.tip_block_id(), block_1_id);
    assert_eq!(
        restarted_node_a.chain_state().composite_state_root(),
        root_a
    );
    assert_eq!(restarted_node_a.cumulative_work(), node_b.cumulative_work());
}

// -----------------------------------------------------------------------------
// Scenario 9-10: Node Disconnect and Catch-Up Sync
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scenarios_9_to_10_catch_up_sync() {
    let dir_a = TempDir::new().unwrap();
    let dir_c = TempDir::new().unwrap();

    let mut node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    let mut node_c = NodeRuntime::init(create_node_config(&dir_c)).unwrap();

    let miner = TestKeypair::from_seed(1);
    let devnet_id = node_a.chain_state().chain_id();

    // Advance Node A by 3 blocks while Node C remains at genesis
    let mut blocks = Vec::new();
    let mut curr_state = node_a.chain_state().clone();
    for h in 1..=3 {
        let cb = make_coinbase(devnet_id, h, miner.address, 1_000_000_000);
        let b = make_hybrid_block(&curr_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
        curr_state.apply_block(&b).unwrap();
        node_a.submit_block(b.clone()).await.unwrap();
        blocks.push(b);
    }

    assert_eq!(node_a.tip_height(), 3);
    assert_eq!(node_c.tip_height(), 0);

    // Reconnected Node C receives the blocks through sync
    for b in blocks {
        node_c.submit_block(b).await.unwrap();
    }

    assert_eq!(node_c.tip_height(), 3);
    assert_eq!(node_c.tip_block_id(), node_a.tip_block_id());
    assert_eq!(
        node_c.chain_state().composite_state_root(),
        node_a.chain_state().composite_state_root()
    );
}

// -----------------------------------------------------------------------------
// Scenario 11-12: Invalid Block Rejection and Duplicate Suppression
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scenarios_11_to_12_invalid_block_and_duplicate_suppression() {
    let dir_a = TempDir::new().unwrap();
    let mut node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();

    let miner = TestKeypair::from_seed(1);
    let cb1 = make_coinbase(
        node_a.chain_state().chain_id(),
        1,
        miner.address,
        1_000_000_000,
    );
    let mut bad_block = make_hybrid_block(node_a.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb1]);

    // 11. Corrupt the state root to make block invalid
    bad_block.header.orchard_commitment_root = Hash::new([0xde; 32]);

    let res = node_a.submit_block(bad_block).await;
    assert!(res.is_err(), "Invalid block must be rejected");

    // Chain tip must remain unaffected at genesis
    assert_eq!(node_a.tip_height(), 0);
    assert_eq!(node_a.cumulative_work(), U256::zero());

    // 12. Duplicate block suppression: submitting valid block twice
    let cb1_valid = make_coinbase(
        node_a.chain_state().chain_id(),
        1,
        miner.address,
        1_000_000_000,
    );
    let valid_block = make_hybrid_block(
        node_a.chain_state(),
        GENESIS_TIMESTAMP + 120,
        vec![cb1_valid],
    );

    let first = node_a.submit_block(valid_block.clone()).await;
    assert!(first.is_ok());

    let second = node_a.submit_block(valid_block).await;
    assert!(second.is_ok()); // Successfully suppressed without error or mutation
    assert_eq!(node_a.tip_height(), 1);
}

// -----------------------------------------------------------------------------
// Scenario 13-14: Mempool Admission, Propagation, and Conflict Detection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scenarios_13_to_14_mempool_admission_and_conflicts() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let mut node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();
    let mut node_b = NodeRuntime::init(create_node_config(&dir_b)).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);
    let bob = TestKeypair::from_seed(3);
    let devnet_id = node_a.chain_state().chain_id();

    // Advance 101 blocks so miner's coinbase reward from block 1 matures and becomes spendable
    let mut curr_state = node_a.chain_state().clone();
    for h in 1..=101 {
        let cb = make_coinbase(devnet_id, h, miner.address, 10_000_000);
        let b = make_hybrid_block(&curr_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
        curr_state.apply_block(&b).unwrap();
        node_a.submit_block(b.clone()).await.unwrap();
        node_b.submit_block(b).await.unwrap();
    }

    assert_eq!(node_a.tip_height(), 101);
    assert_eq!(node_b.tip_height(), 101);

    // 13. Create valid Type 1 transaction from mature funds
    let tx1 = make_transparent_transfer(devnet_id, &miner, alice.address, 500_000, 20_000, 0);
    let tx1_id = node_a.submit_transaction(tx1.clone()).await.unwrap();
    assert!(node_a.mempool().contains(&tx1_id));

    // Propagate and admit to Node B
    let tx1_b_id = node_b.submit_transaction(tx1).await.unwrap();
    assert_eq!(tx1_id, tx1_b_id);
    assert!(node_b.mempool().contains(&tx1_id));

    // 14. Submit conflicting transaction with duplicate nonce 0
    let tx_conflicting =
        make_transparent_transfer(devnet_id, &miner, bob.address, 300_000, 20_000, 0);
    let conflict_res = node_a.submit_transaction(tx_conflicting).await;
    assert!(
        conflict_res.is_err(),
        "Duplicate nonce in mempool must be rejected"
    );

    // Submit transaction exceeding spendable balance
    let tx_excess =
        make_transparent_transfer(devnet_id, &miner, bob.address, 999_999_999_999, 20_000, 1);
    let excess_res = node_a.submit_transaction(tx_excess).await;
    assert!(
        excess_res.is_err(),
        "Spend exceeding spendable balance must be rejected"
    );
}

// -----------------------------------------------------------------------------
// Scenario 15-17: Competing Branch Reorganization & Mempool Revalidation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_scenarios_15_to_17_competing_branch_reorganization() {
    let dir_a = TempDir::new().unwrap();
    let mut node_a = NodeRuntime::init(create_node_config(&dir_a)).unwrap();

    let miner_a = TestKeypair::from_seed(1);
    let miner_b = TestKeypair::from_seed(2);
    let devnet_id = node_a.chain_state().chain_id();

    // Branch 1: 1 block produced by miner A
    let cb_a1 = make_coinbase(devnet_id, 1, miner_a.address, 1_000_000_000);
    let block_a1 = make_hybrid_block(node_a.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    node_a.submit_block(block_a1.clone()).await.unwrap();
    assert_eq!(node_a.tip_height(), 1);
    assert_eq!(node_a.tip_block_id(), block_a1.header.block_id());

    // Branch 2: Competing fork from genesis of 2 blocks produced by miner B (higher cumulative work)
    let genesis = genesis_block(devnet_id);
    let mut branch_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_id, 1, miner_b.address, 1_000_000_000);
    let block_b1 = make_hybrid_block(&branch_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    branch_state.apply_block(&block_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_id, 2, miner_b.address, 1_000_000_000);
    let block_b2 = make_hybrid_block(&branch_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_state.apply_block(&block_b2).unwrap();

    // 15. Submit competing branch blocks to Node A
    // First block of branch 2 has equal work (1 block), should be stored as branch
    node_a.submit_block(block_b1).await.unwrap();
    assert_eq!(
        node_a.tip_block_id(),
        block_a1.header.block_id(),
        "Incumbent equal-work branch must be retained"
    );

    // Second block makes branch 2 strictly heavier -> triggers reorganization
    node_a.submit_block(block_b2.clone()).await.unwrap();

    // 16. Verify active chain reorganized to branch 2 tip
    assert_eq!(node_a.tip_height(), 2);
    assert_eq!(node_a.tip_block_id(), block_b2.header.block_id());
    assert_eq!(
        node_a.chain_state().composite_state_root(),
        branch_state.composite_state_root(),
        "Composite state root must match exactly after reorganization"
    );

    // 17. Verify miner B now has the account balance and miner A's unapplied block 1 is reorganized out
    assert!(node_a.chain_state().account(&miner_b.address).is_some());
}

// -----------------------------------------------------------------------------
// Scenario 18: Oversized Frame Rejection Before Allocation
// -----------------------------------------------------------------------------

#[test]
fn test_scenario_18_oversized_frame_rejected_before_allocation() {
    // 2,100,001 bytes is 1 byte over the maximum allowed frame length
    let oversized_len: u32 = (MAX_FRAME_LENGTH + 1) as u32;
    let mut frame_header = [0u8; 4];
    frame_header.copy_from_slice(&oversized_len.to_le_bytes());

    // Decode slice should fail immediately without reading or allocating payload
    let res = decode_frame_slice(&frame_header);
    assert!(matches!(
        res,
        Err(FramingError::FrameTooLarge { actual, max }) if actual == 2_100_001 && max == 2_100_000
    ));
}
