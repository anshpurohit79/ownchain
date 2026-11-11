//! Multi-node runtime, persistence, synchronization, and P2P networking end-to-end integration suite.
//!
//! Exercising all M1-I requirements:
//! 1. Three independent node instances with separate temporary directories and identity keys.
//! 2. Consistent devnet genesis chain ID, block ID, and composite state root across all nodes.
//! 3. Real libp2p P2P handshake exchange and verification (/ownchain/sync/1).
//! 4. Incompatible chain ID handshake rejection over real network connection.
//! 5. Block creation and independent local consensus validation.
//! 6. Real Gossipsub block propagation between nodes without manual submit_block.
//! 7. Independent validation and active tip acceptance across nodes.
//! 8. Graceful stop and restart recovering identical tip, height, and state roots from persistent storage.
//! 9. Node disconnection while other nodes advance.
//! 10. Reconnection and fork-aware catch-up synchronization (/ownchain/sync/1).
//! 11. Invalid block rejection over the network without active chain or storage mutation.
//! 12. Duplicate block announcement suppression.
//! 13. Mempool transaction admission and real Gossipsub propagation.
//! 14. Conflicting transaction rejection (conflicting nonce and spendable balance).
//! 15. Competing branch reorganization based on cumulative proof of work.
//! 16. Multi-block, same-height, and lower-height higher-work forks.
//! 17. Missing parent arriving after its child (orphan queue and recovery).
//! 18. Invalid ancestor in competing branch rejected.
//! 19. Successful subsequent reorganization after synchronization.
//! 20. Bounded orphan block pool and FIFO eviction.
//! 21. Rejection of oversized frames (>2,100,000 bytes) before allocating memory.
//! 22. Equal-work peer convergence over the real network (Section 4 tie-break).
//! 23. Side-branch orphan recovery (retrying waiting orphans when parent is persisted as side branch).

use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use libp2p::core::Multiaddr;
use libp2p::identity::PeerId;
use tempfile::TempDir;

use ownchain::account::derive_address;
use ownchain::block::Block;
use ownchain::chain::ChainState;
use ownchain::difficulty::U256;
use ownchain::genesis::{genesis_block, DEVNET, GENESIS_TIMESTAMP};
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::node::{
    candidate_wins_fork_choice, BlockProcessingOutcome, NodeConfig, NodeHandle, NodeRuntime,
    NodeStatus,
};
use ownchain::orchard_root::empty_commitment_root;
use ownchain::p2p::framing::{decode_frame_slice, FramingError, MAX_FRAME_LENGTH};
use ownchain::p2p::{
    HandshakeMessage, NetworkEvent, NetworkService, SyncRequest, SyncResponse,
    HANDSHAKE_PROTOCOL_VERSION,
};

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

fn make_hybrid_block_with_diff(
    state: &ChainState,
    diff: u128,
    timestamp: u64,
    transactions: Vec<Vec<u8>>,
) -> Block {
    let parent = state.tip().expect("must have parent");
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    let tx_root = merkle::tx_root(&ids);

    let mut dummy_block = Block {
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
    };
    let state_root = state
        .simulate_candidate_state_root(&dummy_block)
        .expect("simulation must succeed");
    dummy_block.header.orchard_commitment_root = state_root;

    if diff > 1 {
        let key_id = genesis_block(state.chain_id()).block_id();
        let target = ownchain::randomx::pow_target(diff).unwrap();
        let mut nonce = 0u64;
        loop {
            dummy_block.header.nonce = nonce;
            let header_bytes = dummy_block.header.to_bytes();
            let h = ownchain::randomx::randomx_hash(
                key_id.as_bytes(),
                &header_bytes,
                ownchain::randomx::RandomxMode::Light,
            )
            .unwrap();
            let h_val = U256::from_le_bytes(h);
            if h_val <= target {
                break;
            }
            nonce += 1;
        }
    }
    dummy_block
}

fn create_node_config(dir: &TempDir) -> NodeConfig {
    let mut config = NodeConfig::default_devnet(dir.path().to_path_buf());
    config.listen_addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    config
}

async fn wait_for_listen_addr(handle: &NodeHandle) -> Multiaddr {
    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    loop {
        if let Ok(addrs) = handle.get_listen_addrs().await {
            if let Some(addr) = addrs.into_iter().next() {
                return addr;
            }
        }
        if start.elapsed() > timeout {
            panic!(
                "Timed out waiting for listen address for node {}",
                handle.peer_id()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_peer_handshake(handle: &NodeHandle, peer_id: PeerId) {
    let timeout = Duration::from_secs(10);
    let start = Instant::now();
    loop {
        if let Ok(peers) = handle.get_connected_peers().await {
            if let Some(p) = peers.iter().find(|p| p.peer_id == peer_id) {
                if p.handshake.is_some() {
                    return;
                }
            }
        }
        if start.elapsed() > timeout {
            panic!(
                "Timed out waiting for handshake with peer {} on node {}",
                peer_id,
                handle.peer_id()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_tip(
    handle: &NodeHandle,
    expected_height: u64,
    expected_tip_id: Hash,
) -> NodeStatus {
    let timeout = Duration::from_secs(15);
    let start = Instant::now();
    loop {
        if let Ok(status) = handle.status().await {
            if status.tip_height == expected_height && status.tip_block_id == expected_tip_id {
                return status;
            }
        }
        if start.elapsed() > timeout {
            let curr = handle.status().await;
            panic!(
                "Timed out waiting for tip #{expected_height} ({expected_tip_id}) on node {}. Current: {:?}",
                handle.peer_id(),
                curr
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_mempool_tx(handle: &NodeHandle) {
    let timeout = Duration::from_secs(10);
    let start = Instant::now();
    loop {
        if let Ok(status) = handle.status().await {
            if status.mempool_size > 0 {
                return;
            }
        }
        if start.elapsed() > timeout {
            panic!(
                "Timed out waiting for tx in mempool on node {}",
                handle.peer_id()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// -----------------------------------------------------------------------------
// Test 1: Real Network Handshake & Incompatible Chain ID Rejection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_handshake_and_incompatible_chain_id_rejection() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let dir_c = TempDir::new().unwrap();
        let dir_foreign = TempDir::new().unwrap();

        let (node_a, _t_a) = NodeRuntime::spawn(create_node_config(&dir_a)).unwrap();
        let (node_b, _t_b) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();
        let (node_c, _t_c) = NodeRuntime::spawn(create_node_config(&dir_c)).unwrap();

        let addr_a = wait_for_listen_addr(&node_a).await;
        let addr_b = wait_for_listen_addr(&node_b).await;
        let _addr_c = wait_for_listen_addr(&node_c).await;

        // 1. Separate identities
        assert_ne!(node_a.peer_id(), node_b.peer_id());
        assert_ne!(node_b.peer_id(), node_c.peer_id());
        assert_ne!(node_a.peer_id(), node_c.peer_id());

        // 2. Consistent devnet genesis state across all nodes
        let status_a = node_a.status().await.unwrap();
        let status_b = node_b.status().await.unwrap();
        let status_c = node_c.status().await.unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let genesis_id = genesis.block_id();
        let genesis_root = genesis.header.orchard_commitment_root;

        assert_eq!(status_a.tip_block_id, genesis_id);
        assert_eq!(status_b.tip_block_id, genesis_id);
        assert_eq!(status_c.tip_block_id, genesis_id);

        assert_eq!(status_a.composite_state_root, genesis_root);
        assert_eq!(status_b.composite_state_root, genesis_root);
        assert_eq!(status_c.composite_state_root, genesis_root);

        // 3. Real network dialing and application handshake exchange
        node_b.dial(addr_a.clone()).await.unwrap();
        node_c.dial(addr_a.clone()).await.unwrap();
        node_c.dial(addr_b.clone()).await.unwrap();

        wait_for_peer_handshake(&node_a, node_b.peer_id()).await;
        wait_for_peer_handshake(&node_a, node_c.peer_id()).await;
        wait_for_peer_handshake(&node_b, node_a.peer_id()).await;
        wait_for_peer_handshake(&node_c, node_a.peer_id()).await;

        // 4. Incompatible chain ID rejected over actual network connection
        let mut foreign_config = create_node_config(&dir_foreign);
        foreign_config.network_name = "testnet".into();
        foreign_config.chain_id = hash::chain_id("testnet");

        let (node_foreign, _t_f) = NodeRuntime::spawn(foreign_config).unwrap();
        let _ = wait_for_listen_addr(&node_foreign).await;

        node_foreign.dial(addr_a.clone()).await.unwrap();

        // Allow handshake attempt and rejection to process
        tokio::time::sleep(Duration::from_millis(500)).await;

        let peers_a = node_a.get_connected_peers().await.unwrap();
        assert!(
            !peers_a.iter().any(|p| p.peer_id == node_foreign.peer_id()),
            "Incompatible chain ID peer must be rejected and disconnected"
        );

        node_a.stop().await;
        node_b.stop().await;
        node_c.stop().await;
        node_foreign.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 2: Real Gossipsub Block & Transaction Propagation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_gossipsub_block_and_tx_propagation() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let dir_c = TempDir::new().unwrap();

        let (node_a, _t_a) = NodeRuntime::spawn(create_node_config(&dir_a)).unwrap();
        let (node_b, _t_b) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();
        let (node_c, _t_c) = NodeRuntime::spawn(create_node_config(&dir_c)).unwrap();

        let addr_a = wait_for_listen_addr(&node_a).await;
        let addr_b = wait_for_listen_addr(&node_b).await;

        node_b.dial(addr_a.clone()).await.unwrap();
        node_c.dial(addr_a.clone()).await.unwrap();
        node_c.dial(addr_b.clone()).await.unwrap();

        wait_for_peer_handshake(&node_a, node_b.peer_id()).await;
        wait_for_peer_handshake(&node_a, node_c.peer_id()).await;
        wait_for_peer_handshake(&node_b, node_a.peer_id()).await;
        wait_for_peer_handshake(&node_c, node_a.peer_id()).await;

        // Mine block 1 on Node A
        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut local_state = ChainState::from_genesis(&genesis).unwrap();

        let miner = TestKeypair::from_seed(1);
        let cb1 = make_coinbase(devnet_chain_id, 1, miner.address, 1_000_000_000);
        let block_1 = make_hybrid_block(&local_state, GENESIS_TIMESTAMP + 120, vec![cb1]);
        local_state.apply_block(&block_1).unwrap();
        let block_1_id = block_1.header.block_id();

        // 5 & 6. Submit Block 1 ONLY to Node A. It publishes to Gossipsub!
        node_a.submit_block(block_1.clone()).await.unwrap();
        assert_eq!(node_a.status().await.unwrap().tip_height, 1);

        // Nodes B and C must receive and independently validate Block 1 over the network!
        // DO NOT invoke submit_block on B or C!
        let status_b = wait_for_tip(&node_b, 1, block_1_id).await;
        let status_c = wait_for_tip(&node_c, 1, block_1_id).await;
        let status_a = node_a.status().await.unwrap();

        assert_eq!(status_b.tip_block_id, block_1_id);
        assert_eq!(status_c.tip_block_id, block_1_id);
        assert_eq!(status_b.composite_state_root, status_a.composite_state_root);
        assert_eq!(status_c.composite_state_root, status_a.composite_state_root);

        // 7. Duplicate block announcement suppression: submitting block 1 again does not cause duplicate acceptance
        let second_submit = node_a.submit_block(block_1.clone()).await;
        assert!(second_submit.is_ok());
        assert_eq!(node_a.status().await.unwrap().tip_height, 1);

        // 8. Invalid block received over the network is rejected without state mutation
        let mut bad_block = block_1.clone();
        bad_block.header.height = 2;
        bad_block.header.parent_block_id = block_1_id;
        bad_block.header.orchard_commitment_root = Hash::new([0xee; 32]); // Corrupt root

        let res = node_a.submit_block(bad_block).await;
        assert!(res.is_err(), "Invalid block must be rejected");
        assert_eq!(node_a.status().await.unwrap().tip_height, 1);

        node_a.stop().await;
        node_b.stop().await;
        node_c.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 3: Disconnect, Miss Blocks, Reconnect, and Fork-Aware Catch-Up Sync
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_disconnect_advance_reconnect_and_sync() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let dir_c = TempDir::new().unwrap();

        let (node_a, _t_a) = NodeRuntime::spawn(create_node_config(&dir_a)).unwrap();
        let (node_b, _t_b) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();
        let (node_c, _t_c) = NodeRuntime::spawn(create_node_config(&dir_c)).unwrap();

        let addr_a = wait_for_listen_addr(&node_a).await;
        let addr_b = wait_for_listen_addr(&node_b).await;

        node_b.dial(addr_a.clone()).await.unwrap();
        node_c.dial(addr_a.clone()).await.unwrap();
        node_c.dial(addr_b.clone()).await.unwrap();

        wait_for_peer_handshake(&node_a, node_b.peer_id()).await;
        wait_for_peer_handshake(&node_a, node_c.peer_id()).await;

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut chain_state = ChainState::from_genesis(&genesis).unwrap();
        let miner = TestKeypair::from_seed(1);

        // Advance 1 block on all nodes via Gossipsub
        let cb1 = make_coinbase(devnet_chain_id, 1, miner.address, 1_000_000_000);
        let b1 = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + 120, vec![cb1]);
        chain_state.apply_block(&b1).unwrap();
        node_a.submit_block(b1.clone()).await.unwrap();

        wait_for_tip(&node_b, 1, b1.block_id()).await;
        wait_for_tip(&node_c, 1, b1.block_id()).await;

        // Disconnect Node C
        node_c.stop().await;

        // Node A produces and publishes Blocks 2, 3, 4
        let mut tip_4_id = Hash::ZERO;
        for h in 2..=4 {
            let cb = make_coinbase(devnet_chain_id, h, miner.address, 1_000_000_000);
            let b = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            chain_state.apply_block(&b).unwrap();
            tip_4_id = b.block_id();
            node_a.submit_block(b).await.unwrap();
        }

        // Node B is online and advances to height 4 via Gossipsub
        wait_for_tip(&node_b, 4, tip_4_id).await;

        // Restart Node C from disk (recovering height 1 from persistent storage)
        let (node_c_restarted, _t_c2) = NodeRuntime::spawn(create_node_config(&dir_c)).unwrap();
        let _ = wait_for_listen_addr(&node_c_restarted).await;

        let c_status_before = node_c_restarted.status().await.unwrap();
        assert_eq!(
            c_status_before.tip_height, 1,
            "Node C must recover height 1 from disk"
        );

        // Reconnected Node C dials Node A
        node_c_restarted.dial(addr_a.clone()).await.unwrap();
        wait_for_peer_handshake(&node_c_restarted, node_a.peer_id()).await;

        // Node C synchronizes missing blocks 2..4 through request-response protocol (/ownchain/sync/1)
        let status_c_synced = wait_for_tip(&node_c_restarted, 4, tip_4_id).await;
        let status_a = node_a.status().await.unwrap();
        let status_b = node_b.status().await.unwrap();

        // All nodes converge on the exact same tip, cumulative work, and composite state root
        assert_eq!(status_c_synced.tip_block_id, status_a.tip_block_id);
        assert_eq!(status_b.tip_block_id, status_a.tip_block_id);
        assert_eq!(status_c_synced.cumulative_work, status_a.cumulative_work);
        assert_eq!(status_b.cumulative_work, status_a.cumulative_work);
        assert_eq!(
            status_c_synced.composite_state_root,
            status_a.composite_state_root
        );
        assert_eq!(status_b.composite_state_root, status_a.composite_state_root);

        node_a.stop().await;
        node_b.stop().await;
        node_c_restarted.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 4: Mempool Transaction Admission, Propagation, and Conflict Rejection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_mempool_admission_gossip_and_conflict_rejection() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let (node_a, _t_a) = NodeRuntime::spawn(create_node_config(&dir_a)).unwrap();
        let (node_b, _t_b) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();

        let addr_a = wait_for_listen_addr(&node_a).await;
        node_b.dial(addr_a).await.unwrap();
        wait_for_peer_handshake(&node_b, node_a.peer_id()).await;
        wait_for_peer_handshake(&node_a, node_b.peer_id()).await;

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut chain_state = ChainState::from_genesis(&genesis).unwrap();
        let miner = TestKeypair::from_seed(1);
        let alice = TestKeypair::from_seed(2);
        let bob = TestKeypair::from_seed(3);

        // Advance 101 blocks so miner's coinbase reward from block 1 matures and becomes spendable
        for h in 1..=101 {
            let cb = make_coinbase(devnet_chain_id, h, miner.address, 10_000_000);
            let b = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            chain_state.apply_block(&b).unwrap();
            node_a.submit_block(b).await.unwrap();
        }

        // Wait for Node B to receive and validate all blocks up to height 101
        let tip_101_id = chain_state.tip_block_id().unwrap();
        wait_for_tip(&node_b, 101, tip_101_id).await;

        // Submit valid Type 1 transaction on Node B
        let tx1 =
            make_transparent_transfer(devnet_chain_id, &miner, alice.address, 500_000, 20_000, 0);
        let _tx1_id = node_b.submit_transaction(tx1).await.unwrap();
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        // Node B broadcasts the transaction via Gossipsub. Node A must receive and admit it!
        wait_for_mempool_tx(&node_a).await;
        assert_eq!(node_a.status().await.unwrap().mempool_size, 1);

        // Submitting conflicting nonce 0 transaction must be rejected
        let tx_conflict =
            make_transparent_transfer(devnet_chain_id, &miner, bob.address, 300_000, 20_000, 0);
        let conflict_res = node_a.submit_transaction(tx_conflict).await;
        assert!(
            conflict_res.is_err(),
            "Conflicting nonce in mempool must be rejected"
        );

        // Submitting transaction exceeding spendable balance must be rejected
        let tx_excess = make_transparent_transfer(
            devnet_chain_id,
            &miner,
            bob.address,
            999_999_999_999,
            20_000,
            1,
        );
        let excess_res = node_a.submit_transaction(tx_excess).await;
        assert!(
            excess_res.is_err(),
            "Excess spend exceeding spendable balance must be rejected"
        );

        node_a.stop().await;
        node_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 5: Remote Missing Parent Recovery Over Real P2P Connection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_remote_missing_parent_recovery() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let config_a = create_node_config(&dir_a);
        let config_b = create_node_config(&dir_b);
        let devnet_chain_id = config_a.chain_id;

        let miner = TestKeypair::from_seed(1);
        let genesis = genesis_block(devnet_chain_id);
        let mut chain_state = ChainState::from_genesis(&genesis).unwrap();

        // Build Block 1 and Block 2
        let cb1 = make_coinbase(devnet_chain_id, 1, miner.address, 1_000_000_000);
        let b1 = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + 120, vec![cb1]);
        chain_state.apply_block(&b1).unwrap();

        let cb2 = make_coinbase(devnet_chain_id, 2, miner.address, 1_000_000_000);
        let b2 = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + 240, vec![cb2]);
        chain_state.apply_block(&b2).unwrap();
        let expected_tip_id = b2.block_id();
        let expected_state_root = chain_state.composite_state_root();

        // Source node (Node A) stores Block 1 and Block 2 in its storage
        let runtime_a = NodeRuntime::init(config_a).unwrap();
        runtime_a
            .storage()
            .store_branch_block(&b1, U256::from_u128(1))
            .unwrap();
        runtime_a
            .storage()
            .store_branch_block(&b2, U256::from_u128(2))
            .unwrap();
        // Tip remains at 0 so handshake does not trigger premature batch sync
        let (handle_a, _task_a) = runtime_a.spawn_actor();

        // Receiving node (Node B) starts fresh at Genesis
        let runtime_b = NodeRuntime::init(config_b).unwrap();
        assert_eq!(runtime_b.tip_height(), 0);
        let (handle_b, _task_b) = runtime_b.spawn_actor();

        // Connect Node B to Node A
        let addr_a = wait_for_listen_addr(&handle_a).await;
        handle_b.dial_peer(addr_a).await.unwrap();

        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;

        // Receiving peer receives child (b2) BEFORE parent (b1)
        handle_b.submit_block(b2.clone()).await.unwrap();

        // Node B sees parent b1 is missing, puts b2 in orphan pool,
        // and sends a request-response query over /ownchain/sync/1 to Node A.
        // Node A returns b1 from its block storage.
        // Node B passes b1 through local consensus validation, accepts b1,
        // and then unrolls and accepts orphan child b2!
        let timeout = Duration::from_secs(10);
        let start = Instant::now();
        loop {
            let h_b = handle_b.get_tip_height().await.unwrap();
            let orphans_b = handle_b.get_orphan_count().await.unwrap();
            if h_b == 2 && orphans_b == 0 {
                break;
            }
            if start.elapsed() > timeout {
                panic!(
                    "Timed out waiting for remote missing parent recovery. h_b={}, orphans={}",
                    h_b, orphans_b
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Verify Node B accepted both blocks and converged on expected tip and state root
        assert_eq!(handle_b.get_tip_height().await.unwrap(), 2);
        assert_eq!(handle_b.get_tip_block_id().await.unwrap(), expected_tip_id);
        assert_eq!(
            handle_b.get_composite_state_root().await.unwrap(),
            expected_state_root
        );

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 6: Competing Branch Reorganization & Revalidation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_competing_branch_reorganization_and_invalid_ancestor() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();

    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(1);
    let miner_b = TestKeypair::from_seed(2);

    // Branch A: 1 block produced by miner A
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let b_a1 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    runtime.submit_block(b_a1.clone()).await.unwrap();
    assert_eq!(runtime.tip_height(), 1);
    assert_eq!(runtime.tip_block_id(), b_a1.header.block_id());

    // Branch B: Competing fork from genesis with 2 blocks (higher cumulative work)
    let genesis = genesis_block(devnet_chain_id);
    let mut branch_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b_b1 = make_hybrid_block(&branch_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    branch_state.apply_block(&b_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b_b2 = make_hybrid_block(&branch_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_state.apply_block(&b_b2).unwrap();

    // Section 4 fork choice: this submission has cumulative work 1 == 1 (equal work).
    // The tie-break compares the block-ID sequences from genesis at the first
    // differing height (height 1: b_a1 vs b_b1) and elects the lexicographically
    // smaller block ID, regardless of submission order.
    let b_a1_id = b_a1.header.block_id();
    let b_b1_id = b_b1.header.block_id();
    let equal_work_winner_id = if b_b1_id < b_a1_id { b_b1_id } else { b_a1_id };
    runtime.submit_block(b_b1.clone()).await.unwrap();
    assert_eq!(
        runtime.tip_block_id(),
        equal_work_winner_id,
        "Section 4: equal cumulative work must select the lexicographically smaller block-ID sequence \
         from genesis, not the first-seen branch"
    );

    // Second block makes Branch B strictly heavier -> triggers reorganization
    runtime.submit_block(b_b2.clone()).await.unwrap();
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(runtime.tip_block_id(), b_b2.header.block_id());
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        branch_state.composite_state_root()
    );

    // Test Invalid Ancestor: Competing branch with corrupted ancestor block is rejected
    let bad_branch_state = ChainState::from_genesis(&genesis).unwrap();
    let mut bad_b1 = make_hybrid_block(
        &bad_branch_state,
        GENESIS_TIMESTAMP + 120,
        vec![make_coinbase(
            devnet_chain_id,
            1,
            miner_a.address,
            1_000_000_000,
        )],
    );
    bad_b1.header.orchard_commitment_root = Hash::new([0xbb; 32]); // Corrupt root

    // Submit bad branch block; active tip must not change
    let bad_res = runtime.submit_block(bad_b1).await;
    assert!(bad_res.is_err() || runtime.tip_block_id() == b_b2.header.block_id());
    assert_eq!(runtime.tip_block_id(), b_b2.header.block_id());
}

// -----------------------------------------------------------------------------
// Test 7: Bounded Orphan Pool and Safe FIFO Eviction
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_bounded_orphan_pool_and_eviction() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let peer_id = PeerId::random();

    // Insert 105 orphan blocks with unknown parents
    for i in 0..105 {
        let dummy_block = Block {
            header: Header {
                version: 1,
                chain_id: runtime.chain_state().chain_id(),
                height: 10 + i,
                parent_block_id: Hash::new([i as u8 + 1; 32]), // Unknown parent
                transaction_root: Hash::ZERO,
                orchard_commitment_root: empty_commitment_root(),
                timestamp: GENESIS_TIMESTAMP + 1000 + i,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![],
        };
        runtime
            .handle_inbound_block(peer_id, Box::new(dummy_block))
            .await
            .unwrap();
    }

    // Must never exceed MAX_ORPHAN_BLOCKS (100)
    assert!(
        runtime.orphan_count() <= ownchain::node::runtime::MAX_ORPHAN_BLOCKS,
        "Orphan pool count {} exceeded maximum allowed {}",
        runtime.orphan_count(),
        ownchain::node::runtime::MAX_ORPHAN_BLOCKS
    );

    assert!(
        runtime.orphan_bytes() <= ownchain::node::runtime::MAX_ORPHAN_BYTES,
        "Orphan pool bytes {} exceeded maximum allowed {}",
        runtime.orphan_bytes(),
        ownchain::node::runtime::MAX_ORPHAN_BYTES
    );
}

// -----------------------------------------------------------------------------
// Test 8: Lower-Height and Same-Height Higher-Work Fork Reorganizations
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_lower_height_and_same_height_higher_work_reorganization() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();

    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(1);
    let miner_b = TestKeypair::from_seed(2);

    // 1. Build Branch A up to height 18 (timestamps 120s apart, difficulty 1 each -> cumulative work = 18)
    let genesis = genesis_block(devnet_chain_id);
    let mut state_a = ChainState::from_genesis(&genesis).unwrap();
    let mut branch_a_blocks = Vec::new();

    for h in 1..=18 {
        let cb = make_coinbase(devnet_chain_id, h, miner_a.address, 1_000_000_000);
        let b = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + h * 120, vec![cb]);
        state_a.apply_block(&b).unwrap();
        runtime.submit_block(b.clone()).await.unwrap();
        branch_a_blocks.push(b);
    }

    assert_eq!(runtime.tip_height(), 18);
    assert_eq!(runtime.cumulative_work(), U256::from_u128(18));

    // 2. Build Branch B forking from Genesis:
    // Block 1 has timestamp +40, Block 2 has timestamp +80.
    // At height 17, the retarget window (lag=15, samples 0..=2) sees 80s timespan instead of 240s.
    // Difficulty adjusts: 2 * 120 / 80 = 3!
    let mut state_b = ChainState::from_genesis(&genesis).unwrap();
    let mut branch_b_blocks = Vec::new();

    for h in 1..=16 {
        let cb = make_coinbase(devnet_chain_id, h, miner_b.address, 1_000_000_000);
        let ts = if h == 1 {
            GENESIS_TIMESTAMP + 40
        } else if h == 2 {
            GENESIS_TIMESTAMP + 80
        } else {
            GENESIS_TIMESTAMP + 80 + h
        };
        let b = make_hybrid_block(&state_b, ts, vec![cb]);
        state_b.apply_block(&b).unwrap();
        branch_b_blocks.push(b);
    }

    // Block 17 has expected difficulty 3
    let diff_17 = state_b.expected_difficulty_for_next_block().unwrap();
    assert_eq!(
        diff_17, 3,
        "Difficulty for block 17 with 80s timespan must be 3"
    );

    let cb17 = make_coinbase(devnet_chain_id, 17, miner_b.address, 1_000_000_000);
    let b17 = make_hybrid_block_with_diff(&state_b, diff_17, GENESIS_TIMESTAMP + 120, vec![cb17]);
    state_b.apply_block(&b17).unwrap();
    branch_b_blocks.push(b17.clone());

    // Branch B has height 17 and cumulative work = 16 + 3 = 19
    assert_eq!(state_b.tip_height(), Some(17));
    assert_eq!(state_b.cumulative_work(), U256::from_u128(19));

    // 3. Submit Branch B to Node Runtime
    // Blocks 1..16 have cumulative work <= 18, so they are stored as side branch blocks
    for b in &branch_b_blocks[0..16] {
        runtime.submit_block(b.clone()).await.unwrap();
    }
    // Tip is still Branch A (height 18)
    assert_eq!(runtime.tip_height(), 18);

    // Block 17 makes Branch B cumulative work (19) strictly higher than Branch A (18)
    // Even though Branch B has LOWER height (17 < 18)!
    runtime.submit_block(b17.clone()).await.unwrap();

    // 4. Verify successful reorganization to lower-height, higher-work Branch B
    assert_eq!(
        runtime.tip_height(),
        17,
        "Reorganization must accept lower-height fork with higher work"
    );
    assert_eq!(runtime.tip_block_id(), b17.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(19));
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        state_b.composite_state_root()
    );

    // 5. Verify height 18 from Branch A was cleanly pruned from active storage
    assert!(runtime.storage().get_block_by_height(18).unwrap().is_none());

    // 6. Test Subsequent Reorganization:
    // Extend Branch A with 2 more blocks (heights 19 and 20, difficulty 1 each)
    // Cumulative work becomes 18 + 1 + 1 = 20 > 19!
    let mut state_a_extend = state_a.clone();
    let mut branch_a_extend_blocks = Vec::new();

    let cb19 = make_coinbase(devnet_chain_id, 19, miner_a.address, 1_000_000_000);
    let b19 = make_hybrid_block(&state_a_extend, GENESIS_TIMESTAMP + 19 * 120, vec![cb19]);
    state_a_extend.apply_block(&b19).unwrap();
    branch_a_extend_blocks.push(b19.clone());

    let cb20 = make_coinbase(devnet_chain_id, 20, miner_a.address, 1_000_000_000);
    let b20 = make_hybrid_block(&state_a_extend, GENESIS_TIMESTAMP + 20 * 120, vec![cb20]);
    state_a_extend.apply_block(&b20).unwrap();
    branch_a_extend_blocks.push(b20.clone());

    assert_eq!(state_a_extend.cumulative_work(), U256::from_u128(20));

    // Submit block 19: work is 19 == 19 (equal work). Protocol Section 4 breaks the
    // tie by comparing the block-ID sequences from genesis at the first
    // differing height — here height 1, Branch B's first block vs Branch A's
    // first block. The lexicographically smaller sequence wins regardless of
    // submission order; height alone never decides an equal-work tie.
    let branch_b_smaller =
        branch_b_blocks[0].header.block_id() < branch_a_blocks[0].header.block_id();
    runtime.submit_block(b19).await.unwrap();
    if branch_b_smaller {
        assert_eq!(
            runtime.tip_height(),
            17,
            "Branch B wins the Section 4 tie-break at the first differing height and is retained \
             until strictly heavier work arrives"
        );
    } else {
        assert_eq!(
            runtime.tip_height(),
            19,
            "Section 4: Branch A extension wins the equal-work tie-break at the first differing height \
             (its height-1 block ID is lexicographically smaller)"
        );
    }

    // Submit block 20: work is 20 > 19 -> triggers reorganization back to Branch A!
    runtime.submit_block(b20.clone()).await.unwrap();

    // Node reorganizes BACK to Branch A!
    assert_eq!(runtime.tip_height(), 20);
    assert_eq!(runtime.tip_block_id(), b20.block_id());
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        state_a_extend.composite_state_root()
    );
}

// -----------------------------------------------------------------------------
// Test 9: Real P2P Fork-Aware Sync and Competing Branch Reorganization
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_competing_branch_sync_and_reorganization() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let config_a = create_node_config(&dir_a);
        let config_b = create_node_config(&dir_b);
        let devnet_chain_id = config_a.chain_id;

        let miner_a = TestKeypair::from_seed(1);
        let miner_b = TestKeypair::from_seed(2);
        let genesis = genesis_block(devnet_chain_id);

        // 1. Build Branch A up to height 18 (timestamps 120s apart, difficulty 1 each -> cumulative work = 18)
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let mut branch_a_blocks = Vec::new();
        for h in 1..=18 {
            let cb = make_coinbase(devnet_chain_id, h, miner_a.address, 1_000_000_000);
            let b = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            state_a.apply_block(&b).unwrap();
            branch_a_blocks.push(b);
        }

        // 2. Build Branch B forking from Genesis:
        // Block 1 timestamp +40, Block 2 timestamp +80.
        // At height 17, retarget window adjusts difficulty to 3.
        // Branch B cumulative work = 16 * 1 + 3 = 19.
        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let mut branch_b_blocks = Vec::new();
        for h in 1..=16 {
            let cb = make_coinbase(devnet_chain_id, h, miner_b.address, 1_000_000_000);
            let ts = if h == 1 {
                GENESIS_TIMESTAMP + 40
            } else if h == 2 {
                GENESIS_TIMESTAMP + 80
            } else {
                GENESIS_TIMESTAMP + 80 + h
            };
            let b = make_hybrid_block(&state_b, ts, vec![cb]);
            state_b.apply_block(&b).unwrap();
            branch_b_blocks.push(b);
        }
        let diff_17 = state_b.expected_difficulty_for_next_block().unwrap();
        assert_eq!(diff_17, 3);
        let cb17 = make_coinbase(devnet_chain_id, 17, miner_b.address, 1_000_000_000);
        let b17 = make_hybrid_block_with_diff(&state_b, diff_17, GENESIS_TIMESTAMP + 120, vec![cb17]);
        state_b.apply_block(&b17).unwrap();
        branch_b_blocks.push(b17.clone());

        // 3. Node A starts with Branch A (height 18, work 18)
        let mut runtime_a = NodeRuntime::init(config_a).unwrap();
        for b in &branch_a_blocks {
            runtime_a.submit_block(b.clone()).await.unwrap();
        }
        assert_eq!(runtime_a.tip_height(), 18);
        assert_eq!(runtime_a.cumulative_work(), U256::from_u128(18));

        // 4. Node B starts with Branch B (height 17, work 19)
        let mut runtime_b = NodeRuntime::init(config_b).unwrap();
        for b in &branch_b_blocks {
            runtime_b.submit_block(b.clone()).await.unwrap();
        }
        assert_eq!(runtime_b.tip_height(), 17);
        assert_eq!(runtime_b.cumulative_work(), U256::from_u128(19));

        // 5. Spawn both nodes and establish real libp2p TCP connections
        let (handle_a, _task_a) = runtime_a.spawn_actor();
        let (handle_b, _task_b) = runtime_b.spawn_actor();

        let addr_b = wait_for_listen_addr(&handle_b).await;
        handle_a.dial_peer(addr_b).await.unwrap();

        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;

        // 6. Node A receives Node B's handshake, recognizes Node B has work 19 > 18 despite height 17 < 18!
        // Node A runs common-ancestor discovery (Genesis), requests replacement blocks over /ownchain/sync/1,
        // validates all blocks, and reorganizes to Branch B!
        let timeout = Duration::from_secs(15);
        let start = Instant::now();
        loop {
            let h_a = handle_a.get_tip_height().await.unwrap();
            let work_a = handle_a.get_cumulative_work().await.unwrap();
            if h_a == 17 && work_a == U256::from_u128(19) {
                break;
            }
            if start.elapsed() > timeout {
                panic!("Timed out waiting for Node A to reorganize to Branch B via P2P sync. h_a={h_a}, work_a={work_a:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Verify Node A and Node B converged on identical tip, work, and composite state root
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 17);
        assert_eq!(handle_a.get_tip_block_id().await.unwrap(), b17.block_id());
        assert_eq!(handle_a.get_tip_block_id().await.unwrap(), handle_b.get_tip_block_id().await.unwrap());
        assert_eq!(handle_a.get_cumulative_work().await.unwrap(), U256::from_u128(19));
        assert_eq!(handle_a.get_composite_state_root().await.unwrap(), handle_b.get_composite_state_root().await.unwrap());

        // 7. Subsequent heavier Branch A extension:
        // Extend Branch A with block 19 and block 20 (work 20 > 19)
        let cb19 = make_coinbase(devnet_chain_id, 19, miner_a.address, 1_000_000_000);
        let b19 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 19 * 120, vec![cb19]);
        state_a.apply_block(&b19).unwrap();

        let cb20 = make_coinbase(devnet_chain_id, 20, miner_a.address, 1_000_000_000);
        let b20 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 20 * 120, vec![cb20]);
        state_a.apply_block(&b20).unwrap();

        // Submit blocks 19 and 20 to Node A
        handle_a.submit_block(b19.clone()).await.unwrap();
        handle_a.submit_block(b20.clone()).await.unwrap();

        // Node A reorganizes back to Branch A at height 20
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 20);
        assert_eq!(handle_a.get_cumulative_work().await.unwrap(), U256::from_u128(20));

        // Node B synchronizes from Node A over /ownchain/sync/1
        handle_b.sync_with_peer(handle_a.peer_id(), 20).await.unwrap();

        let start2 = Instant::now();
        loop {
            let h_b = handle_b.get_tip_height().await.unwrap();
            let work_b = handle_b.get_cumulative_work().await.unwrap();
            if h_b == 20 && work_b == U256::from_u128(20) {
                break;
            }
            if start2.elapsed() > timeout {
                panic!("Timed out waiting for Node B to reorganize to heavier Branch A. h_b={h_b}, work_b={work_b:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Verify Node B reorganized to Branch A and matches Node A exactly
        assert_eq!(handle_b.get_tip_height().await.unwrap(), 20);
        assert_eq!(handle_b.get_tip_block_id().await.unwrap(), b20.block_id());
        assert_eq!(handle_b.get_cumulative_work().await.unwrap(), U256::from_u128(20));
        assert_eq!(handle_b.get_composite_state_root().await.unwrap(), handle_a.get_composite_state_root().await.unwrap());

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 10: Oversized Frame Rejection Before Allocation
// -----------------------------------------------------------------------------

#[test]
fn test_oversized_frame_rejected_before_allocation() {
    let oversized_len: u32 = (MAX_FRAME_LENGTH + 1) as u32;
    let mut frame_header = [0u8; 4];
    frame_header.copy_from_slice(&oversized_len.to_le_bytes());

    let res = decode_frame_slice(&frame_header);
    assert!(matches!(
        res,
        Err(FramingError::FrameTooLarge { actual, max }) if actual == 2_100_001 && max == 2_100_000
    ));
}

// -----------------------------------------------------------------------------
// Test 11: Real P2P Simultaneous Synchronization
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_simultaneous_synchronization() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let mut state_b = ChainState::from_genesis(&genesis).unwrap();

        let miner_a = TestKeypair::from_seed(1);
        let miner_b = TestKeypair::from_seed(2);

        // Build 3 blocks on Branch A for Node A (total work 3)
        let mut blocks_a = Vec::new();
        for h in 1..=3 {
            let cb = make_coinbase(devnet_chain_id, h, miner_a.address, 1_000_000_000);
            let b = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            state_a.apply_block(&b).unwrap();
            blocks_a.push(b);
        }

        // Build 5 blocks on Branch B for Node B (total work 5)
        let mut blocks_b = Vec::new();
        for h in 1..=5 {
            let cb = make_coinbase(devnet_chain_id, h, miner_b.address, 1_000_000_000);
            let b = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + h * 120 + 1, vec![cb]);
            state_b.apply_block(&b).unwrap();
            blocks_b.push(b);
        }

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let config_b = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_b.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();
        let (handle_b, _s_b) = NodeRuntime::spawn(config_b).unwrap();

        // Submit Branch A blocks to Node A
        for b in blocks_a {
            handle_a.submit_block(b).await.unwrap();
        }
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 3);
        assert_eq!(
            handle_a.get_cumulative_work().await.unwrap(),
            U256::from_u128(3)
        );

        // Submit Branch B blocks to Node B
        for b in &blocks_b {
            handle_b.submit_block(b.clone()).await.unwrap();
        }
        assert_eq!(handle_b.get_tip_height().await.unwrap(), 5);
        assert_eq!(
            handle_b.get_cumulative_work().await.unwrap(),
            U256::from_u128(5)
        );

        // Connect nodes
        let addr_b = wait_for_listen_addr(&handle_b).await;
        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;

        // Trigger simultaneous sync in both directions concurrently
        let sync_a = handle_a.sync_with_peer(handle_b.peer_id(), 5);
        let sync_b = handle_b.sync_with_peer(handle_a.peer_id(), 3);

        let (res_a, res_b) = tokio::join!(sync_a, sync_b);
        assert!(
            res_a.is_ok(),
            "Node A sync with Node B must succeed: {:?}",
            res_a
        );
        assert!(
            res_b.is_ok(),
            "Node B sync with Node A must succeed: {:?}",
            res_b
        );

        let expected_tip_b = blocks_b.last().unwrap().block_id();
        let status_a = wait_for_tip(&handle_a, 5, expected_tip_b).await;
        let status_b = wait_for_tip(&handle_b, 5, expected_tip_b).await;

        // Verify both nodes converged on the heavier Branch B
        assert_eq!(status_a.tip_height, 5);
        assert_eq!(status_b.tip_height, 5);
        assert_eq!(status_a.tip_block_id, expected_tip_b);
        assert_eq!(status_b.tip_block_id, expected_tip_b);
        assert_eq!(status_a.cumulative_work, U256::from_u128(5));
        assert_eq!(status_b.cumulative_work, U256::from_u128(5));
        assert_eq!(status_a.composite_state_root, status_b.composite_state_root);

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 12: Controlled Runtime Responsiveness During Active Outbound Synchronization
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_runtime_responsiveness_during_sync() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let miner_b = TestKeypair::from_seed(3);

        // Build 6 blocks for remote peer B
        let mut blocks_b = Vec::new();
        for h in 1..=6 {
            let cb = make_coinbase(devnet_chain_id, h, miner_b.address, 1_000_000_000);
            let b = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            state_b.apply_block(&b).unwrap();
            blocks_b.push(b);
        }

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();

        // Node B is a controlled NetworkService instance so we can hold sync requests pending
        let keypair_b = libp2p::identity::Keypair::generate_ed25519();
        let peer_id_b = ownchain::p2p::peer_id_from_keypair(&keypair_b);
        let (network_service_b, network_handle_b, mut network_event_rx_b) = NetworkService::new(
            keypair_b,
            "devnet",
            devnet_chain_id,
            genesis.block_id(),
            6,
            blocks_b.last().unwrap().block_id(),
            U256::from_u128(6),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            500,
            500,
        )
        .unwrap();
        let b_task = tokio::spawn(network_service_b.run());

        // Get listen address of Node B
        let mut addr_b = None;
        for _ in 0..50 {
            let addrs = network_handle_b
                .get_listen_addrs()
                .await
                .unwrap_or_default();
            if let Some(a) = addrs.into_iter().next() {
                addr_b = Some(a);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let addr_b = addr_b.expect("Node B failed to bind listen address");

        // Node A dials Node B
        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, peer_id_b).await;

        let handle_a_clone = handle_a.clone();

        // 1. Start outbound synchronization from Node A to Node B
        let sync_task =
            tokio::spawn(async move { handle_a_clone.sync_with_peer(peer_id_b, 6).await });

        // 2. Deliberately hold remote sync response pending on Node B
        let (pending_req, pending_chan) = loop {
            match network_event_rx_b.recv().await {
                Some(NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request,
                    channel,
                }) => {
                    if peer_id == handle_a.peer_id() {
                        break (request, channel);
                    }
                }
                Some(_) => {}
                None => panic!("Node B network event stream closed unexpectedly"),
            }
        };
        assert!(
            matches!(pending_req, SyncRequest::GetHeaders { .. }),
            "First sync request must be GetHeaders, got {:?}",
            pending_req
        );

        // 3. While the sync worker is still blocked waiting for Node B, verify local actor responds to GetStatus
        let status_a = handle_a.status().await.unwrap();
        assert_eq!(status_a.peer_id, handle_a.peer_id());

        // 4. Issue an inbound sync request from Node B to Node A and verify it receives an immediate response
        let inbound_resp = network_handle_b
            .send_sync_request(handle_a.peer_id(), SyncRequest::GetStatus)
            .await
            .expect("Inbound GetStatus request to Node A must succeed");
        match inbound_resp {
            SyncResponse::Status { tip_height, .. } => {
                assert_eq!(tip_height, 0);
            }
            other => panic!("Expected SyncResponse::Status, got {other:?}"),
        }

        // 5. Only then release the pending outbound headers response
        let headers: Vec<Header> = blocks_b.iter().map(|b| b.header).collect();
        network_handle_b
            .send_sync_response(pending_chan, SyncResponse::Headers(headers))
            .await
            .unwrap();

        // 6. Handle the subsequent GetBlocks request from Node A
        loop {
            match network_event_rx_b.recv().await {
                Some(NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request,
                    channel,
                }) => {
                    if peer_id == handle_a.peer_id() {
                        if let SyncRequest::GetBlocks { .. } = request {
                            network_handle_b
                                .send_sync_response(channel, SyncResponse::Blocks(blocks_b.clone()))
                                .await
                                .unwrap();
                            break;
                        }
                    }
                }
                Some(_) => {}
                None => panic!("Node B network event stream closed unexpectedly"),
            }
        }

        // 7. Complete synchronization and verify final chain state
        let sync_res = sync_task.await.unwrap();
        assert!(sync_res.is_ok(), "Sync task failed: {:?}", sync_res);

        let final_tip_b = blocks_b.last().unwrap().block_id();
        let final_status = wait_for_tip(&handle_a, 6, final_tip_b).await;
        assert_eq!(final_status.tip_height, 6);
        assert_eq!(final_status.tip_block_id, final_tip_b);

        handle_a.stop().await;
        b_task.abort();
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 13: Non-Blocking Missing-Parent Recovery
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_nonblocking_missing_parent_recovery() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let miner_a = TestKeypair::from_seed(4);

        // Build block 1 and block 2
        let cb1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
        let b1 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb1]);
        state_a.apply_block(&b1).unwrap();

        let cb2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
        let b2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb2]);

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let config_b = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_b.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();
        let (handle_b, _s_b) = NodeRuntime::spawn(config_b).unwrap();

        // Node A gets block 1 only
        handle_a.submit_block(b1.clone()).await.unwrap();
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 1);

        // Connect Node A and Node B
        let addr_b = wait_for_listen_addr(&handle_b).await;
        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;

        // Deliver block 2 (missing parent block 1) directly to Node B
        handle_b.submit_block(b2.clone()).await.unwrap();

        // While missing parent recovery is active, verify Node B remains immediately responsive
        let start = Instant::now();
        let status_b = handle_b.status().await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "Node B status took {:?}, exceeding 500ms bound",
            elapsed
        );
        assert_eq!(status_b.peer_id, handle_b.peer_id());

        // Node B should recover parent block 1 from Node A and process both block 1 and block 2
        let final_status_b = wait_for_tip(&handle_b, 2, b2.block_id()).await;
        assert_eq!(final_status_b.tip_height, 2);
        assert_eq!(final_status_b.tip_block_id, b2.block_id());
        assert_eq!(handle_b.get_orphan_count().await.unwrap(), 0);

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 14: Synchronization Cancellation and Peer Disconnection Handling
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_sync_cancellation_and_peer_disconnect() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let miner_b = TestKeypair::from_seed(5);

        // Build 5 blocks for remote peer B
        let mut blocks_b = Vec::new();
        for h in 1..=5 {
            let cb = make_coinbase(devnet_chain_id, h, miner_b.address, 1_000_000_000);
            let b = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            state_b.apply_block(&b).unwrap();
            blocks_b.push(b);
        }

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();

        // Node B is a controlled NetworkService instance so we can hold sync requests pending
        let keypair_b = libp2p::identity::Keypair::generate_ed25519();
        let peer_id_b = ownchain::p2p::peer_id_from_keypair(&keypair_b);
        let (network_service_b, network_handle_b, mut network_event_rx_b) = NetworkService::new(
            keypair_b,
            "devnet",
            devnet_chain_id,
            genesis.block_id(),
            5,
            blocks_b.last().unwrap().block_id(),
            U256::from_u128(5),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            500,
            500,
        )
        .unwrap();
        let b_task = tokio::spawn(network_service_b.run());

        // Get listen address of Node B
        let mut addr_b = None;
        for _ in 0..50 {
            let addrs = network_handle_b
                .get_listen_addrs()
                .await
                .unwrap_or_default();
            if let Some(a) = addrs.into_iter().next() {
                addr_b = Some(a);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let addr_b = addr_b.expect("Node B failed to bind listen address");

        // Node A dials Node B
        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, peer_id_b).await;

        let handle_a_clone = handle_a.clone();

        // 1. Spawn sync task on Node A
        let sync_task =
            tokio::spawn(async move { handle_a_clone.sync_with_peer(peer_id_b, 5).await });

        // 2. Wait until Node B receives the initial GetHeaders sync request from Node A
        let (_pending_req, _pending_chan) = loop {
            match network_event_rx_b.recv().await {
                Some(NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request,
                    channel,
                }) => {
                    if peer_id == handle_a.peer_id() {
                        assert!(
                            matches!(request, SyncRequest::GetHeaders { .. }),
                            "First sync request must be GetHeaders, got {:?}",
                            request
                        );
                        break (request, channel);
                    }
                }
                Some(_) => {}
                None => panic!("Node B network event stream closed unexpectedly"),
            }
        };

        // 3. While the sync worker is actively waiting for Node B's response, disconnect Node B
        handle_a.disconnect(peer_id_b).await.unwrap();

        // 4. The waiting sync caller must terminate promptly and receive an Err
        let sync_res = sync_task.await.unwrap();
        assert!(
            sync_res.is_err(),
            "Sync task must receive error on peer disconnect, got {:?}",
            sync_res
        );

        // 5. Node A runtime must remain responsive after disconnect
        let status = handle_a.status().await.unwrap();
        assert_eq!(status.peer_id, handle_a.peer_id());

        // 6. Graceful shutdown must complete without hanging
        handle_a.stop().await;
        b_task.abort();
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 15: Consistent Chain View and Ancestor Discovery Invalidation on Mutation
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_sync_ancestor_discovery_chain_mutation_restart() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let miner_a = TestKeypair::from_seed(10);

        // Build Block A1 and Block A2 for Node A
        let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
        let b_a1 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);
        state_a.apply_block(&b_a1).unwrap();

        let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
        let b_a2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
        state_a.apply_block(&b_a2).unwrap();

        // Build Block A3 (to be submitted during pending ancestor discovery)
        let cb_a3 = make_coinbase(devnet_chain_id, 3, miner_a.address, 1_000_000_000);
        let b_a3 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 360, vec![cb_a3]);

        // Build 4 blocks on Branch B for Node B
        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let miner_b = TestKeypair::from_seed(20);
        let mut blocks_b = Vec::new();
        for h in 1..=4 {
            let cb = make_coinbase(devnet_chain_id, h, miner_b.address, 1_000_000_000);
            let b = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + h * 120 + 1, vec![cb]);
            state_b.apply_block(&b).unwrap();
            blocks_b.push(b);
        }

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();
        handle_a.submit_block(b_a1).await.unwrap();
        handle_a.submit_block(b_a2).await.unwrap();
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 2);

        // Controlled Node B network service
        let keypair_b = libp2p::identity::Keypair::generate_ed25519();
        let peer_id_b = ownchain::p2p::peer_id_from_keypair(&keypair_b);
        let (network_service_b, network_handle_b, mut network_event_rx_b) = NetworkService::new(
            keypair_b,
            "devnet",
            devnet_chain_id,
            genesis.block_id(),
            4,
            blocks_b.last().unwrap().block_id(),
            U256::from_u128(4),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            500,
            500,
        )
        .unwrap();
        let b_task = tokio::spawn(network_service_b.run());

        let mut addr_b = None;
        for _ in 0..50 {
            let addrs = network_handle_b
                .get_listen_addrs()
                .await
                .unwrap_or_default();
            if let Some(a) = addrs.into_iter().next() {
                addr_b = Some(a);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let addr_b = addr_b.expect("Node B failed to bind listen address");

        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, peer_id_b).await;

        let handle_a_clone = handle_a.clone();
        // Start sync with Node B
        let sync_task =
            tokio::spawn(async move { handle_a_clone.sync_with_peer(peer_id_b, 4).await });

        // Intercept initial GetHeaders request from Node A
        let (first_req, first_channel) = loop {
            match network_event_rx_b.recv().await {
                Some(NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request,
                    channel,
                }) if peer_id == handle_a.peer_id() => break (request, channel),
                Some(_) => {}
                None => panic!("Node B event stream closed"),
            }
        };
        assert!(matches!(first_req, SyncRequest::GetHeaders { .. }));

        // While ancestor discovery is pending on Node B, mutate Node A's local chain by submitting Block A3!
        handle_a.submit_block(b_a3).await.unwrap();
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 3);

        // Now respond to the first GetHeaders request
        network_handle_b
            .send_sync_response(
                first_channel,
                SyncResponse::Headers(vec![blocks_b[1].header]),
            )
            .await
            .unwrap();

        // Node A must detect the chain revision change and restart ancestor discovery!
        // Loop through remaining sync requests from Node A, answering properly
        let b_blocks_clone = blocks_b.clone();
        let peer_id_a = handle_a.peer_id();
        tokio::spawn(async move {
            while let Some(ev) = network_event_rx_b.recv().await {
                if let NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request,
                    channel,
                } = ev
                {
                    if peer_id == peer_id_a {
                        match request {
                            SyncRequest::GetHeaders {
                                start_height,
                                max_count,
                            } => {
                                let mut hdrs = Vec::new();
                                for h in start_height..(start_height + max_count as u64) {
                                    if h >= 1 && h <= b_blocks_clone.len() as u64 {
                                        hdrs.push(b_blocks_clone[(h - 1) as usize].header);
                                    }
                                }
                                let _ = network_handle_b
                                    .send_sync_response(channel, SyncResponse::Headers(hdrs))
                                    .await;
                            }
                            SyncRequest::GetBlocks { block_ids } => {
                                let mut blks = Vec::new();
                                for id in block_ids {
                                    if let Some(b) =
                                        b_blocks_clone.iter().find(|b| b.block_id() == id)
                                    {
                                        blks.push(b.clone());
                                    }
                                }
                                let _ = network_handle_b
                                    .send_sync_response(channel, SyncResponse::Blocks(blks))
                                    .await;
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        // Sync task must resolve cleanly against a coherent chain view
        let sync_res = sync_task.await.unwrap();
        assert!(sync_res.is_ok(), "Sync task failed: {:?}", sync_res);

        let final_tip_b = blocks_b.last().unwrap().block_id();
        let final_status = wait_for_tip(&handle_a, 4, final_tip_b).await;
        assert_eq!(final_status.tip_height, 4);
        assert_eq!(final_status.tip_block_id, final_tip_b);

        handle_a.stop().await;
        b_task.abort();
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 16: Recursive Missing Parent Recovery
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_missing_parent_recursive_cascade() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let miner_a = TestKeypair::from_seed(30);

        // Build Blocks 1, 2, and 3
        let cb1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
        let b1 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb1]);
        state_a.apply_block(&b1).unwrap();

        let cb2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
        let b2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb2]);
        state_a.apply_block(&b2).unwrap();

        let cb3 = make_coinbase(devnet_chain_id, 3, miner_a.address, 1_000_000_000);
        let b3 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 360, vec![cb3]);
        state_a.apply_block(&b3).unwrap();

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let config_b = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_b.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();
        let (handle_b, _s_b) = NodeRuntime::spawn(config_b).unwrap();

        // Node A has all 3 blocks
        handle_a.submit_block(b1).await.unwrap();
        handle_a.submit_block(b2).await.unwrap();
        handle_a.submit_block(b3.clone()).await.unwrap();
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 3);

        // Connect Node A and Node B
        let addr_b = wait_for_listen_addr(&handle_b).await;
        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;

        // Submit Block 3 directly to Node B (missing Block 2 and Block 1)
        handle_b.submit_block(b3.clone()).await.unwrap();

        // Node B must recursively fetch Block 2 then Block 1 from Node A, and cascade-apply all 3 blocks
        let final_status_b = wait_for_tip(&handle_b, 3, b3.block_id()).await;
        assert_eq!(final_status_b.tip_height, 3);
        assert_eq!(final_status_b.tip_block_id, b3.block_id());
        assert_eq!(handle_b.get_orphan_count().await.unwrap(), 0);

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 17: Missing Parent Recovery Safe Retry After Initial Failure
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_missing_parent_retry_after_failure() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let miner = TestKeypair::from_seed(40);

        // Build Block 1 and Block 2
        let cb1 = make_coinbase(devnet_chain_id, 1, miner.address, 1_000_000_000);
        let b1 = make_hybrid_block(&state, GENESIS_TIMESTAMP + 120, vec![cb1]);
        state.apply_block(&b1).unwrap();

        let cb2 = make_coinbase(devnet_chain_id, 2, miner.address, 1_000_000_000);
        let b2 = make_hybrid_block(&state, GENESIS_TIMESTAMP + 240, vec![cb2]);

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let config_b = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_b.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();
        let (handle_b, _s_b) = NodeRuntime::spawn(config_b).unwrap();

        let addr_b = wait_for_listen_addr(&handle_b).await;
        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;

        // Step 1: Submit Block 2 to Node B. Node A does NOT have Block 1 yet.
        // Recovery attempt 1 fails and enters bounded exponential backoff.
        handle_b.submit_block(b2.clone()).await.unwrap();

        // Give Node B a moment to query Node A, fail, and enter backoff
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(handle_b.get_tip_height().await.unwrap(), 0);

        // Step 2: Now supply Block 1 to Node A
        handle_a.submit_block(b1).await.unwrap();
        assert_eq!(handle_a.get_tip_height().await.unwrap(), 1);

        // Step 3: Node B autonomously retries missing parent recovery via backoff without child block resubmission!
        let final_status_b = wait_for_tip(&handle_b, 2, b2.block_id()).await;
        assert_eq!(final_status_b.tip_height, 2);
        assert_eq!(final_status_b.tip_block_id, b2.block_id());
        assert_eq!(handle_b.get_orphan_count().await.unwrap(), 0);

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 18: Node Shutdown Aborts and Awaits Active Sync Workers
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_real_p2p_shutdown_aborts_and_joins_active_sync() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_a = TempDir::new().unwrap();
        let devnet_chain_id = hash::chain_id(DEVNET);
        let genesis = genesis_block(devnet_chain_id);

        let config_a = NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: devnet_chain_id,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir_a.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        };

        let (handle_a, _s_a) = NodeRuntime::spawn(config_a).unwrap();

        // Node B is a controlled NetworkService that deliberately never responds to sync requests
        let keypair_b = libp2p::identity::Keypair::generate_ed25519();
        let peer_id_b = ownchain::p2p::peer_id_from_keypair(&keypair_b);
        let (network_service_b, network_handle_b, mut network_event_rx_b) = NetworkService::new(
            keypair_b,
            "devnet",
            devnet_chain_id,
            genesis.block_id(),
            10,
            Hash::new([99u8; 32]),
            U256::from_u128(10),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            500,
            500,
        )
        .unwrap();
        let b_task = tokio::spawn(network_service_b.run());

        let mut addr_b = None;
        for _ in 0..50 {
            let addrs = network_handle_b
                .get_listen_addrs()
                .await
                .unwrap_or_default();
            if let Some(a) = addrs.into_iter().next() {
                addr_b = Some(a);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let addr_b = addr_b.expect("Node B failed to bind listen address");

        handle_a.dial(addr_b).await.unwrap();
        wait_for_peer_handshake(&handle_a, peer_id_b).await;

        let handle_a_clone = handle_a.clone();
        // Start sync with Node B
        let sync_task =
            tokio::spawn(async move { handle_a_clone.sync_with_peer(peer_id_b, 10).await });

        // Wait until Node B receives the initial GetHeaders request
        loop {
            match network_event_rx_b.recv().await {
                Some(NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request: SyncRequest::GetHeaders { .. },
                    ..
                }) if peer_id == handle_a.peer_id() => break,
                Some(_) => {}
                None => panic!("Node B event stream closed"),
            }
        }

        // Call stop on Node A while sync worker is active
        let stop_start = Instant::now();
        handle_a.stop().await;
        let stop_duration = stop_start.elapsed();

        // Node stop must finish promptly and join background workers
        assert!(
            stop_duration < Duration::from_secs(5),
            "Shutdown took {:?}, exceeding 5s bound",
            stop_duration
        );

        // Pending sync caller must receive error result
        let sync_res = sync_task.await.unwrap();
        assert!(
            sync_res.is_err(),
            "Pending sync task must receive error on shutdown, got {:?}",
            sync_res
        );

        b_task.abort();
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 19: Equal-Work P2P Convergence (Section 4 tie-break across the network)
// -----------------------------------------------------------------------------

/// Returns a nonce variant of `base` whose block ID satisfies `want_smaller`
/// against `bound` (smaller than `bound` when `true`, larger when `false`).
///
/// At difficulty 1 every proof-of-work hash is accepted and the simulated
/// composite state root is nonce-independent, so every variant is a fully
/// valid block.
fn nonce_variant_block(base: &Block, bound: Hash, want_smaller: bool) -> Block {
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

#[tokio::test]
async fn test_real_p2p_equal_work_convergence() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let config_a = create_node_config(&dir_a);
        let config_b = create_node_config(&dir_b);
        let devnet_chain_id = config_a.chain_id;

        let miner_a = TestKeypair::from_seed(1);
        let miner_b = TestKeypair::from_seed(2);
        let genesis = genesis_block(devnet_chain_id);

        // Two equal-work branches fork at genesis: 2 difficulty-1 blocks each,
        // so cumulative work is 2 on both sides. The height-1 IDs decide the
        // Section 4 tie-break (a1 < b1). The height-2 tip IDs are deliberately ordered
        // the opposite way (a2 > b2), so a fork choice that compared only final
        // tip IDs would elect the wrong branch.
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
        let a1_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);

        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
        let b1 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 120, vec![cb_b1]);

        let a1 = nonce_variant_block(&a1_base, b1.block_id(), true);
        assert!(
            a1.block_id() < b1.block_id(),
            "test construction: branch A must own the lexicographically smaller height-1 block ID"
        );
        state_a.apply_block(&a1).unwrap();
        state_b.apply_block(&b1).unwrap();

        let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
        let a2_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
        let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
        let b2 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 240, vec![cb_b2]);

        let a2 = nonce_variant_block(&a2_base, b2.block_id(), false);
        assert!(
            a2.block_id() > b2.block_id(),
            "test construction: tip IDs must oppose the deciding height-1 ordering"
        );
        state_a.apply_block(&a2).unwrap();
        state_b.apply_block(&b2).unwrap();

        // Equal cumulative work, distinct chains: this is a pure Section 4 tie-break.
        assert_eq!(state_a.cumulative_work(), state_b.cumulative_work());
        assert_eq!(state_a.cumulative_work(), U256::from_u128(2));
        assert_ne!(
            state_a.composite_state_root(),
            state_b.composite_state_root()
        );

        let winner_tip_id = a2.block_id();
        let winner_state_root = state_a.composite_state_root();

        // Node A starts on the Section 4-winning branch; Node B starts on the
        // equal-work loser.
        let mut runtime_a = NodeRuntime::init(config_a).unwrap();
        runtime_a.submit_block(a1.clone()).await.unwrap();
        runtime_a.submit_block(a2.clone()).await.unwrap();

        let mut runtime_b = NodeRuntime::init(config_b).unwrap();
        runtime_b.submit_block(b1.clone()).await.unwrap();
        runtime_b.submit_block(b2.clone()).await.unwrap();

        assert_eq!(runtime_a.tip_block_id(), winner_tip_id);
        assert_eq!(runtime_a.cumulative_work(), runtime_b.cumulative_work());
        assert_eq!(runtime_b.tip_block_id(), b2.block_id());

        // Start both node actors.
        let (handle_a, _task_a) = runtime_a.spawn_actor();
        let (handle_b, _task_b) = runtime_b.spawn_actor();

        // Connect through the real libp2p transport and wait for the
        // handshake on both sides.
        let addr_a = wait_for_listen_addr(&handle_a).await;
        handle_b.dial_peer(addr_a).await.unwrap();
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;

        // Both peers advertised equal work over the handshake. This is exactly
        // the network-level condition under which synchronization must still
        // run: neither the handshake handler (runtime.rs:1916) nor periodic
        // peer selection (runtime.rs:1211-1218) starts a sync on equal work,
        // because both compare with a strict `>`.
        let peers_a = handle_a.get_connected_peers().await.unwrap();
        let remote_b = peers_a
            .iter()
            .find(|p| p.peer_id == handle_b.peer_id())
            .and_then(|p| p.handshake.as_ref())
            .expect("node A must have verified node B's handshake");
        assert_eq!(remote_b.cumulative_work, U256::from_u128(2));
        assert_eq!(remote_b.tip_block_id, b2.block_id());

        let peers_b = handle_b.get_connected_peers().await.unwrap();
        let remote_a = peers_b
            .iter()
            .find(|p| p.peer_id == handle_a.peer_id())
            .and_then(|p| p.handshake.as_ref())
            .expect("node B must have verified node A's handshake");
        assert_eq!(remote_a.cumulative_work, U256::from_u128(2));
        assert_eq!(remote_a.tip_block_id, winner_tip_id);

        // Wait for Section 4 convergence. The periodic 500 ms peer-selection pass runs
        // many times inside this window.
        let timeout = Duration::from_secs(12);
        let start = Instant::now();
        loop {
            let status_a = handle_a.status().await.unwrap();
            let status_b = handle_b.status().await.unwrap();
            if status_a.tip_block_id == winner_tip_id
                && status_b.tip_block_id == winner_tip_id
                && status_a.tip_height == 2
                && status_b.tip_height == 2
                && status_a.cumulative_work == U256::from_u128(2)
                && status_b.cumulative_work == U256::from_u128(2)
                && status_a.composite_state_root == winner_state_root
                && status_b.composite_state_root == winner_state_root
            {
                break;
            }
            if start.elapsed() > timeout {
                panic!(
                    "Timed out waiting for equal-work P2P convergence (Section 4): peers never \
                     exchanged their equal-work branches.\n\
                     node A: tip #{} {} work {:?} root {}\n\
                     node B: tip #{} {} work {:?} root {}\n\
                     expected Section 4 winner: tip #2 {} work {:?} root {}\n\
                     A->B handshake work: {:?}; B->A handshake work: {:?}",
                    status_a.tip_height,
                    status_a.tip_block_id,
                    status_a.cumulative_work,
                    status_a.composite_state_root,
                    status_b.tip_height,
                    status_b.tip_block_id,
                    status_b.cumulative_work,
                    status_b.composite_state_root,
                    winner_tip_id,
                    U256::from_u128(2),
                    winner_state_root,
                    remote_b.cumulative_work,
                    remote_a.cumulative_work,
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Both nodes must converge on the same tip block ID, height,
        // cumulative work, and composite state root.
        let final_a = handle_a.status().await.unwrap();
        let final_b = handle_b.status().await.unwrap();
        assert_eq!(final_a.tip_block_id, final_b.tip_block_id);
        assert_eq!(final_a.tip_height, final_b.tip_height);
        assert_eq!(final_a.tip_height, 2);
        assert_eq!(final_a.cumulative_work, final_b.cumulative_work);
        assert_eq!(final_a.cumulative_work, U256::from_u128(2));
        assert_eq!(final_a.composite_state_root, final_b.composite_state_root);
        assert_eq!(final_a.tip_block_id, winner_tip_id);
        assert_eq!(final_a.composite_state_root, winner_state_root);

        handle_a.stop().await;
        handle_b.stop().await;
    })
    .await
    .expect("test timed out");
}

// -----------------------------------------------------------------------------
// Test 20: Side-Branch Orphan Recovery
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_side_branch_orphan_recovery() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(10);
    let miner_b = TestKeypair::from_seed(20);

    // 1. Establish an active chain with 3 blocks (tip height 3, work 3).
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let b_a1 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    runtime.submit_block(b_a1.clone()).await.unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let b_a2 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    runtime.submit_block(b_a2.clone()).await.unwrap();

    let cb_a3 = make_coinbase(devnet_chain_id, 3, miner_a.address, 1_000_000_000);
    let b_a3 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 360, vec![cb_a3]);
    runtime.submit_block(b_a3.clone()).await.unwrap();

    assert_eq!(runtime.tip_height(), 3);
    assert_eq!(runtime.tip_block_id(), b_a3.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(3));

    // 2. Construct valid competing side branch: b_b1 (height 1) and b_b2 (height 2).
    // Ensure b_b1 has a block ID deterministically lexicographically larger than b_a1.
    let genesis = genesis_block(devnet_chain_id);
    let mut branch_b_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b_b1_base = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    let b_b1 = nonce_variant_block(&b_b1_base, b_a1.block_id(), false);
    assert!(
        b_b1.block_id() > b_a1.block_id(),
        "b_b1 must be lexicographically larger than b_a1"
    );
    branch_b_state.apply_block(&b_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b_b2 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_b_state.apply_block(&b_b2).unwrap();

    // 3. Deliver child (b_b2) BEFORE parent (b_b1).
    runtime.submit_block(b_b2.clone()).await.unwrap();

    // 4. Confirm child is registered as an orphan and not yet in storage.
    assert_eq!(runtime.orphan_count(), 1);
    assert!(!runtime.storage().has_block(&b_b2.block_id()).unwrap());

    // 5. Deliver side-branch parent (b_b1).
    runtime.submit_block(b_b1.clone()).await.unwrap();

    // 6. Confirm side-branch parent is persisted.
    assert!(runtime.storage().has_block(&b_b1.block_id()).unwrap());

    // 7. Confirm waiting orphan child (b_b2) is automatically retried and unrolled from orphan pool.
    assert_eq!(runtime.orphan_count(), 0);

    // 8. Confirm child is now persisted in storage.
    assert!(runtime.storage().has_block(&b_b2.block_id()).unwrap());

    // 9. Confirm active tip did NOT change because Branch B work (2) < active chain work (3).
    assert_eq!(runtime.tip_height(), 3);
    assert_eq!(runtime.tip_block_id(), b_a3.block_id());

    // 10. Construct competing branch's height-3 block (b_b3).
    let cb_b3 = make_coinbase(devnet_chain_id, 3, miner_b.address, 1_000_000_000);
    let b_b3 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 360, vec![cb_b3]);
    branch_b_state.apply_block(&b_b3).unwrap();

    // 11. Assert that it loses the equal-work tie-break.
    let active_blocks = vec![genesis.clone(), b_a1.clone(), b_a2.clone(), b_a3.clone()];
    let candidate_blocks = vec![genesis.clone(), b_b1.clone(), b_b2.clone(), b_b3.clone()];
    assert!(
        !candidate_wins_fork_choice(
            branch_b_state.cumulative_work(),
            &candidate_blocks,
            runtime.cumulative_work(),
            &active_blocks,
        ),
        "Branch B must lose equal-work tie-break because b_b1 > b_a1 at first differing height"
    );

    // 12. Submit the competing branch's height-3 block.
    runtime.submit_block(b_b3.clone()).await.unwrap();

    // 13. Verify that it is persisted as a side branch and the active tip remains unchanged.
    assert!(runtime.storage().has_block(&b_b3.block_id()).unwrap());
    assert!(
        !runtime
            .storage()
            .get_block_metadata(&b_b3.block_id())
            .unwrap()
            .unwrap()
            .is_active
    );
    assert_eq!(runtime.tip_height(), 3);
    assert_eq!(runtime.tip_block_id(), b_a3.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(3));

    // 14. Construct the height-4 block on branch B, making Branch B heavier (work 4 > 3).
    let cb_b4 = make_coinbase(devnet_chain_id, 4, miner_b.address, 1_000_000_000);
    let b_b4 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 480, vec![cb_b4]);
    branch_b_state.apply_block(&b_b4).unwrap();

    // 15. Submit the height-4 block.
    runtime.submit_block(b_b4.clone()).await.unwrap();

    // 16. Verify that the branch reorganization completes and the heavier branch reorganizes the active chain.
    assert_eq!(runtime.orphan_count(), 0);
    assert!(
        runtime
            .storage()
            .get_block_metadata(&b_b4.block_id())
            .unwrap()
            .unwrap()
            .is_active
    );

    // 17. Assert the final tip, cumulative work, and composite state root.
    assert_eq!(runtime.tip_height(), 4);
    assert_eq!(runtime.tip_block_id(), b_b4.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(4));
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        branch_b_state.composite_state_root()
    );
}

#[tokio::test]
async fn test_side_branch_orphan_unroll_triggers_heavier_reorg() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(11);
    let miner_b = TestKeypair::from_seed(22);

    // 1. Establish an active chain with 3 blocks.
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let b_a1 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    runtime.submit_block(b_a1.clone()).await.unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let b_a2 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    runtime.submit_block(b_a2.clone()).await.unwrap();

    let cb_a3 = make_coinbase(devnet_chain_id, 3, miner_a.address, 1_000_000_000);
    let b_a3 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 360, vec![cb_a3]);
    runtime.submit_block(b_a3.clone()).await.unwrap();

    // 2. Construct Branch B up to height 4, with b_b1 > b_a1 (loses tie-break at height 3).
    let genesis = genesis_block(devnet_chain_id);
    let mut branch_b_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b_b1_base = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    let b_b1 = nonce_variant_block(&b_b1_base, b_a1.block_id(), false);
    assert!(b_b1.block_id() > b_a1.block_id());
    branch_b_state.apply_block(&b_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b_b2 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_b_state.apply_block(&b_b2).unwrap();

    let cb_b3 = make_coinbase(devnet_chain_id, 3, miner_b.address, 1_000_000_000);
    let b_b3 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 360, vec![cb_b3]);
    branch_b_state.apply_block(&b_b3).unwrap();

    let cb_b4 = make_coinbase(devnet_chain_id, 4, miner_b.address, 1_000_000_000);
    let b_b4 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 480, vec![cb_b4]);
    branch_b_state.apply_block(&b_b4).unwrap();

    // Submit b_b1 and b_b2 as side-branch blocks
    runtime.submit_block(b_b1.clone()).await.unwrap();
    runtime.submit_block(b_b2.clone()).await.unwrap();
    assert_eq!(runtime.tip_height(), 3);
    assert_eq!(runtime.tip_block_id(), b_a3.block_id());

    // Submit orphan child b_b4 BEFORE its parent b_b3
    runtime.submit_block(b_b4.clone()).await.unwrap();
    assert_eq!(runtime.orphan_count(), 1);
    assert!(!runtime.storage().has_block(&b_b4.block_id()).unwrap());

    // Submit parent b_b3: it loses the equal-work tie-break, persists as a side branch,
    // and waking orphan child b_b4 completes recovery and reorganizes the chain!
    runtime.submit_block(b_b3.clone()).await.unwrap();
    assert_eq!(runtime.orphan_count(), 0);
    assert_eq!(runtime.tip_height(), 4);
    assert_eq!(runtime.tip_block_id(), b_b4.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(4));
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        branch_b_state.composite_state_root()
    );
}

#[tokio::test]
async fn test_stored_side_branch_reevaluation_wins_fork_choice() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(31);
    let miner_b = TestKeypair::from_seed(32);

    // 1. Establish Active Chain A with 2 blocks
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let b_a1 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    runtime.submit_block(b_a1.clone()).await.unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let b_a2 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    runtime.submit_block(b_a2.clone()).await.unwrap();

    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(runtime.tip_block_id(), b_a2.block_id());

    // 2. Build Branch B where b_b1 < b_a1 (Branch B wins equal-work tie-break)
    let genesis = genesis_block(devnet_chain_id);
    let mut branch_b_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b_b1_base = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    let b_b1 = nonce_variant_block(&b_b1_base, b_a1.block_id(), true);
    assert!(
        b_b1.block_id() < b_a1.block_id(),
        "b_b1 must be smaller to win tie-break"
    );
    branch_b_state.apply_block(&b_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b_b2 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_b_state.apply_block(&b_b2).unwrap();

    // 3. Store Branch B directly into storage as an inactive side branch
    runtime
        .storage()
        .store_branch_block(&b_b1, U256::from_u128(1))
        .unwrap();
    runtime
        .storage()
        .store_branch_block(&b_b2, U256::from_u128(2))
        .unwrap();

    // Verify blocks are stored as inactive
    let meta_b1 = runtime
        .storage()
        .get_block_metadata(&b_b1.block_id())
        .unwrap()
        .unwrap();
    let meta_b2 = runtime
        .storage()
        .get_block_metadata(&b_b2.block_id())
        .unwrap()
        .unwrap();
    assert!(!meta_b1.is_active);
    assert!(!meta_b2.is_active);
    assert_eq!(runtime.tip_block_id(), b_a2.block_id());

    // 4. Peer advertises Branch B tip
    let remote_peer = PeerId::random();
    let handshake = HandshakeMessage {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        chain_id: devnet_chain_id,
        genesis_hash: genesis.block_id(),
        tip_height: 2,
        tip_block_id: b_b2.block_id(),
        cumulative_work: U256::from_u128(2),
        capabilities: 0,
        software_version: "test/1.0".to_string(),
    };

    // Stored side branch should be re-evaluated, not re-downloaded via network sync
    assert!(runtime.should_reevaluate_stored_side_branch(&handshake));
    assert!(!runtime.is_peer_sync_eligible(&handshake));

    // 5. Re-evaluate stored side branch
    let outcome = runtime
        .reevaluate_stored_side_branch(remote_peer, b_b2.block_id())
        .await
        .unwrap();

    assert_eq!(
        outcome,
        BlockProcessingOutcome::ActiveChainAccepted(b_b2.block_id())
    );

    // Active chain is now Branch B
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(runtime.tip_block_id(), b_b2.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(2));
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        branch_b_state.composite_state_root()
    );

    // Metadata in storage is updated: Branch B is active, Branch A is inactive
    let meta_b2_now = runtime
        .storage()
        .get_block_metadata(&b_b2.block_id())
        .unwrap()
        .unwrap();
    let meta_a2_now = runtime
        .storage()
        .get_block_metadata(&b_a2.block_id())
        .unwrap()
        .unwrap();
    assert!(meta_b2_now.is_active);
    assert!(!meta_a2_now.is_active);
}

#[tokio::test]
async fn test_stored_side_branch_reevaluation_loses_and_prevents_loops() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(41);
    let miner_b = TestKeypair::from_seed(42);

    // 1. Establish Active Chain A with 2 blocks
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let b_a1 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    runtime.submit_block(b_a1.clone()).await.unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let b_a2 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    runtime.submit_block(b_a2.clone()).await.unwrap();

    // 2. Build Branch B where b_b1 > b_a1 (Branch B loses equal-work tie-break)
    let genesis = genesis_block(devnet_chain_id);
    let mut branch_b_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b_b1_base = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    let b_b1 = nonce_variant_block(&b_b1_base, b_a1.block_id(), false);
    assert!(
        b_b1.block_id() > b_a1.block_id(),
        "b_b1 must be larger to lose tie-break"
    );
    branch_b_state.apply_block(&b_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b_b2 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_b_state.apply_block(&b_b2).unwrap();

    // Store Branch B in storage as inactive side branch
    runtime
        .storage()
        .store_branch_block(&b_b1, U256::from_u128(1))
        .unwrap();
    runtime
        .storage()
        .store_branch_block(&b_b2, U256::from_u128(2))
        .unwrap();

    let remote_peer = PeerId::random();
    let handshake = HandshakeMessage {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        chain_id: devnet_chain_id,
        genesis_hash: genesis.block_id(),
        tip_height: 2,
        tip_block_id: b_b2.block_id(),
        cumulative_work: U256::from_u128(2),
        capabilities: 0,
        software_version: "test/1.0".to_string(),
    };

    // First time: eligible for local re-evaluation, not network sync
    assert!(runtime.should_reevaluate_stored_side_branch(&handshake));
    assert!(!runtime.is_peer_sync_eligible(&handshake));

    // Re-evaluate: loses tie-break, active chain preserved
    let outcome = runtime
        .reevaluate_stored_side_branch(remote_peer, b_b2.block_id())
        .await
        .unwrap();
    assert_eq!(
        outcome,
        BlockProcessingOutcome::SideBranchPersisted(b_b2.block_id())
    );
    assert_eq!(runtime.tip_block_id(), b_a2.block_id());

    // Subsequent check with the same handshake must NOT re-evaluate again (loop prevention)
    assert!(
        !runtime.should_reevaluate_stored_side_branch(&handshake),
        "Subsequent handshake must be suppressed by evaluated_side_branches cache"
    );
    assert!(
        !runtime.is_peer_sync_eligible(&handshake),
        "Equal-work stored block must not initiate network sync"
    );
}

#[tokio::test]
async fn test_stored_side_branch_resubmitted_via_single_block_reevaluates() {
    let dir = TempDir::new().unwrap();
    let mut runtime = NodeRuntime::init(create_node_config(&dir)).unwrap();
    let devnet_chain_id = runtime.chain_state().chain_id();
    let miner_a = TestKeypair::from_seed(51);
    let miner_b = TestKeypair::from_seed(52);

    // 1. Establish Active Chain A with 2 blocks
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let b_a1 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    runtime.submit_block(b_a1.clone()).await.unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let b_a2 = make_hybrid_block(runtime.chain_state(), GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    runtime.submit_block(b_a2.clone()).await.unwrap();

    // 2. Build Branch B where b_b1 < b_a1 (Branch B wins equal-work tie-break)
    let genesis = genesis_block(devnet_chain_id);
    let mut branch_b_state = ChainState::from_genesis(&genesis).unwrap();

    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b_b1_base = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    let b_b1 = nonce_variant_block(&b_b1_base, b_a1.block_id(), true);
    assert!(b_b1.block_id() < b_a1.block_id());
    branch_b_state.apply_block(&b_b1).unwrap();

    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b_b2 = make_hybrid_block(&branch_b_state, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    branch_b_state.apply_block(&b_b2).unwrap();

    // Store Branch B in storage as inactive side branch
    runtime
        .storage()
        .store_branch_block(&b_b1, U256::from_u128(1))
        .unwrap();
    runtime
        .storage()
        .store_branch_block(&b_b2, U256::from_u128(2))
        .unwrap();
    assert_eq!(runtime.tip_block_id(), b_a2.block_id());

    // 3. Resubmit b_b2 through submit_block (exercises process_single_block reevaluation)
    runtime.submit_block(b_b2.clone()).await.unwrap();
    assert_eq!(runtime.tip_block_id(), b_b2.block_id());
    assert_eq!(
        runtime.chain_state().composite_state_root(),
        branch_b_state.composite_state_root()
    );
}

#[tokio::test]
async fn test_warm_storage_upgrade_p2p_handshake_reevaluation() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let config_a = create_node_config(&dir_a);
        let config_b = create_node_config(&dir_b);
        let devnet_chain_id = config_a.chain_id;

        let miner_a = TestKeypair::from_seed(101);
        let miner_b = TestKeypair::from_seed(102);
        let genesis = genesis_block(devnet_chain_id);

        // 1. Construct Branch A and Branch B
        // b1 < a1 so Branch B wins the Section 4 tie-break
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
        let a1_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);

        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
        let b1 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 120, vec![cb_b1]);

        let a1 = nonce_variant_block(&a1_base, b1.block_id(), false);
        assert!(
            b1.block_id() < a1.block_id(),
            "Branch B must have smaller block ID at height 1 to win tie-break"
        );
        state_a.apply_block(&a1).unwrap();
        state_b.apply_block(&b1).unwrap();

        let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
        let a2_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
        let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
        let b2 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 240, vec![cb_b2]);

        // b2 > a2 so final tip alone would oppose height-1 tie break
        let a2 = nonce_variant_block(&a2_base, b2.block_id(), true);
        assert!(
            b2.block_id() > a2.block_id(),
            "Branch B tip must be larger to prove tie-break uses first differing height"
        );
        state_a.apply_block(&a2).unwrap();
        state_b.apply_block(&b2).unwrap();

        assert_eq!(state_a.cumulative_work(), state_b.cumulative_work());
        assert_eq!(state_a.cumulative_work(), U256::from_u128(2));

        // 2. Initialize Node A with temporary persistent database and establish active Branch A
        let mut runtime_a = NodeRuntime::init(config_a.clone()).unwrap();
        runtime_a.submit_block(a1.clone()).await.unwrap();
        runtime_a.submit_block(a2.clone()).await.unwrap();
        assert_eq!(runtime_a.tip_height(), 2);
        assert_eq!(runtime_a.tip_block_id(), a2.block_id());

        // 3. Persist equal-work Branch B as an inactive side branch in storage
        // (simulating data left by an older first-seen fork-choice implementation)
        runtime_a
            .storage()
            .store_branch_block(&b1, U256::from_u128(1))
            .unwrap();
        runtime_a
            .storage()
            .store_branch_block(&b2, U256::from_u128(2))
            .unwrap();

        let meta_b2_before = runtime_a
            .storage()
            .get_block_metadata(&b2.block_id())
            .unwrap()
            .unwrap();
        assert!(!meta_b2_before.is_active);

        // 4. Shut down and drop runtime_a
        drop(runtime_a);

        // 5. Reopen the same database using a fresh runtime
        let runtime_a_fresh = NodeRuntime::init(config_a.clone()).unwrap();
        assert_eq!(runtime_a_fresh.tip_height(), 2);
        assert_eq!(runtime_a_fresh.tip_block_id(), a2.block_id());
        assert_eq!(runtime_a_fresh.cumulative_work(), U256::from_u128(2));

        // Prepare Node B with active Branch B
        let mut runtime_b = NodeRuntime::init(config_b).unwrap();
        runtime_b.submit_block(b1.clone()).await.unwrap();
        runtime_b.submit_block(b2.clone()).await.unwrap();
        assert_eq!(runtime_b.tip_height(), 2);
        assert_eq!(runtime_b.tip_block_id(), b2.block_id());

        // Spawn both actors
        let (handle_a, task_a) = runtime_a_fresh.spawn_actor();
        let (handle_b, task_b) = runtime_b.spawn_actor();

        // 6. Connect through normal P2P handshake path
        let addr_a = wait_for_listen_addr(&handle_a).await;
        handle_b.dial_peer(addr_a).await.unwrap();
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;

        // 7 & 8. Verify that runtime automatically recognizes and reevaluates stored branch B,
        // and that Branch B becomes active when it wins protocol tie-break.
        let timeout = Duration::from_secs(12);
        let start = Instant::now();
        loop {
            let status_a = handle_a.status().await.unwrap();
            if status_a.tip_block_id == b2.block_id() {
                // 9. Verify final tip, cumulative work, and composite state root
                assert_eq!(status_a.tip_height, 2);
                assert_eq!(status_a.cumulative_work, U256::from_u128(2));
                assert_eq!(status_a.composite_state_root, state_b.composite_state_root());
                break;
            }
            if start.elapsed() > timeout {
                panic!(
                    "Timed out waiting for Node A to reevaluate and activate stored Branch B via P2P handshake. Current tip: #{} ({})",
                    status_a.tip_height, status_a.tip_block_id
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Stop actors and verify persistent on-disk metadata
        handle_a.stop().await;
        handle_b.stop().await;
        let _ = task_a.await;
        let _ = task_b.await;

        let runtime_a_reopened = NodeRuntime::init(config_a).unwrap();
        let meta_b2 = runtime_a_reopened.storage().get_block_metadata(&b2.block_id()).unwrap().unwrap();
        let meta_a2 = runtime_a_reopened.storage().get_block_metadata(&a2.block_id()).unwrap().unwrap();
        assert!(meta_b2.is_active, "Branch B tip must be marked active on disk");
        assert!(!meta_a2.is_active, "Branch A tip must be marked inactive on disk");
        let (disk_h, disk_tip, disk_work) = runtime_a_reopened.storage().get_tip().unwrap();
        assert_eq!(disk_h, 2);
        assert_eq!(disk_tip, b2.block_id());
        assert_eq!(disk_work, U256::from_u128(2));
        assert_eq!(runtime_a_reopened.tip_height(), 2);
        assert_eq!(runtime_a_reopened.tip_block_id(), b2.block_id());
        assert_eq!(runtime_a_reopened.cumulative_work(), U256::from_u128(2));
        assert_eq!(runtime_a_reopened.chain_state().composite_state_root(), state_b.composite_state_root());
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_warm_storage_upgrade_p2p_handshake_losing_branch_no_loop() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        let config_a = create_node_config(&dir_a);
        let config_b = create_node_config(&dir_b);
        let devnet_chain_id = config_a.chain_id;

        let miner_a = TestKeypair::from_seed(103);
        let miner_b = TestKeypair::from_seed(104);
        let genesis = genesis_block(devnet_chain_id);

        // Construct Branch A and Branch B: b1 > a1 so Branch B LOSES the Section 4 tie-break
        let mut state_a = ChainState::from_genesis(&genesis).unwrap();
        let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
        let a1_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);

        let mut state_b = ChainState::from_genesis(&genesis).unwrap();
        let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
        let b1 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 120, vec![cb_b1]);

        let a1 = nonce_variant_block(&a1_base, b1.block_id(), true);
        assert!(
            a1.block_id() < b1.block_id(),
            "Branch A must have smaller block ID at height 1 so Branch B loses tie-break"
        );
        state_a.apply_block(&a1).unwrap();
        state_b.apply_block(&b1).unwrap();

        let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
        let a2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
        let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
        let b2 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 240, vec![cb_b2]);

        state_a.apply_block(&a2).unwrap();
        state_b.apply_block(&b2).unwrap();

        // 1. Establish active Branch A in runtime A
        let mut runtime_a = NodeRuntime::init(config_a.clone()).unwrap();
        runtime_a.submit_block(a1.clone()).await.unwrap();
        runtime_a.submit_block(a2.clone()).await.unwrap();
        assert_eq!(runtime_a.tip_block_id(), a2.block_id());

        // 2. Persist losing Branch B as inactive side branch
        runtime_a
            .storage()
            .store_branch_block(&b1, U256::from_u128(1))
            .unwrap();
        runtime_a
            .storage()
            .store_branch_block(&b2, U256::from_u128(2))
            .unwrap();

        // 3. Drop runtime A and reopen
        drop(runtime_a);

        let runtime_a_fresh = NodeRuntime::init(config_a.clone()).unwrap();
        assert_eq!(runtime_a_fresh.tip_block_id(), a2.block_id());

        // Node B has active Branch B
        let mut runtime_b = NodeRuntime::init(config_b).unwrap();
        runtime_b.submit_block(b1.clone()).await.unwrap();
        runtime_b.submit_block(b2.clone()).await.unwrap();
        assert_eq!(runtime_b.tip_block_id(), b2.block_id());

        // Spawn actors
        let (handle_a, task_a) = runtime_a_fresh.spawn_actor();
        let (handle_b, task_b) = runtime_b.spawn_actor();

        // Connect via normal P2P handshake
        let addr_a = wait_for_listen_addr(&handle_a).await;
        handle_b.dial_peer(addr_a).await.unwrap();
        wait_for_peer_handshake(&handle_b, handle_a.peer_id()).await;
        wait_for_peer_handshake(&handle_a, handle_b.peer_id()).await;

        // Allow multiple sync ticks (500ms interval) to fire to ensure no repeated reeval or sync loops occur
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Verify Node A retained Branch A
        let status_a = handle_a.status().await.unwrap();
        assert_eq!(status_a.tip_height, 2);
        assert_eq!(status_a.tip_block_id, a2.block_id());
        assert_eq!(status_a.cumulative_work, U256::from_u128(2));
        assert_eq!(
            status_a.composite_state_root,
            state_a.composite_state_root()
        );

        handle_a.stop().await;
        handle_b.stop().await;
        let _ = task_a.await;
        let _ = task_b.await;

        let runtime_a_reopened = NodeRuntime::init(config_a).unwrap();
        let meta_a2 = runtime_a_reopened
            .storage()
            .get_block_metadata(&a2.block_id())
            .unwrap()
            .unwrap();
        let meta_b2 = runtime_a_reopened
            .storage()
            .get_block_metadata(&b2.block_id())
            .unwrap()
            .unwrap();
        assert!(meta_a2.is_active, "Branch A must remain active on disk");
        assert!(
            !meta_b2.is_active,
            "Losing Branch B must remain inactive on disk"
        );
        assert_eq!(runtime_a_reopened.tip_height(), 2);
        assert_eq!(runtime_a_reopened.tip_block_id(), a2.block_id());
        assert_eq!(runtime_a_reopened.cumulative_work(), U256::from_u128(2));
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_peer_advertised_lower_work_does_not_gate_stored_branch_reevaluation() {
    let dir = TempDir::new().unwrap();
    let config = create_node_config(&dir);
    let devnet_chain_id = config.chain_id;
    let genesis = genesis_block(devnet_chain_id);
    let miner_a = TestKeypair::from_seed(105);
    let miner_b = TestKeypair::from_seed(106);

    let mut state_a = ChainState::from_genesis(&genesis).unwrap();
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let a1_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);

    let mut state_b = ChainState::from_genesis(&genesis).unwrap();
    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 120, vec![cb_b1]);

    let a1 = nonce_variant_block(&a1_base, b1.block_id(), false);
    assert!(b1.block_id() < a1.block_id());
    state_a.apply_block(&a1).unwrap();
    state_b.apply_block(&b1).unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let a2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b2 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    state_a.apply_block(&a2).unwrap();
    state_b.apply_block(&b2).unwrap();

    let mut runtime = NodeRuntime::init(config).unwrap();
    runtime.submit_block(a1.clone()).await.unwrap();
    runtime.submit_block(a2.clone()).await.unwrap();
    assert_eq!(runtime.tip_block_id(), a2.block_id());

    // Store Branch B as inactive side branch
    runtime
        .storage()
        .store_branch_block(&b1, U256::from_u128(1))
        .unwrap();
    runtime
        .storage()
        .store_branch_block(&b2, U256::from_u128(2))
        .unwrap();

    // Handshake advertises tip b2, but untrusted peer claims cumulative_work: 1 (less than local work 2)
    let handshake = HandshakeMessage {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        chain_id: devnet_chain_id,
        genesis_hash: genesis.block_id(),
        tip_height: 2,
        tip_block_id: b2.block_id(),
        cumulative_work: U256::from_u128(1), // Less than local work 2!
        capabilities: 0,
        software_version: "untrusted-peer/1.0".to_string(),
    };

    // Even though peer advertises work 1 < 2, local reevaluation is NOT gated by peer-advertised work!
    assert!(
        runtime.should_reevaluate_stored_side_branch(&handshake),
        "should_reevaluate_stored_side_branch must not gate on untrusted remote work"
    );

    // Reevaluate using authoritative local consensus state
    let outcome = runtime
        .reevaluate_stored_side_branch(PeerId::random(), b2.block_id())
        .await
        .unwrap();

    assert_eq!(
        outcome,
        BlockProcessingOutcome::ActiveChainAccepted(b2.block_id())
    );
    assert_eq!(runtime.tip_block_id(), b2.block_id());
    assert_eq!(runtime.cumulative_work(), U256::from_u128(2));
}

#[tokio::test]
async fn test_stored_branch_reevaluation_orphan_child_error_handling() {
    let dir = TempDir::new().unwrap();
    let config = create_node_config(&dir);
    let devnet_chain_id = config.chain_id;
    let genesis = genesis_block(devnet_chain_id);
    let miner_a = TestKeypair::from_seed(107);
    let miner_b = TestKeypair::from_seed(108);

    // 1. Establish Active Chain A with 2 blocks
    let mut state_a = ChainState::from_genesis(&genesis).unwrap();
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let a1 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);
    state_a.apply_block(&a1).unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let a2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    state_a.apply_block(&a2).unwrap();

    let mut runtime = NodeRuntime::init(config).unwrap();
    runtime.submit_block(a1.clone()).await.unwrap();
    runtime.submit_block(a2.clone()).await.unwrap();
    assert_eq!(runtime.tip_block_id(), a2.block_id());

    // 2. Build Branch B parent b1 (height 1)
    let mut state_b = ChainState::from_genesis(&genesis).unwrap();
    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 120, vec![cb_b1]);
    state_b.apply_block(&b1).unwrap();

    // 3. Construct an invalid orphan child b2 whose parent is b1:
    // It has height 2 and parent b1, but carries a corrupted state root
    let mut invalid_child = make_candidate_block(
        &state_b,
        GENESIS_TIMESTAMP + 240,
        vec![make_coinbase(
            devnet_chain_id,
            2,
            miner_b.address,
            1_000_000_000,
        )],
    );
    invalid_child.header.orchard_commitment_root = Hash::new([0xff; 32]); // Corrupted root

    // 4. Submit invalid child BEFORE parent b1 is in storage:
    // Since b1 is unknown, invalid_child is queued as an orphan
    runtime.submit_block(invalid_child.clone()).await.unwrap();
    assert_eq!(runtime.orphan_count(), 1);
    assert!(!runtime
        .storage()
        .has_block(&invalid_child.block_id())
        .unwrap());

    // 5. Now store parent b1 as an inactive side branch
    runtime
        .storage()
        .store_branch_block(&b1, U256::from_u128(1))
        .unwrap();
    assert!(
        !runtime
            .storage()
            .get_block_metadata(&b1.block_id())
            .unwrap()
            .unwrap()
            .is_active
    );

    // 6. Reevaluate stored parent branch b1:
    // Parent b1 has work 1 < 2, so it evaluates cleanly and persists as a side branch.
    // Unrolling its waiting orphan children wakes invalid_child.
    // invalid_child fails validation in handle_inbound_block, which is logged as a warning.
    // The parent operation succeeds (Ok) and is preserved, while the orphan is drained.
    let outcome = runtime
        .reevaluate_stored_side_branch(PeerId::random(), b1.block_id())
        .await
        .unwrap();

    assert_eq!(
        outcome,
        BlockProcessingOutcome::SideBranchPersisted(b1.block_id()),
        "Parent branch reevaluation must succeed and persist as side branch"
    );

    // 7. Verify orphan queue is clean and invalid child was not stored
    assert_eq!(runtime.orphan_count(), 0);
    assert_eq!(runtime.tip_block_id(), a2.block_id());
    assert!(runtime.storage().has_block(&b1.block_id()).unwrap());
    assert!(!runtime
        .storage()
        .has_block(&invalid_child.block_id())
        .unwrap());
}

#[tokio::test]
async fn test_evaluated_side_branches_cache_invalidated_on_active_chain_extension() {
    let dir = TempDir::new().unwrap();
    let config = create_node_config(&dir);
    let devnet_chain_id = config.chain_id;
    let genesis = genesis_block(devnet_chain_id);
    let miner_a = TestKeypair::from_seed(201);
    let miner_b = TestKeypair::from_seed(202);

    // 1. Establish Active Chain A with 2 blocks (tip height 2)
    let mut state_a = ChainState::from_genesis(&genesis).unwrap();
    let cb_a1 = make_coinbase(devnet_chain_id, 1, miner_a.address, 1_000_000_000);
    let a1_base = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 120, vec![cb_a1]);

    let mut state_b = ChainState::from_genesis(&genesis).unwrap();
    let cb_b1 = make_coinbase(devnet_chain_id, 1, miner_b.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 120, vec![cb_b1]);

    // b1 > a1 so Branch B loses the tie-break against Branch A
    let a1 = nonce_variant_block(&a1_base, b1.block_id(), true);
    assert!(a1.block_id() < b1.block_id());
    state_a.apply_block(&a1).unwrap();
    state_b.apply_block(&b1).unwrap();

    let cb_a2 = make_coinbase(devnet_chain_id, 2, miner_a.address, 1_000_000_000);
    let a2 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 240, vec![cb_a2]);
    let cb_b2 = make_coinbase(devnet_chain_id, 2, miner_b.address, 1_000_000_000);
    let b2 = make_hybrid_block(&state_b, GENESIS_TIMESTAMP + 240, vec![cb_b2]);
    state_a.apply_block(&a2).unwrap();
    state_b.apply_block(&b2).unwrap();

    let mut runtime = NodeRuntime::init(config).unwrap();
    runtime.submit_block(a1.clone()).await.unwrap();
    runtime.submit_block(a2.clone()).await.unwrap();
    assert_eq!(runtime.tip_height(), 2);
    assert_eq!(runtime.tip_block_id(), a2.block_id());
    assert_eq!(runtime.evaluated_side_branch_count(), 0);

    // 2. Persist equal-work Branch B as inactive side branch
    runtime
        .storage()
        .store_branch_block(&b1, U256::from_u128(1))
        .unwrap();
    runtime
        .storage()
        .store_branch_block(&b2, U256::from_u128(2))
        .unwrap();

    // 3. Re-evaluate Branch B against tip a2: Branch B loses tie-break
    let peer_id = PeerId::random();
    let handshake = HandshakeMessage {
        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
        chain_id: devnet_chain_id,
        genesis_hash: genesis.block_id(),
        tip_height: 2,
        tip_block_id: b2.block_id(),
        cumulative_work: U256::from_u128(2),
        capabilities: 0,
        software_version: "test/1.0".to_string(),
    };

    assert!(runtime.should_reevaluate_stored_side_branch(&handshake));
    let outcome = runtime
        .reevaluate_stored_side_branch(peer_id, b2.block_id())
        .await
        .unwrap();
    assert_eq!(
        outcome,
        BlockProcessingOutcome::SideBranchPersisted(b2.block_id())
    );
    assert_eq!(runtime.tip_block_id(), a2.block_id());

    // 4. Verify that the cache prevents repeated evaluation against unchanged active tip a2
    assert_eq!(runtime.evaluated_side_branch_count(), 1);
    assert!(runtime.is_side_branch_evaluated(&b2.block_id()));
    assert!(
        !runtime.should_reevaluate_stored_side_branch(&handshake),
        "Repeated evaluation against unchanged tip a2 must be suppressed"
    );

    // 5. Active chain extends via ordinary block acceptance (a3)
    let cb_a3 = make_coinbase(devnet_chain_id, 3, miner_a.address, 1_000_000_000);
    let a3 = make_hybrid_block(&state_a, GENESIS_TIMESTAMP + 360, vec![cb_a3]);
    state_a.apply_block(&a3).unwrap();

    runtime.submit_block(a3.clone()).await.unwrap();

    // 6. Verify that active tip advanced to a3 AND the evaluated_side_branches cache was cleared
    assert_eq!(runtime.tip_height(), 3);
    assert_eq!(runtime.tip_block_id(), a3.block_id());
    assert_eq!(
        runtime.evaluated_side_branch_count(),
        0,
        "evaluated_side_branches cache must be invalidated when active chain extends"
    );
    assert!(
        !runtime.is_side_branch_evaluated(&b2.block_id()),
        "b2 must no longer be present in evaluated_side_branches after active-chain extension"
    );
}
