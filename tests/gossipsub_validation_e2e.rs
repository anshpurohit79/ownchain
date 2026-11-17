//! Focused E2E regression tests for SEC-P2P-002 (Gossipsub message validation,
//! forwarding suppression before/on rejection, header block_id anti-poisoning,
//! MempoolFull retryability, and reorganization tx re-admission).

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use libp2p::core::Multiaddr;
use libp2p::gossipsub::{
    Behaviour as Gossipsub, ConfigBuilder as GossipsubConfigBuilder, Event as GossipsubEvent,
    IdentTopic, MessageAuthenticity, ValidationMode,
};
use libp2p::identity::{Keypair, PeerId};
use libp2p::noise;
use libp2p::request_response::{
    Behaviour as RequestResponse, Config as ReqRespConfig, Event as ReqRespEvent,
    Message as ReqRespMessage, ProtocolSupport,
};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{tcp, yamux, StreamProtocol, Swarm};
use tempfile::TempDir;

use ownchain::account::derive_address;
use ownchain::block::Block;
use ownchain::chain::ChainState;
use ownchain::difficulty::U256;
use ownchain::genesis::{genesis_block, DEVNET, GENESIS_TIMESTAMP};
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::mempool::MempoolConfig;
use ownchain::merkle;
use ownchain::node::{NodeConfig, NodeHandle, NodeRuntime};
use ownchain::orchard_root::empty_commitment_root;
use ownchain::p2p::framing::encode_frame;
use ownchain::p2p::{
    HandshakeMessage, SyncCodec, SyncRequest, SyncResponse, HANDSHAKE_PROTOCOL_VERSION,
    SYNC_PROTOCOL_ID,
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

fn create_node_config(dir: &TempDir) -> NodeConfig {
    let mut cfg = NodeConfig::default_devnet(dir.path().to_path_buf());
    cfg.listen_addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    cfg
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

fn make_hybrid_block(state: &ChainState, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let parent = state.tip().expect("must have parent");
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    let tx_root = merkle::tx_root(&ids);
    let diff = state.expected_difficulty_for_next_block().unwrap_or(1);

    let mut block = Block {
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
    block.header.orchard_commitment_root = state
        .simulate_candidate_state_root(&block)
        .expect("simulation must succeed");
    block
}

#[derive(NetworkBehaviour)]
struct HarnessPeerBehaviour {
    gossipsub: Gossipsub,
    request_response: RequestResponse<SyncCodec>,
}

fn spawn_harness_peer(
    keypair: Keypair,
    authenticity: MessageAuthenticity,
) -> (Swarm<HarnessPeerBehaviour>, IdentTopic, IdentTopic) {
    let blocks_topic = IdentTopic::new(format!("/ownchain/{DEVNET}/blocks/v1"));
    let txs_topic = IdentTopic::new(format!("/ownchain/{DEVNET}/txs/v1"));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| {
            let gs_cfg = GossipsubConfigBuilder::default()
                .validation_mode(ValidationMode::Permissive)
                .heartbeat_interval(Duration::from_millis(500))
                .max_transmit_size(2_100_000)
                .build()
                .unwrap();
            let mut gossipsub = Gossipsub::new(authenticity, gs_cfg).unwrap();
            gossipsub.subscribe(&blocks_topic).unwrap();
            gossipsub.subscribe(&txs_topic).unwrap();

            let protocols = [(StreamProtocol::new(SYNC_PROTOCOL_ID), ProtocolSupport::Full)];
            let request_response =
                RequestResponse::with_codec(SyncCodec, protocols, ReqRespConfig::default());
            Ok(HarnessPeerBehaviour {
                gossipsub,
                request_response,
            })
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    (swarm, blocks_topic, txs_topic)
}

async fn wait_for_node_listen_addr(node: &NodeHandle) -> Multiaddr {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(addrs) = node.get_listen_addrs().await {
                if let Some(a) = addrs.into_iter().next() {
                    return a;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node must expose listen addr")
}

async fn pump_until_mesh_ready(
    swarm: &mut Swarm<HarnessPeerBehaviour>,
    target_peer: PeerId,
    blocks_topic: &IdentTopic,
    txs_topic: &IdentTopic,
    chain_id: Hash,
    genesis_hash: Hash,
) {
    let b_hash = blocks_topic.hash();
    let t_hash = txs_topic.hash();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let b_ready = swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&b_hash)
            .any(|p| *p == target_peer);
        let t_ready = swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&t_hash)
            .any(|p| *p == target_peer);
        if b_ready && t_ready {
            return;
        }
        tokio::select! {
            ev = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(HarnessPeerBehaviourEvent::RequestResponse(
                    ReqRespEvent::Message {
                        message: ReqRespMessage::Request { request: SyncRequest::Handshake(_), channel, .. },
                        ..
                    }
                )) = ev {
                    let hs = HandshakeMessage {
                        protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                        chain_id,
                        genesis_hash,
                        tip_height: 0,
                        tip_block_id: genesis_hash,
                        cumulative_work: U256::zero(),
                        capabilities: 0,
                        software_version: "harness/1".into(),
                    };
                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::Handshake(hs));
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    panic!("Timed out waiting for mesh readiness with peer {target_peer}");
}

async fn drive_swarms_until<F>(
    swarm_a: &mut Swarm<HarnessPeerBehaviour>,
    swarm_c: &mut Swarm<HarnessPeerBehaviour>,
    mut on_c_gossip: F,
    timeout: Duration,
) -> bool
where
    F: FnMut(PeerId, Option<PeerId>, libp2p::gossipsub::TopicHash, Vec<u8>) -> bool,
{
    let res = tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                _ = swarm_a.select_next_some() => {}
                ev_c = swarm_c.select_next_some() => {
                    if let SwarmEvent::Behaviour(HarnessPeerBehaviourEvent::Gossipsub(
                        GossipsubEvent::Message { propagation_source, message, .. }
                    )) = ev_c {
                        if on_c_gossip(propagation_source, message.source, message.topic, message.data) {
                            return true;
                        }
                    }
                }
            }
        }
    })
    .await;
    res.unwrap_or(false)
}

#[tokio::test]
async fn test_e2e_line_topology_valid_block_and_tx_forwarded_without_rebroadcast() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir_b = TempDir::new().unwrap();
        let (node_b, _tb) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();
        let addr_b = wait_for_node_listen_addr(&node_b).await;
        let peer_b = node_b.peer_id();

        let cid = hash::chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let ghash = genesis.block_id();

        let kp_a = Keypair::generate_ed25519();
        let peer_a = kp_a.public().to_peer_id();
        let (mut swarm_a, blocks_topic, txs_topic) =
            spawn_harness_peer(kp_a.clone(), MessageAuthenticity::Signed(kp_a));

        let kp_c = Keypair::generate_ed25519();
        let (mut swarm_c, _, _) =
            spawn_harness_peer(kp_c.clone(), MessageAuthenticity::Signed(kp_c));

        swarm_a.dial(addr_b.clone()).unwrap();
        swarm_c.dial(addr_b).unwrap();
        pump_until_mesh_ready(&mut swarm_a, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;
        pump_until_mesh_ready(&mut swarm_c, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;

        let mut chain_state = ChainState::from_genesis(&genesis).unwrap();
        let miner = TestKeypair::from_seed(11);
        let alice = TestKeypair::from_seed(12);

        // 1. Swarm A publishes Block 1 over Gossipsub
        let cb1 = make_coinbase(cid, 1, miner.address, 10_000_000);
        let b1 = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + 120, vec![cb1]);
        chain_state.apply_block(&b1).unwrap();
        let b1_id = b1.block_id();

        let b1_frame = encode_frame(&b1.to_bytes().unwrap()).unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic.clone(), b1_frame)
            .unwrap();

        // Expect Node B to validate & forward to Swarm C with ORIGINAL author source == peer_a,
        // and NO duplicate rebroadcast under source == peer_b.
        let b_hash = blocks_topic.hash();
        let mut saw_from_a = false;
        let mut saw_rebroadcast_from_b = false;

        let _ = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |prop_src, author, topic, _data| {
                if topic == b_hash && prop_src == peer_b {
                    if author == Some(peer_a) {
                        saw_from_a = true;
                    } else if author == Some(peer_b) {
                        saw_rebroadcast_from_b = true;
                    }
                }
                false
            },
            Duration::from_secs(2),
        )
        .await;

        assert!(
            saw_from_a,
            "Swarm C must receive Block 1 forwarded by B with original source A"
        );
        assert!(
            !saw_rebroadcast_from_b,
            "Node B must NOT redundantly republish gossip block under B's own identity"
        );
        assert_eq!(node_b.status().await.unwrap().tip_height, 1);
        assert_eq!(node_b.status().await.unwrap().tip_block_id, b1_id);

        // 2. Advance 100 more blocks locally on Node B so miner coinbase matures
        for h in 2..=101 {
            let cb = make_coinbase(cid, h, miner.address, 10_000_000);
            let b = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            chain_state.apply_block(&b).unwrap();
            node_b.submit_block(b).await.unwrap();
        }

        // Drain any locally submitted blocks from Swarm C before tx test
        let _ = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |_, _, _, _| false,
            Duration::from_millis(400),
        )
        .await;

        // 3. Swarm A publishes valid Type 1 transfer over Gossipsub
        let tx1 = make_transparent_transfer(cid, &miner, alice.address, 500_000, 20_000, 0);
        let tx1_frame = encode_frame(&tx1).unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), tx1_frame)
            .unwrap();

        let t_hash = txs_topic.hash();
        let mut tx_from_a = false;
        let mut tx_rebroadcast_from_b = false;

        let _ = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |prop_src, author, topic, _data| {
                if topic == t_hash && prop_src == peer_b {
                    if author == Some(peer_a) {
                        tx_from_a = true;
                    } else if author == Some(peer_b) {
                        tx_rebroadcast_from_b = true;
                    }
                }
                false
            },
            Duration::from_secs(2),
        )
        .await;

        assert!(
            tx_from_a,
            "Swarm C must receive valid tx forwarded by B with source A"
        );
        assert!(
            !tx_rebroadcast_from_b,
            "Node B must NOT redundantly republish gossip transaction under B's own identity"
        );
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        node_b.stop().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_e2e_invalid_block_header_poisoning_then_valid_block_accepted() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir_b = TempDir::new().unwrap();
        let (node_b, _tb) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();
        let addr_b = wait_for_node_listen_addr(&node_b).await;
        let peer_b = node_b.peer_id();

        let cid = hash::chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let ghash = genesis.block_id();

        let kp_a = Keypair::generate_ed25519();
        let peer_a = kp_a.public().to_peer_id();
        let (mut swarm_a, blocks_topic, txs_topic) =
            spawn_harness_peer(kp_a.clone(), MessageAuthenticity::Signed(kp_a));
        let kp_c = Keypair::generate_ed25519();
        let (mut swarm_c, _, _) =
            spawn_harness_peer(kp_c.clone(), MessageAuthenticity::Signed(kp_c));

        swarm_a.dial(addr_b.clone()).unwrap();
        swarm_c.dial(addr_b).unwrap();
        pump_until_mesh_ready(&mut swarm_a, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;
        pump_until_mesh_ready(&mut swarm_c, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;

        let chain_state = ChainState::from_genesis(&genesis).unwrap();
        let miner = TestKeypair::from_seed(21);
        let cb1 = make_coinbase(cid, 1, miner.address, 10_000_000);
        let valid_b1 = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + 120, vec![cb1]);
        let valid_b1_id = valid_b1.block_id();

        // Tamper body while keeping identical header block_id!
        let mut poisoned_b1 = valid_b1.clone();
        poisoned_b1.transactions.push(vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(poisoned_b1.block_id(), valid_b1_id);

        // Publish malformed raw frame + consensus-invalid bad-body block
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic.clone(), vec![0xff, 0xff, 0xff, 0x0f, 1])
            .unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(
                blocks_topic.clone(),
                encode_frame(&poisoned_b1.to_bytes().unwrap()).unwrap(),
            )
            .unwrap();

        let b_hash = blocks_topic.hash();
        let saw_invalid_on_c = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |_, _, topic, _| topic == b_hash,
            Duration::from_secs(2),
        )
        .await;
        assert!(
            !saw_invalid_on_c,
            "Invalid/malformed blocks must never be forwarded to Swarm C"
        );
        assert_eq!(node_b.status().await.unwrap().tip_height, 0);

        // Now publish the genuine valid_b1 sharing the same header block_id = valid_b1_id
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(
                blocks_topic.clone(),
                encode_frame(&valid_b1.to_bytes().unwrap()).unwrap(),
            )
            .unwrap();

        let forwarded_valid = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |prop_src, author, topic, data| {
                topic == b_hash && prop_src == peer_b && author == Some(peer_a) && !data.is_empty()
            },
            Duration::from_secs(5),
        )
        .await;
        assert!(
            forwarded_valid,
            "Genuine Block 1 must NOT be suppressed after prior rejected payload with same block_id"
        );
        assert_eq!(node_b.status().await.unwrap().tip_height, 1);
        assert_eq!(node_b.status().await.unwrap().tip_block_id, valid_b1_id);

        node_b.stop().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_e2e_invalid_tx_suppressed_and_mempool_full_allows_retry() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir_b = TempDir::new().unwrap();
        let mut cfg = create_node_config(&dir_b);
        cfg.mempool_config = MempoolConfig {
            max_transactions: 1,
            max_bytes: 1_000_000,
        };
        let (node_b, _tb) = NodeRuntime::spawn(cfg).unwrap();
        let addr_b = wait_for_node_listen_addr(&node_b).await;
        let peer_b = node_b.peer_id();

        let cid = hash::chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let ghash = genesis.block_id();

        let kp_a = Keypair::generate_ed25519();
        let (mut swarm_a, blocks_topic, txs_topic) =
            spawn_harness_peer(kp_a.clone(), MessageAuthenticity::Signed(kp_a));
        let kp_c = Keypair::generate_ed25519();
        let (mut swarm_c, _, _) =
            spawn_harness_peer(kp_c.clone(), MessageAuthenticity::Signed(kp_c));

        swarm_a.dial(addr_b.clone()).unwrap();
        swarm_c.dial(addr_b).unwrap();
        pump_until_mesh_ready(&mut swarm_a, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;
        pump_until_mesh_ready(&mut swarm_c, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;

        let mut chain_state = ChainState::from_genesis(&genesis).unwrap();
        let miner1 = TestKeypair::from_seed(31);
        let miner2 = TestKeypair::from_seed(32);
        let alice = TestKeypair::from_seed(33);

        // Mature both miner1 (block 1) and miner2 (block 2) coinbases by advancing to height 102
        for h in 1..=102 {
            let payout_addr = if h == 2 {
                miner2.address
            } else {
                miner1.address
            };
            let cb = make_coinbase(cid, h, payout_addr, 10_000_000);
            let b = make_hybrid_block(&chain_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            chain_state.apply_block(&b).unwrap();
            node_b.submit_block(b).await.unwrap();
        }

        // 1. Invalid txs: coinbase on gossip topic + under-minimum fee tx
        let bad_cb = make_coinbase(cid, 103, miner1.address, 10_000_000);
        let bad_fee = make_transparent_transfer(cid, &miner1, alice.address, 100_000, 1, 0);
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&bad_cb).unwrap())
            .unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&bad_fee).unwrap())
            .unwrap();

        let t_hash = txs_topic.hash();
        let forwarded_bad_tx = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |_, _, topic, _| topic == t_hash,
            Duration::from_millis(1500),
        )
        .await;
        assert!(!forwarded_bad_tx, "Invalid txs must not be forwarded to C");
        assert_eq!(node_b.status().await.unwrap().mempool_size, 0);

        // 2. Fill 1-slot mempool with tx_1, then gossip valid tx_2 -> MempoolFull -> Ignore (not mark_seen)
        let tx_1 = make_transparent_transfer(cid, &miner1, alice.address, 100_000, 20_000, 0);
        let tx_2 = make_transparent_transfer(cid, &miner2, alice.address, 100_000, 20_000, 0);
        node_b.submit_transaction(tx_1.clone()).await.unwrap();
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        // Drain tx_1 gossip from Swarm C before publishing tx_2
        let _ = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |_, _, _, _| false,
            Duration::from_millis(400),
        )
        .await;

        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&tx_2).unwrap())
            .unwrap();

        let forwarded_during_full = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |_, _, topic, _| topic == t_hash,
            Duration::from_millis(1500),
        )
        .await;
        assert!(
            !forwarded_during_full,
            "tx_2 ignored under MempoolFull must not be forwarded while mempool full"
        );
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        // 3. Mine block 103 confirming tx_1 -> frees the 1-slot mempool
        let cb103 = make_coinbase(cid, 103, miner1.address, 10_000_000);
        let b103 = make_hybrid_block(
            &chain_state,
            GENESIS_TIMESTAMP + 103 * 120,
            vec![cb103, tx_1],
        );
        chain_state.apply_block(&b103).unwrap();
        node_b.submit_block(b103).await.unwrap();
        assert_eq!(node_b.status().await.unwrap().mempool_size, 0);

        // 4. Republish tx_2 (new Gossipsub sequence_number -> fresh MessageId): must be admitted & forwarded!
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&tx_2).unwrap())
            .unwrap();

        let forwarded_after_drain = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |prop_src, _, topic, _| topic == t_hash && prop_src == peer_b,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            forwarded_after_drain,
            "tx_2 must NOT be suppressed by MempoolFull and must succeed on retry"
        );
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        node_b.stop().await;
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_e2e_reorg_unconfirms_tx_and_allows_readmission_via_gossip() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir_b = TempDir::new().unwrap();
        let (node_b, _tb) = NodeRuntime::spawn(create_node_config(&dir_b)).unwrap();
        let addr_b = wait_for_node_listen_addr(&node_b).await;
        let peer_b = node_b.peer_id();

        let cid = hash::chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let ghash = genesis.block_id();

        let kp_a = Keypair::generate_ed25519();
        let (mut swarm_a, blocks_topic, txs_topic) =
            spawn_harness_peer(kp_a.clone(), MessageAuthenticity::Signed(kp_a));
        let kp_c = Keypair::generate_ed25519();
        let (mut swarm_c, _, _) =
            spawn_harness_peer(kp_c.clone(), MessageAuthenticity::Signed(kp_c));

        swarm_a.dial(addr_b.clone()).unwrap();
        swarm_c.dial(addr_b).unwrap();
        pump_until_mesh_ready(&mut swarm_a, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;
        pump_until_mesh_ready(&mut swarm_c, peer_b, &blocks_topic, &txs_topic, cid, ghash).await;

        let mut base_state = ChainState::from_genesis(&genesis).unwrap();
        let miner = TestKeypair::from_seed(41);
        let alt_miner = TestKeypair::from_seed(42);
        let alice = TestKeypair::from_seed(43);

        for h in 1..=101 {
            let cb = make_coinbase(cid, h, miner.address, 10_000_000);
            let b = make_hybrid_block(&base_state, GENESIS_TIMESTAMP + h * 120, vec![cb]);
            base_state.apply_block(&b).unwrap();
            node_b.submit_block(b).await.unwrap();
        }

        let tx_1 = make_transparent_transfer(cid, &miner, alice.address, 250_000, 20_000, 0);

        // 1. Gossip tx_1 first (enters mempool and seen_txs!)
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&tx_1).unwrap())
            .unwrap();
        let t_hash = txs_topic.hash();
        assert!(
            drive_swarms_until(
                &mut swarm_a,
                &mut swarm_c,
                |prop_src, _, topic, _| topic == t_hash && prop_src == peer_b,
                Duration::from_secs(5),
            )
            .await
        );
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        // 2. Confirm tx_1 on Branch A (Block 102_A) -> removed from mempool, now AlreadyOnChain
        let mut branch_a = base_state.clone();
        let cb102a = make_coinbase(cid, 102, miner.address, 10_000_000);
        let b102a = make_hybrid_block(
            &branch_a,
            GENESIS_TIMESTAMP + 102 * 120,
            vec![cb102a, tx_1.clone()],
        );
        branch_a.apply_block(&b102a).unwrap();
        node_b.submit_block(b102a).await.unwrap();
        assert_eq!(node_b.status().await.unwrap().tip_height, 102);
        assert_eq!(node_b.status().await.unwrap().mempool_size, 0);

        // Replay tx_1 while AlreadyOnChain -> must remain ignored (not re-admitted or forwarded)
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&tx_1).unwrap())
            .unwrap();
        let forwarded_while_on_chain = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |_, _, topic, _| topic == t_hash,
            Duration::from_millis(1200),
        )
        .await;
        assert!(
            !forwarded_while_on_chain,
            "AlreadyOnChain tx must be ignored"
        );

        // 3. Reorganize onto heavier Branch B (Blocks 102_B, 103_B without tx_1)
        let mut branch_b = base_state.clone();
        let cb102b = make_coinbase(cid, 102, alt_miner.address, 10_000_000);
        let b102b = make_hybrid_block(&branch_b, GENESIS_TIMESTAMP + 102 * 120 + 1, vec![cb102b]);
        branch_b.apply_block(&b102b).unwrap();
        let cb103b = make_coinbase(cid, 103, alt_miner.address, 10_000_000);
        let b103b = make_hybrid_block(&branch_b, GENESIS_TIMESTAMP + 103 * 120, vec![cb103b]);
        branch_b.apply_block(&b103b).unwrap();
        let b103b_id = b103b.block_id();

        node_b.submit_block(b102b).await.unwrap();
        node_b.submit_block(b103b).await.unwrap();
        assert_eq!(node_b.status().await.unwrap().tip_height, 103);
        assert_eq!(node_b.status().await.unwrap().tip_block_id, b103b_id);
        assert_eq!(node_b.status().await.unwrap().mempool_size, 0);

        // 4. Re-gossip tx_1 after reorg: seen_txs was cleared on reorg, so tx_1 is re-admitted & forwarded!
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(txs_topic.clone(), encode_frame(&tx_1).unwrap())
            .unwrap();

        let forwarded_after_reorg = drive_swarms_until(
            &mut swarm_a,
            &mut swarm_c,
            |prop_src, _, topic, _| topic == t_hash && prop_src == peer_b,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            forwarded_after_reorg,
            "tx_1 unconfirmed by reorg must be re-admitted and forwarded via Gossipsub"
        );
        assert_eq!(node_b.status().await.unwrap().mempool_size, 1);

        node_b.stop().await;
    })
    .await
    .expect("test timed out");
}
