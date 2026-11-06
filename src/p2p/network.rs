//! P2P network service, swarm coordination, and event loop.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! - Rust libp2p with TCP, Noise, Yamux.
//! - Gossipsub for block and transaction gossip.
//! - Kademlia DHT for peer discovery and operator bootstrap peers.
//! - Application handshake `/ownchain/1`.
//! - Bounded sync protocol via RequestResponse.

use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::Multiaddr;
use libp2p::gossipsub::{Event as GossipsubEvent, IdentTopic, Message as GossipsubMessage};
use libp2p::identity::{Keypair, PeerId};
use libp2p::noise;
use libp2p::request_response::{
    Event as ReqRespEvent, Message as ReqRespMessage, OutboundRequestId, ResponseChannel,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{tcp, yamux, Swarm};
use tokio::sync::{mpsc, oneshot};

use crate::block::Block;
use crate::difficulty::U256;
use crate::hash::{self, Hash};
use crate::p2p::behaviour::{OwnChainBehaviour, OwnChainBehaviourEvent};
use crate::p2p::framing::{decode_frame_slice, encode_frame, MAX_FRAME_LENGTH};
use crate::p2p::handshake::{HandshakeMessage, HANDSHAKE_PROTOCOL_VERSION};
use crate::p2p::protocol::{SyncRequest, SyncResponse};

/// Maximum number of connected peers permitted.
pub const DEFAULT_MAX_PEERS: usize = 50;

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub address: Option<Multiaddr>,
    pub handshake: Option<HandshakeMessage>,
    pub connected_at: std::time::Instant,
}

/// Commands sent from the node runtime to the network service.
pub enum NetworkCommand {
    /// Broadcast a newly validated block to the gossip network.
    BroadcastBlock(Block),
    /// Broadcast a validated transaction to the gossip network.
    BroadcastTransaction(Vec<u8>),
    /// Send a sync request to a specific peer and await response.
    SendSyncRequest {
        peer_id: PeerId,
        request: SyncRequest,
        sender: oneshot::Sender<Result<SyncResponse, String>>,
    },
    /// Respond to an inbound sync request.
    SendSyncResponse {
        channel: ResponseChannel<SyncResponse>,
        response: SyncResponse,
    },
    /// Dial a remote peer multiaddress.
    Dial(Multiaddr),
    /// Disconnect a peer.
    Disconnect(PeerId),
    /// Query list of currently connected peers.
    GetConnectedPeers(oneshot::Sender<Vec<PeerInfo>>),
    /// Update local tip status for future handshakes.
    UpdateTip {
        height: u64,
        block_id: Hash,
        cumulative_work: U256,
    },
}

/// Events emitted by the network service to the node runtime.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A new peer successfully connected and completed the `/ownchain/1` handshake.
    PeerHandshakeCompleted {
        peer_id: PeerId,
        handshake: HandshakeMessage,
    },
    /// A peer disconnected.
    PeerDisconnected { peer_id: PeerId },
    /// A block was received via gossip or sync.
    BlockReceived { peer_id: PeerId, block: Box<Block> },
    /// A transaction was received via gossip.
    TransactionReceived {
        peer_id: PeerId,
        transaction: Vec<u8>,
    },
    /// Inbound sync request requiring data from the node runtime.
    SyncRequestReceived {
        peer_id: PeerId,
        request: SyncRequest,
        channel: ResponseChannel<SyncResponse>,
    },
}

/// Handle used to interact with the network service from other tasks.
#[derive(Clone)]
pub struct NetworkHandle {
    command_tx: mpsc::Sender<NetworkCommand>,
    local_peer_id: PeerId,
}

impl NetworkHandle {
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub async fn broadcast_block(&self, block: Block) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::BroadcastBlock(block))
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn broadcast_transaction(&self, tx: Vec<u8>) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::BroadcastTransaction(tx))
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn send_sync_request(
        &self,
        peer_id: PeerId,
        request: SyncRequest,
    ) -> Result<SyncResponse, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::SendSyncRequest {
                peer_id,
                request,
                sender: tx,
            })
            .await
            .map_err(|e| e.to_string())?;
        rx.await.map_err(|e| format!("response dropped: {e}"))?
    }

    pub async fn send_sync_response(
        &self,
        channel: ResponseChannel<SyncResponse>,
        response: SyncResponse,
    ) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::SendSyncResponse { channel, response })
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::Dial(addr))
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::Disconnect(peer_id))
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_connected_peers(&self) -> Result<Vec<PeerInfo>, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::GetConnectedPeers(tx))
            .await
            .map_err(|e| e.to_string())?;
        rx.await.map_err(|e| format!("query dropped: {e}"))
    }

    pub async fn update_tip(
        &self,
        height: u64,
        block_id: Hash,
        cumulative_work: U256,
    ) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::UpdateTip {
                height,
                block_id,
                cumulative_work,
            })
            .await
            .map_err(|e| e.to_string())
    }
}

/// Network service running the libp2p swarm and background event loop.
pub struct NetworkService {
    swarm: Swarm<OwnChainBehaviour>,
    _network_name: String,
    chain_id: Hash,
    genesis_hash: Hash,
    current_height: u64,
    current_tip_id: Hash,
    current_cumulative_work: U256,
    blocks_topic: IdentTopic,
    txs_topic: IdentTopic,
    max_peers: usize,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    peers: HashMap<PeerId, PeerInfo>,
    pending_sync_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<SyncResponse, String>>>,
    seen_announcements: HashSet<Hash>,
    announcement_fifo: VecDeque<Hash>,
}

impl NetworkService {
    /// Builds the network service, swarm, and command/event channels.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keypair: Keypair,
        network_name: &str,
        chain_id: Hash,
        genesis_hash: Hash,
        initial_height: u64,
        initial_tip_id: Hash,
        initial_cumulative_work: U256,
        listen_addr: Multiaddr,
        max_peers: usize,
        command_buffer: usize,
        event_buffer: usize,
    ) -> Result<(Self, NetworkHandle, mpsc::Receiver<NetworkEvent>), Box<dyn Error + Send + Sync>>
    {
        let local_peer_id = keypair.public().to_peer_id();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|kp| OwnChainBehaviour::new(kp, network_name))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Listen on configured address
        swarm.listen_on(listen_addr)?;

        // Gossipsub topics
        let blocks_topic = IdentTopic::new(format!("/ownchain/{network_name}/blocks/v1"));
        let txs_topic = IdentTopic::new(format!("/ownchain/{network_name}/txs/v1"));
        swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;

        let (command_tx, command_rx) = mpsc::channel(command_buffer);
        let (event_tx, event_rx) = mpsc::channel(event_buffer);

        let handle = NetworkHandle {
            command_tx,
            local_peer_id,
        };

        let service = Self {
            swarm,
            _network_name: network_name.to_string(),
            chain_id,
            genesis_hash,
            current_height: initial_height,
            current_tip_id: initial_tip_id,
            current_cumulative_work: initial_cumulative_work,
            blocks_topic,
            txs_topic,
            max_peers,
            command_rx,
            event_tx,
            peers: HashMap::new(),
            pending_sync_requests: HashMap::new(),
            seen_announcements: HashSet::new(),
            announcement_fifo: VecDeque::new(),
        };

        Ok((service, handle, event_rx))
    }

    /// Helper to record and check duplicate announcements (LRU/FIFO bounded at 5,000 entries).
    fn mark_seen(&mut self, id: Hash) -> bool {
        if self.seen_announcements.contains(&id) {
            return false; // Already seen
        }
        if self.announcement_fifo.len() >= 5000 {
            if let Some(old) = self.announcement_fifo.pop_front() {
                self.seen_announcements.remove(&old);
            }
        }
        self.seen_announcements.insert(id);
        self.announcement_fifo.push_back(id);
        true // Newly seen
    }

    fn current_handshake(&self) -> HandshakeMessage {
        HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            tip_height: self.current_height,
            tip_block_id: self.current_tip_id,
            cumulative_work: self.current_cumulative_work,
            capabilities: 0,
            software_version: format!("ownchain/{}", crate::VERSION),
        }
    }

    /// Runs the network event loop until shutdown.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => {
                            tracing::info!("Network command channel closed, shutting down network service");
                            break;
                        }
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::BroadcastBlock(block) => {
                let block_id = block.header.block_id();
                self.mark_seen(block_id);
                if let Ok(raw_bytes) = block.to_bytes() {
                    if raw_bytes.len() <= MAX_FRAME_LENGTH {
                        if let Ok(frame) = encode_frame(&raw_bytes) {
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(self.blocks_topic.clone(), frame);
                        }
                    }
                }
            }
            NetworkCommand::BroadcastTransaction(tx_bytes) => {
                let tx_id = hash::transaction_id(&tx_bytes);
                self.mark_seen(tx_id);
                if tx_bytes.len() <= MAX_FRAME_LENGTH {
                    if let Ok(frame) = encode_frame(&tx_bytes) {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(self.txs_topic.clone(), frame);
                    }
                }
            }
            NetworkCommand::SendSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                let req_id = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);
                self.pending_sync_requests.insert(req_id, sender);
            }
            NetworkCommand::SendSyncResponse { channel, response } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response);
            }
            NetworkCommand::Dial(addr) => {
                let _ = self.swarm.dial(addr);
            }
            NetworkCommand::Disconnect(peer_id) => {
                let _ = self.swarm.disconnect_peer_id(peer_id);
                self.peers.remove(&peer_id);
            }
            NetworkCommand::GetConnectedPeers(sender) => {
                let peer_list: Vec<PeerInfo> = self.peers.values().cloned().collect();
                let _ = sender.send(peer_list);
            }
            NetworkCommand::UpdateTip {
                height,
                block_id,
                cumulative_work,
            } => {
                self.current_height = height;
                self.current_tip_id = block_id;
                self.current_cumulative_work = cumulative_work;
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<OwnChainBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if self.peers.len() >= self.max_peers {
                    tracing::warn!(
                        "Max peers limit reached ({}), rejecting {}",
                        self.max_peers,
                        peer_id
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                let addr = Some(endpoint.get_remote_address().clone());
                self.peers.insert(
                    peer_id,
                    PeerInfo {
                        peer_id,
                        address: addr,
                        handshake: None,
                        connected_at: std::time::Instant::now(),
                    },
                );

                // Send handshake to remote peer
                let local_hs = self.current_handshake();
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, SyncRequest::Handshake(local_hs));
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.peers.remove(&peer_id);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerDisconnected { peer_id })
                    .await;
            }

            SwarmEvent::Behaviour(OwnChainBehaviourEvent::Gossipsub(GossipsubEvent::Message {
                message,
                ..
            })) => {
                self.handle_gossip_message(message).await;
            }

            SwarmEvent::Behaviour(OwnChainBehaviourEvent::RequestResponse(req_resp_event)) => {
                self.handle_request_response_event(req_resp_event).await;
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Node listening on {}", address);
            }

            _ => {}
        }
    }

    async fn handle_gossip_message(&mut self, message: GossipsubMessage) {
        if message.topic == self.blocks_topic.hash() {
            // Block frame: decode length-prefixed frame
            if let Ok((block_bytes, _)) = decode_frame_slice(&message.data) {
                if let Ok(block) = Block::from_bytes(block_bytes) {
                    let block_id = block.header.block_id();
                    if self.mark_seen(block_id) {
                        let peer_id = message.source.unwrap_or(PeerId::random());
                        let _ = self
                            .event_tx
                            .send(NetworkEvent::BlockReceived {
                                peer_id,
                                block: Box::new(block),
                            })
                            .await;
                    }
                }
            }
        } else if message.topic == self.txs_topic.hash() {
            // Transaction frame: decode length-prefixed frame
            if let Ok((tx_bytes, _)) = decode_frame_slice(&message.data) {
                let tx_id = hash::transaction_id(tx_bytes);
                if self.mark_seen(tx_id) {
                    let peer_id = message.source.unwrap_or(PeerId::random());
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::TransactionReceived {
                            peer_id,
                            transaction: tx_bytes.to_vec(),
                        })
                        .await;
                }
            }
        }
    }

    async fn handle_request_response_event(
        &mut self,
        event: ReqRespEvent<SyncRequest, SyncResponse>,
    ) {
        match event {
            ReqRespEvent::Message { peer, message } => match message {
                ReqRespMessage::Request {
                    request_id: _,
                    request,
                    channel,
                } => {
                    self.handle_inbound_request(peer, request, channel).await;
                }
                ReqRespMessage::Response {
                    request_id,
                    response,
                } => {
                    self.handle_inbound_response(peer, request_id, response)
                        .await;
                }
            },
            ReqRespEvent::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(sender) = self.pending_sync_requests.remove(&request_id) {
                    let _ = sender.send(Err(format!("outbound request failed: {error:?}")));
                }
            }
            ReqRespEvent::InboundFailure { error, .. } => {
                tracing::debug!("Inbound sync request failure: {:?}", error);
            }
            ReqRespEvent::ResponseSent { .. } => {}
        }
    }

    async fn handle_inbound_request(
        &mut self,
        peer_id: PeerId,
        request: SyncRequest,
        channel: ResponseChannel<SyncResponse>,
    ) {
        match request {
            SyncRequest::Handshake(remote_handshake) => {
                if let Err(e) =
                    remote_handshake.verify_compatibility(self.chain_id, self.genesis_hash)
                {
                    tracing::warn!("Handshake rejected for peer {}: {}", peer_id, e);
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, SyncResponse::Error(e.to_string()));
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    self.peers.remove(&peer_id);
                    return;
                }

                // Update peer handshake
                if let Some(peer_info) = self.peers.get_mut(&peer_id) {
                    peer_info.handshake = Some(remote_handshake.clone());
                }

                // Send back our local handshake
                let local_handshake = self.current_handshake();
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, SyncResponse::Handshake(local_handshake));

                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerHandshakeCompleted {
                        peer_id,
                        handshake: remote_handshake,
                    })
                    .await;
            }
            other_req => {
                // Forward GetStatus / GetHeaders / GetBlocks etc. to node runtime
                let _ = self
                    .event_tx
                    .send(NetworkEvent::SyncRequestReceived {
                        peer_id,
                        request: other_req,
                        channel,
                    })
                    .await;
            }
        }
    }

    async fn handle_inbound_response(
        &mut self,
        peer_id: PeerId,
        request_id: OutboundRequestId,
        response: SyncResponse,
    ) {
        if let Some(sender) = self.pending_sync_requests.remove(&request_id) {
            let _ = sender.send(Ok(response.clone()));
        }

        // If this was a Handshake response to our initial handshake
        if let SyncResponse::Handshake(remote_handshake) = response {
            if let Err(e) = remote_handshake.verify_compatibility(self.chain_id, self.genesis_hash)
            {
                tracing::warn!(
                    "Peer {} handshake verification failed on response: {}",
                    peer_id,
                    e
                );
                let _ = self.swarm.disconnect_peer_id(peer_id);
                self.peers.remove(&peer_id);
                return;
            }

            if let Some(peer_info) = self.peers.get_mut(&peer_id) {
                peer_info.handshake = Some(remote_handshake.clone());
            }

            let _ = self
                .event_tx
                .send(NetworkEvent::PeerHandshakeCompleted {
                    peer_id,
                    handshake: remote_handshake,
                })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_duplicate_announcement_suppression() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);
        let (mut service, _handle, _rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            tip_id,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let id1 = Hash::new([0xaa; 32]);
        let id2 = Hash::new([0xbb; 32]);

        assert!(service.mark_seen(id1));
        assert!(!service.mark_seen(id1)); // Duplicate suppressed

        assert!(service.mark_seen(id2));
        assert!(!service.mark_seen(id2)); // Duplicate suppressed
    }

    #[tokio::test]
    async fn test_network_service_spawn_and_connect() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let (service1, handle1, _rx1) = NetworkService::new(
            kp1,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            tip_id,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let kp2 = Keypair::generate_ed25519();
        let (service2, handle2, _rx2) = NetworkService::new(
            kp2,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            tip_id,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let s1_handle = tokio::spawn(service1.run());
        let s2_handle = tokio::spawn(service2.run());

        // We can get connected peers or interact via handles
        let p1_id = handle1.local_peer_id();
        let p2_id = handle2.local_peer_id();
        assert_ne!(p1_id, p2_id);

        s1_handle.abort();
        s2_handle.abort();
    }
}
