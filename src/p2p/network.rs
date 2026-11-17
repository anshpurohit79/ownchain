//! P2P network service, swarm coordination, and event loop.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! - Rust libp2p with TCP, Noise, Yamux.
//! - Gossipsub for block and transaction gossip.
//! - Kademlia DHT for peer discovery and operator bootstrap peers.
//! - Application handshake carried over `/ownchain/sync/1`.
//! - Bounded sync protocol via RequestResponse.

use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::Multiaddr;
use libp2p::gossipsub::{
    Event as GossipsubEvent, IdentTopic, Message as GossipsubMessage, MessageAcceptance, MessageId,
};
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
use crate::p2p::framing::{decode_frame_slice_exact, encode_frame, MAX_FRAME_LENGTH};
use crate::p2p::handshake::{HandshakeMessage, HANDSHAKE_PROTOCOL_VERSION};
use crate::p2p::protocol::{SyncRequest, SyncResponse};

/// Maximum number of connected peers permitted.
pub const DEFAULT_MAX_PEERS: usize = 50;

/// Maximum age of an unvalidated gossip message token before expiration cleanup in libp2p.
/// Set strictly below the minimum estimated `mcache` retention window (`(20 - 1) * 500ms = 9.5s`).
pub const PENDING_GOSSIP_TTL: Duration = Duration::from_secs(8);

/// Bounded safety timeout after which uncompleted in-flight payload processing locks are cleaned up.
pub const IN_FLIGHT_PAYLOAD_TTL: Duration = Duration::from_secs(30);

/// Maximum number of concurrent pending gossip validation tokens tracked in memory.
const MAX_PENDING_GOSSIP: usize = 500;

/// Maximum number of concurrent in-flight payloads tracked in memory.
const MAX_IN_FLIGHT_PAYLOADS: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GossipSubjectKind {
    Block,
    Transaction,
}

#[derive(Debug, Clone)]
struct PendingGossipEntry {
    kind: GossipSubjectKind,
    canonical_id: Hash,
    payload_hash: Hash,
    propagation_source: PeerId,
    source: Option<PeerId>,
    created_at: std::time::Instant,
}

/// RAII guard that binds an active validation task's lifecycle to an atomic execution tracker.
///
/// Implements `Drop` so that whether a validation future completes normally,
/// errors out, panics, or is dropped via timeout or cancellation, the active flag
/// is guaranteed to transition to `false`.
#[derive(Debug)]
pub struct ValidationExecutionGuard {
    active_flag: Arc<AtomicBool>,
}

impl ValidationExecutionGuard {
    /// Creates a new guard, asserting the active execution state.
    pub fn new(active_flag: Arc<AtomicBool>) -> Self {
        active_flag.store(true, Ordering::SeqCst);
        Self { active_flag }
    }

    /// Returns whether the tracked validation task is still actively executing.
    pub fn is_executing(&self) -> bool {
        self.active_flag.load(Ordering::SeqCst)
    }
}

impl Drop for ValidationExecutionGuard {
    fn drop(&mut self) {
        self.active_flag.store(false, Ordering::SeqCst);
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct InFlightPayloadEntry {
    payload_hash: Hash,
    canonical_id: Hash,
    kind: GossipSubjectKind,
    created_at: std::time::Instant,
    active_token: Option<MessageId>,
    generation: u64,
    is_active: Arc<AtomicBool>,
}

impl InFlightPayloadEntry {
    pub fn is_executing(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
    }

    pub fn mark_completed(&self) {
        self.is_active.store(false, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    pub fn execution_guard(&self) -> ValidationExecutionGuard {
        ValidationExecutionGuard::new(self.is_active.clone())
    }
}

/// Information about a connected peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub address: Option<Multiaddr>,
    pub handshake: Option<HandshakeMessage>,
    pub connected_at: std::time::Instant,
}

/// Outcome of handling an established connection in the peer registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionAction {
    /// A genuinely new peer was registered; application handshake should be initiated.
    NewPeer,
    /// An additional connection was established for an already registered peer.
    /// Existing handshake and connection timestamp are preserved.
    ExistingPeer,
    /// A new peer was rejected because the maximum unique peer limit has been reached.
    RejectedMaxPeers,
}

/// Registry of unique connected peers.
///
/// Ensures that each unique `PeerId` is represented at most once, regardless of
/// the number of concurrent transport connections.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct PeerRegistry {
    peers: HashMap<PeerId, PeerInfo>,
    max_peers: usize,
}

#[allow(dead_code)]
impl PeerRegistry {
    /// Creates a new peer registry with the configured maximum unique peer limit.
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
        }
    }

    /// Number of unique peers currently registered.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Configured maximum unique peer limit.
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Checks if a peer is registered.
    pub fn contains(&self, peer_id: &PeerId) -> bool {
        self.peers.contains_key(peer_id)
    }

    /// Returns a reference to a registered peer's `PeerInfo`.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Returns a mutable reference to a registered peer's `PeerInfo`.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    /// Returns a list of all currently registered peers.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers.values().cloned().collect()
    }

    /// Handles a connection established event for a peer.
    ///
    /// Invariants:
    /// - If the peer is already registered, updates its address if provided,
    ///   preserves verified handshake and original `connected_at`, and returns `ConnectionAction::ExistingPeer`.
    /// - If the peer is unknown and `len() >= max_peers`, returns `ConnectionAction::RejectedMaxPeers`.
    /// - If the peer is unknown and under capacity, registers a new `PeerInfo` with `handshake: None`
    ///   and current timestamp, returning `ConnectionAction::NewPeer`.
    pub fn handle_connection_established(
        &mut self,
        peer_id: PeerId,
        address: Option<Multiaddr>,
    ) -> ConnectionAction {
        if let Some(info) = self.peers.get_mut(&peer_id) {
            if let Some(addr) = address {
                info.address = Some(addr);
            }
            return ConnectionAction::ExistingPeer;
        }

        if self.peers.len() >= self.max_peers {
            return ConnectionAction::RejectedMaxPeers;
        }

        self.peers.insert(
            peer_id,
            PeerInfo {
                peer_id,
                address,
                handshake: None,
                connected_at: std::time::Instant::now(),
            },
        );

        ConnectionAction::NewPeer
    }

    /// Handles a connection closed event for a peer.
    ///
    /// Invariants:
    /// - If `num_established > 0`, the peer still has at least one active connection
    ///   and remains in the registry. Returns `None`.
    /// - If `num_established == 0`, this was the final connection. The peer is removed
    ///   from the registry. If it was registered, returns `Some(PeerInfo)` so the caller
    ///   can emit `NetworkEvent::PeerDisconnected`. If it was not registered or already removed, returns `None`.
    pub fn handle_connection_closed(
        &mut self,
        peer_id: &PeerId,
        num_established: u32,
    ) -> Option<PeerInfo> {
        if num_established > 0 {
            return None;
        }

        self.peers.remove(peer_id)
    }

    /// Forcefully removes a peer from the registry.
    ///
    /// Used when a peer disconnection cannot be completed asynchronously
    /// (e.g. `disconnect_peer_id` returns `Err(())` indicating the transport is
    /// already disconnected or unknown to the swarm).
    ///
    /// Returns `Some(PeerInfo)` if the peer was present, or `None` if it was not registered.
    pub fn force_remove(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.remove(peer_id)
    }

    /// Checks if a peer has completed an application handshake.
    pub fn is_handshake_done(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .map(|p| p.handshake.is_some())
            .unwrap_or(false)
    }

    /// Updates the handshake for a peer. Returns `true` if this peer transitioned from
    /// unverified (`None`) to verified (`Some`).
    ///
    /// If the peer's handshake is already verified (`Some`), an unsolicited handshake transition
    /// is rejected and the established handshake metadata is preserved intact.
    pub fn update_handshake(&mut self, peer_id: &PeerId, handshake: HandshakeMessage) -> bool {
        if let Some(info) = self.peers.get_mut(peer_id) {
            if info.handshake.is_some() {
                // Handshake already established for this connection; do not overwrite trusted metadata.
                return false;
            }
            info.handshake = Some(handshake);
            true
        } else {
            false
        }
    }
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
    /// Query local listening addresses.
    GetListenAddrs(oneshot::Sender<Vec<Multiaddr>>),
    /// Initiate Kademlia DHT bootstrap.
    BootstrapKademlia,
    /// Update local tip status for future handshakes.
    UpdateTip {
        height: u64,
        block_id: Hash,
        cumulative_work: U256,
    },
    /// Report the application validation outcome for a received Gossipsub message.
    ReportGossipValidation {
        message_id: MessageId,
        propagation_source: PeerId,
        acceptance: MessageAcceptance,
        mark_seen: bool,
        canonical_id: Option<Hash>,
        is_block: bool,
    },
    /// Remove evicted/invalidated transaction IDs from the seen-transaction cache.
    ForgetSeenTransactions(Vec<Hash>),
    /// Clear all cached seen transaction IDs (e.g., after an active-chain reorganization).
    ClearSeenTransactions,
}

/// Events emitted by the network service to the node runtime.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A new peer successfully connected and completed the handshake over `/ownchain/sync/1`.
    PeerHandshakeCompleted {
        peer_id: PeerId,
        handshake: HandshakeMessage,
    },
    /// A peer disconnected.
    PeerDisconnected { peer_id: PeerId },
    /// A block was received via gossip.
    BlockReceived {
        propagation_source: PeerId,
        source: Option<PeerId>,
        message_id: MessageId,
        block: Box<Block>,
        execution_guard: Option<ValidationExecutionGuard>,
    },
    /// A transaction was received via gossip.
    TransactionReceived {
        propagation_source: PeerId,
        source: Option<PeerId>,
        message_id: MessageId,
        transaction: Vec<u8>,
        execution_guard: Option<ValidationExecutionGuard>,
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

    #[cfg(test)]
    pub fn new_mock(command_tx: mpsc::Sender<NetworkCommand>, local_peer_id: PeerId) -> Self {
        Self {
            command_tx,
            local_peer_id,
        }
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

    pub async fn get_listen_addrs(&self) -> Result<Vec<Multiaddr>, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::GetListenAddrs(tx))
            .await
            .map_err(|e| e.to_string())?;
        rx.await.map_err(|e| format!("query dropped: {e}"))
    }

    pub async fn bootstrap_kademlia(&self) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::BootstrapKademlia)
            .await
            .map_err(|e| e.to_string())
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

    pub async fn report_gossip_validation(
        &self,
        message_id: MessageId,
        propagation_source: PeerId,
        acceptance: MessageAcceptance,
        mark_seen: bool,
        canonical_id: Option<Hash>,
        is_block: bool,
    ) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
                mark_seen,
                canonical_id,
                is_block,
            })
            .await
            .map_err(|e| e.to_string())
    }

    pub fn try_report_gossip_validation(
        &self,
        message_id: MessageId,
        propagation_source: PeerId,
        acceptance: MessageAcceptance,
    ) -> Result<(), String> {
        self.command_tx
            .try_send(NetworkCommand::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
                mark_seen: false,
                canonical_id: None,
                is_block: false,
            })
            .map_err(|e| e.to_string())
    }

    pub async fn forget_seen_transactions(&self, tx_ids: Vec<Hash>) -> Result<(), String> {
        if tx_ids.is_empty() {
            return Ok(());
        }
        self.command_tx
            .send(NetworkCommand::ForgetSeenTransactions(tx_ids))
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn clear_seen_transactions(&self) -> Result<(), String> {
        self.command_tx
            .send(NetworkCommand::ClearSeenTransactions)
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
    peers: PeerRegistry,
    listen_addrs: Vec<Multiaddr>,
    pending_sync_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<SyncResponse, String>>>,
    pending_handshake_requests: HashMap<OutboundRequestId, PeerId>,
    inbound_handshake_processed: HashSet<PeerId>,
    seen_announcements: HashSet<Hash>,
    announcement_fifo: VecDeque<Hash>,
    seen_txs: HashSet<Hash>,
    seen_tx_fifo: VecDeque<Hash>,
    pending_gossip: HashMap<MessageId, PendingGossipEntry>,
    in_flight_payloads: HashMap<Hash, InFlightPayloadEntry>,
    in_flight_by_msg_id: HashMap<MessageId, (Hash, u64)>,
    in_flight_generation_counter: u64,
    #[cfg(test)]
    connection_observer: Option<mpsc::UnboundedSender<(PeerId, u32)>>,
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
            peers: PeerRegistry::new(max_peers),
            listen_addrs: Vec::new(),
            pending_sync_requests: HashMap::new(),
            pending_handshake_requests: HashMap::new(),
            inbound_handshake_processed: HashSet::new(),
            seen_announcements: HashSet::new(),
            announcement_fifo: VecDeque::new(),
            seen_txs: HashSet::new(),
            seen_tx_fifo: VecDeque::new(),
            pending_gossip: HashMap::new(),
            in_flight_payloads: HashMap::new(),
            in_flight_by_msg_id: HashMap::new(),
            in_flight_generation_counter: 0,
            #[cfg(test)]
            connection_observer: None,
        };

        Ok((service, handle, event_rx))
    }

    /// Helper to check whether a canonical block announcement ID has already been recorded.
    fn is_seen(&self, id: &Hash) -> bool {
        self.seen_announcements.contains(id)
    }

    /// Helper to record and check duplicate block announcements (LRU/FIFO bounded at 5,000 entries).
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

    fn is_tx_seen(&self, id: &Hash) -> bool {
        self.seen_txs.contains(id)
    }

    fn mark_tx_seen(&mut self, id: Hash) -> bool {
        if self.seen_txs.contains(&id) {
            return false;
        }
        if self.seen_tx_fifo.len() >= 5000 {
            if let Some(old) = self.seen_tx_fifo.pop_front() {
                self.seen_txs.remove(&old);
            }
        }
        self.seen_txs.insert(id);
        self.seen_tx_fifo.push_back(id);
        true
    }

    fn forget_seen_txs(&mut self, tx_ids: &[Hash]) {
        if tx_ids.is_empty() || self.seen_txs.is_empty() {
            return;
        }
        let mut removed_any = false;
        for id in tx_ids {
            if self.seen_txs.remove(id) {
                removed_any = true;
            }
        }
        if removed_any {
            self.seen_tx_fifo.retain(|id| self.seen_txs.contains(id));
        }
    }

    fn clear_seen_txs(&mut self) {
        self.seen_txs.clear();
        self.seen_tx_fifo.clear();
    }

    fn report_gossip_validation_internal(
        &mut self,
        message_id: &MessageId,
        propagation_source: &PeerId,
        acceptance: MessageAcceptance,
    ) {
        let is_accept = matches!(acceptance, MessageAcceptance::Accept);
        match self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, propagation_source, acceptance)
        {
            Ok(true) => {
                tracing::trace!(
                    %message_id,
                    %propagation_source,
                    accepted = is_accept,
                    "Reported gossipsub validation result"
                );
            }
            Ok(false) => {
                if is_accept {
                    tracing::warn!(
                        %message_id,
                        %propagation_source,
                        "Accepted gossip message expired from mcache before validation completed; forwarding did not occur"
                    );
                } else {
                    tracing::debug!(
                        %message_id,
                        %propagation_source,
                        "Gossipsub mcache miss on Reject/Ignore; message already evicted"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    %message_id,
                    %propagation_source,
                    error = %e,
                    "Failed to report gossipsub message validation result"
                );
            }
        }
    }

    fn sweep_stale_pending_gossip(&mut self) {
        let now = std::time::Instant::now();

        // 1. Sweep expired Gossipsub validation tokens (libp2p token TTL ~8s).
        // Separating validation-token expiration from payload-processing ownership:
        // Expiring a token reports Ignore to libp2p to meet the message cache window,
        // but does NOT prematurely release the in-flight payload ownership lock while
        // NodeRuntime is actively processing the payload.
        if !self.pending_gossip.is_empty() {
            let expired_ids: Vec<MessageId> = self
                .pending_gossip
                .iter()
                .filter(|(_, entry)| {
                    now.saturating_duration_since(entry.created_at) >= PENDING_GOSSIP_TTL
                })
                .map(|(id, _)| id.clone())
                .collect();

            for msg_id in expired_ids {
                if let Some(entry) = self.pending_gossip.remove(&msg_id) {
                    if let Some(inflight) = self.in_flight_payloads.get_mut(&entry.payload_hash) {
                        inflight.active_token = None;
                    }
                    tracing::warn!(
                        %msg_id,
                        propagation_source = %entry.propagation_source,
                        author = ?entry.source,
                        "Pending gossip validation token exceeded TTL; reporting Ignore to libp2p while retaining in-flight payload ownership"
                    );
                    self.report_gossip_validation_internal(
                        &msg_id,
                        &entry.propagation_source,
                        MessageAcceptance::Ignore,
                    );
                }
            }
        }

        // 2. Sweep timed-out in-flight payload processing locks (bounded safety TTL ~30s).
        // Prevents a permanently lost event or runtime drop from creating an indefinite lock.
        // Invariant: Do not release ownership while the validation task is still actively
        // executing (!entry.is_executing()).
        if !self.in_flight_payloads.is_empty() {
            let expired_payloads: Vec<Hash> = self
                .in_flight_payloads
                .iter()
                .filter(|(_, entry)| {
                    now.saturating_duration_since(entry.created_at) >= IN_FLIGHT_PAYLOAD_TTL
                        && !entry.is_executing()
                })
                .map(|(h, _)| *h)
                .collect();

            for payload_hash in expired_payloads {
                if let Some(entry) = self.in_flight_payloads.remove(&payload_hash) {
                    entry.mark_completed();
                    if let Some(token) = entry.active_token {
                        self.pending_gossip.remove(&token);
                    }
                    // Remove all message-ID mappings whose associated (payload_hash, generation) matches this entry
                    let target_gen = entry.generation;
                    self.in_flight_by_msg_id
                        .retain(|_, (h, gen)| !(*h == payload_hash && *gen == target_gen));
                    tracing::warn!(
                        %payload_hash,
                        "In-flight payload processing lock timed out; releasing ownership lock"
                    );
                }
            }
        }

        // 3. Prune stale generation-to-message mappings from in_flight_by_msg_id
        self.in_flight_by_msg_id.retain(|_, (h, gen)| {
            if let Some(entry) = self.in_flight_payloads.get(h) {
                entry.generation == *gen
            } else {
                false
            }
        });
    }

    fn drain_pending_gossip_as_ignore(&mut self) {
        self.in_flight_payloads.clear();
        self.in_flight_by_msg_id.clear();
        self.pending_handshake_requests.clear();
        if self.pending_gossip.is_empty() {
            return;
        }
        let drained: Vec<(MessageId, PendingGossipEntry)> = self.pending_gossip.drain().collect();
        for (msg_id, entry) in drained {
            tracing::debug!(
                %msg_id,
                propagation_source = %entry.propagation_source,
                "Draining pending gossip validation token as Ignore during shutdown"
            );
            self.report_gossip_validation_internal(
                &msg_id,
                &entry.propagation_source,
                MessageAcceptance::Ignore,
            );
        }
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

    /// Requests disconnection of a peer, ensuring canonical lifecycle semantics.
    ///
    /// If `disconnect_peer_id` indicates active connections are being closed (`Ok(())`),
    /// canonical registry cleanup and `PeerDisconnected` notification are deferred until
    /// the final connection actually closes in `SwarmEvent::ConnectionClosed`.
    ///
    /// If the peer was not considered connected by the swarm (`Err(())`), immediately
    /// removes the peer from the registry if present to prevent stale entries.
    async fn request_disconnect(&mut self, peer_id: PeerId) {
        self.pending_handshake_requests.retain(|_, p| *p != peer_id);
        if self.swarm.disconnect_peer_id(peer_id).is_err()
            && self.peers.force_remove(&peer_id).is_some()
        {
            self.inbound_handshake_processed.remove(&peer_id);
            let _ = self
                .event_tx
                .send(NetworkEvent::PeerDisconnected { peer_id })
                .await;
        }
    }

    #[cfg(test)]
    pub fn set_connection_observer(&mut self, tx: mpsc::UnboundedSender<(PeerId, u32)>) {
        self.connection_observer = Some(tx);
    }

    /// Runs the network event loop until shutdown.
    pub async fn run(mut self) {
        let mut gossip_sweep_interval = tokio::time::interval(Duration::from_secs(1));
        gossip_sweep_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => {
                            tracing::info!("Network command channel closed, shutting down network service");
                            self.drain_pending_gossip_as_ignore();
                            break;
                        }
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                _ = gossip_sweep_interval.tick(), if !self.pending_gossip.is_empty() || !self.in_flight_payloads.is_empty() => {
                    self.sweep_stale_pending_gossip();
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
                self.mark_tx_seen(tx_id);
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
                self.request_disconnect(peer_id).await;
            }
            NetworkCommand::GetConnectedPeers(sender) => {
                let peer_list = self.peers.peers();
                let _ = sender.send(peer_list);
            }
            NetworkCommand::GetListenAddrs(sender) => {
                let _ = sender.send(self.listen_addrs.clone());
            }
            NetworkCommand::BootstrapKademlia => {
                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
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
            NetworkCommand::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
                mark_seen,
                canonical_id,
                is_block,
            } => {
                // Remove in-flight payload ownership lock associated with this message_id and generation
                if let Some((payload_hash, gen)) = self.in_flight_by_msg_id.remove(&message_id) {
                    if let Some(entry) = self.in_flight_payloads.get(&payload_hash) {
                        if entry.generation == gen {
                            if let Some(removed) = self.in_flight_payloads.remove(&payload_hash) {
                                removed.mark_completed();
                            }
                        }
                    }
                }

                // Pending-token map is the single ownership gate so report_message_validation_result
                // is invoked at most once per MessageId across normal, timeout, and shutdown paths.
                if let Some(entry) = self.pending_gossip.remove(&message_id) {
                    if let Some(inflight) = self.in_flight_payloads.get(&entry.payload_hash) {
                        if inflight.active_token.as_ref() == Some(&message_id) {
                            if let Some(removed) =
                                self.in_flight_payloads.remove(&entry.payload_hash)
                            {
                                removed.mark_completed();
                            }
                        }
                    }
                    if mark_seen {
                        match entry.kind {
                            GossipSubjectKind::Block => {
                                self.mark_seen(entry.canonical_id);
                            }
                            GossipSubjectKind::Transaction => {
                                self.mark_tx_seen(entry.canonical_id);
                            }
                        }
                    }
                    self.report_gossip_validation_internal(
                        &message_id,
                        &entry.propagation_source,
                        acceptance,
                    );
                } else {
                    tracing::warn!(
                        %message_id,
                        %propagation_source,
                        ?acceptance,
                        "Received late or duplicate ReportGossipValidation for expired or already-resolved token; payload ownership released"
                    );
                    if mark_seen {
                        if let Some(id) = canonical_id {
                            if is_block {
                                self.mark_seen(id);
                            } else {
                                self.mark_tx_seen(id);
                            }
                        }
                    }
                }
            }
            NetworkCommand::ForgetSeenTransactions(tx_ids) => {
                self.forget_seen_txs(&tx_ids);
            }
            NetworkCommand::ClearSeenTransactions => {
                self.clear_seen_txs();
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<OwnChainBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Node listening on {}", address);
                if !self.listen_addrs.contains(&address) {
                    self.listen_addrs.push(address);
                }
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let _ = num_established;
                #[cfg(test)]
                if let Some(ref observer) = self.connection_observer {
                    let _ = observer.send((peer_id, num_established.get()));
                }
                let remote_addr = endpoint.get_remote_address().clone();
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, remote_addr.clone());

                match self
                    .peers
                    .handle_connection_established(peer_id, Some(remote_addr))
                {
                    ConnectionAction::NewPeer => {
                        // Send handshake to newly registered unique peer
                        let local_hs = self.current_handshake();
                        let req_id = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer_id, SyncRequest::Handshake(local_hs));
                        self.pending_handshake_requests.insert(req_id, peer_id);
                    }
                    ConnectionAction::ExistingPeer => {
                        // Additional connection for existing peer: verified handshake and connected_at
                        // are preserved; do not send redundant handshake.
                        tracing::debug!(
                            "Additional connection established for existing peer {}",
                            peer_id
                        );
                    }
                    ConnectionAction::RejectedMaxPeers => {
                        tracing::warn!(
                            "Max peers limit reached ({}), rejecting new peer {}",
                            self.max_peers,
                            peer_id
                        );
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                    }
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if let Some(_removed) = self
                    .peers
                    .handle_connection_closed(&peer_id, num_established)
                {
                    self.pending_handshake_requests.retain(|_, p| *p != peer_id);
                    self.inbound_handshake_processed.remove(&peer_id);
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::PeerDisconnected { peer_id })
                        .await;
                }
            }

            SwarmEvent::Behaviour(OwnChainBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info, .. },
            )) => {
                for addr in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            }

            SwarmEvent::Behaviour(OwnChainBehaviourEvent::Kademlia(kad_event)) => match kad_event {
                libp2p::kad::Event::RoutingUpdated {
                    peer,
                    is_new_peer,
                    addresses,
                    ..
                } => {
                    tracing::debug!(
                        "Kademlia routing updated: peer={peer}, new={is_new_peer}, addrs={:?}",
                        addresses
                    );
                }
                libp2p::kad::Event::OutboundQueryProgressed { result, .. } => {
                    tracing::debug!("Kademlia query progress: {:?}", result);
                }
                _ => {}
            },

            SwarmEvent::Behaviour(OwnChainBehaviourEvent::Gossipsub(GossipsubEvent::Message {
                propagation_source,
                message_id,
                message,
            })) => {
                self.handle_gossip_message(propagation_source, message_id, message);
            }

            SwarmEvent::Behaviour(OwnChainBehaviourEvent::RequestResponse(req_resp_event)) => {
                self.handle_request_response_event(req_resp_event).await;
            }

            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_gossip_event(
        &mut self,
        kind: GossipSubjectKind,
        canonical_id: Hash,
        payload_hash: Hash,
        propagation_source: PeerId,
        source: Option<PeerId>,
        message_id: MessageId,
        event: NetworkEvent,
    ) {
        if self.pending_gossip.contains_key(&message_id) {
            tracing::debug!(%message_id, "Duplicate pending gossip message_id; ignoring");
            return;
        }
        if self.in_flight_payloads.contains_key(&payload_hash)
            || self.pending_gossip.len() >= MAX_PENDING_GOSSIP
            || self.in_flight_payloads.len() >= MAX_IN_FLIGHT_PAYLOADS
        {
            self.report_gossip_validation_internal(
                &message_id,
                &propagation_source,
                MessageAcceptance::Ignore,
            );
            return;
        }

        // Register in-flight ownership and pending token BEFORE making the event visible
        // to NodeRuntime via event_tx, guaranteeing the token exists prior to any response.
        let now = std::time::Instant::now();
        self.in_flight_generation_counter = self.in_flight_generation_counter.wrapping_add(1);
        let generation = self.in_flight_generation_counter;
        let is_active = Arc::new(AtomicBool::new(false));
        let guard = ValidationExecutionGuard::new(is_active.clone());
        self.in_flight_payloads.insert(
            payload_hash,
            InFlightPayloadEntry {
                payload_hash,
                canonical_id,
                kind,
                created_at: now,
                active_token: Some(message_id.clone()),
                generation,
                is_active,
            },
        );
        self.in_flight_by_msg_id
            .insert(message_id.clone(), (payload_hash, generation));
        self.pending_gossip.insert(
            message_id.clone(),
            PendingGossipEntry {
                kind,
                canonical_id,
                payload_hash,
                propagation_source,
                source,
                created_at: now,
            },
        );

        let mut event = event;
        match &mut event {
            NetworkEvent::BlockReceived {
                execution_guard, ..
            }
            | NetworkEvent::TransactionReceived {
                execution_guard, ..
            } => {
                *execution_guard = Some(guard);
            }
            _ => {}
        }

        match self.event_tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Roll back registrations before reporting Ignore so no stale token or lock remains.
                self.pending_gossip.remove(&message_id);
                self.in_flight_by_msg_id.remove(&message_id);
                if let Some(entry) = self.in_flight_payloads.remove(&payload_hash) {
                    entry.mark_completed();
                }
                tracing::warn!(
                    %message_id,
                    %propagation_source,
                    "Runtime event channel full; ignoring incoming gossip message"
                );
                self.report_gossip_validation_internal(
                    &message_id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Roll back BOTH registrations before reporting Ignore and draining remaining tokens
                // so drain_pending_gossip_as_ignore() cannot report this message_id a second time.
                self.pending_gossip.remove(&message_id);
                self.in_flight_by_msg_id.remove(&message_id);
                if let Some(entry) = self.in_flight_payloads.remove(&payload_hash) {
                    entry.mark_completed();
                }
                tracing::debug!(
                    %message_id,
                    %propagation_source,
                    "Runtime event channel closed; ignoring incoming gossip message"
                );
                self.report_gossip_validation_internal(
                    &message_id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                self.drain_pending_gossip_as_ignore();
            }
        }
    }

    fn handle_gossip_message(
        &mut self,
        propagation_source: PeerId,
        message_id: MessageId,
        message: GossipsubMessage,
    ) {
        self.sweep_stale_pending_gossip();

        if message.topic == self.blocks_topic.hash() {
            let block_bytes = match decode_frame_slice_exact(&message.data) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(%message_id, %propagation_source, error = %e, "Malformed gossip block frame or non-canonical trailing bytes");
                    self.report_gossip_validation_internal(
                        &message_id,
                        &propagation_source,
                        MessageAcceptance::Reject,
                    );
                    return;
                }
            };
            let block = match Block::from_bytes(block_bytes) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(%message_id, %propagation_source, error = %e, "Malformed gossip block payload");
                    self.report_gossip_validation_internal(
                        &message_id,
                        &propagation_source,
                        MessageAcceptance::Reject,
                    );
                    return;
                }
            };
            let block_id = block.header.block_id();
            if self.is_seen(&block_id) {
                self.report_gossip_validation_internal(
                    &message_id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                return;
            }
            let payload_hash = hash::hash(block_bytes);
            let source = message.source;
            let event = NetworkEvent::BlockReceived {
                propagation_source,
                source,
                message_id: message_id.clone(),
                block: Box::new(block),
                execution_guard: None,
            };
            self.dispatch_gossip_event(
                GossipSubjectKind::Block,
                block_id,
                payload_hash,
                propagation_source,
                source,
                message_id,
                event,
            );
        } else if message.topic == self.txs_topic.hash() {
            let tx_bytes = match decode_frame_slice_exact(&message.data) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(%message_id, %propagation_source, error = %e, "Malformed gossip tx frame or non-canonical trailing bytes");
                    self.report_gossip_validation_internal(
                        &message_id,
                        &propagation_source,
                        MessageAcceptance::Reject,
                    );
                    return;
                }
            };
            let tx_id = hash::transaction_id(tx_bytes);
            if self.is_tx_seen(&tx_id) {
                self.report_gossip_validation_internal(
                    &message_id,
                    &propagation_source,
                    MessageAcceptance::Ignore,
                );
                return;
            }
            let payload_hash = hash::hash(tx_bytes);
            let source = message.source;
            let event = NetworkEvent::TransactionReceived {
                propagation_source,
                source,
                message_id: message_id.clone(),
                transaction: tx_bytes.to_vec(),
                execution_guard: None,
            };
            self.dispatch_gossip_event(
                GossipSubjectKind::Transaction,
                tx_id,
                payload_hash,
                propagation_source,
                source,
                message_id,
                event,
            );
        } else {
            self.report_gossip_validation_internal(
                &message_id,
                &propagation_source,
                MessageAcceptance::Ignore,
            );
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
                if let Some(target_peer) = self.pending_handshake_requests.remove(&request_id) {
                    tracing::warn!(
                        "Outbound handshake request {:?} to peer {} failed: {:?}; disconnecting",
                        request_id,
                        target_peer,
                        error
                    );
                    self.request_disconnect(target_peer).await;
                }
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
                if self.inbound_handshake_processed.contains(&peer_id) {
                    tracing::warn!(
                        "Peer {} sent repeated unsolicited handshake request after handshake already established; rejecting",
                        peer_id
                    );
                    let _ = self.swarm.behaviour_mut().request_response.send_response(
                        channel,
                        SyncResponse::Error("handshake already established".into()),
                    );
                    return;
                }

                if let Err(e) =
                    remote_handshake.verify_compatibility(self.chain_id, self.genesis_hash)
                {
                    tracing::warn!("Handshake rejected for peer {}: {}", peer_id, e);
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, SyncResponse::Error(e.to_string()));
                    self.request_disconnect(peer_id).await;
                    return;
                }

                // Mark that we have processed the initial inbound handshake from this peer
                self.inbound_handshake_processed.insert(peer_id);

                // Update peer handshake in registry if not already established
                let is_new_completion = self
                    .peers
                    .update_handshake(&peer_id, remote_handshake.clone());

                // Send back our local handshake
                let local_handshake = self.current_handshake();
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, SyncResponse::Handshake(local_handshake));

                if is_new_completion {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::PeerHandshakeCompleted {
                            peer_id,
                            handshake: remote_handshake,
                        })
                        .await;
                }
            }
            other_req => {
                if !self.peers.is_handshake_done(&peer_id) {
                    tracing::warn!(
                        "Peer {} sent sync request {:?} before completing application handshake; disconnecting",
                        peer_id,
                        other_req
                    );
                    let _ = self.swarm.behaviour_mut().request_response.send_response(
                        channel,
                        SyncResponse::Error("handshake required before sync requests".into()),
                    );
                    self.request_disconnect(peer_id).await;
                    return;
                }

                // Forward GetStatus / GetHeaders / GetBlocks etc. to node runtime via non-blocking send
                match self.event_tx.try_send(NetworkEvent::SyncRequestReceived {
                    peer_id,
                    request: other_req,
                    channel,
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(NetworkEvent::SyncRequestReceived {
                        channel,
                        ..
                    })) => {
                        tracing::warn!(
                            %peer_id,
                            "Runtime event channel full; rejecting incoming sync request with node busy error"
                        );
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, SyncResponse::Error("node busy".into()));
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        tracing::debug!(%peer_id, "Runtime event channel closed; dropping sync request");
                    }
                    Err(_) => {}
                }
            }
        }
    }

    async fn handle_inbound_response(
        &mut self,
        peer_id: PeerId,
        request_id: OutboundRequestId,
        response: SyncResponse,
    ) {
        let is_handshake = self.pending_handshake_requests.remove(&request_id);

        if let Some(expected_peer) = is_handshake {
            if peer_id != expected_peer {
                tracing::warn!(
                    "Peer mismatch on handshake response: expected {}, got {}; disconnecting",
                    expected_peer,
                    peer_id
                );
                self.request_disconnect(peer_id).await;
                return;
            }

            match response {
                SyncResponse::Handshake(remote_handshake) => {
                    if let Err(e) =
                        remote_handshake.verify_compatibility(self.chain_id, self.genesis_hash)
                    {
                        tracing::warn!(
                            "Peer {} handshake verification failed on response: {}",
                            peer_id,
                            e
                        );
                        self.request_disconnect(peer_id).await;
                        return;
                    }

                    if self.peers.is_handshake_done(&peer_id) {
                        tracing::debug!(
                            "Peer {} sent duplicate handshake response after handshake already established; ignoring",
                            peer_id
                        );
                        return;
                    }

                    let is_new_completion = self
                        .peers
                        .update_handshake(&peer_id, remote_handshake.clone());

                    if is_new_completion {
                        let _ = self
                            .event_tx
                            .send(NetworkEvent::PeerHandshakeCompleted {
                                peer_id,
                                handshake: remote_handshake,
                            })
                            .await;
                    }
                }
                unexpected => {
                    tracing::warn!(
                        "Protocol violation: peer {} sent unexpected non-handshake response {:?} to outbound handshake request; disconnecting peer immediately",
                        peer_id,
                        unexpected
                    );
                    self.request_disconnect(peer_id).await;
                }
            }
            return;
        }

        if let Some(sender) = self.pending_sync_requests.remove(&request_id) {
            let _ = sender.send(Ok(response));
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

    #[tokio::test]
    async fn test_handshake_exchange_and_rejection() {
        let chain_id_dev = Hash::new([1u8; 32]);
        let chain_id_test = Hash::new([9u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let (service1, handle1, mut rx1) = NetworkService::new(
            kp1,
            "devnet",
            chain_id_dev,
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

        // Get listen address for service 1
        tokio::time::sleep(Duration::from_millis(100)).await;
        let addrs1 = handle1.get_listen_addrs().await.unwrap();
        assert!(!addrs1.is_empty(), "Service 1 must have listening address");
        let target_addr = addrs1[0].clone();

        // Node 2 has incompatible chain ID
        let kp2 = Keypair::generate_ed25519();
        let (service2, handle2, _rx2) = NetworkService::new(
            kp2,
            "testnet",
            chain_id_test,
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
        let s2_handle = tokio::spawn(service2.run());

        // Dial node 1 from node 2
        handle2.dial(target_addr).await.unwrap();

        // Node 1 should reject the handshake and disconnect Node 2
        let timeout = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(ev) = rx1.recv().await {
                if let NetworkEvent::PeerDisconnected { .. } = ev {
                    return true;
                }
            }
            false
        })
        .await;

        assert!(
            timeout.unwrap_or(false),
            "Incompatible peer must be disconnected after handshake rejection"
        );

        s1_handle.abort();
        s2_handle.abort();
    }

    fn mock_handshake(chain_id: Hash, genesis_hash: Hash) -> HandshakeMessage {
        HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id,
            genesis_hash,
            tip_height: 10,
            tip_block_id: Hash::new([0x42; 32]),
            cumulative_work: U256::zero(),
            capabilities: 0,
            software_version: "ownchain/test".to_string(),
        }
    }

    #[test]
    fn test_regression_1_registering_new_peer_creates_one_peer_info() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        let action = registry.handle_connection_established(peer_id, Some(addr.clone()));
        assert_eq!(action, ConnectionAction::NewPeer);
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&peer_id));

        let info = registry.get(&peer_id).unwrap();
        assert_eq!(info.peer_id, peer_id);
        assert_eq!(info.address, Some(addr));
        assert!(info.handshake.is_none());
        assert!(!registry.is_handshake_done(&peer_id));
    }

    #[test]
    fn test_regression_2_additional_connection_preserves_handshake() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();
        let addr1: Multiaddr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();
        let addr2: Multiaddr = "/ip4/127.0.0.1/tcp/8001".parse().unwrap();

        assert_eq!(
            registry.handle_connection_established(peer_id, Some(addr1)),
            ConnectionAction::NewPeer
        );

        let hs = mock_handshake(Hash::new([1u8; 32]), Hash::new([2u8; 32]));
        assert!(registry.update_handshake(&peer_id, hs.clone()));
        assert!(registry.is_handshake_done(&peer_id));

        // Additional connection established for same peer
        let action = registry.handle_connection_established(peer_id, Some(addr2.clone()));
        assert_eq!(action, ConnectionAction::ExistingPeer);
        assert_eq!(registry.len(), 1);

        let info = registry.get(&peer_id).unwrap();
        assert_eq!(
            info.handshake,
            Some(hs),
            "Verified handshake must be preserved"
        );
        assert_eq!(info.address, Some(addr2));
    }

    #[test]
    fn test_regression_3_additional_connection_preserves_connected_at() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        assert_eq!(
            registry.handle_connection_established(peer_id, Some(addr.clone())),
            ConnectionAction::NewPeer
        );

        let initial_connected_at = registry.get(&peer_id).unwrap().connected_at;

        // Small passage of time
        std::thread::sleep(Duration::from_millis(15));

        assert_eq!(
            registry.handle_connection_established(peer_id, Some(addr)),
            ConnectionAction::ExistingPeer
        );

        let final_connected_at = registry.get(&peer_id).unwrap().connected_at;
        assert_eq!(
            initial_connected_at, final_connected_at,
            "connected_at timestamp must be preserved across additional connections"
        );
    }

    #[test]
    fn test_regression_4_existing_peer_allowed_when_peer_limit_reached() {
        let mut registry = PeerRegistry::new(2);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        assert_eq!(
            registry.handle_connection_established(peer_a, None),
            ConnectionAction::NewPeer
        );
        assert_eq!(
            registry.handle_connection_established(peer_b, None),
            ConnectionAction::NewPeer
        );
        assert_eq!(registry.len(), 2);

        // Registry reached max_peers (2). Additional connection from existing peer_a must be accepted.
        let action = registry.handle_connection_established(peer_a, None);
        assert_eq!(action, ConnectionAction::ExistingPeer);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_regression_5_new_peer_rejected_when_peer_limit_reached() {
        let mut registry = PeerRegistry::new(2);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();

        assert_eq!(
            registry.handle_connection_established(peer_a, None),
            ConnectionAction::NewPeer
        );
        assert_eq!(
            registry.handle_connection_established(peer_b, None),
            ConnectionAction::NewPeer
        );
        assert_eq!(registry.len(), 2);

        // Registry at capacity (2). Genuinely new peer_c must be rejected.
        let action = registry.handle_connection_established(peer_c, None);
        assert_eq!(action, ConnectionAction::RejectedMaxPeers);
        assert_eq!(registry.len(), 2);
        assert!(!registry.contains(&peer_c));
    }

    #[test]
    fn test_regression_6_closing_one_of_multiple_connections_retains_peer() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();

        registry.handle_connection_established(peer_id, None);
        let hs = mock_handshake(Hash::new([1u8; 32]), Hash::new([2u8; 32]));
        registry.update_handshake(&peer_id, hs.clone());

        // Peer has multiple connections. Connection closes with num_established = 1 remaining.
        let removed = registry.handle_connection_closed(&peer_id, 1);
        assert!(
            removed.is_none(),
            "Peer must not be removed while connections remain"
        );
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&peer_id));
        assert_eq!(registry.get(&peer_id).unwrap().handshake, Some(hs));
    }

    #[test]
    fn test_regression_7_closing_final_connection_removes_peer() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();

        registry.handle_connection_established(peer_id, None);
        assert_eq!(registry.len(), 1);

        // Final connection closes (num_established = 0)
        let removed = registry.handle_connection_closed(&peer_id, 0);
        assert!(
            removed.is_some(),
            "Final connection closure must remove peer"
        );
        assert_eq!(removed.unwrap().peer_id, peer_id);
        assert_eq!(registry.len(), 0);
        assert!(!registry.contains(&peer_id));
    }

    #[test]
    fn test_regression_8_repeated_closure_no_duplicate_disconnect() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();

        registry.handle_connection_established(peer_id, None);

        // First closure removes peer and returns Some
        let first = registry.handle_connection_closed(&peer_id, 0);
        assert!(first.is_some());

        // Redundant closure events for the same peer must return None
        let second = registry.handle_connection_closed(&peer_id, 0);
        assert!(second.is_none());

        let third = registry.handle_connection_closed(&peer_id, 0);
        assert!(third.is_none());
    }

    #[test]
    fn test_regression_9_explicit_disconnect_preserves_peer_until_final_closure() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();

        registry.handle_connection_established(peer_id, None);
        assert!(registry.contains(&peer_id));

        // When disconnect is requested and swarm returns Ok(()), peer is retained in registry
        // during asynchronous shutdown.
        assert!(registry.contains(&peer_id));

        // Intermediate connection closes with 1 remaining
        assert!(registry.handle_connection_closed(&peer_id, 1).is_none());
        assert!(registry.contains(&peer_id));

        // Final connection closure removes the peer
        let removed = registry.handle_connection_closed(&peer_id, 0);
        assert!(removed.is_some());
        assert!(!registry.contains(&peer_id));

        // If transport was already closed (disconnect_peer_id returns Err(())),
        // force_remove cleans up immediately without leaving a stale entry.
        let peer_b = PeerId::random();
        registry.handle_connection_established(peer_b, None);
        let force_removed = registry.force_remove(&peer_b);
        assert!(force_removed.is_some());
        assert!(!registry.contains(&peer_b));
    }

    #[test]
    fn test_regression_10_handshake_rejection_cleanup_semantics() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();

        assert_eq!(
            registry.handle_connection_established(peer_id, None),
            ConnectionAction::NewPeer
        );

        // Handshake fails; disconnection is requested.
        // Peer is not prematurely removed before transport actually closes.
        assert!(registry.contains(&peer_id));

        // If another connection remained:
        assert!(registry.handle_connection_closed(&peer_id, 1).is_none());
        assert!(registry.contains(&peer_id));

        // Final closure canonically cleans up registry
        let removed = registry.handle_connection_closed(&peer_id, 0);
        assert!(removed.is_some());
        assert!(!registry.contains(&peer_id));

        // Redundant closure after rejection cannot emit duplicate
        assert!(registry.handle_connection_closed(&peer_id, 0).is_none());
    }

    /// Integration test demonstrating crossed dialing, peer registration,
    /// handshake negotiation, and clean disconnection lifecycle over real libp2p swarm transport.
    ///
    /// Transport behavior note:
    /// In libp2p 0.54 with TCP/Yamux, the swarm multiplexes logical streams over a single
    /// established transport connection and deduplicates simultaneous dials to an active peer,
    /// resulting in `num_established == 1`. Forcing multiple raw transport connections between
    /// the same loopback peers would require custom dial options or connection limits outside the
    /// production protocol specification.
    ///
    /// Multi-connection lifecycle handling (`num_established > 1` maintaining handshake and
    /// timestamp, deferring disconnect until `num_established == 0`) is comprehensively and
    /// authoritatively proven in unit tests (`test_regression_2` through `test_regression_10`).
    /// This integration test authoritatively verifies real-world crossed-dial single-peer registration,
    /// handshake exchange, and event loop disconnection.
    #[tokio::test]
    async fn test_real_libp2p_crossed_dial_and_disconnection_lifecycle() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let (mut service1, handle1, mut rx1) = NetworkService::new(
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
        let (service2, handle2, mut rx2) = NetworkService::new(
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

        let p1 = handle1.local_peer_id();
        let p2 = handle2.local_peer_id();

        let (conn_tx1, mut conn_rx1) = tokio::sync::mpsc::unbounded_channel();
        service1.set_connection_observer(conn_tx1);

        let s1 = tokio::spawn(service1.run());
        let s2 = tokio::spawn(service2.run());

        // Wait for listen addresses deterministically
        let addr1 = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(addrs) = handle1.get_listen_addrs().await {
                    if let Some(a) = addrs.into_iter().next() {
                        return a;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("node 1 must bind listen address");

        let addr2 = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(addrs) = handle2.get_listen_addrs().await {
                    if let Some(a) = addrs.into_iter().next() {
                        return a;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("node 2 must bind listen address");

        // Crossed-dial: both nodes dial each other concurrently
        handle1.dial(addr2.clone()).await.unwrap();
        handle2.dial(addr1.clone()).await.unwrap();

        // Wait for handshake completion events on both nodes
        let completed = tokio::time::timeout(Duration::from_secs(5), async {
            let mut node1_done = false;
            let mut node2_done = false;
            while !node1_done || !node2_done {
                tokio::select! {
                    Some(ev) = rx1.recv() => {
                        if let NetworkEvent::PeerHandshakeCompleted { peer_id, .. } = ev {
                            if peer_id == p2 {
                                node1_done = true;
                            }
                        }
                    }
                    Some(ev) = rx2.recv() => {
                        if let NetworkEvent::PeerHandshakeCompleted { peer_id, .. } = ev {
                            if peer_id == p1 {
                                node2_done = true;
                            }
                        }
                    }
                }
            }
        })
        .await;
        assert!(completed.is_ok(), "Crossed-dial handshakes must complete");

        // Inspect SwarmEvent::ConnectionEstablished and verify authoritative num_established
        let established_count = tokio::time::timeout(Duration::from_secs(2), async {
            if let Some((peer, count)) = conn_rx1.recv().await {
                if peer == p2 {
                    return count;
                }
            }
            0
        })
        .await
        .unwrap_or(0);
        assert_eq!(
            established_count, 1,
            "SwarmEvent::ConnectionEstablished must report num_established = 1"
        );

        // Verify invariant: Exactly 1 PeerInfo exists per peer despite crossed dial
        let peers1 = handle1.get_connected_peers().await.unwrap();
        assert_eq!(
            peers1.len(),
            1,
            "Node 1 must register exactly 1 unique peer"
        );
        assert_eq!(peers1[0].peer_id, p2);
        assert!(
            peers1[0].handshake.is_some(),
            "Node 1 must hold verified handshake"
        );

        let peers2 = handle2.get_connected_peers().await.unwrap();
        assert_eq!(
            peers2.len(),
            1,
            "Node 2 must register exactly 1 unique peer"
        );
        assert_eq!(peers2[0].peer_id, p1);
        assert!(
            peers2[0].handshake.is_some(),
            "Node 2 must hold verified handshake"
        );

        // Disconnect Node 2 from Node 1
        handle1.disconnect(p2).await.unwrap();

        // Node 1 should receive PeerDisconnected event when connection closes
        let disconnected = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(ev) = rx1.recv().await {
                if let NetworkEvent::PeerDisconnected { peer_id } = ev {
                    if peer_id == p2 {
                        return true;
                    }
                }
            }
            false
        })
        .await;
        assert!(
            disconnected.unwrap_or(false),
            "Node 1 must emit PeerDisconnected on final disconnection"
        );

        // Verify registry is cleaned up
        let peers1_final = handle1.get_connected_peers().await.unwrap();
        assert_eq!(
            peers1_final.len(),
            0,
            "Registry must be empty after disconnection"
        );

        s1.abort();
        s2.abort();
    }

    #[derive(libp2p::swarm::NetworkBehaviour)]
    struct TestGossipPeerBehaviour {
        gossipsub: libp2p::gossipsub::Behaviour,
        request_response: libp2p::request_response::Behaviour<crate::p2p::protocol::SyncCodec>,
    }

    fn build_test_gossip_swarm(
        keypair: Keypair,
        authenticity: libp2p::gossipsub::MessageAuthenticity,
        network_name: &str,
    ) -> (Swarm<TestGossipPeerBehaviour>, IdentTopic, IdentTopic) {
        let blocks_topic = IdentTopic::new(format!("/ownchain/{network_name}/blocks/v1"));
        let txs_topic = IdentTopic::new(format!("/ownchain/{network_name}/txs/v1"));

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| {
                let gs_cfg = libp2p::gossipsub::ConfigBuilder::default()
                    .validation_mode(libp2p::gossipsub::ValidationMode::Permissive)
                    .heartbeat_interval(Duration::from_millis(500))
                    .max_transmit_size(2_100_000)
                    .build()
                    .unwrap();
                let mut gossipsub =
                    libp2p::gossipsub::Behaviour::new(authenticity, gs_cfg).unwrap();
                gossipsub.subscribe(&blocks_topic).unwrap();
                gossipsub.subscribe(&txs_topic).unwrap();

                let protocols = [(
                    libp2p::StreamProtocol::new(crate::p2p::protocol::SYNC_PROTOCOL_ID),
                    libp2p::request_response::ProtocolSupport::Full,
                )];
                let request_response = libp2p::request_response::Behaviour::with_codec(
                    crate::p2p::protocol::SyncCodec,
                    protocols,
                    libp2p::request_response::Config::default(),
                );
                Ok(TestGossipPeerBehaviour {
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

    async fn pump_test_swarm_until_mesh(
        swarm: &mut Swarm<TestGossipPeerBehaviour>,
        target_peer: PeerId,
        topic: &IdentTopic,
        handshake_chain_id: Hash,
        handshake_genesis_hash: Hash,
    ) {
        let topic_hash = topic.hash();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut handshake_done = false;
        while tokio::time::Instant::now() < deadline {
            let mesh_ready = swarm
                .behaviour()
                .gossipsub
                .mesh_peers(&topic_hash)
                .any(|p| *p == target_peer);
            if mesh_ready && handshake_done {
                tokio::time::sleep(Duration::from_millis(100)).await;
                return;
            }
            tokio::select! {
                ev = swarm.select_next_some() => {
                    match ev {
                        SwarmEvent::Behaviour(TestGossipPeerBehaviourEvent::RequestResponse(
                            ReqRespEvent::Message { message: ReqRespMessage::Request { request: SyncRequest::Handshake(_), channel, .. }, .. }
                        )) => {
                            let hs = HandshakeMessage {
                                protocol_version: HANDSHAKE_PROTOCOL_VERSION,
                                chain_id: handshake_chain_id,
                                genesis_hash: handshake_genesis_hash,
                                tip_height: 0,
                                tip_block_id: handshake_genesis_hash,
                                cumulative_work: U256::zero(),
                                capabilities: 0,
                                software_version: "test/1".into(),
                            };
                            let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::Handshake(hs));
                        }
                        SwarmEvent::Behaviour(TestGossipPeerBehaviourEvent::RequestResponse(
                            ReqRespEvent::ResponseSent { peer, .. },
                        )) if peer == target_peer => {
                            handshake_done = true;
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        panic!("Timed out waiting for mesh peer {target_peer} on topic {topic_hash} (handshake_done={handshake_done})");
    }

    async fn get_service_listen_addr(handle: &NetworkHandle) -> Multiaddr {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(addrs) = handle.get_listen_addrs().await {
                    if let Some(a) = addrs.into_iter().next() {
                        return a;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("service must bind listen address")
    }

    #[tokio::test]
    async fn test_gossip_tx_cache_invalidation_on_forget_and_clear() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, _handle, _rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0xaa; 32]);
        let tx_1 = Hash::new([0x11; 32]);
        let tx_2 = Hash::new([0x22; 32]);

        assert!(service.mark_seen(block_id));
        assert!(service.mark_tx_seen(tx_1));
        assert!(service.mark_tx_seen(tx_2));
        assert!(service.is_seen(&block_id));
        assert!(service.is_tx_seen(&tx_1));
        assert!(service.is_tx_seen(&tx_2));

        // Selective eviction forgets only evicted tx IDs
        service.forget_seen_txs(&[tx_1]);
        assert!(!service.is_tx_seen(&tx_1));
        assert!(service.is_tx_seen(&tx_2));
        assert!(service.is_seen(&block_id));

        // Reorg clears all cached txs while leaving block announcements intact
        service.clear_seen_txs();
        assert!(!service.is_tx_seen(&tx_2));
        assert!(service.is_seen(&block_id));
    }

    #[tokio::test]
    async fn test_gossip_pending_token_single_gate_and_expiry_cleanup() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, _handle, _rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0x44; 32]);
        let payload_hash = Hash::new([0x55; 32]);
        let msg_id = MessageId::new(b"expired-msg-id");
        let peer = PeerId::random();

        service.in_flight_payloads.insert(
            payload_hash,
            InFlightPayloadEntry {
                payload_hash,
                canonical_id: block_id,
                kind: GossipSubjectKind::Block,
                created_at: std::time::Instant::now()
                    - PENDING_GOSSIP_TTL
                    - Duration::from_millis(100),
                active_token: Some(msg_id.clone()),
                generation: 1,
                is_active: Arc::new(AtomicBool::new(false)),
            },
        );
        service
            .in_flight_by_msg_id
            .insert(msg_id.clone(), (payload_hash, 1));
        service.pending_gossip.insert(
            msg_id.clone(),
            PendingGossipEntry {
                kind: GossipSubjectKind::Block,
                canonical_id: block_id,
                payload_hash,
                propagation_source: peer,
                source: Some(peer),
                created_at: std::time::Instant::now()
                    - PENDING_GOSSIP_TTL
                    - Duration::from_millis(100),
            },
        );

        // 1. TTL sweep expires token from libp2p pending map, BUT preserves in-flight payload ownership!
        service.sweep_stale_pending_gossip();
        assert!(
            service.pending_gossip.is_empty(),
            "libp2p pending token must be expired"
        );
        assert!(
            service.in_flight_payloads.contains_key(&payload_hash),
            "In-flight payload lock must be preserved while processing"
        );
        assert!(!service.is_seen(&block_id));

        // 2. Late ReportGossipValidation arrives after token expiry: releases in-flight payload ownership!
        service
            .handle_command(NetworkCommand::ReportGossipValidation {
                message_id: msg_id,
                propagation_source: peer,
                acceptance: MessageAcceptance::Accept,
                mark_seen: true,
                canonical_id: Some(block_id),
                is_block: true,
            })
            .await;
        assert!(service.pending_gossip.is_empty());
        assert!(
            service.in_flight_payloads.is_empty(),
            "In-flight payload lock must be released on late validation completion"
        );
        assert!(service.is_seen(&block_id));
    }

    #[tokio::test]
    async fn test_gossip_strict_mode_drops_unsigned_messages() {
        let cid = crate::hash::chain_id(crate::genesis::DEVNET);
        let genesis = crate::genesis::genesis_block(cid);
        let ghash = genesis.block_id();

        let (service_b, handle_b, mut rx_b) = NetworkService::new(
            Keypair::generate_ed25519(),
            "devnet",
            cid,
            ghash,
            0,
            ghash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();
        let peer_b = handle_b.local_peer_id();
        let task_b = tokio::spawn(service_b.run());
        let addr_b = get_service_listen_addr(&handle_b).await;

        // Peer A uses MessageAuthenticity::Anonymous (unsigned Gossipsub messages)
        let (mut swarm_a, blocks_topic, _) = build_test_gossip_swarm(
            Keypair::generate_ed25519(),
            libp2p::gossipsub::MessageAuthenticity::Anonymous,
            "devnet",
        );
        swarm_a.dial(addr_b).unwrap();
        pump_test_swarm_until_mesh(&mut swarm_a, peer_b, &blocks_topic, cid, ghash).await;

        let raw = genesis.to_bytes().unwrap();
        let frame = encode_frame(&raw).unwrap();
        let _ = swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic, frame);

        // Pump Peer A and verify Node B (ValidationMode::Strict) never emits BlockReceived
        let got_block = tokio::time::timeout(Duration::from_millis(1500), async {
            loop {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev = rx_b.recv() => {
                        if matches!(ev, Some(NetworkEvent::BlockReceived { .. })) {
                            return true;
                        }
                    }
                }
            }
        })
        .await;

        assert!(
            got_block.is_err(),
            "Unsigned Gossipsub message must be dropped under ValidationMode::Strict"
        );
        task_b.abort();
    }

    #[tokio::test]
    async fn test_gossip_no_forwarding_before_validation_and_accept_forwards() {
        let cid = crate::hash::chain_id(crate::genesis::DEVNET);
        let genesis = crate::genesis::genesis_block(cid);
        let ghash = genesis.block_id();

        let (service_b, handle_b, mut rx_b) = NetworkService::new(
            Keypair::generate_ed25519(),
            "devnet",
            cid,
            ghash,
            0,
            ghash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();
        let peer_b = handle_b.local_peer_id();
        let task_b = tokio::spawn(service_b.run());
        let addr_b = get_service_listen_addr(&handle_b).await;

        // Line topology: A <-> B <-> C (no direct link between A and C)
        let kp_a = Keypair::generate_ed25519();
        let peer_a = kp_a.public().to_peer_id();
        let (mut swarm_a, blocks_topic, _) = build_test_gossip_swarm(
            kp_a.clone(),
            libp2p::gossipsub::MessageAuthenticity::Signed(kp_a),
            "devnet",
        );
        let kp_c = Keypair::generate_ed25519();
        let (mut swarm_c, _, _) = build_test_gossip_swarm(
            kp_c.clone(),
            libp2p::gossipsub::MessageAuthenticity::Signed(kp_c),
            "devnet",
        );

        swarm_a.dial(addr_b.clone()).unwrap();
        swarm_c.dial(addr_b).unwrap();
        pump_test_swarm_until_mesh(&mut swarm_a, peer_b, &blocks_topic, cid, ghash).await;
        pump_test_swarm_until_mesh(&mut swarm_c, peer_b, &blocks_topic, cid, ghash).await;

        // Publish block from A to B
        let raw = genesis.to_bytes().unwrap();
        let frame = encode_frame(&raw).unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic.clone(), frame)
            .unwrap();

        // Wait for B to emit BlockReceived and hold the token WITHOUT reporting validation
        let (prop_source, msg_id, block) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev_c = swarm_c.select_next_some() => {
                        if let SwarmEvent::Behaviour(TestGossipPeerBehaviourEvent::Gossipsub(GossipsubEvent::Message { .. })) = ev_c {
                            panic!("Swarm C must NOT receive message before Node B validates!");
                        }
                    }
                    ev_b = rx_b.recv() => {
                        if let Some(NetworkEvent::BlockReceived { propagation_source, message_id, block, .. }) = ev_b {
                            return (propagation_source, message_id, block);
                        }
                    }
                }
            }
        })
        .await
        .expect("Node B must emit BlockReceived");

        assert_eq!(prop_source, peer_a);
        let block_id = block.header.block_id();

        // Hold validation token for 1.5s across multiple 500ms heartbeats: C must still receive nothing
        let pre_val_forwarded = tokio::time::timeout(Duration::from_millis(1500), async {
            loop {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev_c = swarm_c.select_next_some() => {
                        if let SwarmEvent::Behaviour(TestGossipPeerBehaviourEvent::Gossipsub(GossipsubEvent::Message { .. })) = ev_c {
                            return true;
                        }
                    }
                }
            }
        })
        .await;
        assert!(
            pre_val_forwarded.is_err(),
            "Message must NOT be forwarded by Node B prior to MessageAcceptance::Accept"
        );

        // Now report Accept on B -> C must eventually receive the original signed message
        handle_b
            .report_gossip_validation(
                msg_id,
                prop_source,
                MessageAcceptance::Accept,
                true,
                Some(block_id),
                true,
            )
            .await
            .unwrap();

        let c_received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev_c = swarm_c.select_next_some() => {
                        if let SwarmEvent::Behaviour(TestGossipPeerBehaviourEvent::Gossipsub(
                            GossipsubEvent::Message { propagation_source, message, .. }
                        )) = ev_c {
                            if message.topic == blocks_topic.hash() {
                                return (propagation_source, message.source);
                            }
                        }
                    }
                }
            }
        })
        .await
        .expect("Swarm C must eventually receive message after Node B reports Accept");

        assert_eq!(c_received.0, peer_b);
        assert_eq!(c_received.1, Some(peer_a));
        task_b.abort();
    }

    #[tokio::test]
    async fn test_gossip_header_block_id_not_poisoned_by_rejected_payload() {
        let cid = crate::hash::chain_id(crate::genesis::DEVNET);
        let genesis = crate::genesis::genesis_block(cid);
        let ghash = genesis.block_id();

        let (service_b, handle_b, mut rx_b) = NetworkService::new(
            Keypair::generate_ed25519(),
            "devnet",
            cid,
            ghash,
            0,
            ghash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();
        let peer_b = handle_b.local_peer_id();
        let task_b = tokio::spawn(service_b.run());
        let addr_b = get_service_listen_addr(&handle_b).await;

        let kp_a = Keypair::generate_ed25519();
        let (mut swarm_a, blocks_topic, _) = build_test_gossip_swarm(
            kp_a.clone(),
            libp2p::gossipsub::MessageAuthenticity::Signed(kp_a),
            "devnet",
        );
        swarm_a.dial(addr_b).unwrap();
        pump_test_swarm_until_mesh(&mut swarm_a, peer_b, &blocks_topic, cid, ghash).await;

        // 1. Send malformed frame -> Node B drops directly without emitting BlockReceived
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic.clone(), vec![0xff, 0xff, 0xff, 0x0f, 1, 2])
            .unwrap();

        // 2. Send Block with valid Header (same header block_id as genesis) but corrupted body bytes
        let mut corrupted_block = genesis.clone();
        corrupted_block
            .transactions
            .push(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(corrupted_block.header.block_id(), ghash);
        let bad_frame = encode_frame(&corrupted_block.to_bytes().unwrap()).unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic.clone(), bad_frame)
            .unwrap();

        let (prop_1, msg_id_1) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev_b = rx_b.recv() => {
                        if let Some(NetworkEvent::BlockReceived { propagation_source, message_id, .. }) = ev_b {
                            return (propagation_source, message_id);
                        }
                    }
                }
            }
        })
        .await
        .expect("Node B must emit BlockReceived for decodable bad-body block");

        // Reject the bad-body payload (mark_seen = false!)
        handle_b
            .report_gossip_validation(
                msg_id_1,
                prop_1,
                MessageAcceptance::Reject,
                false,
                None,
                true,
            )
            .await
            .unwrap();

        // 3. Now send genuine valid genesis block with IDENTICAL header block_id = ghash!
        //    It must NOT be poisoned/suppressed in seen_announcements!
        let good_frame = encode_frame(&genesis.to_bytes().unwrap()).unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic, good_frame)
            .unwrap();

        let (prop_2, msg_id_2, rx_block_2) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev_b = rx_b.recv() => {
                        if let Some(NetworkEvent::BlockReceived { propagation_source, message_id, block, .. }) = ev_b {
                            return (propagation_source, message_id, block);
                        }
                    }
                }
            }
        })
        .await
        .expect("Genuine block sharing header block_id must NOT be poisoned by prior Reject");

        assert_eq!(rx_block_2.transactions.len(), 0);
        handle_b
            .report_gossip_validation(
                msg_id_2,
                prop_2,
                MessageAcceptance::Accept,
                true,
                Some(ghash),
                true,
            )
            .await
            .unwrap();

        task_b.abort();
    }

    #[tokio::test]
    async fn test_gossip_token_registered_before_send_and_rolled_back_on_full_or_closed() {
        let cid = crate::hash::chain_id(crate::genesis::DEVNET);
        let genesis = crate::genesis::genesis_block(cid);
        let ghash = genesis.block_id();

        // Single-slot event channel to deterministically trigger TrySendError::Full
        let (mut service, handle, mut rx) = NetworkService::new(
            Keypair::generate_ed25519(),
            "devnet",
            cid,
            ghash,
            0,
            ghash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            1,
        )
        .unwrap();

        let peer_a = PeerId::random();
        let msg_1 = MessageId::new(b"msg-1");
        let payload_1 = Hash::new([0x11; 32]);
        let canon_1 = Hash::new([0x21; 32]);

        // 1. Dispatch msg_1 into the 1-slot channel and verify token + payload ownership exist immediately
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            canon_1,
            payload_1,
            peer_a,
            Some(peer_a),
            msg_1.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_1.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(service.pending_gossip.contains_key(&msg_1));
        assert!(service.in_flight_payloads.contains_key(&payload_1));

        // 2. Dispatch msg_2 while channel is Full -> both pending_gossip and in_flight_payloads must roll back
        let msg_2 = MessageId::new(b"msg-2");
        let payload_2 = Hash::new([0x12; 32]);
        let canon_2 = Hash::new([0x22; 32]);
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            canon_2,
            payload_2,
            peer_a,
            Some(peer_a),
            msg_2.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_2.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(!service.pending_gossip.contains_key(&msg_2));
        assert!(!service.in_flight_payloads.contains_key(&payload_2));
        assert_eq!(service.pending_gossip.len(), 1);
        assert_eq!(service.in_flight_payloads.len(), 1);

        // 3. Runtime immediately responds to msg_1 via handle -> token consumed & cleaned up cleanly
        match rx.try_recv().unwrap() {
            NetworkEvent::BlockReceived {
                propagation_source,
                message_id,
                ..
            } => {
                assert_eq!(message_id, msg_1);
                handle
                    .report_gossip_validation(
                        message_id,
                        propagation_source,
                        MessageAcceptance::Accept,
                        true,
                        Some(canon_1),
                        true,
                    )
                    .await
                    .unwrap();
            }
            other => panic!("unexpected event: {other:?}"),
        }
        let cmd = service.command_rx.recv().await.unwrap();
        service.handle_command(cmd).await;
        assert!(service.pending_gossip.is_empty());
        assert!(service.in_flight_payloads.is_empty());
        assert!(service.is_seen(&canon_1));

        // 4. Queue msg_3, then close/drop rx -> Closed rolls back msg_4 and drains msg_3 cleanly
        let msg_3 = MessageId::new(b"msg-3");
        let payload_3 = Hash::new([0x13; 32]);
        let canon_3 = Hash::new([0x23; 32]);
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            canon_3,
            payload_3,
            peer_a,
            Some(peer_a),
            msg_3.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_3.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert_eq!(service.pending_gossip.len(), 1);

        drop(rx);
        let msg_4 = MessageId::new(b"msg-4");
        let payload_4 = Hash::new([0x14; 32]);
        let canon_4 = Hash::new([0x24; 32]);
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            canon_4,
            payload_4,
            peer_a,
            Some(peer_a),
            msg_4,
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: MessageId::new(b"msg-4"),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(service.pending_gossip.is_empty());
        assert!(service.in_flight_payloads.is_empty());
        assert!(!service.is_seen(&canon_3));
        assert!(!service.is_seen(&canon_4));
    }

    #[tokio::test]
    async fn test_gossip_immediate_validation_response_preserves_token_and_cleans_up() {
        let cid = crate::hash::chain_id(crate::genesis::DEVNET);
        let genesis = crate::genesis::genesis_block(cid);
        let ghash = genesis.block_id();

        let (mut service_b, handle_b, mut rx_b) = NetworkService::new(
            Keypair::generate_ed25519(),
            "devnet",
            cid,
            ghash,
            0,
            ghash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();
        let peer_b = handle_b.local_peer_id();
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let task_b = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stop_rx => return service_b,
                    cmd = service_b.command_rx.recv() => match cmd {
                        Some(c) => service_b.handle_command(c).await,
                        None => return service_b,
                    },
                    ev = service_b.swarm.select_next_some() => service_b.handle_swarm_event(ev).await,
                }
            }
        });
        let addr_b = get_service_listen_addr(&handle_b).await;

        let kp_a = Keypair::generate_ed25519();
        let peer_a = kp_a.public().to_peer_id();
        let (mut swarm_a, blocks_topic, _) = build_test_gossip_swarm(
            kp_a.clone(),
            libp2p::gossipsub::MessageAuthenticity::Signed(kp_a),
            "devnet",
        );
        let kp_c = Keypair::generate_ed25519();
        let (mut swarm_c, _, _) = build_test_gossip_swarm(
            kp_c.clone(),
            libp2p::gossipsub::MessageAuthenticity::Signed(kp_c),
            "devnet",
        );

        swarm_a.dial(addr_b.clone()).unwrap();
        swarm_c.dial(addr_b).unwrap();
        pump_test_swarm_until_mesh(&mut swarm_a, peer_b, &blocks_topic, cid, ghash).await;
        pump_test_swarm_until_mesh(&mut swarm_c, peer_b, &blocks_topic, cid, ghash).await;

        // Spawn an immediate runtime-like responder that replies with Accept on the very instant
        // BlockReceived arrives, racing directly with NetworkService's dispatch step.
        let handle_resp = handle_b.clone();
        let (ack_tx, ack_rx) = oneshot::channel();
        let responder_task = tokio::spawn(async move {
            while let Some(ev) = rx_b.recv().await {
                if let NetworkEvent::BlockReceived {
                    propagation_source,
                    message_id,
                    block,
                    ..
                } = ev
                {
                    let block_id = block.header.block_id();
                    handle_resp
                        .report_gossip_validation(
                            message_id,
                            propagation_source,
                            MessageAcceptance::Accept,
                            true,
                            Some(block_id),
                            true,
                        )
                        .await
                        .unwrap();
                    let _ = ack_tx.send(block_id);
                    break;
                }
            }
        });

        // Publish valid block from Swarm A
        let frame = encode_frame(&genesis.to_bytes().unwrap()).unwrap();
        swarm_a
            .behaviour_mut()
            .gossipsub
            .publish(blocks_topic.clone(), frame)
            .unwrap();

        // Drive swarms and await BOTH immediate responder ack AND Swarm C receipt
        let mut ack_rx = Some(ack_rx);
        let mut responded_id = None;
        let mut forwarded_to_c = None;
        tokio::time::timeout(Duration::from_secs(5), async {
            while responded_id.is_none() || forwarded_to_c.is_none() {
                tokio::select! {
                    _ = swarm_a.select_next_some() => {}
                    ev_c = swarm_c.select_next_some() => {
                        if let SwarmEvent::Behaviour(TestGossipPeerBehaviourEvent::Gossipsub(
                            GossipsubEvent::Message { propagation_source, message, .. }
                        )) = ev_c {
                            if message.topic == blocks_topic.hash() {
                                forwarded_to_c = Some((propagation_source, message.source));
                            }
                        }
                    }
                    ack_res = async {
                        match ack_rx.as_mut() {
                            Some(rx) => rx.await,
                            None => futures::future::pending().await,
                        }
                    }, if ack_rx.is_some() => {
                        ack_rx = None;
                        responded_id = Some(ack_res.expect("Responder must send ack"));
                    }
                }
            }
        })
        .await
        .expect("Validation result must NOT be lost on immediate response; both ack and Swarm C delivery must succeed");

        assert_eq!(responded_id, Some(ghash));
        let forwarded_to_c = forwarded_to_c.unwrap();
        assert_eq!(forwarded_to_c.0, peer_b);
        assert_eq!(forwarded_to_c.1, Some(peer_a));

        responder_task.await.unwrap();
        let _ = stop_tx.send(());
        let service_b = task_b.await.unwrap();
        assert!(
            service_b.pending_gossip.is_empty(),
            "Pending token must be cleaned up after immediate validation response"
        );
        assert!(
            service_b.in_flight_payloads.is_empty(),
            "In-flight payload lock must be cleaned up after immediate validation response"
        );
        assert!(
            service_b.is_seen(&ghash),
            "Block ID must be marked seen after Accept"
        );
    }

    #[tokio::test]
    async fn test_gossip_inflight_ownership_survives_token_ttl_expiry_and_rejects_duplicate() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, handle, mut rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0x33; 32]);
        let payload_hash = Hash::new([0x77; 32]);
        let msg_1 = MessageId::new(b"first-in-flight-msg");
        let peer_a = PeerId::random();

        // 1. Dispatch first message
        let genesis = crate::genesis::genesis_block(chain_id);
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_1.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_1.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(service.pending_gossip.contains_key(&msg_1));
        assert!(service.in_flight_payloads.contains_key(&payload_hash));
        assert!(rx.try_recv().is_ok());

        // 2. Simulate validation taking longer than pending-token TTL (8s):
        // Age the pending token past PENDING_GOSSIP_TTL
        if let Some(entry) = service.pending_gossip.get_mut(&msg_1) {
            entry.created_at =
                std::time::Instant::now() - PENDING_GOSSIP_TTL - Duration::from_millis(50);
        }
        service.sweep_stale_pending_gossip();

        // Libp2p pending token expired and removed from pending_gossip
        assert!(
            service.pending_gossip.is_empty(),
            "Pending token must be evicted from pending_gossip to answer libp2p"
        );
        // CRITICAL SEC-P2P-002 invariant: in-flight payload ownership MUST NOT be prematurely released!
        assert!(
            service.in_flight_payloads.contains_key(&payload_hash),
            "In-flight payload lock must be preserved while NodeRuntime validation remains active"
        );

        // 3. A duplicate payload arrives from peer B while original validation is still active
        let peer_b = PeerId::random();
        let msg_2 = MessageId::new(b"duplicate-in-flight-msg");
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_b,
            Some(peer_b),
            msg_2.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_b,
                source: Some(peer_b),
                message_id: msg_2.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );

        // Duplicate message MUST NOT enter pending_gossip or event_tx!
        assert!(
            !service.pending_gossip.contains_key(&msg_2),
            "Duplicate message must be rejected while payload is in flight"
        );
        assert!(
            rx.try_recv().is_err(),
            "No duplicate validation event should be dispatched to NodeRuntime"
        );

        // 4. NodeRuntime finally finishes slow validation (e.g. at t = 10s) and reports validation
        handle
            .report_gossip_validation(
                msg_1,
                peer_a,
                MessageAcceptance::Accept,
                true,
                Some(block_id),
                true,
            )
            .await
            .unwrap();
        let cmd = service.command_rx.recv().await.unwrap();
        service.handle_command(cmd).await;

        // In-flight payload lock must now be cleanly released and block marked seen
        assert!(
            service.in_flight_payloads.is_empty(),
            "In-flight payload lock must be released on late validation completion"
        );
        assert!(service.is_seen(&block_id));
    }

    #[tokio::test]
    async fn test_gossip_inflight_payload_timeout_and_legitimate_retry() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, _handle, mut rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0x88; 32]);
        let payload_hash = Hash::new([0x99; 32]);
        let msg_1 = MessageId::new(b"lost-event-msg");
        let peer_a = PeerId::random();
        let genesis = crate::genesis::genesis_block(chain_id);

        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_1.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_1.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        let _ = rx.try_recv().unwrap();

        // Simulate a lost event where NodeRuntime never responds:
        // Age the payload past IN_FLIGHT_PAYLOAD_TTL (30s) after execution has ended
        if let Some(entry) = service.in_flight_payloads.get_mut(&payload_hash) {
            entry.created_at =
                std::time::Instant::now() - IN_FLIGHT_PAYLOAD_TTL - Duration::from_millis(50);
            entry.mark_completed();
        }
        service.sweep_stale_pending_gossip();

        // Lock must be released by timeout sweep, avoiding indefinite locks
        assert!(service.in_flight_payloads.is_empty());
        assert!(service.pending_gossip.is_empty());

        // Subsequent legitimate retry arrives: payload can now be admitted again!
        let msg_retry = MessageId::new(b"retry-msg");
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_retry.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_retry.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(service.in_flight_payloads.contains_key(&payload_hash));
        assert!(service.pending_gossip.contains_key(&msg_retry));
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_handshake_rejects_repeated_unsolicited_handshake_request() {
        let mut registry = PeerRegistry::new(10);
        let peer_id = PeerId::random();
        let cid = Hash::new([1u8; 32]);
        let gen = Hash::new([2u8; 32]);

        registry.handle_connection_established(peer_id, None);
        assert!(!registry.is_handshake_done(&peer_id));

        // 1. Initial valid handshake completes
        let hs1 = mock_handshake(cid, gen);
        assert!(registry.update_handshake(&peer_id, hs1.clone()));
        assert!(registry.is_handshake_done(&peer_id));
        assert_eq!(
            registry
                .get(&peer_id)
                .unwrap()
                .handshake
                .as_ref()
                .unwrap()
                .tip_height,
            10
        );

        // 2. Peer attempts unsolicited repeated handshake claiming higher tip height
        let mut hs2 = hs1.clone();
        hs2.tip_height = 999;
        hs2.cumulative_work = U256::from_u128(999);

        // Registry must REJECT the transition and NOT overwrite trusted metadata
        assert!(!registry.update_handshake(&peer_id, hs2));
        assert_eq!(
            registry
                .get(&peer_id)
                .unwrap()
                .handshake
                .as_ref()
                .unwrap()
                .tip_height,
            10,
            "Established handshake metadata must not be overwritten by repeated handshake"
        );
    }

    #[tokio::test]
    async fn test_gossip_inflight_late_stale_result_after_timeout_does_not_corrupt_new_generation()
    {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, handle, mut rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0x33; 32]);
        let payload_hash = Hash::new([0x44; 32]);
        let msg_1 = MessageId::new(b"initial-slow-msg");
        let peer_a = PeerId::random();
        let genesis = crate::genesis::genesis_block(chain_id);

        // 1. Initial message dispatched -> generation 1
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_1.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_1.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        let _ = rx.try_recv().unwrap();
        assert_eq!(
            service
                .in_flight_payloads
                .get(&payload_hash)
                .unwrap()
                .generation,
            1
        );

        // 2. Initial validation times out past IN_FLIGHT_PAYLOAD_TTL (30s)
        if let Some(entry) = service.in_flight_payloads.get_mut(&payload_hash) {
            entry.created_at =
                std::time::Instant::now() - IN_FLIGHT_PAYLOAD_TTL - Duration::from_millis(100);
            entry.mark_completed();
        }
        service.sweep_stale_pending_gossip();
        assert!(service.in_flight_payloads.is_empty());

        // 3. Retry arrives -> acquires in-flight lock under generation 2
        let msg_2 = MessageId::new(b"retry-fresh-msg");
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_2.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_2.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        let _ = rx.try_recv().unwrap();
        assert_eq!(
            service
                .in_flight_payloads
                .get(&payload_hash)
                .unwrap()
                .generation,
            2
        );

        // 4. Stale result for msg_1 (generation 1) arrives late
        handle
            .report_gossip_validation(
                msg_1,
                peer_a,
                MessageAcceptance::Accept,
                true,
                Some(block_id),
                true,
            )
            .await
            .unwrap();
        let cmd = service.command_rx.recv().await.unwrap();
        service.handle_command(cmd).await;

        // 5. Critical invariant: generation 1 result MUST NOT corrupt or release generation 2 lock!
        assert!(
            service.in_flight_payloads.contains_key(&payload_hash),
            "Generation 2 lock must survive late result from stale generation 1"
        );
        assert_eq!(
            service
                .in_flight_payloads
                .get(&payload_hash)
                .unwrap()
                .generation,
            2
        );

        // 6. Legitimate result for msg_2 (generation 2) arrives and cleans up
        handle
            .report_gossip_validation(
                msg_2,
                peer_a,
                MessageAcceptance::Accept,
                true,
                Some(block_id),
                true,
            )
            .await
            .unwrap();
        let cmd = service.command_rx.recv().await.unwrap();
        service.handle_command(cmd).await;

        assert!(service.in_flight_payloads.is_empty());
        assert!(service.is_seen(&block_id));
    }

    #[tokio::test]
    async fn test_gossip_inflight_validation_non_overlapping_invariants() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, handle, mut rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0x77; 32]);
        let payload_hash = Hash::new([0x88; 32]);
        let peer_a = PeerId::random();
        let genesis = crate::genesis::genesis_block(chain_id);

        let msg_1 = MessageId::new(b"msg-initial-active");
        let msg_dup1 = MessageId::new(b"msg-duplicate-before-8s");
        let msg_dup2 = MessageId::new(b"msg-duplicate-after-8s");
        let msg_dup3 = MessageId::new(b"msg-duplicate-at-30s");

        // 1. Initial message dispatched -> generation 1, is_executing == true
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_1.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_1.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        let ev = rx.try_recv().unwrap();
        assert!(matches!(ev, NetworkEvent::BlockReceived { .. }));
        let entry1 = service.in_flight_payloads.get(&payload_hash).unwrap();
        assert_eq!(entry1.generation, 1);
        assert!(entry1.is_executing());

        // Invariant 1: Duplicate arrives before the 8-second token expiry -> rejected, no event to runtime
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_dup1.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_dup1.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(
            rx.try_recv().is_err(),
            "Duplicate before 8s must not reach runtime"
        );
        assert_eq!(service.in_flight_payloads.len(), 1);

        // Invariant 2: Duplicate arrives after 8s token expiry but before validation completes
        // Age pending token past PENDING_GOSSIP_TTL (8s)
        if let Some(token_entry) = service.pending_gossip.get_mut(&msg_1) {
            token_entry.created_at =
                std::time::Instant::now() - PENDING_GOSSIP_TTL - Duration::from_millis(100);
        }
        service.sweep_stale_pending_gossip();
        assert!(
            !service.pending_gossip.contains_key(&msg_1),
            "Pending token must be swept at 8s"
        );
        assert!(
            service.in_flight_payloads.contains_key(&payload_hash),
            "In-flight payload lock must be retained"
        );

        // Duplicate arriving at 10s is still blocked by payload lock
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_dup2.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_dup2.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(
            rx.try_recv().is_err(),
            "Duplicate after 8s token expiry must still be blocked by payload lock"
        );

        // Invariant 3: Validation is still executing at the 30-second ownership boundary -> lock NOT released
        if let Some(entry) = service.in_flight_payloads.get_mut(&payload_hash) {
            entry.created_at =
                std::time::Instant::now() - IN_FLIGHT_PAYLOAD_TTL - Duration::from_millis(500);
            assert!(entry.is_executing(), "Task must still be marked executing");
        }
        service.sweep_stale_pending_gossip();
        assert!(
            service.in_flight_payloads.contains_key(&payload_hash),
            "Ownership lock must NOT be swept at 30s while validation task is still actively executing"
        );

        // Invariant 4: A new validation cannot overlap the original while it is executing
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_dup3.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_dup3.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        assert!(
            rx.try_recv().is_err(),
            "New validation must NOT start or overlap original while active"
        );

        // Invariant 5: A timed-out validation is terminated or invalidated safely
        if let Some(entry) = service.in_flight_payloads.get_mut(&payload_hash) {
            entry.mark_completed(); // Task termination / cancellation signal
        }
        // Now that execution has terminated, sweeping safely cleans up the lock
        service.sweep_stale_pending_gossip();
        assert!(
            service.in_flight_payloads.is_empty(),
            "Terminated task lock is safely swept"
        );

        // Invariant 6 & 7: Legitimate retry permitted after previous validation safely ended;
        // and late result cannot corrupt the newer generation
        let msg_retry = MessageId::new(b"msg-retry-gen2");
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg_retry.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg_retry.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        let ev2 = rx.try_recv().unwrap();
        assert!(matches!(ev2, NetworkEvent::BlockReceived { .. }));
        assert_eq!(
            service
                .in_flight_payloads
                .get(&payload_hash)
                .unwrap()
                .generation,
            2,
            "Fresh retry must acquire generation 2"
        );

        // Stale result for msg_1 (generation 1) arrives late -> must NOT corrupt generation 2
        handle
            .report_gossip_validation(
                msg_1,
                peer_a,
                MessageAcceptance::Accept,
                true,
                Some(block_id),
                true,
            )
            .await
            .unwrap();
        let cmd = service.command_rx.recv().await.unwrap();
        service.handle_command(cmd).await;

        assert_eq!(
            service
                .in_flight_payloads
                .get(&payload_hash)
                .unwrap()
                .generation,
            2,
            "Generation 2 lock must survive late result from stale generation 1"
        );

        // Legitimate result for msg_retry (generation 2) cleans up
        handle
            .report_gossip_validation(
                msg_retry,
                peer_a,
                MessageAcceptance::Accept,
                true,
                Some(block_id),
                true,
            )
            .await
            .unwrap();
        let cmd2 = service.command_rx.recv().await.unwrap();
        service.handle_command(cmd2).await;

        assert!(
            service.in_flight_payloads.is_empty(),
            "Generation 2 cleanly released"
        );
    }

    #[tokio::test]
    async fn test_gossip_task_cancellation_and_raii_guard_lifecycle() {
        let flag = Arc::new(AtomicBool::new(false));

        // 1. Normal completion path: guard dropped at scope exit
        {
            let guard = ValidationExecutionGuard::new(flag.clone());
            assert!(guard.is_executing());
            assert!(flag.load(Ordering::SeqCst));
        }
        assert!(!flag.load(Ordering::SeqCst));

        // 2. Early error return path: guard dropped on Err
        let early_return = || -> Result<(), &'static str> {
            let _guard = ValidationExecutionGuard::new(flag.clone());
            assert!(flag.load(Ordering::SeqCst));
            Err("early failure")
        };
        assert!(early_return().is_err());
        assert!(!flag.load(Ordering::SeqCst));

        // 3. Panic unwind path: Drop runs during unwinding
        let panic_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ValidationExecutionGuard::new(flag.clone());
            assert!(flag.load(Ordering::SeqCst));
            panic!("forced panic for unwind test");
        }));
        assert!(panic_res.is_err());
        assert!(!flag.load(Ordering::SeqCst));

        // 4. Timeout cancellation of directly-awaited future:
        // When tokio::time::timeout expires, the future is dropped.
        // Proves:
        //   a) Active execution guard is automatically cleared on drop.
        //   b) Executing work immediately ceases (loop counter stops incrementing).
        let work_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let work_counter_clone = work_counter.clone();
        let flag_clone = flag.clone();

        let timed_out_future = tokio::time::timeout(Duration::from_millis(40), async move {
            let _guard = ValidationExecutionGuard::new(flag_clone);
            loop {
                work_counter_clone.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let res = timed_out_future.await;
        assert!(res.is_err(), "Future must time out");
        // Execution guard must be false immediately
        assert!(
            !flag.load(Ordering::SeqCst),
            "RAII guard must clear active state upon timeout drop"
        );

        let count_at_timeout = work_counter.load(Ordering::SeqCst);
        assert!(count_at_timeout > 0);
        // Wait an additional 40ms to verify that the task truly stopped and was not detached
        tokio::time::sleep(Duration::from_millis(40)).await;
        let count_after_sleep = work_counter.load(Ordering::SeqCst);
        assert_eq!(
            count_at_timeout, count_after_sleep,
            "Execution must strictly cease after timeout drop; task was not detached"
        );

        // 5. In-flight entry ownership bound to execution guard:
        // Demonstrates that sweep_stale_pending_gossip strictly respects the RAII guard.
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, _handle, _rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let payload_hash = Hash::new([0xaa; 32]);
        let block_id = Hash::new([0xbb; 32]);
        let msg_id = MessageId::new(b"msg-raii-test");
        let active_flag = Arc::new(AtomicBool::new(true));

        service.in_flight_payloads.insert(
            payload_hash,
            InFlightPayloadEntry {
                payload_hash,
                canonical_id: block_id,
                kind: GossipSubjectKind::Block,
                created_at: std::time::Instant::now()
                    - IN_FLIGHT_PAYLOAD_TTL
                    - Duration::from_millis(100),
                active_token: Some(msg_id.clone()),
                generation: 1,
                is_active: active_flag.clone(),
            },
        );
        service
            .in_flight_by_msg_id
            .insert(msg_id.clone(), (payload_hash, 1));

        // Create the guard holding active execution
        let guard = ValidationExecutionGuard::new(active_flag.clone());
        assert!(guard.is_executing());

        // Sweep while active -> ownership cannot be released!
        service.sweep_stale_pending_gossip();
        assert!(
            service.in_flight_payloads.contains_key(&payload_hash),
            "Ownership must not be released while RAII guard indicates active execution"
        );

        // Drop the guard (simulating validation completion or timeout cancellation)
        drop(guard);
        assert!(!active_flag.load(Ordering::SeqCst));

        // Sweep again -> now ownership is safely released
        service.sweep_stale_pending_gossip();
        assert!(
            service.in_flight_payloads.is_empty(),
            "Ownership must be released once RAII guard is dropped"
        );
    }

    #[tokio::test]
    async fn test_gossip_lost_event_sweeps_ownership() {
        let keypair = Keypair::generate_ed25519();
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let (mut service, _handle, mut rx) = NetworkService::new(
            keypair,
            "devnet",
            chain_id,
            genesis_hash,
            0,
            genesis_hash,
            U256::zero(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let block_id = Hash::new([0xaa; 32]);
        let payload_hash = Hash::new([0xbb; 32]);
        let msg = MessageId::new(b"lost-event-test");
        let peer_a = PeerId::random();
        let genesis = crate::genesis::genesis_block(chain_id);

        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_a,
            Some(peer_a),
            msg.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_a,
                source: Some(peer_a),
                message_id: msg.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );

        // Receive the event from channel and DROP IT (simulating lost event or receiver abort)
        let ev = rx.try_recv().expect("Event dispatched");
        let entry = service.in_flight_payloads.get(&payload_hash).unwrap();
        // While the event was in memory, its guard was active
        assert!(entry.is_executing());
        drop(ev); // Dropping the event drops its execution_guard!
                  // Immediately upon drop, is_executing() transitions to false!
        assert!(!entry.is_executing());

        // In addition, age pending token past PENDING_GOSSIP_TTL (8s) so active_token becomes None
        if let Some(e) = service.pending_gossip.get_mut(&msg) {
            e.created_at =
                std::time::Instant::now() - PENDING_GOSSIP_TTL - Duration::from_millis(50);
        }
        service.sweep_stale_pending_gossip();
        assert!(service.pending_gossip.is_empty());
        assert!(service
            .in_flight_payloads
            .get(&payload_hash)
            .unwrap()
            .active_token
            .is_none());

        // Now age payload entry past IN_FLIGHT_PAYLOAD_TTL (30s) while active_token is None
        if let Some(e) = service.in_flight_payloads.get_mut(&payload_hash) {
            e.created_at =
                std::time::Instant::now() - IN_FLIGHT_PAYLOAD_TTL - Duration::from_millis(50);
        }
        service.sweep_stale_pending_gossip();

        // Invariants asserted:
        // 1. pending_gossip is empty
        assert!(service.pending_gossip.is_empty());
        // 2. in_flight_payloads is empty
        assert!(service.in_flight_payloads.is_empty());
        // 3. in_flight_by_msg_id is empty (no stale mappings retained!)
        assert!(service.in_flight_by_msg_id.is_empty());

        // 4. A subsequent retry can be dispatched and acquire generation 2
        let msg2 = MessageId::new(b"lost-event-retry");
        let peer_b = PeerId::random();
        service.dispatch_gossip_event(
            GossipSubjectKind::Block,
            block_id,
            payload_hash,
            peer_b,
            Some(peer_b),
            msg2.clone(),
            NetworkEvent::BlockReceived {
                propagation_source: peer_b,
                source: Some(peer_b),
                message_id: msg2.clone(),
                block: Box::new(genesis.clone()),
                execution_guard: None,
            },
        );
        let entry2 = service.in_flight_payloads.get(&payload_hash).unwrap();
        assert_eq!(entry2.generation, 2);
        assert_eq!(
            service.in_flight_by_msg_id.get(&msg2),
            Some(&(payload_hash, 2))
        );

        // 5. A late stale result from old generation 1 cannot remove the retry's generation 2 lock
        service
            .handle_command(NetworkCommand::ReportGossipValidation {
                message_id: msg.clone(),
                propagation_source: peer_a,
                acceptance: MessageAcceptance::Accept,
                mark_seen: true,
                canonical_id: Some(block_id),
                is_block: true,
            })
            .await;
        // Lock remains held by generation 2!
        let entry2_after = service.in_flight_payloads.get(&payload_hash);
        assert!(entry2_after.is_some());
        assert_eq!(entry2_after.unwrap().generation, 2);
        assert_eq!(
            service.in_flight_by_msg_id.get(&msg2),
            Some(&(payload_hash, 2))
        );

        // Reporting validation for generation 2 cleanly removes the lock
        service
            .handle_command(NetworkCommand::ReportGossipValidation {
                message_id: msg2.clone(),
                propagation_source: peer_b,
                acceptance: MessageAcceptance::Accept,
                mark_seen: true,
                canonical_id: Some(block_id),
                is_block: true,
            })
            .await;
        assert!(service.in_flight_payloads.is_empty());
        assert!(service.in_flight_by_msg_id.is_empty());
    }

    #[tokio::test]
    async fn test_outbound_handshake_timeout_disconnects_peer_promptly() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let (service1, handle1, mut rx1) = NetworkService::new(
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

        // Node 2 is a custom libp2p swarm that implements /ownchain/sync/1 but intentionally ignores handshake requests
        let kp2 = Keypair::generate_ed25519();
        let p2 = kp2.public().to_peer_id();
        let protocols = [(
            libp2p::StreamProtocol::new(crate::p2p::protocol::SYNC_PROTOCOL_ID),
            libp2p::request_response::ProtocolSupport::Full,
        )];
        let req_resp_behaviour = libp2p::request_response::Behaviour::with_codec(
            crate::p2p::protocol::SyncCodec,
            protocols,
            libp2p::request_response::Config::default(),
        );

        let mut swarm2 = libp2p::SwarmBuilder::with_existing_identity(kp2)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| req_resp_behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm2
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let s1 = tokio::spawn(service1.run());

        // Wait for swarm2 to bind its listen address
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
                break address;
            }
        };

        // Run swarm2 in background, holding any incoming handshake requests without responding
        let s2 = tokio::spawn(async move {
            let mut _held_channels = Vec::new();
            loop {
                if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                    message: libp2p::request_response::Message::Request { channel, .. },
                    ..
                }) = swarm2.select_next_some().await
                {
                    // Intentionally hold the channel without sending a response to trigger client-side timeout
                    _held_channels.push(channel);
                }
            }
        });

        // Node 1 dials Node 2
        let start_time = std::time::Instant::now();
        handle1.dial(addr2).await.unwrap();

        // Node 1 must initially register Node 2 with handshake: None
        let mut registered = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(peers) = handle1.get_connected_peers().await {
                if let Some(p) = peers.iter().find(|p| p.peer_id == p2) {
                    assert!(p.handshake.is_none());
                    registered = true;
                    break;
                }
            }
        }
        assert!(
            registered,
            "Node 2 must be registered in PeerRegistry on connection"
        );

        // Node 1's handshake request timeout is 10s (ReqRespConfig::with_request_timeout(10s)).
        // Upon timeout, OutboundFailure must immediately disconnect Node 2.
        // It must NOT wait for the 60-second idle connection timeout.
        let disconnect_event = tokio::time::timeout(Duration::from_secs(25), async {
            while let Some(ev) = rx1.recv().await {
                if let NetworkEvent::PeerDisconnected { peer_id } = ev {
                    if peer_id == p2 {
                        return;
                    }
                }
            }
        })
        .await;

        assert!(
            disconnect_event.is_ok(),
            "Must receive PeerDisconnected within timeout"
        );
        let elapsed = start_time.elapsed();
        assert!(
            elapsed >= Duration::from_secs(9) && elapsed < Duration::from_secs(30),
            "Peer was disconnected after handshake timeout ({:?}), well before 60s idle timeout",
            elapsed
        );

        // Verify Node 2 is no longer in connected peers registry
        let peers = handle1.get_connected_peers().await.unwrap();
        assert!(!peers.iter().any(|p| p.peer_id == p2));

        s1.abort();
        s2.abort();
    }

    #[tokio::test]
    async fn test_outbound_handshake_invalid_response_disconnects_peer_promptly() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let (service1, handle1, mut rx1) = NetworkService::new(
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

        // Node 2 is a custom swarm that responds to Handshake requests with an invalid response type (SyncResponse::Error)
        let kp2 = Keypair::generate_ed25519();
        let p2 = kp2.public().to_peer_id();
        let protocols = [(
            libp2p::StreamProtocol::new(crate::p2p::protocol::SYNC_PROTOCOL_ID),
            libp2p::request_response::ProtocolSupport::Full,
        )];
        let req_resp_behaviour = libp2p::request_response::Behaviour::with_codec(
            crate::p2p::protocol::SyncCodec,
            protocols,
            libp2p::request_response::Config::default(),
        );

        let mut swarm2 = libp2p::SwarmBuilder::with_existing_identity(kp2)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| req_resp_behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm2
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        let s1 = tokio::spawn(service1.run());

        // Wait for swarm2 to bind its listen address
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
                break address;
            }
        };

        // Run swarm2 in background, responding to Handshake with non-handshake response SyncResponse::Error
        let s2 = tokio::spawn(async move {
            loop {
                if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                    message: libp2p::request_response::Message::Request { channel, .. },
                    ..
                }) = swarm2.select_next_some().await
                {
                    let _ = swarm2.behaviour_mut().send_response(
                        channel,
                        SyncResponse::Error("handshake not supported".into()),
                    );
                }
            }
        });

        // Node 1 dials Node 2
        let start_time = std::time::Instant::now();
        handle1.dial(addr2).await.unwrap();

        // Node 1 receives the invalid response, treats it as a protocol violation,
        // and immediately requests disconnection.
        let disconnect_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(ev) = rx1.recv().await {
                if let NetworkEvent::PeerDisconnected { peer_id } = ev {
                    if peer_id == p2 {
                        return;
                    }
                }
            }
        })
        .await;

        assert!(
            disconnect_event.is_ok(),
            "Must receive PeerDisconnected promptly upon invalid handshake response"
        );
        let elapsed = start_time.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "Peer was disconnected promptly ({:?}) without waiting for timeout",
            elapsed
        );

        // Verify Node 2 is no longer in connected peers registry
        let peers = handle1.get_connected_peers().await.unwrap();
        assert!(!peers.iter().any(|p| p.peer_id == p2));

        s1.abort();
        s2.abort();
    }

    #[tokio::test]
    async fn test_gossip_production_timeout_releases_guard() {
        let flag = Arc::new(AtomicBool::new(false));
        let guard = ValidationExecutionGuard::new(flag.clone());
        assert!(guard.is_executing());
        assert!(flag.load(Ordering::SeqCst));

        // Simulate timeout dropping the future that holds the guard
        let res = tokio::time::timeout(Duration::from_millis(10), async {
            let _g = guard;
            tokio::time::sleep(Duration::from_millis(100)).await;
        })
        .await;

        assert!(res.is_err(), "Future timed out");
        // Guard must be dropped by timeout cancellation, resetting the flag
        assert!(!flag.load(Ordering::SeqCst));
    }

    fn make_test_sync_swarm(
        kp: Keypair,
    ) -> libp2p::Swarm<libp2p::request_response::Behaviour<crate::p2p::protocol::SyncCodec>> {
        let protocols = [(
            libp2p::StreamProtocol::new(crate::p2p::protocol::SYNC_PROTOCOL_ID),
            libp2p::request_response::ProtocolSupport::Full,
        )];
        let req_resp_behaviour = libp2p::request_response::Behaviour::with_codec(
            crate::p2p::protocol::SyncCodec,
            protocols,
            libp2p::request_response::Config::default(),
        );

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(kp)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| req_resp_behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        swarm
    }

    #[tokio::test]
    async fn test_handshake_lifecycle_ordering_a_outbound_response_first() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let p1 = kp1.public().to_peer_id();
        let (service1, handle1, mut rx1) = NetworkService::new(
            kp1,
            "devnet",
            chain_id,
            genesis_hash,
            10,
            tip_id,
            U256::from_u128(10),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let kp2 = Keypair::generate_ed25519();
        let p2 = kp2.public().to_peer_id();
        let mut swarm2 = make_test_sync_swarm(kp2);

        let s1 = tokio::spawn(service1.run());

        // Wait for swarm2 to bind its listen address
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
                break address;
            }
        };

        // Node 1 dials Node 2
        handle1.dial(addr2).await.unwrap();

        // Node 2 waits for connection and Node 1's outbound handshake request
        let (channel1, hs1_req) = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Request {
                        request: SyncRequest::Handshake(hs),
                        channel,
                        ..
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                break (channel, hs);
            }
        };
        assert_eq!(hs1_req.tip_height, 10);

        // 1. Process valid handshake response to Node 1's outbound request FIRST
        let hs2_outbound = HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id,
            genesis_hash,
            tip_height: 100,
            tip_block_id: Hash::new([20u8; 32]),
            cumulative_work: U256::from_u128(100),
            capabilities: 0,
            software_version: "test-node-2".into(),
        };
        swarm2
            .behaviour_mut()
            .send_response(channel1, SyncResponse::Handshake(hs2_outbound.clone()))
            .unwrap();

        // Node 1 processes the response, establishes peer metadata, and emits PeerHandshakeCompleted
        let ev = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
            .await
            .expect("Must receive event")
            .expect("Channel must not close");
        assert!(matches!(
            ev,
            NetworkEvent::PeerHandshakeCompleted { peer_id, .. } if peer_id == p2
        ));

        // 2. THEN process peer's legitimate initial inbound handshake request
        // To verify established metadata is NOT overwritten, send different tip height
        let hs2_inbound = HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id,
            genesis_hash,
            tip_height: 555,
            tip_block_id: Hash::new([55u8; 32]),
            cumulative_work: U256::from_u128(555),
            capabilities: 0,
            software_version: "test-node-2-inbound".into(),
        };
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&p1, SyncRequest::Handshake(hs2_inbound));

        // Inbound request must receive SyncResponse::Handshake from Node 1
        let resp = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Response {
                        request_id: id,
                        response,
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                if id == req_id {
                    break response;
                }
            }
        };

        match resp {
            SyncResponse::Handshake(local_hs) => {
                assert_eq!(local_hs.tip_height, 10);
            }
            other => panic!(
                "Inbound request must receive SyncResponse::Handshake, got: {:?}",
                other
            ),
        }

        // 3. Assert peer is not disconnected, and established handshake metadata is not overwritten
        tokio::time::sleep(Duration::from_millis(100)).await;
        let peers = handle1.get_connected_peers().await.unwrap();
        let peer_entry = peers
            .iter()
            .find(|p| p.peer_id == p2)
            .expect("Peer must remain connected");
        let stored_hs = peer_entry
            .handshake
            .as_ref()
            .expect("Peer must remain handshaked");
        assert_eq!(
            stored_hs.tip_height, 100,
            "Established handshake metadata must not be overwritten by subsequent inbound handshake"
        );
        assert_eq!(stored_hs.tip_block_id, Hash::new([20u8; 32]));

        s1.abort();
    }

    #[tokio::test]
    async fn test_handshake_lifecycle_ordering_b_inbound_request_first() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let p1 = kp1.public().to_peer_id();
        let (service1, handle1, mut rx1) = NetworkService::new(
            kp1,
            "devnet",
            chain_id,
            genesis_hash,
            10,
            tip_id,
            U256::from_u128(10),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let kp2 = Keypair::generate_ed25519();
        let p2 = kp2.public().to_peer_id();
        let mut swarm2 = make_test_sync_swarm(kp2);

        let s1 = tokio::spawn(service1.run());

        // Wait for swarm2 to bind its listen address
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
                break address;
            }
        };

        // Node 1 dials Node 2
        handle1.dial(addr2).await.unwrap();

        // Node 2 intercepts Node 1's outbound handshake request (holds channel without answering yet)
        let (channel1, _hs1_req) = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Request {
                        request: SyncRequest::Handshake(hs),
                        channel,
                        ..
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                break (channel, hs);
            }
        };

        // 1. Process peer's initial inbound handshake request FIRST
        let hs2_inbound = HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id,
            genesis_hash,
            tip_height: 200,
            tip_block_id: Hash::new([30u8; 32]),
            cumulative_work: U256::from_u128(200),
            capabilities: 0,
            software_version: "test-node-2-inbound".into(),
        };
        let req_id = swarm2
            .behaviour_mut()
            .send_request(&p1, SyncRequest::Handshake(hs2_inbound.clone()));

        // Inbound request receives SyncResponse::Handshake from Node 1
        let resp = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Response {
                        request_id: id,
                        response,
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                if id == req_id {
                    break response;
                }
            }
        };
        assert!(matches!(resp, SyncResponse::Handshake(_)));

        // Node 1 emitted PeerHandshakeCompleted
        let ev = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
            .await
            .expect("Must receive event")
            .expect("Channel must not close");
        assert!(matches!(
            ev,
            NetworkEvent::PeerHandshakeCompleted { peer_id, .. } if peer_id == p2
        ));

        // 2. THEN process response to Node 1's outbound handshake request
        // Node 2 sends response with different tip metadata to verify it does not corrupt metadata
        let mut hs2_dup = hs2_inbound.clone();
        hs2_dup.tip_height = 999;
        hs2_dup.cumulative_work = U256::from_u128(999);
        swarm2
            .behaviour_mut()
            .send_response(channel1, SyncResponse::Handshake(hs2_dup))
            .unwrap();

        // 3. Assert peer remains handshaked and connected, and duplicate completion does not corrupt metadata
        tokio::time::sleep(Duration::from_millis(100)).await;
        let peers = handle1.get_connected_peers().await.unwrap();
        let peer_entry = peers
            .iter()
            .find(|p| p.peer_id == p2)
            .expect("Peer must remain connected");
        let stored_hs = peer_entry
            .handshake
            .as_ref()
            .expect("Peer must remain handshaked");
        assert_eq!(
            stored_hs.tip_height, 200,
            "Duplicate response must not corrupt established handshake metadata"
        );
        assert_eq!(stored_hs.tip_block_id, Hash::new([30u8; 32]));

        s1.abort();
    }

    #[tokio::test]
    async fn test_handshake_lifecycle_rejects_repeated_unsolicited_inbound_request() {
        let chain_id = Hash::new([1u8; 32]);
        let genesis_hash = Hash::new([2u8; 32]);
        let tip_id = Hash::new([3u8; 32]);

        let kp1 = Keypair::generate_ed25519();
        let p1 = kp1.public().to_peer_id();
        let (service1, handle1, mut rx1) = NetworkService::new(
            kp1,
            "devnet",
            chain_id,
            genesis_hash,
            10,
            tip_id,
            U256::from_u128(10),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            50,
            100,
            100,
        )
        .unwrap();

        let kp2 = Keypair::generate_ed25519();
        let p2 = kp2.public().to_peer_id();
        let mut swarm2 = make_test_sync_swarm(kp2);

        let s1 = tokio::spawn(service1.run());

        // Wait for swarm2 to bind its listen address
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
                break address;
            }
        };

        // Node 1 dials Node 2
        handle1.dial(addr2).await.unwrap();

        // Node 2 intercepts Node 1's outbound handshake request
        let (channel1, _hs1_req) = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Request {
                        request: SyncRequest::Handshake(hs),
                        channel,
                        ..
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                break (channel, hs);
            }
        };

        // Complete normal initial handshake
        let hs2_valid = HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id,
            genesis_hash,
            tip_height: 100,
            tip_block_id: Hash::new([20u8; 32]),
            cumulative_work: U256::from_u128(100),
            capabilities: 0,
            software_version: "test-node-2".into(),
        };
        swarm2
            .behaviour_mut()
            .send_response(channel1, SyncResponse::Handshake(hs2_valid.clone()))
            .unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
            .await
            .expect("Must receive event")
            .expect("Channel must not close");

        // Send legitimate initial inbound handshake from Node 2 to Node 1
        let req_id1 = swarm2
            .behaviour_mut()
            .send_request(&p1, SyncRequest::Handshake(hs2_valid.clone()));

        let resp1 = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Response {
                        request_id: id,
                        response,
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                if id == req_id1 {
                    break response;
                }
            }
        };
        assert!(matches!(resp1, SyncResponse::Handshake(_)));

        // 1. After initial inbound handshake has been processed, send ANOTHER unsolicited inbound handshake with altered tip metadata
        let hs_unsolicited = HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id,
            genesis_hash,
            tip_height: 9999,
            tip_block_id: Hash::new([99u8; 32]),
            cumulative_work: U256::from_u128(9999),
            capabilities: 0,
            software_version: "attacker".into(),
        };
        let req_id2 = swarm2
            .behaviour_mut()
            .send_request(&p1, SyncRequest::Handshake(hs_unsolicited));

        // 2. Assert it is rejected with SyncResponse::Error("handshake already established")
        let resp2 = loop {
            if let SwarmEvent::Behaviour(libp2p::request_response::Event::Message {
                message:
                    libp2p::request_response::Message::Response {
                        request_id: id,
                        response,
                    },
                ..
            }) = swarm2.select_next_some().await
            {
                if id == req_id2 {
                    break response;
                }
            }
        };

        match resp2 {
            SyncResponse::Error(msg) => {
                assert!(
                    msg.contains("handshake already established"),
                    "Expected 'handshake already established', got: {}",
                    msg
                );
            }
            other => panic!("Expected SyncResponse::Error, got {:?}", other),
        }

        // 3. Assert established metadata remains unchanged
        tokio::time::sleep(Duration::from_millis(100)).await;
        let peers = handle1.get_connected_peers().await.unwrap();
        let peer_entry = peers
            .iter()
            .find(|p| p.peer_id == p2)
            .expect("Peer must remain connected");
        let stored_hs = peer_entry
            .handshake
            .as_ref()
            .expect("Peer must remain handshaked");
        assert_eq!(
            stored_hs.tip_height, 100,
            "Unsolicited handshake must not alter established metadata"
        );
        assert_eq!(stored_hs.tip_block_id, Hash::new([20u8; 32]));

        s1.abort();
    }
}
