//! Node runtime lifecycle, service orchestration, block sync, and mempool coordination.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! The node runtime coordinates persistent storage (`BlockStore`), P2P networking
//! (`NetworkService`), mempool admission and revalidation (`Mempool`), and
//! independent local consensus evaluation (`ChainState`).

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use libp2p::core::Multiaddr;
use libp2p::identity::{Keypair, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::block::Block;
use crate::chain::ChainState;
use crate::difficulty::U256;
use crate::genesis::genesis_block;
use crate::hash::Hash;
use crate::mempool::{Mempool, MempoolError};
use crate::node::config::NodeConfig;
use crate::p2p::identity::{load_or_generate_identity, peer_id_from_keypair};
use crate::p2p::network::{NetworkEvent, NetworkHandle, NetworkService, PeerInfo};
use crate::p2p::protocol::{
    SyncRequest, SyncResponse, MAX_BLOCKS_PER_RESPONSE, MAX_HEADERS_PER_RESPONSE,
};
use crate::storage::{BlockStore, StorageError};
use crate::validation::ValidationError;

/// Maximum number of orphan blocks held in memory.
pub const MAX_ORPHAN_BLOCKS: usize = 100;
/// Maximum cumulative bytes of serialized orphan blocks held in memory (5 MB).
pub const MAX_ORPHAN_BYTES: usize = 5 * 1024 * 1024;

/// Runtime errors encountered during node lifecycle operations.
#[derive(Debug)]
pub enum RuntimeError {
    /// File system or I/O error.
    Io(std::io::Error),
    /// Persistent storage error.
    Storage(StorageError),
    /// Network setup error.
    Network(String),
    /// Consensus replay or state error.
    Consensus(ValidationError),
    /// Identity management error.
    Identity(String),
}

impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RuntimeError::Io(e) => write!(f, "I/O error: {e}"),
            RuntimeError::Storage(e) => write!(f, "storage error: {e}"),
            RuntimeError::Network(s) => write!(f, "network error: {s}"),
            RuntimeError::Consensus(e) => write!(f, "consensus error: {e}"),
            RuntimeError::Identity(s) => write!(f, "identity error: {s}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<std::io::Error> for RuntimeError {
    fn from(e: std::io::Error) -> Self {
        RuntimeError::Io(e)
    }
}

impl From<StorageError> for RuntimeError {
    fn from(e: StorageError) -> Self {
        RuntimeError::Storage(e)
    }
}

impl From<ValidationError> for RuntimeError {
    fn from(e: ValidationError) -> Self {
        RuntimeError::Consensus(e)
    }
}

#[derive(Clone, Debug)]
struct OrphanEntry {
    block: Block,
    source_peer: PeerId,
    serialized_size: usize,
}

/// Point-in-time immutable snapshot of canonical active chain block IDs captured by `NodeRuntime`.
/// Used by the synchronization worker for bounded, lock-free common ancestor discovery.
#[derive(Clone, Debug)]
pub struct ActiveChainSnapshot {
    tip_height: u64,
    tip_block_id: Hash,
    block_ids: Arc<Vec<Hash>>,
}

impl ActiveChainSnapshot {
    pub fn get_block_id(&self, height: u64) -> Option<Hash> {
        self.block_ids.get(height as usize).copied()
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_block_id(&self) -> Hash {
        self.tip_block_id
    }
}

/// Result delivered when a background synchronization task terminates.
pub(crate) struct SyncTaskResult {
    pub sync_id: u64,
    pub peer_id: PeerId,
    pub result: Result<(), String>,
}

struct ActiveSyncOperation {
    sync_id: u64,
    peer_id: PeerId,
    task_id: tokio::task::Id,
    abort_handle: tokio::task::AbortHandle,
    cancel_flag: Arc<std::sync::atomic::AtomicBool>,
    notifier: Option<oneshot::Sender<Result<(), String>>>,
}

/// Result delivered when a missing-parent recovery or retry task completes.
pub(crate) enum RecoveryTaskResult {
    Fetched {
        recovery_id: u64,
        parent_id: Hash,
        source_peer: PeerId,
        block: Box<Block>,
    },
    Failed {
        recovery_id: u64,
        parent_id: Hash,
        source_peer: PeerId,
    },
    RetryTriggered {
        recovery_id: u64,
        parent_id: Hash,
        child_block_id: Hash,
        source_peer: PeerId,
    },
}

#[derive(Debug)]
struct MissingParentRecovery {
    recovery_id: u64,
    #[allow(dead_code)]
    parent_id: Hash,
    child_block_id: Hash,
    source_peer: PeerId,
    attempts: u32,
    abort_handle: Option<tokio::task::AbortHandle>,
    is_in_flight: bool,
    is_capacity_waiting: bool,
}

/// Current consensus, chain, and runtime status of a running node.
#[derive(Clone, Debug)]
pub struct NodeStatus {
    pub tip_height: u64,
    pub tip_block_id: Hash,
    pub cumulative_work: U256,
    pub composite_state_root: Hash,
    pub mempool_size: usize,
    pub orphan_pool_size: usize,
    pub peer_id: PeerId,
}

/// Internal messages dispatched from background sync workers to `NodeRuntime`.
pub(crate) enum RuntimeSyncMessage {
    /// Sync worker delivers a batch of fetched blocks to be applied by the runtime.
    ApplyBlockBatch {
        sync_id: u64,
        peer_id: PeerId,
        blocks: Vec<Block>,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
}

/// Internal actor commands dispatched to the `NodeRuntime` event loop.
pub enum NodeCommand {
    SubmitBlock {
        block: Block,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    SubmitTransaction {
        tx_bytes: Vec<u8>,
        respond_to: oneshot::Sender<Result<Hash, MempoolError>>,
    },
    GetStatus {
        respond_to: oneshot::Sender<NodeStatus>,
    },
    GetListenAddrs {
        respond_to: oneshot::Sender<Vec<Multiaddr>>,
    },
    GetConnectedPeers {
        respond_to: oneshot::Sender<Vec<PeerInfo>>,
    },
    Dial {
        addr: Multiaddr,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    Disconnect {
        peer_id: PeerId,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    SyncWithPeer {
        peer_id: PeerId,
        peer_tip_height: u64,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    Stop {
        respond_to: oneshot::Sender<()>,
    },
}

/// Thread-safe and cloneable handle for interacting with a running `NodeRuntime` actor.
#[derive(Clone)]
pub struct NodeHandle {
    peer_id: PeerId,
    command_tx: mpsc::Sender<NodeCommand>,
}

impl NodeHandle {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub async fn submit_block(&self, block: Block) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::SubmitBlock {
                block,
                respond_to: tx,
            })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())?
    }

    pub async fn submit_transaction(&self, tx_bytes: Vec<u8>) -> Result<Hash, MempoolError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::SubmitTransaction {
                tx_bytes,
                respond_to: tx,
            })
            .await
            .map_err(|_| {
                MempoolError::Malformed("Node runtime command channel closed".to_string())
            })?;
        rx.await.map_err(|_| {
            MempoolError::Malformed("Node runtime dropped response receiver".to_string())
        })?
    }

    pub async fn status(&self) -> Result<NodeStatus, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::GetStatus { respond_to: tx })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())
    }

    pub async fn get_listen_addrs(&self) -> Result<Vec<Multiaddr>, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::GetListenAddrs { respond_to: tx })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())
    }

    pub async fn get_connected_peers(&self) -> Result<Vec<PeerInfo>, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::GetConnectedPeers { respond_to: tx })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::Dial {
                addr,
                respond_to: tx,
            })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())?
    }

    pub async fn dial_peer(&self, addr: Multiaddr) -> Result<(), String> {
        self.dial(addr).await
    }

    pub async fn get_tip_height(&self) -> Result<u64, String> {
        Ok(self.status().await?.tip_height)
    }

    pub async fn get_tip_block_id(&self) -> Result<Hash, String> {
        Ok(self.status().await?.tip_block_id)
    }

    pub async fn get_cumulative_work(&self) -> Result<U256, String> {
        Ok(self.status().await?.cumulative_work)
    }

    pub async fn get_composite_state_root(&self) -> Result<Hash, String> {
        Ok(self.status().await?.composite_state_root)
    }

    pub async fn get_orphan_count(&self) -> Result<usize, String> {
        Ok(self.status().await?.orphan_pool_size)
    }

    pub async fn disconnect(&self, peer_id: PeerId) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::Disconnect {
                peer_id,
                respond_to: tx,
            })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())?
    }

    pub async fn sync_with_peer(
        &self,
        peer_id: PeerId,
        peer_tip_height: u64,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::SyncWithPeer {
                peer_id,
                peer_tip_height,
                respond_to: tx,
            })
            .await
            .map_err(|_| "Node runtime has shut down".to_string())?;
        rx.await
            .map_err(|_| "Node runtime dropped response".to_string())?
    }

    pub async fn stop(&self) {
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(NodeCommand::Stop { respond_to: tx })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }
}

/// The running node instance coordinating blockchain storage, networking, and consensus.
pub struct NodeRuntime {
    config: NodeConfig,
    storage: Arc<BlockStore>,
    chain_state: ChainState,
    mempool: Mempool,
    network_handle: NetworkHandle,
    network_event_rx: mpsc::Receiver<NetworkEvent>,
    command_tx: mpsc::Sender<NodeCommand>,
    command_rx: mpsc::Receiver<NodeCommand>,
    sync_msg_tx: mpsc::Sender<RuntimeSyncMessage>,
    sync_msg_rx: mpsc::Receiver<RuntimeSyncMessage>,
    network_task: Option<tokio::task::JoinHandle<()>>,
    current_sync_id: u64,
    active_sync: Option<ActiveSyncOperation>,
    snapshot_tasks: tokio::task::JoinSet<()>,
    sync_tasks: tokio::task::JoinSet<SyncTaskResult>,
    sync_task_metadata: HashMap<tokio::task::Id, (u64, PeerId)>,
    current_recovery_id: u64,
    missing_parents: HashMap<Hash, MissingParentRecovery>,
    waiting_recoveries: VecDeque<Hash>,
    recovery_tasks: tokio::task::JoinSet<RecoveryTaskResult>,
    recovery_task_metadata: HashMap<tokio::task::Id, (u64, Hash, PeerId)>,
    keypair: Keypair,
    peer_id: PeerId,
    orphan_blocks: HashMap<Hash, OrphanEntry>,
    orphan_parents: HashMap<Hash, Vec<Hash>>,
    orphan_order: VecDeque<Hash>,
    orphan_bytes: usize,
}

impl NodeRuntime {
    /// Initializes storage, node identity, consensus state, mempool, and P2P service.
    pub fn init(config: NodeConfig) -> Result<Self, RuntimeError> {
        // 1. Ensure data directory exists
        if !config.data_dir.exists() {
            fs::create_dir_all(&config.data_dir)?;
        }
        let db_dir = config.db_path();
        if !db_dir.exists() {
            fs::create_dir_all(&db_dir)?;
        }

        // 2. Load or generate node identity key
        let keypair = load_or_generate_identity(config.identity_path())
            .map_err(|e| RuntimeError::Identity(e.to_string()))?;
        let peer_id = peer_id_from_keypair(&keypair);

        // 3. Open or initialize persistent block storage
        let db_file = db_dir.join("blockchain.redb");
        let storage = Arc::new(BlockStore::open(db_file, config.chain_id)?);

        // 4. Deterministically reconstruct in-memory ChainState from stored blocks
        let chain_state = storage.reconstruct_chain_state()?;
        let tip_height = chain_state.tip_height().unwrap_or(0);
        let tip_id = chain_state.tip_block_id().unwrap_or(Hash::ZERO);
        let cumulative_work = chain_state.cumulative_work();

        // 5. Initialize bounded mempool
        let mempool = Mempool::with_config(config.mempool_config);

        // 6. Initialize P2P network service
        let genesis = genesis_block(config.chain_id);
        let genesis_hash = genesis.block_id();

        let (network_service, network_handle, network_event_rx) = NetworkService::new(
            keypair.clone(),
            &config.network_name,
            config.chain_id,
            genesis_hash,
            tip_height,
            tip_id,
            cumulative_work,
            config.listen_addr.clone(),
            config.max_peers,
            500,
            500,
        )
        .map_err(|e| RuntimeError::Network(e.to_string()))?;

        // Spawn network service in background tokio task with retained handle
        let network_task = tokio::spawn(network_service.run());

        let (command_tx, command_rx) = mpsc::channel(64);
        let (sync_msg_tx, sync_msg_rx) = mpsc::channel(64);

        Ok(Self {
            config,
            storage,
            chain_state,
            mempool,
            network_handle,
            network_event_rx,
            command_tx,
            command_rx,
            sync_msg_tx,
            sync_msg_rx,
            network_task: Some(network_task),
            current_sync_id: 0,
            active_sync: None,
            snapshot_tasks: tokio::task::JoinSet::new(),
            sync_tasks: tokio::task::JoinSet::new(),
            sync_task_metadata: HashMap::new(),
            current_recovery_id: 0,
            missing_parents: HashMap::new(),
            waiting_recoveries: VecDeque::new(),
            recovery_tasks: tokio::task::JoinSet::new(),
            recovery_task_metadata: HashMap::new(),
            keypair,
            peer_id,
            orphan_blocks: HashMap::new(),
            orphan_parents: HashMap::new(),
            orphan_order: VecDeque::new(),
            orphan_bytes: 0,
        })
    }

    /// Obtains a cloneable `NodeHandle` actor client for this runtime.
    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            peer_id: self.peer_id,
            command_tx: self.command_tx.clone(),
        }
    }

    /// Spawns the node runtime in a background Tokio task and returns its handle.
    pub fn spawn(
        config: NodeConfig,
    ) -> Result<(NodeHandle, tokio::task::JoinHandle<()>), RuntimeError> {
        let runtime = Self::init(config)?;
        Ok(runtime.spawn_actor())
    }

    /// Spawns an initialized node runtime in a background Tokio task and returns its handle.
    pub fn spawn_actor(mut self) -> (NodeHandle, tokio::task::JoinHandle<()>) {
        let handle = self.handle();
        let join_handle = tokio::spawn(async move {
            self.run(None).await;
        });
        (handle, join_handle)
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn tip_height(&self) -> u64 {
        self.chain_state.tip_height().unwrap_or(0)
    }

    pub fn tip_block_id(&self) -> Hash {
        self.chain_state.tip_block_id().unwrap_or(Hash::ZERO)
    }

    pub fn cumulative_work(&self) -> U256 {
        self.chain_state.cumulative_work()
    }

    pub fn chain_state(&self) -> &ChainState {
        &self.chain_state
    }

    pub fn storage(&self) -> &BlockStore {
        &self.storage
    }

    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    pub fn network_handle(&self) -> &NetworkHandle {
        &self.network_handle
    }

    pub fn orphan_count(&self) -> usize {
        self.orphan_blocks.len()
    }

    pub fn orphan_bytes(&self) -> usize {
        self.orphan_bytes
    }

    fn add_orphan(&mut self, block_id: Hash, block: Block, source_peer: PeerId) {
        let block_bytes_len = match block.to_bytes() {
            Ok(b) => b.len(),
            Err(_) => return,
        };

        if block_bytes_len > MAX_ORPHAN_BYTES {
            tracing::warn!(
                "Orphan block {} size {} exceeds maximum orphan storage limit {}",
                block_id,
                block_bytes_len,
                MAX_ORPHAN_BYTES
            );
            return;
        }

        if self.orphan_blocks.contains_key(&block_id) {
            return;
        }

        // Evict oldest orphans if limit reached
        while self.orphan_blocks.len() >= MAX_ORPHAN_BLOCKS
            || (self.orphan_bytes + block_bytes_len > MAX_ORPHAN_BYTES
                && !self.orphan_blocks.is_empty())
        {
            if let Some(oldest_id) = self.orphan_order.pop_front() {
                if let Some(entry) = self.orphan_blocks.remove(&oldest_id) {
                    self.orphan_bytes = self.orphan_bytes.saturating_sub(entry.serialized_size);
                    let p_id = entry.block.header.parent_block_id;
                    let mut cleanup_parent = false;
                    if let Some(children) = self.orphan_parents.get_mut(&p_id) {
                        children.retain(|id| id != &oldest_id);
                        if children.is_empty() {
                            self.orphan_parents.remove(&p_id);
                            cleanup_parent = true;
                        }
                    }
                    if cleanup_parent {
                        if let Some(recovery) = self.missing_parents.remove(&p_id) {
                            if let Some(abort_handle) = recovery.abort_handle {
                                abort_handle.abort();
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }

        let parent_id = block.header.parent_block_id;
        self.orphan_parents
            .entry(parent_id)
            .or_default()
            .push(block_id);
        self.orphan_order.push_back(block_id);
        self.orphan_bytes += block_bytes_len;
        self.orphan_blocks.insert(
            block_id,
            OrphanEntry {
                block,
                source_peer,
                serialized_size: block_bytes_len,
            },
        );
    }

    fn remove_orphan(&mut self, block_id: &Hash) -> Option<OrphanEntry> {
        if let Some(entry) = self.orphan_blocks.remove(block_id) {
            self.orphan_bytes = self.orphan_bytes.saturating_sub(entry.serialized_size);
            self.orphan_order.retain(|id| id != block_id);
            let parent_id = entry.block.header.parent_block_id;
            let mut cleanup_parent = false;
            if let Some(children) = self.orphan_parents.get_mut(&parent_id) {
                children.retain(|id| id != block_id);
                if children.is_empty() {
                    self.orphan_parents.remove(&parent_id);
                    cleanup_parent = true;
                } else {
                    // Update child_block_id to a surviving dependent child!
                    if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
                        if recovery.child_block_id == *block_id {
                            recovery.child_block_id = children[0];
                        }
                    }
                }
            }
            if cleanup_parent {
                if let Some(recovery) = self.missing_parents.remove(&parent_id) {
                    if let Some(abort_handle) = recovery.abort_handle {
                        abort_handle.abort();
                    }
                }
                self.waiting_recoveries.retain(|&pid| pid != parent_id);
            }
            Some(entry)
        } else {
            None
        }
    }

    fn in_flight_recovery_count(&self) -> usize {
        self.missing_parents
            .values()
            .filter(|r| r.is_in_flight)
            .count()
    }

    /// Triggers asynchronous non-blocking recovery for a missing parent block.
    async fn fetch_parent_block(
        network_handle: NetworkHandle,
        local_peer_id: PeerId,
        parent_id: Hash,
        child_block_id: Hash,
        source_peer: PeerId,
    ) -> Option<(Block, PeerId)> {
        let req = SyncRequest::GetBlocks {
            block_ids: vec![parent_id],
        };
        if source_peer != local_peer_id {
            if let Ok(Ok(SyncResponse::Blocks(parents))) = tokio::time::timeout(
                Duration::from_secs(3),
                network_handle.send_sync_request(source_peer, req.clone()),
            )
            .await
            {
                if let Some(p) = parents.into_iter().next() {
                    if p.header.block_id() == parent_id {
                        return Some((p, source_peer));
                    }
                }
            }
        }

        if let Ok(peers) = network_handle.get_connected_peers().await {
            for peer in peers {
                if peer.peer_id != local_peer_id && peer.handshake.is_some() {
                    if let Ok(Ok(SyncResponse::Blocks(parents))) = tokio::time::timeout(
                        Duration::from_secs(3),
                        network_handle.send_sync_request(peer.peer_id, req.clone()),
                    )
                    .await
                    {
                        if let Some(p) = parents.into_iter().next() {
                            if p.header.block_id() == parent_id {
                                return Some((p, peer.peer_id));
                            }
                        }
                    }
                }
            }
        }

        let req_mp = SyncRequest::GetMissingParent { child_block_id };
        if let Ok(peers) = network_handle.get_connected_peers().await {
            for peer in peers {
                if peer.peer_id != local_peer_id && peer.handshake.is_some() {
                    if let Ok(Ok(SyncResponse::Blocks(parents))) = tokio::time::timeout(
                        Duration::from_secs(3),
                        network_handle.send_sync_request(peer.peer_id, req_mp.clone()),
                    )
                    .await
                    {
                        if let Some(p) = parents.into_iter().next() {
                            if p.header.block_id() == parent_id {
                                return Some((p, peer.peer_id));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Triggers asynchronous non-blocking recovery for a missing parent block.
    fn trigger_missing_parent_recovery(
        &mut self,
        parent_id: Hash,
        child_block_id: Hash,
        source_peer: PeerId,
    ) {
        const MAX_PARENT_RETRIES: u32 = 3;

        // 1. Check if already active/in-flight, waiting, or retries exhausted
        if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
            if recovery.is_in_flight
                || recovery.is_capacity_waiting
                || recovery.abort_handle.is_some()
            {
                // Coalesced: request already in flight, waiting for capacity, or awaiting retry backoff
                return;
            }
            if recovery.attempts >= MAX_PARENT_RETRIES {
                tracing::debug!(
                    "Missing parent {} reached maximum retry attempts ({}); skipping recovery",
                    parent_id,
                    MAX_PARENT_RETRIES
                );
                return;
            }
        }

        // 2. Capacity limit (16) checked BEFORE consuming retries!
        if self.in_flight_recovery_count() >= 16 {
            tracing::warn!(
                "Maximum concurrent missing parent recoveries (16) reached; queuing waiting recovery for {}",
                parent_id
            );
            match self.missing_parents.get_mut(&parent_id) {
                Some(rec) => {
                    rec.is_capacity_waiting = true;
                    rec.is_in_flight = false;
                    rec.child_block_id = child_block_id;
                    rec.source_peer = source_peer;
                }
                None => {
                    self.missing_parents.insert(
                        parent_id,
                        MissingParentRecovery {
                            recovery_id: 0,
                            parent_id,
                            child_block_id,
                            source_peer,
                            attempts: 0,
                            abort_handle: None,
                            is_in_flight: false,
                            is_capacity_waiting: true,
                        },
                    );
                }
            }
            if !self.waiting_recoveries.contains(&parent_id) {
                self.waiting_recoveries.push_back(parent_id);
            }
            return;
        }

        // 3. Monotonic recovery generation ID
        self.current_recovery_id = self.current_recovery_id.wrapping_add(1);
        let recovery_id = self.current_recovery_id;

        match self.missing_parents.get_mut(&parent_id) {
            Some(recovery) => {
                recovery.attempts += 1;
                recovery.recovery_id = recovery_id;
                recovery.child_block_id = child_block_id;
                recovery.source_peer = source_peer;
                recovery.is_in_flight = true;
                recovery.is_capacity_waiting = false;
            }
            None => {
                self.missing_parents.insert(
                    parent_id,
                    MissingParentRecovery {
                        recovery_id,
                        parent_id,
                        child_block_id,
                        source_peer,
                        attempts: 1,
                        abort_handle: None,
                        is_in_flight: true,
                        is_capacity_waiting: false,
                    },
                );
            }
        };

        let network_handle = self.network_handle.clone();
        let local_peer_id = self.peer_id;

        let handle = self.recovery_tasks.spawn(async move {
            match Self::fetch_parent_block(
                network_handle,
                local_peer_id,
                parent_id,
                child_block_id,
                source_peer,
            )
            .await
            {
                Some((parent_block, responding_peer)) => RecoveryTaskResult::Fetched {
                    recovery_id,
                    parent_id,
                    source_peer: responding_peer,
                    block: Box::new(parent_block),
                },
                None => RecoveryTaskResult::Failed {
                    recovery_id,
                    parent_id,
                    source_peer,
                },
            }
        });

        let task_id = handle.id();
        self.recovery_task_metadata
            .insert(task_id, (recovery_id, parent_id, source_peer));
        if let Some(entry) = self.missing_parents.get_mut(&parent_id) {
            entry.abort_handle = Some(handle);
        }
    }

    /// Dispatches waiting missing-parent recoveries when capacity slots become available.
    fn dispatch_waiting_recoveries(&mut self) {
        const MAX_PARENT_RETRIES: u32 = 3;
        while self.in_flight_recovery_count() < 16 {
            let parent_id = match self.waiting_recoveries.pop_front() {
                Some(pid) => pid,
                None => break,
            };

            // Verify dependent orphans still exist for this parent
            if !self.orphan_parents.contains_key(&parent_id) {
                self.missing_parents.remove(&parent_id);
                continue;
            }

            let recovery = match self.missing_parents.get_mut(&parent_id) {
                Some(r) => r,
                None => continue,
            };

            if recovery.is_in_flight || recovery.abort_handle.is_some() {
                continue;
            }

            if recovery.attempts >= MAX_PARENT_RETRIES {
                continue;
            }

            recovery.attempts += 1;
            self.current_recovery_id = self.current_recovery_id.wrapping_add(1);
            let recovery_id = self.current_recovery_id;
            recovery.recovery_id = recovery_id;
            recovery.is_in_flight = true;
            recovery.is_capacity_waiting = false;

            // Use surviving child block ID if original was removed
            let child_block_id = self
                .orphan_parents
                .get(&parent_id)
                .and_then(|c| c.first().copied())
                .unwrap_or(recovery.child_block_id);
            recovery.child_block_id = child_block_id;
            let source_peer = recovery.source_peer;

            let network_handle = self.network_handle.clone();
            let local_peer_id = self.peer_id;

            let handle = self.recovery_tasks.spawn(async move {
                match Self::fetch_parent_block(
                    network_handle,
                    local_peer_id,
                    parent_id,
                    child_block_id,
                    source_peer,
                )
                .await
                {
                    Some((parent_block, responding_peer)) => RecoveryTaskResult::Fetched {
                        recovery_id,
                        parent_id,
                        source_peer: responding_peer,
                        block: Box::new(parent_block),
                    },
                    None => RecoveryTaskResult::Failed {
                        recovery_id,
                        parent_id,
                        source_peer,
                    },
                }
            });

            let task_id = handle.id();
            self.recovery_task_metadata
                .insert(task_id, (recovery_id, parent_id, source_peer));
            recovery.abort_handle = Some(handle);
        }
    }

    /// Schedules an autonomous retry for a failed missing-parent recovery using bounded exponential backoff.
    fn evict_stranded_orphans_for_parent(&mut self, parent_id: &Hash) {
        if let Some(children) = self.orphan_parents.remove(parent_id) {
            for child_id in children {
                if let Some(entry) = self.orphan_blocks.remove(&child_id) {
                    self.orphan_bytes = self.orphan_bytes.saturating_sub(entry.serialized_size);
                    self.orphan_order.retain(|id| id != &child_id);
                }
            }
        }
    }

    fn schedule_missing_parent_retry(&mut self, parent_id: Hash) {
        const MAX_PARENT_RETRIES: u32 = 3;
        let recovery = match self.missing_parents.get_mut(&parent_id) {
            Some(r) => r,
            None => return,
        };

        if recovery.attempts >= MAX_PARENT_RETRIES {
            tracing::warn!(
                "Missing parent {} reached retry limit ({}); exhausting retries and evicting stranded orphans",
                parent_id,
                MAX_PARENT_RETRIES
            );
            self.evict_stranded_orphans_for_parent(&parent_id);
            self.missing_parents.remove(&parent_id);
            return;
        }

        // Bounded exponential backoff: 200ms * 2^(attempts - 1), capped at 2000ms
        let delay_millis = 200u64.saturating_mul(1u64 << (recovery.attempts.saturating_sub(1)));
        let backoff_duration = Duration::from_millis(delay_millis.min(2000));

        let recovery_id = recovery.recovery_id;
        let child_block_id = self
            .orphan_parents
            .get(&parent_id)
            .and_then(|c| c.first().copied())
            .unwrap_or(recovery.child_block_id);
        recovery.child_block_id = child_block_id;
        let source_peer = recovery.source_peer;
        recovery.is_in_flight = false;
        recovery.is_capacity_waiting = false;

        let handle = self.recovery_tasks.spawn(async move {
            tokio::time::sleep(backoff_duration).await;
            RecoveryTaskResult::RetryTriggered {
                recovery_id,
                parent_id,
                child_block_id,
                source_peer,
            }
        });

        let task_id = handle.id();
        self.recovery_task_metadata
            .insert(task_id, (recovery_id, parent_id, source_peer));
        recovery.abort_handle = Some(handle);
    }

    /// Submits a transaction locally (e.g. from RPC or CLI).
    ///
    /// Validates and admits the transaction to the mempool, then broadcasts it to peers.
    pub async fn submit_transaction(&mut self, tx_bytes: Vec<u8>) -> Result<Hash, MempoolError> {
        let tx_id = self.mempool.admit(&tx_bytes, &self.chain_state)?;
        let _ = self.network_handle.broadcast_transaction(tx_bytes).await;
        Ok(tx_id)
    }

    /// Submits a block locally (e.g. mined or constructed by tests).
    ///
    /// Validates consensus rules, commits atomically to storage, updates state & mempool,
    /// and broadcasts the block across the network.
    pub async fn submit_block(&mut self, block: Block) -> Result<(), String> {
        self.handle_inbound_block(self.peer_id, Box::new(block))
            .await
    }

    /// Runs the node runtime event loop until a shutdown signal is received.
    pub async fn run(&mut self, mut shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>) {
        tracing::info!(
            "OwnChain node started on {} (Chain ID: {}). Active tip: #{} ({})",
            self.config.network_name,
            self.config.chain_id,
            self.tip_height(),
            self.tip_block_id()
        );

        // Dial bootstrap peers
        for addr in &self.config.bootstrap_peers {
            tracing::info!("Dialing bootstrap peer {}", addr);
            let _ = self.network_handle.dial(addr.clone()).await;
        }

        let mut sync_interval = tokio::time::interval(Duration::from_millis(500));
        let mut stop_responder = None;

        loop {
            tokio::select! {
                _ = async {
                    if let Some(ref mut rx) = shutdown_rx {
                        let _ = rx.changed().await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                } => {
                    tracing::info!("Shutdown signal received, stopping node runtime");
                    break;
                }

                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(NodeCommand::SubmitBlock { block, respond_to }) => {
                            let res = self.handle_inbound_block(self.peer_id, Box::new(block)).await;
                            let _ = respond_to.send(res);
                        }
                        Some(NodeCommand::SubmitTransaction { tx_bytes, respond_to }) => {
                            let res = self.submit_transaction(tx_bytes).await;
                            let _ = respond_to.send(res);
                        }
                        Some(NodeCommand::GetStatus { respond_to }) => {
                            let status = NodeStatus {
                                tip_height: self.tip_height(),
                                tip_block_id: self.tip_block_id(),
                                cumulative_work: self.cumulative_work(),
                                composite_state_root: self.chain_state.composite_state_root(),
                                mempool_size: self.mempool.len(),
                                orphan_pool_size: self.orphan_count(),
                                peer_id: self.peer_id,
                            };
                            let _ = respond_to.send(status);
                        }
                        Some(NodeCommand::GetListenAddrs { respond_to }) => {
                            let addrs = self.network_handle.get_listen_addrs().await.unwrap_or_default();
                            let _ = respond_to.send(addrs);
                        }
                        Some(NodeCommand::GetConnectedPeers { respond_to }) => {
                            let peers = self.network_handle.get_connected_peers().await.unwrap_or_default();
                            let _ = respond_to.send(peers);
                        }
                        Some(NodeCommand::Dial { addr, respond_to }) => {
                            let res = self.network_handle.dial(addr).await;
                            let _ = respond_to.send(res);
                        }
                        Some(NodeCommand::Disconnect { peer_id, respond_to }) => {
                            let res = self.network_handle.disconnect(peer_id).await;
                            let _ = respond_to.send(res);
                        }
                        Some(NodeCommand::SyncWithPeer { peer_id, peer_tip_height, respond_to }) => {
                            self.start_sync(peer_id, peer_tip_height, Some(respond_to));
                        }
                        Some(NodeCommand::Stop { respond_to }) => {
                            stop_responder = Some(respond_to);
                            break;
                        }
                        None => {}
                    }
                }

                _ = sync_interval.tick() => {
                    self.check_sync().await;
                }

                sync_msg = self.sync_msg_rx.recv() => {
                    if let Some(msg) = sync_msg {
                        self.handle_sync_message(msg).await;
                    }
                }

                Some(res) = self.sync_tasks.join_next_with_id(), if !self.sync_tasks.is_empty() => {
                    match res {
                        Ok((task_id, sync_res)) => {
                            let meta = self.sync_task_metadata.remove(&task_id);
                            self.handle_sync_task_success(task_id, meta, sync_res);
                        }
                        Err(join_err) => {
                            let task_id = join_err.id();
                            let meta = self.sync_task_metadata.remove(&task_id);
                            self.handle_sync_task_failure(task_id, meta, join_err);
                        }
                    }
                }

                Some(res) = self.recovery_tasks.join_next_with_id(), if !self.recovery_tasks.is_empty() => {
                    match res {
                        Ok((task_id, rec_res)) => {
                            self.recovery_task_metadata.remove(&task_id);
                            self.handle_recovery_task_result(rec_res).await;
                        }
                        Err(join_err) => {
                            let task_id = join_err.id();
                            let meta = self.recovery_task_metadata.remove(&task_id);
                            self.handle_recovery_task_failure(task_id, meta, join_err).await;
                        }
                    }
                }

                Some(_) = self.snapshot_tasks.join_next(), if !self.snapshot_tasks.is_empty() => {
                    // Reaped completed snapshot preparation task
                }

                event = self.network_event_rx.recv() => {
                    match event {
                        Some(ev) => self.handle_network_event(ev).await,
                        None => {
                            tracing::info!("Network event channel closed, stopping node runtime");
                            break;
                        }
                    }
                }
            }
        }

        // Cleanup on shutdown: abort and join all active background tasks
        if let Some(active) = self.active_sync.take() {
            active
                .cancel_flag
                .store(true, std::sync::atomic::Ordering::SeqCst);
            active.abort_handle.abort();
            if let Some(notifier) = active.notifier {
                let _ = notifier.send(Err("Node runtime stopped".into()));
            }
        }

        for (_, mut recovery) in self.missing_parents.drain() {
            if let Some(handle) = recovery.abort_handle.take() {
                handle.abort();
            }
        }
        self.waiting_recoveries.clear();

        // Drain any pending sync messages to unblock workers that might be awaiting send or ack
        self.sync_msg_rx.close();
        while let Ok(msg) = self.sync_msg_rx.try_recv() {
            match msg {
                RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. } => {
                    let _ = respond_to.send(Err("Node runtime stopped".into()));
                }
            }
        }

        // Await completion of all spawned workers across all JoinSets
        self.sync_tasks.shutdown().await;
        self.recovery_tasks.shutdown().await;
        self.snapshot_tasks.shutdown().await;

        if let Some(net_task) = self.network_task.take() {
            net_task.abort();
            let _ = net_task.await;
        }

        if let Some(responder) = stop_responder {
            let _ = responder.send(());
        }

        tracing::info!("Node runtime cleanly shut down");
    }

    async fn check_sync(&mut self) {
        if self.active_sync.is_some() {
            return;
        }

        if let Ok(peers) = self.network_handle.get_connected_peers().await {
            let mut best_peer = None;
            let mut best_work = self.cumulative_work();

            for p in peers {
                if let Some(ref hs) = p.handshake {
                    if hs.cumulative_work > best_work {
                        best_work = hs.cumulative_work;
                        best_peer = Some((p.peer_id, hs.tip_height));
                    }
                }
            }

            if let Some((peer_id, peer_height)) = best_peer {
                self.start_sync(peer_id, peer_height, None);
            }
        }
    }

    /// Captures a point-in-time immutable snapshot of canonical active chain block IDs up to `peer_tip_height`.
    pub fn capture_active_chain_snapshot(
        &self,
        peer_tip_height: u64,
    ) -> Result<ActiveChainSnapshot, String> {
        let (tip_height, tip_block_id, block_ids) = self
            .storage
            .capture_canonical_chain_snapshot(peer_tip_height)
            .map_err(|e| e.to_string())?;
        Ok(ActiveChainSnapshot {
            tip_height,
            tip_block_id,
            block_ids: Arc::new(block_ids),
        })
    }

    /// Dispatches an asynchronous non-blocking chain synchronization worker.
    fn start_sync(
        &mut self,
        peer_id: PeerId,
        peer_tip_height: u64,
        respond_to: Option<oneshot::Sender<Result<(), String>>>,
    ) {
        if let Some(ref mut active) = self.active_sync {
            if active.peer_id == peer_id && active.notifier.is_none() {
                tracing::debug!(
                    "Sync with peer {} already in progress; attaching notifier to sync #{}",
                    peer_id,
                    active.sync_id
                );
                active.notifier = respond_to;
                return;
            }
            tracing::debug!(
                "Sync already in progress; rejecting concurrent sync request with peer {}",
                peer_id
            );
            if let Some(tx) = respond_to {
                let _ = tx.send(Err("Sync already in progress".to_string()));
            }
            return;
        }

        self.current_sync_id = self.current_sync_id.wrapping_add(1);
        let sync_id = self.current_sync_id;
        let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (snap_tx, snap_rx) = oneshot::channel();

        let storage = self.storage.clone();
        let flag_clone = cancel_flag.clone();
        self.snapshot_tasks.spawn_blocking(move || {
            let res = storage
                .capture_canonical_chain_snapshot_cooperative(peer_tip_height, Some(&flag_clone));
            let _ = snap_tx.send(res);
        });

        let network_handle = self.network_handle.clone();
        let sync_tx = self.sync_msg_tx.clone();

        let worker_handle = self.sync_tasks.spawn(async move {
            let snap_res = match snap_rx.await {
                Ok(res) => res,
                Err(_) => Err(StorageError::InvalidOperation(
                    "Snapshot task cancelled or terminated".into(),
                )),
            };

            let (tip_height, tip_block_id, block_ids) = match snap_res {
                Ok(tuple) => tuple,
                Err(storage_err) => {
                    return SyncTaskResult {
                        sync_id,
                        peer_id,
                        result: Err(format!("Storage error capturing snapshot: {storage_err}")),
                    };
                }
            };

            let snapshot = ActiveChainSnapshot {
                tip_height,
                tip_block_id,
                block_ids: Arc::new(block_ids),
            };

            let ctx = SyncWorkerContext {
                sync_id,
                peer_id,
                peer_tip_height,
                snapshot,
                network_handle,
                sync_tx,
            };

            let worker_res = std::panic::AssertUnwindSafe(Self::run_sync_worker(ctx))
                .catch_unwind()
                .await;

            let result = match worker_res {
                Ok(res) => res,
                Err(panic_payload) => {
                    let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Worker panicked with unknown payload".to_string()
                    };
                    Err(format!("Sync worker panicked: {panic_msg}"))
                }
            };

            SyncTaskResult {
                sync_id,
                peer_id,
                result,
            }
        });

        let task_id = worker_handle.id();
        self.sync_task_metadata.insert(task_id, (sync_id, peer_id));
        self.active_sync = Some(ActiveSyncOperation {
            sync_id,
            peer_id,
            task_id,
            abort_handle: worker_handle,
            cancel_flag,
            notifier: respond_to,
        });
    }

    /// Handles internal synchronization messages on the runtime actor loop.
    async fn handle_sync_message(&mut self, msg: RuntimeSyncMessage) {
        match msg {
            RuntimeSyncMessage::ApplyBlockBatch {
                sync_id,
                peer_id,
                blocks,
                respond_to,
            } => {
                let is_current = match &self.active_sync {
                    Some(active) => active.sync_id == sync_id && active.peer_id == peer_id,
                    None => false,
                };

                if !is_current {
                    tracing::warn!(
                        "Ignoring stale ApplyBlockBatch from sync_id {} (peer {})",
                        sync_id,
                        peer_id
                    );
                    let _ = respond_to.send(Err("stale sync generation".to_string()));
                    return;
                }

                let mut result = Ok(());
                for block in blocks {
                    if let Err(e) = self.handle_inbound_block(peer_id, Box::new(block)).await {
                        tracing::warn!("Sync block validation failed: {}", e);
                        result = Err(e);
                        break;
                    }
                }
                let _ = respond_to.send(result);
            }
        }
    }

    fn handle_sync_task_success(
        &mut self,
        task_id: tokio::task::Id,
        meta: Option<(u64, PeerId)>,
        sync_res: SyncTaskResult,
    ) {
        let (sync_id, peer_id) = match meta {
            Some(m) => m,
            None => (sync_res.sync_id, sync_res.peer_id),
        };

        let is_current = match &self.active_sync {
            Some(active) => active.task_id == task_id && active.sync_id == sync_id,
            None => false,
        };

        if !is_current {
            tracing::warn!(
                "Ignoring stale SyncTaskResult from task {:?}, sync_id {} (peer {})",
                task_id,
                sync_id,
                peer_id
            );
            return;
        }

        tracing::info!(
            "Sync #{} with peer {} finished: {:?}",
            sync_id,
            peer_id,
            sync_res.result
        );

        let active_op = self.active_sync.take().unwrap();
        if let Some(notifier) = active_op.notifier {
            let _ = notifier.send(sync_res.result);
        }
    }

    fn handle_sync_task_failure(
        &mut self,
        task_id: tokio::task::Id,
        meta: Option<(u64, PeerId)>,
        join_err: tokio::task::JoinError,
    ) {
        let (sync_id, peer_id) = meta.unwrap_or((0, self.peer_id));

        let is_current = match &self.active_sync {
            Some(active) => active.task_id == task_id || (active.sync_id == sync_id && sync_id > 0),
            None => false,
        };

        if !is_current {
            tracing::warn!(
                "Ignoring failure from non-active sync task {:?}, sync_id {} (peer {})",
                task_id,
                sync_id,
                peer_id
            );
            return;
        }

        if join_err.is_cancelled() {
            tracing::debug!("Active sync #{} task was cancelled", sync_id);
            if let Some(active_op) = self.active_sync.take() {
                if let Some(notifier) = active_op.notifier {
                    let _ = notifier.send(Err("Sync cancelled".to_string()));
                }
            }
        } else if join_err.is_panic() {
            let panic_msg = if let Ok(panic_payload) = join_err.try_into_panic() {
                if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Worker panicked with unknown payload".to_string()
                }
            } else {
                "Worker panicked".to_string()
            };
            tracing::error!("Sync worker #{} panicked: {}", sync_id, panic_msg);
            if let Some(active_op) = self.active_sync.take() {
                if let Some(notifier) = active_op.notifier {
                    let _ = notifier.send(Err(format!("Sync worker panicked: {panic_msg}")));
                }
            }
        } else {
            tracing::error!("Sync task #{} failed: {}", sync_id, join_err);
            if let Some(active_op) = self.active_sync.take() {
                if let Some(notifier) = active_op.notifier {
                    let _ = notifier.send(Err(format!("Sync task failed: {join_err}")));
                }
            }
        }
    }

    async fn handle_recovery_task_result(&mut self, result: RecoveryTaskResult) {
        match result {
            RecoveryTaskResult::Fetched {
                recovery_id,
                parent_id,
                source_peer,
                block,
            } => {
                match self.missing_parents.get(&parent_id) {
                    Some(recovery) if recovery.recovery_id == recovery_id => {}
                    _ => {
                        tracing::warn!(
                            "Ignoring stale or unknown Fetched for parent {} (recovery_id {})",
                            parent_id,
                            recovery_id
                        );
                        self.dispatch_waiting_recoveries();
                        return;
                    }
                }

                let actual_block_id = block.header.block_id();
                if actual_block_id != parent_id {
                    tracing::warn!(
                        "Missing parent block ID mismatch: expected {}, got {}",
                        parent_id,
                        actual_block_id
                    );
                    if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
                        recovery.is_in_flight = false;
                        recovery.abort_handle = None;
                    }
                    if self.orphan_parents.contains_key(&parent_id) {
                        self.schedule_missing_parent_retry(parent_id);
                    } else {
                        self.missing_parents.remove(&parent_id);
                    }
                    self.dispatch_waiting_recoveries();
                    return;
                }

                if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
                    recovery.is_in_flight = false;
                    recovery.abort_handle = None;
                }

                let apply_res = self.handle_inbound_block(source_peer, block).await;
                let is_accepted = self.storage.has_block(&parent_id).unwrap_or(false);

                if apply_res.is_ok() || is_accepted {
                    self.missing_parents.remove(&parent_id);
                } else {
                    let err_msg = apply_res.err().unwrap_or_else(|| "unknown error".into());
                    tracing::warn!(
                        "Fetched parent block {} failed to apply: {}",
                        parent_id,
                        err_msg
                    );

                    if self.orphan_parents.contains_key(&parent_id) {
                        const MAX_PARENT_RETRIES: u32 = 3;
                        let attempts = self
                            .missing_parents
                            .get(&parent_id)
                            .map(|r| r.attempts)
                            .unwrap_or(0);
                        if attempts < MAX_PARENT_RETRIES {
                            self.schedule_missing_parent_retry(parent_id);
                        } else {
                            tracing::error!(
                                "Missing parent {} reached terminal failure after validation error; evicting stranded orphans",
                                parent_id
                            );
                            self.evict_stranded_orphans_for_parent(&parent_id);
                            self.missing_parents.remove(&parent_id);
                        }
                    } else {
                        self.missing_parents.remove(&parent_id);
                    }
                }

                self.dispatch_waiting_recoveries();
            }

            RecoveryTaskResult::Failed {
                recovery_id,
                parent_id,
                source_peer,
            } => {
                match self.missing_parents.get_mut(&parent_id) {
                    Some(recovery) if recovery.recovery_id == recovery_id => {
                        recovery.is_in_flight = false;
                        recovery.abort_handle = None;
                    }
                    _ => {
                        tracing::warn!(
                            "Ignoring stale or unknown Failed for parent {} (recovery_id {})",
                            parent_id,
                            recovery_id
                        );
                        self.dispatch_waiting_recoveries();
                        return;
                    }
                }

                tracing::debug!(
                    "Missing parent {} recovery from peer {} failed or timed out",
                    parent_id,
                    source_peer
                );

                if self.orphan_parents.contains_key(&parent_id) {
                    self.schedule_missing_parent_retry(parent_id);
                } else {
                    self.missing_parents.remove(&parent_id);
                }

                self.dispatch_waiting_recoveries();
            }

            RecoveryTaskResult::RetryTriggered {
                recovery_id,
                parent_id,
                child_block_id,
                source_peer,
            } => {
                match self.missing_parents.get_mut(&parent_id) {
                    Some(recovery) if recovery.recovery_id == recovery_id => {
                        recovery.abort_handle = None;
                    }
                    _ => {
                        tracing::warn!(
                            "Ignoring stale or unknown RetryTriggered for parent {} (recovery_id {})",
                            parent_id,
                            recovery_id
                        );
                        return;
                    }
                }

                if !self.orphan_parents.contains_key(&parent_id) {
                    self.missing_parents.remove(&parent_id);
                    return;
                }

                if self.in_flight_recovery_count() >= 16 {
                    tracing::warn!(
                        "Concurrency limit (16) reached while retrying missing parent {}; queuing in waiting state",
                        parent_id
                    );
                    if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
                        recovery.is_in_flight = false;
                        recovery.is_capacity_waiting = true;
                    }
                    if !self.waiting_recoveries.contains(&parent_id) {
                        self.waiting_recoveries.push_back(parent_id);
                    }
                    return;
                }

                self.current_recovery_id = self.current_recovery_id.wrapping_add(1);
                let next_recovery_id = self.current_recovery_id;

                if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
                    recovery.attempts += 1;
                    recovery.recovery_id = next_recovery_id;
                    recovery.is_in_flight = true;
                    recovery.is_capacity_waiting = false;
                }

                let effective_child_id = self
                    .orphan_parents
                    .get(&parent_id)
                    .and_then(|c| c.first().copied())
                    .unwrap_or(child_block_id);

                let network_handle = self.network_handle.clone();
                let local_peer_id = self.peer_id;

                let handle = self.recovery_tasks.spawn(async move {
                    match Self::fetch_parent_block(
                        network_handle,
                        local_peer_id,
                        parent_id,
                        effective_child_id,
                        source_peer,
                    )
                    .await
                    {
                        Some((parent_block, responding_peer)) => RecoveryTaskResult::Fetched {
                            recovery_id: next_recovery_id,
                            parent_id,
                            source_peer: responding_peer,
                            block: Box::new(parent_block),
                        },
                        None => RecoveryTaskResult::Failed {
                            recovery_id: next_recovery_id,
                            parent_id,
                            source_peer,
                        },
                    }
                });

                let task_id = handle.id();
                self.recovery_task_metadata
                    .insert(task_id, (next_recovery_id, parent_id, source_peer));
                if let Some(recovery) = self.missing_parents.get_mut(&parent_id) {
                    recovery.abort_handle = Some(handle);
                }
            }
        }
    }

    async fn handle_recovery_task_failure(
        &mut self,
        task_id: tokio::task::Id,
        meta: Option<(u64, Hash, PeerId)>,
        join_err: tokio::task::JoinError,
    ) {
        let (recovery_id, parent_id, _source_peer) = match meta {
            Some(m) => m,
            None => return,
        };

        match self.missing_parents.get_mut(&parent_id) {
            Some(recovery) if recovery.recovery_id == recovery_id => {
                recovery.is_in_flight = false;
                recovery.abort_handle = None;
            }
            _ => {
                tracing::warn!(
                    "Ignoring failure from stale or unknown recovery task {:?}, parent {} (recovery_id {})",
                    task_id,
                    parent_id,
                    recovery_id
                );
                return;
            }
        }

        if join_err.is_panic() {
            tracing::error!("Missing parent recovery worker for {} panicked", parent_id);
        } else if join_err.is_cancelled() {
            tracing::debug!(
                "Missing parent recovery task for {} was cancelled",
                parent_id
            );
        }

        if self.orphan_parents.contains_key(&parent_id) {
            self.schedule_missing_parent_retry(parent_id);
        } else {
            self.missing_parents.remove(&parent_id);
        }

        self.dispatch_waiting_recoveries();
    }

    /// Synchronizes chain state with a peer asynchronously.
    ///
    /// Deprecated: Direct invocation on `NodeRuntime` without running `run()` will not process
    /// background worker messages. Use `NodeHandle::sync_with_peer` or poll the returned receiver.
    #[deprecated(
        note = "Direct invocation on NodeRuntime deadlocks actor loop; use NodeHandle::sync_with_peer or start_sync receiver"
    )]
    pub fn sync_with_peer(
        &mut self,
        peer_id: PeerId,
        peer_tip_height: u64,
    ) -> oneshot::Receiver<Result<(), String>> {
        let (tx, rx) = oneshot::channel();
        self.start_sync(peer_id, peer_tip_height, Some(tx));
        rx
    }
}

struct SyncWorkerContext {
    sync_id: u64,
    peer_id: PeerId,
    peer_tip_height: u64,
    snapshot: ActiveChainSnapshot,
    network_handle: NetworkHandle,
    sync_tx: mpsc::Sender<RuntimeSyncMessage>,
}

impl NodeRuntime {
    /// Outbound synchronization worker performing ancestor discovery and batched block fetches.
    async fn run_sync_worker(ctx: SyncWorkerContext) -> Result<(), String> {
        let SyncWorkerContext {
            sync_id,
            peer_id,
            peer_tip_height,
            snapshot,
            network_handle,
            sync_tx,
        } = ctx;

        // 1. Discover common ancestor between local snapshot and peer chain
        let min_h = snapshot.tip_height().min(peer_tip_height);
        let common_ancestor_height = if min_h == 0 {
            0
        } else {
            // Fast path: check if peer matches our snapshot at min_h
            let fast_req = SyncRequest::GetHeaders {
                start_height: min_h,
                max_count: 1,
            };
            let fast_match = match network_handle.send_sync_request(peer_id, fast_req).await {
                Ok(SyncResponse::Headers(headers)) if headers.len() == 1 => {
                    Some(headers[0].block_id()) == snapshot.get_block_id(min_h)
                }
                _ => false,
            };

            if fast_match {
                min_h
            } else {
                // Binary search for common ancestor in [0, min_h - 1]
                let mut low = 0u64;
                let mut high = min_h - 1;

                while low < high {
                    let mid = (low + high).div_ceil(2);
                    let req = SyncRequest::GetHeaders {
                        start_height: mid,
                        max_count: 1,
                    };
                    match network_handle.send_sync_request(peer_id, req).await {
                        Ok(SyncResponse::Headers(headers)) if headers.len() == 1 => {
                            if Some(headers[0].block_id()) == snapshot.get_block_id(mid) {
                                low = mid;
                            } else {
                                high = mid - 1;
                            }
                        }
                        _ => {
                            return Err(format!(
                                "Failed to query header at height {mid} during ancestor discovery with {peer_id}"
                            ));
                        }
                    }
                }

                low
            }
        };

        tracing::info!(
            "Common ancestor with peer {} found at height #{}. Fetching replacement blocks #{}..#{}",
            peer_id,
            common_ancestor_height,
            common_ancestor_height + 1,
            peer_tip_height
        );

        let mut current_h = common_ancestor_height + 1;
        while current_h <= peer_tip_height {
            let count =
                (peer_tip_height - current_h + 1).min(MAX_HEADERS_PER_RESPONSE as u64) as u32;
            let req = SyncRequest::GetHeaders {
                start_height: current_h,
                max_count: count,
            };

            match network_handle.send_sync_request(peer_id, req).await {
                Ok(SyncResponse::Headers(headers)) => {
                    if headers.is_empty() {
                        break;
                    }

                    let block_ids: Vec<Hash> = headers.iter().map(|h| h.block_id()).collect();

                    // Request blocks for these headers
                    let block_req = SyncRequest::GetBlocks {
                        block_ids: block_ids.clone(),
                    };
                    match network_handle.send_sync_request(peer_id, block_req).await {
                        Ok(SyncResponse::Blocks(blocks)) => {
                            if blocks.is_empty() {
                                break;
                            }
                            let num_blocks = blocks.len() as u64;

                            let (ack_tx, ack_rx) = oneshot::channel();
                            sync_tx
                                .send(RuntimeSyncMessage::ApplyBlockBatch {
                                    sync_id,
                                    peer_id,
                                    blocks,
                                    respond_to: ack_tx,
                                })
                                .await
                                .map_err(|_| "Node runtime shut down during sync".to_string())?;

                            ack_rx.await.map_err(|_| {
                                "Node runtime dropped block batch response".to_string()
                            })??;

                            current_h += num_blocks;
                        }
                        other => {
                            return Err(format!("Unexpected sync blocks response: {other:?}"));
                        }
                    }
                }
                other => {
                    return Err(format!("Unexpected sync headers response: {other:?}"));
                }
            }
        }

        Ok(())
    }

    async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerHandshakeCompleted { peer_id, handshake } => {
                tracing::info!(
                    "Peer {} handshake verified. Remote tip: #{} ({}), work: {:?}",
                    peer_id,
                    handshake.tip_height,
                    handshake.tip_block_id,
                    handshake.cumulative_work
                );
                if handshake.cumulative_work > self.cumulative_work() {
                    self.start_sync(peer_id, handshake.tip_height, None);
                }
            }

            NetworkEvent::PeerDisconnected { peer_id } => {
                tracing::info!("Peer {} disconnected", peer_id);
                if let Some(active) = self.active_sync.take() {
                    if active.peer_id == peer_id {
                        tracing::warn!(
                            "Syncing peer {} disconnected; aborting sync #{}",
                            peer_id,
                            active.sync_id
                        );
                        active
                            .cancel_flag
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        active.abort_handle.abort();
                        if let Some(notifier) = active.notifier {
                            let _ = notifier.send(Err(format!(
                                "Peer {peer_id} disconnected during synchronization"
                            )));
                        }
                    } else {
                        self.active_sync = Some(active);
                    }
                }

                let disconnected_parents: Vec<Hash> = self
                    .missing_parents
                    .iter()
                    .filter(|(_, r)| r.source_peer == peer_id)
                    .map(|(p, _)| *p)
                    .collect();

                for parent_id in disconnected_parents {
                    if let Some(mut recovery) = self.missing_parents.remove(&parent_id) {
                        if let Some(handle) = recovery.abort_handle.take() {
                            handle.abort();
                        }
                        if self.orphan_parents.contains_key(&parent_id) {
                            recovery.is_in_flight = false;
                            recovery.is_capacity_waiting = false;
                            self.missing_parents.insert(parent_id, recovery);
                            self.schedule_missing_parent_retry(parent_id);
                        }
                    }
                }
                self.dispatch_waiting_recoveries();
            }

            NetworkEvent::BlockReceived { peer_id, block } => {
                let _ = self.handle_inbound_block(peer_id, block).await;
            }

            NetworkEvent::TransactionReceived {
                peer_id: _,
                transaction,
            } => match self.mempool.admit(&transaction, &self.chain_state) {
                Ok(tx_id) => {
                    tracing::debug!("Admitted transaction {} into mempool", tx_id);
                    let _ = self.network_handle.broadcast_transaction(transaction).await;
                }
                Err(e) => {
                    tracing::debug!("Rejected inbound transaction: {:?}", e);
                }
            },

            NetworkEvent::SyncRequestReceived {
                peer_id: _,
                request,
                channel,
            } => {
                let response = self.handle_sync_request(request);
                let _ = self
                    .network_handle
                    .send_sync_response(channel, response)
                    .await;
            }
        }
    }

    fn handle_sync_request(&self, request: SyncRequest) -> SyncResponse {
        match request {
            SyncRequest::GetStatus => SyncResponse::Status {
                tip_height: self.tip_height(),
                tip_block_id: self.tip_block_id(),
                cumulative_work: self.cumulative_work(),
            },
            SyncRequest::GetHeaders {
                start_height,
                max_count,
            } => {
                let count = (max_count as usize).min(MAX_HEADERS_PER_RESPONSE);
                let mut headers = Vec::with_capacity(count);
                for h in start_height..(start_height + count as u64) {
                    if let Ok(Some(block)) = self.storage.get_block_by_height(h) {
                        headers.push(block.header);
                    } else {
                        break;
                    }
                }
                SyncResponse::Headers(headers)
            }
            SyncRequest::GetBlocks { block_ids } => {
                let count = block_ids.len().min(MAX_BLOCKS_PER_RESPONSE);
                let mut blocks = Vec::with_capacity(count);
                let mut total_bytes = 0usize;
                for id in block_ids.iter().take(count) {
                    if let Ok(Some(block)) = self.storage.get_block(id) {
                        let block_size = block.to_bytes().map(|b| b.len()).unwrap_or(0);
                        if !blocks.is_empty() && total_bytes + block_size > 1_800_000 {
                            break;
                        }
                        total_bytes += block_size;
                        blocks.push(block);
                    }
                }
                SyncResponse::Blocks(blocks)
            }
            SyncRequest::GetBlockByHeight { height } => {
                match self.storage.get_block_by_height(height) {
                    Ok(Some(block)) => SyncResponse::Blocks(vec![block]),
                    _ => SyncResponse::NotFound,
                }
            }
            SyncRequest::GetMissingParent { child_block_id } => {
                match self.storage.get_block_metadata(&child_block_id) {
                    Ok(Some(meta)) => match self.storage.get_block(&meta.parent_block_id) {
                        Ok(Some(parent)) => SyncResponse::Blocks(vec![parent]),
                        _ => SyncResponse::NotFound,
                    },
                    _ => SyncResponse::NotFound,
                }
            }
            _ => SyncResponse::Error("unsupported sync request variant".into()),
        }
    }

    /// Processes an inbound block from a peer or local source.
    ///
    /// Evaluates consensus rules, atomic persistence, chain reorganization (if competing branch has
    /// strictly higher cumulative proof-of-work), and mempool updates.
    pub async fn handle_inbound_block(
        &mut self,
        source_peer: PeerId,
        block: Box<Block>,
    ) -> Result<(), String> {
        let mut queue = VecDeque::new();
        queue.push_back((source_peer, block));

        while let Some((peer, curr_block)) = queue.pop_front() {
            let (accepted_id, missing_parents) =
                self.process_single_block(peer, curr_block).await?;

            for parent_block in missing_parents {
                queue.push_back((peer, Box::new(parent_block)));
            }

            if let Some(new_id) = accepted_id {
                if let Some(orphan_ids) = self.orphan_parents.remove(&new_id) {
                    for child_id in orphan_ids {
                        if let Some(child_entry) = self.remove_orphan(&child_id) {
                            queue.push_back((child_entry.source_peer, Box::new(child_entry.block)));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_single_block(
        &mut self,
        source_peer: PeerId,
        block: Box<Block>,
    ) -> Result<(Option<Hash>, Vec<Block>), String> {
        let block_id = block.header.block_id();
        let height = block.header.height;
        let parent_id = block.header.parent_block_id;

        // 1. Ignore if block is already known in storage
        if self.storage.has_block(&block_id).unwrap_or(false) {
            return Ok((None, Vec::new()));
        }

        // 2. Missing parent check: if parent is unknown and not genesis, treat as orphan
        let parent_exists =
            parent_id.is_zero() || self.storage.has_block(&parent_id).unwrap_or(false);
        if !parent_exists {
            tracing::debug!(
                "Received orphan block #{} ({}), parent {} unknown. Requesting parent from {}",
                height,
                block_id,
                parent_id,
                source_peer
            );

            self.add_orphan(block_id, *block, source_peer);
            self.trigger_missing_parent_recovery(parent_id, block_id, source_peer);
            return Ok((None, Vec::new()));
        }

        // 3. Case A: Block directly extends current active tip
        if parent_id == self.tip_block_id() {
            let mut candidate_state = self.chain_state.clone();
            candidate_state
                .apply_block(&block)
                .map_err(|e| format!("consensus validation failed: {e}"))?;

            let new_work = candidate_state.cumulative_work();

            // Commit atomically to persistent storage
            self.storage
                .commit_active_block(&block, new_work)
                .map_err(|e| format!("atomic block persistence failed: {e}"))?;

            // Replace in-memory active state ONLY after durable persistence succeeds
            self.chain_state = candidate_state;

            // Update mempool: remove included transactions and revalidate pending
            self.mempool.on_block_accepted(&block, &self.chain_state);

            // Notify network service of new tip
            let _ = self
                .network_handle
                .update_tip(height, block_id, new_work)
                .await;

            // Gossip newly accepted block
            let _ = self.network_handle.broadcast_block(*block).await;

            tracing::info!(
                "Accepted block #{} ({}) into active chain. Work: {:?}",
                height,
                block_id,
                new_work
            );

            return Ok((Some(block_id), Vec::new()));
        }

        // 4. Case B: Competing branch / reorganization evaluation
        let res = self.evaluate_competing_branch(source_peer, *block).await?;
        Ok((res, Vec::new()))
    }

    /// Evaluates a competing branch block, checking whether it leads to a reorganization
    /// based on strictly higher cumulative proof-of-work.
    async fn evaluate_competing_branch(
        &mut self,
        _source_peer: PeerId,
        block: Block,
    ) -> Result<Option<Hash>, String> {
        let block_id = block.header.block_id();

        // Trace backward from `block` to find the common ancestor with the active chain
        let mut branch_blocks = vec![block.clone()];
        let mut curr_parent = block.header.parent_block_id;

        while !curr_parent.is_zero() {
            // Check if curr_parent is on the active chain
            if let Ok(Some(meta)) = self.storage.get_block_metadata(&curr_parent) {
                if meta.is_active {
                    // Found common ancestor!
                    break;
                }
                // Fetch next ancestor on branch
                if let Ok(Some(ancestor_block)) = self.storage.get_block(&curr_parent) {
                    curr_parent = ancestor_block.header.parent_block_id;
                    branch_blocks.push(ancestor_block);
                } else {
                    // Missing middle block on branch
                    let _ = self.storage.store_branch_block(&block, U256::zero());
                    return Ok(None);
                }
            } else {
                let _ = self.storage.store_branch_block(&block, U256::zero());
                return Ok(None);
            }
        }

        branch_blocks.reverse();
        let common_ancestor_id = curr_parent;

        // Reconstruct chain state up to common ancestor
        let common_ancestor_height = if common_ancestor_id.is_zero() {
            0
        } else {
            let meta = self
                .storage
                .get_block_metadata(&common_ancestor_id)
                .map_err(|e| e.to_string())?
                .ok_or("common ancestor metadata not found")?;
            meta.height
        };

        let genesis = genesis_block(self.config.chain_id);
        let mut branch_state = ChainState::from_genesis(&genesis).map_err(|e| e.to_string())?;

        for h in 1..=common_ancestor_height {
            let b = self
                .storage
                .get_block_by_height(h)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("missing block at active height {h}"))?;
            branch_state.apply_block(&b).map_err(|e| e.to_string())?;
        }

        // Apply all replacement branch blocks in sequence
        let mut branch_works = Vec::with_capacity(branch_blocks.len());
        for branch_b in &branch_blocks {
            if let Err(e) = branch_state.apply_block(branch_b) {
                tracing::warn!(
                    "Branch block #{} validation failed: {}",
                    branch_b.header.height,
                    e
                );
                // Do not persist invalid branch block
                return Ok(None);
            }
            branch_works.push(branch_state.cumulative_work());
        }

        let branch_work = branch_state.cumulative_work();
        let active_work = self.chain_state.cumulative_work();

        // Protocol rule: Reorganize ONLY if competing branch cumulative proof-of-work is STRICTLY greater.
        // Equal-work branches must not trigger reorganization (first-seen incumbent rule).
        if branch_work > active_work {
            tracing::warn!(
                "Reorganizing active chain! New branch tip: #{} ({}) with work {:?}, surpassing active work {:?}",
                branch_state.tip_height().unwrap_or(0),
                branch_state.tip_block_id().unwrap_or(Hash::ZERO),
                branch_work,
                active_work
            );

            let old_tip_height = self.chain_state.tip_height().unwrap_or(0);

            // Commit reorganization atomically to storage
            self.storage
                .commit_reorganization(&branch_blocks, &branch_works, old_tip_height)
                .map_err(|e| format!("atomic reorganization persistence failed: {e}"))?;

            // Replace active chain state in memory
            self.chain_state = branch_state;

            // Revalidate mempool after reorganization
            self.mempool.on_reorganization(&self.chain_state);

            // Update network tip
            let tip_h = self.chain_state.tip_height().unwrap_or(0);
            let tip_id = self.chain_state.tip_block_id().unwrap_or(Hash::ZERO);
            let _ = self
                .network_handle
                .update_tip(tip_h, tip_id, branch_work)
                .await;

            // Broadcast new tip
            let _ = self.network_handle.broadcast_block(block.clone()).await;

            Ok(Some(block_id))
        } else {
            // Equal or less work: retain current active chain, record branch block
            let _ = self.storage.store_branch_block(&block, branch_work);
            tracing::debug!(
                "Stored side-branch block #{} ({}). Branch work {:?} <= active work {:?}",
                block.header.height,
                block_id,
                branch_work,
                active_work
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::DEVNET;
    use crate::hash::chain_id;
    use tempfile::TempDir;

    fn make_test_config(dir: &TempDir) -> NodeConfig {
        NodeConfig {
            network_name: "devnet".to_string(),
            chain_id: crate::hash::chain_id("devnet"),
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            data_dir: dir.path().to_path_buf(),
            max_peers: 50,
            bootstrap_peers: vec![],
            mempool_config: Default::default(),
        }
    }

    fn make_test_coinbase(chain_id: Hash, height: u64) -> Vec<u8> {
        use crate::account::scheduled_subsidy;
        let mut tx = Vec::with_capacity(83);
        tx.push(0); // Type 0: Coinbase
        tx.extend_from_slice(&1u16.to_le_bytes());
        tx.extend_from_slice(chain_id.as_bytes());
        tx.extend_from_slice(&height.to_le_bytes());
        tx.extend_from_slice(&[1u8; 32]); // miner address
        let payout = scheduled_subsidy(height) as u64;
        tx.extend_from_slice(&payout.to_le_bytes());
        tx
    }

    fn make_test_valid_child_block(state: &ChainState, timestamp: u64) -> Block {
        use crate::hash::transaction_id;
        use crate::header::Header;
        use crate::merkle;
        use crate::orchard_root::empty_commitment_root;
        let parent = state.tip().unwrap();
        let height = parent.header.height + 1;
        let tx = make_test_coinbase(state.chain_id(), height);
        let tx_id = transaction_id(&tx);
        let mut blk = Block {
            header: Header {
                version: 1,
                chain_id: state.chain_id(),
                height,
                parent_block_id: parent.block_id(),
                transaction_root: merkle::tx_root(&[tx_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp,
                difficulty: state.expected_difficulty_for_next_block().unwrap_or(1),
                nonce: 0,
            },
            transactions: vec![tx],
        };
        let root = state
            .simulate_candidate_state_root(&blk)
            .expect("simulated state root");
        blk.header.orchard_commitment_root = root;
        blk
    }

    #[tokio::test]
    async fn test_sync_worker_supervision_real_panic_cancel_and_stale() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();

        // 1. Normal completion with real spawned task
        let peer_normal = PeerId::random();
        let (tx_normal, rx_normal) = oneshot::channel();
        let sync_id_1 = 101;
        let handle_normal = runtime.sync_tasks.spawn(async move {
            SyncTaskResult {
                sync_id: sync_id_1,
                peer_id: peer_normal,
                result: Ok(()),
            }
        });
        let task_id_normal = handle_normal.id();
        runtime
            .sync_task_metadata
            .insert(task_id_normal, (sync_id_1, peer_normal));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_id: sync_id_1,
            peer_id: peer_normal,
            task_id: task_id_normal,
            abort_handle: handle_normal,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notifier: Some(tx_normal),
        });

        let join_res = runtime.sync_tasks.join_next_with_id().await.unwrap();
        match join_res {
            Ok((t_id, s_res)) => {
                let meta = runtime.sync_task_metadata.remove(&t_id);
                runtime.handle_sync_task_success(t_id, meta, s_res);
            }
            Err(_) => panic!("Expected normal task success"),
        }
        assert!(runtime.active_sync.is_none());
        assert!(rx_normal.await.unwrap().is_ok());

        // 2. Real spawned task panic
        let peer_panic = PeerId::random();
        let (tx_panic, rx_panic) = oneshot::channel();
        let sync_id_2 = 102;
        let handle_panic = runtime.sync_tasks.spawn(async move {
            panic!("real panic in sync worker task");
        });
        let task_id_panic = handle_panic.id();
        runtime
            .sync_task_metadata
            .insert(task_id_panic, (sync_id_2, peer_panic));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_id: sync_id_2,
            peer_id: peer_panic,
            task_id: task_id_panic,
            abort_handle: handle_panic,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notifier: Some(tx_panic),
        });

        let join_res = runtime.sync_tasks.join_next_with_id().await.unwrap();
        match join_res {
            Ok(_) => panic!("Expected task panic JoinError"),
            Err(join_err) => {
                assert!(join_err.is_panic());
                let t_id = join_err.id();
                let meta = runtime.sync_task_metadata.remove(&t_id);
                runtime.handle_sync_task_failure(t_id, meta, join_err);
            }
        }
        assert!(runtime.active_sync.is_none());
        let panic_err = rx_panic.await.unwrap().unwrap_err();
        assert!(
            panic_err.contains("panicked"),
            "Expected panic error, got: {}",
            panic_err
        );

        // 3. Real spawned task cancellation
        let peer_cancel = PeerId::random();
        let (tx_cancel, rx_cancel) = oneshot::channel();
        let sync_id_3 = 103;
        let handle_cancel = runtime.sync_tasks.spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            SyncTaskResult {
                sync_id: sync_id_3,
                peer_id: peer_cancel,
                result: Ok(()),
            }
        });
        let task_id_cancel = handle_cancel.id();
        runtime
            .sync_task_metadata
            .insert(task_id_cancel, (sync_id_3, peer_cancel));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_id: sync_id_3,
            peer_id: peer_cancel,
            task_id: task_id_cancel,
            abort_handle: handle_cancel,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notifier: Some(tx_cancel),
        });

        // Cancel the active sync
        runtime.active_sync.as_ref().unwrap().abort_handle.abort();

        let join_res = runtime.sync_tasks.join_next_with_id().await.unwrap();
        match join_res {
            Ok(_) => panic!("Expected task cancellation JoinError"),
            Err(join_err) => {
                assert!(join_err.is_cancelled());
                let t_id = join_err.id();
                let meta = runtime.sync_task_metadata.remove(&t_id);
                runtime.handle_sync_task_failure(t_id, meta, join_err);
            }
        }
        assert!(runtime.active_sync.is_none());
        let cancel_err = rx_cancel.await.unwrap().unwrap_err();
        assert!(
            cancel_err.contains("cancelled"),
            "Expected cancelled error, got: {}",
            cancel_err
        );

        // 4. Stale task failure arriving after newer sync started
        let old_handle = runtime.sync_tasks.spawn(async {
            panic!("delayed old task panic");
        });
        let old_task_id = old_handle.id();
        runtime
            .sync_task_metadata
            .insert(old_task_id, (999, PeerId::random()));

        // Newer active sync
        let peer_new = PeerId::random();
        let new_handle = runtime.sync_tasks.spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            SyncTaskResult {
                sync_id: 1000,
                peer_id: peer_new,
                result: Ok(()),
            }
        });
        let new_task_id = new_handle.id();
        let (tx_new, _rx_new) = oneshot::channel();
        runtime
            .sync_task_metadata
            .insert(new_task_id, (1000, peer_new));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_id: 1000,
            peer_id: peer_new,
            task_id: new_task_id,
            abort_handle: new_handle,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notifier: Some(tx_new),
        });

        // Old task failure resolves
        let old_join_res = runtime.sync_tasks.join_next_with_id().await.unwrap();
        if let Err(join_err) = old_join_res {
            let t_id = join_err.id();
            let meta = runtime.sync_task_metadata.remove(&t_id);
            runtime.handle_sync_task_failure(t_id, meta, join_err);
        }

        // Newer active sync must remain intact and NOT cleared!
        assert!(runtime.active_sync.is_some());
        assert_eq!(runtime.active_sync.as_ref().unwrap().sync_id, 1000);
        assert_eq!(runtime.active_sync.as_ref().unwrap().task_id, new_task_id);

        // Clean up the newer task
        runtime.active_sync.take().unwrap().abort_handle.abort();
    }

    #[tokio::test]
    async fn test_snapshot_supervision_and_shutdown() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();

        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started_clone = started.clone();
        let finished_clone = finished.clone();

        // Spawn controlled blocking task into snapshot_tasks
        runtime.snapshot_tasks.spawn_blocking(move || {
            started_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            finished_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        for _ in 0..50 {
            if started.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(started.load(std::sync::atomic::Ordering::SeqCst));

        // Shutdown snapshot_tasks explicitly as runtime shutdown does
        runtime.snapshot_tasks.shutdown().await;

        // Verify blocking task is observed to terminate before shutdown returns
        assert!(
            finished.load(std::sync::atomic::Ordering::SeqCst),
            "Blocking snapshot task must be observed to finish before shutdown completes"
        );
    }

    #[tokio::test]
    async fn test_missing_parent_capacity_full_and_auto_dispatch() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer = PeerId::random();

        // Fill missing_parents to capacity (16) with in-flight recoveries
        for i in 0..16 {
            let p_id = Hash::new([i as u8; 32]);
            runtime.missing_parents.insert(
                p_id,
                MissingParentRecovery {
                    recovery_id: i,
                    parent_id: p_id,
                    child_block_id: Hash::new([(i + 100) as u8; 32]),
                    source_peer: peer,
                    attempts: 1,
                    abort_handle: None,
                    is_in_flight: true,
                    is_capacity_waiting: false,
                },
            );
        }
        assert_eq!(runtime.in_flight_recovery_count(), 16);

        // Attempt 17th recovery: capacity full
        let waiting_parent = Hash::new([99u8; 32]);
        let waiting_child = Hash::new([100u8; 32]);

        // Add dependent orphan
        let genesis = crate::genesis::genesis_block(crate::hash::chain_id("devnet"));
        let mut orphan = genesis.clone();
        orphan.header.parent_block_id = waiting_parent;
        runtime.add_orphan(waiting_child, orphan, peer);

        runtime.trigger_missing_parent_recovery(waiting_parent, waiting_child, peer);

        // 1. Prove capacity exhaustion does NOT consume an attempt!
        let waiting_rec = runtime.missing_parents.get(&waiting_parent).unwrap();
        assert_eq!(
            waiting_rec.attempts, 0,
            "Capacity full must not consume an attempt"
        );
        assert!(waiting_rec.is_capacity_waiting);
        assert!(!waiting_rec.is_in_flight);
        assert!(runtime.waiting_recoveries.contains(&waiting_parent));

        // 2. Free up a slot by completing in-flight recovery #0
        let finished_parent = Hash::new([0u8; 32]);
        let genesis_block = genesis.clone();
        runtime
            .handle_recovery_task_result(RecoveryTaskResult::Fetched {
                recovery_id: 0,
                parent_id: finished_parent,
                source_peer: peer,
                block: Box::new(genesis_block),
            })
            .await;

        // 3. Prove waiting recovery is automatically dispatched!
        let dispatched_rec = runtime.missing_parents.get(&waiting_parent).unwrap();
        assert_eq!(
            dispatched_rec.attempts, 1,
            "Dispatched recovery must consume attempt 1"
        );
        assert!(dispatched_rec.is_in_flight);
        assert!(!dispatched_rec.is_capacity_waiting);
        assert!(!runtime.waiting_recoveries.contains(&waiting_parent));
    }

    #[tokio::test]
    async fn test_missing_parent_real_worker_panic_and_retry() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer = PeerId::random();

        let parent_id = Hash::new([77u8; 32]);
        let child_id = Hash::new([88u8; 32]);
        let genesis = crate::genesis::genesis_block(crate::hash::chain_id("devnet"));
        let mut orphan = genesis.clone();
        orphan.header.parent_block_id = parent_id;
        runtime.add_orphan(child_id, orphan, peer);

        // Trigger recovery
        runtime.trigger_missing_parent_recovery(parent_id, child_id, peer);
        let rec_id = runtime.current_recovery_id;
        assert!(
            runtime
                .missing_parents
                .get(&parent_id)
                .unwrap()
                .is_in_flight
        );

        // Spawn a real panicking task into recovery_tasks
        let panic_handle = runtime.recovery_tasks.spawn(async {
            panic!("real panic in recovery worker");
        });
        let panic_task_id = panic_handle.id();
        runtime
            .recovery_task_metadata
            .insert(panic_task_id, (rec_id, parent_id, peer));
        if let Some(r) = runtime.missing_parents.get_mut(&parent_id) {
            r.abort_handle = Some(panic_handle);
        }

        // Join the panicking task
        let join_res = runtime.recovery_tasks.join_next_with_id().await.unwrap();
        match join_res {
            Ok(_) => panic!("Expected worker panic JoinError"),
            Err(join_err) => {
                assert!(join_err.is_panic());
                let t_id = join_err.id();
                let meta = runtime.recovery_task_metadata.remove(&t_id);
                runtime
                    .handle_recovery_task_failure(t_id, meta, join_err)
                    .await;
            }
        }

        // Recovery must NOT be stuck in_flight!
        let recovery = runtime.missing_parents.get(&parent_id).unwrap();
        assert!(
            !recovery.is_in_flight,
            "Panic must not leave recovery marked is_in_flight"
        );
        assert!(
            recovery.abort_handle.is_some(),
            "Panic must schedule backoff retry"
        );
    }

    #[tokio::test]
    async fn test_fetched_parent_validation_failure_and_terminal_exhaustion() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer = PeerId::random();

        let parent_id = Hash::new([33u8; 32]);
        let child_id = Hash::new([44u8; 32]);
        let genesis = crate::genesis::genesis_block(crate::hash::chain_id("devnet"));
        let mut orphan = genesis.clone();
        orphan.header.parent_block_id = parent_id;
        runtime.add_orphan(child_id, orphan, peer);

        runtime.trigger_missing_parent_recovery(parent_id, child_id, peer);
        let rec_id = runtime.current_recovery_id;

        // Construct block with mismatched block ID
        let mut wrong_block = genesis.clone();
        wrong_block.header.height = 999;
        assert_ne!(wrong_block.header.block_id(), parent_id);

        // Deliver mismatched block
        runtime
            .handle_recovery_task_result(RecoveryTaskResult::Fetched {
                recovery_id: rec_id,
                parent_id,
                source_peer: peer,
                block: Box::new(wrong_block),
            })
            .await;

        // Must NOT be accepted; must transition to backoff retry
        let rec_id_3 = {
            let rec = runtime.missing_parents.get(&parent_id).unwrap();
            assert!(!rec.is_in_flight);
            assert!(rec.abort_handle.is_some(), "Mismatch must schedule retry");
            rec.recovery_id
        };

        // Advance attempts to 3 (terminal limit)
        if let Some(r) = runtime.missing_parents.get_mut(&parent_id) {
            r.attempts = 3;
            r.abort_handle = None;
        }

        // Deliver failure on attempt 3 -> triggers terminal failure
        runtime
            .handle_recovery_task_result(RecoveryTaskResult::Failed {
                recovery_id: rec_id_3,
                parent_id,
                source_peer: peer,
            })
            .await;

        // Terminal failure: missing_parents entry removed AND stranded orphan children evicted!
        assert!(!runtime.missing_parents.contains_key(&parent_id));
        assert!(!runtime.orphan_parents.contains_key(&parent_id));
        assert!(!runtime.orphan_blocks.contains_key(&child_id));
    }

    #[tokio::test]
    async fn test_shared_parent_child_removal_fallback() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer = PeerId::random();

        let shared_parent = Hash::new([55u8; 32]);
        let genesis = crate::genesis::genesis_block(crate::hash::chain_id("devnet"));

        let mut orphan1 = genesis.clone();
        orphan1.header.height = 1;
        orphan1.header.parent_block_id = shared_parent;
        orphan1.header.timestamp = 1000;
        let id_1 = orphan1.header.block_id();

        let mut orphan2 = genesis.clone();
        orphan2.header.height = 1;
        orphan2.header.parent_block_id = shared_parent;
        orphan2.header.timestamp = 2000;
        let id_2 = orphan2.header.block_id();

        runtime.add_orphan(id_1, orphan1, peer);
        runtime.trigger_missing_parent_recovery(shared_parent, id_1, peer);
        runtime.add_orphan(id_2, orphan2, peer);

        assert_eq!(
            runtime
                .missing_parents
                .get(&shared_parent)
                .unwrap()
                .child_block_id,
            id_1
        );

        // Remove orphan 1
        runtime.remove_orphan(&id_1);

        // Child block ID must fall back to surviving orphan 2!
        assert!(runtime.missing_parents.contains_key(&shared_parent));
        assert_eq!(
            runtime
                .missing_parents
                .get(&shared_parent)
                .unwrap()
                .child_block_id,
            id_2
        );

        // Remove orphan 2 (last dependent child)
        runtime.remove_orphan(&id_2);

        // Entire recovery entry and waiting entries must be cleaned up
        assert!(!runtime.missing_parents.contains_key(&shared_parent));
        assert!(!runtime.orphan_parents.contains_key(&shared_parent));
    }

    #[tokio::test]
    async fn test_snapshot_acquisition_beyond_genesis() {
        let dir = TempDir::new().unwrap();
        let cid = chain_id(DEVNET);
        let db_path = dir.path().join("blockchain.redb");
        let store = BlockStore::open(&db_path, cid).unwrap();

        let genesis = crate::genesis::genesis_block(cid);
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let mut last_id = genesis.block_id();
        for h in 1..=5 {
            let b = make_test_valid_child_block(&state, genesis.header.timestamp + h * 120);
            state.apply_block(&b).unwrap();
            store
                .commit_active_block(&b, state.cumulative_work())
                .unwrap();
            last_id = b.block_id();
        }

        let (tip_h, tip_id, ids) = store.capture_canonical_chain_snapshot(5).unwrap();
        assert_eq!(tip_h, 5);
        assert_eq!(tip_id, last_id);
        assert_eq!(ids.len(), 6);

        // Bounded scan
        let (tip_h_bounded, _, ids_bounded) = store.capture_canonical_chain_snapshot(3).unwrap();
        assert_eq!(tip_h_bounded, 5);
        assert_eq!(ids_bounded.len(), 4); // heights 0, 1, 2, 3
    }

    #[tokio::test]
    async fn test_runtime_sync_with_peer_public_api_nonblocking() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer = PeerId::random();

        #[allow(deprecated)]
        let rx = runtime.sync_with_peer(peer, 10);
        assert!(runtime.active_sync.is_some());

        drop(rx);
    }
}
