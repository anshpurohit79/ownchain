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

use libp2p::identity::{Keypair, PeerId};
use tokio::sync::mpsc;

use crate::block::Block;
use crate::chain::ChainState;
use crate::difficulty::U256;
use crate::genesis::genesis_block;
use crate::hash::Hash;
use crate::mempool::{Mempool, MempoolError};
use crate::node::config::NodeConfig;
use crate::p2p::identity::{load_or_generate_identity, peer_id_from_keypair};
use crate::p2p::network::{NetworkEvent, NetworkHandle, NetworkService};
use crate::p2p::protocol::{
    SyncRequest, SyncResponse, MAX_BLOCKS_PER_RESPONSE, MAX_HEADERS_PER_RESPONSE,
};
use crate::storage::{BlockStore, StorageError};
use crate::validation::ValidationError;

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

/// The running node instance coordinating blockchain storage, networking, and consensus.
pub struct NodeRuntime {
    config: NodeConfig,
    storage: Arc<BlockStore>,
    chain_state: ChainState,
    mempool: Mempool,
    network_handle: NetworkHandle,
    network_event_rx: mpsc::Receiver<NetworkEvent>,
    keypair: Keypair,
    peer_id: PeerId,
    orphan_blocks: HashMap<Hash, (Block, PeerId)>,
    orphan_parents: HashMap<Hash, Vec<Hash>>,
    is_syncing: bool,
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

        // Spawn network service in background tokio task
        tokio::spawn(network_service.run());

        Ok(Self {
            config,
            storage,
            chain_state,
            mempool,
            network_handle,
            network_event_rx,
            keypair,
            peer_id,
            orphan_blocks: HashMap::new(),
            orphan_parents: HashMap::new(),
            is_syncing: false,
        })
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

        let mut sync_interval = tokio::time::interval(Duration::from_secs(5));

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

                _ = sync_interval.tick() => {
                    self.check_sync().await;
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

        tracing::info!("Node runtime cleanly shut down");
    }

    async fn check_sync(&mut self) {
        if self.is_syncing {
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
                self.sync_with_peer(peer_id, peer_height).await;
            }
        }
    }

    /// Bounded chain synchronization loop with a peer.
    pub async fn sync_with_peer(&mut self, peer_id: PeerId, peer_tip_height: u64) {
        if self.is_syncing {
            return;
        }
        self.is_syncing = true;
        let start_height = self.tip_height() + 1;
        if start_height > peer_tip_height {
            self.is_syncing = false;
            return;
        }

        tracing::info!(
            "Starting chain sync with peer {} from height #{} to #{}",
            peer_id,
            start_height,
            peer_tip_height
        );

        let mut current_h = start_height;
        while current_h <= peer_tip_height {
            let count = (peer_tip_height - current_h + 1).min(50) as u32;
            let req = SyncRequest::GetHeaders {
                start_height: current_h,
                max_count: count,
            };

            match self.network_handle.send_sync_request(peer_id, req).await {
                Ok(SyncResponse::Headers(headers)) => {
                    if headers.is_empty() {
                        break;
                    }

                    let block_ids: Vec<Hash> = headers.iter().map(|h| h.block_id()).collect();
                    let next_h = current_h + headers.len() as u64;

                    // Request blocks for these headers
                    let block_req = SyncRequest::GetBlocks {
                        block_ids: block_ids.clone(),
                    };
                    match self
                        .network_handle
                        .send_sync_request(peer_id, block_req)
                        .await
                    {
                        Ok(SyncResponse::Blocks(blocks)) => {
                            for block in blocks {
                                if let Err(e) =
                                    self.handle_inbound_block(peer_id, Box::new(block)).await
                                {
                                    tracing::warn!("Sync block validation failed: {}", e);
                                    self.is_syncing = false;
                                    return;
                                }
                            }
                        }
                        other => {
                            tracing::warn!("Unexpected sync blocks response: {:?}", other);
                            break;
                        }
                    }

                    current_h = next_h;
                }
                other => {
                    tracing::warn!("Unexpected sync headers response: {:?}", other);
                    break;
                }
            }
        }

        self.is_syncing = false;
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
                    self.sync_with_peer(peer_id, handshake.tip_height).await;
                }
            }

            NetworkEvent::PeerDisconnected { peer_id } => {
                tracing::info!("Peer {} disconnected", peer_id);
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
                for id in block_ids.iter().take(count) {
                    if let Ok(Some(block)) = self.storage.get_block(id) {
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
            let accepted_id = self.process_single_block(peer, curr_block).await?;
            if let Some(new_id) = accepted_id {
                if let Some(orphan_ids) = self.orphan_parents.remove(&new_id) {
                    for child_id in orphan_ids {
                        if let Some((child_block, p)) = self.orphan_blocks.remove(&child_id) {
                            queue.push_back((p, Box::new(child_block)));
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
    ) -> Result<Option<Hash>, String> {
        let block_id = block.header.block_id();
        let height = block.header.height;
        let parent_id = block.header.parent_block_id;

        // 1. Ignore if block is already known in storage
        if self.storage.has_block(&block_id).unwrap_or(false) {
            return Ok(None);
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

            self.orphan_blocks.insert(block_id, (*block, source_peer));
            self.orphan_parents
                .entry(parent_id)
                .or_default()
                .push(block_id);

            // Request missing parent block
            let req = SyncRequest::GetBlocks {
                block_ids: vec![parent_id],
            };
            let _ = self
                .network_handle
                .send_sync_request(source_peer, req)
                .await;
            return Ok(None);
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

            return Ok(Some(block_id));
        }

        // 4. Case B: Competing branch / reorganization evaluation
        self.evaluate_competing_branch(source_peer, *block).await
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
                // Store as unapplied branch block
                let _ = self.storage.store_branch_block(&block, U256::zero());
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
