//! Persistent blockchain storage using embedded ACID key-value database (`redb`).
//!
//! Implements crash-consistent block storage, canonical height indexing,
//! side-branch indexing, and deterministic startup state reconstruction
//! per ADR-005 and `docs/protocol-v1.md`.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};

use crate::block::Block;
use crate::chain::{ChainError, ChainState};
use crate::difficulty::U256;
use crate::error::EncodeError;
use crate::genesis::genesis_block;
use crate::hash::Hash;

/// The database schema version for OwnChain persistent storage.
pub const DATABASE_SCHEMA_VERSION: u32 = 1;

// Table definitions
const TABLE_BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("blocks");
const TABLE_HEIGHT_INDEX: TableDefinition<u64, &[u8; 32]> =
    TableDefinition::new("height_to_block_id");
const TABLE_BLOCK_METADATA: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("block_metadata");
const TABLE_CHAIN_METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_metadata");

/// Metadata keys
const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_CHAIN_ID: &str = "chain_id";
const KEY_TIP_BLOCK_ID: &str = "tip_block_id";
const KEY_TIP_HEIGHT: &str = "tip_height";
const KEY_CUMULATIVE_WORK: &str = "cumulative_work";

/// Errors occurring in persistent blockchain storage.
#[derive(Debug)]
pub enum StorageError {
    /// Database backend error.
    Db(String),
    /// Incompatible database schema version.
    IncompatibleSchemaVersion { found: u32, expected: u32 },
    /// Incompatible network chain ID.
    IncompatibleChainId { found: Hash, expected: Hash },
    /// Malformed or corrupted block data in storage.
    CorruptedBlock { block_id: Hash, source: EncodeError },
    /// Canonical height index missing a block.
    MissingBlockAtHeight { height: u64 },
    /// Block not found by ID.
    BlockNotFound { block_id: Hash },
    /// Reconstructed chain tip does not match persisted metadata.
    TipMismatch {
        reconstructed_id: Hash,
        persisted_id: Hash,
    },
    /// Reconstructed cumulative work does not match persisted metadata.
    WorkMismatch,
    /// Consensus replay error during startup reconstruction.
    ConsensusReplay(ChainError),
    /// Invalid operation.
    InvalidOperation(String),
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::Db(s) => write!(f, "database error: {s}"),
            StorageError::IncompatibleSchemaVersion { found, expected } => write!(
                f,
                "incompatible schema version: found {found}, expected {expected}"
            ),
            StorageError::IncompatibleChainId { found, expected } => {
                write!(
                    f,
                    "incompatible chain ID: found {found}, expected {expected}"
                )
            }
            StorageError::CorruptedBlock { block_id, source } => {
                write!(f, "corrupted block {block_id}: {source}")
            }
            StorageError::MissingBlockAtHeight { height } => {
                write!(f, "missing block at height {height}")
            }
            StorageError::BlockNotFound { block_id } => {
                write!(f, "block not found: {block_id}")
            }
            StorageError::TipMismatch {
                reconstructed_id,
                persisted_id,
            } => write!(
                f,
                "tip mismatch: reconstructed {reconstructed_id}, persisted {persisted_id}"
            ),
            StorageError::WorkMismatch => write!(f, "cumulative work mismatch after replay"),
            StorageError::ConsensusReplay(e) => {
                write!(f, "consensus replay error on startup: {e}")
            }
            StorageError::InvalidOperation(s) => write!(f, "invalid storage operation: {s}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<redb::Error> for StorageError {
    fn from(e: redb::Error) -> Self {
        StorageError::Db(e.to_string())
    }
}

impl From<redb::TransactionError> for StorageError {
    fn from(e: redb::TransactionError) -> Self {
        StorageError::Db(e.to_string())
    }
}

impl From<redb::TableError> for StorageError {
    fn from(e: redb::TableError) -> Self {
        StorageError::Db(e.to_string())
    }
}

impl From<redb::CommitError> for StorageError {
    fn from(e: redb::CommitError) -> Self {
        StorageError::Db(e.to_string())
    }
}

impl From<redb::DatabaseError> for StorageError {
    fn from(e: redb::DatabaseError) -> Self {
        StorageError::Db(e.to_string())
    }
}

impl From<redb::StorageError> for StorageError {
    fn from(e: redb::StorageError) -> Self {
        StorageError::Db(e.to_string())
    }
}

/// Metadata stored per block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StoredBlockMetadata {
    pub parent_block_id: Hash,
    pub height: u64,
    pub cumulative_work: U256,
    pub is_active: bool,
}

impl StoredBlockMetadata {
    pub fn serialize(&self) -> [u8; 73] {
        let mut out = [0u8; 73];
        out[0..32].copy_from_slice(self.parent_block_id.as_bytes());
        out[32..40].copy_from_slice(&self.height.to_le_bytes());
        out[40..72].copy_from_slice(&self.cumulative_work.to_le_bytes());
        out[72] = if self.is_active { 1 } else { 0 };
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 73 {
            return None;
        }
        let mut parent_bytes = [0u8; 32];
        parent_bytes.copy_from_slice(&bytes[0..32]);
        let height = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let mut work_bytes = [0u8; 32];
        work_bytes.copy_from_slice(&bytes[40..72]);
        let cumulative_work = U256::from_le_bytes(work_bytes);
        let is_active = bytes[72] == 1;

        Some(StoredBlockMetadata {
            parent_block_id: Hash::new(parent_bytes),
            height,
            cumulative_work,
            is_active,
        })
    }
}

/// Persistent blockchain database engine.
pub struct BlockStore {
    db: Arc<Database>,
    chain_id: Hash,
}

impl BlockStore {
    /// Opens or initializes a block store at `path` for network `chain_id`.
    ///
    /// If the database is newly created, it writes genesis block and initial metadata.
    /// If the database already exists, it verifies schema version and `chain_id`.
    pub fn open<P: AsRef<Path>>(path: P, chain_id: Hash) -> Result<Self, StorageError> {
        let db = Database::create(path.as_ref())?;
        let db = Arc::new(db);

        let store = Self { db, chain_id };
        store.init_or_verify()?;
        Ok(store)
    }

    /// Initializes tables and genesis if uninitialized, or verifies existing schema & chain ID.
    fn init_or_verify(&self) -> Result<(), StorageError> {
        let write_tx = self.db.begin_write()?;
        {
            let mut chain_meta = write_tx.open_table(TABLE_CHAIN_METADATA)?;

            let existing_version = {
                let guard = chain_meta.get(KEY_SCHEMA_VERSION)?;
                if let Some(v_bytes) = guard {
                    let v =
                        u32::from_le_bytes(v_bytes.value().try_into().map_err(|_| {
                            StorageError::Db("invalid schema version length".into())
                        })?);
                    Some(v)
                } else {
                    None
                }
            };

            if let Some(v) = existing_version {
                if v != DATABASE_SCHEMA_VERSION {
                    return Err(StorageError::IncompatibleSchemaVersion {
                        found: v,
                        expected: DATABASE_SCHEMA_VERSION,
                    });
                }

                let found_chain_id = {
                    let cid_guard = chain_meta.get(KEY_CHAIN_ID)?.ok_or_else(|| {
                        StorageError::Db("missing chain_id in initialized database".into())
                    })?;
                    let mut cid = [0u8; 32];
                    cid.copy_from_slice(cid_guard.value());
                    Hash::new(cid)
                };

                if found_chain_id != self.chain_id {
                    return Err(StorageError::IncompatibleChainId {
                        found: found_chain_id,
                        expected: self.chain_id,
                    });
                }
            } else {
                // Initialize fresh database
                let genesis = genesis_block(self.chain_id);
                let genesis_id = genesis.block_id();
                let genesis_bytes = genesis
                    .to_bytes()
                    .map_err(|e| StorageError::Db(format!("failed to serialize genesis: {e}")))?;

                chain_meta.insert(
                    KEY_SCHEMA_VERSION,
                    &DATABASE_SCHEMA_VERSION.to_le_bytes()[..],
                )?;
                chain_meta.insert(KEY_CHAIN_ID, self.chain_id.as_bytes().as_slice())?;
                chain_meta.insert(KEY_TIP_BLOCK_ID, genesis_id.as_bytes().as_slice())?;
                chain_meta.insert(KEY_TIP_HEIGHT, &0u64.to_le_bytes()[..])?;
                chain_meta.insert(KEY_CUMULATIVE_WORK, U256::zero().to_le_bytes().as_slice())?;

                let mut blocks = write_tx.open_table(TABLE_BLOCKS)?;
                blocks.insert(genesis_id.as_bytes(), genesis_bytes.as_slice())?;

                let mut height_idx = write_tx.open_table(TABLE_HEIGHT_INDEX)?;
                height_idx.insert(0u64, genesis_id.as_bytes())?;

                let mut block_meta = write_tx.open_table(TABLE_BLOCK_METADATA)?;
                let meta = StoredBlockMetadata {
                    parent_block_id: Hash::ZERO,
                    height: 0,
                    cumulative_work: U256::zero(),
                    is_active: true,
                };
                block_meta.insert(genesis_id.as_bytes(), meta.serialize().as_slice())?;
            }
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Reconstructs in-memory `ChainState` from persisted canonical blocks.
    ///
    /// Replays each block in height order through `apply_block`, rebuilding all
    /// transparent accounts, Orchard commitment tree, nullifier set, historical anchors,
    /// pool accounting, and cumulative work from consensus rules.
    pub fn reconstruct_chain_state(&self) -> Result<ChainState, StorageError> {
        let read_tx = self.db.begin_read()?;
        let chain_meta = read_tx.open_table(TABLE_CHAIN_METADATA)?;
        let height_idx = read_tx.open_table(TABLE_HEIGHT_INDEX)?;
        let blocks = read_tx.open_table(TABLE_BLOCKS)?;

        let tip_height = {
            let h_bytes = chain_meta
                .get(KEY_TIP_HEIGHT)?
                .ok_or_else(|| StorageError::Db("missing tip_height in chain metadata".into()))?;
            u64::from_le_bytes(
                h_bytes
                    .value()
                    .try_into()
                    .map_err(|_| StorageError::Db("invalid tip height bytes".into()))?,
            )
        };

        let persisted_tip_id = {
            let id_bytes = chain_meta
                .get(KEY_TIP_BLOCK_ID)?
                .ok_or_else(|| StorageError::Db("missing tip_block_id in chain metadata".into()))?;
            let mut id = [0u8; 32];
            id.copy_from_slice(id_bytes.value());
            Hash::new(id)
        };

        let persisted_work = {
            let w_bytes = chain_meta.get(KEY_CUMULATIVE_WORK)?.ok_or_else(|| {
                StorageError::Db("missing cumulative_work in chain metadata".into())
            })?;
            let mut w = [0u8; 32];
            w.copy_from_slice(w_bytes.value());
            U256::from_le_bytes(w)
        };

        // Load genesis
        let genesis_id_val = height_idx
            .get(0u64)?
            .ok_or(StorageError::MissingBlockAtHeight { height: 0 })?;
        let genesis_id = Hash::new(*genesis_id_val.value());
        let genesis_bytes =
            blocks
                .get(genesis_id.as_bytes())?
                .ok_or(StorageError::BlockNotFound {
                    block_id: genesis_id,
                })?;
        let genesis =
            Block::from_bytes(genesis_bytes.value()).map_err(|e| StorageError::CorruptedBlock {
                block_id: genesis_id,
                source: e,
            })?;

        let mut chain_state =
            ChainState::from_genesis(&genesis).map_err(StorageError::ConsensusReplay)?;

        // Replay blocks 1..=tip_height
        for h in 1..=tip_height {
            let b_id_val = height_idx
                .get(h)?
                .ok_or(StorageError::MissingBlockAtHeight { height: h })?;
            let b_id = Hash::new(*b_id_val.value());
            let b_bytes = blocks
                .get(b_id.as_bytes())?
                .ok_or(StorageError::BlockNotFound { block_id: b_id })?;
            let block =
                Block::from_bytes(b_bytes.value()).map_err(|e| StorageError::CorruptedBlock {
                    block_id: b_id,
                    source: e,
                })?;
            chain_state
                .apply_block(&block)
                .map_err(StorageError::ConsensusReplay)?;
        }

        // Verify reconstructed state against persisted tip metadata
        let reconstructed_tip_id = chain_state.tip_block_id().unwrap_or(genesis_id);
        if reconstructed_tip_id != persisted_tip_id {
            return Err(StorageError::TipMismatch {
                reconstructed_id: reconstructed_tip_id,
                persisted_id: persisted_tip_id,
            });
        }

        if chain_state.cumulative_work() != persisted_work {
            return Err(StorageError::WorkMismatch);
        }

        Ok(chain_state)
    }

    /// Stores a side-branch block (or unapplied fork block) without making it the active tip.
    pub fn store_branch_block(
        &self,
        block: &Block,
        cumulative_work: U256,
    ) -> Result<(), StorageError> {
        let block_id = block.block_id();
        let block_bytes = block
            .to_bytes()
            .map_err(|e| StorageError::Db(format!("failed to serialize block: {e}")))?;

        let write_tx = self.db.begin_write()?;
        {
            let mut blocks = write_tx.open_table(TABLE_BLOCKS)?;
            blocks.insert(block_id.as_bytes(), block_bytes.as_slice())?;

            let mut block_meta = write_tx.open_table(TABLE_BLOCK_METADATA)?;
            let meta = StoredBlockMetadata {
                parent_block_id: block.header.parent_block_id,
                height: block.header.height,
                cumulative_work,
                is_active: false,
            };
            block_meta.insert(block_id.as_bytes(), meta.serialize().as_slice())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Atomically persists an accepted block extending the current active chain tip.
    ///
    /// Writes the block bytes, updates `height_to_block_id` index, records block metadata,
    /// and updates tip metadata atomically in a single ACID transaction.
    pub fn commit_active_block(
        &self,
        block: &Block,
        cumulative_work: U256,
    ) -> Result<(), StorageError> {
        let block_id = block.block_id();
        let height = block.header.height;
        let block_bytes = block
            .to_bytes()
            .map_err(|e| StorageError::Db(format!("failed to serialize block: {e}")))?;

        let write_tx = self.db.begin_write()?;
        {
            let mut blocks = write_tx.open_table(TABLE_BLOCKS)?;
            blocks.insert(block_id.as_bytes(), block_bytes.as_slice())?;

            let mut height_idx = write_tx.open_table(TABLE_HEIGHT_INDEX)?;
            height_idx.insert(height, block_id.as_bytes())?;

            let mut block_meta = write_tx.open_table(TABLE_BLOCK_METADATA)?;
            let meta = StoredBlockMetadata {
                parent_block_id: block.header.parent_block_id,
                height,
                cumulative_work,
                is_active: true,
            };
            block_meta.insert(block_id.as_bytes(), meta.serialize().as_slice())?;

            let mut chain_meta = write_tx.open_table(TABLE_CHAIN_METADATA)?;
            chain_meta.insert(KEY_TIP_BLOCK_ID, block_id.as_bytes().as_slice())?;
            chain_meta.insert(KEY_TIP_HEIGHT, &height.to_le_bytes()[..])?;
            chain_meta.insert(
                KEY_CUMULATIVE_WORK,
                cumulative_work.to_le_bytes().as_slice(),
            )?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Atomically commits a reorganization to a new active branch.
    ///
    /// Updates `height_to_block_id` for every block on the replacement branch,
    /// sets `is_active` flags, removes stale heights if the old branch was longer,
    /// and updates tip metadata inside a single atomic write transaction.
    pub fn commit_reorganization(
        &self,
        new_active_blocks: &[Block],
        new_cumulative_work: &[U256],
        old_tip_height: u64,
    ) -> Result<(), StorageError> {
        if new_active_blocks.is_empty() {
            return Ok(());
        }
        if new_active_blocks.len() != new_cumulative_work.len() {
            return Err(StorageError::InvalidOperation(
                "blocks and work lengths mismatch".into(),
            ));
        }

        let new_tip = new_active_blocks.last().unwrap();
        let new_tip_id = new_tip.block_id();
        let new_tip_height = new_tip.header.height;
        let new_tip_work = *new_cumulative_work.last().unwrap();

        let write_tx = self.db.begin_write()?;
        {
            let mut blocks = write_tx.open_table(TABLE_BLOCKS)?;
            let mut height_idx = write_tx.open_table(TABLE_HEIGHT_INDEX)?;
            let mut block_meta = write_tx.open_table(TABLE_BLOCK_METADATA)?;
            let mut chain_meta = write_tx.open_table(TABLE_CHAIN_METADATA)?;

            // 1. For every active height that will be replaced by the replacement branch:
            // Read its previous block ID from the active height index and mark its metadata inactive.
            let mut displaced_metas = Vec::new();
            for block in new_active_blocks {
                let h = block.header.height;
                let b_id = block.block_id();
                if let Some(old_id_val) = height_idx.get(h)? {
                    let old_id = Hash::new(*old_id_val.value());
                    if old_id != b_id {
                        if let Some(old_meta_val) = block_meta.get(old_id.as_bytes())? {
                            if let Some(mut m) =
                                StoredBlockMetadata::deserialize(old_meta_val.value())
                            {
                                m.is_active = false;
                                displaced_metas.push((old_id, m));
                            }
                        }
                    }
                }
            }

            // 2. If the previous active chain was longer than the new tip,
            // mark displaced blocks inactive and remove the stale height index entries.
            if old_tip_height > new_tip_height {
                for h in (new_tip_height + 1)..=old_tip_height {
                    if let Some(old_id_val) = height_idx.get(h)? {
                        let old_id = Hash::new(*old_id_val.value());
                        if let Some(old_meta_val) = block_meta.get(old_id.as_bytes())? {
                            if let Some(mut m) =
                                StoredBlockMetadata::deserialize(old_meta_val.value())
                            {
                                m.is_active = false;
                                displaced_metas.push((old_id, m));
                            }
                        }
                    }
                    height_idx.remove(h)?;
                }
            }

            for (old_id, m) in displaced_metas {
                block_meta.insert(old_id.as_bytes(), m.serialize().as_slice())?;
            }

            // 3. Insert replacement branch blocks, update height index, and mark metadata active
            for (block, &work) in new_active_blocks.iter().zip(new_cumulative_work.iter()) {
                let b_id = block.block_id();
                let b_bytes = block
                    .to_bytes()
                    .map_err(|e| StorageError::Db(format!("failed to serialize block: {e}")))?;
                blocks.insert(b_id.as_bytes(), b_bytes.as_slice())?;
                height_idx.insert(block.header.height, b_id.as_bytes())?;

                let meta = StoredBlockMetadata {
                    parent_block_id: block.header.parent_block_id,
                    height: block.header.height,
                    cumulative_work: work,
                    is_active: true,
                };
                block_meta.insert(b_id.as_bytes(), meta.serialize().as_slice())?;
            }

            // 4. Update active tip metadata
            chain_meta.insert(KEY_TIP_BLOCK_ID, new_tip_id.as_bytes().as_slice())?;
            chain_meta.insert(KEY_TIP_HEIGHT, &new_tip_height.to_le_bytes()[..])?;
            chain_meta.insert(KEY_CUMULATIVE_WORK, new_tip_work.to_le_bytes().as_slice())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Retrieves a block by its block ID.
    pub fn get_block(&self, block_id: &Hash) -> Result<Option<Block>, StorageError> {
        let read_tx = self.db.begin_read()?;
        let blocks = read_tx.open_table(TABLE_BLOCKS)?;
        match blocks.get(block_id.as_bytes())? {
            Some(bytes) => {
                let block =
                    Block::from_bytes(bytes.value()).map_err(|e| StorageError::CorruptedBlock {
                        block_id: *block_id,
                        source: e,
                    })?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Retrieves the block at height `height` on the active canonical chain.
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, StorageError> {
        let read_tx = self.db.begin_read()?;
        let height_idx = read_tx.open_table(TABLE_HEIGHT_INDEX)?;
        match height_idx.get(height)? {
            Some(id_val) => {
                let id = Hash::new(*id_val.value());
                let blocks = read_tx.open_table(TABLE_BLOCKS)?;
                match blocks.get(id.as_bytes())? {
                    Some(bytes) => {
                        let block = Block::from_bytes(bytes.value()).map_err(|e| {
                            StorageError::CorruptedBlock {
                                block_id: id,
                                source: e,
                            }
                        })?;
                        Ok(Some(block))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Retrieves block metadata by block ID.
    pub fn get_block_metadata(
        &self,
        block_id: &Hash,
    ) -> Result<Option<StoredBlockMetadata>, StorageError> {
        let read_tx = self.db.begin_read()?;
        let meta_table = read_tx.open_table(TABLE_BLOCK_METADATA)?;
        match meta_table.get(block_id.as_bytes())? {
            Some(val) => Ok(StoredBlockMetadata::deserialize(val.value())),
            None => Ok(None),
        }
    }

    /// Checks if a block ID exists in storage (either active or branch).
    pub fn has_block(&self, block_id: &Hash) -> Result<bool, StorageError> {
        let read_tx = self.db.begin_read()?;
        let blocks = read_tx.open_table(TABLE_BLOCKS)?;
        Ok(blocks.get(block_id.as_bytes())?.is_some())
    }

    /// Returns the current active chain tip metadata: `(tip_height, tip_block_id, cumulative_work)`.
    pub fn get_tip(&self) -> Result<(u64, Hash, U256), StorageError> {
        let read_tx = self.db.begin_read()?;
        let chain_meta = read_tx.open_table(TABLE_CHAIN_METADATA)?;

        let h_bytes = chain_meta
            .get(KEY_TIP_HEIGHT)?
            .ok_or_else(|| StorageError::Db("missing tip height".into()))?;
        let height = u64::from_le_bytes(
            h_bytes
                .value()
                .try_into()
                .map_err(|_| StorageError::Db("invalid tip height bytes".into()))?,
        );

        let id_bytes = chain_meta
            .get(KEY_TIP_BLOCK_ID)?
            .ok_or_else(|| StorageError::Db("missing tip block ID".into()))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(id_bytes.value());

        let w_bytes = chain_meta
            .get(KEY_CUMULATIVE_WORK)?
            .ok_or_else(|| StorageError::Db("missing cumulative work".into()))?;
        let mut w = [0u8; 32];
        w.copy_from_slice(w_bytes.value());

        Ok((height, Hash::new(id), U256::from_le_bytes(w)))
    }

    /// Atomically captures a consistent point-in-time snapshot of the canonical chain
    /// block IDs up to `target_max_height` inside a single read transaction.
    ///
    /// The returned tuple contains: `(tip_height, tip_block_id, canonical_block_ids_0_to_scan_limit)`.
    pub fn capture_canonical_chain_snapshot(
        &self,
        target_max_height: u64,
    ) -> Result<(u64, Hash, Vec<Hash>), StorageError> {
        self.capture_canonical_chain_snapshot_cooperative(target_max_height, None)
    }

    /// Captures a point-in-time immutable snapshot with support for cooperative cancellation.
    pub fn capture_canonical_chain_snapshot_cooperative(
        &self,
        target_max_height: u64,
        cancel_flag: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<(u64, Hash, Vec<Hash>), StorageError> {
        let read_tx = self.db.begin_read()?;
        let chain_meta = read_tx.open_table(TABLE_CHAIN_METADATA)?;
        let height_idx = read_tx.open_table(TABLE_HEIGHT_INDEX)?;

        let tip_height = {
            let h_bytes = chain_meta
                .get(KEY_TIP_HEIGHT)?
                .ok_or_else(|| StorageError::Db("missing tip height".into()))?;
            u64::from_le_bytes(
                h_bytes
                    .value()
                    .try_into()
                    .map_err(|_| StorageError::Db("invalid tip height bytes".into()))?,
            )
        };

        let tip_block_id = {
            let id_bytes = chain_meta
                .get(KEY_TIP_BLOCK_ID)?
                .ok_or_else(|| StorageError::Db("missing tip block ID".into()))?;
            let mut id = [0u8; 32];
            id.copy_from_slice(id_bytes.value());
            Hash::new(id)
        };

        let scan_limit = tip_height.min(target_max_height);
        let mut block_ids = Vec::with_capacity((scan_limit + 1) as usize);

        for h in 0..=scan_limit {
            if let Some(flag) = cancel_flag {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StorageError::InvalidOperation(
                        "Snapshot acquisition cancelled".into(),
                    ));
                }
            }
            let id_val = height_idx
                .get(h)?
                .ok_or(StorageError::MissingBlockAtHeight { height: h })?;
            let id = Hash::new(*id_val.value());
            block_ids.push(id);
        }

        Ok((tip_height, tip_block_id, block_ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::scheduled_subsidy;
    use crate::genesis::DEVNET;
    use crate::hash::{chain_id, transaction_id};
    use crate::header::Header;
    use crate::merkle;
    use crate::orchard_root::empty_commitment_root;

    fn make_coinbase(chain_id: Hash, height: u64) -> Vec<u8> {
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

    fn make_valid_child_block(state: &ChainState, timestamp: u64) -> Block {
        let parent = state.tip().unwrap();
        let height = parent.header.height + 1;
        let tx = make_coinbase(state.chain_id(), height);
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

    #[test]
    fn test_init_and_reconstruct_genesis() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let cid = chain_id(DEVNET);

        let store = BlockStore::open(&db_path, cid).unwrap();
        let (height, tip_id, work) = store.get_tip().unwrap();
        assert_eq!(height, 0);
        assert_eq!(work, U256::zero());

        let genesis = genesis_block(cid);
        assert_eq!(tip_id, genesis.block_id());

        // Reconstruct chain state
        let state = store.reconstruct_chain_state().unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(state.tip_height(), Some(0));
        assert_eq!(state.tip_block_id(), Some(genesis.block_id()));
        assert_eq!(state.cumulative_work(), U256::zero());
    }

    #[test]
    fn test_reject_wrong_chain_id() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let cid1 = chain_id(DEVNET);
        let cid2 = chain_id("testnet");

        // Initialize with cid1
        let _store1 = BlockStore::open(&db_path, cid1).unwrap();
        drop(_store1);

        // Open with cid2 -> should fail
        let res = BlockStore::open(&db_path, cid2);
        assert!(matches!(res, Err(StorageError::IncompatibleChainId { .. })));
    }

    #[test]
    fn test_commit_and_reconstruct_chain() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let cid = chain_id(DEVNET);

        let store = BlockStore::open(&db_path, cid).unwrap();
        let mut state = store.reconstruct_chain_state().unwrap();

        let genesis_time = genesis_block(cid).header.timestamp;
        let mut prev_time = genesis_time;

        // Apply and commit 3 blocks
        for _ in 1..=3 {
            prev_time += 120;
            let blk = make_valid_child_block(&state, prev_time);
            state.apply_block(&blk).unwrap();
            store
                .commit_active_block(&blk, state.cumulative_work())
                .unwrap();
        }

        assert_eq!(state.len(), 4);
        let tip_id = state.tip_block_id().unwrap();
        let tip_height = state.tip_height().unwrap();
        let tip_work = state.cumulative_work();

        drop(store);

        // Reopen database and reconstruct
        let reopened_store = BlockStore::open(&db_path, cid).unwrap();
        let (persisted_h, persisted_id, persisted_w) = reopened_store.get_tip().unwrap();
        assert_eq!(persisted_h, tip_height);
        assert_eq!(persisted_id, tip_id);
        assert_eq!(persisted_w, tip_work);

        let reconstructed_state = reopened_store.reconstruct_chain_state().unwrap();
        assert_eq!(reconstructed_state.len(), 4);
        assert_eq!(reconstructed_state.tip_height(), Some(tip_height));
        assert_eq!(reconstructed_state.tip_block_id(), Some(tip_id));
        assert_eq!(reconstructed_state.cumulative_work(), tip_work);
        assert_eq!(
            reconstructed_state.composite_state_root(),
            state.composite_state_root()
        );
    }

    #[test]
    fn test_reorganization_storage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let cid = chain_id(DEVNET);

        let store = BlockStore::open(&db_path, cid).unwrap();
        let genesis_state = store.reconstruct_chain_state().unwrap();
        let genesis_time = genesis_block(cid).header.timestamp;

        // Branch A: 1 block
        let mut state_a = genesis_state.clone();
        let b1a = make_valid_child_block(&state_a, genesis_time + 120);
        state_a.apply_block(&b1a).unwrap();
        store
            .commit_active_block(&b1a, state_a.cumulative_work())
            .unwrap();

        // Branch B: 2 blocks (forks from genesis)
        let mut state_b = genesis_state.clone();
        let b1b = make_valid_child_block(&state_b, genesis_time + 130);
        state_b.apply_block(&b1b).unwrap();
        let b2b = make_valid_child_block(&state_b, genesis_time + 250);
        state_b.apply_block(&b2b).unwrap();

        // Reorganize store to Branch B
        store
            .commit_reorganization(
                &[b1b.clone(), b2b.clone()],
                state_b.cumulative_work_history()[1..].as_ref(),
                state_a.tip_height().unwrap(),
            )
            .unwrap();

        drop(store);

        // Reopen and verify reconstructed tip is Branch B (height 2)
        let reopened = BlockStore::open(&db_path, cid).unwrap();
        let (tip_h, tip_id, tip_work) = reopened.get_tip().unwrap();
        assert_eq!(tip_h, 2);
        assert_eq!(tip_id, b2b.block_id());
        assert_eq!(tip_work, state_b.cumulative_work());

        let reconstructed = reopened.reconstruct_chain_state().unwrap();
        assert_eq!(reconstructed.tip_height(), Some(2));
        assert_eq!(reconstructed.tip_block_id(), Some(b2b.block_id()));
    }

    #[test]
    fn test_reorganization_metadata_consistency_regression() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_reorg_consistency.redb");
        let cid = chain_id(DEVNET);

        let store = BlockStore::open(&db_path, cid).unwrap();
        let genesis_state = store.reconstruct_chain_state().unwrap();
        let genesis_time = genesis_block(cid).header.timestamp;

        // 1. Build active branch A (2 blocks)
        let mut state_a = genesis_state.clone();
        let b1a = make_valid_child_block(&state_a, genesis_time + 120);
        state_a.apply_block(&b1a).unwrap();
        store
            .commit_active_block(&b1a, state_a.cumulative_work())
            .unwrap();

        let b2a = make_valid_child_block(&state_a, genesis_time + 240);
        state_a.apply_block(&b2a).unwrap();
        store
            .commit_active_block(&b2a, state_a.cumulative_work())
            .unwrap();

        let b1a_id = b1a.block_id();
        let b2a_id = b2a.block_id();

        // Both b1a and b2a should be active
        assert!(
            store
                .get_block_metadata(&b1a_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            store
                .get_block_metadata(&b2a_id)
                .unwrap()
                .unwrap()
                .is_active
        );

        // 2. Build competing equal-height branch B (2 blocks) with greater cumulative work
        let mut state_b = genesis_state.clone();
        let b1b = make_valid_child_block(&state_b, genesis_time + 130);
        state_b.apply_block(&b1b).unwrap();
        let b2b = make_valid_child_block(&state_b, genesis_time + 260);
        state_b.apply_block(&b2b).unwrap();

        let b1b_id = b1b.block_id();
        let b2b_id = b2b.block_id();

        // Reorganize store to Branch B with higher cumulative work
        let work_b1 = U256::from_u128(10);
        let work_b2 = U256::from_u128(20);

        store
            .commit_reorganization(
                &[b1b.clone(), b2b.clone()],
                &[work_b1, work_b2],
                state_a.tip_height().unwrap(),
            )
            .unwrap();

        // Verify displaced Branch A blocks are now marked inactive!
        assert!(
            !store
                .get_block_metadata(&b1a_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            !store
                .get_block_metadata(&b2a_id)
                .unwrap()
                .unwrap()
                .is_active
        );

        // Verify replacement Branch B blocks are marked active
        assert!(
            store
                .get_block_metadata(&b1b_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            store
                .get_block_metadata(&b2b_id)
                .unwrap()
                .unwrap()
                .is_active
        );

        // 3. Extend displaced Branch A until it has greater cumulative work than B
        let b3a = make_valid_child_block(&state_a, genesis_time + 360);
        state_a.apply_block(&b3a).unwrap();
        let b4a = make_valid_child_block(&state_a, genesis_time + 480);
        state_a.apply_block(&b4a).unwrap();

        let b3a_id = b3a.block_id();
        let b4a_id = b4a.block_id();

        let work_a1 = state_a.cumulative_work_at(1).unwrap();
        let work_a2 = state_a.cumulative_work_at(2).unwrap();
        let work_a3 = state_a.cumulative_work_at(3).unwrap();
        let work_a4 = state_a.cumulative_work_at(4).unwrap();

        // 4. Reorganize back to Branch A
        store
            .commit_reorganization(
                &[b1a.clone(), b2a.clone(), b3a.clone(), b4a.clone()],
                &[work_a1, work_a2, work_a3, work_a4],
                2, // old tip height was 2 (Branch B)
            )
            .unwrap();

        // Verify Branch B blocks are now marked inactive
        assert!(
            !store
                .get_block_metadata(&b1b_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            !store
                .get_block_metadata(&b2b_id)
                .unwrap()
                .unwrap()
                .is_active
        );

        // Verify Branch A blocks are all marked active
        assert!(
            store
                .get_block_metadata(&b1a_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            store
                .get_block_metadata(&b2a_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            store
                .get_block_metadata(&b3a_id)
                .unwrap()
                .unwrap()
                .is_active
        );
        assert!(
            store
                .get_block_metadata(&b4a_id)
                .unwrap()
                .unwrap()
                .is_active
        );

        // Side-branch blocks (b1b and b2b) remain retrievable by block ID!
        assert!(store.get_block(&b1b_id).unwrap().is_some());
        assert!(store.get_block(&b2b_id).unwrap().is_some());

        drop(store);

        // 5. Restart from storage and verify exact active-chain reconstruction
        let reopened = BlockStore::open(&db_path, cid).unwrap();
        let (tip_h, tip_id, tip_work) = reopened.get_tip().unwrap();
        assert_eq!(tip_h, 4);
        assert_eq!(tip_id, b4a_id);
        assert_eq!(tip_work, work_a4);

        let h1_id = reopened.get_block_by_height(1).unwrap().unwrap().block_id();
        let h2_id = reopened.get_block_by_height(2).unwrap().unwrap().block_id();
        let h3_id = reopened.get_block_by_height(3).unwrap().unwrap().block_id();
        let h4_id = reopened.get_block_by_height(4).unwrap().unwrap().block_id();
        assert_eq!(h1_id, b1a_id);
        assert_eq!(h2_id, b2a_id);
        assert_eq!(h3_id, b3a_id);
        assert_eq!(h4_id, b4a_id);

        let reconstructed = reopened.reconstruct_chain_state().unwrap();
        assert_eq!(reconstructed.tip_height(), Some(4));
        assert_eq!(reconstructed.tip_block_id(), Some(b4a_id));
        assert_eq!(reconstructed.cumulative_work(), state_a.cumulative_work());
    }

    #[test]
    fn test_capture_canonical_chain_snapshot() {
        let dir = tempfile::TempDir::new().unwrap();
        let cid = chain_id(DEVNET);
        let db_path = dir.path().join("blockchain.redb");
        let store = BlockStore::open(&db_path, cid).unwrap();

        // 1. Snapshot on fresh genesis store
        let (tip_h, tip_id, ids) = store.capture_canonical_chain_snapshot(10).unwrap();
        assert_eq!(tip_h, 0);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], tip_id);

        // 2. Commit two blocks
        let genesis = genesis_block(cid);
        let genesis_time = genesis.header.timestamp;
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let b1 = make_valid_child_block(&state, genesis_time + 120);
        state.apply_block(&b1).unwrap();
        store
            .commit_active_block(&b1, state.cumulative_work())
            .unwrap();

        let b2 = make_valid_child_block(&state, genesis_time + 240);
        state.apply_block(&b2).unwrap();
        store
            .commit_active_block(&b2, state.cumulative_work())
            .unwrap();

        // 3. Snapshot up to height 2
        let (tip_h2, tip_id2, ids2) = store.capture_canonical_chain_snapshot(2).unwrap();
        assert_eq!(tip_h2, 2);
        assert_eq!(tip_id2, b2.block_id());
        assert_eq!(ids2.len(), 3);
        assert_eq!(ids2[0], genesis.block_id());
        assert_eq!(ids2[1], b1.block_id());
        assert_eq!(ids2[2], b2.block_id());

        // 4. Snapshot with bounded target (target_max_height = 1)
        let (tip_h_bounded, _, ids_bounded) = store.capture_canonical_chain_snapshot(1).unwrap();
        assert_eq!(tip_h_bounded, 2); // tip_height is still 2
        assert_eq!(ids_bounded.len(), 2); // only scanned up to 1
        assert_eq!(ids_bounded[0], genesis.block_id());
        assert_eq!(ids_bounded[1], b1.block_id());

        // 5. Cooperative cancellation test
        let flag = std::sync::atomic::AtomicBool::new(true);
        let cancel_res = store.capture_canonical_chain_snapshot_cooperative(2, Some(&flag));
        assert!(cancel_res.is_err(), "Must abort when cancel_flag is true");
    }
}
