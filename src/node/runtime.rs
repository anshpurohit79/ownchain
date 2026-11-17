//! Node runtime lifecycle, service orchestration, block sync, and mempool coordination.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! The node runtime coordinates persistent storage (`BlockStore`), P2P networking
//! (`NetworkService`), mempool admission and revalidation (`Mempool`), and
//! independent local consensus evaluation (`ChainState`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use libp2p::core::Multiaddr;
use libp2p::gossipsub::MessageAcceptance;
use libp2p::identity::{Keypair, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::block::Block;
use crate::chain::{ChainError, ChainState};
use crate::difficulty::U256;
use crate::error::EncodeError;
use crate::genesis::genesis_block;
use crate::hash::Hash;
use crate::mempool::{Mempool, MempoolError};
use crate::node::config::NodeConfig;
use crate::p2p::handshake::HandshakeMessage;
use crate::p2p::identity::{load_or_generate_identity, peer_id_from_keypair};
use crate::p2p::network::{NetworkEvent, NetworkHandle, NetworkService, PeerInfo};
use crate::p2p::protocol::{
    SyncRequest, SyncResponse, MAX_BLOCKS_PER_RESPONSE, MAX_HEADERS_PER_RESPONSE,
};
use crate::randomx::RandomxError;
use crate::storage::{BlockStore, StorageError};
use crate::validation::ValidationError;

/// Maximum number of orphan blocks held in memory.
pub const MAX_ORPHAN_BLOCKS: usize = 100;
/// Maximum cumulative bytes of serialized orphan blocks held in memory (5 MB).
pub const MAX_ORPHAN_BYTES: usize = 5 * 1024 * 1024;
/// Maximum active penalized peers retained in the primary sync penalty registry.
pub const MAX_SYNC_PENALTY_PEERS: usize = 1024;
/// Maximum repeat-offender strike histories archived across expired-entry evictions.
pub const MAX_REPEAT_OFFENDER_HISTORY: usize = 4096;
/// Maximum failed manual-sync peer entries buffered during primary registry saturation.
pub const MAX_MANUAL_OVERFLOW_PEERS: usize = 128;

const TRANSIENT_SYNC_BASE_BACKOFF: Duration = Duration::from_secs(2);
const MAX_TRANSIENT_SYNC_BACKOFF: Duration = Duration::from_secs(300);
const QUARANTINE_SYNC_BASE_BACKOFF: Duration = Duration::from_secs(30);
const MAX_QUARANTINE_SYNC_BACKOFF: Duration = Duration::from_secs(600);
const PENALTY_STALE_DECAY_TTL: Duration = Duration::from_secs(900);
const MIN_SYNC_ROTATION_PEERS: usize = 256;
const MAX_SYNC_ROTATION_PEERS: usize = 1024;
const LOCAL_DISCONNECT_MARKER_TTL: Duration = Duration::from_secs(30);

/// Outcome of processing an inbound block in the runtime actor loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockProcessingOutcome {
    /// The block extended or reorganized the active chain, advancing or changing the canonical tip.
    ActiveChainAccepted(Hash),
    /// The block is consensus-valid and stored as a side-branch block (active tip unchanged).
    SideBranchPersisted(Hash),
    /// The block was ignored (e.g. already known) or placed in the orphan pool without storage.
    Ignored,
}

impl BlockProcessingOutcome {
    /// Returns the persisted block ID if the block was durably stored (either as the active tip
    /// or on a valid side branch), signaling that waiting orphan children may be retried.
    pub fn persisted_block_id(&self) -> Option<Hash> {
        match self {
            BlockProcessingOutcome::ActiveChainAccepted(id)
            | BlockProcessingOutcome::SideBranchPersisted(id) => Some(*id),
            BlockProcessingOutcome::Ignored => None,
        }
    }
}

#[derive(Debug)]
enum BlockProcessingError {
    ConsensusInvalid(String),
    InternalOrStorage(String),
}

impl core::fmt::Display for BlockProcessingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockProcessingError::ConsensusInvalid(s)
            | BlockProcessingError::InternalOrStorage(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GossipBlockDisposition {
    AcceptNew(Hash),
    IgnoreKnownDuplicate,
    IgnoreOrphan,
}

struct SingleBlockResult {
    root_block_id: Hash,
    root_newly_persisted: bool,
    outcome: BlockProcessingOutcome,
    gossip_disposition: GossipBlockDisposition,
    missing_parents: Vec<Block>,
}

struct InboundBlockReport {
    root_block_id: Hash,
    root_outcome: BlockProcessingOutcome,
    gossip_disposition: GossipBlockDisposition,
    root_newly_persisted: bool,
}

fn classify_chain_error(err: &ChainError) -> BlockProcessingError {
    match err {
        ChainError::Internal(s) => BlockProcessingError::InternalOrStorage(s.clone()),
        ChainError::Encoding(e) => match e {
            EncodeError::BlockTooLarge { .. }
            | EncodeError::TransactionTooLarge { .. }
            | EncodeError::TooManyTransactions { .. }
            | EncodeError::InvalidHeaderLength { .. }
            | EncodeError::Truncated { .. }
            | EncodeError::TrailingBytes { .. }
            | EncodeError::CountOverflow { .. } => {
                BlockProcessingError::ConsensusInvalid(err.to_string())
            }
        },
        ChainError::Invalid(ve) => match ve {
            ValidationError::MissingExpectedDifficulty { .. }
            | ValidationError::MissingKeyBlock { .. }
            | ValidationError::InvalidDifficulty(_) => {
                BlockProcessingError::InternalOrStorage(err.to_string())
            }
            ValidationError::Randomx(rx_err) => match rx_err {
                RandomxError::AllocationFailed
                | RandomxError::InitializationFailed
                | RandomxError::InvalidInput => {
                    BlockProcessingError::InternalOrStorage(err.to_string())
                }
                RandomxError::ZeroDifficulty | RandomxError::HashAboveTarget => {
                    BlockProcessingError::ConsensusInvalid(err.to_string())
                }
            },
            ValidationError::UnsupportedVersion { .. }
            | ValidationError::WrongChainId { .. }
            | ValidationError::HeightMismatch { .. }
            | ValidationError::UnknownParent { .. }
            | ValidationError::ZeroParentBlockId
            | ValidationError::NonZeroGenesisParent
            | ValidationError::TransactionRootMismatch { .. }
            | ValidationError::DuplicateTransaction { .. }
            | ValidationError::TimestampNotIncreasing { .. }
            | ValidationError::BlockTooLarge { .. }
            | ValidationError::TransactionTooLarge { .. }
            | ValidationError::InvalidCoinbase { .. }
            | ValidationError::InvalidGenesis { .. }
            | ValidationError::MalformedTransaction { .. }
            | ValidationError::CoinbaseHeightMismatch { .. }
            | ValidationError::OrchardRootMismatch { .. }
            | ValidationError::ZeroDifficulty
            | ValidationError::DifficultyMismatch { .. }
            | ValidationError::HashAboveTarget { .. }
            | ValidationError::Encoding(_)
            | ValidationError::InvalidOrchardTransaction { .. }
            | ValidationError::IncorrectTransactionFee { .. }
            | ValidationError::FeeCalculationOverflow { .. }
            | ValidationError::TooManyBlockActions { .. } => {
                BlockProcessingError::ConsensusInvalid(err.to_string())
            }
        },
        ChainError::State(_) => BlockProcessingError::ConsensusInvalid(err.to_string()),
    }
}

fn classify_mempool_error(err: &MempoolError) -> (MessageAcceptance, bool) {
    match err {
        MempoolError::AlreadyInMempool(_) | MempoolError::AlreadyOnChain(_) => {
            (MessageAcceptance::Ignore, true)
        }
        MempoolError::MempoolFull
        | MempoolError::Internal(_)
        | MempoolError::AccountNotFound(_)
        | MempoolError::AccountFrozen(_)
        | MempoolError::NonceExhausted(_)
        | MempoolError::ConflictingNonce { .. }
        | MempoolError::InsufficientSpendableBalance { .. }
        | MempoolError::AllowanceExceeded(_)
        | MempoolError::StaleAnchor(_)
        | MempoolError::NullifierAlreadySpent(_)
        | MempoolError::ConflictingNullifier { .. }
        | MempoolError::InsufficientShieldedPoolBalance { .. }
        | MempoolError::ConflictingCancellation { .. }
        | MempoolError::AccountLockedByPendingGovernance(_)
        | MempoolError::PendingGovernanceConflict { .. } => (MessageAcceptance::Ignore, false),
        MempoolError::Envelope(_)
        | MempoolError::CoinbaseForbidden
        | MempoolError::FeeBelowMinimum { .. }
        | MempoolError::InvalidSignature(_)
        | MempoolError::BundleCodec(_)
        | MempoolError::OrchardValidation(_)
        | MempoolError::DuplicateNullifierInTx(_)
        | MempoolError::ValueBalanceMismatch { .. }
        | MempoolError::Malformed(_) => (MessageAcceptance::Reject, false),
    }
}

/// Evaluates whether a candidate branch wins fork choice against the active chain according to
/// `docs/protocol-v1.md` Section 4:
/// 1. Candidate cumulative work > active cumulative work -> candidate wins.
/// 2. Candidate cumulative work < active cumulative work -> active chain retained.
/// 3. Equal cumulative work -> compare the complete ordered block-ID sequences from genesis.
///    At the first differing height, candidate wins if its block ID is lexicographically smaller.
pub fn candidate_wins_fork_choice(
    candidate_work: U256,
    candidate_blocks: &[Block],
    active_work: U256,
    active_blocks: &[Block],
) -> bool {
    if candidate_work > active_work {
        return true;
    }
    if candidate_work < active_work {
        return false;
    }

    let min_len = candidate_blocks.len().min(active_blocks.len());
    for i in 0..min_len {
        let cand_id = candidate_blocks[i].block_id();
        let act_id = active_blocks[i].block_id();
        if cand_id != act_id {
            return cand_id < act_id;
        }
    }

    false
}

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
        if height == self.tip_height {
            return Some(self.tip_block_id);
        }
        self.block_ids.get(height as usize).copied()
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_block_id(&self) -> Hash {
        self.tip_block_id
    }
}

/// Snapshotted handshake chain claim captured when an automatic sync starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdvertisedTipClaim {
    pub tip_block_id: Hash,
    pub tip_height: u64,
    pub cumulative_work: U256,
}

/// Structured progress receipt returned by `NodeRuntime` for each applied block batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncBatchReceipt {
    pub blocks_processed: usize,
    pub active_blocks_persisted: u64,
    pub side_blocks_persisted: u64,
    pub already_known_duplicates: usize,
    pub reached_advertised_tip: bool,
    pub status: Result<(), SyncBatchError>,
}

impl SyncBatchReceipt {
    pub fn empty() -> Self {
        Self {
            blocks_processed: 0,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            already_known_duplicates: 0,
            reached_advertised_tip: false,
            status: Ok(()),
        }
    }

    #[allow(dead_code)]
    pub fn is_ok(&self) -> bool {
        self.status.is_ok()
    }

    #[allow(dead_code)]
    pub fn is_err(&self) -> bool {
        self.status.is_err()
    }
}

/// Typed batch-application failure returned from `NodeRuntime` to an active sync worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncBatchError {
    StaleOperation,
    ConsensusInvalid(String),
    DisconnectedOrphan {
        block_id: Hash,
        parent_id: Hash,
        height: u64,
        index: usize,
    },
    InternalOrStorage(String),
}

impl core::fmt::Display for SyncBatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyncBatchError::StaleOperation => f.write_str("stale sync generation"),
            SyncBatchError::ConsensusInvalid(s) | SyncBatchError::InternalOrStorage(s) => {
                f.write_str(s)
            }
            SyncBatchError::DisconnectedOrphan {
                block_id,
                parent_id,
                height,
                index,
            } => write!(
                f,
                "disconnected orphan block #{height} ({block_id}) at batch index {index}, parent {parent_id} unknown"
            ),
        }
    }
}

/// Typed success emitted by `run_sync_worker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncWorkerSuccess {
    VerifiedSuccess {
        blocks_applied: u64,
        final_height: u64,
        final_tip_id: Hash,
    },
    AlreadySynchronized {
        tip_height: u64,
        tip_block_id: Hash,
    },
}

/// Typed failure emitted by `run_sync_worker` for penalty attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncWorkerError {
    ConsensusInvalid(String),
    Incomplete {
        requested_height: u64,
        expected_target: u64,
        reason: String,
    },
    TransientOrProtocol(String),
    #[allow(dead_code)]
    FalseAdvertisedClaim(String),
    LocalOrStorage(String),
    BudgetExhausted(String),
}

impl core::fmt::Display for SyncWorkerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyncWorkerError::ConsensusInvalid(s)
            | SyncWorkerError::TransientOrProtocol(s)
            | SyncWorkerError::FalseAdvertisedClaim(s)
            | SyncWorkerError::LocalOrStorage(s)
            | SyncWorkerError::BudgetExhausted(s) => f.write_str(s),
            SyncWorkerError::Incomplete {
                requested_height,
                expected_target,
                reason,
            } => write!(
                f,
                "incomplete sync at height {requested_height}/{expected_target}: {reason}"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncFailureClass {
    InvalidChainData,
    FalseAdvertisedWorkClaim,
    TransientOrTimeout,
    IncompleteProgress,
    ZeroProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncOutcomeEvaluation {
    LocalFaultNoPeerPenalty,
    VerifiedSuccess,
    Penalized(SyncFailureClass),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncPeerPenaltyEntry {
    consecutive_failures: u32,
    cooldown_until: Option<Instant>,
    last_updated_at: Instant,
    last_failure_kind: Option<SyncFailureClass>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OffenseHistory {
    consecutive_failures: u32,
    last_offense_at: Instant,
}

/// Bounded per-`PeerId` sync penalty and cooldown registry surviving peer disconnects.
///
/// Active cooldown entries (`cooldown_until > Some(now)`) are never evicted to admit new peers.
#[derive(Debug, Clone)]
struct SyncPeerPenaltyRegistry {
    entries: HashMap<PeerId, SyncPeerPenaltyEntry>,
    repeat_offender_history: HashMap<PeerId, OffenseHistory>,
    manual_overflow: HashMap<PeerId, SyncPeerPenaltyEntry>,
    global_manual_overflow_cooldown_until: Option<Instant>,
    max_entries: usize,
    max_history: usize,
    max_manual_overflow: usize,
    stale_decay_ttl: Duration,
}

impl SyncPeerPenaltyRegistry {
    fn new(
        max_entries: usize,
        max_history: usize,
        max_manual_overflow: usize,
        stale_decay_ttl: Duration,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            repeat_offender_history: HashMap::new(),
            manual_overflow: HashMap::new(),
            global_manual_overflow_cooldown_until: None,
            max_entries: max_entries.max(1),
            max_history,
            max_manual_overflow: max_manual_overflow.max(1),
            stale_decay_ttl,
        }
    }

    fn backoff_duration(class: SyncFailureClass, consecutive_failures: u32) -> Duration {
        let (base_secs, max_secs) = match class {
            SyncFailureClass::InvalidChainData | SyncFailureClass::FalseAdvertisedWorkClaim => (
                QUARANTINE_SYNC_BASE_BACKOFF.as_secs(),
                MAX_QUARANTINE_SYNC_BACKOFF.as_secs(),
            ),
            SyncFailureClass::TransientOrTimeout
            | SyncFailureClass::IncompleteProgress
            | SyncFailureClass::ZeroProgress => (
                TRANSIENT_SYNC_BASE_BACKOFF.as_secs(),
                MAX_TRANSIENT_SYNC_BACKOFF.as_secs(),
            ),
        };
        let shift = consecutive_failures.saturating_sub(1).min(20);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        Duration::from_secs(base_secs.saturating_mul(factor).min(max_secs))
    }

    fn is_entry_active(entry: &SyncPeerPenaltyEntry, now: Instant) -> bool {
        entry.cooldown_until.is_some_and(|until| until > now)
    }

    fn is_entry_stale_with_ttl(
        entry: &SyncPeerPenaltyEntry,
        now: Instant,
        stale_decay_ttl: Duration,
    ) -> bool {
        !Self::is_entry_active(entry, now)
            && now.saturating_duration_since(entry.last_updated_at) >= stale_decay_ttl
    }

    fn is_entry_stale(&self, entry: &SyncPeerPenaltyEntry, now: Instant) -> bool {
        Self::is_entry_stale_with_ttl(entry, now, self.stale_decay_ttl)
    }

    fn is_cooling_down(&self, peer_id: &PeerId, now: Instant) -> bool {
        self.entries
            .get(peer_id)
            .is_some_and(|e| Self::is_entry_active(e, now))
            || self
                .manual_overflow
                .get(peer_id)
                .is_some_and(|e| Self::is_entry_active(e, now))
    }

    fn consecutive_failures_for(&self, peer_id: &PeerId, now: Instant) -> u32 {
        if let Some(entry) = self.entries.get(peer_id) {
            if !self.is_entry_stale(entry, now) {
                return entry.consecutive_failures;
            }
            return 0;
        }
        if let Some(entry) = self.manual_overflow.get(peer_id) {
            if !self.is_entry_stale(entry, now) {
                return entry.consecutive_failures;
            }
            return 0;
        }
        if let Some(hist) = self.repeat_offender_history.get(peer_id) {
            if now.saturating_duration_since(hist.last_offense_at) < self.stale_decay_ttl {
                return hist.consecutive_failures;
            }
        }
        0
    }

    fn reclaim_maintenance(&mut self, now: Instant) {
        let ttl = self.stale_decay_ttl;
        self.entries
            .retain(|_, e| !Self::is_entry_stale_with_ttl(e, now, ttl));
        self.manual_overflow
            .retain(|_, e| !Self::is_entry_stale_with_ttl(e, now, ttl));
        self.repeat_offender_history
            .retain(|_, h| now.saturating_duration_since(h.last_offense_at) < ttl);
        if self
            .global_manual_overflow_cooldown_until
            .is_some_and(|until| until <= now)
        {
            self.global_manual_overflow_cooldown_until = None;
        }
        self.promote_manual_overflow(now);
    }

    fn has_active_capacity_exhaustion(&self, now: Instant) -> bool {
        self.entries.len() >= self.max_entries
            && self.entries.values().all(|e| Self::is_entry_active(e, now))
    }

    fn is_peer_eligible_auto(&mut self, peer_id: &PeerId, now: Instant) -> bool {
        self.reclaim_maintenance(now);
        if self.is_cooling_down(peer_id, now) {
            return false;
        }
        if self.entries.contains_key(peer_id) || self.manual_overflow.contains_key(peer_id) {
            return true;
        }
        if self
            .global_manual_overflow_cooldown_until
            .is_some_and(|until| until > now)
        {
            return false;
        }
        !self.has_active_capacity_exhaustion(now)
    }

    fn archive_offense_history(&mut self, peer_id: PeerId, history: OffenseHistory, now: Instant) {
        if self.max_history == 0
            || history.consecutive_failures == 0
            || now.saturating_duration_since(history.last_offense_at) >= self.stale_decay_ttl
        {
            return;
        }
        if let Some(existing) = self.repeat_offender_history.get_mut(&peer_id) {
            existing.consecutive_failures = existing
                .consecutive_failures
                .max(history.consecutive_failures);
            if history.last_offense_at > existing.last_offense_at {
                existing.last_offense_at = history.last_offense_at;
            }
            return;
        }
        if self.repeat_offender_history.len() >= self.max_history {
            self.repeat_offender_history.retain(|_, h| {
                now.saturating_duration_since(h.last_offense_at) < self.stale_decay_ttl
            });
        }
        if self.repeat_offender_history.len() >= self.max_history {
            if let Some(victim_id) = self
                .repeat_offender_history
                .iter()
                .min_by_key(|(id, h)| (h.consecutive_failures, h.last_offense_at, **id))
                .map(|(id, _)| *id)
            {
                let victim = self.repeat_offender_history.get(&victim_id).copied();
                let should_replace = victim.is_some_and(|v| {
                    (v.consecutive_failures, v.last_offense_at)
                        < (history.consecutive_failures, history.last_offense_at)
                });
                if should_replace {
                    self.repeat_offender_history.remove(&victim_id);
                } else {
                    return;
                }
            }
        }
        self.repeat_offender_history.insert(peer_id, history);
    }

    fn try_free_expired_primary_slot(&mut self, now: Instant) -> bool {
        if self.entries.len() < self.max_entries {
            return true;
        }
        let ttl = self.stale_decay_ttl;
        self.entries
            .retain(|_, e| !Self::is_entry_stale_with_ttl(e, now, ttl));
        if self.entries.len() < self.max_entries {
            return true;
        }
        // Only expired entries (`cooldown_until <= Some(now)`) may ever be reclaimed;
        // retain higher repeat-offender streaks before evicting lower-strike entries.
        let victim = self
            .entries
            .iter()
            .filter(|(_, e)| !Self::is_entry_active(e, now))
            .min_by_key(|(id, e)| (e.consecutive_failures, e.last_updated_at, **id))
            .map(|(id, _)| *id);

        if let Some(victim_id) = victim {
            if let Some(evicted) = self.entries.remove(&victim_id) {
                self.archive_offense_history(
                    victim_id,
                    OffenseHistory {
                        consecutive_failures: evicted.consecutive_failures,
                        last_offense_at: evicted.last_updated_at,
                    },
                    now,
                );
            }
            return true;
        }
        false
    }

    fn promote_manual_overflow(&mut self, now: Instant) {
        while !self.manual_overflow.is_empty() {
            let next_peer = self
                .manual_overflow
                .iter()
                .filter(|(_, e)| Self::is_entry_active(e, now))
                .max_by_key(|(id, e)| (e.cooldown_until, e.consecutive_failures, **id))
                .or_else(|| {
                    self.manual_overflow
                        .iter()
                        .max_by_key(|(id, e)| (e.consecutive_failures, e.last_updated_at, **id))
                })
                .map(|(id, _)| *id);
            let Some(peer_id) = next_peer else {
                break;
            };
            if self.entries.contains_key(&peer_id) {
                if let Some(overflow_entry) = self.manual_overflow.remove(&peer_id) {
                    if let Some(primary) = self.entries.get_mut(&peer_id) {
                        if overflow_entry.cooldown_until > primary.cooldown_until {
                            primary.cooldown_until = overflow_entry.cooldown_until;
                        }
                        primary.consecutive_failures = primary
                            .consecutive_failures
                            .max(overflow_entry.consecutive_failures);
                    }
                }
                continue;
            }
            if !self.try_free_expired_primary_slot(now) {
                break;
            }
            if let Some(entry) = self.manual_overflow.remove(&peer_id) {
                self.entries.insert(peer_id, entry);
            }
        }
    }

    fn archived_failures_for(&self, peer_id: &PeerId, now: Instant) -> u32 {
        self.repeat_offender_history
            .get(peer_id)
            .filter(|h| now.saturating_duration_since(h.last_offense_at) < self.stale_decay_ttl)
            .map_or(0, |h| h.consecutive_failures)
    }

    fn record_failure(
        &mut self,
        peer_id: PeerId,
        class: SyncFailureClass,
        initiated_by_manual: bool,
        now: Instant,
    ) {
        self.reclaim_maintenance(now);

        if let Some(entry) = self.entries.get_mut(&peer_id) {
            let next = entry.consecutive_failures.saturating_add(1);
            let dur = Self::backoff_duration(class, next);
            entry.consecutive_failures = next;
            entry.cooldown_until = Some(now + dur);
            entry.last_updated_at = now;
            entry.last_failure_kind = Some(class);
            return;
        }

        if let Some(entry) = self.manual_overflow.get_mut(&peer_id) {
            let next = entry.consecutive_failures.saturating_add(1);
            let dur = Self::backoff_duration(class, next);
            entry.consecutive_failures = next;
            entry.cooldown_until = Some(now + dur);
            entry.last_updated_at = now;
            entry.last_failure_kind = Some(class);
            self.promote_manual_overflow(now);
            return;
        }

        // Peek prior strikes without consuming repeat_offender_history until a primary
        // or manual_overflow entry is actually admitted.
        let next_failures = self.archived_failures_for(&peer_id, now).saturating_add(1);
        let dur = Self::backoff_duration(class, next_failures);
        let entry = SyncPeerPenaltyEntry {
            consecutive_failures: next_failures,
            cooldown_until: Some(now + dur),
            last_updated_at: now,
            last_failure_kind: Some(class),
        };

        if self.try_free_expired_primary_slot(now) {
            self.repeat_offender_history.remove(&peer_id);
            self.entries.insert(peer_id, entry);
            return;
        }

        // Primary table is full of active cooldowns: never evict them.
        if initiated_by_manual {
            let ttl = self.stale_decay_ttl;
            self.manual_overflow
                .retain(|_, e| !Self::is_entry_stale_with_ttl(e, now, ttl));
            if self.manual_overflow.len() >= self.max_manual_overflow {
                let victim = self
                    .manual_overflow
                    .iter()
                    .filter(|(_, e)| !Self::is_entry_active(e, now))
                    .min_by_key(|(id, e)| (e.consecutive_failures, e.last_updated_at, **id))
                    .map(|(id, _)| *id);
                if let Some(victim_id) = victim {
                    if let Some(evicted) = self.manual_overflow.remove(&victim_id) {
                        self.archive_offense_history(
                            victim_id,
                            OffenseHistory {
                                consecutive_failures: evicted.consecutive_failures,
                                last_offense_at: evicted.last_updated_at,
                            },
                            now,
                        );
                    }
                }
            }

            if self.manual_overflow.len() < self.max_manual_overflow {
                self.repeat_offender_history.remove(&peer_id);
                self.manual_overflow.insert(peer_id, entry);
            } else {
                // Double saturation: keep bounded memory, preserve longest quarantine ceiling,
                // and never shorten an already active global fallback deadline.
                let ceiling_dur = dur.min(MAX_QUARANTINE_SYNC_BACKOFF);
                let deadline = now + ceiling_dur;
                self.global_manual_overflow_cooldown_until = Some(
                    self.global_manual_overflow_cooldown_until
                        .map_or(deadline, |prev| prev.max(deadline)),
                );
                self.archive_offense_history(
                    peer_id,
                    OffenseHistory {
                        consecutive_failures: next_failures,
                        last_offense_at: now,
                    },
                    now,
                );
            }
        } else {
            // Non-manual failure while primary registry is saturated with active cooldowns:
            // preserve/update incremented repeat-offender strikes in bounded archive
            // (subject to `max_history` / `stale_decay_ttl` cap) instead of discarding history.
            self.archive_offense_history(
                peer_id,
                OffenseHistory {
                    consecutive_failures: next_failures,
                    last_offense_at: now,
                },
                now,
            );
        }
    }

    fn record_verified_success(&mut self, peer_id: &PeerId, now: Instant) {
        self.entries.remove(peer_id);
        self.manual_overflow.remove(peer_id);
        self.repeat_offender_history.remove(peer_id);
        self.reclaim_maintenance(now);
    }
}

/// Bounded equal-work sync candidate rotation tracker preventing HashMap iteration bias.
#[derive(Debug, Clone)]
struct BoundedSyncRotationState {
    last_attempted: HashMap<PeerId, u64>,
    next_attempt_seq: u64,
    max_entries: usize,
}

impl BoundedSyncRotationState {
    fn new(max_entries: usize) -> Self {
        Self {
            last_attempted: HashMap::new(),
            next_attempt_seq: 1,
            max_entries: max_entries.max(1),
        }
    }

    fn attempt_seq(&self, peer_id: &PeerId) -> u64 {
        self.last_attempted.get(peer_id).copied().unwrap_or(0)
    }

    fn mark_attempted(&mut self, peer_id: PeerId, connected_peers: Option<&HashSet<PeerId>>) {
        if !self.last_attempted.contains_key(&peer_id)
            && self.last_attempted.len() >= self.max_entries
        {
            if let Some(connected) = connected_peers {
                if let Some(disconnected_victim) = self
                    .last_attempted
                    .iter()
                    .filter(|(id, _)| !connected.contains(id))
                    .min_by_key(|(id, seq)| (**seq, **id))
                    .map(|(id, _)| *id)
                {
                    self.last_attempted.remove(&disconnected_victim);
                }
            }
            if self.last_attempted.len() >= self.max_entries {
                if let Some(oldest_victim) = self
                    .last_attempted
                    .iter()
                    .min_by_key(|(id, seq)| (**seq, **id))
                    .map(|(id, _)| *id)
                {
                    self.last_attempted.remove(&oldest_victim);
                }
            }
        }
        let seq = self.next_attempt_seq;
        self.next_attempt_seq = self.next_attempt_seq.checked_add(1).unwrap_or_else(|| {
            self.last_attempted.clear();
            1
        });
        self.last_attempted.insert(peer_id, seq);
    }
}

/// Result delivered when a background synchronization task terminates.
pub(crate) struct SyncTaskResult {
    pub sync_operation_id: u64,
    pub peer_id: PeerId,
    pub result: Result<SyncWorkerSuccess, SyncWorkerError>,
}

struct ActiveSyncOperation {
    sync_operation_id: u64,
    peer_id: PeerId,
    task_id: tokio::task::Id,
    abort_handle: tokio::task::AbortHandle,
    cancel_flag: Arc<std::sync::atomic::AtomicBool>,
    advertised_claim: Option<AdvertisedTipClaim>,
    initiated_by_manual: bool,
    active_blocks_persisted: u64,
    side_blocks_persisted: u64,
    reached_advertised_tip_via_sync: bool,
    observed_batch_error: Option<SyncBatchError>,
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
        sync_operation_id: u64,
        peer_id: PeerId,
        blocks: Vec<Block>,
        respond_to: oneshot::Sender<SyncBatchReceipt>,
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
    ReevaluateStoredBranch {
        tip_block_id: Hash,
        respond_to: oneshot::Sender<Result<BlockProcessingOutcome, String>>,
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
                MempoolError::Internal("Node runtime command channel closed".to_string())
            })?;
        rx.await.map_err(|_| {
            MempoolError::Internal("Node runtime dropped response receiver".to_string())
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

    pub async fn reevaluate_stored_branch(
        &self,
        tip_block_id: Hash,
    ) -> Result<BlockProcessingOutcome, String> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NodeCommand::ReevaluateStoredBranch {
                tip_block_id,
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
    current_sync_operation_id: u64,
    active_sync: Option<ActiveSyncOperation>,
    sync_penalties: SyncPeerPenaltyRegistry,
    sync_rotation: BoundedSyncRotationState,
    locally_disconnected_peers: HashMap<PeerId, Instant>,
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
    evaluated_side_branches: HashMap<Hash, Hash>,
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

        let rotation_cap = config
            .max_peers
            .clamp(MIN_SYNC_ROTATION_PEERS, MAX_SYNC_ROTATION_PEERS);

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
            current_sync_operation_id: 0,
            active_sync: None,
            sync_penalties: SyncPeerPenaltyRegistry::new(
                MAX_SYNC_PENALTY_PEERS,
                MAX_REPEAT_OFFENDER_HISTORY,
                MAX_MANUAL_OVERFLOW_PEERS,
                PENALTY_STALE_DECAY_TTL,
            ),
            sync_rotation: BoundedSyncRotationState::new(rotation_cap),
            locally_disconnected_peers: HashMap::new(),
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
            evaluated_side_branches: HashMap::new(),
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

    pub fn evaluated_side_branch_count(&self) -> usize {
        self.evaluated_side_branches.len()
    }

    pub fn is_side_branch_evaluated(&self, side_tip: &Hash) -> bool {
        self.evaluated_side_branches.contains_key(side_tip)
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

    async fn flush_evicted_seen_txs(&mut self) {
        let evicted = self.mempool.drain_evicted_tx_ids();
        if !evicted.is_empty() {
            let _ = self.network_handle.forget_seen_transactions(evicted).await;
        }
    }

    /// Submits a transaction locally (e.g. from RPC or CLI).
    ///
    /// Validates and admits the transaction to the mempool, then broadcasts it to peers.
    pub async fn submit_transaction(&mut self, tx_bytes: Vec<u8>) -> Result<Hash, MempoolError> {
        let tx_id = self.mempool.admit(&tx_bytes, &self.chain_state)?;
        self.flush_evicted_seen_txs().await;
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
                            let now = Instant::now();
                            self.record_local_disconnect_marker(peer_id, now);
                            let res = self.network_handle.disconnect(peer_id).await;
                            if res.is_err() {
                                self.locally_disconnected_peers.remove(&peer_id);
                            }
                            let _ = respond_to.send(res);
                        }
                        Some(NodeCommand::SyncWithPeer { peer_id, peer_tip_height, respond_to }) => {
                            match self.validate_peer_for_manual_sync(peer_id).await {
                                Ok(advertised_claim) => {
                                    let target_height = match advertised_claim.as_ref() {
                                        Some(claim) => claim.tip_height,
                                        None => {
                                            let _ = respond_to.send(Err(format!(
                                                "Cannot sync with peer {peer_id}: missing verified handshake claim"
                                            )));
                                            continue;
                                        }
                                    };
                                    if target_height != peer_tip_height {
                                        tracing::info!(
                                            %peer_id,
                                            caller_supplied_height = peer_tip_height,
                                            authoritative_claim_height = target_height,
                                            "Reconciling manual sync target height with authenticated handshake tip height"
                                        );
                                    }
                                    self.start_sync_internal(
                                        peer_id,
                                        target_height,
                                        advertised_claim,
                                        true,
                                        Some(respond_to),
                                    );
                                }
                                Err(err_msg) => {
                                    let _ = respond_to.send(Err(err_msg));
                                }
                            }
                        }
                        Some(NodeCommand::ReevaluateStoredBranch { tip_block_id, respond_to }) => {
                            let res = self.reevaluate_stored_branch(tip_block_id).await;
                            let _ = respond_to.send(res);
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
                    let mut receipt = SyncBatchReceipt::empty();
                    receipt.status = Err(SyncBatchError::InternalOrStorage(
                        "Node runtime stopped".to_string(),
                    ));
                    let _ = respond_to.send(receipt);
                }
            }
        }

        // Close and drain unprocessed network events so pending gossip validation tokens
        // receive a non-blocking Ignore before tearing down the network task.
        self.network_event_rx.close();
        while let Ok(ev) = self.network_event_rx.try_recv() {
            match ev {
                NetworkEvent::BlockReceived {
                    propagation_source,
                    message_id,
                    ..
                }
                | NetworkEvent::TransactionReceived {
                    propagation_source,
                    message_id,
                    ..
                } => {
                    if let Err(e) = self.network_handle.try_report_gossip_validation(
                        message_id.clone(),
                        propagation_source,
                        MessageAcceptance::Ignore,
                    ) {
                        tracing::debug!(
                            %message_id,
                            error = %e,
                            "Skipping gossip shutdown Ignore report"
                        );
                    }
                }
                _ => {}
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

    /// Determines whether an advertised handshake corresponds to an already-stored
    /// side-branch block that is eligible for local re-evaluation against the active chain.
    ///
    /// Does not gate on peer-advertised cumulative work; the local node re-evaluates
    /// any locally stored inactive block against the active chain using authoritative
    /// local block validation and cumulative work calculation.
    pub fn should_reevaluate_stored_side_branch(&self, handshake: &HandshakeMessage) -> bool {
        // Advertised tip is our active tip -> already active, no reevaluation needed
        if handshake.tip_block_id == self.tip_block_id() {
            return false;
        }

        // Avoid repeated re-evaluations: check if this tip was already evaluated against our current active tip
        if self.evaluated_side_branches.get(&handshake.tip_block_id) == Some(&self.tip_block_id()) {
            return false;
        }

        // Check if the block is stored in our database as an inactive side-branch block
        match self.storage.get_block_metadata(&handshake.tip_block_id) {
            Ok(Some(meta)) => !meta.is_active,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    "Storage error checking metadata for {}: {}",
                    handshake.tip_block_id,
                    e
                );
                false
            }
        }
    }

    /// Re-evaluates an already-stored side branch identified by `tip_block_id` against the active chain.
    pub async fn reevaluate_stored_branch(
        &mut self,
        tip_block_id: Hash,
    ) -> Result<BlockProcessingOutcome, String> {
        let peer_id = self.peer_id;
        self.reevaluate_stored_side_branch(peer_id, tip_block_id)
            .await
    }

    /// Re-evaluates an already-stored side branch against the current active chain.
    ///
    /// Reconstructs the complete candidate branch from its common ancestor using locally stored blocks,
    /// validates every block, recalculates cumulative work, and applies protocol Section 4 fork choice.
    /// If the stored branch wins, reorganizes the active chain.
    /// If it loses, preserves the active chain and caches the decision.
    pub async fn reevaluate_stored_side_branch(
        &mut self,
        source_peer: PeerId,
        tip_block_id: Hash,
    ) -> Result<BlockProcessingOutcome, String> {
        let current_active_tip = self.tip_block_id();
        if tip_block_id == current_active_tip {
            return Ok(BlockProcessingOutcome::Ignored);
        }

        let meta = self
            .storage
            .get_block_metadata(&tip_block_id)
            .map_err(|e| format!("storage error retrieving metadata for {tip_block_id}: {e}"))?
            .ok_or_else(|| format!("block {tip_block_id} not found in storage"))?;

        if meta.is_active {
            return Ok(BlockProcessingOutcome::Ignored);
        }

        if self.evaluated_side_branches.get(&tip_block_id) == Some(&current_active_tip) {
            return Ok(BlockProcessingOutcome::SideBranchPersisted(tip_block_id));
        }

        let tip_block = self
            .storage
            .get_block(&tip_block_id)
            .map_err(|e| format!("storage error retrieving block {tip_block_id}: {e}"))?
            .ok_or_else(|| format!("block {tip_block_id} not found in storage"))?;

        let outcome = self
            .evaluate_competing_branch(source_peer, tip_block, false)
            .await
            .map_err(|e| e.to_string())?;

        // Wake any orphan children that were waiting for this side-branch block
        if let Some(new_id) = outcome.persisted_block_id() {
            if let Some(orphan_ids) = self.orphan_parents.remove(&new_id) {
                for child_id in orphan_ids {
                    if let Some(child_entry) = self.remove_orphan(&child_id) {
                        if let Err(e) = self
                            .handle_inbound_block(
                                child_entry.source_peer,
                                Box::new(child_entry.block),
                            )
                            .await
                        {
                            tracing::warn!(
                                child_block_id = %child_id,
                                parent_block_id = %new_id,
                                source_peer = %child_entry.source_peer,
                                error = %e,
                                "Failed to process unrolled orphan child block after stored branch reevaluation"
                            );
                        }
                    }
                }
            }
        }

        Ok(outcome)
    }

    /// Checks whether a peer is eligible for network synchronization (downloading blocks) under protocol rules:
    /// - Higher work peers with tips not already stored locally are eligible.
    /// - Equal work peers with unknown tips (not in storage) are eligible.
    /// - Peers advertising the active tip or a stored block (active or side-branch) are NOT eligible for network sync
    ///   (stored side branches are reevaluated locally via `should_reevaluate_stored_side_branch`).
    /// - Lower work peers are not eligible.
    /// - Storage errors are handled deliberately and return false.
    pub fn is_peer_sync_eligible(&self, handshake: &HandshakeMessage) -> bool {
        let local_work = self.cumulative_work();
        if handshake.cumulative_work < local_work {
            return false;
        }

        if handshake.tip_block_id == self.tip_block_id() {
            return false;
        }

        // For both higher and equal work: if the tip is already stored locally,
        // we do NOT initiate network synchronization to re-download blocks we already possess.
        match self.storage.get_block_metadata(&handshake.tip_block_id) {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(e) => {
                tracing::warn!(
                    "Storage error checking candidate tip {}: {}",
                    handshake.tip_block_id,
                    e
                );
                false
            }
        }
    }

    /// Validates peer information for manual synchronization eligibility.
    ///
    /// Preconditions enforced:
    /// 1. Peer must be currently connected (`peer_info` is `Some`).
    /// 2. Peer must have completed an application handshake (`peer.handshake.is_some()`).
    /// 3. Peer must have matching `chain_id` and `genesis_hash`.
    pub(crate) fn validate_peer_info_for_manual_sync(
        &self,
        peer_info: Option<&PeerInfo>,
        peer_id: &PeerId,
    ) -> Result<Option<AdvertisedTipClaim>, String> {
        let peer = peer_info
            .ok_or_else(|| format!("Cannot sync with peer {peer_id}: peer is not connected"))?;
        let hs = peer.handshake.as_ref().ok_or_else(|| {
            format!("Cannot sync with peer {peer_id}: peer application handshake is not verified")
        })?;
        if hs.chain_id != self.config.chain_id {
            return Err(format!(
                "Cannot sync with peer {peer_id}: incompatible chain ID {} (expected {})",
                hs.chain_id, self.config.chain_id
            ));
        }
        let expected_genesis = genesis_block(self.config.chain_id).block_id();
        if hs.genesis_hash != expected_genesis {
            return Err(format!(
                "Cannot sync with peer {peer_id}: incompatible genesis hash {} (expected {})",
                hs.genesis_hash, expected_genesis
            ));
        }
        Ok(Some(AdvertisedTipClaim {
            tip_block_id: hs.tip_block_id,
            tip_height: hs.tip_height,
            cumulative_work: hs.cumulative_work,
        }))
    }

    /// Asynchronously fetches connected peers and validates eligibility for manual synchronization.
    pub(crate) async fn validate_peer_for_manual_sync(
        &self,
        peer_id: PeerId,
    ) -> Result<Option<AdvertisedTipClaim>, String> {
        let peers = self
            .network_handle
            .get_connected_peers()
            .await
            .map_err(|e| format!("Failed to retrieve connected peers: {e}"))?;
        let peer_info = peers.iter().find(|p| p.peer_id == peer_id);
        self.validate_peer_info_for_manual_sync(peer_info, &peer_id)
    }

    fn record_local_disconnect_marker(&mut self, peer_id: PeerId, now: Instant) {
        self.locally_disconnected_peers.retain(|_, marked_at| {
            now.saturating_duration_since(*marked_at) < LOCAL_DISCONNECT_MARKER_TTL
        });
        self.locally_disconnected_peers.insert(peer_id, now);
    }

    fn consume_local_disconnect_marker(&mut self, peer_id: &PeerId, now: Instant) -> bool {
        self.locally_disconnected_peers.retain(|_, marked_at| {
            now.saturating_duration_since(*marked_at) < LOCAL_DISCONNECT_MARKER_TTL
        });
        self.locally_disconnected_peers.remove(peer_id).is_some()
    }

    fn verify_or_quarantine_stored_handshake_claim(
        &mut self,
        peer_id: PeerId,
        handshake: &HandshakeMessage,
        now: Instant,
    ) -> bool {
        match self.storage.get_block_metadata(&handshake.tip_block_id) {
            Ok(Some(meta)) => {
                if meta.height != handshake.tip_height
                    || meta.cumulative_work != handshake.cumulative_work
                {
                    if !self.sync_penalties.is_cooling_down(&peer_id, now) {
                        tracing::warn!(
                            %peer_id,
                            tip = %handshake.tip_block_id,
                            advertised_height = handshake.tip_height,
                            actual_height = meta.height,
                            advertised_work = ?handshake.cumulative_work,
                            actual_work = ?meta.cumulative_work,
                            "Peer advertised false height or cumulative work for stored tip; applying quarantine"
                        );
                        self.sync_penalties.record_failure(
                            peer_id,
                            SyncFailureClass::FalseAdvertisedWorkClaim,
                            false,
                            now,
                        );
                    }
                    return true;
                }
                false
            }
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    %peer_id,
                    tip = %handshake.tip_block_id,
                    error = %e,
                    "Storage error checking advertised tip metadata; ignoring without peer penalty"
                );
                true
            }
        }
    }

    fn select_sync_candidate_at(
        &mut self,
        peers: &[PeerInfo],
        now: Instant,
    ) -> Option<(PeerId, u64, AdvertisedTipClaim)> {
        self.sync_penalties.reclaim_maintenance(now);

        let mut best: Option<(PeerId, u64, AdvertisedTipClaim, u32, u64)> = None;
        for p in peers {
            let Some(ref hs) = p.handshake else {
                continue;
            };
            if !self.is_peer_sync_eligible(hs) {
                continue;
            }
            if !self.sync_penalties.is_peer_eligible_auto(&p.peer_id, now) {
                continue;
            }

            let failures = self
                .sync_penalties
                .consecutive_failures_for(&p.peer_id, now);
            let attempt_seq = self.sync_rotation.attempt_seq(&p.peer_id);
            let claim = AdvertisedTipClaim {
                tip_block_id: hs.tip_block_id,
                tip_height: hs.tip_height,
                cumulative_work: hs.cumulative_work,
            };

            let is_better = match best {
                None => true,
                Some((best_id, _, best_claim, best_failures, best_seq)) => {
                    match hs.cumulative_work.cmp(&best_claim.cumulative_work) {
                        std::cmp::Ordering::Greater => true,
                        std::cmp::Ordering::Less => false,
                        std::cmp::Ordering::Equal => {
                            (failures, attempt_seq, p.peer_id) < (best_failures, best_seq, best_id)
                        }
                    }
                }
            };

            if is_better {
                best = Some((p.peer_id, hs.tip_height, claim, failures, attempt_seq));
            }
        }

        best.map(|(peer_id, peer_height, claim, _, _)| (peer_id, peer_height, claim))
    }

    async fn check_sync(&mut self) {
        if self.active_sync.is_some() {
            return;
        }

        if let Ok(peers) = self.network_handle.get_connected_peers().await {
            let now = Instant::now();
            let connected_set: HashSet<PeerId> = peers.iter().map(|p| p.peer_id).collect();

            // Verify stored tip claims first and re-evaluate valid stored inactive side branches.
            for p in &peers {
                if let Some(ref hs) = p.handshake {
                    if self.verify_or_quarantine_stored_handshake_claim(p.peer_id, hs, now) {
                        continue;
                    }
                    if self.should_reevaluate_stored_side_branch(hs) {
                        if let Err(e) = self
                            .reevaluate_stored_side_branch(p.peer_id, hs.tip_block_id)
                            .await
                        {
                            tracing::warn!(
                                "Re-evaluation of stored side branch {} failed: {}",
                                hs.tip_block_id,
                                e
                            );
                        }
                    }
                }
            }

            if let Some((peer_id, peer_height, claim)) = self.select_sync_candidate_at(&peers, now)
            {
                self.sync_rotation
                    .mark_attempted(peer_id, Some(&connected_set));
                self.start_sync_internal(peer_id, peer_height, Some(claim), false, None);
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
    #[allow(dead_code)]
    fn start_sync(
        &mut self,
        peer_id: PeerId,
        peer_tip_height: u64,
        respond_to: Option<oneshot::Sender<Result<(), String>>>,
    ) {
        self.start_sync_internal(peer_id, peer_tip_height, None, true, respond_to);
    }

    fn start_sync_internal(
        &mut self,
        peer_id: PeerId,
        peer_tip_height: u64,
        advertised_claim: Option<AdvertisedTipClaim>,
        initiated_by_manual: bool,
        respond_to: Option<oneshot::Sender<Result<(), String>>>,
    ) {
        if let Some(ref mut active) = self.active_sync {
            if active.peer_id == peer_id && active.notifier.is_none() {
                tracing::debug!(
                    "Sync with peer {} already in progress; attaching notifier to sync operation #{}",
                    peer_id,
                    active.sync_operation_id
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

        self.current_sync_operation_id = self.current_sync_operation_id.checked_add(1).unwrap_or(1);
        let sync_operation_id = self.current_sync_operation_id;
        let effective_peer_tip_height = advertised_claim
            .as_ref()
            .map(|c| c.tip_height)
            .unwrap_or(peer_tip_height);
        let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (snap_tx, snap_rx) = oneshot::channel();

        let storage = self.storage.clone();
        let flag_clone = cancel_flag.clone();
        self.snapshot_tasks.spawn_blocking(move || {
            let res = storage.capture_canonical_chain_snapshot_cooperative(
                effective_peer_tip_height,
                Some(&flag_clone),
            );
            let _ = snap_tx.send(res);
        });

        let network_handle = self.network_handle.clone();
        let sync_tx = self.sync_msg_tx.clone();
        let chain_id = self.config.chain_id;
        let cancel_flag_for_worker = cancel_flag.clone();

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
                        sync_operation_id,
                        peer_id,
                        result: Err(SyncWorkerError::LocalOrStorage(format!(
                            "Storage error capturing snapshot: {storage_err}"
                        ))),
                    };
                }
            };

            let snapshot = ActiveChainSnapshot {
                tip_height,
                tip_block_id,
                block_ids: Arc::new(block_ids),
            };

            let ctx = SyncWorkerContext {
                sync_operation_id,
                peer_id,
                peer_tip_height: effective_peer_tip_height,
                chain_id,
                snapshot,
                network_handle,
                sync_tx,
                advertised_claim,
                sync_timeout: None,
                cancel_flag: cancel_flag_for_worker,
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
                    Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Sync worker panicked: {panic_msg}"
                    )))
                }
            };

            SyncTaskResult {
                sync_operation_id,
                peer_id,
                result,
            }
        });

        let task_id = worker_handle.id();
        self.sync_task_metadata
            .insert(task_id, (sync_operation_id, peer_id));
        self.active_sync = Some(ActiveSyncOperation {
            sync_operation_id,
            peer_id,
            task_id,
            abort_handle: worker_handle,
            cancel_flag,
            advertised_claim,
            initiated_by_manual,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
            notifier: respond_to,
        });
    }

    /// Handles internal synchronization messages on the runtime actor loop.
    async fn handle_sync_message(&mut self, msg: RuntimeSyncMessage) {
        match msg {
            RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id,
                peer_id,
                blocks,
                respond_to,
            } => {
                let (advertised_tip_id, is_cancelled) = match &self.active_sync {
                    Some(active)
                        if active.sync_operation_id == sync_operation_id
                            && active.peer_id == peer_id =>
                    {
                        (
                            active.advertised_claim.map(|c| c.tip_block_id),
                            active.cancel_flag.load(std::sync::atomic::Ordering::SeqCst),
                        )
                    }
                    _ => {
                        tracing::warn!(
                            "Ignoring stale ApplyBlockBatch from sync_operation_id {} (peer {})",
                            sync_operation_id,
                            peer_id
                        );
                        let mut receipt = SyncBatchReceipt::empty();
                        receipt.status = Err(SyncBatchError::StaleOperation);
                        let _ = respond_to.send(receipt);
                        return;
                    }
                };

                if is_cancelled {
                    tracing::warn!(
                        sync_operation_id,
                        %peer_id,
                        "Ignoring ApplyBlockBatch from cancelled sync_operation_id {}",
                        sync_operation_id
                    );
                    let mut receipt = SyncBatchReceipt::empty();
                    receipt.status = Err(SyncBatchError::StaleOperation);
                    let _ = respond_to.send(receipt);
                    return;
                }

                let mut receipt = SyncBatchReceipt::empty();

                for (idx, block) in blocks.into_iter().enumerate() {
                    if let Some(active) = self.active_sync.as_ref() {
                        if active.cancel_flag.load(std::sync::atomic::Ordering::SeqCst) {
                            tracing::warn!(
                                sync_operation_id,
                                %peer_id,
                                "Active sync operation cancelled during ApplyBlockBatch; aborting batch processing"
                            );
                            receipt.status = Err(SyncBatchError::StaleOperation);
                            break;
                        }
                    }
                    let block_id = block.header.block_id();
                    let parent_id = block.header.parent_block_id;
                    let height = block.header.height;

                    // 1. If already known in local storage, count as duplicate and proceed
                    let is_known = match self.storage.has_block(&block_id) {
                        Ok(k) => k,
                        Err(e) => {
                            receipt.status = Err(SyncBatchError::InternalOrStorage(format!(
                                "storage error checking block {block_id}: {e}"
                            )));
                            break;
                        }
                    };

                    if is_known {
                        receipt.already_known_duplicates += 1;
                        receipt.blocks_processed += 1;
                        if advertised_tip_id.is_some_and(|tip| tip == block_id) {
                            receipt.reached_advertised_tip = true;
                        }
                        continue;
                    }

                    // 2. Strict sync-specific parent check: must connect to genesis or known parent in storage!
                    // Under no circumstances do we allow disconnected orphan blocks to enter the orphan pool
                    // during sync batch application or be reported as successfully processed! (SEC-P2P-004)
                    let parent_known = if parent_id.is_zero() {
                        true
                    } else {
                        match self.storage.has_block(&parent_id) {
                            Ok(k) => k,
                            Err(e) => {
                                receipt.status = Err(SyncBatchError::InternalOrStorage(format!(
                                    "storage error checking parent {parent_id}: {e}"
                                )));
                                break;
                            }
                        }
                    };

                    if !parent_known {
                        tracing::warn!(
                            sync_operation_id,
                            %peer_id,
                            %block_id,
                            %parent_id,
                            height,
                            idx,
                            "Sync block disconnected orphan rejected"
                        );
                        receipt.status = Err(SyncBatchError::DisconnectedOrphan {
                            block_id,
                            parent_id,
                            height,
                            index: idx,
                        });
                        break;
                    }

                    // 3. Process the block now that parent is guaranteed to exist
                    match self
                        .process_inbound_block_with_report(peer_id, Box::new(block), false)
                        .await
                    {
                        Ok(report) => {
                            receipt.blocks_processed += 1;
                            if report.root_newly_persisted {
                                match report.root_outcome {
                                    BlockProcessingOutcome::ActiveChainAccepted(_) => {
                                        receipt.active_blocks_persisted += 1;
                                    }
                                    BlockProcessingOutcome::SideBranchPersisted(_) => {
                                        receipt.side_blocks_persisted += 1;
                                    }
                                    BlockProcessingOutcome::Ignored => {
                                        receipt.already_known_duplicates += 1;
                                    }
                                }
                                if advertised_tip_id.is_some_and(|tip| tip == report.root_block_id)
                                {
                                    receipt.reached_advertised_tip = true;
                                }
                            } else {
                                receipt.already_known_duplicates += 1;
                            }
                        }
                        Err(BlockProcessingError::ConsensusInvalid(reason)) => {
                            tracing::warn!(
                                sync_operation_id,
                                %peer_id,
                                "Sync block consensus validation failed: {}",
                                reason
                            );
                            receipt.status = Err(SyncBatchError::ConsensusInvalid(reason));
                            break;
                        }
                        Err(BlockProcessingError::InternalOrStorage(reason)) => {
                            tracing::warn!(
                                sync_operation_id,
                                %peer_id,
                                "Sync block local storage/internal error: {}",
                                reason
                            );
                            receipt.status = Err(SyncBatchError::InternalOrStorage(reason));
                            break;
                        }
                    }
                }

                let Some(active) = self
                    .active_sync
                    .as_mut()
                    .filter(|a| a.sync_operation_id == sync_operation_id && a.peer_id == peer_id)
                else {
                    receipt.status = Err(SyncBatchError::StaleOperation);
                    let _ = respond_to.send(receipt);
                    return;
                };

                active.active_blocks_persisted = active
                    .active_blocks_persisted
                    .saturating_add(receipt.active_blocks_persisted);
                active.side_blocks_persisted = active
                    .side_blocks_persisted
                    .saturating_add(receipt.side_blocks_persisted);
                if receipt.reached_advertised_tip {
                    active.reached_advertised_tip_via_sync = true;
                }
                if let Err(ref err) = receipt.status {
                    if active.observed_batch_error.is_none() {
                        active.observed_batch_error = Some(err.clone());
                    }
                }
                let _ = respond_to.send(receipt);
            }
        }
    }

    fn evaluate_active_sync_outcome(
        &self,
        active_op: &ActiveSyncOperation,
        worker_result: &Result<SyncWorkerSuccess, SyncWorkerError>,
    ) -> SyncOutcomeEvaluation {
        // 1. Local faults (storage/RandomX/context, shutdown cancellation, local disconnect)
        //    never penalize or reset the peer.
        if matches!(
            active_op.observed_batch_error,
            Some(SyncBatchError::InternalOrStorage(_)) | Some(SyncBatchError::StaleOperation)
        ) || matches!(worker_result, Err(SyncWorkerError::LocalOrStorage(_)))
        {
            return SyncOutcomeEvaluation::LocalFaultNoPeerPenalty;
        }

        // 2. Consensus-invalid chain data or disconnected orphans delivered during sync
        //    overrides any earlier partial valid progress.
        if matches!(
            active_op.observed_batch_error,
            Some(SyncBatchError::ConsensusInvalid(_))
                | Some(SyncBatchError::DisconnectedOrphan { .. })
        ) || matches!(worker_result, Err(SyncWorkerError::ConsensusInvalid(_)))
        {
            return SyncOutcomeEvaluation::Penalized(SyncFailureClass::InvalidChainData);
        }

        // 3. Evaluate stored advertised tip metadata independently of how the block arrived.
        let mut claim_meta_matched = false;
        if let Some(claim) = active_op.advertised_claim {
            match self.storage.get_block_metadata(&claim.tip_block_id) {
                Err(e) => {
                    tracing::warn!(
                        sync_operation_id = active_op.sync_operation_id,
                        peer_id = %active_op.peer_id,
                        tip = %claim.tip_block_id,
                        error = %e,
                        "Storage error reading advertised tip metadata at sync completion"
                    );
                    return SyncOutcomeEvaluation::LocalFaultNoPeerPenalty;
                }
                Ok(Some(meta)) => {
                    if meta.height != claim.tip_height
                        || meta.cumulative_work != claim.cumulative_work
                    {
                        return SyncOutcomeEvaluation::Penalized(
                            SyncFailureClass::FalseAdvertisedWorkClaim,
                        );
                    }
                    claim_meta_matched = true;
                }
                Ok(None) => {}
            }
        }

        let validated_persisted = active_op
            .active_blocks_persisted
            .saturating_add(active_op.side_blocks_persisted);

        // 4. Handle worker error variants
        match worker_result {
            Err(SyncWorkerError::FalseAdvertisedClaim(_)) => {
                SyncOutcomeEvaluation::Penalized(SyncFailureClass::FalseAdvertisedWorkClaim)
            }
            Err(SyncWorkerError::Incomplete { .. }) => {
                if validated_persisted > 0 {
                    SyncOutcomeEvaluation::Penalized(SyncFailureClass::IncompleteProgress)
                } else {
                    SyncOutcomeEvaluation::Penalized(SyncFailureClass::ZeroProgress)
                }
            }
            Err(SyncWorkerError::BudgetExhausted(ref msg)) => {
                // If deadline expired waiting for local runtime dispatch or acknowledgement,
                // do not penalize the peer for local processing delay.
                if msg.contains("block batch") || msg.contains("local") {
                    SyncOutcomeEvaluation::LocalFaultNoPeerPenalty
                } else if validated_persisted > 0 {
                    SyncOutcomeEvaluation::Penalized(SyncFailureClass::IncompleteProgress)
                } else {
                    SyncOutcomeEvaluation::Penalized(SyncFailureClass::ZeroProgress)
                }
            }
            Err(SyncWorkerError::TransientOrProtocol(_)) => {
                SyncOutcomeEvaluation::Penalized(SyncFailureClass::TransientOrTimeout)
            }
            Err(SyncWorkerError::ConsensusInvalid(_)) => {
                SyncOutcomeEvaluation::Penalized(SyncFailureClass::InvalidChainData)
            }
            Err(SyncWorkerError::LocalOrStorage(_)) => {
                SyncOutcomeEvaluation::LocalFaultNoPeerPenalty
            }
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height,
                tip_block_id,
            }) => {
                if let Some(claim) = active_op.advertised_claim {
                    if !claim_meta_matched {
                        SyncOutcomeEvaluation::Penalized(SyncFailureClass::FalseAdvertisedWorkClaim)
                    } else if claim.tip_height == *tip_height {
                        if claim.tip_block_id == *tip_block_id {
                            SyncOutcomeEvaluation::VerifiedSuccess
                        } else {
                            SyncOutcomeEvaluation::Penalized(
                                SyncFailureClass::FalseAdvertisedWorkClaim,
                            )
                        }
                    } else if claim.tip_height < *tip_height {
                        // For a lower-height peer claim, verify the advertised block ID is on the
                        // active canonical chain before accepting AlreadySynchronized.
                        // A known side-branch block must not silently qualify as a canonical-prefix AlreadySynchronized outcome.
                        match self.storage.get_header_by_height(claim.tip_height) {
                            Ok(Some(canonical_header)) => {
                                if canonical_header.block_id() == claim.tip_block_id {
                                    SyncOutcomeEvaluation::VerifiedSuccess
                                } else {
                                    SyncOutcomeEvaluation::Penalized(
                                        SyncFailureClass::FalseAdvertisedWorkClaim,
                                    )
                                }
                            }
                            Ok(None) => SyncOutcomeEvaluation::Penalized(
                                SyncFailureClass::FalseAdvertisedWorkClaim,
                            ),
                            Err(e) => {
                                tracing::warn!(
                                    sync_operation_id = active_op.sync_operation_id,
                                    peer_id = %active_op.peer_id,
                                    error = %e,
                                    "Storage error reading canonical header at height {} during AlreadySynchronized evaluation",
                                    claim.tip_height
                                );
                                SyncOutcomeEvaluation::LocalFaultNoPeerPenalty
                            }
                        }
                    } else {
                        SyncOutcomeEvaluation::Penalized(SyncFailureClass::FalseAdvertisedWorkClaim)
                    }
                } else {
                    SyncOutcomeEvaluation::VerifiedSuccess
                }
            }
            Ok(SyncWorkerSuccess::VerifiedSuccess { .. }) => {
                if active_op.advertised_claim.is_some() {
                    if validated_persisted > 0
                        && active_op.reached_advertised_tip_via_sync
                        && claim_meta_matched
                    {
                        SyncOutcomeEvaluation::VerifiedSuccess
                    } else if validated_persisted > 0 {
                        SyncOutcomeEvaluation::Penalized(SyncFailureClass::IncompleteProgress)
                    } else {
                        SyncOutcomeEvaluation::Penalized(SyncFailureClass::ZeroProgress)
                    }
                } else if validated_persisted > 0 {
                    SyncOutcomeEvaluation::VerifiedSuccess
                } else {
                    SyncOutcomeEvaluation::Penalized(SyncFailureClass::ZeroProgress)
                }
            }
        }
    }

    fn finish_active_sync_with_result_at(
        &mut self,
        mut active_op: ActiveSyncOperation,
        worker_result: Result<SyncWorkerSuccess, SyncWorkerError>,
        now: Instant,
    ) {
        let evaluation = self.evaluate_active_sync_outcome(&active_op, &worker_result);
        match evaluation {
            SyncOutcomeEvaluation::LocalFaultNoPeerPenalty => {}
            SyncOutcomeEvaluation::VerifiedSuccess => {
                self.sync_penalties
                    .record_verified_success(&active_op.peer_id, now);
            }
            SyncOutcomeEvaluation::Penalized(class) => {
                self.sync_penalties.record_failure(
                    active_op.peer_id,
                    class,
                    active_op.initiated_by_manual,
                    now,
                );
            }
        }
        if let Some(notifier) = active_op.notifier.take() {
            let res = match evaluation {
                SyncOutcomeEvaluation::VerifiedSuccess => Ok(()),
                SyncOutcomeEvaluation::LocalFaultNoPeerPenalty => {
                    let msg = match &worker_result {
                        Err(e) => format!("sync aborted due to local fault: {e}"),
                        _ => "sync aborted due to local fault or shutdown".to_string(),
                    };
                    Err(msg)
                }
                SyncOutcomeEvaluation::Penalized(class) => {
                    let msg = match &worker_result {
                        Err(e) => format!("sync failed ({class:?}): {e}"),
                        _ => format!("sync failed: {:?}", class),
                    };
                    Err(msg)
                }
            };
            let _ = notifier.send(res);
        }
    }

    fn handle_sync_task_success(
        &mut self,
        task_id: tokio::task::Id,
        meta: Option<(u64, PeerId)>,
        sync_res: SyncTaskResult,
    ) {
        let (sync_operation_id, peer_id) = match meta {
            Some(m) => m,
            None => (sync_res.sync_operation_id, sync_res.peer_id),
        };

        let is_current = match &self.active_sync {
            Some(active) => {
                active.task_id == task_id
                    && active.sync_operation_id == sync_operation_id
                    && active.peer_id == peer_id
            }
            None => false,
        };

        if !is_current {
            tracing::warn!(
                "Ignoring stale SyncTaskResult from task {:?}, sync_operation_id {} (peer {})",
                task_id,
                sync_operation_id,
                peer_id
            );
            return;
        }

        tracing::info!(
            "Sync operation #{} with peer {} finished: {:?}",
            sync_operation_id,
            peer_id,
            sync_res.result
        );

        let active_op = self.active_sync.take().unwrap();
        self.finish_active_sync_with_result_at(active_op, sync_res.result, Instant::now());
    }

    fn handle_sync_task_failure(
        &mut self,
        task_id: tokio::task::Id,
        meta: Option<(u64, PeerId)>,
        join_err: tokio::task::JoinError,
    ) {
        let Some((sync_operation_id, peer_id)) = meta else {
            tracing::warn!(
                "Ignoring sync task {:?} failure without operation metadata",
                task_id
            );
            return;
        };

        let is_current = match &self.active_sync {
            Some(active) => {
                active.task_id == task_id
                    && active.sync_operation_id == sync_operation_id
                    && active.peer_id == peer_id
            }
            None => false,
        };

        if !is_current {
            tracing::warn!(
                "Ignoring failure from non-active sync task {:?}, sync_operation_id {} (peer {})",
                task_id,
                sync_operation_id,
                peer_id
            );
            return;
        }

        let Some(active_op) = self.active_sync.take() else {
            return;
        };

        if join_err.is_cancelled() {
            tracing::debug!("Active sync #{} task was cancelled", sync_operation_id);
            self.finish_active_sync_with_result_at(
                active_op,
                Err(SyncWorkerError::LocalOrStorage(
                    "Sync cancelled".to_string(),
                )),
                Instant::now(),
            );
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
            tracing::error!("Sync worker #{} panicked: {}", sync_operation_id, panic_msg);
            self.finish_active_sync_with_result_at(
                active_op,
                Err(SyncWorkerError::TransientOrProtocol(format!(
                    "Sync worker panicked: {panic_msg}"
                ))),
                Instant::now(),
            );
        } else {
            tracing::error!("Sync task #{} failed: {}", sync_operation_id, join_err);
            self.finish_active_sync_with_result_at(
                active_op,
                Err(SyncWorkerError::TransientOrProtocol(format!(
                    "Sync task failed: {join_err}"
                ))),
                Instant::now(),
            );
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
        self.start_sync_internal(peer_id, peer_tip_height, None, true, Some(tx));
        rx
    }
}

struct SyncWorkerContext {
    sync_operation_id: u64,
    peer_id: PeerId,
    peer_tip_height: u64,
    chain_id: Hash,
    snapshot: ActiveChainSnapshot,
    network_handle: NetworkHandle,
    sync_tx: mpsc::Sender<RuntimeSyncMessage>,
    advertised_claim: Option<AdvertisedTipClaim>,
    sync_timeout: Option<Duration>,
    cancel_flag: Arc<std::sync::atomic::AtomicBool>,
}

const SYNC_BATCH_SIZE: u32 = MAX_BLOCKS_PER_RESPONSE as u32;
const MAX_SYNC_BLOCKS: u64 = 10_000;
const MAX_SYNC_ROUND_TRIPS: u32 = 500;
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

impl NodeRuntime {
    /// Outbound synchronization worker performing ancestor discovery and batched block fetches.
    async fn run_sync_worker(ctx: SyncWorkerContext) -> Result<SyncWorkerSuccess, SyncWorkerError> {
        let SyncWorkerContext {
            sync_operation_id,
            peer_id,
            peer_tip_height,
            chain_id,
            snapshot,
            network_handle,
            sync_tx,
            advertised_claim,
            sync_timeout,
            cancel_flag,
        } = ctx;

        let timeout_duration = sync_timeout.unwrap_or(SYNC_TIMEOUT);
        let deadline = tokio::time::Instant::now() + timeout_duration;

        // 1. Discover common ancestor between local snapshot and peer chain
        let min_h = snapshot.tip_height().min(peer_tip_height);
        let common_ancestor_height = if min_h == 0 {
            let genesis_id = snapshot
                .get_block_id(0)
                .unwrap_or_else(|| genesis_block(chain_id).block_id());
            if let Some(ref claim) = advertised_claim {
                if claim.tip_height == 0 && claim.tip_block_id != genesis_id {
                    return Err(SyncWorkerError::FalseAdvertisedClaim(format!(
                        "Peer {peer_id} advertised invalid genesis tip block ID {} at height 0 (expected {})",
                        claim.tip_block_id,
                        genesis_id
                    )));
                }
            }
            0
        } else {
            if tokio::time::Instant::now() >= deadline {
                return Err(SyncWorkerError::BudgetExhausted(format!(
                    "Sync timeout of {:?} exceeded during ancestor discovery",
                    timeout_duration
                )));
            }
            // Fast path: check if peer matches our snapshot at min_h
            let fast_req = SyncRequest::GetHeaders {
                start_height: min_h,
                max_count: 1,
            };
            let fast_match = match tokio::time::timeout_at(
                deadline,
                network_handle.send_sync_request(peer_id, fast_req),
            )
            .await
            {
                Err(_) => {
                    return Err(SyncWorkerError::BudgetExhausted(format!(
                        "Sync timeout of {:?} exceeded during fast-path query",
                        timeout_duration
                    )));
                }
                Ok(Ok(SyncResponse::Headers(headers))) => {
                    if headers.is_empty() {
                        return Err(SyncWorkerError::Incomplete {
                            requested_height: min_h,
                            expected_target: peer_tip_height,
                            reason: "fast-path header query returned empty headers".into(),
                        });
                    }
                    if headers.len() > 1 {
                        return Err(SyncWorkerError::ConsensusInvalid(format!(
                            "fast-path header query returned {} headers, expected 1",
                            headers.len()
                        )));
                    }
                    let h = &headers[0];
                    if h.height != min_h {
                        return Err(SyncWorkerError::ConsensusInvalid(format!(
                            "fast-path header has height {}, expected {min_h}",
                            h.height
                        )));
                    }
                    if h.chain_id != chain_id {
                        return Err(SyncWorkerError::ConsensusInvalid(format!(
                            "fast-path header has invalid chain ID {}, expected {chain_id}",
                            h.chain_id
                        )));
                    }
                    // Verify consistency with advertised tip if this query is at the peer's claimed tip
                    if let Some(ref claim) = advertised_claim {
                        if claim.tip_height == min_h && h.block_id() != claim.tip_block_id {
                            return Err(SyncWorkerError::FalseAdvertisedClaim(format!(
                                "Peer {peer_id} advertised tip block ID {} at height {min_h}, but served header with block ID {}",
                                claim.tip_block_id,
                                h.block_id()
                            )));
                        }
                    }
                    Some(h.block_id()) == snapshot.get_block_id(min_h)
                }
                Ok(Ok(other)) => {
                    return Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Unexpected response during fast-path header query from {peer_id}: {other:?}"
                    )));
                }
                Ok(Err(e)) => {
                    return Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Transport error querying fast-path header at height {min_h} from {peer_id}: {e}"
                    )));
                }
            };

            if fast_match {
                min_h
            } else {
                // Binary search for common ancestor in [0, min_h - 1]
                let mut low = 0u64;
                let mut high = min_h.saturating_sub(1);

                while low < high {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(SyncWorkerError::BudgetExhausted(format!(
                            "Sync timeout of {:?} exceeded during ancestor discovery",
                            timeout_duration
                        )));
                    }
                    let mid = low + (high - low).div_ceil(2);
                    let req = SyncRequest::GetHeaders {
                        start_height: mid,
                        max_count: 1,
                    };
                    match tokio::time::timeout_at(
                        deadline,
                        network_handle.send_sync_request(peer_id, req),
                    )
                    .await
                    {
                        Err(_) => {
                            return Err(SyncWorkerError::BudgetExhausted(format!(
                                "Sync timeout of {:?} exceeded during binary search query",
                                timeout_duration
                            )));
                        }
                        Ok(Ok(SyncResponse::Headers(headers))) => {
                            if headers.is_empty() {
                                return Err(SyncWorkerError::Incomplete {
                                    requested_height: mid,
                                    expected_target: peer_tip_height,
                                    reason: "binary search header query returned empty headers"
                                        .into(),
                                });
                            }
                            if headers.len() > 1 {
                                return Err(SyncWorkerError::ConsensusInvalid(format!(
                                    "binary search header query returned {} headers, expected 1",
                                    headers.len()
                                )));
                            }
                            let h = &headers[0];
                            if h.height != mid {
                                return Err(SyncWorkerError::ConsensusInvalid(format!(
                                    "binary search header has height {}, expected {mid}",
                                    h.height
                                )));
                            }
                            if h.chain_id != chain_id {
                                return Err(SyncWorkerError::ConsensusInvalid(format!(
                                    "binary search header has invalid chain ID {}, expected {chain_id}",
                                    h.chain_id
                                )));
                            }
                            if Some(h.block_id()) == snapshot.get_block_id(mid) {
                                low = mid;
                            } else {
                                high = mid.saturating_sub(1);
                            }
                        }
                        Ok(Ok(other)) => {
                            return Err(SyncWorkerError::TransientOrProtocol(format!(
                                "Unexpected response querying header at height {mid} during ancestor discovery with {peer_id}: {other:?}"
                            )));
                        }
                        Ok(Err(e)) => {
                            return Err(SyncWorkerError::TransientOrProtocol(format!(
                                "Failed to query header at height {mid} during ancestor discovery with {peer_id}: {e}"
                            )));
                        }
                    }
                }

                low
            }
        };

        if common_ancestor_height == peer_tip_height {
            tracing::info!(
                "Already synchronized with peer {} at height #{}",
                peer_id,
                peer_tip_height
            );
            return Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: snapshot.tip_height(),
                tip_block_id: snapshot.tip_block_id(),
            });
        }

        tracing::info!(
            "Common ancestor with peer {} found at height #{}. Fetching replacement blocks #{}..#{}",
            peer_id,
            common_ancestor_height,
            common_ancestor_height + 1,
            peer_tip_height
        );

        let mut current_h = common_ancestor_height.saturating_add(1);
        let mut total_blocks_applied = 0u64;
        let mut total_bodies_processed = 0u64;
        let mut last_applied_block_id = snapshot
            .get_block_id(common_ancestor_height)
            .unwrap_or(Hash::ZERO);
        let mut last_applied_height = common_ancestor_height;
        let mut round_trips = 0u32;

        while current_h <= peer_tip_height {
            if tokio::time::Instant::now() >= deadline {
                return Err(SyncWorkerError::BudgetExhausted(format!(
                    "Sync timeout of {:?} exceeded",
                    timeout_duration
                )));
            }
            if total_bodies_processed >= MAX_SYNC_BLOCKS {
                return Err(SyncWorkerError::BudgetExhausted(format!(
                    "Max sync blocks limit ({MAX_SYNC_BLOCKS}) reached before reaching target #{peer_tip_height}"
                )));
            }
            round_trips = round_trips.checked_add(1).ok_or_else(|| {
                SyncWorkerError::BudgetExhausted("Round trips count overflowed".into())
            })?;
            if round_trips > MAX_SYNC_ROUND_TRIPS {
                return Err(SyncWorkerError::BudgetExhausted(format!(
                    "Max sync round trips limit ({MAX_SYNC_ROUND_TRIPS}) reached"
                )));
            }

            let remaining_budget = MAX_SYNC_BLOCKS.saturating_sub(total_bodies_processed);
            let count = (peer_tip_height.saturating_sub(current_h).saturating_add(1))
                .min(SYNC_BATCH_SIZE as u64)
                .min(remaining_budget) as u32;
            let req = SyncRequest::GetHeaders {
                start_height: current_h,
                max_count: count,
            };

            let headers = match tokio::time::timeout_at(
                deadline,
                network_handle.send_sync_request(peer_id, req),
            )
            .await
            {
                Err(_) => {
                    return Err(SyncWorkerError::BudgetExhausted(format!(
                        "Sync timeout of {:?} exceeded requesting batch headers",
                        timeout_duration
                    )));
                }
                Ok(Ok(SyncResponse::Headers(headers))) => headers,
                Ok(Ok(other)) => {
                    return Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Unexpected sync headers response from {peer_id}: {other:?}"
                    )));
                }
                Ok(Err(e)) => {
                    return Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Network error requesting headers #{current_h}.. from {peer_id}: {e}"
                    )));
                }
            };

            if headers.is_empty() {
                return Err(SyncWorkerError::Incomplete {
                    requested_height: current_h,
                    expected_target: peer_tip_height,
                    reason: "peer returned empty headers before reaching target height".into(),
                });
            }

            if headers.len() > count as usize {
                return Err(SyncWorkerError::ConsensusInvalid(format!(
                    "Peer returned {} headers, exceeding requested count {}",
                    headers.len(),
                    count
                )));
            }

            // Validate header chain contiguity, heights, and linkage
            let mut prev_id = last_applied_block_id;
            for (i, header) in headers.iter().enumerate() {
                let expected_height = current_h.saturating_add(i as u64);
                if header.height != expected_height {
                    return Err(SyncWorkerError::ConsensusInvalid(format!(
                        "Header at index {i} has height {}, expected {expected_height}",
                        header.height
                    )));
                }
                if header.chain_id != chain_id {
                    return Err(SyncWorkerError::ConsensusInvalid(format!(
                        "Header #{expected_height} has invalid chain ID {}, expected {chain_id}",
                        header.chain_id
                    )));
                }
                if header.parent_block_id != prev_id {
                    return Err(SyncWorkerError::ConsensusInvalid(format!(
                        "Header #{expected_height} parent {} does not match previous block ID {}",
                        header.parent_block_id, prev_id
                    )));
                }
                prev_id = header.block_id();
            }

            // Verify consistency with advertised tip if batch contains the claimed tip header
            if let Some(ref claim) = advertised_claim {
                for header in &headers {
                    if header.height == claim.tip_height && header.block_id() != claim.tip_block_id
                    {
                        return Err(SyncWorkerError::FalseAdvertisedClaim(format!(
                            "Peer {peer_id} advertised tip block ID {} at height {}, but served header with block ID {}",
                            claim.tip_block_id, claim.tip_height, header.block_id()
                        )));
                    }
                }
            }

            let block_ids: Vec<Hash> = headers.iter().map(|h| h.block_id()).collect();

            // Request blocks for these headers
            let block_req = SyncRequest::GetBlocks {
                block_ids: block_ids.clone(),
            };
            let blocks = match tokio::time::timeout_at(
                deadline,
                network_handle.send_sync_request(peer_id, block_req),
            )
            .await
            {
                Err(_) => {
                    return Err(SyncWorkerError::BudgetExhausted(format!(
                        "Sync timeout of {:?} exceeded requesting blocks",
                        timeout_duration
                    )));
                }
                Ok(Ok(SyncResponse::Blocks(blocks))) => blocks,
                Ok(Ok(other)) => {
                    return Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Unexpected sync blocks response from {peer_id}: {other:?}"
                    )));
                }
                Ok(Err(e)) => {
                    return Err(SyncWorkerError::TransientOrProtocol(format!(
                        "Network error requesting blocks from {peer_id}: {e}"
                    )));
                }
            };

            if blocks.is_empty() {
                return Err(SyncWorkerError::Incomplete {
                    requested_height: current_h,
                    expected_target: peer_tip_height,
                    reason: "peer returned empty blocks for non-empty headers".into(),
                });
            }

            if blocks.len() > headers.len() {
                return Err(SyncWorkerError::ConsensusInvalid(format!(
                    "Peer returned {} blocks, exceeding requested count {}",
                    blocks.len(),
                    headers.len()
                )));
            }

            // Verify each block strictly matches its corresponding requested header and position
            for (i, (block, header)) in blocks.iter().zip(headers.iter()).enumerate() {
                let actual_id = block.header.block_id();
                let expected_id = block_ids[i];
                if actual_id != expected_id {
                    return Err(SyncWorkerError::ConsensusInvalid(format!(
                        "Block at index {i} ID {actual_id} does not match requested block ID {expected_id}"
                    )));
                }
                if &block.header != header {
                    return Err(SyncWorkerError::ConsensusInvalid(format!(
                        "Block body header at index {i} does not match requested header"
                    )));
                }
                let expected_height = current_h.saturating_add(i as u64);
                if block.header.height != expected_height {
                    return Err(SyncWorkerError::ConsensusInvalid(format!(
                        "Block at index {i} has height {}, expected {expected_height}",
                        block.header.height
                    )));
                }
            }

            let (ack_tx, ack_rx) = oneshot::channel();
            tokio::time::timeout_at(
                deadline,
                sync_tx.send(RuntimeSyncMessage::ApplyBlockBatch {
                    sync_operation_id,
                    peer_id,
                    blocks,
                    respond_to: ack_tx,
                }),
            )
            .await
            .map_err(|_| {
                cancel_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                SyncWorkerError::BudgetExhausted(format!(
                    "Sync timeout of {:?} exceeded sending block batch to runtime",
                    timeout_duration
                ))
            })?
            .map_err(|_| {
                SyncWorkerError::LocalOrStorage("Node runtime shut down during sync".to_string())
            })?;

            let receipt = tokio::time::timeout_at(deadline, ack_rx)
                .await
                .map_err(|_| {
                    cancel_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    SyncWorkerError::BudgetExhausted(format!(
                        "Sync timeout of {:?} exceeded waiting for block batch receipt",
                        timeout_duration
                    ))
                })?
                .map_err(|_| {
                    SyncWorkerError::LocalOrStorage(
                        "Node runtime dropped block batch response".to_string(),
                    )
                })?;

            let processed = receipt.blocks_processed as u64;
            total_bodies_processed = total_bodies_processed.saturating_add(processed);

            if receipt.blocks_processed > 0 {
                let newly_applied =
                    (receipt.active_blocks_persisted + receipt.side_blocks_persisted) as u64;
                total_blocks_applied = total_blocks_applied.saturating_add(newly_applied);
                if let Some(&id) = block_ids.get(receipt.blocks_processed - 1) {
                    last_applied_block_id = id;
                } else if let Some(&id) = block_ids.last() {
                    last_applied_block_id = id;
                }
                last_applied_height = current_h.saturating_add(processed.saturating_sub(1));
                current_h = last_applied_height.saturating_add(1);
                if last_applied_height >= peer_tip_height {
                    break;
                }
            }

            if let Err(err) = receipt.status {
                return Err(match err {
                    SyncBatchError::ConsensusInvalid(msg) => {
                        SyncWorkerError::ConsensusInvalid(msg)
                    }
                    SyncBatchError::DisconnectedOrphan {
                        block_id,
                        parent_id,
                        height,
                        index,
                    } => SyncWorkerError::ConsensusInvalid(format!(
                        "Peer delivered disconnected orphan block #{height} ({block_id}) at batch index {index}, parent {parent_id} unknown"
                    )),
                    SyncBatchError::InternalOrStorage(msg) => {
                        SyncWorkerError::LocalOrStorage(msg)
                    }
                    SyncBatchError::StaleOperation => {
                        SyncWorkerError::LocalOrStorage(
                            "stale sync generation".to_string(),
                        )
                    }
                });
            }

            if receipt.blocks_processed == 0 {
                return Err(SyncWorkerError::Incomplete {
                    requested_height: current_h,
                    expected_target: peer_tip_height,
                    reason: "Zero blocks processed in batch application".into(),
                });
            }
        }

        if last_applied_height < peer_tip_height {
            return Err(SyncWorkerError::Incomplete {
                requested_height: current_h,
                expected_target: peer_tip_height,
                reason: format!(
                    "Sync loop exited before reaching target height: applied #{last_applied_height} < target #{peer_tip_height}"
                ),
            });
        }

        let final_height = last_applied_height;
        Ok(SyncWorkerSuccess::VerifiedSuccess {
            blocks_applied: total_blocks_applied,
            final_height,
            final_tip_id: last_applied_block_id,
        })
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
                let now = Instant::now();
                if self.verify_or_quarantine_stored_handshake_claim(peer_id, &handshake, now) {
                    if self.active_sync.is_none() {
                        self.check_sync().await;
                    }
                    return;
                }
                if self.should_reevaluate_stored_side_branch(&handshake) {
                    if let Err(e) = self
                        .reevaluate_stored_side_branch(peer_id, handshake.tip_block_id)
                        .await
                    {
                        tracing::warn!(
                            "Re-evaluation of stored side branch {} failed: {}",
                            handshake.tip_block_id,
                            e
                        );
                    }
                } else {
                    self.check_sync().await;
                }
            }

            NetworkEvent::PeerDisconnected { peer_id } => {
                tracing::info!("Peer {} disconnected", peer_id);
                let now = Instant::now();
                let was_local_disconnect = self.consume_local_disconnect_marker(&peer_id, now);
                if let Some(active) = self.active_sync.take() {
                    if active.peer_id == peer_id {
                        tracing::warn!(
                            "Syncing peer {} disconnected; aborting sync operation #{}",
                            peer_id,
                            active.sync_operation_id
                        );
                        active
                            .cancel_flag
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        active.abort_handle.abort();
                        let disconnect_err = if was_local_disconnect {
                            SyncWorkerError::LocalOrStorage(format!(
                                "Local disconnect cancelled synchronization with {peer_id}"
                            ))
                        } else {
                            SyncWorkerError::TransientOrProtocol(format!(
                                "Peer {peer_id} disconnected during synchronization"
                            ))
                        };
                        self.finish_active_sync_with_result_at(active, Err(disconnect_err), now);
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

            NetworkEvent::BlockReceived {
                propagation_source,
                source,
                message_id,
                block,
                execution_guard,
            } => {
                let block_id = block.header.block_id();
                const GOSSIP_VALIDATION_TIMEOUT: Duration = Duration::from_secs(20);
                let (acceptance, mark_seen, canonical_id) = match tokio::time::timeout(
                    GOSSIP_VALIDATION_TIMEOUT,
                    async {
                        let _guard = execution_guard;
                        self.handle_inbound_block_internal(propagation_source, block, true)
                            .await
                    },
                )
                .await
                {
                    Ok(Ok(GossipBlockDisposition::AcceptNew(id))) => {
                        (MessageAcceptance::Accept, true, Some(id))
                    }
                    Ok(Ok(GossipBlockDisposition::IgnoreKnownDuplicate)) => {
                        (MessageAcceptance::Ignore, true, Some(block_id))
                    }
                    Ok(Ok(GossipBlockDisposition::IgnoreOrphan)) => {
                        (MessageAcceptance::Ignore, false, None)
                    }
                    Ok(Err(BlockProcessingError::ConsensusInvalid(reason))) => {
                        tracing::debug!(
                            %block_id,
                            %propagation_source,
                            author = ?source,
                            reason = %reason,
                            "Rejected invalid inbound gossip block"
                        );
                        (MessageAcceptance::Reject, false, None)
                    }
                    Ok(Err(BlockProcessingError::InternalOrStorage(reason))) => {
                        tracing::warn!(
                            %block_id,
                            %propagation_source,
                            author = ?source,
                            reason = %reason,
                            "Internal or storage error while processing inbound gossip block; ignoring without peer penalty"
                        );
                        (MessageAcceptance::Ignore, false, None)
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            %block_id,
                            %propagation_source,
                            author = ?source,
                            timeout = ?GOSSIP_VALIDATION_TIMEOUT,
                            "Inbound gossip block validation timed out; terminating execution safely and ignoring message"
                        );
                        (MessageAcceptance::Ignore, false, None)
                    }
                };
                if let Err(e) = self
                    .network_handle
                    .report_gossip_validation(
                        message_id,
                        propagation_source,
                        acceptance,
                        mark_seen,
                        canonical_id,
                        true,
                    )
                    .await
                {
                    tracing::debug!(
                        %block_id,
                        %propagation_source,
                        error = %e,
                        "Failed to report block gossip validation outcome"
                    );
                }
            }

            NetworkEvent::TransactionReceived {
                propagation_source,
                source,
                message_id,
                transaction,
                execution_guard,
            } => {
                let _guard = execution_guard;
                let tx_id = crate::hash::transaction_id(&transaction);
                let (acceptance, mark_seen, canonical_id) =
                    match self.mempool.admit(&transaction, &self.chain_state) {
                        Ok(admitted_id) => {
                            tracing::debug!("Admitted transaction {} into mempool", admitted_id);
                            self.flush_evicted_seen_txs().await;
                            (MessageAcceptance::Accept, true, Some(admitted_id))
                        }
                        Err(e) => {
                            let (acc, seen) = classify_mempool_error(&e);
                            tracing::debug!(
                                %tx_id,
                                %propagation_source,
                                author = ?source,
                                acceptance = ?acc,
                                error = ?e,
                                "Classified inbound gossip transaction validation failure"
                            );
                            (acc, seen, if seen { Some(tx_id) } else { None })
                        }
                    };
                if let Err(e) = self
                    .network_handle
                    .report_gossip_validation(
                        message_id,
                        propagation_source,
                        acceptance,
                        mark_seen,
                        canonical_id,
                        false,
                    )
                    .await
                {
                    tracing::debug!(
                        %tx_id,
                        %propagation_source,
                        error = %e,
                        "Failed to report transaction gossip validation outcome"
                    );
                }
            }

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
                for i in 0..(count as u64) {
                    let Some(h) = start_height.checked_add(i) else {
                        break;
                    };
                    if let Ok(Some(header)) = self.storage.get_header_by_height(h) {
                        headers.push(header);
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
                        if !blocks.is_empty() && total_bytes.saturating_add(block_size) > 1_800_000
                        {
                            break;
                        }
                        total_bytes = total_bytes.saturating_add(block_size);
                        blocks.push(block);
                    } else {
                        // Preserves contiguous prefix: stop if any block is missing
                        break;
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
        self.handle_inbound_block_internal(source_peer, block, false)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn handle_inbound_block_internal(
        &mut self,
        source_peer: PeerId,
        block: Box<Block>,
        suppress_root_broadcast: bool,
    ) -> Result<GossipBlockDisposition, BlockProcessingError> {
        self.process_inbound_block_with_report(source_peer, block, suppress_root_broadcast)
            .await
            .map(|r| r.gossip_disposition)
    }

    async fn process_inbound_block_with_report(
        &mut self,
        source_peer: PeerId,
        block: Box<Block>,
        suppress_root_broadcast: bool,
    ) -> Result<InboundBlockReport, BlockProcessingError> {
        let root_step = self
            .process_single_block(source_peer, block, suppress_root_broadcast)
            .await?;
        let report = InboundBlockReport {
            root_block_id: root_step.root_block_id,
            root_outcome: root_step.outcome,
            gossip_disposition: root_step.gossip_disposition,
            root_newly_persisted: root_step.root_newly_persisted,
        };

        let mut queue = VecDeque::new();
        for parent_block in root_step.missing_parents {
            queue.push_back((source_peer, Box::new(parent_block)));
        }
        if let Some(new_id) = root_step.outcome.persisted_block_id() {
            if let Some(orphan_ids) = self.orphan_parents.remove(&new_id) {
                for child_id in orphan_ids {
                    if let Some(child_entry) = self.remove_orphan(&child_id) {
                        queue.push_back((child_entry.source_peer, Box::new(child_entry.block)));
                    }
                }
            }
        }

        while let Some((peer, curr_block)) = queue.pop_front() {
            match self.process_single_block(peer, curr_block, false).await {
                Ok(step) => {
                    for parent_block in step.missing_parents {
                        queue.push_back((peer, Box::new(parent_block)));
                    }
                    if let Some(new_id) = step.outcome.persisted_block_id() {
                        if let Some(orphan_ids) = self.orphan_parents.remove(&new_id) {
                            for child_id in orphan_ids {
                                if let Some(child_entry) = self.remove_orphan(&child_id) {
                                    queue.push_back((
                                        child_entry.source_peer,
                                        Box::new(child_entry.block),
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        source_peer = %peer,
                        error = %e,
                        "Failed to process unrolled orphan child block"
                    );
                }
            }
        }

        Ok(report)
    }

    async fn process_single_block(
        &mut self,
        source_peer: PeerId,
        block: Box<Block>,
        suppress_broadcast: bool,
    ) -> Result<SingleBlockResult, BlockProcessingError> {
        let block_id = block.header.block_id();
        let height = block.header.height;
        let parent_id = block.header.parent_block_id;

        // 1. Check if block is already known in storage
        let meta_opt = self.storage.get_block_metadata(&block_id).map_err(|e| {
            BlockProcessingError::InternalOrStorage(format!(
                "storage error checking block metadata {block_id}: {e}"
            ))
        })?;

        if let Some(meta) = meta_opt {
            if meta.is_active {
                // Block is already on the active canonical chain
                return Ok(SingleBlockResult {
                    root_block_id: block_id,
                    root_newly_persisted: false,
                    outcome: BlockProcessingOutcome::Ignored,
                    gossip_disposition: GossipBlockDisposition::IgnoreKnownDuplicate,
                    missing_parents: Vec::new(),
                });
            }

            // Block is in storage as an inactive side branch.
            // If it was already evaluated against our current active tip and lost, ignore it.
            if self.evaluated_side_branches.get(&block_id) == Some(&self.tip_block_id()) {
                return Ok(SingleBlockResult {
                    root_block_id: block_id,
                    root_newly_persisted: false,
                    outcome: BlockProcessingOutcome::SideBranchPersisted(block_id),
                    gossip_disposition: GossipBlockDisposition::IgnoreKnownDuplicate,
                    missing_parents: Vec::new(),
                });
            }

            // Otherwise, evaluate this stored side branch against the current active chain.
            let outcome = self
                .evaluate_competing_branch(source_peer, *block, suppress_broadcast)
                .await?;
            let gossip_disposition = match outcome {
                BlockProcessingOutcome::ActiveChainAccepted(id)
                | BlockProcessingOutcome::SideBranchPersisted(id) => {
                    GossipBlockDisposition::AcceptNew(id)
                }
                BlockProcessingOutcome::Ignored => GossipBlockDisposition::IgnoreKnownDuplicate,
            };
            return Ok(SingleBlockResult {
                root_block_id: block_id,
                root_newly_persisted: false,
                outcome,
                gossip_disposition,
                missing_parents: Vec::new(),
            });
        }

        // 2. Missing parent check: if parent is unknown and not genesis, treat as orphan
        let parent_exists = parent_id.is_zero()
            || self.storage.has_block(&parent_id).map_err(|e| {
                BlockProcessingError::InternalOrStorage(format!(
                    "storage error checking parent {parent_id}: {e}"
                ))
            })?;
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
            return Ok(SingleBlockResult {
                root_block_id: block_id,
                root_newly_persisted: false,
                outcome: BlockProcessingOutcome::Ignored,
                gossip_disposition: GossipBlockDisposition::IgnoreOrphan,
                missing_parents: Vec::new(),
            });
        }

        // 3. Case A: Block directly extends current active tip
        if parent_id == self.tip_block_id() {
            let mut candidate_state = self.chain_state.clone();
            candidate_state
                .apply_block(&block)
                .map_err(|e| classify_chain_error(&e))?;

            let new_work = candidate_state.cumulative_work();

            // Commit atomically to persistent storage
            self.storage
                .commit_active_block(&block, new_work)
                .map_err(|e| {
                    BlockProcessingError::InternalOrStorage(format!(
                        "atomic block persistence failed: {e}"
                    ))
                })?;

            // Replace in-memory active state ONLY after durable persistence succeeds
            self.chain_state = candidate_state;

            // Invalidate evaluated side-branches cache because the active canonical tip has changed
            self.evaluated_side_branches.clear();

            // Update mempool: remove included transactions and revalidate pending
            self.mempool.on_block_accepted(&block, &self.chain_state);
            self.flush_evicted_seen_txs().await;

            // Notify network service of new tip
            let _ = self
                .network_handle
                .update_tip(height, block_id, new_work)
                .await;

            // Gossip newly accepted block unless Gossipsub itself is forwarding on Accept
            if !suppress_broadcast {
                let _ = self.network_handle.broadcast_block(*block).await;
            }

            tracing::info!(
                "Accepted block #{} ({}) into active chain. Work: {:?}",
                height,
                block_id,
                new_work
            );

            return Ok(SingleBlockResult {
                root_block_id: block_id,
                root_newly_persisted: true,
                outcome: BlockProcessingOutcome::ActiveChainAccepted(block_id),
                gossip_disposition: GossipBlockDisposition::AcceptNew(block_id),
                missing_parents: Vec::new(),
            });
        }

        // 4. Case B: Competing branch / reorganization evaluation
        let outcome = self
            .evaluate_competing_branch(source_peer, *block, suppress_broadcast)
            .await?;
        let (root_newly_persisted, gossip_disposition) = match outcome {
            BlockProcessingOutcome::ActiveChainAccepted(id)
            | BlockProcessingOutcome::SideBranchPersisted(id) => {
                (true, GossipBlockDisposition::AcceptNew(id))
            }
            BlockProcessingOutcome::Ignored => {
                (false, GossipBlockDisposition::IgnoreKnownDuplicate)
            }
        };
        Ok(SingleBlockResult {
            root_block_id: block_id,
            root_newly_persisted,
            outcome,
            gossip_disposition,
            missing_parents: Vec::new(),
        })
    }

    /// Evaluates a competing branch block, checking whether it leads to a reorganization
    /// according to protocol Section 4 fork choice (greater cumulative work, or equal work with lexicographically
    /// smaller block-ID sequence from genesis at the first differing height).
    async fn evaluate_competing_branch(
        &mut self,
        _source_peer: PeerId,
        block: Block,
        suppress_broadcast: bool,
    ) -> Result<BlockProcessingOutcome, BlockProcessingError> {
        let block_id = block.header.block_id();

        // Trace backward from `block` to find the common ancestor with the active chain
        let mut branch_blocks = vec![block.clone()];
        let mut curr_parent = block.header.parent_block_id;

        while !curr_parent.is_zero() {
            // Check if curr_parent is on the active chain
            let meta_opt = self.storage.get_block_metadata(&curr_parent).map_err(|e| {
                BlockProcessingError::InternalOrStorage(format!(
                    "storage error retrieving metadata for {curr_parent}: {e}"
                ))
            })?;
            if let Some(meta) = meta_opt {
                if meta.is_active {
                    // Found common ancestor!
                    break;
                }
                // Fetch next ancestor on branch
                if let Some(ancestor_block) = self.storage.get_block(&curr_parent).map_err(|e| {
                    BlockProcessingError::InternalOrStorage(format!(
                        "storage error retrieving ancestor block {curr_parent}: {e}"
                    ))
                })? {
                    curr_parent = ancestor_block.header.parent_block_id;
                    branch_blocks.push(ancestor_block);
                } else {
                    return Err(BlockProcessingError::InternalOrStorage(format!(
                        "missing intermediate branch block {curr_parent} in storage"
                    )));
                }
            } else {
                return Err(BlockProcessingError::InternalOrStorage(format!(
                    "missing ancestor metadata for {curr_parent} in storage"
                )));
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
                .map_err(|e| BlockProcessingError::InternalOrStorage(e.to_string()))?
                .ok_or_else(|| {
                    BlockProcessingError::InternalOrStorage(
                        "common ancestor metadata not found".into(),
                    )
                })?;
            meta.height
        };

        let genesis = genesis_block(self.config.chain_id);
        let mut branch_state = ChainState::from_genesis(&genesis)
            .map_err(|e| BlockProcessingError::InternalOrStorage(e.to_string()))?;

        for h in 1..=common_ancestor_height {
            let b = self
                .storage
                .get_block_by_height(h)
                .map_err(|e| BlockProcessingError::InternalOrStorage(e.to_string()))?
                .ok_or_else(|| {
                    BlockProcessingError::InternalOrStorage(format!(
                        "missing block at active height {h}"
                    ))
                })?;
            branch_state
                .apply_block(&b)
                .map_err(|e| BlockProcessingError::InternalOrStorage(e.to_string()))?;
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
                return Err(classify_chain_error(&e));
            }
            branch_works.push(branch_state.cumulative_work());
        }

        let branch_work = branch_state.cumulative_work();
        let active_work = self.chain_state.cumulative_work();

        let candidate_wins = candidate_wins_fork_choice(
            branch_work,
            branch_state.blocks(),
            active_work,
            self.chain_state.blocks(),
        );

        if candidate_wins {
            tracing::warn!(
                "Reorganizing active chain! New branch tip: #{} ({}) with work {:?}, defeating active work {:?}",
                branch_state.tip_height().unwrap_or(0),
                branch_state.tip_block_id().unwrap_or(Hash::ZERO),
                branch_work,
                active_work
            );

            let old_tip_height = self.chain_state.tip_height().unwrap_or(0);

            // Commit reorganization atomically to storage
            self.storage
                .commit_reorganization(&branch_blocks, &branch_works, old_tip_height)
                .map_err(|e| {
                    BlockProcessingError::InternalOrStorage(format!(
                        "atomic reorganization persistence failed: {e}"
                    ))
                })?;

            // Replace active chain state in memory
            self.chain_state = branch_state;
            self.evaluated_side_branches.clear();

            // Revalidate mempool after reorganization and invalidate cached seen transactions
            self.mempool.on_reorganization(&self.chain_state);
            let _ = self.network_handle.clear_seen_transactions().await;

            // Update network tip
            let tip_h = self.chain_state.tip_height().unwrap_or(0);
            let tip_id = self.chain_state.tip_block_id().unwrap_or(Hash::ZERO);
            let _ = self
                .network_handle
                .update_tip(tip_h, tip_id, branch_work)
                .await;

            // Broadcast new tip unless Gossipsub itself is forwarding on Accept
            if !suppress_broadcast {
                let _ = self.network_handle.broadcast_block(block.clone()).await;
            }

            Ok(BlockProcessingOutcome::ActiveChainAccepted(block_id))
        } else {
            // Retain current active chain, record branch block
            self.storage
                .store_branch_block(&block, branch_work)
                .map_err(|e| {
                    BlockProcessingError::InternalOrStorage(format!(
                        "failed to store branch block {block_id}: {e}"
                    ))
                })?;
            let active_tip = self.chain_state.tip_block_id().unwrap_or(Hash::ZERO);
            self.evaluated_side_branches.insert(block_id, active_tip);
            tracing::debug!(
                "Stored side-branch block #{} ({}). Branch work {:?}, active work {:?}",
                block.header.height,
                block_id,
                branch_work,
                active_work
            );
            Ok(BlockProcessingOutcome::SideBranchPersisted(block_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::DEVNET;
    use crate::hash::chain_id;
    use crate::header::Header;
    use crate::p2p::NetworkCommand;
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
                sync_operation_id: sync_id_1,
                peer_id: peer_normal,
                result: Ok(SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied: 1,
                    final_height: 1,
                    final_tip_id: Hash::ZERO,
                }),
            }
        });
        let task_id_normal = handle_normal.id();
        runtime
            .sync_task_metadata
            .insert(task_id_normal, (sync_id_1, peer_normal));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_operation_id: sync_id_1,
            peer_id: peer_normal,
            task_id: task_id_normal,
            abort_handle: handle_normal,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertised_claim: None,
            initiated_by_manual: true,
            active_blocks_persisted: 1,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
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
            sync_operation_id: sync_id_2,
            peer_id: peer_panic,
            task_id: task_id_panic,
            abort_handle: handle_panic,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertised_claim: None,
            initiated_by_manual: true,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
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
                sync_operation_id: sync_id_3,
                peer_id: peer_cancel,
                result: Ok(SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied: 0,
                    final_height: 0,
                    final_tip_id: Hash::ZERO,
                }),
            }
        });
        let task_id_cancel = handle_cancel.id();
        runtime
            .sync_task_metadata
            .insert(task_id_cancel, (sync_id_3, peer_cancel));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_operation_id: sync_id_3,
            peer_id: peer_cancel,
            task_id: task_id_cancel,
            abort_handle: handle_cancel,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertised_claim: None,
            initiated_by_manual: true,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
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
                sync_operation_id: 1000,
                peer_id: peer_new,
                result: Ok(SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied: 0,
                    final_height: 0,
                    final_tip_id: Hash::ZERO,
                }),
            }
        });
        let new_task_id = new_handle.id();
        let (tx_new, _rx_new) = oneshot::channel();
        runtime
            .sync_task_metadata
            .insert(new_task_id, (1000, peer_new));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_operation_id: 1000,
            peer_id: peer_new,
            task_id: new_task_id,
            abort_handle: new_handle,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertised_claim: None,
            initiated_by_manual: true,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
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
        assert_eq!(
            runtime.active_sync.as_ref().unwrap().sync_operation_id,
            1000
        );
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

    #[test]
    fn test_classify_mempool_error_outcomes() {
        let h = Hash::new([1u8; 32]);

        // 1. Stateless/cryptographic/structural invalidity -> Reject, mark_seen = false
        for err in [
            MempoolError::Envelope(crate::tx::EnvelopeError::MissingPayload),
            MempoolError::CoinbaseForbidden,
            MempoolError::FeeBelowMinimum { fee: 1, min: 10 },
            MempoolError::InvalidSignature("bad sig".into()),
            MempoolError::DuplicateNullifierInTx(h),
            MempoolError::ValueBalanceMismatch {
                value_balance: 1,
                expected: 0,
            },
            MempoolError::Malformed("bad payload".into()),
        ] {
            let (acc, seen) = classify_mempool_error(&err);
            assert!(
                matches!(acc, MessageAcceptance::Reject),
                "Expected Reject for {err:?}"
            );
            assert!(!seen, "Invalid tx {err:?} must not mark_seen");
        }

        // 2. Mempool duplicate and confirmed on-chain -> Ignore, mark_seen = true (deduplicated)
        let (acc_mem, seen_mem) = classify_mempool_error(&MempoolError::AlreadyInMempool(h));
        assert!(matches!(acc_mem, MessageAcceptance::Ignore));
        assert!(seen_mem);

        let (acc_chain, seen_chain) = classify_mempool_error(&MempoolError::AlreadyOnChain(h));
        assert!(matches!(acc_chain, MessageAcceptance::Ignore));
        assert!(
            seen_chain,
            "AlreadyOnChain must be deduplicated in seen cache"
        );

        // 3. Capacity, internal, and state-dependent conflicts -> Ignore, mark_seen = false (retryable)
        for err in [
            MempoolError::MempoolFull,
            MempoolError::Internal("eviction bookkeeping bug".into()),
            MempoolError::AccountNotFound(h),
            MempoolError::AccountFrozen(h),
            MempoolError::NonceExhausted(h),
            MempoolError::ConflictingNonce {
                account: h,
                expected: 0,
                found: 1,
            },
            MempoolError::InsufficientSpendableBalance {
                account: h,
                spendable: 0,
                required: 10,
            },
            MempoolError::AllowanceExceeded("limit exceeded".into()),
            MempoolError::StaleAnchor(h),
            MempoolError::NullifierAlreadySpent(h),
            MempoolError::ConflictingNullifier {
                nullifier: h,
                existing_tx: h,
            },
            MempoolError::InsufficientShieldedPoolBalance {
                available: 0,
                required: 5,
            },
            MempoolError::ConflictingCancellation {
                transfer_id: h,
                existing_tx: h,
            },
            MempoolError::AccountLockedByPendingGovernance(h),
            MempoolError::PendingGovernanceConflict {
                account: h,
                existing_tx: h,
            },
        ] {
            let (acc, seen) = classify_mempool_error(&err);
            assert!(
                matches!(acc, MessageAcceptance::Ignore),
                "Expected Ignore for {err:?}"
            );
            assert!(
                !seen,
                "AlreadyOnChain/capacity/internal/conflict {err:?} must not poison seen cache"
            );
        }
    }

    #[test]
    fn test_classify_chain_error_outcomes() {
        let h = Hash::new([2u8; 32]);

        // Consensus invalidities -> ConsensusInvalid (maps to Reject)
        for err in [
            ChainError::Invalid(ValidationError::ZeroDifficulty),
            ChainError::Invalid(ValidationError::HashAboveTarget {
                hash: h,
                target: U256::zero(),
            }),
            ChainError::Invalid(ValidationError::TransactionRootMismatch {
                computed: h,
                declared: Hash::ZERO,
            }),
            ChainError::Invalid(ValidationError::Randomx(RandomxError::ZeroDifficulty)),
            ChainError::Invalid(ValidationError::Randomx(RandomxError::HashAboveTarget)),
            ChainError::Encoding(EncodeError::BlockTooLarge {
                actual: 3_000_000,
                limit: 2_000_000,
            }),
            ChainError::State("invalid signature".into()),
        ] {
            assert!(
                matches!(
                    classify_chain_error(&err),
                    BlockProcessingError::ConsensusInvalid(_)
                ),
                "Expected ConsensusInvalid for {err:?}"
            );
        }

        // Local/internal/RandomX-FFI/missing-context failures -> InternalOrStorage (maps to Ignore)
        for err in [
            ChainError::Internal("sender missing during pending release".into()),
            ChainError::Invalid(ValidationError::MissingExpectedDifficulty { height: 10 }),
            ChainError::Invalid(ValidationError::MissingKeyBlock {
                height: 64,
                key_height: 0,
            }),
            ChainError::Invalid(ValidationError::InvalidDifficulty(
                crate::difficulty::DifficultyError::InsufficientHistory,
            )),
            ChainError::Invalid(ValidationError::InvalidDifficulty(
                crate::difficulty::DifficultyError::CumulativeWorkUnderflow,
            )),
            ChainError::Invalid(ValidationError::Randomx(RandomxError::AllocationFailed)),
            ChainError::Invalid(ValidationError::Randomx(RandomxError::InitializationFailed)),
            ChainError::Invalid(ValidationError::Randomx(RandomxError::InvalidInput)),
        ] {
            assert!(
                matches!(
                    classify_chain_error(&err),
                    BlockProcessingError::InternalOrStorage(_)
                ),
                "Expected InternalOrStorage for {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_orphan_unroll_error_does_not_fail_valid_root_block() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = crate::genesis::genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        // Construct valid Block 1
        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();

        // Construct an invalid child Block 2 referencing Block 1 (parent unknown yet),
        // with corrupted orchard commitment root so it will fail consensus when unrolled.
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();
        let mut invalid_child =
            make_test_valid_child_block(&state_after_1, genesis.header.timestamp + 240);
        invalid_child.header.orchard_commitment_root = Hash::new([0xff; 32]);
        let invalid_child_id = invalid_child.block_id();

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        // 1. Arrive invalid orphan child first -> IgnoreOrphan
        let res_child = runtime
            .handle_inbound_block_internal(peer_a, Box::new(invalid_child), true)
            .await
            .unwrap();
        assert_eq!(res_child, GossipBlockDisposition::IgnoreOrphan);
        assert_eq!(runtime.orphan_count(), 1);

        // 2. Arrive valid parent Block 1 -> must succeed with AcceptNew despite child unroll failing!
        let res_parent = runtime
            .handle_inbound_block_internal(peer_b, Box::new(block_1), true)
            .await
            .unwrap();
        assert_eq!(res_parent, GossipBlockDisposition::AcceptNew(block_1_id));
        assert_eq!(runtime.tip_height(), 1);
        assert_eq!(runtime.tip_block_id(), block_1_id);
        assert_eq!(runtime.orphan_count(), 0);
        assert!(!runtime.storage.has_block(&invalid_child_id).unwrap());
    }

    fn make_test_peer_info(
        peer_id: PeerId,
        chain_id: Hash,
        genesis_hash: Hash,
        tip_height: u64,
        tip_block_id: Hash,
        cumulative_work: U256,
    ) -> PeerInfo {
        PeerInfo {
            peer_id,
            address: None,
            handshake: Some(HandshakeMessage {
                protocol_version: crate::p2p::handshake::HANDSHAKE_PROTOCOL_VERSION,
                chain_id,
                genesis_hash,
                tip_height,
                tip_block_id,
                cumulative_work,
                capabilities: 0,
                software_version: "test/1.0".to_string(),
            }),
            connected_at: Instant::now(),
        }
    }

    fn make_test_active_op(
        runtime: &mut NodeRuntime,
        sync_operation_id: u64,
        peer_id: PeerId,
        advertised_claim: Option<AdvertisedTipClaim>,
        initiated_by_manual: bool,
    ) -> oneshot::Receiver<Result<(), String>> {
        let (tx, rx) = oneshot::channel();
        let handle = runtime.sync_tasks.spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            SyncTaskResult {
                sync_operation_id,
                peer_id,
                result: Ok(SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied: 0,
                    final_height: 0,
                    final_tip_id: Hash::ZERO,
                }),
            }
        });
        let task_id = handle.id();
        runtime
            .sync_task_metadata
            .insert(task_id, (sync_operation_id, peer_id));
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_operation_id,
            peer_id,
            task_id,
            abort_handle: handle,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            advertised_claim,
            initiated_by_manual,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
            notifier: Some(tx),
        });
        rx
    }

    #[test]
    fn test_sync_penalty_registry_saturation_anti_churn_and_manual_overflow() {
        let t0 = Instant::now();
        let mut reg = SyncPeerPenaltyRegistry::new(4, 16, 2, PENALTY_STALE_DECAY_TTL);

        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();
        let p4 = PeerId::random();
        let p_untracked = PeerId::random();
        let p_manual = PeerId::random();

        // Fill all 4 primary slots with active cooldowns
        reg.record_failure(p1, SyncFailureClass::TransientOrTimeout, false, t0);
        reg.record_failure(p2, SyncFailureClass::InvalidChainData, false, t0);
        reg.record_failure(p3, SyncFailureClass::ZeroProgress, false, t0);
        reg.record_failure(p4, SyncFailureClass::FalseAdvertisedWorkClaim, false, t0);

        assert_eq!(reg.entries.len(), 4);
        assert!(reg.has_active_capacity_exhaustion(t0));
        // Untracked peer fails closed for automatic sync while saturated with active cooldowns
        assert!(!reg.is_peer_eligible_auto(&p_untracked, t0));
        assert!(reg.is_cooling_down(&p1, t0));

        // Manual failure for untracked p_manual MUST NOT evict any active cooldown from p1..p4
        reg.record_failure(p_manual, SyncFailureClass::InvalidChainData, true, t0);
        assert_eq!(reg.entries.len(), 4);
        assert!(reg.is_cooling_down(&p1, t0));
        assert!(reg.is_cooling_down(&p2, t0));
        assert!(reg.is_cooling_down(&p3, t0));
        assert!(reg.is_cooling_down(&p4, t0));
        assert!(reg.manual_overflow.contains_key(&p_manual));
        assert!(reg.is_cooling_down(&p_manual, t0));

        // After p1's 2s cooldown expires (t0 + 3s), p1 is reclaimable while p_manual's 30s
        // quarantine stays enforced and promotes into primary instead of letting p_manual bypass
        let t1 = t0 + Duration::from_secs(3);
        assert!(reg.is_peer_eligible_auto(&p_untracked, t1));
        assert!(reg.is_cooling_down(&p_manual, t1));
        assert!(!reg.is_peer_eligible_auto(&p_manual, t1));
        assert!(reg.entries.contains_key(&p_manual));

        // Double saturation test: fill primary (4) and manual_overflow (2) with active cooldowns
        let mut dbl = SyncPeerPenaltyRegistry::new(2, 16, 2, PENALTY_STALE_DECAY_TTL);
        let a1 = PeerId::random();
        let a2 = PeerId::random();
        let m1 = PeerId::random();
        let m2 = PeerId::random();
        let m3 = PeerId::random();
        let m4 = PeerId::random();

        dbl.record_failure(a1, SyncFailureClass::InvalidChainData, false, t0);
        dbl.record_failure(a2, SyncFailureClass::InvalidChainData, false, t0);
        dbl.record_failure(m1, SyncFailureClass::TransientOrTimeout, true, t0);
        dbl.record_failure(m2, SyncFailureClass::TransientOrTimeout, true, t0);

        // Escalate m3 up to 600s false-claim quarantine under double saturation (30,60,120,240,480,600)
        for _ in 0..6 {
            dbl.record_failure(m3, SyncFailureClass::FalseAdvertisedWorkClaim, true, t0);
        }
        let deadline_600 = dbl
            .global_manual_overflow_cooldown_until
            .expect("global fallback must engage on double saturation");
        assert_eq!(deadline_600, t0 + Duration::from_secs(600));

        // Shorter 2s transient manual failure MUST NEVER shorten existing 600s global deadline
        dbl.record_failure(m4, SyncFailureClass::TransientOrTimeout, true, t0);
        assert_eq!(
            dbl.global_manual_overflow_cooldown_until,
            Some(deadline_600)
        );
        assert!(!dbl.is_peer_eligible_auto(&PeerId::random(), t0 + Duration::from_secs(301)));
    }

    #[test]
    fn test_sync_repeat_offender_retains_escalation_under_capacity_pressure() {
        let t0 = Instant::now();
        let mut reg = SyncPeerPenaltyRegistry::new(3, 8, 2, PENALTY_STALE_DECAY_TTL);
        let repeater = PeerId::random();
        let p_active_1 = PeerId::random();
        let p_active_2 = PeerId::random();
        let p_churn = PeerId::random();

        // Repeater fails 3 times: 2s -> 4s -> 8s (consecutive_failures == 3)
        reg.record_failure(repeater, SyncFailureClass::TransientOrTimeout, false, t0);
        let t1 = t0 + Duration::from_secs(2);
        reg.record_failure(repeater, SyncFailureClass::TransientOrTimeout, false, t1);
        let t2 = t1 + Duration::from_secs(4);
        reg.record_failure(repeater, SyncFailureClass::TransientOrTimeout, false, t2);
        assert_eq!(reg.consecutive_failures_for(&repeater, t2), 3);

        // Advance just past repeater's 8s cooldown expiry (well within 900s decay TTL)
        let t3 = t2 + Duration::from_secs(9);
        assert!(!reg.is_cooling_down(&repeater, t3));

        // Active peers fill remaining slots, then a new failure forces Phase 2 eviction of expired repeater
        reg.record_failure(p_active_1, SyncFailureClass::InvalidChainData, false, t3);
        reg.record_failure(p_active_2, SyncFailureClass::InvalidChainData, false, t3);
        reg.record_failure(p_churn, SyncFailureClass::InvalidChainData, false, t3);

        // Active peers must NOT be evicted; repeater's streak was archived
        assert!(reg.is_cooling_down(&p_active_1, t3));
        assert!(reg.is_cooling_down(&p_active_2, t3));
        assert!(reg.is_cooling_down(&p_churn, t3));
        assert!(!reg.entries.contains_key(&repeater));
        assert_eq!(reg.consecutive_failures_for(&repeater, t3), 3);

        // Once capacity opens after p_churn expires, repeater fails a 4th time and resumes at k=4 (16s),
        // NOT restarting at base 2s cooldown!
        let t4 = t3 + Duration::from_secs(31);
        reg.record_failure(repeater, SyncFailureClass::TransientOrTimeout, false, t4);
        let entry = reg.entries.get(&repeater).unwrap();
        assert_eq!(entry.consecutive_failures, 4);
        assert_eq!(entry.cooldown_until, Some(t4 + Duration::from_secs(16)));
    }

    #[test]
    fn test_sync_exponential_backoff_escalation_and_cap() {
        let expected_transient = [2u64, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300];
        for (idx, secs) in expected_transient.iter().enumerate() {
            let dur = SyncPeerPenaltyRegistry::backoff_duration(
                SyncFailureClass::TransientOrTimeout,
                (idx + 1) as u32,
            );
            assert_eq!(dur, Duration::from_secs(*secs));
        }

        let expected_quarantine = [30u64, 60, 120, 240, 480, 600, 600];
        for (idx, secs) in expected_quarantine.iter().enumerate() {
            let dur = SyncPeerPenaltyRegistry::backoff_duration(
                SyncFailureClass::FalseAdvertisedWorkClaim,
                (idx + 1) as u32,
            );
            assert_eq!(dur, Duration::from_secs(*secs));
        }

        // High u32::MAX failure count must not panic or overflow
        assert_eq!(
            SyncPeerPenaltyRegistry::backoff_duration(SyncFailureClass::InvalidChainData, u32::MAX),
            Duration::from_secs(600)
        );
    }

    #[tokio::test]
    async fn test_sync_equal_priority_rotation_and_churn_starvation_immunity() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        runtime.sync_rotation = BoundedSyncRotationState::new(4);

        let cid = runtime.config.chain_id;
        let gen_id = genesis_block(cid).block_id();

        // Churn 10 disconnected peers through rotation tracker
        for _ in 0..10 {
            runtime.sync_rotation.mark_attempted(PeerId::random(), None);
        }
        assert!(runtime.sync_rotation.last_attempted.len() <= 4);

        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        let peer_d = PeerId::random();

        let tip_b = Hash::new([11u8; 32]);
        let tip_c = Hash::new([22u8; 32]);
        let tip_d = Hash::new([33u8; 32]);
        let info_b = make_test_peer_info(peer_b, cid, gen_id, 5, tip_b, U256::from_u128(5));
        let info_c = make_test_peer_info(peer_c, cid, gen_id, 5, tip_c, U256::from_u128(5));
        let info_d = make_test_peer_info(peer_d, cid, gen_id, 5, tip_d, U256::from_u128(5));

        let connected: HashSet<PeerId> = [peer_b, peer_c, peer_d].into_iter().collect();
        // Record prior attempts on peer_b and peer_c; keep peer_d clean & absent from rotation map
        runtime
            .sync_rotation
            .mark_attempted(peer_b, Some(&connected));
        runtime
            .sync_rotation
            .mark_attempted(peer_c, Some(&connected));

        let now = Instant::now();
        // Regardless of slice iteration order, clean absent peer_d (attempt_seq = 0) wins immediately
        let perm1 = vec![info_b.clone(), info_c.clone(), info_d.clone()];
        let perm2 = vec![info_c.clone(), info_d.clone(), info_b.clone()];
        assert_eq!(
            runtime.select_sync_candidate_at(&perm1, now).unwrap().0,
            peer_d
        );
        assert_eq!(
            runtime.select_sync_candidate_at(&perm2, now).unwrap().0,
            peer_d
        );

        // Rotate across equal-work peers deterministically: peer_d -> peer_b -> peer_c
        runtime
            .sync_rotation
            .mark_attempted(peer_d, Some(&connected));
        assert_eq!(
            runtime.select_sync_candidate_at(&perm1, now).unwrap().0,
            peer_b
        );
        runtime
            .sync_rotation
            .mark_attempted(peer_b, Some(&connected));
        assert_eq!(
            runtime.select_sync_candidate_at(&perm2, now).unwrap().0,
            peer_c
        );

        // All-peers-cooling-down idle behavior: zero candidates selected
        for p in [peer_b, peer_c, peer_d] {
            runtime
                .sync_penalties
                .record_failure(p, SyncFailureClass::ZeroProgress, false, now);
        }
        assert!(runtime.select_sync_candidate_at(&perm1, now).is_none());
    }

    #[tokio::test]
    async fn test_sync_stale_operation_id_attributable_progress_and_gossipsub_isolation() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();
        let block_2 = make_test_valid_child_block(&state_after_1, genesis.header.timestamp + 240);

        let peer_a = PeerId::random();
        let peer_gossip = PeerId::random();
        let claim = AdvertisedTipClaim {
            tip_block_id: block_1_id,
            tip_height: 1,
            cumulative_work: state_after_1.cumulative_work(),
        };

        // Buffer block_2 first as an orphan from another peer (must NOT increment sync progress later)
        runtime
            .handle_inbound_block_internal(peer_gossip, Box::new(block_2), true)
            .await
            .unwrap();
        assert_eq!(runtime.orphan_count(), 1);

        let _rx1 = make_test_active_op(&mut runtime, 10, peer_a, Some(claim), false);

        // 1. Stale sync_operation_id (even with same PeerId!) must be rejected without touching counters
        let (stale_tx, stale_rx) = oneshot::channel();
        runtime
            .handle_sync_message(RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id: 9,
                peer_id: peer_a,
                blocks: vec![block_1.clone()],
                respond_to: stale_tx,
            })
            .await;
        assert!(matches!(
            stale_rx.await.unwrap().status,
            Err(SyncBatchError::StaleOperation)
        ));
        assert_eq!(
            runtime
                .active_sync
                .as_ref()
                .unwrap()
                .active_blocks_persisted,
            0
        );
        assert_eq!(runtime.tip_height(), 0);

        // 2. Gossipsub independently accepts block_1 -> active_sync counters remain 0 and sync classifies ZeroProgress
        let disp = runtime
            .handle_inbound_block_internal(peer_gossip, Box::new(block_1.clone()), true)
            .await
            .unwrap();
        assert_eq!(disp, GossipBlockDisposition::AcceptNew(block_1_id));
        assert_eq!(runtime.tip_height(), 2); // block_1 + unrolled orphan block_2!
        assert_eq!(
            runtime
                .active_sync
                .as_ref()
                .unwrap()
                .active_blocks_persisted,
            0
        );
        assert!(
            !runtime
                .active_sync
                .as_ref()
                .unwrap()
                .reached_advertised_tip_via_sync
        );

        // Duplicate batch now sent by peer_a -> already known, still 0 attributable progress
        let (dup_tx, dup_rx) = oneshot::channel();
        runtime
            .handle_sync_message(RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id: 10,
                peer_id: peer_a,
                blocks: vec![block_1.clone()],
                respond_to: dup_tx,
            })
            .await;
        assert!(dup_rx.await.unwrap().is_ok());
        assert_eq!(
            runtime
                .active_sync
                .as_ref()
                .unwrap()
                .active_blocks_persisted,
            0
        );

        let active_op = runtime.active_sync.take().unwrap();
        active_op.abort_handle.abort();
        let t0 = Instant::now();
        runtime.finish_active_sync_with_result_at(
            active_op,
            Ok(SyncWorkerSuccess::VerifiedSuccess {
                blocks_applied: 0,
                final_height: 0,
                final_tip_id: Hash::ZERO,
            }),
            t0,
        );
        assert!(runtime.sync_penalties.is_cooling_down(&peer_a, t0));
        assert_eq!(
            runtime
                .sync_penalties
                .entries
                .get(&peer_a)
                .unwrap()
                .last_failure_kind,
            Some(SyncFailureClass::ZeroProgress)
        );
    }

    #[tokio::test]
    async fn test_sync_valid_tip_with_false_work_or_height_claim_and_partial_precedence() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();
        let block_2 = make_test_valid_child_block(&state_after_1, genesis.header.timestamp + 240);
        let block_2_id = block_2.block_id();

        let peer_liar = PeerId::random();
        let bogus_claim = AdvertisedTipClaim {
            tip_block_id: block_1_id,
            tip_height: 1,
            cumulative_work: U256::from_le_bytes([0xff; 32]), // False work claim for genuine valid block_1!
        };

        let _rx = make_test_active_op(&mut runtime, 20, peer_liar, Some(bogus_claim), false);
        let (tx, rx) = oneshot::channel();
        runtime
            .handle_sync_message(RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id: 20,
                peer_id: peer_liar,
                blocks: vec![block_1],
                respond_to: tx,
            })
            .await;
        assert!(rx.await.unwrap().is_ok());

        // Block 1 was validated & persisted, yet mismatch with StoredBlockMetadata triggers FalseAdvertisedWorkClaim
        let active_op = runtime.active_sync.take().unwrap();
        active_op.abort_handle.abort();
        let t0 = Instant::now();
        runtime.finish_active_sync_with_result_at(
            active_op,
            Ok(SyncWorkerSuccess::VerifiedSuccess {
                blocks_applied: 1,
                final_height: 1,
                final_tip_id: block_1_id,
            }),
            t0,
        );
        let entry = runtime.sync_penalties.entries.get(&peer_liar).unwrap();
        assert_eq!(
            entry.last_failure_kind,
            Some(SyncFailureClass::FalseAdvertisedWorkClaim)
        );
        assert_eq!(entry.cooldown_until, Some(t0 + Duration::from_secs(30)));
        assert_eq!(runtime.tip_block_id(), block_1_id);

        // Pre-selection check on stored block_1 with mismatched height quarantines peer immediately
        let peer_height_liar = PeerId::random();
        let bad_height_hs = HandshakeMessage {
            protocol_version: crate::p2p::handshake::HANDSHAKE_PROTOCOL_VERSION,
            chain_id: cid,
            genesis_hash: genesis.block_id(),
            tip_height: 999,
            tip_block_id: block_1_id,
            cumulative_work: state_after_1.cumulative_work(),
            capabilities: 0,
            software_version: "test/1.0".to_string(),
        };
        assert!(runtime.verify_or_quarantine_stored_handshake_claim(
            peer_height_liar,
            &bad_height_hs,
            t0
        ));
        assert!(runtime
            .sync_penalties
            .is_cooling_down(&peer_height_liar, t0));

        // Partial valid progress followed by ConsensusInvalid -> InvalidChainData (30s quarantine, no reset)
        let peer_partial_bad = PeerId::random();
        let mut invalid_b3 = {
            let mut st2 = state_after_1.clone();
            st2.apply_block(&block_2).unwrap();
            let mut b3 = make_test_valid_child_block(&st2, genesis.header.timestamp + 360);
            b3.header.orchard_commitment_root = Hash::new([0xfe; 32]);
            b3
        };
        let claim_3 = AdvertisedTipClaim {
            tip_block_id: invalid_b3.block_id(),
            tip_height: 3,
            cumulative_work: U256::from_u128(3),
        };
        let _rx2 = make_test_active_op(&mut runtime, 21, peer_partial_bad, Some(claim_3), false);
        let (tx2, rx2) = oneshot::channel();
        runtime
            .handle_sync_message(RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id: 21,
                peer_id: peer_partial_bad,
                blocks: vec![block_2, std::mem::replace(&mut invalid_b3, genesis.clone())],
                respond_to: tx2,
            })
            .await;
        assert!(matches!(
            rx2.await.unwrap().status,
            Err(SyncBatchError::ConsensusInvalid(_))
        ));
        let op2 = runtime.active_sync.take().unwrap();
        op2.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op2,
            Err(SyncWorkerError::ConsensusInvalid("bad state root".into())),
            t0,
        );
        let bad_entry = runtime
            .sync_penalties
            .entries
            .get(&peer_partial_bad)
            .unwrap();
        assert_eq!(
            bad_entry.last_failure_kind,
            Some(SyncFailureClass::InvalidChainData)
        );
        assert_eq!(runtime.tip_block_id(), block_2_id);

        // Local InternalOrStorage error must NEVER penalize peer
        let peer_local_err = PeerId::random();
        let _rx3 = make_test_active_op(&mut runtime, 22, peer_local_err, None, false);
        let mut op3 = runtime.active_sync.take().unwrap();
        op3.abort_handle.abort();
        op3.observed_batch_error = Some(SyncBatchError::InternalOrStorage("io err".into()));
        runtime.finish_active_sync_with_result_at(
            op3,
            Err(SyncWorkerError::LocalOrStorage("io err".into())),
            t0,
        );
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_local_err));
    }

    #[tokio::test]
    async fn test_sync_disconnect_attribution_and_handshake_gating() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer_remote_drop = PeerId::random();
        let peer_local_drop = PeerId::random();

        // 1. Ambiguous non-local PeerDisconnected mid-sync -> TransientOrTimeout (never InvalidChainData)
        let rx1 = make_test_active_op(&mut runtime, 30, peer_remote_drop, None, false);
        runtime
            .handle_network_event(NetworkEvent::PeerDisconnected {
                peer_id: peer_remote_drop,
            })
            .await;
        assert!(rx1.await.unwrap().is_err());
        let entry = runtime
            .sync_penalties
            .entries
            .get(&peer_remote_drop)
            .unwrap();
        assert_eq!(
            entry.last_failure_kind,
            Some(SyncFailureClass::TransientOrTimeout)
        );
        let now = Instant::now();
        assert!(runtime
            .sync_penalties
            .is_cooling_down(&peer_remote_drop, now));
        assert!(!runtime
            .sync_penalties
            .is_peer_eligible_auto(&peer_remote_drop, now));

        // 2. Local NodeCommand::Disconnect marker -> zero penalty on PeerDisconnected
        let t_local = Instant::now();
        runtime.record_local_disconnect_marker(peer_local_drop, t_local);
        let rx2 = make_test_active_op(&mut runtime, 31, peer_local_drop, None, false);
        runtime
            .handle_network_event(NetworkEvent::PeerDisconnected {
                peer_id: peer_local_drop,
            })
            .await;
        assert!(rx2.await.unwrap().is_err());
        assert!(!runtime
            .sync_penalties
            .entries
            .contains_key(&peer_local_drop));
    }

    #[tokio::test]
    async fn test_sync_zero_progress_and_verified_progress_recovery_same_peer() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();
        let claim = AdvertisedTipClaim {
            tip_block_id: block_1_id,
            tip_height: 1,
            cumulative_work: state_after_1.cumulative_work(),
        };

        let peer_a = PeerId::random();
        let t0 = Instant::now();

        // Phase A: Same Peer A initially completes Ok(()) with 0 persisted blocks -> ZeroProgress backoff
        let _rx1 = make_test_active_op(&mut runtime, 40, peer_a, Some(claim), false);
        let op1 = runtime.active_sync.take().unwrap();
        op1.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op1,
            Ok(SyncWorkerSuccess::VerifiedSuccess {
                blocks_applied: 0,
                final_height: 0,
                final_tip_id: Hash::ZERO,
            }),
            t0,
        );

        assert!(runtime.sync_penalties.is_cooling_down(&peer_a, t0));
        assert_eq!(
            runtime
                .sync_penalties
                .entries
                .get(&peer_a)
                .unwrap()
                .last_failure_kind,
            Some(SyncFailureClass::ZeroProgress)
        );
        assert!(!runtime.sync_penalties.is_peer_eligible_auto(&peer_a, t0));

        // Phase B: After cooldown expires, same Peer A delivers validated block_1 matching claim -> VerifiedSuccess
        let t1 = t0 + Duration::from_secs(3);
        assert!(runtime.sync_penalties.is_peer_eligible_auto(&peer_a, t1));

        let _rx2 = make_test_active_op(&mut runtime, 41, peer_a, Some(claim), false);
        let (tx2, rx2) = oneshot::channel();
        runtime
            .handle_sync_message(RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id: 41,
                peer_id: peer_a,
                blocks: vec![block_1],
                respond_to: tx2,
            })
            .await;
        assert!(rx2.await.unwrap().is_ok());

        let op2 = runtime.active_sync.take().unwrap();
        op2.abort_handle.abort();
        assert_eq!(op2.active_blocks_persisted, 1);
        assert!(op2.reached_advertised_tip_via_sync);

        runtime.finish_active_sync_with_result_at(
            op2,
            Ok(SyncWorkerSuccess::VerifiedSuccess {
                blocks_applied: 1,
                final_height: 1,
                final_tip_id: block_1_id,
            }),
            t1,
        );
        assert!(!runtime.sync_penalties.is_cooling_down(&peer_a, t1));
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_a));
        assert_eq!(
            runtime.sync_penalties.consecutive_failures_for(&peer_a, t1),
            0
        );
        assert_eq!(runtime.tip_block_id(), block_1_id);
    }

    #[test]
    fn test_sync_repeat_offender_archived_history_preserved_during_non_manual_saturation() {
        let t0 = Instant::now();
        let mut reg = SyncPeerPenaltyRegistry::new(3, 8, 2, PENALTY_STALE_DECAY_TTL);
        let peer_x = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();

        // Give untracked peer_x archived repeat-offender history (k = 3)
        reg.archive_offense_history(
            peer_x,
            OffenseHistory {
                consecutive_failures: 3,
                last_offense_at: t0,
            },
            t0,
        );
        assert_eq!(reg.consecutive_failures_for(&peer_x, t0), 3);

        // Fill all 3 primary slots with active cooldowns
        let t1 = t0 + Duration::from_secs(1);
        reg.record_failure(p1, SyncFailureClass::TransientOrTimeout, false, t1);
        reg.record_failure(p2, SyncFailureClass::InvalidChainData, false, t1);
        reg.record_failure(p3, SyncFailureClass::InvalidChainData, false, t1);
        assert!(reg.has_active_capacity_exhaustion(t1));

        // Trigger a non-manual FalseAdvertisedWorkClaim failure for peer_x while saturated
        reg.record_failure(
            peer_x,
            SyncFailureClass::FalseAdvertisedWorkClaim,
            false,
            t1,
        );

        // Active cooldowns p1..p3 must NOT be evicted, and peer_x's strike history must NOT be lost
        assert_eq!(reg.entries.len(), 3);
        assert!(reg.is_cooling_down(&p1, t1));
        assert!(reg.is_cooling_down(&p2, t1));
        assert!(reg.is_cooling_down(&p3, t1));
        assert!(!reg.entries.contains_key(&peer_x));
        assert_eq!(reg.consecutive_failures_for(&peer_x, t1), 4);
        assert!(reg.repeat_offender_history.contains_key(&peer_x));

        // Release p1's slot via verified success and trigger peer_x's next failure
        let t2 = t1 + Duration::from_secs(1);
        reg.record_verified_success(&p1, t2);
        assert_eq!(reg.entries.len(), 2);

        reg.record_failure(peer_x, SyncFailureClass::TransientOrTimeout, false, t2);
        let entry = reg
            .entries
            .get(&peer_x)
            .expect("peer_x must enter primary registry once slot opens");
        assert_eq!(entry.consecutive_failures, 5);
        assert_eq!(entry.cooldown_until, Some(t2 + Duration::from_secs(32)));
        assert!(!reg.repeat_offender_history.contains_key(&peer_x));
    }

    #[tokio::test]
    async fn test_sync_task_failure_strict_correlation_match_and_mismatches() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer_active = PeerId::random();
        let peer_wrong = PeerId::random();

        // Spawn active operation #77
        let _rx_active = make_test_active_op(&mut runtime, 77, peer_active, None, false);
        let active_task_id = runtime.active_sync.as_ref().unwrap().task_id;

        // Spawn stray panicked task to obtain genuine JoinError values
        let mut stray_set = tokio::task::JoinSet::new();
        for _ in 0..4 {
            stray_set.spawn(async { panic!("mismatched failure") });
        }

        // 1. Missing meta -> ignored, active operation stays intact
        let je_none = stray_set.join_next().await.unwrap().unwrap_err();
        runtime.handle_sync_task_failure(active_task_id, None, je_none);
        assert_eq!(runtime.active_sync.as_ref().unwrap().sync_operation_id, 77);

        // 2. Wrong task_id with matching op_id and peer_id -> ignored!
        let je_wrong_task = stray_set.join_next().await.unwrap().unwrap_err();
        let wrong_task_id = je_wrong_task.id();
        runtime.handle_sync_task_failure(wrong_task_id, Some((77, peer_active)), je_wrong_task);
        assert_eq!(runtime.active_sync.as_ref().unwrap().sync_operation_id, 77);
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_active));

        // 3. Wrong sync_operation_id (even with same task_id and same peer_id!) -> ignored!
        let je_wrong_op = stray_set.join_next().await.unwrap().unwrap_err();
        runtime.handle_sync_task_failure(active_task_id, Some((76, peer_active)), je_wrong_op);
        assert_eq!(runtime.active_sync.as_ref().unwrap().sync_operation_id, 77);
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_active));

        // 4. Wrong peer_id (even with matching task_id and matching op_id!) -> ignored!
        let je_wrong_peer = stray_set.join_next().await.unwrap().unwrap_err();
        runtime.handle_sync_task_failure(active_task_id, Some((77, peer_wrong)), je_wrong_peer);
        assert_eq!(runtime.active_sync.as_ref().unwrap().sync_operation_id, 77);
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_active));
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_wrong));

        // 5. Stale earlier operation involving the SAME peer_id cleanly ignored when newer op is active
        runtime.active_sync.take().unwrap().abort_handle.abort();
        let _rx78 = make_test_active_op(&mut runtime, 78, peer_active, None, false);
        let op78_task_id = runtime.active_sync.as_ref().unwrap().task_id;
        let mut stale_set = tokio::task::JoinSet::new();
        let old_op = stale_set.spawn(async {
            panic!("delayed earlier task for same peer");
        });
        let old_task_id = old_op.id();
        let join_old = stale_set.join_next().await.unwrap().unwrap_err();
        runtime.handle_sync_task_failure(old_task_id, Some((77, peer_active)), join_old);
        assert_eq!(runtime.active_sync.as_ref().unwrap().sync_operation_id, 78);
        assert_eq!(runtime.active_sync.as_ref().unwrap().task_id, op78_task_id);
        assert!(!runtime.sync_penalties.entries.contains_key(&peer_active));

        // 6. Exact match on all three (task_id, sync_operation_id, peer_id) clears active_sync and penalizes
        runtime.active_sync.as_ref().unwrap().abort_handle.abort();
        let mut real_panic_set = tokio::task::JoinSet::new();
        let handle_real_panic = real_panic_set.spawn(async move {
            panic!("exact matching failure");
        });
        let real_panic_id = handle_real_panic.id();
        runtime.active_sync.as_mut().unwrap().task_id = real_panic_id;
        let join_exact = real_panic_set.join_next().await.unwrap().unwrap_err();
        runtime.handle_sync_task_failure(real_panic_id, Some((78, peer_active)), join_exact);
        assert!(runtime.active_sync.is_none());
        assert_eq!(
            runtime
                .sync_penalties
                .entries
                .get(&peer_active)
                .unwrap()
                .last_failure_kind,
            Some(SyncFailureClass::TransientOrTimeout)
        );
    }

    #[tokio::test]
    async fn test_sync_false_stored_claim_handshake_triggers_immediate_failover_to_honest_peer() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let dir_victim = TempDir::new().unwrap();
            let mut runtime = NodeRuntime::init(make_test_config(&dir_victim)).unwrap();
            let cid = runtime.config.chain_id;
            let genesis = genesis_block(cid);
            let mut honest_state = ChainState::from_genesis(&genesis).unwrap();
            let honest_b1 =
                make_test_valid_child_block(&honest_state, genesis.header.timestamp + 120);
            honest_state.apply_block(&honest_b1).unwrap();

            // Spawn Honest Peer B NetworkService with unstored tip height 1, work 1
            let kp_honest = Keypair::generate_ed25519();
            let peer_honest = peer_id_from_keypair(&kp_honest);
            let (svc_honest, handle_honest, _rx_honest) = NetworkService::new(
                kp_honest,
                "devnet",
                cid,
                genesis.block_id(),
                1,
                honest_b1.block_id(),
                honest_state.cumulative_work(),
                "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                50,
                500,
                500,
            )
            .unwrap();
            let task_honest = tokio::spawn(svc_honest.run());

            // Spawn Malicious Peer A NetworkService advertising a false claim for STORED genesis block!
            let kp_bad = Keypair::generate_ed25519();
            let peer_bad = peer_id_from_keypair(&kp_bad);
            let bad_work = U256::from_le_bytes([0xff; 32]);
            let (svc_bad, handle_bad, _rx_bad) = NetworkService::new(
                kp_bad,
                "devnet",
                cid,
                genesis.block_id(),
                999,                // stored genesis actual height is 0!
                genesis.block_id(), // stored locally!
                bad_work,           // stored genesis actual work is 0!
                "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                50,
                500,
                500,
            )
            .unwrap();
            let task_bad = tokio::spawn(svc_bad.run());

            let mut addr_honest = None;
            let mut addr_bad = None;
            for _ in 0..50 {
                if addr_honest.is_none() {
                    addr_honest = handle_honest
                        .get_listen_addrs()
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .next();
                }
                if addr_bad.is_none() {
                    addr_bad = handle_bad
                        .get_listen_addrs()
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .next();
                }
                if addr_honest.is_some() && addr_bad.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let addr_honest = addr_honest.unwrap();
            let addr_bad = addr_bad.unwrap();

            // 1. Connect Honest Peer B and drain its PeerHandshakeCompleted (without calling runtime.run()
            //    so NO periodic 500ms timer exists!).
            runtime.network_handle.dial(addr_honest).await.unwrap();
            loop {
                match runtime.network_event_rx.recv().await.unwrap() {
                    NetworkEvent::PeerHandshakeCompleted { peer_id, .. }
                        if peer_id == peer_honest =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
            assert!(runtime.active_sync.is_none());

            // 2. Connect Malicious Peer A advertising false stored claim -> wait for its PeerHandshakeCompleted
            runtime.network_handle.dial(addr_bad).await.unwrap();
            let ev_bad = loop {
                match runtime.network_event_rx.recv().await.unwrap() {
                    ev @ NetworkEvent::PeerHandshakeCompleted { peer_id, .. }
                        if peer_id == peer_bad =>
                    {
                        break ev;
                    }
                    _ => {}
                }
            };

            // 3. Deliver ONLY Peer A's PeerHandshakeCompleted event directly to handle_network_event.
            //    Peer A must be quarantined AND Honest Peer B must be selected immediately (no timer tick!).
            runtime.handle_network_event(ev_bad).await;

            assert!(runtime
                .sync_penalties
                .is_cooling_down(&peer_bad, Instant::now()));
            assert_eq!(
                runtime
                    .sync_penalties
                    .entries
                    .get(&peer_bad)
                    .unwrap()
                    .last_failure_kind,
                Some(SyncFailureClass::FalseAdvertisedWorkClaim)
            );
            let active = runtime
                .active_sync
                .as_ref()
                .expect("Honest Peer B must be selected immediately upon false claim quarantine");
            assert_eq!(active.peer_id, peer_honest);

            if let Some(op) = runtime.active_sync.take() {
                op.abort_handle.abort();
            }
            if let Some(net) = runtime.network_task.take() {
                net.abort();
            }
            task_honest.abort();
            task_bad.abort();
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn test_sync_batch_orphan_rejected_never_enters_orphan_pool_and_fails_batch() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();
        let block_2 = make_test_valid_child_block(&state_after_1, genesis.header.timestamp + 240);

        let peer_evil = PeerId::random();
        let claim = AdvertisedTipClaim {
            tip_block_id: block_2.block_id(),
            tip_height: 2,
            cumulative_work: U256::from_u128(2),
        };

        // Active sync started with peer_evil
        let rx_notifier = make_test_active_op(&mut runtime, 50, peer_evil, Some(claim), true);

        // Peer delivers block_2 directly WITHOUT block_1 being known in storage!
        // This is a disconnected orphan.
        let (tx, rx) = oneshot::channel();
        runtime
            .handle_sync_message(RuntimeSyncMessage::ApplyBlockBatch {
                sync_operation_id: 50,
                peer_id: peer_evil,
                blocks: vec![block_2.clone()],
                respond_to: tx,
            })
            .await;

        let receipt = rx.await.unwrap();
        assert!(receipt.is_err());
        assert!(matches!(
            receipt.status,
            Err(SyncBatchError::DisconnectedOrphan {
                height: 2,
                index: 0,
                ..
            })
        ));
        assert_eq!(receipt.blocks_processed, 0);

        // SEC-P2P-004 assertion: Disconnected sync block must NEVER enter the orphan pool!
        assert_eq!(runtime.orphan_count(), 0);
        assert_eq!(
            runtime
                .active_sync
                .as_ref()
                .unwrap()
                .active_blocks_persisted,
            0
        );

        // Finishing sync with this failure must penalize peer with InvalidChainData
        // and notify the caller with an error (NEVER Ok(()))
        let op = runtime.active_sync.take().unwrap();
        op.abort_handle.abort();
        let t0 = Instant::now();
        runtime.finish_active_sync_with_result_at(
            op,
            Err(SyncWorkerError::ConsensusInvalid("orphan delivered".into())),
            t0,
        );

        let entry = runtime.sync_penalties.entries.get(&peer_evil).unwrap();
        assert_eq!(
            entry.last_failure_kind,
            Some(SyncFailureClass::InvalidChainData)
        );
        let notify_res = rx_notifier.await.unwrap();
        assert!(
            notify_res.is_err(),
            "Manual sync notifier must never receive Ok(()) on orphan failure"
        );
    }

    #[tokio::test]
    async fn test_sync_notifier_never_receives_success_on_incomplete_or_penalized_outcome() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer_incomplete = PeerId::random();
        let claim = AdvertisedTipClaim {
            tip_block_id: Hash::new([0xaa; 32]),
            tip_height: 10,
            cumulative_work: U256::from_u128(10),
        };

        // 1. Worker returns Incomplete -> notifier receives Err
        let rx1 = make_test_active_op(&mut runtime, 60, peer_incomplete, Some(claim), true);
        let mut op1 = runtime.active_sync.take().unwrap();
        op1.abort_handle.abort();
        op1.active_blocks_persisted = 5; // partial progress
        runtime.finish_active_sync_with_result_at(
            op1,
            Err(SyncWorkerError::Incomplete {
                requested_height: 6,
                expected_target: 10,
                reason: "peer closed stream".into(),
            }),
            Instant::now(),
        );
        let res1 = rx1.await.unwrap();
        assert!(res1.is_err());
        assert!(res1.unwrap_err().contains("IncompleteProgress"));

        // 2. Worker returns ZeroProgress (e.g. timeout with 0 blocks) -> notifier receives Err
        let peer_zero = PeerId::random();
        let rx2 = make_test_active_op(&mut runtime, 61, peer_zero, Some(claim), true);
        let op2 = runtime.active_sync.take().unwrap();
        op2.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op2,
            Err(SyncWorkerError::TransientOrProtocol("timeout".into())),
            Instant::now(),
        );
        let res2 = rx2.await.unwrap();
        assert!(res2.is_err());
        assert!(res2.unwrap_err().contains("TransientOrTimeout"));
    }

    #[tokio::test]
    async fn test_sync_already_synchronized_verified_local_storage_match() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();

        runtime
            .handle_inbound_block_internal(PeerId::random(), Box::new(block_1), true)
            .await
            .unwrap();
        assert_eq!(runtime.tip_height(), 1);

        let peer_honest = PeerId::random();
        let honest_claim = AdvertisedTipClaim {
            tip_block_id: block_1_id,
            tip_height: 1,
            cumulative_work: state_after_1.cumulative_work(),
        };

        // Honest AlreadySynchronized matches verified local storage -> VerifiedSuccess
        let rx1 = make_test_active_op(&mut runtime, 70, peer_honest, Some(honest_claim), true);
        let op1 = runtime.active_sync.take().unwrap();
        op1.abort_handle.abort();
        let t0 = Instant::now();
        runtime.finish_active_sync_with_result_at(
            op1,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 1,
                tip_block_id: block_1_id,
            }),
            t0,
        );
        assert!(!runtime.sync_penalties.is_cooling_down(&peer_honest, t0));
        assert!(rx1.await.unwrap().is_ok());

        // Fraudulent claim (higher work claimed for block_1) -> FalseAdvertisedWorkClaim
        let peer_fraud = PeerId::random();
        let fraud_claim = AdvertisedTipClaim {
            tip_block_id: block_1_id,
            tip_height: 1,
            cumulative_work: U256::from_le_bytes([0xff; 32]),
        };
        let rx2 = make_test_active_op(&mut runtime, 71, peer_fraud, Some(fraud_claim), true);
        let op2 = runtime.active_sync.take().unwrap();
        op2.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op2,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 1,
                tip_block_id: block_1_id,
            }),
            t0,
        );
        assert!(runtime.sync_penalties.is_cooling_down(&peer_fraud, t0));
        assert_eq!(
            runtime
                .sync_penalties
                .entries
                .get(&peer_fraud)
                .unwrap()
                .last_failure_kind,
            Some(SyncFailureClass::FalseAdvertisedWorkClaim)
        );
        assert!(rx2.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_handle_sync_request_get_blocks_breaks_on_missing_block() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();
        let block_2 = make_test_valid_child_block(&state_after_1, genesis.header.timestamp + 240);
        let block_2_id = block_2.block_id();

        // Persist block 1 and block 2
        runtime
            .handle_inbound_block_internal(PeerId::random(), Box::new(block_1), true)
            .await
            .unwrap();
        runtime
            .handle_inbound_block_internal(PeerId::random(), Box::new(block_2), true)
            .await
            .unwrap();

        let unknown_id = Hash::new([0xde; 32]);
        // Request [block_1, unknown, block_2]
        let resp = runtime.handle_sync_request(SyncRequest::GetBlocks {
            block_ids: vec![block_1_id, unknown_id, block_2_id],
        });

        match resp {
            SyncResponse::Blocks(blocks) => {
                // Must stop at unknown_id and return only block_1 (contiguous prefix)!
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks[0].block_id(), block_1_id);
            }
            other => panic!("Expected SyncResponse::Blocks, got {:?}", other),
        }
    }

    fn make_test_sync_header(height: u64, chain_id: Hash, parent_id: Hash) -> Header {
        use crate::orchard_root::empty_commitment_root;
        Header {
            version: 1,
            chain_id,
            height,
            parent_block_id: parent_id,
            transaction_root: Hash::new([0x11; 32]),
            orchard_commitment_root: empty_commitment_root(),
            timestamp: 10_000u64.saturating_add(height.saturating_mul(120)),
            difficulty: 1,
            nonce: 0,
        }
    }

    #[tokio::test]
    async fn test_sync_worker_fast_path_empty_headers_returns_incomplete() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id, genesis_id]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(matches!(res, Err(SyncWorkerError::Incomplete { .. })));
    }

    #[tokio::test]
    async fn test_sync_worker_fast_path_multiple_headers_returns_consensus_invalid() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id, genesis_id]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let h1 = make_test_sync_header(1, cid, genesis_id);
                let h2 = make_test_sync_header(2, cid, h1.block_id());
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1, h2])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("returned 2 headers, expected 1"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_fast_path_wrong_height_returns_consensus_invalid() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id, genesis_id]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let h = make_test_sync_header(99, cid, genesis_id);
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("expected 1"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_fast_path_wrong_chain_id_returns_consensus_invalid() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id, genesis_id]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let bad_cid = Hash::new([0xee; 32]);
                let h = make_test_sync_header(1, bad_cid, genesis_id);
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("invalid chain ID"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_transport_failure_does_not_trigger_fallback() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id, genesis_id]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Err("peer timeout".into()));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::TransientOrProtocol(msg)) if msg.contains("peer timeout"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_binary_search_malformed_response_returns_consensus_invalid() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 2,
            tip_block_id: h2.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id(), h2.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path query at height 2: return fork mismatch (different block ID)
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let mut alt_h2 = make_test_sync_header(2, cid, h1.block_id());
                alt_h2.timestamp += 10;
                let _ = sender.send(Ok(SyncResponse::Headers(vec![alt_h2])));
            }
            // 2. Binary search query at mid: return malformed header (>1 headers or wrong height)
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let bad_mid = make_test_sync_header(99, cid, genesis_id);
                let _ = sender.send(Ok(SyncResponse::Headers(vec![bad_mid])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("binary search header has height 99"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_wrong_first_header_height() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches at height 1
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Batch headers query for height 2: return header at height 3
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let h3 = make_test_sync_header(3, cid, h1.block_id());
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h3])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("expected 2"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_incorrect_chain_id() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches at height 1
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Batch headers query: return header with incorrect chain ID
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let wrong_cid = Hash::new([0x33; 32]);
                let h2 = make_test_sync_header(2, wrong_cid, h1.block_id());
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("invalid chain ID"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_broken_parent_linkage() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches at height 1
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Batch headers query: return header with non-matching parent ID
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let broken_parent = Hash::new([0xbb; 32]);
                let h2 = make_test_sync_header(2, cid, broken_parent);
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("does not match previous block ID"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_response_count_exceeding_request() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches at height 1
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Batch headers query requests 1 header (for height 2), return 2 headers
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let h2 = make_test_sync_header(2, cid, h1.block_id());
                let h3 = make_test_sync_header(3, cid, h2.block_id());
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2, h3])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("exceeding requested count 1"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_reordered_headers() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 3,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches at height 1
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Batch headers query requests 2 headers (#2, #3), return reordered [#3, #2]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let h2 = make_test_sync_header(2, cid, h1.block_id());
                let h3 = make_test_sync_header(3, cid, h2.block_id());
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h3, h2])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("Header at index 0 has height 3, expected 2"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_block_response_exceeding_requested_count() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Headers query: return [h2]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2])));
            }
            // 3. Blocks query: return 2 blocks for 1 requested header
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let b2 = Block {
                    header: h2,
                    transactions: vec![],
                };
                let h3 = make_test_sync_header(3, cid, h2.block_id());
                let b3 = Block {
                    header: h3,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b2, b3])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("exceeding requested count 1"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_reordered_block_bodies() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let h3 = make_test_sync_header(3, cid, h2.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 3,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Headers query: return [h2, h3]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2, h3])));
            }
            // 3. Blocks query: return reordered [b3, b2]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let b2 = Block {
                    header: h2,
                    transactions: vec![],
                };
                let b3 = Block {
                    header: h3,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b3, b2])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("does not match requested block ID"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_unrequested_block_body() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Headers query: return [h2]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2])));
            }
            // 3. Blocks query: return unrequested body (different nonce)
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let mut alt_h2 = h2;
                alt_h2.nonce = 777;
                let b_alt = Block {
                    header: alt_h2,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b_alt])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("does not match requested block ID"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_missing_middle_block() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let h3 = make_test_sync_header(3, cid, h2.block_id());
        let h4 = make_test_sync_header(4, cid, h3.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 4,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Headers query: return [h2, h3, h4]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2, h3, h4])));
            }
            // 3. Blocks query: return [b2, b4] (skipping middle block b3)
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let b2 = Block {
                    header: h2,
                    transactions: vec![],
                };
                let b4 = Block {
                    header: h4,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b2, b4])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("does not match requested block ID"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_rejects_body_with_mismatching_header() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 2,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Headers query: return [h2]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2])));
            }
            // 3. Blocks query: return body with mismatched header (timestamp altered)
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let mut bad_h2 = h2;
                bad_h2.timestamp += 1;
                let b = Block {
                    header: bad_h2,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b])));
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        assert!(
            matches!(res, Err(SyncWorkerError::ConsensusInvalid(msg)) if msg.contains("does not match requested block ID") || msg.contains("does not match requested header"))
        );
    }

    #[tokio::test]
    async fn test_sync_worker_accepts_short_contiguous_prefix_and_advances_cursor() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, mut sync_rx) = mpsc::channel(32);
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h2 = make_test_sync_header(2, cid, h1.block_id());
        let h3 = make_test_sync_header(3, cid, h2.block_id());
        let snapshot = ActiveChainSnapshot {
            tip_height: 1,
            tip_block_id: h1.block_id(),
            block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
        };
        let ctx = SyncWorkerContext {
            sync_operation_id: 1,
            peer_id: PeerId::random(),
            peer_tip_height: 3,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // 1. Fast path matches at height 1
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            // 2. Round 1 GetHeaders for [h2, h3]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h2, h3])));
            }
            // 3. Round 1 GetBlocks: return short prefix containing ONLY [b2]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let b2 = Block {
                    header: h2,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b2])));
            }
            // 4. Round 2 GetHeaders: worker should have advanced cursor to height 3!
            if let Some(NetworkCommand::SendSyncRequest {
                request, sender, ..
            }) = cmd_rx.recv().await
            {
                match request {
                    SyncRequest::GetHeaders {
                        start_height,
                        max_count,
                    } => {
                        assert_eq!(start_height, 3, "Worker must advance cursor to height 3!");
                        assert_eq!(max_count, 1);
                        let _ = sender.send(Ok(SyncResponse::Headers(vec![h3])));
                    }
                    other => panic!("Expected GetHeaders at height 3, got {:?}", other),
                }
            }
            // 5. Round 2 GetBlocks: return [b3]
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let b3 = Block {
                    header: h3,
                    transactions: vec![],
                };
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![b3])));
            }
        });

        // Mock runtime responding to ApplyBlockBatch
        tokio::spawn(async move {
            // Round 1 ApplyBlockBatch for b2
            if let Some(RuntimeSyncMessage::ApplyBlockBatch {
                blocks, respond_to, ..
            }) = sync_rx.recv().await
            {
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks[0].header.height, 2);
                let _ = respond_to.send(SyncBatchReceipt {
                    blocks_processed: 1,
                    active_blocks_persisted: 1,
                    side_blocks_persisted: 0,
                    already_known_duplicates: 0,
                    reached_advertised_tip: false,
                    status: Ok(()),
                });
            }
            // Round 2 ApplyBlockBatch for b3
            if let Some(RuntimeSyncMessage::ApplyBlockBatch {
                blocks, respond_to, ..
            }) = sync_rx.recv().await
            {
                assert_eq!(blocks.len(), 1);
                assert_eq!(blocks[0].header.height, 3);
                let _ = respond_to.send(SyncBatchReceipt {
                    blocks_processed: 1,
                    active_blocks_persisted: 1,
                    side_blocks_persisted: 0,
                    already_known_duplicates: 0,
                    reached_advertised_tip: true,
                    status: Ok(()),
                });
            }
        });

        let res = NodeRuntime::run_sync_worker(ctx).await;
        match res {
            Ok(SyncWorkerSuccess::VerifiedSuccess {
                blocks_applied,
                final_height,
                final_tip_id,
            }) => {
                assert_eq!(blocks_applied, 2);
                assert_eq!(final_height, 3);
                assert_eq!(final_tip_id, h3.block_id());
            }
            other => panic!("Expected VerifiedSuccess, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_sync_budget_exhaustion_never_produces_success() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let peer = PeerId::random();
        let rx = make_test_active_op(&mut runtime, 88, peer, None, true);
        let op = runtime.active_sync.take().unwrap();
        op.abort_handle.abort();
        let t0 = Instant::now();
        runtime.finish_active_sync_with_result_at(
            op,
            Err(SyncWorkerError::BudgetExhausted(
                "round trips exceeded".into(),
            )),
            t0,
        );
        let res = rx.await.unwrap();
        assert!(res.is_err(), "Budget exhaustion must never produce success");
        assert!(runtime.sync_penalties.is_cooling_down(&peer, t0));
    }

    #[tokio::test]
    async fn test_verified_already_synchronized_manual_completion() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let block_1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let block_1_id = block_1.block_id();
        let mut state_after_1 = state.clone();
        state_after_1.apply_block(&block_1).unwrap();

        runtime
            .handle_inbound_block_internal(PeerId::random(), Box::new(block_1), true)
            .await
            .unwrap();
        assert_eq!(runtime.tip_height(), 1);

        // 1. Local node and peer already possess the same verified target chain at height 1.
        let peer_honest = PeerId::random();
        let honest_claim = AdvertisedTipClaim {
            tip_block_id: block_1_id,
            tip_height: 1,
            cumulative_work: state_after_1.cumulative_work(),
        };

        // 2. A manual sync operation is initiated.
        let rx1 = make_test_active_op(&mut runtime, 201, peer_honest, Some(honest_claim), true);
        let op1 = runtime.active_sync.take().unwrap();
        op1.abort_handle.abort();
        let t0 = Instant::now();

        // 3. The worker verifies the target is already satisfied.
        // 4. No new block needs to be persisted.
        // 5. The evaluator returns the appropriate verified no-op outcome.
        runtime.finish_active_sync_with_result_at(
            op1,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 1,
                tip_block_id: block_1_id,
            }),
            t0,
        );

        // 6. The manual notifier receives Ok(()).
        let notifier_res = rx1.await.unwrap();
        assert!(
            notifier_res.is_ok(),
            "Manual notifier must receive Ok(()) for verified AlreadySynchronized"
        );

        // 7. The peer is not penalized for making no contribution.
        assert!(
            !runtime.sync_penalties.is_cooling_down(&peer_honest, t0),
            "Honest peer must not be penalized for AlreadySynchronized"
        );
        assert_eq!(runtime.tip_height(), 1, "No new block must be persisted");
        assert_eq!(runtime.tip_block_id(), block_1_id);

        // Negative check A: Local ahead of peer (local height 1, peer height 0) does not imply same chain.
        // A peer advertising a forked block at height 1 cannot claim AlreadySynchronized.
        let peer_fork = PeerId::random();
        let forked_block_id = Hash::new([0xfe; 32]);
        let forked_claim = AdvertisedTipClaim {
            tip_block_id: forked_block_id,
            tip_height: 1,
            cumulative_work: state_after_1.cumulative_work(),
        };
        let rx_fork = make_test_active_op(&mut runtime, 202, peer_fork, Some(forked_claim), true);
        let op_fork = runtime.active_sync.take().unwrap();
        op_fork.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op_fork,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 1,
                tip_block_id: block_1_id, // Local tip differs from peer claim
            }),
            t0,
        );
        let fork_res = rx_fork.await.unwrap();
        assert!(fork_res.is_err(), "Forked block claim must be rejected");
        assert!(
            runtime.sync_penalties.is_cooling_down(&peer_fork, t0),
            "Peer advertising forked claim must be penalized"
        );

        // Negative check B: Equal heights alone do not establish identical chains.
        // If peer returns an unknown advertised tip, it cannot be accepted without proof.
        let peer_unknown = PeerId::random();
        let unknown_claim = AdvertisedTipClaim {
            tip_block_id: Hash::new([0x99; 32]),
            tip_height: 1,
            cumulative_work: U256::from_u128(999),
        };
        let rx_unknown =
            make_test_active_op(&mut runtime, 203, peer_unknown, Some(unknown_claim), true);
        let op_unknown = runtime.active_sync.take().unwrap();
        op_unknown.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op_unknown,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 1,
                tip_block_id: block_1_id,
            }),
            t0,
        );
        assert!(rx_unknown.await.unwrap().is_err());
        assert!(runtime.sync_penalties.is_cooling_down(&peer_unknown, t0));

        // Negative check C: Incomplete or invalid worker response returns error to notifier.
        let peer_incomplete = PeerId::random();
        let rx_inc = make_test_active_op(&mut runtime, 204, peer_incomplete, None, true);
        let op_inc = runtime.active_sync.take().unwrap();
        op_inc.abort_handle.abort();
        runtime.finish_active_sync_with_result_at(
            op_inc,
            Err(SyncWorkerError::Incomplete {
                requested_height: 1,
                expected_target: 1,
                reason: "empty headers".into(),
            }),
            t0,
        );
        assert!(rx_inc.await.unwrap().is_err());
        assert!(runtime.sync_penalties.is_cooling_down(&peer_incomplete, t0));
    }

    #[tokio::test]
    async fn test_sync_terminal_height_and_arithmetic_invariants() {
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let (sync_tx, mut sync_rx) = mpsc::channel(32);

        // 1. min_h == 0 fast path and ancestor search
        {
            let (cmd_tx, _cmd_rx) = mpsc::channel(32);
            let snapshot = ActiveChainSnapshot {
                tip_height: 0,
                tip_block_id: genesis_id,
                block_ids: Arc::new(vec![genesis_id]),
            };
            let ctx = SyncWorkerContext {
                sync_operation_id: 301,
                peer_id: PeerId::random(),
                peer_tip_height: 0,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
                sync_tx: sync_tx.clone(),
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            // When min_h == 0 and peer_tip_height == 0, worker immediately completes with AlreadySynchronized at height 0
            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
                    .await
                    .expect("Must not hang")
                    .unwrap();
            assert_eq!(
                res,
                SyncWorkerSuccess::AlreadySynchronized {
                    tip_height: 0,
                    tip_block_id: genesis_id,
                }
            );
        }

        // 2. Ancestor search where common ancestor is at height 0 (genesis)
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let h1 = make_test_sync_header(1, cid, genesis_id);
            let mut alt_h1 = make_test_sync_header(1, cid, genesis_id);
            alt_h1.nonce = 1; // Distinct block ID (fork at height 1)
            let snapshot = ActiveChainSnapshot {
                tip_height: 1,
                tip_block_id: h1.block_id(),
                block_ids: Arc::new(vec![genesis_id, h1.block_id()]),
            };
            let ctx = SyncWorkerContext {
                sync_operation_id: 302,
                peer_id: PeerId::random(),
                peer_tip_height: 1,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
                sync_tx: sync_tx.clone(),
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            tokio::spawn(async move {
                // Fast path at height 1 returns alt_h1 (fork!)
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![alt_h1])));
                }
                // Ancestor search on [0, 0] does not iterate; ancestor is 0. Next request is GetHeaders for height 1
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetHeaders { start_height, .. },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(
                        start_height, 1,
                        "Ancestor discovery must find height 0 and fetch starting at 1"
                    );
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![alt_h1])));
                }
                // GetBlocks for alt_h1
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                        header: alt_h1,
                        transactions: vec![],
                    }])));
                }
            });
            tokio::spawn(async move {
                if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                    sync_rx.recv().await
                {
                    let _ = respond_to.send(SyncBatchReceipt {
                        blocks_processed: 1,
                        active_blocks_persisted: 0,
                        side_blocks_persisted: 1,
                        already_known_duplicates: 0,
                        reached_advertised_tip: true,
                        status: Ok(()),
                    });
                }
            });
            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
                    .await
                    .expect("Must not hang")
                    .unwrap();
            match res {
                SyncWorkerSuccess::VerifiedSuccess { final_height, .. } => {
                    assert_eq!(final_height, 1)
                }
                other => panic!("Expected VerifiedSuccess, got {:?}", other),
            }
        }

        // 3. Common ancestor at height 1 (shared 0 and 1, forked at 2)
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let h1 = make_test_sync_header(1, cid, genesis_id);
            let h2 = make_test_sync_header(2, cid, h1.block_id());
            let mut alt_h2 = make_test_sync_header(2, cid, h1.block_id());
            alt_h2.nonce = 1; // Distinct block ID (fork at height 2)
            let snapshot = ActiveChainSnapshot {
                tip_height: 2,
                tip_block_id: h2.block_id(),
                block_ids: Arc::new(vec![genesis_id, h1.block_id(), h2.block_id()]),
            };
            let ctx = SyncWorkerContext {
                sync_operation_id: 303,
                peer_id: PeerId::random(),
                peer_tip_height: 2,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
                sync_tx: sync_tx.clone(),
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            tokio::spawn(async move {
                // 1. Fast path at height 2 returns alt_h2 (fork at 2)
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![alt_h2])));
                }
                // 2. Binary search on [0, 1] tests mid=1: peer returns h1 (matches local!)
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetHeaders { start_height, .. },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(start_height, 1);
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
                }
                // 3. Ancestor found at height 1. Next fetch begins at height 2!
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetHeaders { start_height, .. },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(
                        start_height, 2,
                        "Must start fetching from common_ancestor + 1 = 2"
                    );
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![alt_h2])));
                }
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                        header: alt_h2,
                        transactions: vec![],
                    }])));
                }
            });
            let (sync_tx_3, mut sync_rx_3) = mpsc::channel(32);
            let mut ctx3 = ctx;
            ctx3.sync_tx = sync_tx_3;
            tokio::spawn(async move {
                if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                    sync_rx_3.recv().await
                {
                    let _ = respond_to.send(SyncBatchReceipt {
                        blocks_processed: 1,
                        active_blocks_persisted: 0,
                        side_blocks_persisted: 1,
                        already_known_duplicates: 0,
                        reached_advertised_tip: true,
                        status: Ok(()),
                    });
                }
            });
            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx3))
                    .await
                    .expect("Must not hang")
                    .unwrap();
            match res {
                SyncWorkerSuccess::VerifiedSuccess { final_height, .. } => {
                    assert_eq!(final_height, 2)
                }
                other => panic!("Expected VerifiedSuccess, got {:?}", other),
            }
        }

        // 4 & 5. Common ancestor at u64::MAX - 1 and sync target at u64::MAX (does not loop infinitely)
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let max_h = u64::MAX;
            let prev_h = max_h - 1;
            let h_prev = make_test_sync_header(prev_h, cid, genesis_id);
            let h_max = make_test_sync_header(max_h, cid, h_prev.block_id());
            let snapshot = ActiveChainSnapshot {
                tip_height: prev_h,
                tip_block_id: h_prev.block_id(),
                block_ids: Arc::new(vec![genesis_id, h_prev.block_id()]),
            };
            let (sync_tx_max, mut sync_rx_max) = mpsc::channel(32);
            let ctx = SyncWorkerContext {
                sync_operation_id: 304,
                peer_id: PeerId::random(),
                peer_tip_height: max_h,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
                sync_tx: sync_tx_max,
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            tokio::spawn(async move {
                // 1. Fast path checks min_h = u64::MAX - 1 -> peer matches h_prev
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetHeaders { start_height, .. },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(start_height, prev_h);
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_prev])));
                }
                // 2. Fetch header at u64::MAX
                if let Some(NetworkCommand::SendSyncRequest {
                    request:
                        SyncRequest::GetHeaders {
                            start_height,
                            max_count,
                        },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(start_height, max_h);
                    assert_eq!(max_count, 1);
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_max])));
                }
                // 3. Fetch block at u64::MAX
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                        header: h_max,
                        transactions: vec![],
                    }])));
                }
            });
            tokio::spawn(async move {
                if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                    sync_rx_max.recv().await
                {
                    let _ = respond_to.send(SyncBatchReceipt {
                        blocks_processed: 1,
                        active_blocks_persisted: 1,
                        side_blocks_persisted: 0,
                        already_known_duplicates: 0,
                        reached_advertised_tip: true,
                        status: Ok(()),
                    });
                }
            });
            // Critical: must terminate and report final_height == u64::MAX, not cycle infinitely!
            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
                    .await
                    .expect("Sync at u64::MAX must terminate and not loop infinitely")
                    .unwrap();

            match res {
                SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied,
                    final_height,
                    final_tip_id,
                } => {
                    assert_eq!(blocks_applied, 1);
                    assert_eq!(final_height, u64::MAX);
                    assert_eq!(final_tip_id, h_max.block_id());
                }
                other => panic!("Expected VerifiedSuccess at u64::MAX, got {:?}", other),
            }
        }

        // 6. Empty remaining range when current_h > peer_tip_height (AlreadySynchronized before batch loop)
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let h5 = make_test_sync_header(5, cid, genesis_id);
            let snapshot = ActiveChainSnapshot {
                tip_height: 5,
                tip_block_id: h5.block_id(),
                block_ids: Arc::new(vec![genesis_id]),
            };
            let (sync_tx_empty, _sync_rx_empty) = mpsc::channel(32);
            let ctx = SyncWorkerContext {
                sync_operation_id: 305,
                peer_id: PeerId::random(),
                peer_tip_height: 5,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
                sync_tx: sync_tx_empty,
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            tokio::spawn(async move {
                // Fast path matches at height 5
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h5])));
                }
            });
            // When common_ancestor_height == peer_tip_height == 5, worker returns AlreadySynchronized before loop
            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
                    .await
                    .expect("Must not hang")
                    .unwrap();
            assert!(matches!(res, SyncWorkerSuccess::AlreadySynchronized { .. }));
        }

        // 7. Step advancement at u64::MAX (checked_add does not overflow or produce empty ranges)
        {
            let start = u64::MAX;
            let mut steps = 0;
            for i in 0..1u64 {
                if let Some(h) = start.checked_add(i) {
                    assert_eq!(h, u64::MAX);
                    steps += 1;
                }
            }
            assert_eq!(steps, 1);
        }

        // 8. Zero-count request rejection in SyncRequest
        {
            let mut zero_headers = vec![crate::p2p::protocol::TAG_REQ_GET_HEADERS];
            zero_headers.extend_from_slice(&10u64.to_le_bytes());
            zero_headers.extend_from_slice(&0u32.to_le_bytes());
            assert!(SyncRequest::from_bytes(&zero_headers).is_err());

            let mut zero_blocks = vec![crate::p2p::protocol::TAG_REQ_GET_BLOCKS];
            zero_blocks.extend_from_slice(&0u32.to_le_bytes());
            assert!(SyncRequest::from_bytes(&zero_blocks).is_err());
        }
    }

    #[tokio::test]
    async fn test_sync_terminal_height_short_prefix_and_manual_completion() {
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let max_h = u64::MAX;
        let ancestor_h = max_h - 2;
        let h_ancestor = make_test_sync_header(ancestor_h, cid, genesis_id);
        let h_1 = make_test_sync_header(max_h - 1, cid, h_ancestor.block_id());
        let h_max = make_test_sync_header(max_h, cid, h_1.block_id());

        let snapshot = ActiveChainSnapshot {
            tip_height: ancestor_h,
            tip_block_id: h_ancestor.block_id(),
            block_ids: Arc::new(vec![genesis_id, h_ancestor.block_id()]),
        };

        // Case 1: Peer returns short prefix (only h_1), worker MUST NOT terminate or return success.
        // Worker must issue second request for h_max, receive it, and only then return VerifiedSuccess.
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let (sync_tx, mut sync_rx) = mpsc::channel(32);
            let peer_id = PeerId::random();
            let ctx = SyncWorkerContext {
                sync_operation_id: 401,
                peer_id,
                peer_tip_height: max_h,
                chain_id: cid,
                snapshot: snapshot.clone(),
                network_handle: NetworkHandle::new_mock(cmd_tx, peer_id),
                sync_tx,
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };

            tokio::spawn(async move {
                // 1. Fast path checks min_h = ancestor_h -> matches h_ancestor
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetHeaders { start_height, .. },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(start_height, ancestor_h);
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_ancestor])));
                }
                // 2. Iteration 1: Worker requests headers from ancestor_h + 1 = max_h - 1
                if let Some(NetworkCommand::SendSyncRequest {
                    request:
                        SyncRequest::GetHeaders {
                            start_height,
                            max_count,
                        },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(start_height, max_h - 1);
                    assert_eq!(max_count, 2);
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_1, h_max])));
                }
                // 3. Worker requests blocks for both headers
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetBlocks { block_ids },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(block_ids.len(), 2);
                    // SHORT PREFIX: Peer only returns block 1 (h_1)
                    let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                        header: h_1,
                        transactions: vec![],
                    }])));
                }
                // 4. CRITICAL: Worker MUST NOT stop at max_h - 1! It MUST request header at max_h
                if let Some(NetworkCommand::SendSyncRequest {
                    request:
                        SyncRequest::GetHeaders {
                            start_height,
                            max_count,
                        },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(
                        start_height, max_h,
                        "Worker must query terminal height max_h on short prefix"
                    );
                    assert_eq!(max_count, 1);
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_max])));
                }
                // 5. Worker requests block for h_max
                if let Some(NetworkCommand::SendSyncRequest {
                    request: SyncRequest::GetBlocks { block_ids },
                    sender,
                    ..
                }) = cmd_rx.recv().await
                {
                    assert_eq!(block_ids, vec![h_max.block_id()]);
                    let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                        header: h_max,
                        transactions: vec![],
                    }])));
                }
            });

            tokio::spawn(async move {
                // Batch 1: 1 block applied
                if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                    sync_rx.recv().await
                {
                    let _ = respond_to.send(SyncBatchReceipt {
                        blocks_processed: 1,
                        active_blocks_persisted: 1,
                        side_blocks_persisted: 0,
                        already_known_duplicates: 0,
                        reached_advertised_tip: false,
                        status: Ok(()),
                    });
                }
                // Batch 2: 1 block applied (terminal block)
                if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                    sync_rx.recv().await
                {
                    let _ = respond_to.send(SyncBatchReceipt {
                        blocks_processed: 1,
                        active_blocks_persisted: 1,
                        side_blocks_persisted: 0,
                        already_known_duplicates: 0,
                        reached_advertised_tip: true,
                        status: Ok(()),
                    });
                }
            });

            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
                    .await
                    .expect("Must terminate")
                    .unwrap();

            match res {
                SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied,
                    final_height,
                    final_tip_id,
                } => {
                    assert_eq!(blocks_applied, 2);
                    assert_eq!(final_height, max_h);
                    assert_eq!(final_tip_id, h_max.block_id());
                }
                other => panic!(
                    "Expected VerifiedSuccess at terminal height, got {:?}",
                    other
                ),
            }

            // Verify manual no-advertised-claim completion path with VerifiedSuccess
            let dir = TempDir::new().unwrap();
            let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
            let (manual_tx, manual_rx) = oneshot::channel();
            let dummy_handle = tokio::spawn(async {});
            let task_id = dummy_handle.id();
            let active_op = ActiveSyncOperation {
                sync_operation_id: 401,
                peer_id,
                task_id,
                abort_handle: dummy_handle.abort_handle(),
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                advertised_claim: None, // Manual no-advertised-claim path
                initiated_by_manual: true,
                notifier: Some(manual_tx),
                active_blocks_persisted: 2,
                side_blocks_persisted: 0,
                reached_advertised_tip_via_sync: false,
                observed_batch_error: None,
            };
            runtime.finish_active_sync_with_result_at(active_op, Ok(res), Instant::now());
            assert_eq!(manual_rx.await.unwrap(), Ok(()));
            assert!(!runtime
                .sync_penalties
                .is_cooling_down(&peer_id, Instant::now()));
        }

        // Case 2: Peer returns short prefix and then fails on the terminal block -> must fail with Incomplete, NOT VerifiedSuccess!
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let (sync_tx, mut sync_rx) = mpsc::channel(32);
            let peer_id = PeerId::random();
            let ctx = SyncWorkerContext {
                sync_operation_id: 402,
                peer_id,
                peer_tip_height: max_h,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, peer_id),
                sync_tx,
                advertised_claim: None,
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };

            tokio::spawn(async move {
                // Fast path matches
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_ancestor])));
                }
                // Headers 1
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![h_1, h_max])));
                }
                // Blocks 1: short prefix (only h_1)
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                        header: h_1,
                        transactions: vec![],
                    }])));
                }
                // Headers 2: peer returns EMPTY headers for terminal block
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![])));
                }
            });

            tokio::spawn(async move {
                if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                    sync_rx.recv().await
                {
                    let _ = respond_to.send(SyncBatchReceipt {
                        blocks_processed: 1,
                        active_blocks_persisted: 1,
                        side_blocks_persisted: 0,
                        already_known_duplicates: 0,
                        reached_advertised_tip: false,
                        status: Ok(()),
                    });
                }
            });

            let res =
                tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
                    .await
                    .expect("Must terminate");

            assert!(
                matches!(res, Err(SyncWorkerError::Incomplete { .. })),
                "Must return Incomplete error when peer drops out before terminal height"
            );
        }
    }

    #[tokio::test]
    async fn test_sync_budget_clamping_and_duplicate_exhaustion() {
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let snapshot = ActiveChainSnapshot {
            tip_height: 0,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id]),
        };

        // 1. Clamping when 9,999 blocks have been processed: next request must be clamped to remaining budget = 1
        // and duplicate responses must exhaust budget and return BudgetExhausted, not VerifiedSuccess.
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, mut sync_rx) = mpsc::channel(32);
        let peer_id = PeerId::random();
        let h1 = make_test_sync_header(1, cid, genesis_id);
        let h10000 = make_test_sync_header(10000, cid, h1.block_id());
        let ctx = SyncWorkerContext {
            sync_operation_id: 501,
            peer_id,
            peer_tip_height: 20000,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, peer_id),
            sync_tx,
            advertised_claim: None,
            sync_timeout: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        tokio::spawn(async move {
            // Round 1: start_height = 1, requested count = min(20000, 50, 10000) = 50
            if let Some(NetworkCommand::SendSyncRequest {
                request:
                    SyncRequest::GetHeaders {
                        start_height,
                        max_count,
                    },
                sender,
                ..
            }) = cmd_rx.recv().await
            {
                assert_eq!(start_height, 1);
                assert_eq!(max_count, SYNC_BATCH_SIZE);
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            if let Some(NetworkCommand::SendSyncRequest {
                request: SyncRequest::GetBlocks { .. },
                sender,
                ..
            }) = cmd_rx.recv().await
            {
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                    header: h1,
                    transactions: vec![],
                }])));
            }

            // Round 2: After 9,999 processed, remaining budget is 1.
            // MUST be clamped to 1 even though target is 20000 and batch size is 50!
            if let Some(NetworkCommand::SendSyncRequest {
                request:
                    SyncRequest::GetHeaders {
                        start_height,
                        max_count,
                    },
                sender,
                ..
            }) = cmd_rx.recv().await
            {
                assert_eq!(start_height, 10000);
                assert_eq!(
                    max_count, 1,
                    "Request count must be clamped to remaining budget = 1"
                );
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h10000])));
            }
            if let Some(NetworkCommand::SendSyncRequest {
                request: SyncRequest::GetBlocks { .. },
                sender,
                ..
            }) = cmd_rx.recv().await
            {
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![Block {
                    header: h10000,
                    transactions: vec![],
                }])));
            }
        });

        tokio::spawn(async move {
            // Round 1 ApplyBlockBatch: Peer returned duplicate blocks, receipt reports 9,999 processed
            if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                sync_rx.recv().await
            {
                let _ = respond_to.send(SyncBatchReceipt {
                    blocks_processed: (MAX_SYNC_BLOCKS - 1) as usize,
                    active_blocks_persisted: 0,
                    side_blocks_persisted: 0,
                    already_known_duplicates: (MAX_SYNC_BLOCKS - 1) as usize,
                    reached_advertised_tip: false,
                    status: Ok(()),
                });
            }

            // Round 2 ApplyBlockBatch: 1 block processed (reaching 10,000 MAX_SYNC_BLOCKS)
            if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                sync_rx.recv().await
            {
                let _ = respond_to.send(SyncBatchReceipt {
                    blocks_processed: 1,
                    active_blocks_persisted: 0,
                    side_blocks_persisted: 0,
                    already_known_duplicates: 1,
                    reached_advertised_tip: false,
                    status: Ok(()),
                });
            }
        });

        let res = tokio::time::timeout(Duration::from_secs(5), NodeRuntime::run_sync_worker(ctx))
            .await
            .expect("Must terminate");

        match res {
            Err(SyncWorkerError::BudgetExhausted(reason)) => {
                assert!(
                    reason.contains("Max sync blocks limit"),
                    "Expected Max sync blocks limit exhausted, got {reason}"
                );
            }
            other => panic!("Expected BudgetExhausted, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_verified_already_synchronized_full_lifecycle() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let genesis_id = runtime.chain_state.tip_block_id().unwrap();
        let genesis_work = runtime.cumulative_work();

        // 1. Prove Preconditions for manual synchronization eligibility:
        // (a) Unconnected peer is rejected immediately
        let unconnected_peer = PeerId::random();
        let res_unconnected = runtime
            .validate_peer_for_manual_sync(unconnected_peer)
            .await;
        assert!(
            res_unconnected.is_err(),
            "Unconnected peer must be rejected"
        );
        assert!(
            res_unconnected
                .unwrap_err()
                .contains("peer is not connected"),
            "Error must specify peer is not connected"
        );

        // (b) Connected peer without application handshake is rejected
        let unhandshaked_peer_id = PeerId::random();
        let unhandshaked_peer = PeerInfo {
            peer_id: unhandshaked_peer_id,
            address: None,
            handshake: None,
            connected_at: Instant::now(),
        };
        let res_no_hs = runtime
            .validate_peer_info_for_manual_sync(Some(&unhandshaked_peer), &unhandshaked_peer_id);
        assert!(
            res_no_hs.is_err(),
            "Peer without verified handshake must be rejected"
        );
        assert!(
            res_no_hs
                .unwrap_err()
                .contains("peer application handshake is not verified"),
            "Error must specify handshake is not verified"
        );

        // (c) Connected peer with incompatible chain ID is rejected
        let bad_chain_id = PeerId::random();
        let bad_chain_hs = HandshakeMessage {
            protocol_version: 1,
            chain_id: Hash::new([99u8; 32]),
            genesis_hash: genesis_id,
            tip_height: 0,
            tip_block_id: genesis_id,
            cumulative_work: genesis_work,
            capabilities: 0,
            software_version: "test".into(),
        };
        let bad_chain_peer = PeerInfo {
            peer_id: bad_chain_id,
            address: None,
            handshake: Some(bad_chain_hs),
            connected_at: Instant::now(),
        };
        let res_bad_chain =
            runtime.validate_peer_info_for_manual_sync(Some(&bad_chain_peer), &bad_chain_id);
        assert!(
            res_bad_chain.is_err(),
            "Peer with incompatible chain ID must be rejected"
        );
        assert!(
            res_bad_chain.unwrap_err().contains("incompatible chain ID"),
            "Error must specify incompatible chain ID"
        );

        // (d) Connected peer with incompatible genesis hash is rejected
        let bad_gen_id = PeerId::random();
        let bad_gen_hs = HandshakeMessage {
            protocol_version: 1,
            chain_id: runtime.config.chain_id,
            genesis_hash: Hash::new([88u8; 32]),
            tip_height: 0,
            tip_block_id: Hash::new([88u8; 32]),
            cumulative_work: genesis_work,
            capabilities: 0,
            software_version: "test".into(),
        };
        let bad_gen_peer = PeerInfo {
            peer_id: bad_gen_id,
            address: None,
            handshake: Some(bad_gen_hs),
            connected_at: Instant::now(),
        };
        let res_bad_gen =
            runtime.validate_peer_info_for_manual_sync(Some(&bad_gen_peer), &bad_gen_id);
        assert!(
            res_bad_gen.is_err(),
            "Peer with incompatible genesis hash must be rejected"
        );
        assert!(
            res_bad_gen
                .unwrap_err()
                .contains("incompatible genesis hash"),
            "Error must specify incompatible genesis hash"
        );

        // (e) Connected peer with verified handshake matching local genesis and chain ID is accepted
        let verified_peer_id = PeerId::random();
        let valid_hs = HandshakeMessage {
            protocol_version: 1,
            chain_id: runtime.config.chain_id,
            genesis_hash: genesis_id,
            tip_height: 0,
            tip_block_id: genesis_id,
            cumulative_work: genesis_work,
            capabilities: 0,
            software_version: "test".into(),
        };
        let verified_peer = PeerInfo {
            peer_id: verified_peer_id,
            address: None,
            handshake: Some(valid_hs),
            connected_at: Instant::now(),
        };
        let claim = runtime
            .validate_peer_info_for_manual_sync(Some(&verified_peer), &verified_peer_id)
            .expect("Verified peer must pass manual sync validation");
        assert!(
            claim.is_some(),
            "Verified peer must produce an AdvertisedTipClaim"
        );

        // 2. Full synchronization lifecycle with verified peer at height 0:
        let (notifier_tx, notifier_rx) = oneshot::channel();
        runtime.start_sync_internal(verified_peer_id, 0, claim, true, Some(notifier_tx));
        assert!(runtime.active_sync.is_some());

        // Wait for worker task to complete
        let task_result = runtime
            .sync_tasks
            .join_next()
            .await
            .expect("Worker must finish")
            .expect("Task must not panic");

        assert_eq!(
            task_result.result,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 0,
                tip_block_id: genesis_id,
            })
        );

        // Process completion through runtime handler
        runtime.handle_sync_task_success(
            runtime.active_sync.as_ref().unwrap().task_id,
            None,
            task_result,
        );

        // Assertions:
        // 1. Manual notifier receives Ok(())
        let notifier_res = notifier_rx.await.expect("Notifier must receive result");
        assert_eq!(notifier_res, Ok(()));

        // 2. Exactly 0 new blocks persisted in storage (tip height still 0)
        assert_eq!(runtime.storage.get_tip().unwrap().0, 0);
        assert_eq!(runtime.tip_height(), 0);

        // 3. Peer is not penalized
        assert!(!runtime
            .sync_penalties
            .is_cooling_down(&verified_peer_id, Instant::now()));
        assert!(runtime.active_sync.is_none());
    }

    #[tokio::test]
    async fn test_already_synchronized_side_branch_claim_rejected_and_penalized() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        // 1. Create canonical chain G -> A1 -> A2
        let block_a1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let mut state_a1 = state.clone();
        state_a1.apply_block(&block_a1).unwrap();
        let block_a2 = make_test_valid_child_block(&state_a1, genesis.header.timestamp + 240);

        // Submit A1 and A2 to runtime (becomes active canonical chain)
        runtime.submit_block(block_a1.clone()).await.unwrap();
        runtime.submit_block(block_a2.clone()).await.unwrap();
        assert_eq!(runtime.tip_height(), 2);
        assert_eq!(runtime.tip_block_id(), block_a2.block_id());
        assert_eq!(
            runtime
                .storage
                .get_header_by_height(1)
                .unwrap()
                .unwrap()
                .block_id(),
            block_a1.block_id()
        );

        // 2. Create valid side-branch block B1 at height 1 on genesis G
        let mut block_b1 = make_test_valid_child_block(&state, genesis.header.timestamp + 130);
        block_b1.header.nonce = 999; // Ensure different block ID from A1
        let mut state_b1 = state.clone();
        state_b1.apply_block(&block_b1).unwrap();
        let b1_work = state_b1.cumulative_work();

        // Store B1 as a side branch block (metadata stored, but NOT on canonical chain)
        runtime
            .storage
            .store_branch_block(&block_b1, b1_work)
            .unwrap();
        assert!(runtime
            .storage
            .get_block_metadata(&block_b1.block_id())
            .unwrap()
            .is_some());
        // Verify canonical chain at height 1 is still A1, NOT B1
        assert_eq!(
            runtime
                .storage
                .get_header_by_height(1)
                .unwrap()
                .unwrap()
                .block_id(),
            block_a1.block_id()
        );

        let peer_id = PeerId::random();
        let claim_b1 = AdvertisedTipClaim {
            tip_block_id: block_b1.block_id(),
            tip_height: 1,
            cumulative_work: b1_work,
        };

        // 3. Test sync worker detection of inconsistent response:
        // Peer advertised B1 at height 1, but when asked for header at height 1 it sends A1!
        {
            let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
            let (sync_tx, _sync_rx) = mpsc::channel(32);
            let (tip_h, tip_id, ids) = runtime.storage.capture_canonical_chain_snapshot(2).unwrap();
            let snapshot = ActiveChainSnapshot {
                tip_height: tip_h,
                tip_block_id: tip_id,
                block_ids: Arc::new(ids),
            };
            let ctx = SyncWorkerContext {
                sync_operation_id: 601,
                peer_id,
                peer_tip_height: 1,
                chain_id: cid,
                snapshot,
                network_handle: NetworkHandle::new_mock(cmd_tx, peer_id),
                sync_tx,
                advertised_claim: Some(claim_b1),
                sync_timeout: None,
                cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };

            tokio::spawn(async move {
                if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                    // Peer sends A1 header instead of advertised B1 header
                    let _ = sender.send(Ok(SyncResponse::Headers(vec![block_a1.header])));
                }
            });

            let res = NodeRuntime::run_sync_worker(ctx).await;
            assert!(
                matches!(res, Err(SyncWorkerError::FalseAdvertisedClaim(_))),
                "Worker must reject inconsistent header response with FalseAdvertisedClaim, got {res:?}"
            );
        }

        // 4. Test evaluator rejection of side-branch claim:
        // Even if worker produced AlreadySynchronized { tip_height: 2, tip_block_id: A2 },
        // evaluator must verify that claim_b1 is NOT on canonical chain and return Penalized.
        {
            let rx_notifier = make_test_active_op(&mut runtime, 602, peer_id, Some(claim_b1), true);
            let worker_res = Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 2,
                tip_block_id: block_a2.block_id(),
            });

            let now = Instant::now();
            let op = runtime.active_sync.take().unwrap();
            runtime.finish_active_sync_with_result_at(op, worker_res, now);

            // Manual notifier MUST receive Err (cannot receive Ok(()))
            let notifier_res = rx_notifier.await.expect("Notifier must receive result");
            assert!(
                notifier_res.is_err(),
                "Notifier must receive error on side-branch claim"
            );
            assert_eq!(
                notifier_res.unwrap_err(),
                "sync failed: FalseAdvertisedWorkClaim"
            );

            // Peer must be penalized
            assert!(runtime.sync_penalties.is_cooling_down(&peer_id, now));
        }

        // 5. Test legitimate canonical claim:
        // When peer claims A1 (which is genuinely on the canonical chain at height 1),
        // AlreadySynchronized is accepted as VerifiedSuccess and notifier receives Ok(()).
        {
            let peer_honest = PeerId::random();
            let a1_work = state_a1.cumulative_work();
            let claim_a1 = AdvertisedTipClaim {
                tip_block_id: block_a1.block_id(),
                tip_height: 1,
                cumulative_work: a1_work,
            };

            let rx_notifier =
                make_test_active_op(&mut runtime, 603, peer_honest, Some(claim_a1), true);
            let worker_res = Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 2,
                tip_block_id: block_a2.block_id(),
            });

            let now = Instant::now();
            let op = runtime.active_sync.take().unwrap();
            runtime.finish_active_sync_with_result_at(op, worker_res, now);

            // Manual notifier MUST receive Ok(())
            let notifier_res = rx_notifier.await.expect("Notifier must receive result");
            assert_eq!(
                notifier_res,
                Ok(()),
                "Notifier must receive Ok(()) for legitimate canonical claim"
            );

            // Peer must NOT be penalized
            assert!(!runtime.sync_penalties.is_cooling_down(&peer_honest, now));
        }
    }

    #[tokio::test]
    async fn test_sync_worker_absolute_deadline_enforcement_on_stalled_request() {
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, _sync_rx) = mpsc::channel(32);

        let snapshot = ActiveChainSnapshot {
            tip_height: 0,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id]),
        };

        let short_deadline = Duration::from_millis(50);
        let ctx = SyncWorkerContext {
            sync_operation_id: 701,
            peer_id: PeerId::random(),
            peer_tip_height: 5,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: Some(short_deadline),
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Network mock receives GetHeaders request but deliberately never responds (simulating stalled request)
        tokio::spawn(async move {
            let _held_request = cmd_rx.recv().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let start = Instant::now();
        let res = NodeRuntime::run_sync_worker(ctx).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(res, Err(SyncWorkerError::BudgetExhausted(_))),
            "Worker must return BudgetExhausted on stalled request, got {res:?}"
        );
        let err_msg = match res {
            Err(SyncWorkerError::BudgetExhausted(msg)) => msg,
            _ => unreachable!(),
        };
        assert!(
            err_msg.contains("Sync timeout"),
            "Error message must specify sync timeout exceeded, got: {err_msg}"
        );
        assert!(
            elapsed >= Duration::from_millis(40) && elapsed < Duration::from_millis(500),
            "Worker must terminate promptly at injected deadline ({:?}), elapsed: {:?}",
            short_deadline,
            elapsed
        );
    }

    #[tokio::test]
    async fn test_sync_worker_absolute_deadline_enforcement_on_stalled_batch_ack() {
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, mut sync_rx) = mpsc::channel(32);

        let snapshot = ActiveChainSnapshot {
            tip_height: 0,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id]),
        };

        let h1 = make_test_sync_header(1, cid, genesis_id);
        let block1 = Block {
            header: h1,
            transactions: vec![],
        };

        let short_deadline = Duration::from_millis(50);
        let ctx = SyncWorkerContext {
            sync_operation_id: 702,
            peer_id: PeerId::random(),
            peer_tip_height: 1,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, PeerId::random()),
            sync_tx,
            advertised_claim: None,
            sync_timeout: Some(short_deadline),
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Network returns headers and blocks
        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![h1])));
            }
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![block1])));
            }
        });

        // Runtime receives ApplyBlockBatch message but deliberately never responds on respond_to
        tokio::spawn(async move {
            if let Some(RuntimeSyncMessage::ApplyBlockBatch { respond_to, .. }) =
                sync_rx.recv().await
            {
                let _held = respond_to;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        let start = Instant::now();
        let res = NodeRuntime::run_sync_worker(ctx).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(res, Err(SyncWorkerError::BudgetExhausted(_))),
            "Worker must return BudgetExhausted on stalled batch ack, got {res:?}"
        );
        let err_msg = match res {
            Err(SyncWorkerError::BudgetExhausted(msg)) => msg,
            _ => unreachable!(),
        };
        assert!(
            err_msg.contains("Sync timeout"),
            "Error message must specify sync timeout exceeded, got: {err_msg}"
        );
        assert!(
            elapsed >= Duration::from_millis(40) && elapsed < Duration::from_millis(500),
            "Worker must terminate promptly at injected deadline ({:?}), elapsed: {:?}",
            short_deadline,
            elapsed
        );
    }

    #[tokio::test]
    async fn test_manual_sync_reconciles_caller_height_mismatch_with_authenticated_handshake() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let genesis_id = runtime.chain_state.tip_block_id().unwrap();
        let genesis_work = runtime.cumulative_work();

        // 1. Peer has verified handshake advertising height 0 and genesis block ID G
        let verified_peer_id = PeerId::random();
        let valid_hs = HandshakeMessage {
            protocol_version: 1,
            chain_id: runtime.config.chain_id,
            genesis_hash: genesis_id,
            tip_height: 0,
            tip_block_id: genesis_id,
            cumulative_work: genesis_work,
            capabilities: 0,
            software_version: "test".into(),
        };
        let verified_peer = PeerInfo {
            peer_id: verified_peer_id,
            address: None,
            handshake: Some(valid_hs),
            connected_at: Instant::now(),
        };

        let claim = runtime
            .validate_peer_info_for_manual_sync(Some(&verified_peer), &verified_peer_id)
            .expect("Verified peer must pass manual sync validation");

        // 2. Caller erroneously supplies a stale/mismatched height (e.g. height 999)
        let caller_supplied_height = 999u64;
        let (notifier_tx, notifier_rx) = oneshot::channel();

        // start_sync_internal must reconcile the caller-supplied height to claim.tip_height (0)
        runtime.start_sync_internal(
            verified_peer_id,
            caller_supplied_height,
            claim,
            true,
            Some(notifier_tx),
        );

        // Verify active_sync record has advertised_claim with tip_height 0, not 999
        let active = runtime
            .active_sync
            .as_ref()
            .expect("Active sync must be started");
        assert_eq!(
            active.advertised_claim.as_ref().map(|c| c.tip_height),
            Some(0),
            "Active sync must reconcile target height to authenticated handshake (0) instead of caller height (999)"
        );

        // Wait for worker task to complete
        let task_result = runtime
            .sync_tasks
            .join_next()
            .await
            .expect("Worker must finish")
            .expect("Task must not panic");

        assert_eq!(
            task_result.result,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 0,
                tip_block_id: genesis_id,
            }),
            "Worker must target authenticated height 0 and return AlreadySynchronized"
        );

        // Process completion through runtime handler
        runtime.handle_sync_task_success(
            runtime.active_sync.as_ref().unwrap().task_id,
            None,
            task_result,
        );

        // 3. Verify caller receives Ok(()) and peer receives no penalty
        let notifier_res = notifier_rx.await.expect("Notifier must receive result");
        assert_eq!(
            notifier_res,
            Ok(()),
            "Manual caller must receive Ok(()) despite supplying mismatched height"
        );
        assert!(
            !runtime
                .sync_penalties
                .is_cooling_down(&verified_peer_id, Instant::now()),
            "Honest peer must not be penalized for caller's mismatched height"
        );
    }

    #[tokio::test]
    async fn test_manual_sync_genesis_only_peer_valid() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let genesis_id = genesis.block_id();
        let state = ChainState::from_genesis(&genesis).unwrap();

        // 1. Build canonical chain G -> A1 -> A2
        let block_a1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let mut state_a1 = state.clone();
        state_a1.apply_block(&block_a1).unwrap();
        let block_a2 = make_test_valid_child_block(&state_a1, genesis.header.timestamp + 240);

        runtime.submit_block(block_a1).await.unwrap();
        runtime.submit_block(block_a2).await.unwrap();
        assert_eq!(runtime.tip_height(), 2);

        // 2. Peer advertises height 0 and correct genesis block ID G
        let peer_id = PeerId::random();
        let hs = HandshakeMessage {
            protocol_version: 1,
            chain_id: cid,
            genesis_hash: genesis_id,
            tip_height: 0,
            tip_block_id: genesis_id,
            cumulative_work: state.cumulative_work(),
            capabilities: 0,
            software_version: "test".into(),
        };
        let peer_info = PeerInfo {
            peer_id,
            address: None,
            handshake: Some(hs),
            connected_at: Instant::now(),
        };

        let claim = runtime
            .validate_peer_info_for_manual_sync(Some(&peer_info), &peer_id)
            .expect("Peer must pass validation");

        // 3. Initiate manual sync with peer at height 0
        let (notifier_tx, notifier_rx) = oneshot::channel();
        runtime.start_sync_internal(peer_id, 0, claim, true, Some(notifier_tx));

        // Worker should run and complete
        let task_result = runtime
            .sync_tasks
            .join_next()
            .await
            .expect("Worker task must complete")
            .expect("Task must not panic");

        assert_eq!(
            task_result.result,
            Ok(SyncWorkerSuccess::AlreadySynchronized {
                tip_height: 2,
                tip_block_id: runtime.tip_block_id(),
            }),
            "Worker must return AlreadySynchronized for genesis-only peer on canonical chain"
        );

        let task_id = runtime.active_sync.as_ref().unwrap().task_id;
        runtime.handle_sync_task_success(task_id, None, task_result);

        // Caller receives Ok(())
        let notifier_res = notifier_rx.await.expect("Notifier must receive result");
        assert_eq!(
            notifier_res,
            Ok(()),
            "Caller must receive Ok(()) for valid genesis-only peer"
        );

        // Zero peer penalty
        assert!(
            !runtime
                .sync_penalties
                .is_cooling_down(&peer_id, Instant::now()),
            "Peer must not be penalized"
        );
        assert_eq!(runtime.tip_height(), 2, "Tip height must remain 2");
    }

    #[tokio::test]
    async fn test_manual_sync_genesis_only_peer_invalid() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis = genesis_block(cid);
        let genesis_id = genesis.block_id();
        let state = ChainState::from_genesis(&genesis).unwrap();

        // 1. Build canonical chain G -> A1 -> A2
        let block_a1 = make_test_valid_child_block(&state, genesis.header.timestamp + 120);
        let mut state_a1 = state.clone();
        state_a1.apply_block(&block_a1).unwrap();
        let block_a2 = make_test_valid_child_block(&state_a1, genesis.header.timestamp + 240);

        runtime.submit_block(block_a1).await.unwrap();
        runtime.submit_block(block_a2).await.unwrap();
        assert_eq!(runtime.tip_height(), 2);

        // 2. Peer advertises height 0 but tip block ID different from G
        let peer_id = PeerId::random();
        let fake_genesis_id = Hash::new([77u8; 32]);
        let hs = HandshakeMessage {
            protocol_version: 1,
            chain_id: cid,
            genesis_hash: genesis_id, // Handshake message genesis_hash matches
            tip_height: 0,
            tip_block_id: fake_genesis_id, // but tip_block_id at height 0 is fake!
            cumulative_work: state.cumulative_work(),
            capabilities: 0,
            software_version: "test".into(),
        };
        let peer_info = PeerInfo {
            peer_id,
            address: None,
            handshake: Some(hs),
            connected_at: Instant::now(),
        };

        let claim = runtime
            .validate_peer_info_for_manual_sync(Some(&peer_info), &peer_id)
            .expect("Peer info with matching genesis_hash passes initial info validation");

        // 3. Initiate manual sync with invalid genesis peer
        let (notifier_tx, notifier_rx) = oneshot::channel();
        runtime.start_sync_internal(peer_id, 0, claim, true, Some(notifier_tx));

        // Worker runs and rejects the claim
        let task_result = runtime
            .sync_tasks
            .join_next()
            .await
            .expect("Worker task must complete")
            .expect("Task must not panic");

        assert!(
            matches!(
                task_result.result,
                Err(SyncWorkerError::FalseAdvertisedClaim(_))
            ),
            "Worker must return FalseAdvertisedClaim, got {:?}",
            task_result.result
        );

        let task_id = runtime.active_sync.as_ref().unwrap().task_id;
        runtime.handle_sync_task_success(task_id, None, task_result);

        // Caller receives Err
        let notifier_res = notifier_rx.await.expect("Notifier must receive result");
        assert!(
            notifier_res.is_err(),
            "Caller must receive error for invalid genesis tip claim"
        );
        let err_msg = notifier_res.unwrap_err();
        assert!(
            err_msg.contains("FalseAdvertisedWorkClaim")
                || err_msg.contains("FalseAdvertisedClaim"),
            "Error must indicate false advertised claim, got: {err_msg}"
        );

        // Peer is penalized
        assert!(
            runtime
                .sync_penalties
                .is_cooling_down(&peer_id, Instant::now()),
            "Peer must be penalized for false advertised genesis tip"
        );
    }

    #[tokio::test]
    async fn test_late_batch_ack_at_deadline_does_not_persist_or_penalize_peer() {
        let dir = TempDir::new().unwrap();
        let mut runtime = NodeRuntime::init(make_test_config(&dir)).unwrap();
        let cid = chain_id(DEVNET);
        let genesis_id = genesis_block(cid).block_id();
        let peer_id = PeerId::random();

        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (sync_tx, mut sync_rx) = mpsc::channel(32);

        let snapshot = ActiveChainSnapshot {
            tip_height: 0,
            tip_block_id: genesis_id,
            block_ids: Arc::new(vec![genesis_id]),
        };

        let state = ChainState::from_genesis(&genesis_block(cid)).unwrap();
        let block_a1 =
            make_test_valid_child_block(&state, genesis_block(cid).header.timestamp + 120);

        let short_deadline = Duration::from_millis(50);
        let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let ctx = SyncWorkerContext {
            sync_operation_id: 801,
            peer_id,
            peer_tip_height: 1,
            chain_id: cid,
            snapshot,
            network_handle: NetworkHandle::new_mock(cmd_tx, peer_id),
            sync_tx,
            advertised_claim: None,
            sync_timeout: Some(short_deadline),
            cancel_flag: cancel_flag.clone(),
        };

        // Network returns headers and block
        let block_a1_clone = block_a1.clone();
        tokio::spawn(async move {
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Headers(vec![block_a1_clone.header])));
            }
            if let Some(NetworkCommand::SendSyncRequest { sender, .. }) = cmd_rx.recv().await {
                let _ = sender.send(Ok(SyncResponse::Blocks(vec![block_a1_clone])));
            }
        });

        // Intercept ApplyBlockBatch message: hold it until AFTER the worker deadline expires
        let held_msg =
            tokio::spawn(
                async move { sync_rx.recv().await.expect("Must receive ApplyBlockBatch") },
            );

        // Run worker: it sends batch and waits for ack on ack_rx, which stalls and exceeds the 50ms deadline
        let worker_res = NodeRuntime::run_sync_worker(ctx).await;

        // Worker must return BudgetExhausted
        assert!(
            matches!(worker_res, Err(SyncWorkerError::BudgetExhausted(_))),
            "Worker must return BudgetExhausted on deadline expiration, got {:?}",
            worker_res
        );
        let err_msg = match &worker_res {
            Err(SyncWorkerError::BudgetExhausted(msg)) => msg.clone(),
            _ => unreachable!(),
        };
        assert!(
            err_msg.contains("block batch") || err_msg.contains("Sync timeout"),
            "Error must mention batch or timeout, got: {err_msg}"
        );

        // Verify cancel_flag was set to true by the worker upon timeout
        assert!(
            cancel_flag.load(std::sync::atomic::Ordering::SeqCst),
            "Worker must set cancel_flag = true on deadline expiry awaiting ack"
        );

        // Now simulate runtime processing the late batch:
        // Set up active sync operation in runtime
        let (notifier_tx, notifier_rx) = oneshot::channel();
        let dummy_handle = runtime.sync_tasks.spawn(async move {
            SyncTaskResult {
                sync_operation_id: 801,
                peer_id,
                result: Ok(SyncWorkerSuccess::VerifiedSuccess {
                    blocks_applied: 0,
                    final_height: 0,
                    final_tip_id: Hash::ZERO,
                }),
            }
        });
        runtime.active_sync = Some(ActiveSyncOperation {
            sync_operation_id: 801,
            peer_id,
            task_id: dummy_handle.id(),
            abort_handle: dummy_handle,
            cancel_flag: cancel_flag.clone(),
            advertised_claim: None,
            initiated_by_manual: true,
            active_blocks_persisted: 0,
            side_blocks_persisted: 0,
            reached_advertised_tip_via_sync: false,
            observed_batch_error: None,
            notifier: Some(notifier_tx),
        });

        // Runtime receives and processes the late batch message
        let batch_msg = held_msg.await.expect("held msg task panicked");
        runtime.handle_sync_message(batch_msg).await;

        // Verify runtime did NOT persist blocks for the cancelled operation
        assert_eq!(
            runtime.storage.get_tip().unwrap().0,
            0,
            "Runtime must NOT persist blocks after worker returned BudgetExhausted and cancelled"
        );

        // Evaluate outcome: must evaluate to LocalFaultNoPeerPenalty, NOT penalizing the peer
        let active_op = runtime.active_sync.take().unwrap();
        let evaluation = runtime.evaluate_active_sync_outcome(&active_op, &worker_res);
        assert_eq!(
            evaluation,
            SyncOutcomeEvaluation::LocalFaultNoPeerPenalty,
            "Timeout waiting for local batch acknowledgement must evaluate to LocalFaultNoPeerPenalty"
        );

        runtime.finish_active_sync_with_result_at(active_op, worker_res, Instant::now());
        let notifier_res = notifier_rx.await.expect("Notifier must receive result");
        assert!(
            notifier_res.is_err(),
            "Notifier must receive error describing local abort"
        );
        let notif_err = notifier_res.unwrap_err();
        assert!(
            notif_err.contains("local fault") || notif_err.contains("LocalFault"),
            "Error must specify local fault, got: {notif_err}"
        );

        assert!(
            !runtime
                .sync_penalties
                .is_cooling_down(&peer_id, Instant::now()),
            "Peer must NOT be penalized for a locally delayed acknowledgement"
        );
    }
}
