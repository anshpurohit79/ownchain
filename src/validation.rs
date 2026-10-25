//! Consensus validation of candidate blocks.
//!
//! This module implements consensus validation rules defined in `docs/protocol-v1.md`:
//!
//! * §6.1 — canonical header fields and canonical block encoding.
//! * §6.2 — transaction Merkle commitment.
//! * §6.3 — block and transaction size caps, aggregate action limits, and coinbase rule.
//! * §6.4 — genesis shape.
//! * §7.0 — canonical transaction outer envelope.
//! * §7.3, §12 — stateless Orchard V2 bundle verification (proofs, signatures, fee rules).
//! * §4 — upper-median timestamp rule.
//! * §4, §4.1 — network-computed expected difficulty enforcement.
//! * §4, §4.1 — RandomX proof-of-work verification against the validated target.
//!
//! Stateless Orchard V2 bundle verification (including Halo2 proof verification,
//! spend authorization signatures, binding signatures, and exact consensus fee
//! formula enforcement) is fully integrated into the block-validation path.
//!
//! Stateful checks that require historical anchor validation against active chain
//! commitment-tree roots, nullifier double-spend tracking against the chain,
//! commitment tree updates and header `orchard_commitment_root` calculation for
//! transaction-bearing blocks, subsidy limits, and pool balance accounting remain
//! deferred to the subsequent stateful consensus integration stage.
//! This module never invents a rule the specification does not state; in
//! particular it does not implement the "two hours ahead of local time"
//! deferral rule, because §4 explicitly classifies that as a local-clock
//! policy and *not* a permanent consensus invalidity.

use core::fmt;

use crate::block::{Block, MAX_BLOCK_SIZE, MAX_TRANSACTION_SIZE, TX_COUNT_LEN, TX_LENGTH_LEN};
use crate::hash::Hash;
use crate::header::{HEADER_LEN, VERSION_INITIAL};
use crate::orchard_root::empty_commitment_root;
use crate::tx::{self, TxType};

/// The number of ancestor blocks the timestamp rule considers.
///
/// `docs/protocol-v1.md` §4: a block timestamp must be greater than the
/// upper median of the available timestamps in the last 11 ancestor blocks
/// (up to 11 for early heights).
pub const TIMESTAMP_WINDOW: usize = 11;

/// Errors produced when a candidate block fails structural validation.
///
/// Every variant is a permanent consensus invalidity of the candidate
/// block: the block can never become valid by being retried later.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValidationError {
    /// The header `version` is not the supported protocol version.
    UnsupportedVersion {
        /// The version found in the header.
        found: u16,
        /// The only version this implementation supports.
        expected: u16,
    },
    /// The header's `chain_id` is not the active network's chain ID.
    WrongChainId {
        /// The chain ID carried by the header.
        found: Hash,
        /// The chain ID of the active network.
        expected: Hash,
    },
    /// The header height does not follow the parent block.
    HeightMismatch {
        /// The height carried by the header.
        found: u64,
        /// The height the block must have, given its parent.
        expected: u64,
    },
    /// The header's `parent_block_id` is not the ID of the block at
    /// `height - 1` on the selected chain.
    UnknownParent {
        /// The parent block ID carried by the header.
        found: Hash,
        /// The ID of the block at `height - 1` on the selected chain.
        expected: Hash,
    },
    /// A non-genesis block declared a zero parent block ID.
    ZeroParentBlockId,
    /// A genesis block declared a non-zero parent block ID.
    NonZeroGenesisParent,
    /// The header's transaction Merkle root does not match the block's
    /// transactions.
    TransactionRootMismatch {
        /// The root computed from the block's transactions.
        computed: Hash,
        /// The root carried by the header.
        declared: Hash,
    },
    /// The block contains the same transaction twice.
    DuplicateTransaction {
        /// The index of the second occurrence.
        index: usize,
        /// The ID of the duplicated transaction.
        transaction_id: Hash,
    },
    /// The block timestamp is not greater than the upper median of the
    /// ancestor timestamps.
    TimestampNotIncreasing {
        /// The timestamp carried by the header.
        found: u64,
        /// The upper-median ancestor timestamp the block must exceed.
        median: u64,
    },
    /// The canonical block size exceeds the consensus limit.
    BlockTooLarge {
        /// The actual size of the canonical encoding, in bytes.
        actual: usize,
        /// The maximum permitted size, in bytes.
        limit: usize,
    },
    /// A transaction's canonical size exceeds the consensus limit.
    TransactionTooLarge {
        /// The actual size of the canonical transaction, in bytes.
        actual: usize,
        /// The maximum permitted size, in bytes.
        limit: usize,
    },
    /// A non-genesis block does not contain exactly one coinbase at index 0.
    InvalidCoinbase {
        /// A human-readable description of the defect.
        reason: String,
    },
    /// The candidate does not match the canonical genesis block of §6.4.
    InvalidGenesis {
        /// A human-readable description of the mismatch.
        reason: String,
    },
    /// A transaction's outer envelope is malformed.
    MalformedTransaction {
        /// The index of the offending transaction within the block.
        index: usize,
        /// A human-readable description of the defect.
        reason: String,
    },
    /// The coinbase's declared height does not match the block height.
    CoinbaseHeightMismatch {
        /// The height declared by the coinbase.
        found: u64,
        /// The height of the block containing the coinbase.
        expected: u64,
    },
    /// The header's `orchard_commitment_root` is not the canonical empty
    /// Orchard root even though the block carries no transactions.
    OrchardRootMismatch {
        /// The root computed from the block's Orchard commitments.
        computed: Hash,
        /// The root carried by the header.
        declared: Hash,
    },
    /// The block's difficulty is zero.
    ZeroDifficulty,
    /// The block's declared difficulty does not match the network-computed expected difficulty.
    DifficultyMismatch {
        /// The difficulty declared in the candidate block.
        found: u128,
        /// The network-computed expected difficulty.
        expected: u128,
    },
    /// Expected difficulty was not provided in the validation context.
    MissingExpectedDifficulty {
        /// The candidate block height.
        height: u64,
    },
    /// Difficulty adjustment calculation failed.
    InvalidDifficulty(crate::difficulty::DifficultyError),
    /// Proof of work could not be verified because the required key block was not provided.
    MissingKeyBlock {
        /// The candidate block height.
        height: u64,
        /// The required key block height.
        key_height: u64,
    },
    /// The proof-of-work hash exceeds the target for the declared difficulty.
    HashAboveTarget {
        /// The computed RandomX hash.
        hash: Hash,
        /// The target threshold for the declared difficulty.
        target: crate::difficulty::U256,
    },
    /// RandomX proof-of-work calculation failed.
    Randomx(crate::randomx::RandomxError),
    /// The block's canonical serialization could not be produced.
    Encoding(crate::error::EncodeError),
    /// An Orchard transaction failed stateless verification (§7.3, §12).
    InvalidOrchardTransaction {
        /// The index of the offending transaction within the block.
        index: usize,
        /// The stateless validation error.
        error: crate::orchard_tx::OrchardValidationError,
    },
    /// A transaction declared an invalid consensus fee (§4).
    IncorrectTransactionFee {
        /// The index of the offending transaction within the block.
        index: usize,
        /// The fee declared in the transaction.
        declared: u64,
        /// The expected consensus fee according to the formula.
        expected: u64,
    },
    /// A transaction fee calculation overflowed (§4).
    FeeCalculationOverflow {
        /// The index of the offending transaction within the block.
        index: usize,
    },
    /// The total number of Orchard actions across all transactions in the block exceeds the block limit (§6.3).
    TooManyBlockActions {
        /// The actual number of actions in the block.
        actual: usize,
        /// The maximum permitted number of actions.
        limit: usize,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::UnsupportedVersion { found, expected } => {
                write!(f, "unsupported header version {found}, expected {expected}")
            }
            ValidationError::WrongChainId { found, expected } => {
                write!(f, "wrong chain ID {found}, expected {expected}")
            }
            ValidationError::HeightMismatch { found, expected } => {
                write!(f, "wrong height {found}, expected {expected}")
            }
            ValidationError::UnknownParent { found, expected } => {
                write!(f, "unknown parent block {found}, expected {expected}")
            }
            ValidationError::ZeroParentBlockId => {
                write!(f, "non-genesis block has a zero parent block ID")
            }
            ValidationError::NonZeroGenesisParent => {
                write!(f, "genesis block has a non-zero parent block ID")
            }
            ValidationError::TransactionRootMismatch { computed, declared } => {
                write!(
                    f,
                    "transaction root mismatch: computed {computed}, declared {declared}"
                )
            }
            ValidationError::DuplicateTransaction {
                index,
                transaction_id,
            } => {
                write!(f, "duplicate transaction {transaction_id} at index {index}")
            }
            ValidationError::TimestampNotIncreasing { found, median } => {
                write!(
                    f,
                    "timestamp {found} is not greater than the ancestor median {median}"
                )
            }
            ValidationError::BlockTooLarge { actual, limit } => {
                write!(
                    f,
                    "canonical block is {actual} bytes, exceeds limit {limit}"
                )
            }
            ValidationError::TransactionTooLarge { actual, limit } => {
                write!(
                    f,
                    "canonical transaction is {actual} bytes, exceeds limit {limit}"
                )
            }
            ValidationError::InvalidCoinbase { reason } => {
                write!(f, "invalid coinbase: {reason}")
            }
            ValidationError::InvalidGenesis { reason } => {
                write!(f, "invalid genesis block: {reason}")
            }
            ValidationError::MalformedTransaction { index, reason } => {
                write!(f, "malformed transaction at index {index}: {reason}")
            }
            ValidationError::CoinbaseHeightMismatch { found, expected } => {
                write!(
                    f,
                    "coinbase height {found} does not match block height {expected}"
                )
            }
            ValidationError::OrchardRootMismatch { computed, declared } => {
                write!(
                    f,
                    "orchard commitment root mismatch: computed {computed}, declared {declared}"
                )
            }
            ValidationError::ZeroDifficulty => {
                write!(f, "block difficulty must be non-zero")
            }
            ValidationError::DifficultyMismatch { found, expected } => {
                write!(
                    f,
                    "block difficulty mismatch: declared {found}, expected {expected}"
                )
            }
            ValidationError::MissingExpectedDifficulty { height } => {
                write!(
                    f,
                    "missing expected difficulty for block at height {height}"
                )
            }
            ValidationError::InvalidDifficulty(e) => {
                write!(f, "invalid difficulty calculation: {e}")
            }
            ValidationError::MissingKeyBlock { height, key_height } => {
                write!(
                    f,
                    "missing key block for height {height}: requires key block at height {key_height}"
                )
            }
            ValidationError::HashAboveTarget { hash, target } => {
                write!(f, "proof-of-work hash {hash} exceeds target {target:?}")
            }
            ValidationError::Randomx(e) => write!(f, "RandomX error: {e}"),
            ValidationError::Encoding(e) => write!(f, "encoding error: {e}"),
            ValidationError::InvalidOrchardTransaction { index, error } => {
                write!(f, "invalid Orchard transaction at index {index}: {error}")
            }
            ValidationError::IncorrectTransactionFee {
                index,
                declared,
                expected,
            } => {
                write!(
                    f,
                    "incorrect transaction fee at index {index}: declared {declared}, expected {expected}"
                )
            }
            ValidationError::FeeCalculationOverflow { index } => {
                write!(
                    f,
                    "transaction fee calculation overflowed for transaction at index {index}"
                )
            }
            ValidationError::TooManyBlockActions { actual, limit } => {
                write!(
                    f,
                    "block contains {actual} Orchard actions, exceeds limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<crate::error::EncodeError> for ValidationError {
    fn from(e: crate::error::EncodeError) -> Self {
        ValidationError::Encoding(e)
    }
}

impl From<crate::randomx::RandomxError> for ValidationError {
    fn from(e: crate::randomx::RandomxError) -> Self {
        ValidationError::Randomx(e)
    }
}

impl From<crate::difficulty::DifficultyError> for ValidationError {
    fn from(e: crate::difficulty::DifficultyError) -> Self {
        ValidationError::InvalidDifficulty(e)
    }
}

/// The chain context a candidate block is validated against.
///
/// This bundles everything a candidate must be checked *against* — the
/// active network, the parent it builds on, the ancestor timestamps the
/// timestamp rule consumes, and the transaction IDs already on the chain —
/// so that the validation function has a single, explicit input.
#[derive(Clone, Copy, Debug)]
pub struct ValidationContext<'a> {
    /// The chain ID of the active network.
    pub chain_id: Hash,
    /// The parent block, or `None` when the candidate is the genesis block.
    pub parent: Option<&'a Block>,
    /// The timestamps of the ancestor blocks, oldest first.
    ///
    /// These are the samples the upper-median timestamp rule uses. Only the
    /// last [`TIMESTAMP_WINDOW`] entries are considered.
    pub ancestor_timestamps: &'a [u64],
    /// The IDs of the transactions already accepted on the selected chain.
    ///
    /// §6.3 requires a node to reject duplicate transaction IDs "within a
    /// block or against the selected chain", so the accepted set has to be
    /// part of the context.
    pub accepted_transaction_ids: &'a [Hash],
    /// The key block ID for proof-of-work verification.
    pub key_block_id: Option<Hash>,
    /// The RandomX execution mode (Light or Fast).
    pub randomx_mode: crate::randomx::RandomxMode,
    /// The network-computed expected difficulty.
    pub expected_difficulty: Option<u128>,
}

impl<'a> ValidationContext<'a> {
    /// Creates a context for a candidate that builds on the given parent.
    pub fn new(chain_id: Hash, parent: &'a Block, ancestor_timestamps: &'a [u64]) -> Self {
        let key_block_id = if parent.header.height == 0 {
            Some(parent.block_id())
        } else {
            None
        };
        // §4.1: For any block at height 1..=16 (building on parent at height < 16),
        // fewer than 2 samples remain after applying the 15-block lag, so expected
        // difficulty is unconditionally 1.
        let expected_difficulty = if parent.header.height < 16 {
            Some(1)
        } else {
            None
        };
        ValidationContext {
            chain_id,
            parent: Some(parent),
            ancestor_timestamps,
            accepted_transaction_ids: &[],
            key_block_id,
            randomx_mode: crate::randomx::RandomxMode::Light,
            expected_difficulty,
        }
    }

    /// Creates a context for a candidate genesis block.
    pub fn genesis(chain_id: Hash) -> Self {
        ValidationContext {
            chain_id,
            parent: None,
            ancestor_timestamps: &[],
            accepted_transaction_ids: &[],
            key_block_id: None,
            randomx_mode: crate::randomx::RandomxMode::Light,
            expected_difficulty: Some(crate::genesis::GENESIS_DIFFICULTY),
        }
    }

    /// Returns a copy of this context that also knows the transaction IDs
    /// already accepted on the selected chain.
    pub fn with_accepted_transaction_ids(mut self, ids: &'a [Hash]) -> Self {
        self.accepted_transaction_ids = ids;
        self
    }

    /// Supplies the key block ID for proof-of-work verification.
    pub fn with_key_block_id(mut self, id: Hash) -> Self {
        self.key_block_id = Some(id);
        self
    }

    /// Sets the RandomX validation mode (Light or Fast).
    pub fn with_randomx_mode(mut self, mode: crate::randomx::RandomxMode) -> Self {
        self.randomx_mode = mode;
        self
    }

    /// Supplies the network-computed expected difficulty.
    pub fn with_expected_difficulty(mut self, difficulty: u128) -> Self {
        self.expected_difficulty = Some(difficulty);
        self
    }
}

/// Validates a candidate block against consensus rules.
///
/// This performs the consensus checks of `docs/protocol-v1.md` §4, §4.1,
/// §6.1–§6.4 and §7.0:
///
/// 1. header `version` and `chain_id` (§6.1);
/// 2. genesis shape, or height/parent linkage to parent block (§6.1);
/// 3. declared difficulty against network-computed expected difficulty (§4, §4.1);
/// 4. canonical block and transaction size limits (§6.3);
/// 5. transaction Merkle root (§6.2) and duplicate transaction IDs (§6.3);
/// 6. transaction envelopes, coinbase position and coinbase height (§7.0, §7.1);
/// 7. stateless Orchard transaction validation, fee rules, and block action limits (§7.3, §4, §6.3, §12);
/// 8. Orchard commitment root (§6.3, §6.4);
/// 9. upper-median timestamp rule (§4);
/// 10. RandomX proof of work against the validated target (§4, §4.1).
///
/// Stateful checks (historical anchors against active chain commitment-tree roots,
/// nullifier double-spend tracking against the chain, commitment tree updates,
/// header `orchard_commitment_root` calculation for transaction-bearing blocks, subsidy limits,
/// and pool-balance accounting) remain deferred.
///
/// The function is pure: it never mutates any state. A caller may therefore
/// validate first and only then commit the block, which is what
/// [`crate::chain::ChainState::apply_block`] does.
pub fn validate_block(
    block: &Block,
    context: &ValidationContext<'_>,
) -> Result<(), ValidationError> {
    validate_header(block, context)?;
    validate_difficulty(block, context)?;
    validate_transactions(block, context)?;
    validate_orchard_root(block)?;
    validate_timestamp(block, context)?;
    validate_pow(block, context)?;
    Ok(())
}

/// Validates the header of a candidate block.
fn validate_header(block: &Block, context: &ValidationContext<'_>) -> Result<(), ValidationError> {
    let header = &block.header;

    // §6.1: the header version must be the supported one.
    if header.version != VERSION_INITIAL {
        return Err(ValidationError::UnsupportedVersion {
            found: header.version,
            expected: VERSION_INITIAL,
        });
    }

    // §6.1 / §7.0: the header must be bound to the active network.
    if header.chain_id != context.chain_id {
        return Err(ValidationError::WrongChainId {
            found: header.chain_id,
            expected: context.chain_id,
        });
    }

    match context.parent {
        // Genesis: §6.4 fixes its shape exactly.
        None => validate_genesis(block, context),
        Some(parent) => {
            // §6.1: a non-genesis block never has an all-zero parent ID.
            if header.parent_block_id.is_zero() {
                return Err(ValidationError::ZeroParentBlockId);
            }

            // §6.1: the parent ID must be the ID of the block at height - 1.
            let expected_parent = parent.block_id();
            if header.parent_block_id != expected_parent {
                return Err(ValidationError::UnknownParent {
                    found: header.parent_block_id,
                    expected: expected_parent,
                });
            }

            // §6.1: the height must be exactly one above the parent's.
            let expected_height = parent.header.height + 1;
            if header.height != expected_height {
                return Err(ValidationError::HeightMismatch {
                    found: header.height,
                    expected: expected_height,
                });
            }

            Ok(())
        }
    }
}

/// Validates that the candidate is the canonical genesis block of §6.4.
fn validate_genesis(block: &Block, context: &ValidationContext<'_>) -> Result<(), ValidationError> {
    let header = &block.header;

    if header.height != crate::genesis::GENESIS_HEIGHT {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "height is {}, expected {}",
                header.height,
                crate::genesis::GENESIS_HEIGHT
            ),
        });
    }

    if !header.parent_block_id.is_zero() {
        return Err(ValidationError::NonZeroGenesisParent);
    }

    if !block.transactions.is_empty() {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "carries {} transactions, expected none",
                block.transactions.len()
            ),
        });
    }

    if header.difficulty != crate::genesis::GENESIS_DIFFICULTY {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "difficulty is {}, expected {}",
                header.difficulty,
                crate::genesis::GENESIS_DIFFICULTY
            ),
        });
    }

    if header.nonce != crate::genesis::GENESIS_NONCE {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "nonce is {}, expected {}",
                header.nonce,
                crate::genesis::GENESIS_NONCE
            ),
        });
    }

    if header.timestamp != crate::genesis::GENESIS_TIMESTAMP {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "timestamp is {}, expected {}",
                header.timestamp,
                crate::genesis::GENESIS_TIMESTAMP
            ),
        });
    }

    let expected_tx_root = crate::genesis::genesis_transaction_root();
    if header.transaction_root != expected_tx_root {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "transaction root is {}, expected {expected_tx_root}",
                header.transaction_root
            ),
        });
    }

    let expected_orchard_root = empty_commitment_root();
    if header.orchard_commitment_root != expected_orchard_root {
        return Err(ValidationError::InvalidGenesis {
            reason: format!(
                "orchard commitment root is {}, expected {expected_orchard_root}",
                header.orchard_commitment_root
            ),
        });
    }

    // Genesis is a fixed protocol constant: the candidate must be exactly
    // the genesis block of the active network, byte for byte.
    let expected = crate::genesis::genesis_block(context.chain_id);
    if block != &expected {
        return Err(ValidationError::InvalidGenesis {
            reason: "does not match the canonical genesis block".to_string(),
        });
    }

    Ok(())
}

/// Returns the size of the canonical serialization of a block, in bytes.
///
/// This mirrors [`crate::block::Block::canonical_size`] but never fails:
/// the size is reported even when it exceeds a consensus limit, so that the
/// caller can turn the overflow into the matching consensus error.
fn canonical_block_size(block: &Block) -> usize {
    let mut size = HEADER_LEN + TX_COUNT_LEN;
    for tx in &block.transactions {
        size += TX_LENGTH_LEN + tx.len();
    }
    size
}

/// Validates the transactions of a candidate block.
///
/// Covers §6.3 (size limits, coinbase position, duplicate IDs), §6.2
/// (transaction Merkle root) and §7.0/§7.1 (outer envelope, coinbase
/// height).
fn validate_transactions(
    block: &Block,
    context: &ValidationContext<'_>,
) -> Result<(), ValidationError> {
    // §6.3: Count declared Orchard actions across all transactions in the block.
    // Enforcing MAX_ACTIONS_PER_BLOCK early bounds block complexity before allocating
    // large buffers or running expensive Halo2 cryptographic proof verification.
    if context.parent.is_some() {
        let mut total_actions = 0usize;
        for raw in &block.transactions {
            if raw.len() > tx::TX_ENVELOPE_LEN + 8 {
                let mut bundle_slice = &raw[tx::TX_ENVELOPE_LEN + 8..];
                if let Ok(n_actions) = crate::orchard_tx::decode_compact_size(&mut bundle_slice) {
                    total_actions = total_actions.checked_add(n_actions).ok_or(
                        ValidationError::TooManyBlockActions {
                            actual: usize::MAX,
                            limit: crate::orchard_tx::MAX_ACTIONS_PER_BLOCK,
                        },
                    )?;
                }
            }
        }
        if total_actions > crate::orchard_tx::MAX_ACTIONS_PER_BLOCK {
            return Err(ValidationError::TooManyBlockActions {
                actual: total_actions,
                limit: crate::orchard_tx::MAX_ACTIONS_PER_BLOCK,
            });
        }
    }

    // §6.3: the canonical block encoding must fit into the block limit.
    //
    // The size is computed here rather than taken from
    // `Block::canonical_size`, because that helper fails with an
    // `EncodeError` as soon as a limit is exceeded. The consensus limit is
    // a structural invalidity of the candidate block, so it is reported as
    // `ValidationError::BlockTooLarge` instead of a generic encoding error.
    let size = canonical_block_size(block);
    if size > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            actual: size,
            limit: MAX_BLOCK_SIZE,
        });
    }

    // §7.0/§7.1: parse every envelope first. The type tag of a transaction
    // decides whether the 1,000,000-byte cap of §6.3 applies (it is a
    // *non-coinbase* cap), and the coinbase rule of §6.3 is expressed in
    // terms of the parsed type.
    let mut envelopes = Vec::with_capacity(block.transactions.len());
    for (index, raw) in block.transactions.iter().enumerate() {
        let envelope = parse_envelope_at(index, raw, context.chain_id)?;
        envelopes.push(envelope);
    }

    // §6.3: the size cap applies to non-coinbase transactions.
    for (index, raw) in block.transactions.iter().enumerate() {
        if envelopes[index].tx_type == TxType::Coinbase {
            continue;
        }
        if raw.len() > MAX_TRANSACTION_SIZE {
            return Err(ValidationError::TransactionTooLarge {
                actual: raw.len(),
                limit: MAX_TRANSACTION_SIZE,
            });
        }
    }

    // §6.3: "The coinbase is transaction index 0 and exactly one coinbase is
    // required in every non-genesis block." Genesis carries no transactions
    // at all, so the rule does not apply to it.
    if context.parent.is_some() {
        let Some(first) = block.transactions.first() else {
            return Err(ValidationError::InvalidCoinbase {
                reason: "block carries no transactions".to_string(),
            });
        };
        if envelopes[0].tx_type != TxType::Coinbase {
            return Err(ValidationError::InvalidCoinbase {
                reason: "transaction 0 is not a coinbase".to_string(),
            });
        }

        // §7.1: the coinbase is only allowed at position 0.
        for (index, envelope) in envelopes.iter().enumerate().skip(1) {
            if envelope.tx_type == TxType::Coinbase {
                return Err(ValidationError::InvalidCoinbase {
                    reason: format!("coinbase found at index {index}, expected index 0"),
                });
            }
        }

        // §7.0: the coinbase payload declares the height of the block that
        // contains it.
        let declared =
            tx::coinbase_height(first).ok_or_else(|| ValidationError::MalformedTransaction {
                index: 0,
                reason: "coinbase payload has no height field".to_string(),
            })?;
        if declared != block.header.height {
            return Err(ValidationError::CoinbaseHeightMismatch {
                found: declared,
                expected: block.header.height,
            });
        }
    }

    // §6.3: duplicate transaction IDs within a block are rejected, and so
    // are IDs already present on the selected chain.
    let ids = block.transaction_ids();
    for index in 0..ids.len() {
        for other in index + 1..ids.len() {
            if ids[index] == ids[other] {
                return Err(ValidationError::DuplicateTransaction {
                    index: other,
                    transaction_id: ids[other],
                });
            }
        }
    }
    for (index, id) in ids.iter().enumerate() {
        if context.accepted_transaction_ids.contains(id) {
            return Err(ValidationError::DuplicateTransaction {
                index,
                transaction_id: *id,
            });
        }
    }

    // §6.2: the header's transaction root must commit to the block's
    // transactions. An empty block commits to the empty-tree root.
    let computed = crate::merkle::tx_root(&ids);
    if computed != block.header.transaction_root {
        return Err(ValidationError::TransactionRootMismatch {
            computed,
            declared: block.header.transaction_root,
        });
    }

    // §7.3, §12: For non-genesis blocks, every transaction must pass production
    // stateless Orchard validation (canonical bundle deserialization, action count,
    // flag validation, value balance rules, Halo2 proof verification against the
    // pinned FixedPostNu6_2 verifying key, spend authorization signatures, and binding
    // signature verification).
    //
    // Also enforces:
    // - Exact consensus fee formula for OrchardTransfer transactions (§4).
    // - Block aggregate action count limit MAX_ACTIONS_PER_BLOCK (§6.3).
    //
    // Stateful checks (historical anchors against active chain commitment-tree
    // roots, nullifier double-spend tracking against the chain, commitment tree
    // updates, header orchard_commitment_root for tx-bearing blocks, subsidy limits,
    // and pool balance accounting) remain deferred.
    if context.parent.is_some() {
        let vk = crate::orchard_tx::verifying_key();
        let mut total_actions = 0usize;

        for (index, raw) in block.transactions.iter().enumerate() {
            let validated =
                crate::orchard_tx::validate_transaction_stateless(raw, context.chain_id, vk)
                    .map_err(|error| ValidationError::InvalidOrchardTransaction { index, error })?;

            let action_count = validated.bundle().actions().len();
            total_actions = total_actions.checked_add(action_count).ok_or(
                ValidationError::TooManyBlockActions {
                    actual: usize::MAX,
                    limit: crate::orchard_tx::MAX_ACTIONS_PER_BLOCK,
                },
            )?;

            if validated.tx_type() == TxType::OrchardTransfer {
                let declared_fee = validated.fee_atoms().unwrap_or(0);
                match crate::orchard_tx::check_transaction_fee(
                    action_count,
                    raw.len(),
                    declared_fee,
                ) {
                    Ok(_) => {}
                    Err(crate::orchard_tx::FeeError::Overflow) => {
                        return Err(ValidationError::FeeCalculationOverflow { index });
                    }
                    Err(crate::orchard_tx::FeeError::Mismatch { declared, expected }) => {
                        return Err(ValidationError::IncorrectTransactionFee {
                            index,
                            declared,
                            expected,
                        });
                    }
                }
            }
        }

        if total_actions > crate::orchard_tx::MAX_ACTIONS_PER_BLOCK {
            return Err(ValidationError::TooManyBlockActions {
                actual: total_actions,
                limit: crate::orchard_tx::MAX_ACTIONS_PER_BLOCK,
            });
        }
    }

    Ok(())
}

/// Parses the envelope of the transaction at `index`, mapping the envelope
/// error into a validation error.
fn parse_envelope_at(
    index: usize,
    raw: &[u8],
    chain_id: Hash,
) -> Result<crate::tx::TxEnvelope, ValidationError> {
    tx::parse_envelope(raw, chain_id).map_err(|e| ValidationError::MalformedTransaction {
        index,
        reason: e.to_string(),
    })
}

/// Validates the header's Orchard commitment root.
///
/// §6.3: the Orchard commitment tree uses the upstream Orchard tree rules
/// at its fixed depth of 32, and the header root is the tree state after
/// processing the complete block.
///
/// While stateless Orchard bundle verification is now active, incremental
/// commitment-tree state updates and root calculation for transaction-bearing
/// blocks remain deferred to the subsequent stateful consensus integration stage.
/// The check is therefore applied exactly where it is currently decidable without
/// stateful tree tracking — a block that carries no transactions commits to no Orchard
/// commitment, so its header must carry the canonical empty Orchard root.
fn validate_orchard_root(block: &Block) -> Result<(), ValidationError> {
    if !block.transactions.is_empty() {
        // Deferred to stateful consensus integration: commitment tree state updates
        // and header orchard_commitment_root verification for transaction-bearing blocks.
        return Ok(());
    }

    let expected = empty_commitment_root();
    if block.header.orchard_commitment_root != expected {
        return Err(ValidationError::OrchardRootMismatch {
            computed: expected,
            declared: block.header.orchard_commitment_root,
        });
    }
    Ok(())
}

/// Validates the block timestamp against the upper-median rule of §4.
///
/// A block timestamp must be greater than the upper median of the available
/// timestamps in the last 11 ancestor blocks. The samples are sorted
/// ascending and index `len / 2` is chosen.
///
/// The "two hours ahead of local time" deferral rule of §4 is deliberately
/// **not** implemented here: the specification classifies it as a
/// local-clock policy and explicitly states that it "is not a permanent
/// consensus invalidity".
fn validate_timestamp(
    block: &Block,
    context: &ValidationContext<'_>,
) -> Result<(), ValidationError> {
    // Only the last `TIMESTAMP_WINDOW` ancestors are considered.
    let start = context
        .ancestor_timestamps
        .len()
        .saturating_sub(TIMESTAMP_WINDOW);
    let window = &context.ancestor_timestamps[start..];

    let Some(median) = upper_median(window) else {
        // No ancestor samples: the rule has nothing to compare against.
        return Ok(());
    };

    if block.header.timestamp <= median {
        return Err(ValidationError::TimestampNotIncreasing {
            found: block.header.timestamp,
            median,
        });
    }

    Ok(())
}

/// Returns the upper median of the given timestamps.
///
/// `docs/protocol-v1.md` §4: sort ascending and choose index `len / 2`.
/// Returns `None` when there are no samples.
pub fn upper_median(timestamps: &[u64]) -> Option<u64> {
    if timestamps.is_empty() {
        return None;
    }
    let mut sorted = timestamps.to_vec();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
}

/// Validates the block difficulty against the network-computed expected difficulty.
///
/// §4: "Difficulty must be the network-computed expected value, not a miner-selected value."
/// §6.4: Genesis difficulty is fixed at 1 and validated in `validate_genesis`.
fn validate_difficulty(
    block: &Block,
    context: &ValidationContext<'_>,
) -> Result<(), ValidationError> {
    if block.header.height == 0 {
        // Genesis difficulty is validated in validate_genesis against GENESIS_DIFFICULTY.
        return Ok(());
    }

    if block.header.difficulty == 0 {
        return Err(ValidationError::ZeroDifficulty);
    }

    let expected =
        context
            .expected_difficulty
            .ok_or(ValidationError::MissingExpectedDifficulty {
                height: block.header.height,
            })?;

    if expected == 0 {
        return Err(ValidationError::ZeroDifficulty);
    }

    if block.header.difficulty != expected {
        return Err(ValidationError::DifficultyMismatch {
            found: block.header.difficulty,
            expected,
        });
    }

    Ok(())
}

/// Validates the proof-of-work of a candidate block.
///
/// §6.4: The genesis block is a fixed protocol constant and never goes
/// through RandomX validation.
///
/// For any block at height > 0:
/// 1. The key block ID must be provided in `context.key_block_id`, or derived
///    from the canonical genesis block if `key_height(height) == 0`.
/// 2. The block difficulty must match the validated expected difficulty.
/// 3. The RandomX hash over the 170-byte canonical header bytes is computed.
/// 4. The 256-bit hash (little-endian) must be less than or equal to the
///    proof-of-work target T(d) = floor((2^256 - 1) / expected_difficulty).
fn validate_pow(block: &Block, context: &ValidationContext<'_>) -> Result<(), ValidationError> {
    if block.header.height == 0 {
        // §6.4: Genesis skips RandomX validation
        return Ok(());
    }

    let expected_diff =
        context
            .expected_difficulty
            .ok_or(ValidationError::MissingExpectedDifficulty {
                height: block.header.height,
            })?;

    if expected_diff == 0 {
        return Err(ValidationError::ZeroDifficulty);
    }

    if block.header.difficulty != expected_diff {
        return Err(ValidationError::DifficultyMismatch {
            found: block.header.difficulty,
            expected: expected_diff,
        });
    }

    let kh = crate::randomx::key_height(block.header.height);
    let key_id = context
        .key_block_id
        .or_else(|| {
            if kh == 0 {
                Some(crate::genesis::genesis_block(context.chain_id).block_id())
            } else {
                None
            }
        })
        .ok_or(ValidationError::MissingKeyBlock {
            height: block.header.height,
            key_height: kh,
        })?;

    let header_bytes = block.header.to_bytes();
    let hash =
        crate::randomx::randomx_hash(key_id.as_bytes(), &header_bytes, context.randomx_mode)?;

    let target =
        crate::randomx::pow_target(expected_diff).ok_or(ValidationError::ZeroDifficulty)?;
    let h = crate::difficulty::U256::from_le_bytes(hash);
    if h > target {
        return Err(ValidationError::HashAboveTarget {
            hash: Hash::new(hash),
            target,
        });
    }

    Ok(())
}
