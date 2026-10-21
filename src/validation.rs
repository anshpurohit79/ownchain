//! Structural validation of candidate blocks.
//!
//! This module implements the *structural* subset of the OwnChain v1
//! validation rules defined in `docs/protocol-v1.md`:
//!
//! * §6.1 — canonical header fields and the canonical block encoding.
//! * §6.2 — the transaction Merkle commitment.
//! * §6.3 — the block and transaction size caps and the coinbase rule.
//! * §6.4 — the genesis shape.
//! * §7.0 — the canonical transaction outer envelope.
//! * §4 — the upper-median timestamp rule.
//!
//! Everything that requires a full Orchard V2 bundle, RandomX proof of
//! work, the difficulty retarget or fork choice is explicitly **out of
//! scope** for this milestone (see §12, the Orchard compatibility gate).
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
    /// The block's canonical serialization could not be produced.
    Encoding(crate::error::EncodeError),
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
            ValidationError::Encoding(e) => write!(f, "encoding error: {e}"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<crate::error::EncodeError> for ValidationError {
    fn from(e: crate::error::EncodeError) -> Self {
        ValidationError::Encoding(e)
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
}

impl<'a> ValidationContext<'a> {
    /// Creates a context for a candidate that builds on the given parent.
    pub fn new(chain_id: Hash, parent: &'a Block, ancestor_timestamps: &'a [u64]) -> Self {
        ValidationContext {
            chain_id,
            parent: Some(parent),
            ancestor_timestamps,
            accepted_transaction_ids: &[],
        }
    }

    /// Creates a context for a candidate genesis block.
    pub fn genesis(chain_id: Hash) -> Self {
        ValidationContext {
            chain_id,
            parent: None,
            ancestor_timestamps: &[],
            accepted_transaction_ids: &[],
        }
    }

    /// Returns a copy of this context that also knows the transaction IDs
    /// already accepted on the selected chain.
    ///
    /// This is how the chain state supplies the "duplicate IDs against the
    /// selected chain" check of §6.3 without the validation function having
    /// to reach into the chain state itself.
    pub fn with_accepted_transaction_ids(mut self, ids: &'a [Hash]) -> Self {
        self.accepted_transaction_ids = ids;
        self
    }
}

/// Validates a candidate block structurally against the given context.
///
/// This performs the checks of `docs/protocol-v1.md` §6.1–§6.4, §7.0 and
/// §4 that are implementable without an Orchard bundle:
///
/// 1. header `version` and `chain_id` (§6.1);
/// 2. genesis shape, or the height/parent linkage to the parent block (§6.1);
/// 3. canonical block and transaction size limits (§6.3);
/// 4. the transaction Merkle root (§6.2) and duplicate transaction IDs (§6.3);
/// 5. the transaction envelopes, the coinbase position and the coinbase
///    height (§7.0, §7.1);
/// 6. the Orchard commitment root (§6.3, §6.4);
/// 7. the upper-median timestamp rule (§4).
///
/// Proof of work, difficulty retargeting, fork choice, the Orchard bundle
/// proof, the nullifier set, the fee formula and the pool-value accounting
/// are **not** checked here; they belong to later milestones.
///
/// The function is pure: it never mutates any state. A caller may therefore
/// validate first and only then commit the block, which is what
/// [`crate::chain::ChainState::apply_block`] does.
pub fn validate_block(
    block: &Block,
    context: &ValidationContext<'_>,
) -> Result<(), ValidationError> {
    validate_header(block, context)?;
    validate_transactions(block, context)?;
    validate_orchard_root(block)?;
    validate_timestamp(block, context)?;
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
/// Milestone M1-B does not parse Orchard bundles, so it cannot compute the
/// tree state for a block that carries transactions: the commitments live
/// inside the bundle, which is opaque here. The check is therefore applied
/// exactly where it is decidable — a block that carries no transactions
/// commits to no Orchard commitment, so its header must carry the canonical
/// empty Orchard root.
///
/// For a block that carries transactions the root is **deferred** to the
/// Orchard compatibility gate of §12. This is a known, documented limitation
/// of the milestone, not an oversight: silently accepting an unverified
/// commitment root would be a consensus hole, and rejecting every block with
/// a transaction would make the chain unusable. The Orchard root of a
/// transaction-bearing block is verified once bundle parsing lands.
fn validate_orchard_root(block: &Block) -> Result<(), ValidationError> {
    if !block.transactions.is_empty() {
        // Deferred: the commitment tree state cannot be computed without
        // parsing the Orchard bundles.
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
