//! The accepted-chain state and atomic block application.
//!
//! This module owns the state that structural block validation mutates:
//! the list of accepted blocks and the derived chain view (tip height,
//! tip block ID, and the ancestor timestamps the timestamp rule needs).
//!
//! The atomicity rule from `docs/protocol-v1.md` is enforced by
//! construction: [`ChainState::apply_block`] validates the candidate
//! block **completely** before it touches any state. A rejected block
//! therefore cannot mutate the accepted chain in any way — the tip, the
//! accepted block list, cumulative work and the timestamp window are all
//! left exactly as they were.
//!
//! RandomX proof of work, difficulty retargeting, and consensus validation
//! are fully enforced against accepted state. Orchard transaction proof
//! verification, mempool and p2p networking are deferred to later milestones.

use crate::block::Block;
use crate::error::EncodeError;
use crate::hash::Hash;
use crate::validation::{validate_block, ValidationContext, ValidationError};

/// The number of ancestor blocks the timestamp rule considers.
///
/// `docs/protocol-v1.md` §4: a block timestamp must be greater than the
/// upper median of the timestamps of the last 11 ancestor blocks.
pub const TIMESTAMP_WINDOW: usize = 11;

/// An error produced while applying a block to the chain state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChainError {
    /// The block failed structural validation.
    Invalid(ValidationError),
    /// The block could not be canonically encoded.
    Encoding(EncodeError),
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Invalid(e) => write!(f, "invalid block: {e}"),
            ChainError::Encoding(e) => write!(f, "encoding error: {e}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<ValidationError> for ChainError {
    fn from(e: ValidationError) -> Self {
        ChainError::Invalid(e)
    }
}

impl From<EncodeError> for ChainError {
    fn from(e: EncodeError) -> Self {
        ChainError::Encoding(e)
    }
}

/// The accepted-chain state.
///
/// The chain is a single linear sequence of accepted blocks starting at
/// genesis. A block is accepted only if it validates structurally against
/// the current tip; a rejected block leaves the state untouched.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainState {
    chain_id: Hash,
    blocks: Vec<Block>,
    /// The IDs of every transaction accepted on the chain.
    ///
    /// §6.3 requires rejecting a transaction ID that is already present on
    /// the selected chain. The set is kept as a sorted, deduplicated vector
    /// so that the state stays `Eq` and `Debug`-comparable and so that a
    /// membership test is a binary search.
    accepted_transaction_ids: Vec<Hash>,
    /// Cumulative accepted work through each block height.
    cumulative_work: Vec<crate::difficulty::U256>,
    /// Difficulty samples for every accepted block.
    difficulty_samples: Vec<crate::difficulty::DifficultySample>,
}

impl ChainState {
    /// Creates a chain state positioned before genesis.
    ///
    /// The chain is empty until a genesis block is applied.
    pub fn new(chain_id: Hash) -> Self {
        ChainState {
            chain_id,
            blocks: Vec::new(),
            accepted_transaction_ids: Vec::new(),
            cumulative_work: Vec::new(),
            difficulty_samples: Vec::new(),
        }
    }

    /// Creates a chain state whose only accepted block is the given genesis
    /// block.
    ///
    /// Fails if the genesis block is not structurally valid.
    pub fn from_genesis(genesis: &Block) -> Result<Self, ChainError> {
        let mut state = ChainState::new(genesis.header.chain_id);
        state.apply_block(genesis)?;
        Ok(state)
    }

    /// Returns the chain ID of this chain.
    pub fn chain_id(&self) -> Hash {
        self.chain_id
    }

    /// Returns the number of accepted blocks.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Returns `true` if no block has been accepted yet.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the accepted blocks, in height order.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Returns the accepted block at the given height, if any.
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        self.blocks.get(usize::try_from(height).ok()?)
    }

    /// Returns the current tip block, if any.
    pub fn tip(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// Returns the height of the current tip, if any.
    pub fn tip_height(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.header.height)
    }

    /// Returns the block ID of the current tip, if any.
    pub fn tip_block_id(&self) -> Option<Hash> {
        self.blocks.last().map(|b| b.block_id())
    }

    /// Validates a candidate block against the current state **without**
    /// mutating it.
    ///
    /// This is the read-only counterpart of [`ChainState::apply_block`] and
    /// is what a node should call when it wants to check a block it is not
    /// ready to accept.
    pub fn validate(&self, block: &Block) -> Result<(), ValidationError> {
        let timestamps = self.ancestor_timestamps();
        let mut context = match self.tip() {
            Some(parent) => ValidationContext::new(self.chain_id, parent, &timestamps),
            None => ValidationContext::genesis(self.chain_id),
        }
        .with_accepted_transaction_ids(&self.accepted_transaction_ids);

        if block.header.height > 0 {
            let kh = crate::randomx::key_height(block.header.height);
            if let Some(key_block) = self.block_at(kh) {
                context = context.with_key_block_id(key_block.block_id());
            }

            // Expected height according to accepted tip
            let expected_height = match self.tip() {
                Some(parent) => parent.header.height + 1,
                None => 0,
            };

            // Derive expected difficulty from accepted ancestor history:
            let expected_difficulty = self.expected_difficulty(expected_height)?;
            context = context.with_expected_difficulty(expected_difficulty);
        }

        validate_block(block, &context)
    }

    /// Validates and, if the candidate is valid, accepts it.
    ///
    /// The candidate is validated in full against the current state
    /// *before* any state is modified. If validation fails, the error is
    /// returned and the chain state — the accepted block list, cumulative
    /// work, difficulty history, the tip and the timestamp window — is left
    /// exactly as it was.
    ///
    /// The only state change on success is the atomic append of the accepted
    /// block, its cumulative work, and its difficulty sample.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), ChainError> {
        // Validate first. Nothing below this line may mutate `self` until
        // every check has passed, so a rejected block cannot leave partial
        // state behind.
        self.validate(block)?;

        // The canonical encoding must succeed; this is a pure check that
        // cannot mutate state either.
        block.to_bytes()?;

        // Calculate next cumulative work before mutating state:
        let next_cumulative_work = if block.header.height == 0 {
            // §4: Genesis contributes zero work.
            crate::difficulty::U256::zero()
        } else {
            let prev_work = self
                .cumulative_work
                .last()
                .copied()
                .unwrap_or_else(crate::difficulty::U256::zero);
            prev_work
                .checked_add(crate::difficulty::U256::from_u128(block.header.difficulty))
                .ok_or(ValidationError::from(
                    crate::difficulty::DifficultyError::CumulativeWorkOverflow,
                ))?
        };

        // All checks succeeded. The block is accepted: atomically extend chain state.
        for id in block.transaction_ids() {
            if self.accepted_transaction_ids.binary_search(&id).is_err() {
                self.accepted_transaction_ids.push(id);
            }
        }
        self.accepted_transaction_ids.sort_unstable();
        self.cumulative_work.push(next_cumulative_work);
        self.difficulty_samples
            .push(crate::difficulty::DifficultySample {
                height: block.header.height,
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
            });
        self.blocks.push(block.clone());
        Ok(())
    }

    /// Returns the IDs of every transaction accepted on the chain.
    ///
    /// The IDs are sorted and deduplicated.
    pub fn accepted_transaction_ids(&self) -> &[Hash] {
        &self.accepted_transaction_ids
    }

    /// Returns the cumulative work through the current tip block.
    ///
    /// Per `docs/protocol-v1.md` §4, genesis contributes zero work.
    /// Returns zero if the chain is empty.
    pub fn cumulative_work(&self) -> crate::difficulty::U256 {
        self.cumulative_work
            .last()
            .copied()
            .unwrap_or_else(crate::difficulty::U256::zero)
    }

    /// Returns the cumulative work through the block at the given height, if accepted.
    pub fn cumulative_work_at(&self, height: u64) -> Option<crate::difficulty::U256> {
        self.cumulative_work
            .get(usize::try_from(height).ok()?)
            .copied()
    }

    /// Returns the cumulative work history for all accepted blocks.
    pub fn cumulative_work_history(&self) -> &[crate::difficulty::U256] {
        &self.cumulative_work
    }

    /// Returns the difficulty samples for all accepted blocks.
    pub fn difficulty_samples(&self) -> &[crate::difficulty::DifficultySample] {
        &self.difficulty_samples
    }

    /// Computes the network-computed expected difficulty for a block extending
    /// the current tip, according to `docs/protocol-v1.md` §4.1.
    pub fn expected_difficulty_for_next_block(&self) -> Result<u128, ValidationError> {
        let next_height = match self.tip() {
            Some(tip) => tip.header.height + 1,
            None => 0,
        };
        self.expected_difficulty(next_height)
    }

    /// Computes the network-computed expected difficulty for a block at `height`.
    pub fn expected_difficulty(&self, height: u64) -> Result<u128, ValidationError> {
        if height == 0 {
            return Ok(crate::genesis::GENESIS_DIFFICULTY);
        }
        crate::difficulty::next_difficulty(height, &self.difficulty_samples, &self.cumulative_work)
            .map_err(ValidationError::from)
    }

    /// Returns the timestamps of the last `TIMESTAMP_WINDOW` ancestor blocks,
    /// oldest first.
    ///
    /// These are the samples the upper-median timestamp rule uses.
    pub fn ancestor_timestamps(&self) -> Vec<u64> {
        let start = self.blocks.len().saturating_sub(TIMESTAMP_WINDOW);
        self.blocks[start..]
            .iter()
            .map(|b| b.header.timestamp)
            .collect()
    }

    /// Returns the upper median of the ancestor timestamps.
    ///
    /// The samples are sorted ascending and index `len / 2` is chosen, per
    /// `docs/protocol-v1.md` §4. Returns `None` when there are no
    /// ancestors.
    pub fn ancestor_median_timestamp(&self) -> Option<u64> {
        crate::validation::upper_median(&self.ancestor_timestamps())
    }
}
