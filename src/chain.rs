//! The accepted-chain state, atomic block application, and hybrid consensus integration.
//!
//! This module owns the state that block validation mutates:
//! - The list of accepted blocks and derived chain view (tip height, tip block ID).
//! - Cumulative work and difficulty samples for difficulty retargeting.
//! - The transparent account ledger, spendable balances, allowances, and guardian controls.
//! - The depth-32 Orchard incremental note commitment tree and historical anchors.
//! - The consumed-nullifier set and double-spend tracking.
//! - Cumulative shielded pool balance and global monetary conservation ($T + S = I$).
//! - Exact composite state root verification and atomic reorganization rollback.

use std::collections::{BTreeMap, BTreeSet};

use crate::account::{
    derive_address, scheduled_subsidy, AccountState, CoinbaseTranche, PendingTransfer,
    COINBASE_MATURITY_BLOCKS, MAX_SUPPLY_ATOMS,
};
use crate::block::Block;
use crate::error::EncodeError;
use crate::hash::{self, Hash};
use crate::merkle::{
    composite_state_root, nullifier_merkle_root, pool_balance_commitment, state_empty_root,
    state_merkle_root,
};
use crate::orchard_root::empty_commitment_root;
use crate::orchard_tree::OrchardTree;
use crate::orchard_tx::deserialize_bundle;
use crate::tx;
use crate::validation::{validate_block, ValidationContext, ValidationError};

/// The number of ancestor blocks the timestamp rule considers.
pub const TIMESTAMP_WINDOW: usize = 11;

/// An error produced while applying a block to the chain state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChainError {
    /// The block failed structural validation.
    Invalid(ValidationError),
    /// The block could not be canonically encoded.
    Encoding(EncodeError),
    /// The block failed consensus state transition.
    State(String),
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Invalid(e) => write!(f, "invalid block: {e}"),
            ChainError::Encoding(e) => write!(f, "encoding error: {e}"),
            ChainError::State(s) => write!(f, "state transition error: {s}"),
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

/// A snapshot of the consensus state at a specific block height.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainStateSnapshot {
    /// Transparent account ledger.
    pub accounts: BTreeMap<Hash, AccountState>,
    /// Set of spent nullifiers.
    pub nullifier_set: BTreeSet<Hash>,
    /// Cumulative balance in the shielded Orchard pool.
    pub shielded_pool_balance: u128,
    /// Total cumulative currency issued so far.
    pub cumulative_issuance: u128,
    /// Incremental Orchard note commitment tree.
    pub orchard_tree: OrchardTree,
    /// Historical Orchard roots for the anchor window.
    pub historical_anchors: BTreeMap<u64, Hash>,
    /// Accepted transaction IDs on the chain.
    pub accepted_transaction_ids: Vec<Hash>,
    pub confirmed_recipients: BTreeSet<(Hash, Hash)>,
    pub pending_confirmations: BTreeMap<u64, Vec<(Hash, Hash)>>,
}

/// The accepted-chain state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainState {
    chain_id: Hash,
    blocks: Vec<Block>,
    accepted_transaction_ids: Vec<Hash>,
    cumulative_work: Vec<crate::difficulty::U256>,
    difficulty_samples: Vec<crate::difficulty::DifficultySample>,

    // Hybrid consensus state components:
    pub accounts: BTreeMap<Hash, AccountState>,
    pub nullifier_set: BTreeSet<Hash>,
    pub shielded_pool_balance: u128,
    pub cumulative_issuance: u128,
    pub orchard_tree: OrchardTree,
    pub historical_anchors: BTreeMap<u64, Hash>,
    pub confirmed_recipients: BTreeSet<(Hash, Hash)>,
    pub pending_confirmations: BTreeMap<u64, Vec<(Hash, Hash)>>,
    history: BTreeMap<u64, ChainStateSnapshot>,
}

/// Candidate state transition evaluated against chain state.
#[derive(Clone, Debug)]
pub struct CandidateStateTransition {
    pub accounts: BTreeMap<Hash, AccountState>,
    pub nullifier_set: BTreeSet<Hash>,
    pub shielded_pool_balance: u128,
    pub cumulative_issuance: u128,
    pub orchard_tree: OrchardTree,
    pub historical_anchors: BTreeMap<u64, Hash>,
    pub accepted_transaction_ids: Vec<Hash>,
    pub confirmed_recipients: BTreeSet<(Hash, Hash)>,
    pub pending_confirmations: BTreeMap<u64, Vec<(Hash, Hash)>>,
    pub computed_state_root: Hash,
    pub next_cumulative_work: crate::difficulty::U256,
}

/// Checks and advances spend allowance accounting for transparent transactions.
fn check_and_apply_allowance(
    account: &mut AccountState,
    height: u64,
    cost: u128,
) -> Result<(), ChainError> {
    if account.allowance_limit > 0 && account.allowance_window_len > 0 {
        let window_end = account
            .allowance_window_start
            .checked_add(account.allowance_window_len)
            .ok_or_else(|| ChainError::State("allowance window overflow".into()))?;
        if height >= window_end {
            account.allowance_window_start = height;
            account.allowance_spent = 0;
        }
        let new_spent = account
            .allowance_spent
            .checked_add(cost)
            .ok_or_else(|| ChainError::State("allowance arithmetic overflow".into()))?;
        if new_spent > account.allowance_limit {
            return Err(ChainError::State("allowance limit exceeded".into()));
        }
        account.allowance_spent = new_spent;
    }
    Ok(())
}

impl ChainState {
    /// Creates a chain state positioned before genesis.
    pub fn new(chain_id: Hash) -> Self {
        let mut historical_anchors = BTreeMap::new();
        historical_anchors.insert(0, empty_commitment_root());
        ChainState {
            chain_id,
            blocks: Vec::new(),
            accepted_transaction_ids: Vec::new(),
            cumulative_work: Vec::new(),
            difficulty_samples: Vec::new(),
            accounts: BTreeMap::new(),
            nullifier_set: BTreeSet::new(),
            shielded_pool_balance: 0,
            cumulative_issuance: 0,
            orchard_tree: OrchardTree::new(),
            historical_anchors,
            confirmed_recipients: BTreeSet::new(),
            pending_confirmations: BTreeMap::new(),
            history: BTreeMap::new(),
        }
    }

    /// Creates a chain state whose only accepted block is the given genesis block.
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

    /// Returns the transparent account ledger.
    pub fn accounts(&self) -> &BTreeMap<Hash, AccountState> {
        &self.accounts
    }

    /// Returns the transparent account state for `address`, if it exists.
    pub fn account(&self, address: &Hash) -> Option<&AccountState> {
        self.accounts.get(address)
    }

    /// Returns the consumed-nullifier set.
    pub fn nullifier_set(&self) -> &BTreeSet<Hash> {
        &self.nullifier_set
    }

    /// Returns the cumulative shielded pool balance in atoms.
    pub fn shielded_pool_balance(&self) -> u128 {
        self.shielded_pool_balance
    }

    /// Returns the cumulative issuance in atoms.
    pub fn cumulative_issuance(&self) -> u128 {
        self.cumulative_issuance
    }

    /// Returns the current depth-32 Orchard commitment tree.
    pub fn orchard_tree(&self) -> &OrchardTree {
        &self.orchard_tree
    }

    /// Returns the current Orchard commitment tree root.
    pub fn orchard_root(&self) -> Hash {
        self.orchard_tree.root()
    }

    /// Returns the historical Orchard roots indexed by block height.
    pub fn historical_anchors(&self) -> &BTreeMap<u64, Hash> {
        &self.historical_anchors
    }

    /// Computes the recursive-split Merkle root over sorted transparent accounts.
    pub fn transparent_state_root(&self) -> Hash {
        if self.accounts.is_empty() {
            return state_empty_root();
        }
        let leaves: Vec<Vec<u8>> = self
            .accounts
            .iter()
            .map(|(addr, acc)| {
                let mut leaf = Vec::with_capacity(32 + 342);
                leaf.extend_from_slice(addr.as_bytes());
                leaf.extend_from_slice(&acc.serialize());
                leaf
            })
            .collect();
        state_merkle_root(&leaves)
    }

    /// Computes the recursive-split Merkle root over sorted nullifiers.
    pub fn nullifier_state_root(&self) -> Hash {
        let nfs: Vec<Hash> = self.nullifier_set.iter().copied().collect();
        nullifier_merkle_root(&nfs)
    }

    /// Computes the pool balance commitment for the current shielded balance.
    pub fn pool_balance_commitment(&self) -> Hash {
        pool_balance_commitment(self.shielded_pool_balance)
    }

    /// Computes the composite state root from the 4 component roots.
    pub fn composite_state_root(&self) -> Hash {
        composite_state_root(
            &self.transparent_state_root(),
            &self.orchard_root(),
            &self.nullifier_state_root(),
            &self.pool_balance_commitment(),
        )
    }

    /// Returns whether `recipient` has previously received a confirmed transfer from `sender`.
    pub fn is_confirmed_recipient(&self, sender: &Hash, recipient: &Hash) -> bool {
        self.confirmed_recipients.contains(&(*sender, *recipient))
    }

    /// Reconstructs the confirmed recipients set by replaying all accepted blocks from genesis.
    pub fn reconstruct_confirmed_recipients(&self) -> Result<BTreeSet<(Hash, Hash)>, ChainError> {
        if self.blocks.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut replay = ChainState::from_genesis(&self.blocks[0])?;
        for block in &self.blocks[1..] {
            replay.apply_block(block)?;
        }
        Ok(replay.confirmed_recipients)
    }

    /// Creates a snapshot of the current state.
    pub fn snapshot(&self) -> ChainStateSnapshot {
        ChainStateSnapshot {
            accounts: self.accounts.clone(),
            nullifier_set: self.nullifier_set.clone(),
            shielded_pool_balance: self.shielded_pool_balance,
            cumulative_issuance: self.cumulative_issuance,
            orchard_tree: self.orchard_tree.clone(),
            historical_anchors: self.historical_anchors.clone(),
            accepted_transaction_ids: self.accepted_transaction_ids.clone(),
            confirmed_recipients: self.confirmed_recipients.clone(),
            pending_confirmations: self.pending_confirmations.clone(),
        }
    }

    /// Rolls back the chain state to `height`, restoring exact historical state.
    pub fn rollback_to(&mut self, height: u64) -> Result<(), ChainError> {
        if self.blocks.is_empty() {
            return Ok(());
        }
        let target = height as usize;
        if target >= self.blocks.len() {
            return Ok(());
        }
        let snap = self.history.get(&height).ok_or_else(|| {
            ChainError::State(format!(
                "no snapshot available for rollback to height {height}"
            ))
        })?;

        self.accounts = snap.accounts.clone();
        self.nullifier_set = snap.nullifier_set.clone();
        self.shielded_pool_balance = snap.shielded_pool_balance;
        self.cumulative_issuance = snap.cumulative_issuance;
        self.orchard_tree = snap.orchard_tree.clone();
        self.historical_anchors = snap.historical_anchors.clone();
        self.accepted_transaction_ids = snap.accepted_transaction_ids.clone();
        self.confirmed_recipients = snap.confirmed_recipients.clone();
        self.pending_confirmations = snap.pending_confirmations.clone();

        self.blocks.truncate(target + 1);
        self.cumulative_work.truncate(target + 1);
        self.difficulty_samples.truncate(target + 1);
        self.history.retain(|&h, _| h <= height);
        Ok(())
    }

    /// Reorganizes the chain from current tip to a candidate branch.
    pub fn reorganize(&mut self, new_branch: &[Block]) -> Result<(), ChainError> {
        if new_branch.is_empty() {
            return Ok(());
        }
        let fork_first = &new_branch[0];
        let fork_parent_id = fork_first.header.parent_block_id;
        let fork_height = self
            .blocks
            .iter()
            .position(|b| b.block_id() == fork_parent_id)
            .ok_or_else(|| {
                ChainError::State("reorg fork block not found on current chain".into())
            })? as u64;

        let backup_tip = self.tip_height().unwrap_or(0);
        self.rollback_to(fork_height)?;

        for b in new_branch {
            if let Err(e) = self.apply_block(b) {
                let _ = self.rollback_to(backup_tip);
                return Err(e);
            }
        }
        Ok(())
    }

    fn validation_context<'a>(
        &'a self,
        block: &Block,
        timestamps: &'a [u64],
    ) -> Result<ValidationContext<'a>, ValidationError> {
        let mut context = match self.tip() {
            Some(parent) => ValidationContext::new(self.chain_id, parent, timestamps),
            None => ValidationContext::genesis(self.chain_id),
        }
        .with_accepted_transaction_ids(&self.accepted_transaction_ids);

        if block.header.height > 0 {
            let kh = crate::randomx::key_height(block.header.height);
            if let Some(key_block) = self.block_at(kh) {
                context = context.with_key_block_id(key_block.block_id());
            }

            let expected_height = match self.tip() {
                Some(parent) => parent.header.height + 1,
                None => 0,
            };

            let expected_difficulty = self.expected_difficulty(expected_height)?;
            context = context.with_expected_difficulty(expected_difficulty);
        }

        Ok(context)
    }

    /// Validates a candidate block against the current state **without** mutating it.
    pub fn validate(&self, block: &Block) -> Result<(), ValidationError> {
        let timestamps = self.ancestor_timestamps();
        let context = self.validation_context(block, &timestamps)?;
        validate_block(block, &context)
    }

    /// Validates candidate block consensus and cryptographic validity against current state without requiring solved proof-of-work.
    pub fn validate_candidate(&self, block: &Block) -> Result<(), ValidationError> {
        let timestamps = self.ancestor_timestamps();
        let context = self.validation_context(block, &timestamps)?;
        crate::validation::validate_candidate_block(block, &context)
    }

    /// Evaluates a candidate block that has already passed stateless block validation ([`Self::validate`]).
    ///
    /// Computes the candidate post-state transition without mutating the chain.
    fn evaluate_candidate_validated(
        &self,
        block: &Block,
    ) -> Result<CandidateStateTransition, ChainError> {
        // 1. Structural encoding check
        block.to_bytes()?;

        let next_cumulative_work = if block.header.height == 0 {
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

        // 2. Stateful Consensus Execution on Candidate Snapshot
        let mut candidate_accounts = self.accounts.clone();
        let mut candidate_nullifiers = self.nullifier_set.clone();
        let mut candidate_pool_balance = self.shielded_pool_balance;
        let mut candidate_issuance = self.cumulative_issuance;
        let mut candidate_tree = self.orchard_tree.clone();
        let mut candidate_anchors = self.historical_anchors.clone();
        let mut candidate_tx_ids = self.accepted_transaction_ids.clone();
        let mut candidate_confirmed = self.confirmed_recipients.clone();
        let mut candidate_pending_confirmations = self.pending_confirmations.clone();

        let h = block.header.height;
        let mut block_fees: u128 = 0;
        let mut coinbase_payout: u128 = 0;

        if h == 0 {
            // Genesis height 0
            candidate_anchors.insert(0, empty_commitment_root());
        } else {
            // Height H >= 1
            // A. Start-of-block transitions:
            // 1. Mature coinbase tranches where unlock_height <= H
            for acc in candidate_accounts.values_mut() {
                acc.coinbase_tranches.retain(|t| t.unlock_height > h);
            }

            // 2. Release pending transfers where release_height <= H
            let mut releases = Vec::new();
            for (sender_addr, acc) in candidate_accounts.iter_mut() {
                let mut remaining = Vec::new();
                for p in acc.pending_transfers.drain(..) {
                    if p.release_height <= h {
                        releases.push((*sender_addr, p.recipient, p.amount));
                    } else {
                        remaining.push(p);
                    }
                }
                acc.pending_transfers = remaining;
            }
            for (sender_addr, recipient, amount) in releases {
                let sender = candidate_accounts.get_mut(&sender_addr).ok_or_else(|| {
                    ChainError::State("sender missing during pending release".into())
                })?;
                sender.balance = sender
                    .balance
                    .checked_sub(amount)
                    .ok_or_else(|| ChainError::State("underflow during pending release".into()))?;
                let rec = candidate_accounts.entry(recipient).or_default();
                rec.balance = rec
                    .balance
                    .checked_add(amount)
                    .ok_or_else(|| ChainError::State("overflow during pending release".into()))?;
                candidate_confirmed.insert((sender_addr, recipient));
            }

            // 3. Mature ordinary direct transfer confirmations where unlock_height <= H
            let mut matured_keys = Vec::new();
            for &unlock_h in candidate_pending_confirmations.keys() {
                if unlock_h <= h {
                    matured_keys.push(unlock_h);
                }
            }
            for k in matured_keys {
                if let Some(pairs) = candidate_pending_confirmations.remove(&k) {
                    for pair in pairs {
                        candidate_confirmed.insert(pair);
                    }
                }
            }

            // B. Build valid 10-block ancestor-anchor window [max(0, H-10), H-1]
            // saturating_sub is safe here: heights are small and clamping at 0 only affects
            // genesis-adjacent blocks where the window is naturally truncated.
            let min_anchor_h = h.saturating_sub(10);
            let max_anchor_h = h.saturating_sub(1); // h >= 1 in this branch, so no saturation
            let mut valid_anchors = BTreeSet::new();
            for anch_h in min_anchor_h..=max_anchor_h {
                if let Some(anc) = candidate_anchors.get(&anch_h) {
                    valid_anchors.insert(*anc);
                }
            }
            if h <= 10 {
                if let Some(anc0) = candidate_anchors.get(&0) {
                    valid_anchors.insert(*anc0);
                }
            }

            // C. Execute block transactions in order
            let mut same_block_incoming: BTreeMap<Hash, u128> = BTreeMap::new();

            for (index, raw_tx) in block.transactions.iter().enumerate() {
                let tx_id = hash::transaction_id(raw_tx);
                if candidate_tx_ids.binary_search(&tx_id).is_ok() {
                    return Err(ChainError::Invalid(ValidationError::DuplicateTransaction {
                        index,
                        transaction_id: tx_id,
                    }));
                }

                let tag = *raw_tx
                    .first()
                    .ok_or_else(|| ChainError::State("empty transaction bytes".into()))?;

                match tag {
                    tx::TX_TYPE_COINBASE => {
                        if index != 0 {
                            return Err(ChainError::Invalid(ValidationError::InvalidCoinbase {
                                reason: "coinbase must be at index 0".into(),
                            }));
                        }
                        if raw_tx.len() != 83 {
                            return Err(ChainError::Invalid(ValidationError::InvalidCoinbase {
                                reason: format!(
                                    "invalid coinbase wire length: expected 83 (transparent-only), found {}",
                                    raw_tx.len()
                                ),
                            }));
                        }
                        // Transparent Coinbase
                        let cb_h = u64::from_le_bytes(raw_tx[35..43].try_into().unwrap());
                        if cb_h != h {
                            return Err(ChainError::Invalid(
                                ValidationError::CoinbaseHeightMismatch {
                                    found: cb_h,
                                    expected: h,
                                },
                            ));
                        }
                        let recipient = Hash::new(raw_tx[43..75].try_into().unwrap());
                        let payout = u64::from_le_bytes(raw_tx[75..83].try_into().unwrap()) as u128;
                        coinbase_payout = payout;

                        let miner = candidate_accounts.entry(recipient).or_default();
                        miner.balance = miner
                            .balance
                            .checked_add(payout)
                            .ok_or_else(|| ChainError::State("miner balance overflow".into()))?;
                        let unlock_height = h
                            .checked_add(COINBASE_MATURITY_BLOCKS)
                            .ok_or_else(|| ChainError::State("maturity height overflow".into()))?;
                        miner.coinbase_tranches.push(CoinbaseTranche {
                            coinbase_tx_id: tx_id,
                            amount: payout,
                            unlock_height,
                        });
                    }

                    tx::TX_TYPE_TRANSPARENT_TRANSFER => {
                        if raw_tx.len() != 195 {
                            return Err(ChainError::State(format!(
                                "invalid Type 1 TransparentTransfer wire length: expected 195, got {}",
                                raw_tx.len()
                            )));
                        }
                        let unsigned_tx = &raw_tx[..131];
                        let sig_bytes: [u8; 64] = raw_tx[131..195].try_into().unwrap();

                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        let mut sender_key = [0u8; 32];
                        sender_key.copy_from_slice(&payload[..32]);

                        // Strict Ed25519 signature verification over canonical signing preimage
                        let preimage =
                            crate::auth::compute_signing_preimage(self.chain_id, unsigned_tx);
                        crate::auth::verify_signature(&sender_key, &preimage, &sig_bytes).map_err(
                            |e| ChainError::State(format!("signature verification failed: {e}")),
                        )?;

                        let sender_addr = derive_address(&sender_key);

                        let recipient = Hash::new(payload[32..64].try_into().unwrap());
                        let amount = u128::from_le_bytes(payload[64..80].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[80..88].try_into().unwrap()) as u128;
                        let nonce = u64::from_le_bytes(payload[88..96].try_into().unwrap());

                        let min_fee = crate::tx::min_fee(raw_tx.len()).ok_or_else(|| {
                            ChainError::State("transaction too large for fee calculation".into())
                        })? as u128;
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below consensus minimum".into()));
                        }

                        let sender = candidate_accounts
                            .get_mut(&sender_addr)
                            .ok_or_else(|| ChainError::State("sender account not found".into()))?;

                        if sender.is_frozen {
                            return Err(ChainError::State("sender account is frozen".into()));
                        }
                        if sender.nonce != nonce {
                            return Err(ChainError::State(format!(
                                "nonce mismatch: expected {}, got {}",
                                sender.nonce, nonce
                            )));
                        }

                        let total_cost = amount.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("transfer total cost overflow".into())
                        })?;

                        let spendable = sender.spendable_balance(h).map_err(|_| {
                            ChainError::State("negative spendable balance calculation".into())
                        })?;
                        let incoming = same_block_incoming.get(&sender_addr).copied().unwrap_or(0);
                        let effective_spendable =
                            spendable.checked_sub(incoming).ok_or_else(|| {
                                ChainError::State(
                                    "insufficient spendable balance (same-block incoming locked)"
                                        .into(),
                                )
                            })?;
                        if effective_spendable < total_cost {
                            return Err(ChainError::State(format!(
                                "insufficient spendable balance: {effective_spendable} < {total_cost}"
                            )));
                        }

                        // Allowance window check
                        check_and_apply_allowance(sender, h, total_cost)?;

                        sender.nonce = sender
                            .nonce
                            .checked_add(1)
                            .ok_or_else(|| ChainError::State("nonce overflow".into()))?;
                        // Bounds guaranteed: spendable >= total_cost >= fee_atoms (checked above), so balance >= fee_atoms.
                        sender.balance -= fee_atoms;
                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;

                        let is_confirmed = candidate_confirmed.contains(&(sender_addr, recipient));
                        if sender.guardian_enabled
                            && !is_confirmed
                            && sender.new_recipient_delay > 0
                        {
                            // First-time recipient under guardian protection: locked in pending transfer
                            let mut inp = [0u8; 40];
                            inp[..32].copy_from_slice(tx_id.as_bytes());
                            inp[32..].copy_from_slice(b"/pending");
                            let pending_id = hash::hash(&inp);

                            let release_height = h
                                .checked_add(sender.new_recipient_delay as u64)
                                .ok_or_else(|| {
                                ChainError::State("release height overflow".into())
                            })?;

                            sender.pending_transfers.push(PendingTransfer {
                                transfer_id: pending_id,
                                recipient,
                                amount,
                                release_height,
                            });
                        } else {
                            // Immediate transfer (unprotected or previously confirmed recipient)
                            sender.balance =
                                sender.balance.checked_sub(amount).ok_or_else(|| {
                                    ChainError::State("sender balance underflow".into())
                                })?;
                            let rec = candidate_accounts.entry(recipient).or_default();
                            rec.balance = rec.balance.checked_add(amount).ok_or_else(|| {
                                ChainError::State("recipient balance overflow".into())
                            })?;

                            // Track direct Type 1 credit in same_block_incoming
                            let inc = same_block_incoming.entry(recipient).or_default();
                            *inc = inc.checked_add(amount).ok_or_else(|| {
                                ChainError::State("same-block incoming overflow".into())
                            })?;

                            // Schedule recipient confirmation for height h + 1 (after 1-block maturity)
                            let unlock_h = h.checked_add(1).ok_or_else(|| {
                                ChainError::State("transfer maturity height overflow".into())
                            })?;
                            candidate_pending_confirmations
                                .entry(unlock_h)
                                .or_default()
                                .push((sender_addr, recipient));
                        }
                    }

                    tx::TX_TYPE_CONFIGURE_GUARDIANS => {
                        if raw_tx.len() < 436 {
                            return Err(ChainError::State(
                                "truncated configure guardians payload".into(),
                            ));
                        }
                        let unsigned_prefix = &raw_tx[..371];
                        let owner_sig: [u8; 64] = raw_tx[371..435].try_into().unwrap();
                        let guardian_section = &raw_tx[435..];

                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        let mut account_key = [0u8; 32];
                        account_key.copy_from_slice(&payload[..32]);

                        let account_addr = derive_address(&account_key);

                        let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[40..48].try_into().unwrap()) as u128;

                        let min_fee = crate::tx::min_fee(raw_tx.len()).ok_or_else(|| {
                            ChainError::State("transaction too large for fee calculation".into())
                        })? as u128;
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below minimum".into()));
                        }

                        // Validate all 7 new guardian keys strictly and ensure uniqueness
                        let mut new_guardians = [[0u8; 32]; 7];
                        for i in 0..7 {
                            new_guardians[i]
                                .copy_from_slice(&payload[48 + i * 32..48 + (i + 1) * 32]);
                        }
                        crate::auth::validate_guardian_keys_set(&new_guardians).map_err(|e| {
                            ChainError::State(format!("invalid new guardian keys: {e}"))
                        })?;

                        let mut recovery_key = [0u8; 32];
                        recovery_key.copy_from_slice(&payload[304..336]);
                        crate::auth::validate_pubkey(&recovery_key)
                            .map_err(|e| ChainError::State(format!("invalid recovery key: {e}")))?;

                        // Parse guardian signature entries
                        let guardian_entries = crate::auth::parse_guardian_sigs(guardian_section)
                            .map_err(|e| {
                            ChainError::State(format!("malformed guardian signatures: {e}"))
                        })?;

                        // Canonical unsigned tx bytes binds declared quorum count and guardian indices
                        let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(
                            unsigned_prefix,
                            &guardian_entries,
                        );
                        let preimage =
                            crate::auth::compute_signing_preimage(self.chain_id, &unsigned_tx);

                        // Strict owner signature verification over canonical signing preimage
                        crate::auth::verify_signature(&account_key, &preimage, &owner_sig)
                            .map_err(|e| {
                                ChainError::State(format!(
                                    "owner signature verification failed: {e}"
                                ))
                            })?;

                        let account = candidate_accounts.entry(account_addr).or_default();

                        if account.is_frozen {
                            return Err(ChainError::State("account is frozen".into()));
                        }
                        if account.nonce != nonce {
                            return Err(ChainError::State("nonce mismatch".into()));
                        }
                        let spendable = account
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        let incoming = same_block_incoming.get(&account_addr).copied().unwrap_or(0);
                        let effective_spendable =
                            spendable.checked_sub(incoming).ok_or_else(|| {
                                ChainError::State(
                                    "insufficient spendable balance (same-block incoming locked)"
                                        .into(),
                                )
                            })?;
                        if effective_spendable < fee_atoms {
                            return Err(ChainError::State("insufficient balance for fee".into()));
                        }

                        // Allowance check for configuring account
                        check_and_apply_allowance(account, h, fee_atoms)?;

                        if account.guardian_enabled {
                            // Reconfiguration requires at least 4 distinct signatures from OLD guardians
                            crate::auth::verify_guardian_quorum(
                                &account.guardians,
                                &preimage,
                                &guardian_entries,
                                4,
                            )
                            .map_err(|e| {
                                ChainError::State(format!(
                                    "reconfiguration guardian verification failed: {e}"
                                ))
                            })?;
                        } else if !guardian_entries.is_empty() {
                            return Err(ChainError::State(
                                "initial guardian configuration must not carry guardian signatures"
                                    .into(),
                            ));
                        }

                        account.nonce = account
                            .nonce
                            .checked_add(1)
                            .ok_or_else(|| ChainError::State("nonce overflow".into()))?;
                        // Bounds guaranteed: spendable >= fee_atoms (checked above), so balance >= fee_atoms.
                        account.balance -= fee_atoms;
                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;

                        account.guardians = new_guardians;
                        account.new_recipient_delay =
                            u32::from_le_bytes(payload[272..276].try_into().unwrap());
                        account.withdrawal_delay =
                            u32::from_le_bytes(payload[276..280].try_into().unwrap());
                        account.allowance_limit =
                            u128::from_le_bytes(payload[280..296].try_into().unwrap());
                        account.allowance_window_len =
                            u64::from_le_bytes(payload[296..304].try_into().unwrap());
                        account.recovery_key = recovery_key;
                        account.guardian_enabled = true;
                    }

                    tx::TX_TYPE_GUARDIAN_ACTION => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 45 {
                            return Err(ChainError::State(
                                "truncated guardian action payload".into(),
                            ));
                        }
                        let target_addr = Hash::new(payload[..32].try_into().unwrap());
                        let action_type = payload[32];
                        let fee_atoms =
                            u64::from_le_bytes(payload[33..41].try_into().unwrap()) as u128;
                        let min_fee = crate::tx::min_fee(raw_tx.len()).ok_or_else(|| {
                            ChainError::State("transaction too large for fee calculation".into())
                        })? as u128;
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below minimum".into()));
                        }
                        let params_len =
                            u32::from_le_bytes(payload[41..45].try_into().unwrap()) as usize;
                        if payload.len() < 45 + params_len + 1 {
                            return Err(ChainError::State(
                                "truncated guardian action params".into(),
                            ));
                        }
                        let params = &payload[45..45 + params_len];

                        // Validate action type and exact parameter lengths
                        crate::auth::validate_guardian_action_params(action_type, params).map_err(
                            |e| ChainError::State(format!("invalid guardian action params: {e}")),
                        )?;

                        let unsigned_end = tx::TX_ENVELOPE_LEN + 45 + params_len;
                        let unsigned_prefix = &raw_tx[..unsigned_end];
                        let guardian_section = &raw_tx[unsigned_end..];

                        let guardian_entries = crate::auth::parse_guardian_sigs(guardian_section)
                            .map_err(|e| {
                            ChainError::State(format!("malformed guardian signatures: {e}"))
                        })?;

                        let req_quorum =
                            crate::auth::guardian_action_quorum(action_type).map_err(|e| {
                                ChainError::State(format!("invalid guardian action quorum: {e}"))
                            })?;

                        let target = candidate_accounts.get_mut(&target_addr).ok_or_else(|| {
                            ChainError::State("target account not found or has no guardians".into())
                        })?;
                        if !target.guardian_enabled {
                            return Err(ChainError::State(
                                "guardians not enabled on target account".into(),
                            ));
                        }

                        // Canonical unsigned tx bytes binds declared quorum count and guardian indices
                        let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(
                            unsigned_prefix,
                            &guardian_entries,
                        );
                        let preimage =
                            crate::auth::compute_signing_preimage(self.chain_id, &unsigned_tx);

                        // Cryptographic verification of guardian signatures over preimage
                        crate::auth::verify_guardian_quorum(
                            &target.guardians,
                            &preimage,
                            &guardian_entries,
                            req_quorum,
                        )
                        .map_err(|e| {
                            ChainError::State(format!("guardian quorum verification failed: {e}"))
                        })?;

                        let spendable = target
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        let incoming = same_block_incoming.get(&target_addr).copied().unwrap_or(0);
                        let effective_spendable =
                            spendable.checked_sub(incoming).ok_or_else(|| {
                                ChainError::State(
                                    "insufficient spendable balance (same-block incoming locked)"
                                        .into(),
                                )
                            })?;
                        if effective_spendable < fee_atoms {
                            return Err(ChainError::State("insufficient balance for fee".into()));
                        }

                        // Allowance check for target account paying the action fee
                        check_and_apply_allowance(target, h, fee_atoms)?;

                        // Bounds guaranteed: spendable >= fee_atoms (checked above), so balance >= fee_atoms.
                        target.balance -= fee_atoms;
                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;

                        match action_type {
                            crate::auth::ACTION_STRENGTHEN_DELAYS => {
                                // Strengthen delays: cannot decrease
                                let new_delay = u32::from_le_bytes(params[..4].try_into().unwrap());
                                if new_delay < target.new_recipient_delay {
                                    return Err(ChainError::State(
                                        "cannot decrease delay with 3-of-7 quorum".into(),
                                    ));
                                }
                                target.new_recipient_delay = new_delay;
                            }
                            crate::auth::ACTION_STRENGTHEN_ALLOWANCE => {
                                // Strengthen allowance: cannot increase limit or shorten window, cannot disable allowance
                                let new_lim = u128::from_le_bytes(params[..16].try_into().unwrap());
                                let new_len =
                                    u64::from_le_bytes(params[16..24].try_into().unwrap());
                                if new_lim == 0 || new_len == 0 {
                                    return Err(ChainError::State(
                                        "cannot disable allowance with 3-of-7 quorum".into(),
                                    ));
                                }
                                if target.allowance_limit > 0 && new_lim > target.allowance_limit {
                                    return Err(ChainError::State(
                                        "cannot increase limit with 3-of-7 quorum".into(),
                                    ));
                                }
                                if target.allowance_window_len > 0
                                    && new_len < target.allowance_window_len
                                {
                                    return Err(ChainError::State(
                                        "cannot shorten window with 3-of-7 quorum".into(),
                                    ));
                                }
                                target.allowance_limit = new_lim;
                                target.allowance_window_len = new_len;
                            }
                            crate::auth::ACTION_WEAKEN_DELAYS => {
                                // Weaken delays
                                target.new_recipient_delay =
                                    u32::from_le_bytes(params[..4].try_into().unwrap());
                            }
                            crate::auth::ACTION_WEAKEN_ALLOWANCE => {
                                // Weaken allowance
                                target.allowance_limit =
                                    u128::from_le_bytes(params[..16].try_into().unwrap());
                                target.allowance_window_len =
                                    u64::from_le_bytes(params[16..24].try_into().unwrap());
                            }
                            crate::auth::ACTION_FREEZE => target.is_frozen = true,
                            crate::auth::ACTION_UNFREEZE => target.is_frozen = false,
                            crate::auth::ACTION_EMERGENCY_RECOVERY => {
                                // Emergency recovery: transfer spendable balance to recovery key
                                let rec_addr = derive_address(&target.recovery_key);
                                let spendable = target.spendable_balance(h).map_err(|_| {
                                    ChainError::State("spendable balance error".into())
                                })?;
                                let incoming =
                                    same_block_incoming.get(&target_addr).copied().unwrap_or(0);
                                let recoverable = spendable.checked_sub(incoming).ok_or_else(|| {
                                    ChainError::State("insufficient spendable balance (same-block incoming locked)".into())
                                })?;
                                // Bounds guaranteed: recoverable = spendable_balance <= balance.
                                target.balance -= recoverable;
                                let rec = candidate_accounts.entry(rec_addr).or_default();
                                rec.balance =
                                    rec.balance.checked_add(recoverable).ok_or_else(|| {
                                        ChainError::State("recovery balance overflow".into())
                                    })?;
                            }
                            crate::auth::ACTION_REPLACE_GUARDIANS => {
                                let mut new_guardians = [[0u8; 32]; 7];
                                for i in 0..7 {
                                    new_guardians[i].copy_from_slice(&params[i * 32..(i + 1) * 32]);
                                }
                                crate::auth::validate_guardian_keys_set(&new_guardians).map_err(
                                    |e| {
                                        ChainError::State(format!(
                                            "invalid replacement guardian keys: {e}"
                                        ))
                                    },
                                )?;
                                target.guardians = new_guardians;
                            }
                            crate::auth::ACTION_REPLACE_RECOVERY_KEY => {
                                let mut new_rec = [0u8; 32];
                                new_rec.copy_from_slice(&params[..32]);
                                crate::auth::validate_pubkey(&new_rec).map_err(|e| {
                                    ChainError::State(format!(
                                        "invalid replacement recovery key: {e}"
                                    ))
                                })?;
                                target.recovery_key = new_rec;
                            }
                            _ => unreachable!(),
                        }
                    }

                    tx::TX_TYPE_CANCEL_PENDING => {
                        if raw_tx.len() < 180 {
                            return Err(ChainError::State(
                                "truncated cancel pending payload".into(),
                            ));
                        }
                        let unsigned_prefix = &raw_tx[..115];
                        let sender_sig: [u8; 64] = raw_tx[115..179].try_into().unwrap();
                        let guardian_section = &raw_tx[179..];

                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        let mut sender_key = [0u8; 32];
                        sender_key.copy_from_slice(&payload[..32]);

                        let sender_addr = derive_address(&sender_key);

                        let transfer_id = Hash::new(payload[32..64].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[64..72].try_into().unwrap()) as u128;
                        let min_fee = crate::tx::min_fee(raw_tx.len()).ok_or_else(|| {
                            ChainError::State("transaction too large for fee calculation".into())
                        })? as u128;
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below minimum".into()));
                        }
                        let nonce = u64::from_le_bytes(payload[72..80].try_into().unwrap());

                        let sender = candidate_accounts
                            .get_mut(&sender_addr)
                            .ok_or_else(|| ChainError::State("sender account not found".into()))?;
                        if sender.is_frozen {
                            return Err(ChainError::State("sender account is frozen".into()));
                        }
                        if !sender.guardian_enabled {
                            return Err(ChainError::State(
                                "sender account does not have guardians enabled".into(),
                            ));
                        }
                        if sender.nonce != nonce {
                            return Err(ChainError::State("nonce mismatch".into()));
                        }

                        // Parse guardian signature entries
                        let guardian_entries = crate::auth::parse_guardian_sigs(guardian_section)
                            .map_err(|e| {
                            ChainError::State(format!("malformed guardian signatures: {e}"))
                        })?;

                        // Canonical unsigned tx bytes binds declared quorum count and guardian indices
                        let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(
                            unsigned_prefix,
                            &guardian_entries,
                        );
                        let preimage =
                            crate::auth::compute_signing_preimage(self.chain_id, &unsigned_tx);

                        // Strict sender signature verification over canonical signing preimage
                        crate::auth::verify_signature(&sender_key, &preimage, &sender_sig)
                            .map_err(|e| {
                                ChainError::State(format!(
                                    "sender signature verification failed: {e}"
                                ))
                            })?;

                        // Strict 4-of-7 guardian quorum verification
                        crate::auth::verify_guardian_quorum(
                            &sender.guardians,
                            &preimage,
                            &guardian_entries,
                            4,
                        )
                        .map_err(|e| {
                            ChainError::State(format!("guardian quorum verification failed: {e}"))
                        })?;

                        let spendable = sender
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        let incoming = same_block_incoming.get(&sender_addr).copied().unwrap_or(0);
                        let effective_spendable =
                            spendable.checked_sub(incoming).ok_or_else(|| {
                                ChainError::State(
                                    "insufficient spendable balance (same-block incoming locked)"
                                        .into(),
                                )
                            })?;
                        if effective_spendable < fee_atoms {
                            return Err(ChainError::State("insufficient balance for fee".into()));
                        }

                        let found_idx = sender
                            .pending_transfers
                            .iter()
                            .position(|p| p.transfer_id == transfer_id)
                            .ok_or_else(|| {
                                ChainError::State("pending transfer not found".into())
                            })?;

                        // Allowance check for sender paying cancellation fee
                        check_and_apply_allowance(sender, h, fee_atoms)?;

                        sender.pending_transfers.remove(found_idx);
                        sender.nonce = sender
                            .nonce
                            .checked_add(1)
                            .ok_or_else(|| ChainError::State("nonce overflow".into()))?;
                        // Bounds guaranteed: spendable >= fee_atoms (checked above), so balance >= fee_atoms.
                        sender.balance -= fee_atoms;
                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;
                    }

                    tx::TX_TYPE_SHIELDED_TRANSFER => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 8 {
                            return Err(ChainError::State(
                                "truncated shielded transfer payload".into(),
                            ));
                        }
                        let fee_atoms =
                            u64::from_le_bytes(payload[..8].try_into().unwrap()) as u128;
                        let bundle = deserialize_bundle(&payload[8..])
                            .map_err(|e| ChainError::State(format!("bundle error: {e:?}")))?;

                        let anchor = Hash::new(bundle.anchor().to_bytes());
                        if !valid_anchors.contains(&anchor) {
                            return Err(ChainError::State(format!(
                                "anchor {} not in 10-block ancestor window",
                                anchor.to_hex()
                            )));
                        }

                        let mut tx_nfs = Vec::new();
                        for act in bundle.actions() {
                            let nf = Hash::new(act.nullifier().to_bytes());
                            if tx_nfs.contains(&nf) {
                                return Err(ChainError::State(
                                    "duplicate nullifier within transaction".into(),
                                ));
                            }
                            if candidate_nullifiers.contains(&nf) {
                                if self.nullifier_set.contains(&nf) {
                                    return Err(ChainError::State("nullifier double-spend".into()));
                                } else {
                                    return Err(ChainError::State(
                                        "nullifier double-spend: duplicate nullifier across transactions".into(),
                                    ));
                                }
                            }
                            tx_nfs.push(nf);
                        }

                        if candidate_pool_balance < fee_atoms {
                            return Err(ChainError::State(
                                "insufficient shielded pool balance for fee".into(),
                            ));
                        }

                        // Bounds guaranteed: candidate_pool_balance >= fee_atoms (checked above).
                        candidate_pool_balance -= fee_atoms;
                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;
                        candidate_nullifiers.extend(tx_nfs);

                        for act in bundle.actions() {
                            candidate_tree.append(act.cmx());
                        }
                    }

                    tx::TX_TYPE_TRANSPARENT_TO_SHIELDED => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 133 {
                            return Err(ChainError::State(
                                "truncated transparent-to-shielded payload".into(),
                            ));
                        }

                        let tx_version = u16::from_le_bytes(raw_tx[1..3].try_into().unwrap());

                        let mut sender_key = [0u8; 32];
                        sender_key.copy_from_slice(&payload[..32]);
                        crate::auth::parse_strict_pubkey(&sender_key).map_err(|e| {
                            ChainError::State(format!("invalid sender public key: {e}"))
                        })?;
                        let sender_addr = derive_address(&sender_key);

                        let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                        let shielded_amount =
                            u128::from_le_bytes(payload[40..56].try_into().unwrap());
                        if shielded_amount == 0 {
                            return Err(ChainError::State(
                                "shielded amount must be greater than zero".into(),
                            ));
                        }

                        let fee_atoms =
                            u64::from_le_bytes(payload[56..64].try_into().unwrap()) as u128;
                        let min_fee = crate::tx::min_fee(raw_tx.len()).ok_or_else(|| {
                            ChainError::State("transaction too large for fee calculation".into())
                        })? as u128;
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below minimum".into()));
                        }

                        let bundle_len =
                            u32::from_le_bytes(payload[64..68].try_into().unwrap()) as usize;
                        let fixed_prefix_len = 68usize;
                        let bundle_end = fixed_prefix_len
                            .checked_add(bundle_len)
                            .ok_or_else(|| ChainError::State("bundle length overflow".into()))?;
                        let sender_sig_end = bundle_end.checked_add(64).ok_or_else(|| {
                            ChainError::State("sender signature end overflow".into())
                        })?;

                        if payload.len() < sender_sig_end + 1 {
                            return Err(ChainError::State(
                                "truncated transparent-to-shielded bundle/signatures".into(),
                            ));
                        }

                        let bundle_bytes = &payload[fixed_prefix_len..bundle_end];
                        let bundle = deserialize_bundle(bundle_bytes)
                            .map_err(|e| ChainError::State(format!("bundle error: {e:?}")))?;

                        // Bundle structural consensus invariants
                        let n_actions = bundle.actions().len();
                        if n_actions == 0 || n_actions > crate::orchard_tx::MAX_ACTIONS_PER_TX {
                            return Err(ChainError::State(format!(
                                "invalid action count {n_actions}"
                            )));
                        }

                        if *bundle.flags() != orchard::bundle::Flags::SPENDS_DISABLED {
                            return Err(ChainError::State(
                                "Type 6 bundle must have SPENDS_DISABLED flags".into(),
                            ));
                        }

                        if *bundle.anchor() != orchard::tree::Anchor::empty_tree() {
                            return Err(ChainError::State(
                                "Type 6 bundle anchor must be empty tree root".into(),
                            ));
                        }

                        let vb = *bundle.value_balance();
                        if vb >= 0 {
                            return Err(ChainError::State(
                                "Type 6 value balance must be negative".into(),
                            ));
                        }

                        let expected_vb = -i64::try_from(shielded_amount).map_err(|_| {
                            ChainError::State("shielded amount exceeds i64 bounds".into())
                        })?;
                        if vb != expected_vb {
                            return Err(ChainError::State(format!(
                                "value balance mismatch: got {vb}, expected {expected_vb}"
                            )));
                        }

                        let mut sender_sig = [0u8; 64];
                        sender_sig.copy_from_slice(&payload[bundle_end..sender_sig_end]);

                        let guardian_section = &payload[sender_sig_end..];
                        let guardian_entries = crate::auth::parse_guardian_sigs(guardian_section)
                            .map_err(|e| {
                            ChainError::State(format!("malformed guardian signatures: {e}"))
                        })?;

                        // Compute cross-pool authorization digest
                        let auth_digest = crate::orchard_tx::compute_type6_bundle_auth_digest(
                            *self.chain_id.as_bytes(),
                            tx_version,
                            sender_key,
                            nonce,
                            shielded_amount,
                            fee_atoms as u64,
                            &bundle,
                        );

                        // Strict sender Ed25519 signature verification over auth_digest
                        crate::auth::verify_signature(&sender_key, &auth_digest, &sender_sig)
                            .map_err(|e| {
                                ChainError::State(format!(
                                    "sender signature verification failed: {e}"
                                ))
                            })?;

                        // Binding signature verification over auth_digest
                        bundle
                            .binding_validating_key()
                            .verify(&auth_digest, bundle.authorization().binding_signature())
                            .map_err(|_| {
                                ChainError::State("binding signature verification failed".into())
                            })?;

                        // Verify SpendAuth signatures on each action over auth_digest
                        for (idx, action) in bundle.actions().iter().enumerate() {
                            action
                                .rk()
                                .verify(&auth_digest, action.authorization())
                                .map_err(|_| {
                                    ChainError::State(format!(
                                        "spend auth signature verification failed for action {idx}"
                                    ))
                                })?;
                        }

                        // Nullifiers check (dummy spends under SPENDS_DISABLED must be tracked)
                        let mut tx_nfs = Vec::new();
                        for act in bundle.actions() {
                            let nf = Hash::new(act.nullifier().to_bytes());
                            if tx_nfs.contains(&nf) {
                                return Err(ChainError::State(
                                    "duplicate nullifier within transaction".into(),
                                ));
                            }
                            if candidate_nullifiers.contains(&nf) {
                                if self.nullifier_set.contains(&nf) {
                                    return Err(ChainError::State("nullifier double-spend".into()));
                                } else {
                                    return Err(ChainError::State(
                                        "nullifier double-spend: duplicate nullifier across transactions".into(),
                                    ));
                                }
                            }
                            tx_nfs.push(nf);
                        }

                        let sender = candidate_accounts
                            .get_mut(&sender_addr)
                            .ok_or_else(|| ChainError::State("sender account not found".into()))?;

                        if sender.is_frozen {
                            return Err(ChainError::State("sender account is frozen".into()));
                        }
                        if sender.nonce != nonce {
                            return Err(ChainError::State(format!(
                                "nonce mismatch: expected {}, got {}",
                                sender.nonce, nonce
                            )));
                        }

                        let total_cost = shielded_amount
                            .checked_add(fee_atoms)
                            .ok_or_else(|| ChainError::State("total cost overflow".into()))?;

                        let spendable = sender
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        let incoming = same_block_incoming.get(&sender_addr).copied().unwrap_or(0);
                        let effective_spendable =
                            spendable.checked_sub(incoming).ok_or_else(|| {
                                ChainError::State(
                                    "insufficient spendable balance (same-block incoming locked)"
                                        .into(),
                                )
                            })?;
                        if effective_spendable < total_cost {
                            return Err(ChainError::State(format!(
                                "insufficient spendable balance: {effective_spendable} < {total_cost}"
                            )));
                        }

                        // Allowance window check (for total_cost = shielded_amount + fee_atoms)
                        check_and_apply_allowance(sender, h, total_cost)?;

                        // Guardian authorization verification
                        if sender.guardian_enabled {
                            if guardian_entries.len() < 4 {
                                return Err(ChainError::State(
                                    "protected account requires at least 4 guardian signatures"
                                        .into(),
                                ));
                            }
                            crate::orchard_tx::verify_type6_guardian_signatures(
                                &auth_digest,
                                &guardian_entries,
                                &sender.guardians,
                            )
                            .map_err(|e| {
                                ChainError::State(format!("guardian verification failed: {e}"))
                            })?;
                        } else if !guardian_entries.is_empty() {
                            return Err(ChainError::State(
                                "unprotected account must not carry guardian signatures".into(),
                            ));
                        }

                        // State transitions
                        sender.nonce = sender
                            .nonce
                            .checked_add(1)
                            .ok_or_else(|| ChainError::State("nonce overflow".into()))?;

                        sender.balance = sender
                            .balance
                            .checked_sub(total_cost)
                            .ok_or_else(|| ChainError::State("sender balance underflow".into()))?;

                        candidate_pool_balance = candidate_pool_balance
                            .checked_add(shielded_amount)
                            .ok_or_else(|| {
                                ChainError::State("shielded pool balance overflow".into())
                            })?;

                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;

                        // Extend candidate nullifiers with action dummy nullifiers
                        candidate_nullifiers.extend(tx_nfs);

                        // Append output commitments to Orchard tree
                        for act in bundle.actions() {
                            candidate_tree.append(act.cmx());
                        }
                    }

                    tx::TX_TYPE_SHIELDED_TO_TRANSPARENT => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 60 {
                            return Err(ChainError::State(
                                "truncated shielded-to-transparent payload".into(),
                            ));
                        }

                        let tx_version = u16::from_le_bytes(raw_tx[1..3].try_into().unwrap());

                        let mut recipient_bytes = [0u8; 32];
                        recipient_bytes.copy_from_slice(&payload[..32]);
                        let recipient = Hash::new(recipient_bytes);

                        let release_amount =
                            u128::from_le_bytes(payload[32..48].try_into().unwrap());
                        if release_amount == 0 {
                            return Err(ChainError::State(
                                "release amount must be greater than zero".into(),
                            ));
                        }

                        let fee_atoms =
                            u64::from_le_bytes(payload[48..56].try_into().unwrap()) as u128;
                        let min_fee = crate::tx::min_fee(raw_tx.len()).ok_or_else(|| {
                            ChainError::State("transaction too large for fee calculation".into())
                        })? as u128;
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below minimum".into()));
                        }

                        let bundle_len =
                            u32::from_le_bytes(payload[56..60].try_into().unwrap()) as usize;
                        let expected_payload_len = 60usize
                            .checked_add(bundle_len)
                            .ok_or_else(|| ChainError::State("bundle length overflow".into()))?;
                        if payload.len() != expected_payload_len {
                            return Err(ChainError::State(
                                "invalid shielded-to-transparent bundle length or trailing bytes"
                                    .into(),
                            ));
                        }

                        let bundle_bytes = &payload[60..expected_payload_len];
                        let bundle = deserialize_bundle(bundle_bytes)
                            .map_err(|e| ChainError::State(format!("bundle error: {e:?}")))?;

                        // Bundle structural consensus invariants
                        let n_actions = bundle.actions().len();
                        if n_actions == 0 || n_actions > crate::orchard_tx::MAX_ACTIONS_PER_TX {
                            return Err(ChainError::State(format!(
                                "invalid action count {n_actions}"
                            )));
                        }

                        if !bundle.flags().spends_enabled() {
                            return Err(ChainError::State(
                                "Type 7 bundle must have spends enabled".into(),
                            ));
                        }

                        let vb = *bundle.value_balance();
                        if vb <= 0 {
                            return Err(ChainError::State(
                                "Type 7 value balance must be positive".into(),
                            ));
                        }

                        let total_deshield = release_amount
                            .checked_add(fee_atoms)
                            .ok_or_else(|| ChainError::State("total deshield overflow".into()))?;
                        let expected_vb = i64::try_from(total_deshield).map_err(|_| {
                            ChainError::State("total deshield exceeds i64 bounds".into())
                        })?;
                        if vb != expected_vb {
                            return Err(ChainError::State(format!(
                                "value balance mismatch: got {vb}, expected {expected_vb}"
                            )));
                        }

                        // Compute cross-pool authorization digest
                        let auth_digest = crate::orchard_tx::compute_type7_bundle_auth_digest(
                            *self.chain_id.as_bytes(),
                            tx_version,
                            recipient_bytes,
                            release_amount,
                            fee_atoms as u64,
                            &bundle,
                        );

                        // Verify SpendAuth signatures on each action over auth_digest
                        for (idx, action) in bundle.actions().iter().enumerate() {
                            action
                                .rk()
                                .verify(&auth_digest, action.authorization())
                                .map_err(|_| {
                                    ChainError::State(format!(
                                        "spend auth signature verification failed for action {idx}"
                                    ))
                                })?;
                        }

                        // Verify binding signature over auth_digest
                        bundle
                            .binding_validating_key()
                            .verify(&auth_digest, bundle.authorization().binding_signature())
                            .map_err(|_| {
                                ChainError::State("binding signature verification failed".into())
                            })?;

                        // Anchor verification against active 10-block ancestor window
                        let anchor = Hash::new(bundle.anchor().to_bytes());
                        if !valid_anchors.contains(&anchor) {
                            return Err(ChainError::State(format!(
                                "anchor {} not in 10-block ancestor window",
                                anchor.to_hex()
                            )));
                        }

                        // Nullifiers check (real and dummy)
                        let mut tx_nfs = Vec::new();
                        for act in bundle.actions() {
                            let nf = Hash::new(act.nullifier().to_bytes());
                            if tx_nfs.contains(&nf) {
                                return Err(ChainError::State(
                                    "duplicate nullifier within transaction".into(),
                                ));
                            }
                            if candidate_nullifiers.contains(&nf) {
                                if self.nullifier_set.contains(&nf) {
                                    return Err(ChainError::State("nullifier double-spend".into()));
                                } else {
                                    return Err(ChainError::State(
                                        "nullifier double-spend: duplicate nullifier across transactions".into(),
                                    ));
                                }
                            }
                            tx_nfs.push(nf);
                        }

                        // Shielded pool balance check
                        if candidate_pool_balance < total_deshield {
                            return Err(ChainError::State(format!(
                                "insufficient shielded pool balance: {candidate_pool_balance} < {total_deshield}"
                            )));
                        }

                        // State transitions
                        // 1. Debit shielded pool balance
                        candidate_pool_balance = candidate_pool_balance
                            .checked_sub(total_deshield)
                            .ok_or_else(|| {
                                ChainError::State("shielded pool balance underflow".into())
                            })?;

                        // 2. Credit transparent recipient
                        let rec = candidate_accounts.entry(recipient).or_default();
                        rec.balance = rec.balance.checked_add(release_amount).ok_or_else(|| {
                            ChainError::State("recipient balance overflow".into())
                        })?;

                        // 3. Record same-block incoming credit (locks funds from being spent in the same block)
                        let inc = same_block_incoming.entry(recipient).or_default();
                        *inc = inc.checked_add(release_amount).ok_or_else(|| {
                            ChainError::State("same-block incoming overflow".into())
                        })?;

                        // 4. Accumulate block fees
                        block_fees = block_fees.checked_add(fee_atoms).ok_or_else(|| {
                            ChainError::State("block fee accumulation overflow".into())
                        })?;

                        // 5. Extend candidate nullifiers
                        candidate_nullifiers.extend(tx_nfs);

                        // 6. Append every action's cmx commitment to Orchard tree
                        // (including dummy output commitments under Flags::OUTPUTS_DISABLED)
                        for act in bundle.actions() {
                            candidate_tree.append(act.cmx());
                        }
                    }

                    _ => {
                        return Err(ChainError::Invalid(ValidationError::MalformedTransaction {
                            index,
                            reason: format!("unknown transaction type tag {tag}"),
                        }));
                    }
                }

                if candidate_tx_ids.binary_search(&tx_id).is_err() {
                    candidate_tx_ids.push(tx_id);
                    candidate_tx_ids.sort_unstable();
                }
            }

            // D. Subsidy Claim & Cumulative Issuance Accounting
            let sched = scheduled_subsidy(h);
            // The coinbase payout must cover all aggregate block fees; the miner may only
            // claim the difference as subsidy. An underpayment (payout < fees) is invalid.
            let actual_claimed = coinbase_payout.checked_sub(block_fees).ok_or_else(|| {
                ChainError::State(format!(
                    "coinbase underpayment: payout {coinbase_payout} < aggregate block fees {block_fees}"
                ))
            })?;
            if actual_claimed > sched {
                return Err(ChainError::State(format!(
                    "claimed subsidy {actual_claimed} exceeds scheduled limit {sched}"
                )));
            }
            let new_issuance = candidate_issuance
                .checked_add(actual_claimed)
                .ok_or_else(|| ChainError::State("cumulative issuance overflow".into()))?;
            if new_issuance > MAX_SUPPLY_ATOMS {
                return Err(ChainError::State(
                    "cumulative issuance exceeds 21M OWN cap".into(),
                ));
            }
            candidate_issuance = new_issuance;

            // E. Global Monetary Conservation Invariant: T + S = I
            // Checked aggregation: account balances are summed with overflow protection.
            let mut t_total: u128 = 0;
            for acc in candidate_accounts.values() {
                t_total = t_total.checked_add(acc.balance).ok_or_else(|| {
                    ChainError::State("transparent balance aggregation overflow".into())
                })?;
            }
            let s_total = candidate_pool_balance;
            let i_total = candidate_issuance;
            let t_plus_s = t_total
                .checked_add(s_total)
                .ok_or_else(|| ChainError::State("T + S overflow".into()))?;
            if t_plus_s != i_total {
                return Err(ChainError::State(format!(
                    "monetary conservation violated: T({t_total}) + S({s_total}) = {t_plus_s} != I({i_total})"
                )));
            }

            candidate_anchors.insert(h, candidate_tree.root());
        }

        // F. Composite State Root Verification:
        let t_root = if candidate_accounts.is_empty() {
            state_empty_root()
        } else {
            let leaves: Vec<Vec<u8>> = candidate_accounts
                .iter()
                .map(|(addr, acc)| {
                    let mut leaf = Vec::with_capacity(32 + 342);
                    leaf.extend_from_slice(addr.as_bytes());
                    leaf.extend_from_slice(&acc.serialize());
                    leaf
                })
                .collect();
            state_merkle_root(&leaves)
        };
        let o_root = candidate_tree.root();
        let nf_root = {
            let nfs: Vec<Hash> = candidate_nullifiers.iter().copied().collect();
            nullifier_merkle_root(&nfs)
        };
        let s_comm = pool_balance_commitment(candidate_pool_balance);
        let computed_state_root = composite_state_root(&t_root, &o_root, &nf_root, &s_comm);

        Ok(CandidateStateTransition {
            accounts: candidate_accounts,
            nullifier_set: candidate_nullifiers,
            shielded_pool_balance: candidate_pool_balance,
            cumulative_issuance: candidate_issuance,
            orchard_tree: candidate_tree,
            historical_anchors: candidate_anchors,
            accepted_transaction_ids: candidate_tx_ids,
            confirmed_recipients: candidate_confirmed,
            pending_confirmations: candidate_pending_confirmations,
            computed_state_root,
            next_cumulative_work,
        })
    }

    /// Evaluates a candidate block and computes the candidate post-state transition without mutating the chain.
    ///
    /// Performs full candidate block validation before state evaluation.
    pub fn evaluate_candidate(
        &self,
        block: &Block,
    ) -> Result<CandidateStateTransition, ChainError> {
        self.validate_candidate(block)?;
        self.evaluate_candidate_validated(block)
    }

    /// Simulates block application and returns the expected post-state composite state root.
    ///
    /// Performs full candidate block validation before computing and returning the candidate state root.
    pub fn simulate_candidate_state_root(&self, block: &Block) -> Result<Hash, ChainError> {
        let cand = self.evaluate_candidate(block)?;
        Ok(cand.computed_state_root)
    }

    /// Validates and atomically accepts a candidate block.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), ChainError> {
        self.validate(block)?;
        let cand = self.evaluate_candidate_validated(block)?;

        // Header slot 6 holds composite state root.
        // Both genesis (h=0) and subsequent blocks (H >= 1) strictly require
        // exact equality with computed_state_root.
        if block.header.orchard_commitment_root != cand.computed_state_root {
            return Err(ChainError::Invalid(ValidationError::OrchardRootMismatch {
                computed: cand.computed_state_root,
                declared: block.header.orchard_commitment_root,
            }));
        }

        // 3. Atomically Commit Candidate State to Chain
        self.accounts = cand.accounts;
        self.nullifier_set = cand.nullifier_set;
        self.shielded_pool_balance = cand.shielded_pool_balance;
        self.cumulative_issuance = cand.cumulative_issuance;
        self.orchard_tree = cand.orchard_tree;
        self.historical_anchors = cand.historical_anchors;
        self.accepted_transaction_ids = cand.accepted_transaction_ids;
        self.confirmed_recipients = cand.confirmed_recipients;
        self.pending_confirmations = cand.pending_confirmations;

        self.cumulative_work.push(cand.next_cumulative_work);
        self.difficulty_samples
            .push(crate::difficulty::DifficultySample {
                height: block.header.height,
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
            });
        self.blocks.push(block.clone());

        // Save historical snapshot for reorg rollback
        self.history.insert(block.header.height, self.snapshot());

        Ok(())
    }

    /// Returns the IDs of every transaction accepted on the chain.
    pub fn accepted_transaction_ids(&self) -> &[Hash] {
        &self.accepted_transaction_ids
    }

    /// Returns the cumulative work through the current tip block.
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

    /// Computes the network-computed expected difficulty for a block extending the current tip.
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

    /// Returns the timestamps of the last `TIMESTAMP_WINDOW` ancestor blocks, oldest first.
    pub fn ancestor_timestamps(&self) -> Vec<u64> {
        // saturating_sub is safe: blocks.len() is bounded by chain length and clamping at 0
        // only yields an empty/small window for short chains.
        let start = self.blocks.len().saturating_sub(TIMESTAMP_WINDOW);
        self.blocks[start..]
            .iter()
            .map(|b| b.header.timestamp)
            .collect()
    }

    /// Returns the upper median of the ancestor timestamps.
    pub fn ancestor_median_timestamp(&self) -> Option<u64> {
        crate::validation::upper_median(&self.ancestor_timestamps())
    }
}
