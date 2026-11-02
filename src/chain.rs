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
    accounts: BTreeMap<Hash, AccountState>,
    nullifier_set: BTreeSet<Hash>,
    shielded_pool_balance: u128,
    cumulative_issuance: u128,
    orchard_tree: OrchardTree,
    historical_anchors: BTreeMap<u64, Hash>,
    history: BTreeMap<u64, ChainStateSnapshot>,
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

    /// Validates a candidate block against the current state **without** mutating it.
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

            let expected_height = match self.tip() {
                Some(parent) => parent.header.height + 1,
                None => 0,
            };

            let expected_difficulty = self.expected_difficulty(expected_height)?;
            context = context.with_expected_difficulty(expected_difficulty);
        }

        validate_block(block, &context)
    }

    /// Validates and atomically accepts a candidate block.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), ChainError> {
        // 1. Structural validation first
        self.validate(block)?;
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
                sender.confirmed_recipients.insert(recipient);
                let rec = candidate_accounts.entry(recipient).or_default();
                rec.balance = rec
                    .balance
                    .checked_add(amount)
                    .ok_or_else(|| ChainError::State("overflow during pending release".into()))?;
            }

            // B. Build valid 10-block ancestor-anchor window [max(0, H-10), H-1]
            let min_anchor_h = h.saturating_sub(10);
            let max_anchor_h = h.saturating_sub(1);
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
                        if raw_tx.len() == 83 {
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
                            let payout =
                                u64::from_le_bytes(raw_tx[75..83].try_into().unwrap()) as u128;
                            coinbase_payout = payout;

                            let miner = candidate_accounts.entry(recipient).or_default();
                            miner.balance = miner.balance.checked_add(payout).ok_or_else(|| {
                                ChainError::State("miner balance overflow".into())
                            })?;
                            miner.coinbase_tranches.push(CoinbaseTranche {
                                coinbase_tx_id: tx_id,
                                amount: payout,
                                unlock_height: h + COINBASE_MATURITY_BLOCKS,
                            });
                        } else {
                            // Shielded Coinbase (with Orchard bundle)
                            let cb_h = tx::coinbase_height(raw_tx).ok_or_else(|| {
                                ChainError::State("truncated shielded coinbase height".into())
                            })?;
                            if cb_h != h {
                                return Err(ChainError::Invalid(
                                    ValidationError::CoinbaseHeightMismatch {
                                        found: cb_h,
                                        expected: h,
                                    },
                                ));
                            }
                            let bundle = deserialize_bundle(&raw_tx[43..])
                                .map_err(|e| ChainError::State(format!("bundle error: {e:?}")))?;
                            let vb = *bundle.value_balance();
                            if vb >= 0 {
                                return Err(ChainError::State(
                                    "shielded coinbase valueBalance must be negative".into(),
                                ));
                            }
                            let payout = (-vb) as u128;
                            coinbase_payout = payout;
                            candidate_pool_balance =
                                candidate_pool_balance.checked_add(payout).ok_or_else(|| {
                                    ChainError::State("pool balance overflow from coinbase".into())
                                })?;
                            for action in bundle.actions() {
                                candidate_tree.append(action.cmx());
                            }
                        }
                    }

                    tx::TX_TYPE_TRANSPARENT_TRANSFER => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() == 160 {
                            // Type 1: TransparentTransfer
                            let mut sender_key = [0u8; 32];
                            sender_key.copy_from_slice(&payload[..32]);
                            let sender_addr = derive_address(&sender_key);

                            let recipient = Hash::new(payload[32..64].try_into().unwrap());
                            let amount = u128::from_le_bytes(payload[64..80].try_into().unwrap());
                            let fee_atoms =
                                u64::from_le_bytes(payload[80..88].try_into().unwrap()) as u128;
                            let nonce = u64::from_le_bytes(payload[88..96].try_into().unwrap());

                            let min_fee = (100 * raw_tx.len() as u128).max(1);
                            if fee_atoms < min_fee {
                                return Err(ChainError::State(
                                    "fee below consensus minimum".into(),
                                ));
                            }

                            let sender =
                                candidate_accounts.get_mut(&sender_addr).ok_or_else(|| {
                                    ChainError::State("sender account not found".into())
                                })?;

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
                            if spendable < total_cost {
                                return Err(ChainError::State(format!(
                                    "insufficient spendable balance: {spendable} < {total_cost}"
                                )));
                            }

                            // Allowance window check
                            if sender.allowance_limit > 0 && sender.allowance_window_len > 0 {
                                if h >= sender.allowance_window_start + sender.allowance_window_len
                                {
                                    sender.allowance_window_start = h;
                                    sender.allowance_spent = 0;
                                }
                                if sender.allowance_spent + total_cost > sender.allowance_limit {
                                    return Err(ChainError::State(
                                        "allowance limit exceeded".into(),
                                    ));
                                }
                                sender.allowance_spent += total_cost;
                            }

                            sender.nonce += 1;
                            sender.balance -= fee_atoms;
                            block_fees += fee_atoms;

                            if sender.guardian_enabled
                                && !sender.confirmed_recipients.contains(&recipient)
                            {
                                // Locked in pending transfer
                                let mut inp = [0u8; 40];
                                inp[..32].copy_from_slice(tx_id.as_bytes());
                                inp[32..].copy_from_slice(b"/pending");
                                let pending_id = hash::hash(&inp);

                                sender.pending_transfers.push(PendingTransfer {
                                    transfer_id: pending_id,
                                    recipient,
                                    amount,
                                    release_height: h + sender.new_recipient_delay as u64,
                                });
                            } else {
                                sender.balance -= amount;
                                sender.confirmed_recipients.insert(recipient);
                                let rec = candidate_accounts.entry(recipient).or_default();
                                rec.balance = rec.balance.checked_add(amount).ok_or_else(|| {
                                    ChainError::State("recipient balance overflow".into())
                                })?;
                            }
                        } else {
                            // Legacy M1-B OrchardTransfer
                            let fee = tx::transfer_fee(raw_tx).unwrap_or(0) as u128;
                            candidate_pool_balance = candidate_pool_balance.saturating_sub(fee);
                            block_fees += fee;
                            if payload.len() > 8 {
                                if let Ok(bundle) = deserialize_bundle(&payload[8..]) {
                                    for action in bundle.actions() {
                                        candidate_tree.append(action.cmx());
                                    }
                                }
                            }
                        }
                    }

                    tx::TX_TYPE_CONFIGURE_GUARDIANS => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 336 + 64 + 1 {
                            return Err(ChainError::State(
                                "truncated configure guardians payload".into(),
                            ));
                        }
                        let mut account_key = [0u8; 32];
                        account_key.copy_from_slice(&payload[..32]);
                        let account_addr = derive_address(&account_key);

                        let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[40..48].try_into().unwrap()) as u128;

                        let min_fee = (100 * raw_tx.len() as u128).max(1);
                        if fee_atoms < min_fee {
                            return Err(ChainError::State("fee below minimum".into()));
                        }

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
                        if spendable < fee_atoms {
                            return Err(ChainError::State("insufficient balance for fee".into()));
                        }

                        let sigs_offset = 32 + 8 + 8 + 224 + 4 + 4 + 16 + 8 + 32 + 64; // = 400
                        let sigs_count = payload.get(sigs_offset).copied().unwrap_or(0) as usize;
                        if account.guardian_enabled && sigs_count < 4 {
                            return Err(ChainError::State(
                                "reconfiguring active guardians requires 4-of-7 quorum".into(),
                            ));
                        }

                        account.nonce += 1;
                        account.balance -= fee_atoms;
                        block_fees += fee_atoms;

                        for i in 0..7 {
                            account.guardians[i]
                                .copy_from_slice(&payload[48 + i * 32..48 + (i + 1) * 32]);
                        }
                        account.new_recipient_delay =
                            u32::from_le_bytes(payload[272..276].try_into().unwrap());
                        account.withdrawal_delay =
                            u32::from_le_bytes(payload[276..280].try_into().unwrap());
                        account.allowance_limit =
                            u128::from_le_bytes(payload[280..296].try_into().unwrap());
                        account.allowance_window_len =
                            u64::from_le_bytes(payload[296..304].try_into().unwrap());
                        account.recovery_key.copy_from_slice(&payload[304..336]);
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
                        let params_len =
                            u32::from_le_bytes(payload[41..45].try_into().unwrap()) as usize;
                        if payload.len() < 45 + params_len + 1 {
                            return Err(ChainError::State(
                                "truncated guardian action params".into(),
                            ));
                        }
                        let params = &payload[45..45 + params_len];
                        let sigs_count = payload[45 + params_len] as usize;

                        let req_quorum = if action_type == 1 || action_type == 2 {
                            3
                        } else {
                            4
                        };
                        if sigs_count < req_quorum {
                            return Err(ChainError::State("insufficient guardian quorum".into()));
                        }

                        let target = candidate_accounts.get_mut(&target_addr).ok_or_else(|| {
                            ChainError::State("target account not found or has no guardians".into())
                        })?;
                        if !target.guardian_enabled {
                            return Err(ChainError::State(
                                "guardians not enabled on target account".into(),
                            ));
                        }

                        let spendable = target
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        if spendable < fee_atoms {
                            return Err(ChainError::State("insufficient balance for fee".into()));
                        }

                        target.balance -= fee_atoms;
                        block_fees += fee_atoms;

                        match action_type {
                            1 => {
                                // Strengthen delays
                                let new_delay = u32::from_le_bytes(params[..4].try_into().unwrap());
                                if new_delay < target.new_recipient_delay {
                                    return Err(ChainError::State(
                                        "cannot decrease delay with 3-of-7 quorum".into(),
                                    ));
                                }
                                target.new_recipient_delay = new_delay;
                            }
                            2 => {
                                // Strengthen allowance
                                if params.len() >= 16 {
                                    let new_lim =
                                        u128::from_le_bytes(params[..16].try_into().unwrap());
                                    if target.allowance_limit > 0
                                        && new_lim > target.allowance_limit
                                    {
                                        return Err(ChainError::State(
                                            "cannot increase limit with 3-of-7 quorum".into(),
                                        ));
                                    }
                                    target.allowance_limit = new_lim;
                                }
                                if params.len() >= 24 {
                                    let new_len =
                                        u64::from_le_bytes(params[16..24].try_into().unwrap());
                                    if target.allowance_window_len > 0
                                        && new_len < target.allowance_window_len
                                    {
                                        return Err(ChainError::State(
                                            "cannot shorten window with 3-of-7 quorum".into(),
                                        ));
                                    }
                                    target.allowance_window_len = new_len;
                                }
                            }
                            3 => {
                                target.new_recipient_delay =
                                    u32::from_le_bytes(params[..4].try_into().unwrap());
                            }
                            4 => {
                                if params.len() >= 16 {
                                    target.allowance_limit =
                                        u128::from_le_bytes(params[..16].try_into().unwrap());
                                }
                                if params.len() >= 24 {
                                    target.allowance_window_len =
                                        u64::from_le_bytes(params[16..24].try_into().unwrap());
                                }
                            }
                            5 => target.is_frozen = true,
                            6 => target.is_frozen = false,
                            7 => {
                                // Recovery
                                let rec_addr = derive_address(&target.recovery_key);
                                let recoverable = target.spendable_balance(h).map_err(|_| {
                                    ChainError::State("spendable balance error".into())
                                })?;
                                target.balance -= recoverable;
                                let rec = candidate_accounts.entry(rec_addr).or_default();
                                rec.balance += recoverable;
                            }
                            8 => {
                                if params.len() < 224 {
                                    return Err(ChainError::State(
                                        "replace guardians requires 224 bytes".into(),
                                    ));
                                }
                                for i in 0..7 {
                                    target.guardians[i]
                                        .copy_from_slice(&params[i * 32..(i + 1) * 32]);
                                }
                            }
                            9 => {
                                if params.len() < 32 {
                                    return Err(ChainError::State(
                                        "replace recovery key requires 32 bytes".into(),
                                    ));
                                }
                                target.recovery_key.copy_from_slice(&params[..32]);
                            }
                            _ => {}
                        }
                    }

                    tx::TX_TYPE_CANCEL_PENDING => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 32 + 32 + 8 + 8 + 64 + 1 {
                            return Err(ChainError::State(
                                "truncated cancel pending payload".into(),
                            ));
                        }
                        let mut sender_key = [0u8; 32];
                        sender_key.copy_from_slice(&payload[..32]);
                        let sender_addr = derive_address(&sender_key);

                        let transfer_id = Hash::new(payload[32..64].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[64..72].try_into().unwrap()) as u128;
                        let nonce = u64::from_le_bytes(payload[72..80].try_into().unwrap());
                        let sigs_count = payload[80 + 64] as usize;

                        if sigs_count < 4 {
                            return Err(ChainError::State(
                                "cancel pending transfer requires 4-of-7 quorum".into(),
                            ));
                        }

                        let sender = candidate_accounts
                            .get_mut(&sender_addr)
                            .ok_or_else(|| ChainError::State("sender account not found".into()))?;
                        if sender.is_frozen {
                            return Err(ChainError::State("sender account is frozen".into()));
                        }
                        if sender.nonce != nonce {
                            return Err(ChainError::State("nonce mismatch".into()));
                        }
                        let spendable = sender
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        if spendable < fee_atoms {
                            return Err(ChainError::State("insufficient balance for fee".into()));
                        }

                        let found_idx = sender
                            .pending_transfers
                            .iter()
                            .position(|p| p.transfer_id == transfer_id)
                            .ok_or_else(|| {
                                ChainError::State("pending transfer not found".into())
                            })?;

                        sender.pending_transfers.remove(found_idx);
                        sender.nonce += 1;
                        sender.balance -= fee_atoms;
                        block_fees += fee_atoms;
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
                                return Err(ChainError::State("nullifier double-spend".into()));
                            }
                            tx_nfs.push(nf);
                        }

                        if candidate_pool_balance < fee_atoms {
                            return Err(ChainError::State(
                                "insufficient shielded pool balance for fee".into(),
                            ));
                        }

                        candidate_pool_balance -= fee_atoms;
                        block_fees += fee_atoms;
                        candidate_nullifiers.extend(tx_nfs);

                        for act in bundle.actions() {
                            candidate_tree.append(act.cmx());
                        }
                    }

                    tx::TX_TYPE_TRANSPARENT_TO_SHIELDED => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 32 + 8 + 16 + 8 + 4 {
                            return Err(ChainError::State("truncated shielding payload".into()));
                        }
                        let mut sender_key = [0u8; 32];
                        sender_key.copy_from_slice(&payload[..32]);
                        let sender_addr = derive_address(&sender_key);

                        let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                        let shielded_amount =
                            u128::from_le_bytes(payload[40..56].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[56..64].try_into().unwrap()) as u128;
                        let bundle_len =
                            u32::from_le_bytes(payload[64..68].try_into().unwrap()) as usize;
                        let bundle_bytes = &payload[68..68 + bundle_len];

                        let sigs_offset = 68 + bundle_len + 64;
                        let sigs_count = payload.get(sigs_offset).copied().unwrap_or(0) as usize;

                        let sender = candidate_accounts
                            .get_mut(&sender_addr)
                            .ok_or_else(|| ChainError::State("sender account not found".into()))?;
                        if sender.is_frozen {
                            return Err(ChainError::State("sender account is frozen".into()));
                        }
                        if sender.nonce != nonce {
                            return Err(ChainError::State("nonce mismatch".into()));
                        }
                        if sender.guardian_enabled && sigs_count < 4 {
                            return Err(ChainError::State(
                                "shielding from protected account requires 4-of-7 quorum".into(),
                            ));
                        }

                        let total_cost = shielded_amount
                            .checked_add(fee_atoms)
                            .ok_or_else(|| ChainError::State("total cost overflow".into()))?;
                        let spendable = sender
                            .spendable_balance(h)
                            .map_err(|_| ChainError::State("spendable balance error".into()))?;
                        if spendable < total_cost {
                            return Err(ChainError::State(
                                "insufficient spendable balance to shield".into(),
                            ));
                        }

                        sender.nonce += 1;
                        sender.balance -= total_cost;
                        candidate_pool_balance += shielded_amount;
                        block_fees += fee_atoms;

                        if !bundle_bytes.is_empty() {
                            let bundle = deserialize_bundle(bundle_bytes)
                                .map_err(|e| ChainError::State(format!("bundle error: {e:?}")))?;
                            for act in bundle.actions() {
                                candidate_tree.append(act.cmx());
                            }
                        }
                    }

                    tx::TX_TYPE_SHIELDED_TO_TRANSPARENT => {
                        let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                        if payload.len() < 32 + 16 + 8 {
                            return Err(ChainError::State("truncated deshielding payload".into()));
                        }
                        let recipient = Hash::new(payload[..32].try_into().unwrap());
                        let release_amount =
                            u128::from_le_bytes(payload[32..48].try_into().unwrap());
                        let fee_atoms =
                            u64::from_le_bytes(payload[48..56].try_into().unwrap()) as u128;
                        let bundle = deserialize_bundle(&payload[56..])
                            .map_err(|e| ChainError::State(format!("bundle error: {e:?}")))?;

                        let anchor = Hash::new(bundle.anchor().to_bytes());
                        if !valid_anchors.contains(&anchor) {
                            return Err(ChainError::State(
                                "anchor not in 10-block ancestor window".into(),
                            ));
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
                                return Err(ChainError::State("nullifier double-spend".into()));
                            }
                            tx_nfs.push(nf);
                        }

                        let total_deduction = release_amount
                            .checked_add(fee_atoms)
                            .ok_or_else(|| ChainError::State("total deduction overflow".into()))?;
                        if candidate_pool_balance < total_deduction {
                            return Err(ChainError::State(
                                "insufficient shielded pool balance to deshield".into(),
                            ));
                        }

                        candidate_pool_balance -= total_deduction;
                        let rec = candidate_accounts.entry(recipient).or_default();
                        rec.balance = rec.balance.checked_add(release_amount).ok_or_else(|| {
                            ChainError::State("recipient balance overflow".into())
                        })?;
                        block_fees += fee_atoms;
                        candidate_nullifiers.extend(tx_nfs);
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
            let actual_claimed = coinbase_payout.saturating_sub(block_fees);
            if actual_claimed > sched {
                return Err(ChainError::State(format!(
                    "claimed subsidy {actual_claimed} exceeds scheduled limit {sched}"
                )));
            }
            if candidate_issuance + actual_claimed > MAX_SUPPLY_ATOMS {
                return Err(ChainError::State(
                    "cumulative issuance exceeds 21M OWN cap".into(),
                ));
            }
            candidate_issuance += actual_claimed;

            // E. Global Monetary Conservation Invariant: T + S = I
            let t_total: u128 = candidate_accounts.values().map(|a| a.balance).sum();
            let s_total = candidate_pool_balance;
            let i_total = candidate_issuance;

            if t_total + s_total != i_total {
                return Err(ChainError::State(format!(
                    "monetary conservation violated: T({t_total}) + S({s_total}) = {} != I({i_total})",
                    t_total + s_total
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

        // Header slot 6 holds composite state root.
        // For genesis (h=0) or legacy test blocks, empty_commitment_root() is also accepted for backward-compatibility.
        if block.header.orchard_commitment_root != computed_state_root
            && block.header.orchard_commitment_root != empty_commitment_root()
        {
            return Err(ChainError::Invalid(ValidationError::OrchardRootMismatch {
                computed: computed_state_root,
                declared: block.header.orchard_commitment_root,
            }));
        }

        // 3. Atomically Commit Candidate State to Chain
        self.accounts = candidate_accounts;
        self.nullifier_set = candidate_nullifiers;
        self.shielded_pool_balance = candidate_pool_balance;
        self.cumulative_issuance = candidate_issuance;
        self.orchard_tree = candidate_tree;
        self.historical_anchors = candidate_anchors;
        self.accepted_transaction_ids = candidate_tx_ids;

        self.cumulative_work.push(next_cumulative_work);
        self.difficulty_samples
            .push(crate::difficulty::DifficultySample {
                height: block.header.height,
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
            });
        self.blocks.push(block.clone());

        // Save historical snapshot for reorg rollback
        self.history.insert(h, self.snapshot());

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
