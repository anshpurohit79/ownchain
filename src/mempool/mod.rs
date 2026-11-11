//! Mempool: bounded pending transaction management and admission.
//!
//! Enforces canonical decoding, network chain ID validation, exact minimum fees,
//! stateless cryptographic verification, stateful nonce and spendable-balance checks,
//! 10-block Orchard anchor window policy, nullifier conflict detection, and
//! automatic revalidation after block inclusion or reorganization.

use std::collections::{BTreeMap, BTreeSet};

use crate::account::{derive_address, AccountState};
use crate::chain::ChainState;
use crate::hash::{self, Hash};
use crate::orchard_tx::{
    compute_type6_bundle_auth_digest, compute_type7_bundle_auth_digest, deserialize_bundle,
    validate_bundle_stateless, verifying_key, BundleCodecError, OrchardValidationError,
};
use crate::tx::{self, min_fee, parse_envelope, transaction_fee, EnvelopeError, TxType};

/// Default maximum number of transactions allowed in the mempool.
pub const DEFAULT_MAX_MEMPOOL_TRANSACTIONS: usize = 5_000;

/// Default maximum cumulative memory usage (in bytes) allowed for the mempool.
pub const DEFAULT_MAX_MEMPOOL_BYTES: usize = 10_000_000;

/// Configuration parameters for the mempool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MempoolConfig {
    /// Maximum count of admitted transactions.
    pub max_transactions: usize,
    /// Maximum total serialized byte size of admitted transactions.
    pub max_bytes: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: DEFAULT_MAX_MEMPOOL_TRANSACTIONS,
            max_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
        }
    }
}

/// Errors that prevent transaction admission into the mempool.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MempoolError {
    /// Invalid transaction envelope.
    Envelope(EnvelopeError),
    /// Coinbase transactions cannot be admitted to the mempool.
    CoinbaseForbidden,
    /// Transaction fee is below protocol minimum fee.
    FeeBelowMinimum { fee: u64, min: u64 },
    /// Transaction already exists in the mempool.
    AlreadyInMempool(Hash),
    /// Transaction has already been included on the active chain.
    AlreadyOnChain(Hash),
    /// Mempool transaction count or byte capacity exceeded.
    MempoolFull,
    /// Sender transparent account does not exist or has zero balance.
    AccountNotFound(Hash),
    /// Sender transparent account is frozen by guardians.
    AccountFrozen(Hash),
    /// Account nonce has been exhausted (reached u64::MAX).
    NonceExhausted(Hash),
    /// Nonce mismatch or conflicting pending nonce.
    ConflictingNonce {
        account: Hash,
        expected: u64,
        found: u64,
    },
    /// Insufficient spendable balance to cover amount and fees.
    InsufficientSpendableBalance {
        account: Hash,
        spendable: u128,
        required: u128,
    },
    /// Spend allowance exceeded for active window.
    AllowanceExceeded(String),
    /// Cryptographic signature verification failed.
    InvalidSignature(String),
    /// Orchard bundle decoding error.
    BundleCodec(BundleCodecError),
    /// Orchard stateless validation error (proof or signature).
    OrchardValidation(OrchardValidationError),
    /// Orchard anchor is outside the active 10-block ancestor window.
    StaleAnchor(Hash),
    /// Nullifier has already been spent on-chain.
    NullifierAlreadySpent(Hash),
    /// Nullifier conflicts with another pending transaction in the mempool.
    ConflictingNullifier { nullifier: Hash, existing_tx: Hash },
    /// Duplicate nullifier within the same transaction.
    DuplicateNullifierInTx(Hash),
    /// Value balance mismatch.
    ValueBalanceMismatch { value_balance: i64, expected: i64 },
    /// Total deshield amount exceeds shielded pool balance.
    InsufficientShieldedPoolBalance { available: u128, required: u128 },
    /// Pending transfer is already targeted for cancellation by another pending transaction.
    ConflictingCancellation {
        transfer_id: Hash,
        existing_tx: Hash,
    },
    /// Sender account is locked by an active pending governance action.
    AccountLockedByPendingGovernance(Hash),
    /// Account already has a conflicting pending governance action or conflicting pending activity.
    PendingGovernanceConflict { account: Hash, existing_tx: Hash },
    /// Malformed transaction payload or guardian signatures.
    Malformed(String),
}

impl core::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MempoolError::Envelope(e) => write!(f, "invalid envelope: {e}"),
            MempoolError::CoinbaseForbidden => write!(f, "coinbase transactions cannot enter mempool"),
            MempoolError::FeeBelowMinimum { fee, min } => {
                write!(f, "fee {fee} below minimum required {min}")
            }
            MempoolError::AlreadyInMempool(h) => write!(f, "transaction {h} already in mempool"),
            MempoolError::AlreadyOnChain(h) => write!(f, "transaction {h} already on chain"),
            MempoolError::MempoolFull => write!(f, "mempool capacity exceeded"),
            MempoolError::AccountNotFound(a) => write!(f, "account {a} not found"),
            MempoolError::AccountFrozen(a) => write!(f, "account {a} is frozen"),
            MempoolError::NonceExhausted(a) => write!(f, "nonce exhausted for account {a}"),
            MempoolError::ConflictingNonce {
                account,
                expected,
                found,
            } => write!(
                f,
                "nonce conflict for account {account}: expected {expected}, found {found}"
            ),
            MempoolError::InsufficientSpendableBalance {
                account,
                spendable,
                required,
            } => write!(
                f,
                "insufficient spendable balance for {account}: spendable {spendable}, required {required}"
            ),
            MempoolError::AllowanceExceeded(s) => write!(f, "allowance exceeded: {s}"),
            MempoolError::InvalidSignature(s) => write!(f, "invalid signature: {s}"),
            MempoolError::BundleCodec(e) => write!(f, "bundle codec error: {e:?}"),
            MempoolError::OrchardValidation(e) => write!(f, "orchard validation error: {e:?}"),
            MempoolError::StaleAnchor(a) => write!(f, "stale anchor {a} outside 10-block window"),
            MempoolError::NullifierAlreadySpent(n) => write!(f, "nullifier {n} already spent on chain"),
            MempoolError::ConflictingNullifier {
                nullifier,
                existing_tx,
            } => write!(
                f,
                "nullifier {nullifier} conflicts with pending tx {existing_tx}"
            ),
            MempoolError::DuplicateNullifierInTx(nf) => {
                write!(f, "duplicate nullifier {nf} within transaction")
            }
            MempoolError::ValueBalanceMismatch {
                value_balance,
                expected,
            } => write!(
                f,
                "value balance mismatch: got {value_balance}, expected {expected}"
            ),
            MempoolError::InsufficientShieldedPoolBalance {
                available,
                required,
            } => write!(
                f,
                "insufficient shielded pool balance: available {available}, required {required}"
            ),
            MempoolError::ConflictingCancellation {
                transfer_id,
                existing_tx,
            } => write!(
                f,
                "transfer {transfer_id} is already targeted for cancellation by pending tx {existing_tx}"
            ),
            MempoolError::AccountLockedByPendingGovernance(a) => {
                write!(f, "account {a} is locked by pending governance action")
            }
            MempoolError::PendingGovernanceConflict {
                account,
                existing_tx,
            } => write!(
                f,
                "governance conflict for account {account}: existing pending tx {existing_tx}"
            ),
            MempoolError::Malformed(s) => write!(f, "malformed transaction: {s}"),
        }
    }
}

impl std::error::Error for MempoolError {}

impl From<EnvelopeError> for MempoolError {
    fn from(e: EnvelopeError) -> Self {
        MempoolError::Envelope(e)
    }
}

impl From<BundleCodecError> for MempoolError {
    fn from(e: BundleCodecError) -> Self {
        MempoolError::BundleCodec(e)
    }
}

impl From<OrchardValidationError> for MempoolError {
    fn from(e: OrchardValidationError) -> Self {
        MempoolError::OrchardValidation(e)
    }
}

/// Represents an active pending governance lock on an account.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GovernanceLock {
    pub tx_id: Hash,
    pub tx_type: TxType,
    pub action_type: Option<u8>,
}

impl GovernanceLock {
    /// Returns true if this lock represents an emergency security action (Freeze or Emergency Recovery).
    pub fn is_emergency(&self) -> bool {
        self.tx_type == TxType::GuardianAction
            && matches!(
                self.action_type,
                Some(crate::auth::ACTION_FREEZE) | Some(crate::auth::ACTION_EMERGENCY_RECOVERY)
            )
    }
}

/// Metadata recorded for an admitted transaction.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct AdmittedTxMeta {
    tx_type: TxType,
    size: usize,
    fee: u64,
    sender_account: Option<Hash>,
    account_nonce: Option<u64>,
    account_spend: u128,
    nullifiers: Vec<Hash>,
    shielded_drain: u128,
    cancellation_target: Option<Hash>,
    allowance_consumption: u128,
    governance_lock: Option<Hash>,
}

/// A transaction memory pool for valid unconfirmed transactions.
pub struct Mempool {
    config: MempoolConfig,
    /// Admitted transactions indexed by transaction ID.
    transactions: BTreeMap<Hash, Vec<u8>>,
    /// Metadata for admitted transactions.
    tx_meta: BTreeMap<Hash, AdmittedTxMeta>,
    /// Insertion order for FIFO / tie-break tracking.
    insertion_order: Vec<Hash>,
    /// Total bytes of raw transactions currently stored.
    total_bytes: usize,
    /// Pending nonces tracked per account: `account -> set of nonces`.
    account_nonces: BTreeMap<Hash, BTreeSet<u64>>,
    /// Pending transparent spend (amount + fee) tracked per account.
    account_spends: BTreeMap<Hash, u128>,
    /// Pending allowance spend tracked per account.
    account_allowance_reservations: BTreeMap<Hash, u128>,
    /// Pending nullifiers mapped to the transaction ID that spends them.
    mempool_nullifiers: BTreeMap<Hash, Hash>,
    /// Total drain currently pending against the shielded pool (Type 5 fees + Type 7 deshields).
    total_pending_shielded_drain: u128,
    /// Pending cancellation targets mapped to the transaction ID that targets them: transfer_id -> tx_id.
    cancellation_targets: BTreeMap<Hash, Hash>,
    /// Active governance locks per account: target_account -> GovernanceLock.
    pending_governance_locks: BTreeMap<Hash, GovernanceLock>,
}

impl Mempool {
    /// Creates a new mempool with default configuration.
    pub fn new() -> Self {
        Self::with_config(MempoolConfig::default())
    }

    /// Creates a new mempool with custom configuration.
    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            config,
            transactions: BTreeMap::new(),
            tx_meta: BTreeMap::new(),
            insertion_order: Vec::new(),
            total_bytes: 0,
            account_nonces: BTreeMap::new(),
            account_spends: BTreeMap::new(),
            account_allowance_reservations: BTreeMap::new(),
            mempool_nullifiers: BTreeMap::new(),
            total_pending_shielded_drain: 0,
            cancellation_targets: BTreeMap::new(),
            pending_governance_locks: BTreeMap::new(),
        }
    }

    /// Returns the number of transactions currently in the mempool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns `true` if the mempool contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns the total serialized byte size of transactions in the mempool.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Checks if a transaction ID is present in the mempool.
    pub fn contains(&self, tx_id: &Hash) -> bool {
        self.transactions.contains_key(tx_id)
    }

    /// Returns the pending allowance reservation for an account.
    pub fn pending_allowance_reservation(&self, account: &Hash) -> u128 {
        self.account_allowance_reservations
            .get(account)
            .copied()
            .unwrap_or(0)
    }

    /// Returns the total pending drain on the shielded pool.
    pub fn total_pending_shielded_drain(&self) -> u128 {
        self.total_pending_shielded_drain
    }

    /// Checks if a pending transfer ID is currently reserved by a pending Type 4 cancellation.
    pub fn is_cancellation_target_reserved(&self, transfer_id: &Hash) -> bool {
        self.cancellation_targets.contains_key(transfer_id)
    }

    /// Returns the active governance lock for an account, if one exists.
    pub fn governance_lock(&self, account: &Hash) -> Option<&GovernanceLock> {
        self.pending_governance_locks.get(account)
    }

    /// Checks if an account currently has an active pending governance lock.
    pub fn is_account_governance_locked(&self, account: &Hash) -> bool {
        self.pending_governance_locks.contains_key(account)
    }

    /// Returns the transaction ID of any pending transaction associated with `account` (originating or lock).
    fn find_pending_account_tx(&self, account: &Hash) -> Option<Hash> {
        if let Some(lock) = self.pending_governance_locks.get(account) {
            return Some(lock.tx_id);
        }
        for (tx_id, meta) in &self.tx_meta {
            if meta.sender_account == Some(*account) {
                return Some(*tx_id);
            }
        }
        None
    }

    /// Retrieves canonical bytes for a pending transaction by its ID.
    pub fn get(&self, tx_id: &Hash) -> Option<&[u8]> {
        self.transactions.get(tx_id).map(|v| v.as_slice())
    }

    /// Returns all transaction IDs currently in the mempool.
    pub fn transaction_ids(&self) -> Vec<Hash> {
        self.transactions.keys().copied().collect()
    }

    /// Returns all raw transactions currently in the mempool, in insertion order.
    pub fn all_transactions(&self) -> Vec<Vec<u8>> {
        self.insertion_order
            .iter()
            .filter_map(|id| self.transactions.get(id).cloned())
            .collect()
    }

    /// Validates and admits a transaction into the mempool.
    ///
    /// The transaction is validated against the active consensus state and checked
    /// for conflicts against other pending transactions. Admitting a transaction does
    /// not mutate the chain state.
    pub fn admit(&mut self, raw_tx: &[u8], chain_state: &ChainState) -> Result<Hash, MempoolError> {
        let tx_id = hash::transaction_id(raw_tx);

        if self.transactions.contains_key(&tx_id) {
            return Err(MempoolError::AlreadyInMempool(tx_id));
        }

        if chain_state
            .accepted_transaction_ids()
            .binary_search(&tx_id)
            .is_ok()
        {
            return Err(MempoolError::AlreadyOnChain(tx_id));
        }

        // Envelope validation
        let env = parse_envelope(raw_tx, chain_state.chain_id())?;

        if env.tx_type == TxType::Coinbase {
            return Err(MempoolError::CoinbaseForbidden);
        }

        // Minimum fee validation
        let fee = transaction_fee(raw_tx)
            .ok_or_else(|| MempoolError::Malformed("unable to read transaction fee".into()))?;
        let min = min_fee(raw_tx.len())
            .ok_or_else(|| MempoolError::Malformed("transaction too large for fee rules".into()))?;
        if fee < min {
            return Err(MempoolError::FeeBelowMinimum { fee, min });
        }

        // Cheap preliminary capacity gate for ordinary (non-emergency) transactions.
        // Potential emergency transactions (Type 3 ACTION_FREEZE or ACTION_EMERGENCY_RECOVERY)
        // bypass this preliminary check because they may evict conflicting pending transactions,
        // and are instead subjected to full validation and the final projected capacity check below.
        let is_potential_emergency = env.tx_type == TxType::GuardianAction
            && raw_tx.len() > tx::TX_ENVELOPE_LEN + 32
            && (raw_tx[tx::TX_ENVELOPE_LEN + 32] == crate::auth::ACTION_FREEZE
                || raw_tx[tx::TX_ENVELOPE_LEN + 32] == crate::auth::ACTION_EMERGENCY_RECOVERY);

        if !is_potential_emergency {
            let projected_count = self
                .transactions
                .len()
                .checked_add(1)
                .ok_or(MempoolError::MempoolFull)?;
            if projected_count > self.config.max_transactions {
                return Err(MempoolError::MempoolFull);
            }
            let projected_bytes = self
                .total_bytes
                .checked_add(raw_tx.len())
                .ok_or(MempoolError::MempoolFull)?;
            if projected_bytes > self.config.max_bytes {
                return Err(MempoolError::MempoolFull);
            }
        }

        // Type-specific stateful and conflict validation (pure read-only pre-calculation)
        let (meta, to_evict) = self.validate_and_build_meta(raw_tx, &env, fee, chain_state)?;

        // Final bounded capacity checks accounting for projected evictions with checked arithmetic
        let surviving_count = self
            .transactions
            .len()
            .checked_sub(to_evict.len())
            .ok_or_else(|| {
                MempoolError::Malformed(
                    "eviction count exceeds total transactions in mempool".into(),
                )
            })?;
        let projected_count = surviving_count
            .checked_add(1)
            .ok_or(MempoolError::MempoolFull)?;
        if projected_count > self.config.max_transactions {
            return Err(MempoolError::MempoolFull);
        }

        let evicted_bytes: usize = to_evict.iter().try_fold(0usize, |acc, id| {
            let meta = self.tx_meta.get(id).ok_or_else(|| {
                MempoolError::Malformed(format!("missing metadata for evicted transaction {id}"))
            })?;
            acc.checked_add(meta.size)
                .ok_or_else(|| MempoolError::Malformed("evicted bytes calculation overflow".into()))
        })?;
        let surviving_bytes = self.total_bytes.checked_sub(evicted_bytes).ok_or_else(|| {
            MempoolError::Malformed("evicted bytes exceed total bytes in mempool".into())
        })?;
        let projected_total_bytes = surviving_bytes
            .checked_add(raw_tx.len())
            .ok_or(MempoolError::MempoolFull)?;
        if projected_total_bytes > self.config.max_bytes {
            return Err(MempoolError::MempoolFull);
        }

        // Precompute checked shielded drain total before applying any state mutations
        let new_shielded_drain = if meta.shielded_drain > 0 {
            self.total_pending_shielded_drain
                .checked_add(meta.shielded_drain)
                .ok_or_else(|| MempoolError::Malformed("shielded drain overflow".into()))?
        } else {
            self.total_pending_shielded_drain
        };

        // Precompute checked allowance reservation total before applying any state mutations
        let new_allowance_reservation = if meta.allowance_consumption > 0 {
            if let Some(acct) = meta.sender_account {
                let evicted_allowance: u128 = to_evict.iter().try_fold(0u128, |acc, id| {
                    let m = self.tx_meta.get(id).ok_or_else(|| {
                        MempoolError::AllowanceExceeded(format!(
                            "missing metadata for evicted transaction {id}"
                        ))
                    })?;
                    acc.checked_add(m.allowance_consumption).ok_or_else(|| {
                        MempoolError::AllowanceExceeded(
                            "evicted allowance calculation overflow".into(),
                        )
                    })
                })?;
                let current = self
                    .account_allowance_reservations
                    .get(&acct)
                    .copied()
                    .unwrap_or(0);
                let surviving_allowance =
                    current.checked_sub(evicted_allowance).ok_or_else(|| {
                        MempoolError::AllowanceExceeded(
                            "evicted allowance exceeds current pending reservation".into(),
                        )
                    })?;
                Some((
                    acct,
                    surviving_allowance
                        .checked_add(meta.allowance_consumption)
                        .ok_or_else(|| {
                            MempoolError::AllowanceExceeded("allowance reservation overflow".into())
                        })?,
                ))
            } else {
                None
            }
        } else {
            None
        };

        // All validations and checked arithmetic succeeded: atomically evict conflicting transactions
        for evict_id in &to_evict {
            self.remove(evict_id);
        }

        // Register in mempool state atomically
        if let Some(acct) = meta.sender_account {
            if let Some(n) = meta.account_nonce {
                self.account_nonces.entry(acct).or_default().insert(n);
            }
            if meta.account_spend > 0 {
                let current = self.account_spends.entry(acct).or_default();
                *current = current.saturating_add(meta.account_spend);
            }
        }

        for nf in &meta.nullifiers {
            self.mempool_nullifiers.insert(*nf, tx_id);
        }

        self.total_pending_shielded_drain = new_shielded_drain;

        if let Some((acct, total)) = new_allowance_reservation {
            self.account_allowance_reservations.insert(acct, total);
        }

        if let Some(target) = meta.cancellation_target {
            self.cancellation_targets.insert(target, tx_id);
        }

        if let Some(target) = meta.governance_lock {
            let action_type = if meta.tx_type == TxType::GuardianAction {
                Some(raw_tx[tx::TX_ENVELOPE_LEN + 32])
            } else {
                None
            };
            self.pending_governance_locks.insert(
                target,
                GovernanceLock {
                    tx_id,
                    tx_type: meta.tx_type,
                    action_type,
                },
            );
        }

        self.total_bytes = self
            .total_bytes
            .checked_add(raw_tx.len())
            .expect("capacity prechecked");
        self.transactions.insert(tx_id, raw_tx.to_vec());
        self.tx_meta.insert(tx_id, meta);
        self.insertion_order.push(tx_id);

        Ok(tx_id)
    }

    /// Internal validation and metadata construction for candidate transaction.
    fn validate_and_build_meta(
        &self,
        raw_tx: &[u8],
        env: &crate::tx::TxEnvelope,
        fee: u64,
        chain_state: &ChainState,
    ) -> Result<(AdmittedTxMeta, Vec<Hash>), MempoolError> {
        let tip_h = chain_state.tip_height().unwrap_or(0);
        let active_anchors = self.active_anchor_set(chain_state);

        match env.tx_type {
            TxType::Coinbase => Err(MempoolError::CoinbaseForbidden),

            TxType::TransparentTransfer => {
                if raw_tx.len() != 195 {
                    return Err(MempoolError::Malformed("invalid Type 1 length".into()));
                }
                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                let mut sender_key = [0u8; 32];
                sender_key.copy_from_slice(&payload[0..32]);
                let sender_addr = derive_address(&sender_key);

                // Pending governance lock check
                if self.pending_governance_locks.contains_key(&sender_addr) {
                    return Err(MempoolError::AccountLockedByPendingGovernance(sender_addr));
                }

                let amount = u128::from_le_bytes(payload[64..80].try_into().unwrap());
                let nonce = u64::from_le_bytes(payload[88..96].try_into().unwrap());

                // Signature check
                let unsigned_preimage =
                    crate::auth::compute_signing_preimage(chain_state.chain_id(), &raw_tx[..131]);
                let sig: [u8; 64] = raw_tx[131..195].try_into().unwrap();
                crate::auth::verify_signature(&sender_key, &unsigned_preimage, &sig)
                    .map_err(|e| MempoolError::InvalidSignature(e.to_string()))?;

                // Account state checks
                let acct = chain_state
                    .account(&sender_addr)
                    .ok_or(MempoolError::AccountNotFound(sender_addr))?;
                if acct.is_frozen {
                    return Err(MempoolError::AccountFrozen(sender_addr));
                }

                // Sequential nonce validation
                if nonce == u64::MAX {
                    return Err(MempoolError::NonceExhausted(sender_addr));
                }
                let expected_nonce = self.expected_next_nonce(&sender_addr, acct.nonce)?;
                if nonce != expected_nonce {
                    return Err(MempoolError::ConflictingNonce {
                        account: sender_addr,
                        expected: expected_nonce,
                        found: nonce,
                    });
                }

                // Spendable balance validation
                let total_spend = amount
                    .checked_add(fee as u128)
                    .ok_or_else(|| MempoolError::Malformed("spend overflow".into()))?;
                let current_pending = self.account_spends.get(&sender_addr).copied().unwrap_or(0);
                let needed = current_pending
                    .checked_add(total_spend)
                    .ok_or_else(|| MempoolError::Malformed("spend overflow".into()))?;
                let spendable = acct
                    .spendable_balance(tip_h)
                    .map_err(|_| MempoolError::Malformed("spendable balance calculation".into()))?;
                if needed > spendable {
                    return Err(MempoolError::InsufficientSpendableBalance {
                        account: sender_addr,
                        spendable,
                        required: needed,
                    });
                }

                // Check spend allowance
                self.check_mempool_allowance(acct, &sender_addr, tip_h, total_spend)?;
                let allowance_consumption =
                    if acct.allowance_limit > 0 && acct.allowance_window_len > 0 {
                        total_spend
                    } else {
                        0
                    };

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: Some(sender_addr),
                        account_nonce: Some(nonce),
                        account_spend: total_spend,
                        nullifiers: Vec::new(),
                        shielded_drain: 0,
                        cancellation_target: None,
                        allowance_consumption,
                        governance_lock: None,
                    },
                    Vec::new(),
                ))
            }

            TxType::ConfigureGuardians => {
                if raw_tx.len() < 436 {
                    return Err(MempoolError::Malformed("invalid Type 2 length".into()));
                }
                let unsigned_prefix = &raw_tx[..371];
                let mut owner_sig = [0u8; 64];
                owner_sig.copy_from_slice(&raw_tx[371..435]);
                let guardian_section = &raw_tx[435..];

                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                let mut account_key = [0u8; 32];
                account_key.copy_from_slice(&payload[..32]);
                crate::auth::parse_strict_pubkey(&account_key)
                    .map_err(|e| MempoolError::Malformed(format!("invalid account key: {e}")))?;
                let account_addr = derive_address(&account_key);

                // Type 2 is a maintenance governance action: reject if lock exists or pending account activity
                if let Some(lock) = self.pending_governance_locks.get(&account_addr) {
                    return Err(MempoolError::PendingGovernanceConflict {
                        account: account_addr,
                        existing_tx: lock.tx_id,
                    });
                }
                if let Some(existing_tx) = self.find_pending_account_tx(&account_addr) {
                    return Err(MempoolError::PendingGovernanceConflict {
                        account: account_addr,
                        existing_tx,
                    });
                }

                let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());

                let mut new_guardians = [[0u8; 32]; 7];
                for i in 0..7 {
                    new_guardians[i].copy_from_slice(&payload[48 + i * 32..48 + (i + 1) * 32]);
                }
                crate::auth::validate_guardian_keys_set(&new_guardians)
                    .map_err(|e| MempoolError::Malformed(format!("invalid guardian keys: {e}")))?;

                let mut recovery_key = [0u8; 32];
                recovery_key.copy_from_slice(&payload[304..336]);
                crate::auth::validate_pubkey(&recovery_key)
                    .map_err(|e| MempoolError::Malformed(format!("invalid recovery key: {e}")))?;

                let guardian_entries =
                    crate::auth::parse_guardian_sigs(guardian_section).map_err(|e| {
                        MempoolError::Malformed(format!("malformed guardian signatures: {e}"))
                    })?;

                let expected_tx_len = 435 + 1 + guardian_entries.len() * 65;
                if raw_tx.len() != expected_tx_len {
                    return Err(MempoolError::Malformed(
                        "invalid Type 2 wire length or trailing bytes".into(),
                    ));
                }

                let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(
                    unsigned_prefix,
                    &guardian_entries,
                );
                let preimage =
                    crate::auth::compute_signing_preimage(chain_state.chain_id(), &unsigned_tx);

                crate::auth::verify_signature(&account_key, &preimage, &owner_sig).map_err(
                    |e| {
                        MempoolError::InvalidSignature(format!(
                            "owner signature verification failed: {e}"
                        ))
                    },
                )?;

                let acct = chain_state
                    .account(&account_addr)
                    .ok_or(MempoolError::AccountNotFound(account_addr))?;
                if acct.is_frozen {
                    return Err(MempoolError::AccountFrozen(account_addr));
                }

                if nonce == u64::MAX {
                    return Err(MempoolError::NonceExhausted(account_addr));
                }
                let expected_nonce = self.expected_next_nonce(&account_addr, acct.nonce)?;
                if nonce != expected_nonce {
                    return Err(MempoolError::ConflictingNonce {
                        account: account_addr,
                        expected: expected_nonce,
                        found: nonce,
                    });
                }

                let current_pending = self.account_spends.get(&account_addr).copied().unwrap_or(0);
                let needed = current_pending
                    .checked_add(fee as u128)
                    .ok_or_else(|| MempoolError::Malformed("fee overflow".into()))?;
                let spendable = acct
                    .spendable_balance(tip_h)
                    .map_err(|_| MempoolError::Malformed("spendable balance".into()))?;
                if needed > spendable {
                    return Err(MempoolError::InsufficientSpendableBalance {
                        account: account_addr,
                        spendable,
                        required: needed,
                    });
                }

                self.check_mempool_allowance(acct, &account_addr, tip_h, fee as u128)?;
                let allowance_consumption =
                    if acct.allowance_limit > 0 && acct.allowance_window_len > 0 {
                        fee as u128
                    } else {
                        0
                    };

                if acct.guardian_enabled {
                    if guardian_entries.len() < 4 {
                        return Err(MempoolError::Malformed(
                            "reconfiguration requires at least 4 guardian signatures".into(),
                        ));
                    }
                    crate::auth::verify_guardian_quorum(
                        &acct.guardians,
                        &preimage,
                        &guardian_entries,
                        4,
                    )
                    .map_err(|e| {
                        MempoolError::InvalidSignature(format!(
                            "reconfiguration guardian verification failed: {e}"
                        ))
                    })?;
                } else if !guardian_entries.is_empty() {
                    return Err(MempoolError::Malformed(
                        "initial guardian configuration must not carry guardian signatures".into(),
                    ));
                }

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: Some(account_addr),
                        account_nonce: Some(nonce),
                        account_spend: fee as u128,
                        nullifiers: Vec::new(),
                        shielded_drain: 0,
                        cancellation_target: None,
                        allowance_consumption,
                        governance_lock: Some(account_addr),
                    },
                    Vec::new(),
                ))
            }

            TxType::GuardianAction => {
                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                if payload.len() < 45 {
                    return Err(MempoolError::Malformed("truncated Type 3 payload".into()));
                }
                let mut target_key = [0u8; 32];
                target_key.copy_from_slice(&payload[..32]);
                let target_addr = Hash::new(target_key);
                let action_type = payload[32];

                let is_emergency = action_type == crate::auth::ACTION_FREEZE
                    || action_type == crate::auth::ACTION_EMERGENCY_RECOVERY;

                let to_evict = if is_emergency {
                    // Security preemption: if another emergency action owns the lock, conflict!
                    if let Some(lock) = self.pending_governance_locks.get(&target_addr) {
                        if lock.is_emergency() {
                            return Err(MempoolError::PendingGovernanceConflict {
                                account: target_addr,
                                existing_tx: lock.tx_id,
                            });
                        }
                    }
                    // Determine conflicting pending transactions originating from target_addr
                    let mut evict_list = Vec::new();
                    for &tx_id in &self.insertion_order {
                        if let Some(m) = self.tx_meta.get(&tx_id) {
                            if m.sender_account == Some(target_addr) {
                                evict_list.push(tx_id);
                            }
                        }
                    }
                    evict_list
                } else {
                    // Maintenance action: reject if lock exists or any pending account activity exists
                    if let Some(lock) = self.pending_governance_locks.get(&target_addr) {
                        return Err(MempoolError::PendingGovernanceConflict {
                            account: target_addr,
                            existing_tx: lock.tx_id,
                        });
                    }
                    if let Some(existing_tx) = self.find_pending_account_tx(&target_addr) {
                        return Err(MempoolError::PendingGovernanceConflict {
                            account: target_addr,
                            existing_tx,
                        });
                    }
                    Vec::new()
                };

                let params_len = u32::from_le_bytes(payload[41..45].try_into().unwrap()) as usize;
                if payload.len() < 45 + params_len + 1 {
                    return Err(MempoolError::Malformed(
                        "truncated guardian action params".into(),
                    ));
                }
                let params = &payload[45..45 + params_len];

                crate::auth::validate_guardian_action_params(action_type, params).map_err(|e| {
                    MempoolError::Malformed(format!("invalid guardian action params: {e}"))
                })?;

                let unsigned_end = tx::TX_ENVELOPE_LEN + 45 + params_len;
                let unsigned_prefix = &raw_tx[..unsigned_end];
                let guardian_section = &raw_tx[unsigned_end..];

                let guardian_entries =
                    crate::auth::parse_guardian_sigs(guardian_section).map_err(|e| {
                        MempoolError::Malformed(format!("malformed guardian signatures: {e}"))
                    })?;

                let expected_tx_len = unsigned_end + 1 + guardian_entries.len() * 65;
                if raw_tx.len() != expected_tx_len {
                    return Err(MempoolError::Malformed(
                        "invalid Type 3 wire length or trailing bytes".into(),
                    ));
                }

                let req_quorum = crate::auth::guardian_action_quorum(action_type).map_err(|e| {
                    MempoolError::Malformed(format!("invalid guardian action quorum: {e}"))
                })?;

                let target = chain_state
                    .account(&target_addr)
                    .ok_or(MempoolError::AccountNotFound(target_addr))?;
                if !target.guardian_enabled {
                    return Err(MempoolError::Malformed(
                        "guardians not enabled on target account".into(),
                    ));
                }

                let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(
                    unsigned_prefix,
                    &guardian_entries,
                );
                let preimage =
                    crate::auth::compute_signing_preimage(chain_state.chain_id(), &unsigned_tx);

                crate::auth::verify_guardian_quorum(
                    &target.guardians,
                    &preimage,
                    &guardian_entries,
                    req_quorum,
                )
                .map_err(|e| {
                    MempoolError::InvalidSignature(format!(
                        "guardian quorum verification failed: {e}"
                    ))
                })?;

                match action_type {
                    crate::auth::ACTION_STRENGTHEN_DELAYS => {
                        let new_delay = u32::from_le_bytes(params[..4].try_into().unwrap());
                        if new_delay < target.new_recipient_delay {
                            return Err(MempoolError::Malformed(
                                "cannot decrease delay with 3-of-7 quorum".into(),
                            ));
                        }
                    }
                    crate::auth::ACTION_STRENGTHEN_ALLOWANCE => {
                        let new_lim = u128::from_le_bytes(params[..16].try_into().unwrap());
                        let new_len = u64::from_le_bytes(params[16..24].try_into().unwrap());
                        if new_lim == 0 || new_len == 0 {
                            return Err(MempoolError::Malformed(
                                "cannot disable allowance with 3-of-7 quorum".into(),
                            ));
                        }
                        if target.allowance_limit > 0 && new_lim > target.allowance_limit {
                            return Err(MempoolError::Malformed(
                                "cannot increase limit with 3-of-7 quorum".into(),
                            ));
                        }
                        if target.allowance_window_len > 0 && new_len < target.allowance_window_len
                        {
                            return Err(MempoolError::Malformed(
                                "cannot shorten window with 3-of-7 quorum".into(),
                            ));
                        }
                    }
                    crate::auth::ACTION_REPLACE_GUARDIANS => {
                        let mut new_guardians = [[0u8; 32]; 7];
                        for i in 0..7 {
                            new_guardians[i].copy_from_slice(&params[i * 32..(i + 1) * 32]);
                        }
                        crate::auth::validate_guardian_keys_set(&new_guardians).map_err(|e| {
                            MempoolError::Malformed(format!(
                                "invalid replacement guardian keys: {e}"
                            ))
                        })?;
                    }
                    crate::auth::ACTION_REPLACE_RECOVERY_KEY => {
                        let mut new_rec = [0u8; 32];
                        new_rec.copy_from_slice(&params[..32]);
                        crate::auth::validate_pubkey(&new_rec).map_err(|e| {
                            MempoolError::Malformed(format!(
                                "invalid replacement recovery key: {e}"
                            ))
                        })?;
                    }
                    _ => {}
                }

                // Calculate projected pending transparent spend excluding evicted transactions
                let evicted_spends: u128 = to_evict.iter().try_fold(0u128, |acc, id| {
                    let m = self.tx_meta.get(id).ok_or_else(|| {
                        MempoolError::Malformed(format!(
                            "missing metadata for evicted transaction {id}"
                        ))
                    })?;
                    acc.checked_add(m.account_spend).ok_or_else(|| {
                        MempoolError::Malformed("evicted spends calculation overflow".into())
                    })
                })?;
                let current_pending = self.account_spends.get(&target_addr).copied().unwrap_or(0);
                let projected_pending =
                    current_pending.checked_sub(evicted_spends).ok_or_else(|| {
                        MempoolError::Malformed(
                            "evicted spends exceed current pending spend reservation".into(),
                        )
                    })?;
                let needed = projected_pending
                    .checked_add(fee as u128)
                    .ok_or_else(|| MempoolError::Malformed("fee overflow".into()))?;
                let spendable = target
                    .spendable_balance(tip_h)
                    .map_err(|_| MempoolError::Malformed("spendable balance".into()))?;
                if needed > spendable {
                    return Err(MempoolError::InsufficientSpendableBalance {
                        account: target_addr,
                        spendable,
                        required: needed,
                    });
                }

                // Calculate projected pending allowance reservations excluding evicted transactions
                let evicted_allowance: u128 = to_evict.iter().try_fold(0u128, |acc, id| {
                    let m = self.tx_meta.get(id).ok_or_else(|| {
                        MempoolError::AllowanceExceeded(format!(
                            "missing metadata for evicted transaction {id}"
                        ))
                    })?;
                    acc.checked_add(m.allowance_consumption).ok_or_else(|| {
                        MempoolError::AllowanceExceeded(
                            "evicted allowance calculation overflow".into(),
                        )
                    })
                })?;
                let current_allowance = self.pending_allowance_reservation(&target_addr);
                let projected_allowance = current_allowance
                    .checked_sub(evicted_allowance)
                    .ok_or_else(|| {
                        MempoolError::AllowanceExceeded(
                            "evicted allowance exceeds current pending allowance reservation"
                                .into(),
                        )
                    })?;

                check_account_allowance(target, tip_h, projected_allowance, fee as u128)?;
                let allowance_consumption =
                    if target.allowance_limit > 0 && target.allowance_window_len > 0 {
                        fee as u128
                    } else {
                        0
                    };

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: Some(target_addr),
                        account_nonce: None,
                        account_spend: fee as u128,
                        nullifiers: Vec::new(),
                        shielded_drain: 0,
                        cancellation_target: None,
                        allowance_consumption,
                        governance_lock: Some(target_addr),
                    },
                    to_evict,
                ))
            }

            TxType::CancelPendingTransfer => {
                if raw_tx.len() < 180 {
                    return Err(MempoolError::Malformed("invalid Type 4 length".into()));
                }
                let unsigned_prefix = &raw_tx[..115];
                let mut sender_sig = [0u8; 64];
                sender_sig.copy_from_slice(&raw_tx[115..179]);
                let guardian_section = &raw_tx[179..];

                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                let mut sender_key = [0u8; 32];
                sender_key.copy_from_slice(&payload[..32]);
                let sender_addr = derive_address(&sender_key);

                // Pending governance lock check
                if self.pending_governance_locks.contains_key(&sender_addr) {
                    return Err(MempoolError::AccountLockedByPendingGovernance(sender_addr));
                }

                let transfer_id = Hash::new(payload[32..64].try_into().unwrap());
                let nonce = u64::from_le_bytes(payload[72..80].try_into().unwrap());

                let guardian_entries =
                    crate::auth::parse_guardian_sigs(guardian_section).map_err(|e| {
                        MempoolError::Malformed(format!("malformed guardian signatures: {e}"))
                    })?;

                let expected_tx_len = 179 + 1 + guardian_entries.len() * 65;
                if raw_tx.len() != expected_tx_len {
                    return Err(MempoolError::Malformed(
                        "invalid Type 4 wire length or trailing bytes".into(),
                    ));
                }

                let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(
                    unsigned_prefix,
                    &guardian_entries,
                );
                let preimage =
                    crate::auth::compute_signing_preimage(chain_state.chain_id(), &unsigned_tx);

                crate::auth::verify_signature(&sender_key, &preimage, &sender_sig).map_err(
                    |e| {
                        MempoolError::InvalidSignature(format!(
                            "sender signature verification failed: {e}"
                        ))
                    },
                )?;

                let sender = chain_state
                    .account(&sender_addr)
                    .ok_or(MempoolError::AccountNotFound(sender_addr))?;
                if sender.is_frozen {
                    return Err(MempoolError::AccountFrozen(sender_addr));
                }
                if !sender.guardian_enabled {
                    return Err(MempoolError::Malformed(
                        "sender account does not have guardians enabled".into(),
                    ));
                }

                if guardian_entries.len() < 4 {
                    return Err(MempoolError::Malformed(
                        "cancellation requires at least 4 guardian signatures".into(),
                    ));
                }
                crate::auth::verify_guardian_quorum(
                    &sender.guardians,
                    &preimage,
                    &guardian_entries,
                    4,
                )
                .map_err(|e| {
                    MempoolError::InvalidSignature(format!(
                        "guardian quorum verification failed: {e}"
                    ))
                })?;

                if !sender
                    .pending_transfers
                    .iter()
                    .any(|p| p.transfer_id == transfer_id)
                {
                    return Err(MempoolError::Malformed(
                        "pending transfer not found on account".into(),
                    ));
                }

                if let Some(existing_tx) = self.cancellation_targets.get(&transfer_id) {
                    return Err(MempoolError::ConflictingCancellation {
                        transfer_id,
                        existing_tx: *existing_tx,
                    });
                }

                if nonce == u64::MAX {
                    return Err(MempoolError::NonceExhausted(sender_addr));
                }
                let expected_nonce = self.expected_next_nonce(&sender_addr, sender.nonce)?;
                if nonce != expected_nonce {
                    return Err(MempoolError::ConflictingNonce {
                        account: sender_addr,
                        expected: expected_nonce,
                        found: nonce,
                    });
                }

                let current_pending = self.account_spends.get(&sender_addr).copied().unwrap_or(0);
                let needed = current_pending
                    .checked_add(fee as u128)
                    .ok_or_else(|| MempoolError::Malformed("fee overflow".into()))?;
                let spendable = sender
                    .spendable_balance(tip_h)
                    .map_err(|_| MempoolError::Malformed("spendable balance".into()))?;
                if needed > spendable {
                    return Err(MempoolError::InsufficientSpendableBalance {
                        account: sender_addr,
                        spendable,
                        required: needed,
                    });
                }

                self.check_mempool_allowance(sender, &sender_addr, tip_h, fee as u128)?;
                let allowance_consumption =
                    if sender.allowance_limit > 0 && sender.allowance_window_len > 0 {
                        fee as u128
                    } else {
                        0
                    };

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: Some(sender_addr),
                        account_nonce: Some(nonce),
                        account_spend: fee as u128,
                        nullifiers: Vec::new(),
                        shielded_drain: 0,
                        cancellation_target: Some(transfer_id),
                        allowance_consumption,
                        governance_lock: None,
                    },
                    Vec::new(),
                ))
            }

            TxType::ShieldedTransfer => {
                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                if payload.len() < 8 {
                    return Err(MempoolError::Malformed("truncated Type 5".into()));
                }
                let bundle_bytes = &payload[8..];
                let bundle = deserialize_bundle(bundle_bytes)?;

                let vk = verifying_key();
                validate_bundle_stateless(env, fee, &bundle, vk)?;

                // Anchor verification
                let anchor = Hash::new(bundle.anchor().to_bytes());
                if !active_anchors.contains(&anchor) {
                    return Err(MempoolError::StaleAnchor(anchor));
                }

                // Shielded pool balance check for fee reservation
                let pool_drain = fee as u128;
                let pool_balance = chain_state.shielded_pool_balance();
                let current_drain = self
                    .total_pending_shielded_drain
                    .checked_add(pool_drain)
                    .ok_or_else(|| MempoolError::Malformed("shielded drain overflow".into()))?;
                if current_drain > pool_balance {
                    return Err(MempoolError::InsufficientShieldedPoolBalance {
                        available: pool_balance,
                        required: current_drain,
                    });
                }

                // Nullifier extraction and conflict check
                let mut tx_nfs = BTreeSet::new();
                let mut nfs = Vec::with_capacity(bundle.actions().len());
                for action in bundle.actions() {
                    let nf = Hash::new(action.nullifier().to_bytes());
                    if !tx_nfs.insert(nf) {
                        return Err(MempoolError::DuplicateNullifierInTx(nf));
                    }
                    if chain_state.nullifier_set().contains(&nf) {
                        return Err(MempoolError::NullifierAlreadySpent(nf));
                    }
                    if let Some(existing_tx) = self.mempool_nullifiers.get(&nf) {
                        return Err(MempoolError::ConflictingNullifier {
                            nullifier: nf,
                            existing_tx: *existing_tx,
                        });
                    }
                    nfs.push(nf);
                }

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: None,
                        account_nonce: None,
                        account_spend: 0,
                        nullifiers: nfs,
                        shielded_drain: pool_drain,
                        cancellation_target: None,
                        allowance_consumption: 0,
                        governance_lock: None,
                    },
                    Vec::new(),
                ))
            }

            TxType::TransparentToShielded => {
                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                if payload.len() < 133 {
                    return Err(MempoolError::Malformed("truncated Type 6".into()));
                }
                let mut sender_key = [0u8; 32];
                sender_key.copy_from_slice(&payload[..32]);
                let sender_addr = derive_address(&sender_key);

                // Pending governance lock check
                if self.pending_governance_locks.contains_key(&sender_addr) {
                    return Err(MempoolError::AccountLockedByPendingGovernance(sender_addr));
                }

                let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());
                let shielded_amount = u128::from_le_bytes(payload[40..56].try_into().unwrap());
                if shielded_amount == 0 {
                    return Err(MempoolError::Malformed(
                        "shielded amount must be > 0".into(),
                    ));
                }

                let bundle_len = u32::from_le_bytes(payload[64..68].try_into().unwrap()) as usize;
                let bundle_end = 68 + bundle_len;
                let sig_end = bundle_end + 64;
                if payload.len() < sig_end + 1 {
                    return Err(MempoolError::Malformed(
                        "truncated Type 6 bundle/sig".into(),
                    ));
                }

                let bundle_bytes = &payload[68..bundle_end];
                let bundle = deserialize_bundle(bundle_bytes)?;

                let n_actions = bundle.actions().len();
                if n_actions == 0 || n_actions > crate::orchard_tx::MAX_ACTIONS_PER_TX {
                    return Err(MempoolError::Malformed(format!(
                        "invalid action count {n_actions}"
                    )));
                }

                if *bundle.flags() != orchard::bundle::Flags::SPENDS_DISABLED {
                    return Err(MempoolError::Malformed(
                        "Type 6 requires SPENDS_DISABLED".into(),
                    ));
                }
                if *bundle.anchor() != orchard::tree::Anchor::empty_tree() {
                    return Err(MempoolError::Malformed(
                        "Type 6 anchor must be empty tree".into(),
                    ));
                }

                let vb = *bundle.value_balance();
                if vb >= 0 {
                    return Err(MempoolError::Malformed(
                        "Type 6 value balance must be negative".into(),
                    ));
                }

                let expected_vb = -i64::try_from(shielded_amount).map_err(|_| {
                    MempoolError::Malformed("shielded amount exceeds i64 bounds".into())
                })?;
                if vb != expected_vb {
                    return Err(MempoolError::ValueBalanceMismatch {
                        value_balance: vb,
                        expected: expected_vb,
                    });
                }

                // Stateless bundle proof check
                let vk = verifying_key();
                bundle.verify_proof(vk).map_err(|e| {
                    OrchardValidationError::ProofVerificationFailed(format!("{e:?}"))
                })?;

                // Sender signature check over cross-pool auth digest
                let auth_digest = compute_type6_bundle_auth_digest(
                    *chain_state.chain_id().as_bytes(),
                    1,
                    sender_key,
                    nonce,
                    shielded_amount,
                    fee,
                    &bundle,
                );
                let mut sender_sig = [0u8; 64];
                sender_sig.copy_from_slice(&payload[bundle_end..sig_end]);
                crate::auth::verify_signature(&sender_key, &auth_digest, &sender_sig)
                    .map_err(|e| MempoolError::InvalidSignature(e.to_string()))?;

                // Binding signature verification over auth_digest
                bundle
                    .binding_validating_key()
                    .verify(&auth_digest, bundle.authorization().binding_signature())
                    .map_err(|_| MempoolError::InvalidSignature("binding signature".into()))?;

                // Verify SpendAuth signatures on each action over auth_digest
                for (idx, action) in bundle.actions().iter().enumerate() {
                    action
                        .rk()
                        .verify(&auth_digest, action.authorization())
                        .map_err(|_| {
                            MempoolError::InvalidSignature(format!(
                                "spend auth signature verification failed for action {idx}"
                            ))
                        })?;
                }

                let acct = chain_state
                    .account(&sender_addr)
                    .ok_or(MempoolError::AccountNotFound(sender_addr))?;
                if acct.is_frozen {
                    return Err(MempoolError::AccountFrozen(sender_addr));
                }

                let guardian_section = &payload[sig_end..];
                let guardian_entries = crate::auth::parse_guardian_sigs(guardian_section)
                    .map_err(|e| MempoolError::Malformed(format!("guardian sigs: {e}")))?;
                let expected_payload_len = sig_end + 1 + guardian_entries.len() * 65;
                if payload.len() != expected_payload_len {
                    return Err(MempoolError::Malformed(
                        "invalid Type 6 length or trailing bytes".into(),
                    ));
                }

                if acct.guardian_enabled {
                    if guardian_entries.len() < 4 {
                        return Err(MempoolError::Malformed(
                            "protected account requires at least 4 guardian signatures".into(),
                        ));
                    }
                    crate::orchard_tx::verify_type6_guardian_signatures(
                        &auth_digest,
                        &guardian_entries,
                        &acct.guardians,
                    )
                    .map_err(|e| MempoolError::InvalidSignature(format!("quorum: {e}")))?;
                } else if !guardian_entries.is_empty() {
                    return Err(MempoolError::Malformed(
                        "unprotected account must not carry guardian signatures".into(),
                    ));
                }

                // Nonce and spendable balance check
                if nonce == u64::MAX {
                    return Err(MempoolError::NonceExhausted(sender_addr));
                }
                let expected_nonce = self.expected_next_nonce(&sender_addr, acct.nonce)?;
                if nonce != expected_nonce {
                    return Err(MempoolError::ConflictingNonce {
                        account: sender_addr,
                        expected: expected_nonce,
                        found: nonce,
                    });
                }

                let total_spend = shielded_amount
                    .checked_add(fee as u128)
                    .ok_or_else(|| MempoolError::Malformed("spend overflow".into()))?;
                let current_pending = self.account_spends.get(&sender_addr).copied().unwrap_or(0);
                let needed = current_pending
                    .checked_add(total_spend)
                    .ok_or_else(|| MempoolError::Malformed("spend overflow".into()))?;
                let spendable = acct
                    .spendable_balance(tip_h)
                    .map_err(|_| MempoolError::Malformed("spendable balance".into()))?;
                if needed > spendable {
                    return Err(MempoolError::InsufficientSpendableBalance {
                        account: sender_addr,
                        spendable,
                        required: needed,
                    });
                }

                self.check_mempool_allowance(acct, &sender_addr, tip_h, total_spend)?;
                let allowance_consumption =
                    if acct.allowance_limit > 0 && acct.allowance_window_len > 0 {
                        total_spend
                    } else {
                        0
                    };

                // Nullifier extraction
                let mut tx_nfs = BTreeSet::new();
                let mut nfs = Vec::with_capacity(bundle.actions().len());
                for action in bundle.actions() {
                    let nf = Hash::new(action.nullifier().to_bytes());
                    if !tx_nfs.insert(nf) {
                        return Err(MempoolError::DuplicateNullifierInTx(nf));
                    }
                    if chain_state.nullifier_set().contains(&nf) {
                        return Err(MempoolError::NullifierAlreadySpent(nf));
                    }
                    if let Some(existing_tx) = self.mempool_nullifiers.get(&nf) {
                        return Err(MempoolError::ConflictingNullifier {
                            nullifier: nf,
                            existing_tx: *existing_tx,
                        });
                    }
                    nfs.push(nf);
                }

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: Some(sender_addr),
                        account_nonce: Some(nonce),
                        account_spend: total_spend,
                        nullifiers: nfs,
                        shielded_drain: 0,
                        cancellation_target: None,
                        allowance_consumption,
                        governance_lock: None,
                    },
                    Vec::new(),
                ))
            }

            TxType::ShieldedToTransparent => {
                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                if payload.len() < 60 {
                    return Err(MempoolError::Malformed("truncated Type 7".into()));
                }
                let mut recipient_bytes = [0u8; 32];
                recipient_bytes.copy_from_slice(&payload[..32]);

                let release_amount = u128::from_le_bytes(payload[32..48].try_into().unwrap());
                if release_amount == 0 {
                    return Err(MempoolError::Malformed("release amount must be > 0".into()));
                }

                let bundle_len = u32::from_le_bytes(payload[56..60].try_into().unwrap()) as usize;
                let expected_len = 60 + bundle_len;
                if payload.len() != expected_len {
                    return Err(MempoolError::Malformed(
                        "invalid Type 7 bundle length".into(),
                    ));
                }

                let bundle_bytes = &payload[60..expected_len];
                let bundle = deserialize_bundle(bundle_bytes)?;

                let n_actions = bundle.actions().len();
                if n_actions == 0 || n_actions > crate::orchard_tx::MAX_ACTIONS_PER_TX {
                    return Err(MempoolError::Malformed(format!(
                        "invalid action count {n_actions}"
                    )));
                }

                if !bundle.flags().spends_enabled() {
                    return Err(MempoolError::Malformed(
                        "Type 7 requires spends enabled".into(),
                    ));
                }

                let vb = *bundle.value_balance();
                if vb <= 0 {
                    return Err(MempoolError::Malformed(
                        "Type 7 value balance must be positive".into(),
                    ));
                }

                let total_deshield = release_amount
                    .checked_add(fee as u128)
                    .ok_or_else(|| MempoolError::Malformed("total deshield overflow".into()))?;
                let expected_vb = i64::try_from(total_deshield).map_err(|_| {
                    MempoolError::Malformed("total deshield exceeds i64 bounds".into())
                })?;
                if vb != expected_vb {
                    return Err(MempoolError::ValueBalanceMismatch {
                        value_balance: vb,
                        expected: expected_vb,
                    });
                }

                let vk = verifying_key();
                bundle.verify_proof(vk).map_err(|e| {
                    OrchardValidationError::ProofVerificationFailed(format!("{e:?}"))
                })?;

                // Anchor verification
                let anchor = Hash::new(bundle.anchor().to_bytes());
                if !active_anchors.contains(&anchor) {
                    return Err(MempoolError::StaleAnchor(anchor));
                }

                // Cross-pool auth digest and signatures
                let auth_digest = compute_type7_bundle_auth_digest(
                    *chain_state.chain_id().as_bytes(),
                    1,
                    recipient_bytes,
                    release_amount,
                    fee,
                    &bundle,
                );
                for (idx, action) in bundle.actions().iter().enumerate() {
                    action
                        .rk()
                        .verify(&auth_digest, action.authorization())
                        .map_err(|_| {
                            MempoolError::InvalidSignature(format!("spend auth action {idx}"))
                        })?;
                }
                bundle
                    .binding_validating_key()
                    .verify(&auth_digest, bundle.authorization().binding_signature())
                    .map_err(|_| MempoolError::InvalidSignature("binding signature".into()))?;

                // Shielded pool balance check
                let current_drain = self
                    .total_pending_shielded_drain
                    .checked_add(total_deshield)
                    .ok_or_else(|| MempoolError::Malformed("deshield overflow".into()))?;
                let pool_balance = chain_state.shielded_pool_balance();
                if current_drain > pool_balance {
                    return Err(MempoolError::InsufficientShieldedPoolBalance {
                        available: pool_balance,
                        required: current_drain,
                    });
                }

                // Nullifiers
                let mut tx_nfs = BTreeSet::new();
                let mut nfs = Vec::with_capacity(bundle.actions().len());
                for action in bundle.actions() {
                    let nf = Hash::new(action.nullifier().to_bytes());
                    if !tx_nfs.insert(nf) {
                        return Err(MempoolError::DuplicateNullifierInTx(nf));
                    }
                    if chain_state.nullifier_set().contains(&nf) {
                        return Err(MempoolError::NullifierAlreadySpent(nf));
                    }
                    if let Some(existing_tx) = self.mempool_nullifiers.get(&nf) {
                        return Err(MempoolError::ConflictingNullifier {
                            nullifier: nf,
                            existing_tx: *existing_tx,
                        });
                    }
                    nfs.push(nf);
                }

                Ok((
                    AdmittedTxMeta {
                        tx_type: env.tx_type,
                        size: raw_tx.len(),
                        fee,
                        sender_account: None,
                        account_nonce: None,
                        account_spend: 0,
                        nullifiers: nfs,
                        shielded_drain: total_deshield,
                        cancellation_target: None,
                        allowance_consumption: 0,
                        governance_lock: None,
                    },
                    Vec::new(),
                ))
            }
        }
    }

    /// Computes the expected next nonce for `account`, taking pending mempool txs into account.
    ///
    /// Uses checked arithmetic. Returns `Err(MempoolError::NonceExhausted)` if the next nonce
    /// overflows or reaches `u64::MAX` (as consensus cannot execute an increment from `u64::MAX`).
    fn expected_next_nonce(
        &self,
        account: &Hash,
        committed_nonce: u64,
    ) -> Result<u64, MempoolError> {
        let next = if let Some(nonces) = self.account_nonces.get(account) {
            if let Some(&max_nonce) = nonces.iter().max() {
                max_nonce
                    .checked_add(1)
                    .ok_or(MempoolError::NonceExhausted(*account))?
            } else {
                committed_nonce
            }
        } else {
            committed_nonce
        };

        if next == u64::MAX {
            return Err(MempoolError::NonceExhausted(*account));
        }

        Ok(next)
    }

    /// Returns the set of valid anchors in the active 10-block ancestor window
    /// for the next candidate block (height = tip_height + 1).
    fn active_anchor_set(&self, chain_state: &ChainState) -> BTreeSet<Hash> {
        let cand_h = chain_state
            .tip_height()
            .map(|h| h.saturating_add(1))
            .unwrap_or(0);
        if cand_h == 0 {
            return BTreeSet::new();
        }

        let min_h = cand_h.saturating_sub(10);
        let max_h = cand_h.saturating_sub(1);
        let mut anchors = BTreeSet::new();
        for h in min_h..=max_h {
            if let Some(anc) = chain_state.historical_anchors().get(&h) {
                anchors.insert(*anc);
            }
        }
        if cand_h <= 10 {
            if let Some(anc0) = chain_state.historical_anchors().get(&0) {
                anchors.insert(*anc0);
            }
        }
        anchors
    }

    /// Validates spend allowance limits for an account, taking pending reservations into account.
    fn check_mempool_allowance(
        &self,
        account: &AccountState,
        account_addr: &Hash,
        height: u64,
        cost: u128,
    ) -> Result<(), MempoolError> {
        let pending = self.pending_allowance_reservation(account_addr);
        check_account_allowance(account, height, pending, cost)
    }

    /// Removes a transaction from the mempool by transaction ID.
    pub fn remove(&mut self, tx_id: &Hash) -> Option<Vec<u8>> {
        let raw_tx = self.transactions.remove(tx_id)?;
        if let Some(meta) = self.tx_meta.remove(tx_id) {
            self.total_bytes = self.total_bytes.saturating_sub(meta.size);
            if let Some(acct) = meta.sender_account {
                if let Some(nonce) = meta.account_nonce {
                    if let Some(nonces) = self.account_nonces.get_mut(&acct) {
                        nonces.remove(&nonce);
                        if nonces.is_empty() {
                            self.account_nonces.remove(&acct);
                        }
                    }
                }
                if let Some(spend) = self.account_spends.get_mut(&acct) {
                    *spend = spend.saturating_sub(meta.account_spend);
                    if *spend == 0 {
                        self.account_spends.remove(&acct);
                    }
                }
            }
            for nf in meta.nullifiers {
                self.mempool_nullifiers.remove(&nf);
            }
            if meta.shielded_drain > 0 {
                self.total_pending_shielded_drain = self
                    .total_pending_shielded_drain
                    .checked_sub(meta.shielded_drain)
                    .expect("shielded drain underflow on removal");
            }
            if let Some(target) = meta.cancellation_target {
                if self.cancellation_targets.get(&target) == Some(tx_id) {
                    self.cancellation_targets.remove(&target);
                }
            }
            if meta.allowance_consumption > 0 {
                if let Some(acct) = meta.sender_account {
                    if let Some(res) = self.account_allowance_reservations.get_mut(&acct) {
                        *res = res
                            .checked_sub(meta.allowance_consumption)
                            .expect("allowance reservation underflow on removal");
                        if *res == 0 {
                            self.account_allowance_reservations.remove(&acct);
                        }
                    }
                }
            }
            if let Some(target) = meta.governance_lock {
                if self.pending_governance_locks.get(&target).map(|l| l.tx_id) == Some(*tx_id) {
                    self.pending_governance_locks.remove(&target);
                }
            }
        }
        self.insertion_order.retain(|id| id != tx_id);
        Some(raw_tx)
    }

    /// Handles a new accepted block: removes confirmed transactions and revalidates remaining mempool.
    pub fn on_block_accepted(&mut self, block: &crate::block::Block, chain_state: &ChainState) {
        for tx in &block.transactions {
            let tx_id = hash::transaction_id(tx);
            self.remove(&tx_id);
        }
        self.revalidate(chain_state);
    }

    /// Handles a chain reorganization: revalidates all pending mempool transactions against `new_chain_state`.
    pub fn on_reorganization(&mut self, new_chain_state: &ChainState) {
        self.revalidate(new_chain_state);
    }

    /// Revalidates all mempool transactions against `chain_state`.
    ///
    /// Transactions that are no longer valid (e.g. stale nonces, spent nullifiers,
    /// expired anchors, or depleted balances) are evicted.
    pub fn revalidate(&mut self, chain_state: &ChainState) {
        let current_txs: Vec<(Hash, Vec<u8>)> = self
            .insertion_order
            .iter()
            .filter_map(|id| self.transactions.get(id).map(|tx| (*id, tx.clone())))
            .collect();

        // Clear tracking tables
        self.transactions.clear();
        self.tx_meta.clear();
        self.insertion_order.clear();
        self.total_bytes = 0;
        self.account_nonces.clear();
        self.account_spends.clear();
        self.mempool_nullifiers.clear();
        self.total_pending_shielded_drain = 0;
        self.cancellation_targets.clear();
        self.account_allowance_reservations.clear();
        self.pending_governance_locks.clear();

        for (_id, raw_tx) in current_txs {
            // Attempt re-admission against new state
            let _ = self.admit(&raw_tx, chain_state);
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates spend allowance limits for an account, incorporating pending reservations.
fn check_account_allowance(
    account: &AccountState,
    height: u64,
    pending_reservation: u128,
    cost: u128,
) -> Result<(), MempoolError> {
    if account.allowance_limit > 0 && account.allowance_window_len > 0 {
        let is_expired = match account
            .allowance_window_start
            .checked_add(account.allowance_window_len)
        {
            Some(window_end) => height >= window_end,
            None => false,
        };
        let current_spent = if is_expired {
            0
        } else {
            account.allowance_spent
        };
        let total_reserved = current_spent
            .checked_add(pending_reservation)
            .ok_or_else(|| MempoolError::AllowanceExceeded("arithmetic overflow".into()))?;
        let new_spent = total_reserved
            .checked_add(cost)
            .ok_or_else(|| MempoolError::AllowanceExceeded("arithmetic overflow".into()))?;
        if new_spent > account.allowance_limit {
            return Err(MempoolError::AllowanceExceeded(
                "spending limit would be exceeded".into(),
            ));
        }
    }
    Ok(())
}

/// Validates spend allowance limits for an account without pending reservations.
#[allow(dead_code)]
fn check_mempool_allowance(
    account: &AccountState,
    height: u64,
    cost: u128,
) -> Result<(), MempoolError> {
    check_account_allowance(account, height, 0, cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::scheduled_subsidy;
    use crate::block::Block;
    use crate::genesis::DEVNET;
    use crate::hash::{chain_id, transaction_id};
    use crate::header::Header;
    use crate::merkle;
    use crate::orchard_root::empty_commitment_root;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_chain_id() -> Hash {
        chain_id(DEVNET)
    }

    fn make_coinbase(chain_id: Hash, height: u64, miner_addr: [u8; 32]) -> Vec<u8> {
        let mut tx = Vec::with_capacity(83);
        tx.push(0); // Type 0: Coinbase
        tx.extend_from_slice(&1u16.to_le_bytes());
        tx.extend_from_slice(chain_id.as_bytes());
        tx.extend_from_slice(&height.to_le_bytes());
        tx.extend_from_slice(&miner_addr);
        let payout = scheduled_subsidy(height) as u64;
        tx.extend_from_slice(&payout.to_le_bytes());
        tx
    }

    fn make_type1_tx(
        chain_id: Hash,
        sender_sk: &SigningKey,
        recipient: Hash,
        amount: u128,
        fee: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let mut unsigned_tx = Vec::with_capacity(131);
        unsigned_tx.push(1); // Type 1
        unsigned_tx.extend_from_slice(&1u16.to_le_bytes());
        unsigned_tx.extend_from_slice(chain_id.as_bytes());
        unsigned_tx.extend_from_slice(&sender_pk);
        unsigned_tx.extend_from_slice(recipient.as_bytes());
        unsigned_tx.extend_from_slice(&amount.to_le_bytes());
        unsigned_tx.extend_from_slice(&fee.to_le_bytes());
        unsigned_tx.extend_from_slice(&nonce.to_le_bytes());

        let preimage = crate::auth::compute_signing_preimage(chain_id, &unsigned_tx);
        let sig = sender_sk.sign(&preimage);

        let mut signed_tx = unsigned_tx;
        signed_tx.extend_from_slice(&sig.to_bytes());
        signed_tx
    }

    fn setup_chain_with_funded_account(miner_sk: &SigningKey) -> (ChainState, Block) {
        let cid = test_chain_id();
        let genesis = crate::genesis::genesis_block(cid);
        let mut state = ChainState::from_genesis(&genesis).unwrap();

        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);

        // Mine blocks 1 through 101 so block 1 coinbase matures (100 block maturity)
        let mut prev_time = genesis.header.timestamp;
        let mut last_block = genesis;
        for h in 1..=101 {
            prev_time += 120;
            let cb = make_coinbase(cid, h, *miner_addr.as_bytes());
            let cb_id = transaction_id(&cb);
            let mut blk = Block {
                header: Header {
                    version: 1,
                    chain_id: cid,
                    height: h,
                    parent_block_id: last_block.block_id(),
                    transaction_root: merkle::tx_root(&[cb_id]),
                    orchard_commitment_root: empty_commitment_root(),
                    timestamp: prev_time,
                    difficulty: state.expected_difficulty_for_next_block().unwrap_or(1),
                    nonce: 0,
                },
                transactions: vec![cb],
            };
            let root = state
                .simulate_candidate_state_root(&blk)
                .expect("simulated state root");
            blk.header.orchard_commitment_root = root;
            state.apply_block(&blk).unwrap();
            last_block = blk;
        }

        (state, last_block)
    }

    #[test]
    fn test_reject_coinbase_in_mempool() {
        let cid = test_chain_id();
        let genesis = crate::genesis::genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();
        let cb = make_coinbase(cid, 1, [0x02; 32]);

        let mut pool = Mempool::new();
        let res = pool.admit(&cb, &state);
        assert_eq!(res, Err(MempoolError::CoinbaseForbidden));
    }

    #[test]
    fn test_reject_fee_below_minimum() {
        let cid = test_chain_id();
        let genesis = crate::genesis::genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let sender_sk = SigningKey::from_bytes(&[0x11; 32]);
        let recipient = Hash::new([0x22; 32]);
        // Min fee for 195 bytes is 19,500 atoms. Pass 5,000.
        let tx = make_type1_tx(cid, &sender_sk, recipient, 1_000_000, 5_000, 0);

        let mut pool = Mempool::new();
        let res = pool.admit(&tx, &state);
        assert!(matches!(res, Err(MempoolError::FeeBelowMinimum { .. })));
    }

    #[test]
    fn test_mempool_capacity_limits() {
        let cid = test_chain_id();
        let genesis = crate::genesis::genesis_block(cid);
        let state = ChainState::from_genesis(&genesis).unwrap();

        let sender_sk = SigningKey::from_bytes(&[0x11; 32]);
        let recipient = Hash::new([0x22; 32]);
        let tx = make_type1_tx(cid, &sender_sk, recipient, 1_000_000, 20_000, 0);

        // Max 0 transactions
        let mut pool = Mempool::with_config(MempoolConfig {
            max_transactions: 0,
            max_bytes: 10_000_000,
        });
        let res = pool.admit(&tx, &state);
        assert_eq!(res, Err(MempoolError::MempoolFull));
    }

    #[test]
    fn test_mempool_nonce_and_balance_conflicts() {
        let miner_sk = SigningKey::from_bytes(&[0x07; 32]);
        let (state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();

        let recipient1 = Hash::new([0x22; 32]);
        let recipient2 = Hash::new([0x33; 32]);

        let mut pool = Mempool::new();

        // Transaction 1: nonce 0, amount 100_000, fee 20_000
        let tx1 = make_type1_tx(cid, &miner_sk, recipient1, 100_000, 20_000, 0);
        let tx1_id = pool.admit(&tx1, &state).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx1_id));

        // Duplicate admission of tx1 -> AlreadyInMempool
        assert_eq!(
            pool.admit(&tx1, &state),
            Err(MempoolError::AlreadyInMempool(tx1_id))
        );

        // Competing Transaction with SAME nonce 0 to recipient2 -> ConflictingNonce
        let tx_competing = make_type1_tx(cid, &miner_sk, recipient2, 50_000, 20_000, 0);
        let res = pool.admit(&tx_competing, &state);
        assert!(matches!(res, Err(MempoolError::ConflictingNonce { .. })));

        // Nonce gap: trying nonce 2 instead of 1 -> ConflictingNonce
        let tx_gap = make_type1_tx(cid, &miner_sk, recipient2, 50_000, 20_000, 2);
        assert!(matches!(
            pool.admit(&tx_gap, &state),
            Err(MempoolError::ConflictingNonce { .. })
        ));

        // Sequential Transaction with nonce 1 -> succeeds!
        let tx2 = make_type1_tx(cid, &miner_sk, recipient2, 50_000, 20_000, 1);
        let tx2_id = pool.admit(&tx2, &state).unwrap();
        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&tx2_id));

        // Excess balance spend: account has 10 OWN mature (1_000_000_000 atoms)
        // Trying to spend 2_000_000_000 atoms with nonce 2 -> InsufficientSpendableBalance
        let tx_excess = make_type1_tx(cid, &miner_sk, recipient2, 2_000_000_000, 20_000, 2);
        assert!(matches!(
            pool.admit(&tx_excess, &state),
            Err(MempoolError::InsufficientSpendableBalance { .. })
        ));
    }

    #[test]
    fn test_mempool_block_inclusion_and_revalidation() {
        let miner_sk = SigningKey::from_bytes(&[0x07; 32]);
        let (mut state, last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();

        let recipient1 = Hash::new([0x22; 32]);
        let recipient2 = Hash::new([0x33; 32]);

        let mut pool = Mempool::new();

        let tx1 = make_type1_tx(cid, &miner_sk, recipient1, 100_000, 20_000, 0);
        let tx2 = make_type1_tx(cid, &miner_sk, recipient2, 50_000, 20_000, 1);

        let tx1_id = pool.admit(&tx1, &state).unwrap();
        let tx2_id = pool.admit(&tx2, &state).unwrap();
        assert_eq!(pool.len(), 2);

        // Include tx1 in a new block at height 102
        let h = 102;
        let cb = make_coinbase(cid, h, [0x05; 32]);
        let tx_ids = vec![transaction_id(&cb), tx1_id];
        let mut blk = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: h,
                parent_block_id: last_block.block_id(),
                transaction_root: merkle::tx_root(&tx_ids),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: last_block.header.timestamp + 120,
                difficulty: state.expected_difficulty_for_next_block().unwrap_or(1),
                nonce: 0,
            },
            transactions: vec![cb, tx1.clone()],
        };
        let root = state
            .simulate_candidate_state_root(&blk)
            .expect("simulated state root");
        blk.header.orchard_commitment_root = root;

        state.apply_block(&blk).unwrap();

        // Notify mempool of block acceptance
        pool.on_block_accepted(&blk, &state);

        // tx1 should be removed
        assert!(!pool.contains(&tx1_id));
        // tx2 should still be in mempool, revalidated against state where miner nonce is now 1
        assert!(pool.contains(&tx2_id));
        assert_eq!(pool.len(), 1);
    }

    fn make_test_key(seed: u8) -> SigningKey {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        key_bytes[31] = 0x01;
        SigningKey::from_bytes(&key_bytes)
    }

    #[test]
    fn test_mempool_type2_authorization_checks() {
        let miner_sk = make_test_key(1);
        let (state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();

        let mut guardians = [[0u8; 32]; 7];
        for (i, g) in guardians.iter_mut().enumerate() {
            *g = make_test_key(10 + i as u8).verifying_key().to_bytes();
        }
        let recovery_pk = make_test_key(99).verifying_key().to_bytes();

        // 1. Valid initial configuration (no guardian signatures required)
        let mut unsigned_prefix = Vec::with_capacity(371);
        unsigned_prefix.push(2); // Type 2
        unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
        unsigned_prefix.extend_from_slice(cid.as_bytes());
        unsigned_prefix.extend_from_slice(&miner_pk);
        unsigned_prefix.extend_from_slice(&0u64.to_le_bytes()); // nonce 0
        unsigned_prefix.extend_from_slice(&50_000u64.to_le_bytes()); // fee 50,000
        for g in &guardians {
            unsigned_prefix.extend_from_slice(g);
        }
        unsigned_prefix.extend_from_slice(&100u32.to_le_bytes()); // new_recipient_delay
        unsigned_prefix.extend_from_slice(&200u32.to_le_bytes()); // withdrawal_delay
        unsigned_prefix.extend_from_slice(&1_000_000u128.to_le_bytes()); // allowance_limit
        unsigned_prefix.extend_from_slice(&50u64.to_le_bytes()); // allowance_window_len
        unsigned_prefix.extend_from_slice(&recovery_pk);
        assert_eq!(unsigned_prefix.len(), 371);

        let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(&unsigned_prefix, &[]);
        let preimage = crate::auth::compute_signing_preimage(cid, &unsigned_tx);
        let valid_owner_sig = miner_sk.sign(&preimage);

        let mut valid_tx2 = unsigned_prefix.clone();
        valid_tx2.extend_from_slice(&valid_owner_sig.to_bytes());
        valid_tx2.push(0); // 0 guardian signatures

        let mut pool = Mempool::new();
        let admitted = pool.admit(&valid_tx2, &state);
        assert!(admitted.is_ok(), "Valid Type 2 must be admitted");

        // 2. Corrupted owner signature
        let mut bad_sig_tx = valid_tx2.clone();
        bad_sig_tx[371] ^= 0xff; // flip byte in owner signature
        let mut pool_bad_sig = Mempool::new();
        let res_bad_sig = pool_bad_sig.admit(&bad_sig_tx, &state);
        assert!(matches!(
            res_bad_sig,
            Err(MempoolError::InvalidSignature(_))
        ));

        // 3. Invalid recovery key (all zero)
        let mut bad_rec_tx = unsigned_prefix.clone();
        bad_rec_tx[339..371].copy_from_slice(&[0u8; 32]); // zero recovery key
        let unsigned_bad = crate::auth::canonical_unsigned_with_guardians(&bad_rec_tx, &[]);
        let pre_bad = crate::auth::compute_signing_preimage(cid, &unsigned_bad);
        let sig_bad = miner_sk.sign(&pre_bad);
        bad_rec_tx.extend_from_slice(&sig_bad.to_bytes());
        bad_rec_tx.push(0);
        let mut pool_bad_rec = Mempool::new();
        let res_bad_rec = pool_bad_rec.admit(&bad_rec_tx, &state);
        assert!(matches!(res_bad_rec, Err(MempoolError::Malformed(_))));
    }

    #[test]
    fn test_mempool_type3_guardian_action_authorization_checks() {
        let miner_sk = make_test_key(1);
        let (state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);

        // Try guardian action on account that does NOT have guardians enabled
        let mut tx3 = Vec::new();
        tx3.push(3); // Type 3
        tx3.extend_from_slice(&1u16.to_le_bytes());
        tx3.extend_from_slice(cid.as_bytes());
        tx3.extend_from_slice(miner_addr.as_bytes());
        tx3.push(crate::auth::ACTION_FREEZE);
        tx3.extend_from_slice(&50_000u64.to_le_bytes()); // fee
        tx3.extend_from_slice(&0u32.to_le_bytes()); // params_len = 0
        tx3.push(0); // 0 guardian signatures

        let mut pool = Mempool::new();
        let res = pool.admit(&tx3, &state);
        assert!(matches!(res, Err(MempoolError::Malformed(_))));
    }

    #[test]
    fn test_mempool_type3_strengthen_allowance_zero_bypass_regression() {
        let miner_sk = make_test_key(1);
        let (mut state, last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);

        let guardian_sks: Vec<SigningKey> = (10..17).map(make_test_key).collect();
        let mut guardians = [[0u8; 32]; 7];
        for (i, sk) in guardian_sks.iter().enumerate() {
            guardians[i] = sk.verifying_key().to_bytes();
        }
        let recovery_pk = make_test_key(99).verifying_key().to_bytes();

        // Configure guardians with active allowance: 1_000_000 limit, 50 window length
        let mut unsigned_prefix = Vec::with_capacity(371);
        unsigned_prefix.push(2); // Type 2
        unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
        unsigned_prefix.extend_from_slice(cid.as_bytes());
        unsigned_prefix.extend_from_slice(&miner_pk);
        unsigned_prefix.extend_from_slice(&0u64.to_le_bytes()); // nonce 0
        unsigned_prefix.extend_from_slice(&50_000u64.to_le_bytes()); // fee 50,000
        for g in &guardians {
            unsigned_prefix.extend_from_slice(g);
        }
        unsigned_prefix.extend_from_slice(&100u32.to_le_bytes()); // new_recipient_delay
        unsigned_prefix.extend_from_slice(&200u32.to_le_bytes()); // withdrawal_delay
        unsigned_prefix.extend_from_slice(&1_000_000u128.to_le_bytes()); // allowance_limit
        unsigned_prefix.extend_from_slice(&50u64.to_le_bytes()); // allowance_window_len
        unsigned_prefix.extend_from_slice(&recovery_pk);

        let unsigned_tx = crate::auth::canonical_unsigned_with_guardians(&unsigned_prefix, &[]);
        let preimage = crate::auth::compute_signing_preimage(cid, &unsigned_tx);
        let owner_sig = miner_sk.sign(&preimage);

        let mut config_tx2 = unsigned_prefix;
        config_tx2.extend_from_slice(&owner_sig.to_bytes());
        config_tx2.push(0); // 0 guardian signatures

        // Apply config to chain state at height 102
        let cb = make_coinbase(cid, 102, *miner_addr.as_bytes());
        let cb_id = transaction_id(&cb);
        let cfg_id = transaction_id(&config_tx2);
        let mut blk = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 102,
                parent_block_id: last_block.block_id(),
                transaction_root: merkle::tx_root(&[cb_id, cfg_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: last_block.header.timestamp + 120,
                difficulty: state.expected_difficulty_for_next_block().unwrap_or(1),
                nonce: 0,
            },
            transactions: vec![cb, config_tx2],
        };
        let root = state
            .simulate_candidate_state_root(&blk)
            .expect("simulated state root");
        blk.header.orchard_commitment_root = root;
        state.apply_block(&blk).unwrap();

        assert_eq!(
            state.account(&miner_addr).unwrap().allowance_limit,
            1_000_000
        );
        assert_eq!(state.account(&miner_addr).unwrap().allowance_window_len, 50);

        let make_strengthen_tx = |new_lim: u128, new_len: u64| -> Vec<u8> {
            let mut params = Vec::with_capacity(24);
            params.extend_from_slice(&new_lim.to_le_bytes());
            params.extend_from_slice(&new_len.to_le_bytes());

            let mut prefix = Vec::new();
            prefix.push(3); // Type 3
            prefix.extend_from_slice(&1u16.to_le_bytes());
            prefix.extend_from_slice(cid.as_bytes());
            prefix.extend_from_slice(miner_addr.as_bytes());
            prefix.push(crate::auth::ACTION_STRENGTHEN_ALLOWANCE);
            prefix.extend_from_slice(&50_000u64.to_le_bytes()); // fee
            prefix.extend_from_slice(&(params.len() as u32).to_le_bytes());
            prefix.extend_from_slice(&params);

            let indices = [0u8, 1, 2];
            let unsigned = crate::auth::canonical_unsigned_with_indices(&prefix, &indices);
            let preimage = crate::auth::compute_signing_preimage(cid, &unsigned);

            let mut tx = prefix;
            tx.push(3); // 3 guardian signatures
            for idx in indices {
                tx.push(idx);
                let sig = guardian_sks[idx as usize].sign(&preimage);
                tx.extend_from_slice(&sig.to_bytes());
            }
            tx
        };

        // 1. Zero limit is rejected by mempool
        let tx_zero_lim = make_strengthen_tx(0, 50);
        let mut pool = Mempool::new();
        let res_zero_lim = pool.admit(&tx_zero_lim, &state);
        assert!(matches!(
            res_zero_lim,
            Err(MempoolError::Malformed(msg)) if msg.contains("cannot disable allowance with 3-of-7 quorum")
        ));
        assert_eq!(pool.len(), 0);

        // 2. Zero window length is rejected by mempool
        let tx_zero_len = make_strengthen_tx(1_000_000, 0);
        let mut pool2 = Mempool::new();
        let res_zero_len = pool2.admit(&tx_zero_len, &state);
        assert!(matches!(
            res_zero_len,
            Err(MempoolError::Malformed(msg)) if msg.contains("cannot disable allowance with 3-of-7 quorum")
        ));
        assert_eq!(pool2.len(), 0);

        // 3. Both zero is rejected by mempool
        let tx_zero_both = make_strengthen_tx(0, 0);
        let mut pool3 = Mempool::new();
        let res_zero_both = pool3.admit(&tx_zero_both, &state);
        assert!(matches!(
            res_zero_both,
            Err(MempoolError::Malformed(msg)) if msg.contains("cannot disable allowance with 3-of-7 quorum")
        ));
        assert_eq!(pool3.len(), 0);

        // 4. Increasing limit is rejected by mempool
        let tx_inc = make_strengthen_tx(2_000_000, 50);
        let mut pool4 = Mempool::new();
        let res_inc = pool4.admit(&tx_inc, &state);
        assert!(matches!(
            res_inc,
            Err(MempoolError::Malformed(msg)) if msg.contains("cannot increase limit with 3-of-7 quorum")
        ));
        assert_eq!(pool4.len(), 0);

        // 5. Shortening window is rejected by mempool
        let tx_short = make_strengthen_tx(1_000_000, 20);
        let mut pool5 = Mempool::new();
        let res_short = pool5.admit(&tx_short, &state);
        assert!(matches!(
            res_short,
            Err(MempoolError::Malformed(msg)) if msg.contains("cannot shorten window with 3-of-7 quorum")
        ));
        assert_eq!(pool5.len(), 0);

        // 6. Legitimate tightening is admitted to mempool
        let tx_tight = make_strengthen_tx(600_000, 100);
        let mut pool6 = Mempool::new();
        let res_tight = pool6.admit(&tx_tight, &state);
        assert!(
            res_tight.is_ok(),
            "Legitimate tightening must be admitted: {res_tight:?}"
        );
        assert_eq!(pool6.len(), 1);

        // 7. Positive-value re-enabling on disabled allowance is admitted to mempool
        let mut weaken_params = Vec::with_capacity(24);
        weaken_params.extend_from_slice(&0u128.to_le_bytes());
        weaken_params.extend_from_slice(&0u64.to_le_bytes());

        let mut weaken_prefix = Vec::new();
        weaken_prefix.push(3);
        weaken_prefix.extend_from_slice(&1u16.to_le_bytes());
        weaken_prefix.extend_from_slice(cid.as_bytes());
        weaken_prefix.extend_from_slice(miner_addr.as_bytes());
        weaken_prefix.push(crate::auth::ACTION_WEAKEN_ALLOWANCE);
        weaken_prefix.extend_from_slice(&50_000u64.to_le_bytes());
        weaken_prefix.extend_from_slice(&(weaken_params.len() as u32).to_le_bytes());
        weaken_prefix.extend_from_slice(&weaken_params);

        let weaken_indices = [0u8, 1, 2, 3];
        let unsigned_weaken =
            crate::auth::canonical_unsigned_with_indices(&weaken_prefix, &weaken_indices);
        let preimage_weaken = crate::auth::compute_signing_preimage(cid, &unsigned_weaken);

        let mut weaken_tx = weaken_prefix;
        weaken_tx.push(4);
        for idx in weaken_indices {
            weaken_tx.push(idx);
            let sig = guardian_sks[idx as usize].sign(&preimage_weaken);
            weaken_tx.extend_from_slice(&sig.to_bytes());
        }

        let cb103 = make_coinbase(cid, 103, *miner_addr.as_bytes());
        let cb103_id = transaction_id(&cb103);
        let w_id = transaction_id(&weaken_tx);
        let mut blk103 = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 103,
                parent_block_id: blk.block_id(),
                transaction_root: merkle::tx_root(&[cb103_id, w_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: blk.header.timestamp + 120,
                difficulty: state.expected_difficulty_for_next_block().unwrap_or(1),
                nonce: 0,
            },
            transactions: vec![cb103, weaken_tx],
        };
        let root103 = state
            .simulate_candidate_state_root(&blk103)
            .expect("simulated state root");
        blk103.header.orchard_commitment_root = root103;
        state.apply_block(&blk103).unwrap();

        assert_eq!(state.account(&miner_addr).unwrap().allowance_limit, 0);
        assert_eq!(state.account(&miner_addr).unwrap().allowance_window_len, 0);

        let tx_enable = make_strengthen_tx(500_000, 75);
        let mut pool7 = Mempool::new();
        let res_enable = pool7.admit(&tx_enable, &state);
        assert!(
            res_enable.is_ok(),
            "Positive-value re-enabling must be admitted: {res_enable:?}"
        );
        assert_eq!(pool7.len(), 1);
    }

    #[test]
    fn test_mempool_type4_cancel_pending_authorization_checks() {
        let miner_sk = make_test_key(1);
        let (state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();

        // Try cancel pending on account without guardians
        let mut tx4 = Vec::new();
        tx4.push(4); // Type 4
        tx4.extend_from_slice(&1u16.to_le_bytes());
        tx4.extend_from_slice(cid.as_bytes());
        tx4.extend_from_slice(&miner_pk);
        tx4.extend_from_slice(&[0xaa; 32]); // transfer_id
        tx4.extend_from_slice(&50_000u64.to_le_bytes()); // fee
        tx4.extend_from_slice(&0u64.to_le_bytes()); // nonce
        let fake_sig = [0u8; 64];
        tx4.extend_from_slice(&fake_sig);
        tx4.push(0); // 0 guardian sigs

        let mut pool = Mempool::new();
        let res = pool.admit(&tx4, &state);
        assert!(res.is_err(), "Must be rejected");
    }

    use crate::orchard_tree::EMPTY_ROOTS;
    use crate::orchard_tx::serialize_bundle;
    use orchard::builder::{Builder, BundleType, InProgress, Unauthorized};
    use orchard::bundle::{BundleVersion, Flags};
    use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
    use orchard::keys::{
        FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey,
    };
    use orchard::note::{ExtractedNoteCommitment, Note};
    use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
    use orchard::value::NoteValue;
    use orchard::Proof;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::OnceLock;

    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();

    fn get_proving_key() -> &'static ProvingKey {
        PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
    }

    fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
        let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
        let path = MerklePath::from_parts(0, auth_path);
        let anchor = path.root(*cmx);
        (anchor, path)
    }

    fn build_test_type6_bundle(
        shielded_amount: u64,
        seed: u8,
    ) -> (
        orchard::Bundle<InProgress<Proof, Unauthorized>, i64>,
        Note,
        ExtractedNoteCommitment,
    ) {
        let mut rng = StdRng::from_seed([seed; 32]);
        let pk = get_proving_key();

        let recipient_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
        let recipient_fvk = FullViewingKey::from(&recipient_sk);
        let recipient_address = recipient_fvk.address_at(0u32, Scope::External);

        let mut builder = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .unwrap();

        let ovk = OutgoingViewingKey::from([0x55; 32]);
        builder
            .add_output(
                Some(ovk.clone()),
                recipient_address,
                NoteValue::from_raw(shielded_amount),
                [0u8; 512],
            )
            .unwrap();

        let (unauth_bundle, meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let note = unauth_bundle
            .recover_output_with_ovk(meta.output_action_index(0).unwrap(), &ovk)
            .unwrap()
            .0;
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let proven_bundle = unauth_bundle.create_proof(pk, &mut rng).unwrap();
        (proven_bundle, note, cmx)
    }

    fn make_test_type6_tx(
        chain_id: Hash,
        sender_sk: &SigningKey,
        nonce: u64,
        shielded_amount: u128,
        fee_atoms: u64,
        proven_bundle: &orchard::Bundle<InProgress<Proof, Unauthorized>, i64>,
    ) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(42);
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let auth_digest = compute_type6_bundle_auth_digest(
            *chain_id.as_bytes(),
            1u16,
            sender_pk,
            nonce,
            shielded_amount,
            fee_atoms,
            proven_bundle,
        );
        let authorized_bundle = proven_bundle
            .clone()
            .apply_signatures(&mut rng, auth_digest, &[])
            .unwrap();
        let bundle_bytes = serialize_bundle(&authorized_bundle);
        let sender_sig = sender_sk.sign(&auth_digest).to_bytes();

        let mut raw_tx = Vec::new();
        raw_tx.push(6u8); // Type 6
        raw_tx.extend_from_slice(&1u16.to_le_bytes());
        raw_tx.extend_from_slice(chain_id.as_bytes());

        raw_tx.extend_from_slice(&sender_pk);
        raw_tx.extend_from_slice(&nonce.to_le_bytes());
        raw_tx.extend_from_slice(&shielded_amount.to_le_bytes());
        raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
        raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
        raw_tx.extend_from_slice(&bundle_bytes);
        raw_tx.extend_from_slice(&sender_sig);
        raw_tx.push(0); // 0 guardian signatures
        raw_tx
    }

    #[allow(clippy::too_many_arguments)]
    fn build_test_type7_bundle(
        user_sk: &SpendingKey,
        seed_note: Note,
        seed_path: MerklePath,
        anchor: Anchor,
        _release_amount: u64,
        change_amount: u64,
        _fee_atoms: u64,
        seed: u8,
    ) -> orchard::Bundle<InProgress<Proof, Unauthorized>, i64> {
        let mut rng = StdRng::from_seed([seed; 32]);
        let pk = get_proving_key();
        let user_fvk = FullViewingKey::from(user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);
        let user_ovk = OutgoingViewingKey::from([0x55; 32]);

        let mut builder = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            anchor,
        )
        .unwrap();

        builder.add_spend(user_fvk, seed_note, seed_path).unwrap();
        if change_amount > 0 {
            builder
                .add_output(
                    Some(user_ovk),
                    user_address,
                    NoteValue::from_raw(change_amount),
                    [0u8; 512],
                )
                .unwrap();
        }

        let (unauth, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        unauth.create_proof(pk, &mut rng).unwrap()
    }

    fn make_test_type7_tx(
        chain_id: Hash,
        user_sk: &SpendingKey,
        recipient: Hash,
        release_amount: u128,
        fee_atoms: u64,
        proven_bundle: &orchard::Bundle<InProgress<Proof, Unauthorized>, i64>,
    ) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(99);
        let auth_digest = compute_type7_bundle_auth_digest(
            *chain_id.as_bytes(),
            1u16,
            *recipient.as_bytes(),
            release_amount,
            fee_atoms,
            proven_bundle,
        );
        let spend_auth_key = SpendAuthorizingKey::from(user_sk);
        let spend_auth_keys: Vec<SpendAuthorizingKey> = (0..proven_bundle.actions().len())
            .map(|_| spend_auth_key.clone())
            .collect();
        let authorized_bundle = proven_bundle
            .clone()
            .apply_signatures(&mut rng, auth_digest, &spend_auth_keys)
            .unwrap();
        let bundle_bytes = serialize_bundle(&authorized_bundle);

        let mut raw_tx = Vec::new();
        raw_tx.push(7u8); // Type 7
        raw_tx.extend_from_slice(&1u16.to_le_bytes());
        raw_tx.extend_from_slice(chain_id.as_bytes());

        raw_tx.extend_from_slice(recipient.as_bytes());
        raw_tx.extend_from_slice(&release_amount.to_le_bytes());
        raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
        raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
        raw_tx.extend_from_slice(&bundle_bytes);
        raw_tx
    }

    #[test]
    fn test_mempool_type6_value_balance_mismatch_rejected() {
        let miner_sk = make_test_key(1);
        let (state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();

        // Build valid proven bundle with 50_000_000 atoms (value_balance = -50_000_000)
        let (proven, _, _) = build_test_type6_bundle(50_000_000, 0x11);

        // Put outer shielded_amount = 80_000_000 with fee = 1_000_000
        // Valid proof and signatures, but outer shielded_amount != bundle value balance
        let bad_type6 = make_test_type6_tx(cid, &miner_sk, 0, 80_000_000, 1_000_000, &proven);

        let mut pool = Mempool::new();
        let res = pool.admit(&bad_type6, &state);
        assert_eq!(
            res,
            Err(MempoolError::ValueBalanceMismatch {
                value_balance: -50_000_000,
                expected: -80_000_000,
            }),
            "Type 6 with inconsistent shielded amount must be rejected with ValueBalanceMismatch"
        );
    }

    #[test]
    fn test_mempool_type7_value_balance_mismatch_rejected() {
        let miner_sk = make_test_key(1);
        let (mut state, last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);
        let user_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();

        // 1. Advance chain with valid Type 6 block to deposit 100M note into tree and pool
        let (type6_proven, seed_note, seed_cmx) = build_test_type6_bundle(100_000_000, 0x22);
        let valid_type6 =
            make_test_type6_tx(cid, &miner_sk, 0, 100_000_000, 1_000_000, &type6_proven);

        let (anchor, path) = single_leaf_witness(&seed_cmx);

        let next_h = last_block.header.height + 1;
        let cb = make_coinbase(cid, next_h, *miner_addr.as_bytes());
        let cb_id = transaction_id(&cb);
        let tx6_id = transaction_id(&valid_type6);
        let mut blk = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: next_h,
                parent_block_id: last_block.block_id(),
                transaction_root: merkle::tx_root(&[cb_id, tx6_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: last_block.header.timestamp + 120,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![cb, valid_type6],
        };
        let root = state.simulate_candidate_state_root(&blk).expect("root");
        blk.header.orchard_commitment_root = root;
        state.apply_block(&blk).expect("apply type 6 block");

        // 2. Build Type 7 bundle spending 100M note, with change 39M (value_balance = 61_000_000)
        let type7_proven = build_test_type7_bundle(
            &user_sk, seed_note, path, anchor, 60_000_000, 39_000_000, 1_000_000, 0x33,
        );

        // Put outer release_amount = 40_000_000 and fee = 1_000_000 (expected_vb = 41_000_000)
        // Bundle value balance is 61_000_000. Outer total deshield is 41_000_000.
        let recipient = Hash::new([0x33; 32]);
        let bad_type7 = make_test_type7_tx(
            cid,
            &user_sk,
            recipient,
            40_000_000,
            1_000_000,
            &type7_proven,
        );

        let mut pool = Mempool::new();
        let res = pool.admit(&bad_type7, &state);
        assert_eq!(
            res,
            Err(MempoolError::ValueBalanceMismatch {
                value_balance: 61_000_000,
                expected: 41_000_000,
            }),
            "Type 7 with inconsistent release amount must be rejected with ValueBalanceMismatch"
        );
    }

    #[test]
    fn test_mempool_valid_type6_and_type7_admission() {
        let miner_sk = make_test_key(1);
        let (mut state, last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);
        let user_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();

        // 1. Valid Type 6 transaction admitted to mempool
        let (type6_proven, seed_note, seed_cmx) = build_test_type6_bundle(100_000_000, 0x44);
        let valid_type6 =
            make_test_type6_tx(cid, &miner_sk, 0, 100_000_000, 1_000_000, &type6_proven);

        let mut pool = Mempool::new();
        let tx6_id = pool
            .admit(&valid_type6, &state)
            .expect("Valid Type 6 must be admitted");
        assert!(pool.contains(&tx6_id));
        assert_eq!(pool.len(), 1);

        // 2. Include Type 6 in block so anchor and pool balance are updated on chain
        let (anchor, path) = single_leaf_witness(&seed_cmx);
        let next_h = last_block.header.height + 1;
        let cb = make_coinbase(cid, next_h, *miner_addr.as_bytes());
        let cb_id = transaction_id(&cb);
        let mut blk = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: next_h,
                parent_block_id: last_block.block_id(),
                transaction_root: merkle::tx_root(&[cb_id, tx6_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: last_block.header.timestamp + 120,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![cb, valid_type6],
        };
        let root = state.simulate_candidate_state_root(&blk).expect("root");
        blk.header.orchard_commitment_root = root;
        state.apply_block(&blk).expect("apply block");

        // 3. Valid Type 7 transaction (releases 60M + 1M fee, value_balance = 61M) admitted to mempool
        let type7_proven = build_test_type7_bundle(
            &user_sk, seed_note, path, anchor, 60_000_000, 39_000_000, 1_000_000, 0x55,
        );
        let recipient = Hash::new([0x33; 32]);
        let valid_type7 = make_test_type7_tx(
            cid,
            &user_sk,
            recipient,
            60_000_000,
            1_000_000,
            &type7_proven,
        );

        let mut pool7 = Mempool::new();
        let tx7_id = pool7
            .admit(&valid_type7, &state)
            .expect("Valid Type 7 must be admitted");
        assert!(pool7.contains(&tx7_id));
        assert_eq!(pool7.len(), 1);
    }

    #[test]
    fn test_mempool_duplicate_nullifiers_within_same_tx_rejected() {
        let miner_sk = make_test_key(1);
        let (mut state, last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);
        let user_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();

        // Deposit note to get an anchor
        let (type6_proven, seed_note, seed_cmx) = build_test_type6_bundle(100_000_000, 0x66);
        let valid_type6 =
            make_test_type6_tx(cid, &miner_sk, 0, 100_000_000, 1_000_000, &type6_proven);
        let (anchor, seed_path) = single_leaf_witness(&seed_cmx);

        let next_h = last_block.header.height + 1;
        let cb = make_coinbase(cid, next_h, *miner_addr.as_bytes());
        let cb_id = transaction_id(&cb);
        let tx6_id = transaction_id(&valid_type6);
        let mut blk = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: next_h,
                parent_block_id: last_block.block_id(),
                transaction_root: merkle::tx_root(&[cb_id, tx6_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: last_block.header.timestamp + 120,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![cb, valid_type6],
        };
        let root = state.simulate_candidate_state_root(&blk).expect("root");
        blk.header.orchard_commitment_root = root;
        state.apply_block(&blk).expect("apply block");

        // Build 2-action bundle spending seed_note twice (yielding duplicate nullifiers)
        let mut rng = StdRng::from_seed([0x77; 32]);
        let pk = get_proving_key();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);
        let user_ovk = OutgoingViewingKey::from([0x55; 32]);

        let mut builder = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            anchor,
        )
        .unwrap();

        builder
            .add_spend(user_fvk.clone(), seed_note, seed_path.clone())
            .unwrap();
        builder
            .add_spend(user_fvk.clone(), seed_note, seed_path.clone())
            .unwrap();
        builder
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(139_000_000),
                [0u8; 512],
            )
            .unwrap();

        let (unauth_dup, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_dup_proven = unauth_dup.create_proof(pk, &mut rng).unwrap();

        let recipient = Hash::new([0x33; 32]);
        let dup_type7 = make_test_type7_tx(
            cid,
            &user_sk,
            recipient,
            60_000_000,
            1_000_000,
            &type7_dup_proven,
        );

        let mut pool = Mempool::new();
        let res = pool.admit(&dup_type7, &state);
        assert!(
            matches!(res, Err(MempoolError::DuplicateNullifierInTx(_))),
            "Type 7 with duplicate nullifiers must be rejected with DuplicateNullifierInTx"
        );

        // Also test Type 5 with duplicate nullifiers
        let mut builder5 = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            anchor,
        )
        .unwrap();
        builder5
            .add_spend(user_fvk.clone(), seed_note, seed_path.clone())
            .unwrap();
        builder5.add_spend(user_fvk, seed_note, seed_path).unwrap();
        builder5
            .add_output(
                Some(user_ovk),
                user_address,
                NoteValue::from_raw(199_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth5_dup, _) = builder5.build::<i64>(&mut rng).unwrap().unwrap();
        let type5_dup_proven = unauth5_dup.create_proof(pk, &mut rng).unwrap();
        let sighash5 = crate::orchard_tx::compute_bundle_auth_digest(
            *cid.as_bytes(),
            crate::tx::TxType::ShieldedTransfer.tag(),
            1u16,
            1_000_000,
            &type5_dup_proven,
        );
        let spend_auth_key = SpendAuthorizingKey::from(&user_sk);
        let spend_auth_keys5 = vec![spend_auth_key.clone(), spend_auth_key];
        let authorized5 = type5_dup_proven
            .apply_signatures(&mut rng, sighash5, &spend_auth_keys5)
            .unwrap();
        let bundle5_bytes = serialize_bundle(&authorized5);

        let mut raw_tx5 = Vec::new();
        raw_tx5.push(5u8); // Type 5
        raw_tx5.extend_from_slice(&1u16.to_le_bytes());
        raw_tx5.extend_from_slice(cid.as_bytes());
        raw_tx5.extend_from_slice(&1_000_000u64.to_le_bytes()); // fee
        raw_tx5.extend_from_slice(&bundle5_bytes);

        let res5 = pool.admit(&raw_tx5, &state);
        assert!(
            matches!(res5, Err(MempoolError::DuplicateNullifierInTx(_))),
            "Type 5 with duplicate nullifiers must be rejected with DuplicateNullifierInTx"
        );
    }

    #[test]
    fn test_check_mempool_allowance_semantics() {
        // 1. Normal boundary: start = 100, len = 50 -> window_end = 150
        let mut acct = AccountState::new();
        acct.allowance_limit = 1_000;
        acct.allowance_window_start = 100;
        acct.allowance_window_len = 50;
        acct.allowance_spent = 600;

        // At height 149 (< 150): window active
        assert!(check_mempool_allowance(&acct, 149, 300).is_ok());
        let err = check_mempool_allowance(&acct, 149, 500).unwrap_err();
        assert!(matches!(err, MempoolError::AllowanceExceeded(_)));

        // At height 150 (>= 150): window expires
        assert!(check_mempool_allowance(&acct, 150, 400).is_ok());

        // 2. Overflowing window end: start = 100, len = u64::MAX
        let mut acct_overflow = AccountState::new();
        acct_overflow.allowance_limit = 1_000;
        acct_overflow.allowance_window_start = 100;
        acct_overflow.allowance_window_len = u64::MAX;
        acct_overflow.allowance_spent = 300;

        // Window never expires mathematically; spending within limit succeeds
        assert!(check_mempool_allowance(&acct_overflow, 200, 400).is_ok());

        // At height = u64::MAX, window is still unexpired without arithmetic failure
        assert!(check_mempool_allowance(&acct_overflow, u64::MAX, 400).is_ok());

        // 4. Allowance exhaustion is enforced even when window overflows
        assert!(matches!(
            check_mempool_allowance(&acct_overflow, 200, 800),
            Err(MempoolError::AllowanceExceeded(_))
        ));
        assert!(matches!(
            check_mempool_allowance(&acct_overflow, u64::MAX, 800),
            Err(MempoolError::AllowanceExceeded(_))
        ));
    }

    #[test]
    fn test_f06_mempool_nonce_exhaustion_regression() {
        let miner_sk = SigningKey::from_bytes(&[0x42; 32]);
        let (mut state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);
        let recipient = Hash::new([0x99; 32]);

        let mut pool = Mempool::new();

        // 1. Normal sequential nonce admission
        let tx0 = make_type1_tx(cid, &miner_sk, recipient, 100_000, 20_000, 0);
        let tx0_id = pool.admit(&tx0, &state).expect("tx0 admission");
        assert!(pool.contains(&tx0_id));

        let tx1 = make_type1_tx(cid, &miner_sk, recipient, 100_000, 20_000, 1);
        let tx1_id = pool.admit(&tx1, &state).expect("tx1 admission");
        assert!(pool.contains(&tx1_id));

        // 2. Duplicate and gap nonce rejection
        // Duplicate nonce 0
        let tx0_dup = make_type1_tx(cid, &miner_sk, recipient, 50_000, 20_000, 0);
        let err_dup = pool.admit(&tx0_dup, &state).unwrap_err();
        assert!(matches!(
            err_dup,
            MempoolError::ConflictingNonce {
                expected: 2,
                found: 0,
                ..
            }
        ));

        // Gap nonce 3 (expected 2)
        let tx_gap = make_type1_tx(cid, &miner_sk, recipient, 50_000, 20_000, 3);
        let err_gap = pool.admit(&tx_gap, &state).unwrap_err();
        assert!(matches!(
            err_gap,
            MempoolError::ConflictingNonce {
                expected: 2,
                found: 3,
                ..
            }
        ));

        // 3. Admission from committed nonce u64::MAX - 1
        let mut pool_near_exhaustion = Mempool::new();
        let acct = state.accounts.get_mut(&miner_addr).unwrap();
        acct.nonce = u64::MAX - 1;

        let tx_max_minus_1 =
            make_type1_tx(cid, &miner_sk, recipient, 100_000, 20_000, u64::MAX - 1);
        let tx_mm1_id = pool_near_exhaustion
            .admit(&tx_max_minus_1, &state)
            .expect("tx with nonce u64::MAX - 1 must be admitted");
        assert!(pool_near_exhaustion.contains(&tx_mm1_id));

        // 4. Rejection of the next transaction requiring nonce u64::MAX
        let tx_max = make_type1_tx(cid, &miner_sk, recipient, 100_000, 20_000, u64::MAX);
        let err_exhausted = pool_near_exhaustion.admit(&tx_max, &state).unwrap_err();
        assert_eq!(
            err_exhausted,
            MempoolError::NonceExhausted(miner_addr),
            "Tx requiring nonce u64::MAX must be rejected with NonceExhausted"
        );

        // Also test directly when committed nonce is already u64::MAX
        let mut pool_exhausted = Mempool::new();
        let acct_exhausted = state.accounts.get_mut(&miner_addr).unwrap();
        acct_exhausted.nonce = u64::MAX;

        let err_committed_max = pool_exhausted.admit(&tx_max, &state).unwrap_err();
        assert_eq!(
            err_committed_max,
            MempoolError::NonceExhausted(miner_addr),
            "Account with committed nonce u64::MAX must be rejected with NonceExhausted"
        );

        // 5. Multiple pending transactions cannot share an exhausted nonce
        let tx_max_competing = make_type1_tx(
            cid,
            &miner_sk,
            Hash::new([0x88; 32]),
            50_000,
            20_000,
            u64::MAX,
        );
        let err_competing = pool_near_exhaustion
            .admit(&tx_max_competing, &state)
            .unwrap_err();
        assert_eq!(err_competing, MempoolError::NonceExhausted(miner_addr));
        assert_eq!(pool_near_exhaustion.len(), 1);
    }

    #[test]
    fn test_f01_mempool_anchor_window_boundary_regression() {
        let cid = test_chain_id();
        let genesis = crate::genesis::genesis_block(cid);
        let mut state = ChainState::from_genesis(&genesis).unwrap();
        let miner_sk = SigningKey::from_bytes(&[0x05; 32]);
        let miner_pk = miner_sk.verifying_key().to_bytes();
        let miner_addr = derive_address(&miner_pk);

        // Pre-fund miner transparent balance and issuance so Type 6 deposit in block 1 succeeds without waiting 100 blocks
        let miner_acct = state.accounts.entry(miner_addr).or_default();
        miner_acct.balance = 1_000_000_000;
        state.cumulative_issuance += 1_000_000_000;

        let mut anchors = Vec::new();
        anchors.push(empty_commitment_root()); // height 0 anchor

        let pool = Mempool::new();

        // 1. Advance chain with valid Type 6 block to deposit 100M note at block 1
        let (type6_proven, seed_note, seed_cmx) = build_test_type6_bundle(100_000_000, 0x11);
        let valid_type6 =
            make_test_type6_tx(cid, &miner_sk, 0, 100_000_000, 1_000_000, &type6_proven);
        let (anchor1, _seed_path) = single_leaf_witness(&seed_cmx);

        let mut prev_time = genesis.header.timestamp + 120;
        let cb1 = make_coinbase(cid, 1, *miner_addr.as_bytes());
        let cb1_id = transaction_id(&cb1);
        let tx6_id = transaction_id(&valid_type6);
        let mut blk1 = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 1,
                parent_block_id: genesis.block_id(),
                transaction_root: merkle::tx_root(&[cb1_id, tx6_id]),
                orchard_commitment_root: empty_commitment_root(),
                timestamp: prev_time,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![cb1, valid_type6],
        };
        let root1 = state.simulate_candidate_state_root(&blk1).expect("root 1");
        blk1.header.orchard_commitment_root = root1;
        state.apply_block(&blk1).unwrap();
        anchors.push(state.historical_anchors().get(&1).copied().unwrap());
        assert_eq!(anchors[1], Hash::new(anchor1.to_bytes()));

        // Mine blocks 2 through 12 (coinbase only)
        let mut last_block = blk1;
        let mut state_at_tip9: Option<ChainState> = None;
        let mut state_at_tip10: Option<ChainState> = None;
        let mut state_at_tip11: Option<ChainState> = None;

        for h in 2..=12 {
            prev_time += 120;
            let cb = make_coinbase(cid, h, *miner_addr.as_bytes());
            let cb_id = transaction_id(&cb);
            let mut blk = Block {
                header: Header {
                    version: 1,
                    chain_id: cid,
                    height: h,
                    parent_block_id: last_block.block_id(),
                    transaction_root: merkle::tx_root(&[cb_id]),
                    orchard_commitment_root: empty_commitment_root(),
                    timestamp: prev_time,
                    difficulty: 1,
                    nonce: 0,
                },
                transactions: vec![cb],
            };
            let root = state
                .simulate_candidate_state_root(&blk)
                .expect("simulated state root");
            blk.header.orchard_commitment_root = root;
            state.apply_block(&blk).unwrap();
            last_block = blk;
            // Assign distinct historical anchor for each block height h >= 2 so each height has a distinct root
            let distinct_anchor = Hash::new([h as u8; 32]);
            state.historical_anchors.insert(h, distinct_anchor);
            anchors.push(distinct_anchor);

            if h == 9 {
                state_at_tip9 = Some(state.clone());
            } else if h == 10 {
                state_at_tip10 = Some(state.clone());
            } else if h == 11 {
                state_at_tip11 = Some(state.clone());
            }
        }

        let s9 = state_at_tip9.unwrap();
        let s10 = state_at_tip10.unwrap();
        let s11 = state_at_tip11.unwrap();

        // 1. Boundary at tip height 9 / candidate height 10:
        // Window is [0, 9], cand_h = 10 <= 10 -> anchor 0 (genesis root) IS admitted
        let anchors_tip9 = pool.active_anchor_set(&s9);
        assert!(
            anchors_tip9.contains(&anchors[0]),
            "Genesis anchor 0 must be admitted at tip height 9 (candidate height 10)"
        );
        assert!(anchors_tip9.contains(&anchors[1]));
        assert!(anchors_tip9.contains(&anchors[9]));

        // Focused assertion: absent height-0 entry must NOT insert the empty commitment root
        let mut s9_without_height0 = s9.clone();
        s9_without_height0.historical_anchors.remove(&0);
        let anchors_without_h0 = pool.active_anchor_set(&s9_without_height0);
        assert!(
            !anchors_without_h0.contains(&empty_commitment_root()),
            "Absent height-0 entry must not insert empty commitment root"
        );

        // 2. Boundary at tip height 10 / candidate height 11:
        // Window is [1, 10], cand_h = 11 > 10 -> anchor 0 (genesis root) MUST be rejected!
        let anchors_tip10 = pool.active_anchor_set(&s10);
        assert!(
            !anchors_tip10.contains(&anchors[0]),
            "Genesis anchor 0 must be REJECTED at tip height 10 (candidate height 11)"
        );
        // 4. Oldest valid anchor accepted: anchor 1
        assert!(
            anchors_tip10.contains(&anchors[1]),
            "Oldest valid anchor 1 must be accepted at tip height 10"
        );
        assert!(anchors_tip10.contains(&anchors[10]));

        // 3. Boundary at tip height 11 / candidate height 12:
        // Window is [2, 11], cand_h = 12 > 10
        let anchors_tip11 = pool.active_anchor_set(&s11);
        // 5. One-block-too-old anchor rejected: anchor 1 rejected at candidate height 12
        assert!(
            !anchors_tip11.contains(&anchors[1]),
            "Anchor 1 is one-block-too-old and must be rejected at tip height 11 (candidate height 12)"
        );
        assert!(
            !anchors_tip11.contains(&anchors[0]),
            "Anchor 0 must be rejected at tip height 11"
        );
        // Oldest valid anchor accepted: anchor 2
        assert!(
            anchors_tip11.contains(&anchors[2]),
            "Oldest valid anchor 2 must be accepted at tip height 11"
        );
        assert!(anchors_tip11.contains(&anchors[11]));

        // 6. Type 5 and Type 7 admission use the same valid anchor set:
        // Build valid Type 7 and Type 5 bundles rooted at anchor1
        let user_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);
        let user_ovk = OutgoingViewingKey::from([0x55; 32]);
        let pk = get_proving_key();

        let recipient = Hash::new([0x33; 32]);
        let type7_tx = make_test_type7_tx(
            cid,
            &user_sk,
            recipient,
            60_000_000,
            1_000_000,
            &build_test_type7_bundle(
                &user_sk,
                seed_note,
                single_leaf_witness(&seed_cmx).1,
                anchor1,
                60_000_000,
                39_000_000,
                1_000_000,
                0x88,
            ),
        );

        let mut rng = StdRng::from_seed([0x77; 32]);
        let mut builder5 = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            anchor1,
        )
        .unwrap();
        builder5
            .add_spend(
                user_fvk.clone(),
                seed_note,
                single_leaf_witness(&seed_cmx).1,
            )
            .unwrap();
        builder5
            .add_output(
                Some(user_ovk),
                user_address,
                NoteValue::from_raw(99_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth5, _) = builder5.build::<i64>(&mut rng).unwrap().unwrap();
        let type5_proven = unauth5.create_proof(pk, &mut rng).unwrap();
        let sighash5 = crate::orchard_tx::compute_bundle_auth_digest(
            *cid.as_bytes(),
            crate::tx::TxType::ShieldedTransfer.tag(),
            1u16,
            1_000_000,
            &type5_proven,
        );
        let spend_auth_key = SpendAuthorizingKey::from(&user_sk);
        let spend_auth_keys5 = vec![spend_auth_key];
        let authorized5 = type5_proven
            .apply_signatures(&mut rng, sighash5, &spend_auth_keys5)
            .unwrap();
        let bundle5_bytes = serialize_bundle(&authorized5);

        let mut type5_tx = Vec::new();
        type5_tx.push(5u8); // Type 5
        type5_tx.extend_from_slice(&1u16.to_le_bytes());
        type5_tx.extend_from_slice(cid.as_bytes());
        type5_tx.extend_from_slice(&1_000_000u64.to_le_bytes()); // fee
        type5_tx.extend_from_slice(&bundle5_bytes);

        // At tip height 10 (candidate height 11):
        // anchor1 is the oldest valid anchor in window [1, 10]. Both Type 5 and Type 7 must be admitted!
        let mut pool10_t7 = Mempool::new();
        let res7_at_10 = pool10_t7.admit(&type7_tx, &s10);
        assert!(
            res7_at_10.is_ok(),
            "Type 7 with anchor1 must be admitted at tip height 10 (oldest valid anchor): {res7_at_10:?}"
        );

        let mut pool10_t5 = Mempool::new();
        let res5_at_10 = pool10_t5.admit(&type5_tx, &s10);
        assert!(
            res5_at_10.is_ok(),
            "Type 5 with anchor1 must be admitted at tip height 10 (oldest valid anchor): {res5_at_10:?}"
        );

        // At tip height 11 (candidate height 12):
        // anchor1 is one-block-too-old for window [2, 11]. Both Type 5 and Type 7 must be rejected with StaleAnchor!
        let mut pool11_t7 = Mempool::new();
        let res7_at_11 = pool11_t7.admit(&type7_tx, &s11);
        assert_eq!(
            res7_at_11,
            Err(MempoolError::StaleAnchor(anchors[1])),
            "Type 7 with anchor1 must be rejected with StaleAnchor at tip height 11"
        );

        let mut pool11_t5 = Mempool::new();
        let res5_at_11 = pool11_t5.admit(&type5_tx, &s11);
        assert_eq!(
            res5_at_11,
            Err(MempoolError::StaleAnchor(anchors[1])),
            "Type 5 with anchor1 must be rejected with StaleAnchor at tip height 11"
        );
    }
    fn make_test_type4_tx(
        chain_id: Hash,
        sender_sk: &SigningKey,
        transfer_id: Hash,
        fee_atoms: u64,
        nonce: u64,
        guardian_signers: &[(u8, &SigningKey)],
    ) -> Vec<u8> {
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let mut unsigned_prefix = Vec::with_capacity(115);
        unsigned_prefix.push(4); // Type 4
        unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
        unsigned_prefix.extend_from_slice(chain_id.as_bytes());
        unsigned_prefix.extend_from_slice(&sender_pk);
        unsigned_prefix.extend_from_slice(transfer_id.as_bytes());
        unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
        unsigned_prefix.extend_from_slice(&nonce.to_le_bytes());

        let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
        let unsigned_tx =
            crate::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
        let preimage = crate::auth::compute_signing_preimage(chain_id, &unsigned_tx);
        let sender_sig = sender_sk.sign(&preimage);

        let mut tx = unsigned_prefix;
        tx.extend_from_slice(&sender_sig.to_bytes());
        tx.push(guardian_signers.len() as u8);
        for (idx, signer) in guardian_signers {
            tx.push(*idx);
            let g_sig = signer.sign(&preimage);
            tx.extend_from_slice(&g_sig.to_bytes());
        }
        tx
    }

    #[test]
    fn test_f04_type5_and_type7_shielded_pool_reservations() {
        let miner_sk = make_test_key(1);
        let (mut state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();
        let user_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);
        let user_ovk = OutgoingViewingKey::from([0x55; 32]);
        let pk = get_proving_key();

        // Build 3 independent notes with single-leaf paths
        let (_b1, note1, cmx1) = build_test_type6_bundle(100_000_000, 0x11);
        let (anchor1, path1) = single_leaf_witness(&cmx1);

        let (_b2, note2, cmx2) = build_test_type6_bundle(100_000_000, 0x22);
        let (anchor2, path2) = single_leaf_witness(&cmx2);

        let (_b3, note3, cmx3) = build_test_type6_bundle(100_000_000, 0x33);
        let (anchor3, path3) = single_leaf_witness(&cmx3);

        // Insert anchors into active window (candidate height = 102, window = [92, 101])
        state
            .historical_anchors
            .insert(101, Hash::new(anchor1.to_bytes()));
        state
            .historical_anchors
            .insert(100, Hash::new(anchor2.to_bytes()));
        state
            .historical_anchors
            .insert(99, Hash::new(anchor3.to_bytes()));

        // Type 5 tx 1: spends note1, output 99M, fee 1M (value_balance = 1M)
        let mut rng1 = StdRng::seed_from_u64(1);
        let mut builder1 = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            anchor1,
        )
        .unwrap();
        builder1.add_spend(user_fvk.clone(), note1, path1).unwrap();
        builder1
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(99_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth1, _) = builder1.build::<i64>(&mut rng1).unwrap().unwrap();
        let proven1 = unauth1.create_proof(pk, &mut rng1).unwrap();
        let sighash1 = crate::orchard_tx::compute_bundle_auth_digest(
            *cid.as_bytes(),
            TxType::ShieldedTransfer.tag(),
            1u16,
            1_000_000,
            &proven1,
        );
        let auth_key = SpendAuthorizingKey::from(&user_sk);
        let auth_bundle1 = proven1
            .apply_signatures(&mut rng1, sighash1, std::slice::from_ref(&auth_key))
            .unwrap();
        let b_bytes1 = serialize_bundle(&auth_bundle1);
        let mut type5_tx1 = Vec::new();
        type5_tx1.push(5u8);
        type5_tx1.extend_from_slice(&1u16.to_le_bytes());
        type5_tx1.extend_from_slice(cid.as_bytes());
        type5_tx1.extend_from_slice(&1_000_000u64.to_le_bytes());
        type5_tx1.extend_from_slice(&b_bytes1);

        // Type 5 tx 2: spends note2, output 98.5M, fee 1.5M (value_balance = 1.5M)
        let mut rng2 = StdRng::seed_from_u64(2);
        let mut builder2 = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            anchor2,
        )
        .unwrap();
        builder2.add_spend(user_fvk.clone(), note2, path2).unwrap();
        builder2
            .add_output(
                Some(user_ovk),
                user_address,
                NoteValue::from_raw(98_500_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth2, _) = builder2.build::<i64>(&mut rng2).unwrap().unwrap();
        let proven2 = unauth2.create_proof(pk, &mut rng2).unwrap();
        let sighash2 = crate::orchard_tx::compute_bundle_auth_digest(
            *cid.as_bytes(),
            TxType::ShieldedTransfer.tag(),
            1u16,
            1_500_000,
            &proven2,
        );
        let auth_bundle2 = proven2
            .clone()
            .apply_signatures(&mut rng2, sighash2, &[auth_key])
            .unwrap();
        let b_bytes2 = serialize_bundle(&auth_bundle2);
        let mut type5_tx2 = Vec::new();
        type5_tx2.push(5u8);
        type5_tx2.extend_from_slice(&1u16.to_le_bytes());
        type5_tx2.extend_from_slice(cid.as_bytes());
        type5_tx2.extend_from_slice(&1_500_000u64.to_le_bytes());
        type5_tx2.extend_from_slice(&b_bytes2);

        // Type 7 tx: spends note3, release 60M, fee 1M, change 39M (total deshield = 61M)
        let type7_proven = build_test_type7_bundle(
            &user_sk, note3, path3, anchor3, 60_000_000, 39_000_000, 1_000_000, 0x33,
        );
        let recipient = Hash::new([0x33; 32]);
        let type7_tx = make_test_type7_tx(
            cid,
            &user_sk,
            recipient,
            60_000_000,
            1_000_000,
            &type7_proven,
        );

        let mut pool = Mempool::new();

        // 1. Rejection when confirmed pool balance is 0
        state.shielded_pool_balance = 0;
        let res_zero = pool.admit(&type5_tx1, &state);
        assert_eq!(
            res_zero,
            Err(MempoolError::InsufficientShieldedPoolBalance {
                available: 0,
                required: 1_000_000,
            }),
            "Type 5 must be rejected when confirmed pool balance is 0"
        );

        // 2. Rejection when confirmed balance is strictly less than fee
        state.shielded_pool_balance = 999_999;
        let res_insufficient = pool.admit(&type5_tx1, &state);
        assert_eq!(
            res_insufficient,
            Err(MempoolError::InsufficientShieldedPoolBalance {
                available: 999_999,
                required: 1_000_000,
            }),
            "Type 5 must be rejected when balance < fee"
        );

        // 3. Admission when balance is sufficient, reserving fee
        state.shielded_pool_balance = 2_000_000;
        let id1 = pool
            .admit(&type5_tx1, &state)
            .expect("Type 5 tx 1 must be admitted");
        assert_eq!(
            pool.total_pending_shielded_drain(),
            1_000_000,
            "Type 5 fee must be reserved in pending shielded drain"
        );

        // 4. Two Type 5s whose combined fees exceed balance cannot both be admitted
        // Available: 2_000_000. Needed: 1_000_000 (pending) + 1_500_000 (tx2) = 2_500_000.
        let res_exceed = pool.admit(&type5_tx2, &state);
        assert_eq!(
            res_exceed,
            Err(MempoolError::InsufficientShieldedPoolBalance {
                available: 2_000_000,
                required: 2_500_000,
            }),
            "Second Type 5 must be rejected when aggregate fee exceeds confirmed pool balance"
        );
        assert_eq!(
            pool.total_pending_shielded_drain(),
            1_000_000,
            "Pending drain must remain unchanged after rejected admission"
        );

        // 5. Removing Type 5 releases its fee reservation
        let removed = pool.remove(&id1);
        assert!(removed.is_some());
        assert_eq!(
            pool.total_pending_shielded_drain(),
            0,
            "Removal of Type 5 must release its fee reservation"
        );

        // Now tx2 (fee 1.5M <= 2.0M) can be admitted
        let id2 = pool
            .admit(&type5_tx2, &state)
            .expect("Type 5 tx 2 must be admitted after fee release");
        assert_eq!(pool.total_pending_shielded_drain(), 1_500_000);

        // 6. Shared reservation between Type 5 and Type 7
        // Set pool balance to exact sum: 1.5M (tx2 fee) + 61M (Type 7 deshield) = 62.5M
        state.shielded_pool_balance = 62_500_000;
        let id7 = pool
            .admit(&type7_tx, &state)
            .expect("Type 7 must be admitted at exact shared boundary");
        assert_eq!(
            pool.total_pending_shielded_drain(),
            62_500_000,
            "Pending drain must correctly sum Type 5 fee + Type 7 total deshield"
        );

        // Any further transaction exceeds balance
        let res_exceed_shared = pool.admit(&type5_tx1, &state);
        assert_eq!(
            res_exceed_shared,
            Err(MempoolError::InsufficientShieldedPoolBalance {
                available: 62_500_000,
                required: 63_500_000,
            }),
            "Additional drain beyond shared balance must be rejected"
        );

        // 7. Revalidation clears and rebuilds reservations accurately without double counting
        pool.revalidate(&state);
        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&id2));
        assert!(pool.contains(&id7));
        assert_eq!(
            pool.total_pending_shielded_drain(),
            62_500_000,
            "Revalidation must preserve exact aggregate drain without double-counting"
        );

        // 8. Revalidation against reduced balance evicts transaction that no longer fits
        state.shielded_pool_balance = 1_500_000;
        pool.revalidate(&state);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&id2));
        assert!(!pool.contains(&id7));
        assert_eq!(
            pool.total_pending_shielded_drain(),
            1_500_000,
            "Eviction during revalidation must update shielded drain reservation"
        );

        // 9. Real block inclusion via on_block_accepted:
        // Reset pool with both type5_tx2 (drain 1.5M) and type7_tx (drain 61M)
        state.shielded_pool_balance = 62_500_000;
        let mut pool = Mempool::new();
        let id2 = pool.admit(&type5_tx2, &state).unwrap();
        let id7 = pool.admit(&type7_tx, &state).unwrap();
        assert_eq!(pool.total_pending_shielded_drain(), 62_500_000);

        // A new block confirms type5_tx2: consensus deducts fee (1.5M) from pool
        let mut state_after_b1 = state.clone();
        state_after_b1.shielded_pool_balance -= 1_500_000; // now 61_000_000
        for act in proven2.actions() {
            let nf = Hash::new(act.nullifier().to_bytes());
            state_after_b1.nullifier_set.insert(nf);
        }

        let blk1 = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 102,
                parent_block_id: Hash::new([0x01; 32]),
                transaction_root: Hash::new([0x02; 32]),
                orchard_commitment_root: Hash::new([0x03; 32]),
                timestamp: 1000,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![type5_tx2.clone()],
        };

        pool.on_block_accepted(&blk1, &state_after_b1);

        // Included Type 5 is removed from mempool
        assert!(!pool.contains(&id2), "Included Type 5 must be removed");
        // Remaining pending Type 7 retains its reservation
        assert!(pool.contains(&id7), "Remaining Type 7 must be retained");
        assert_eq!(pool.len(), 1);
        // Type 5 reservation released exactly once; remaining drain matches Type 7
        assert_eq!(
            pool.total_pending_shielded_drain(),
            61_000_000,
            "Reservation for Type 5 must be released; remaining Type 7 drain must be 61M"
        );

        // A second block confirms type7_tx: consensus deducts total deshield (61M) from pool
        let mut state_after_b2 = state_after_b1.clone();
        state_after_b2.shielded_pool_balance -= 61_000_000; // now 0
        for act in type7_proven.actions() {
            let nf = Hash::new(act.nullifier().to_bytes());
            state_after_b2.nullifier_set.insert(nf);
        }

        let blk2 = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 103,
                parent_block_id: Hash::new([0x04; 32]),
                transaction_root: Hash::new([0x05; 32]),
                orchard_commitment_root: Hash::new([0x06; 32]),
                timestamp: 1120,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![type7_tx.clone()],
        };

        pool.on_block_accepted(&blk2, &state_after_b2);

        // Included Type 7 is removed from mempool
        assert!(!pool.contains(&id7), "Included Type 7 must be removed");
        assert_eq!(pool.len(), 0);
        // No stale or double-counted reservation remains
        assert_eq!(
            pool.total_pending_shielded_drain(),
            0,
            "Pending drain must be 0 after confirming all transactions"
        );
    }

    #[test]
    fn test_f03_type4_cancellation_target_reservations() {
        use crate::account::PendingTransfer;
        let miner_sk = make_test_key(1);
        let (mut state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();

        let alice_sk = SigningKey::from_bytes(&[0xaa; 32]);
        let alice_pk = alice_sk.verifying_key().to_bytes();
        let alice_addr = derive_address(&alice_pk);

        let guardian_sks: Vec<SigningKey> = (0x10..0x17)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let mut guardians = [[0u8; 32]; 7];
        for i in 0..7 {
            guardians[i] = guardian_sks[i].verifying_key().to_bytes();
        }

        let transfer1 = Hash::new([0x41; 32]);
        let transfer2 = Hash::new([0x42; 32]);

        let mut alice = AccountState::new();
        alice.balance = 1_000_000_000;
        alice.nonce = 10;
        alice.guardian_enabled = true;
        alice.guardians = guardians;
        alice.pending_transfers.push(PendingTransfer {
            transfer_id: transfer1,
            recipient: Hash::new([0xbb; 32]),
            amount: 100_000_000,
            release_height: 200,
        });
        alice.pending_transfers.push(PendingTransfer {
            transfer_id: transfer2,
            recipient: Hash::new([0xcc; 32]),
            amount: 200_000_000,
            release_height: 200,
        });
        state.accounts.insert(alice_addr, alice);

        let signers: Vec<(u8, &SigningKey)> = (0..4).map(|i| (i as u8, &guardian_sks[i])).collect();

        // Cancellation 1: targets transfer1 with nonce 10
        let cancel1_nonce10 = make_test_type4_tx(cid, &alice_sk, transfer1, 50_000, 10, &signers);

        // Cancellation 1 duplicate target: targets SAME transfer1 with sequential nonce 11
        let cancel1_nonce11 = make_test_type4_tx(cid, &alice_sk, transfer1, 50_000, 11, &signers);

        // Cancellation 2: targets DISTINCT transfer2 with sequential nonce 11
        let cancel2_nonce11 = make_test_type4_tx(cid, &alice_sk, transfer2, 50_000, 11, &signers);

        let mut pool = Mempool::new();

        // 1. First Type 4 targeting transfer1 is admitted
        let tx1_id = pool
            .admit(&cancel1_nonce10, &state)
            .expect("First cancellation must be admitted");
        assert!(pool.contains(&tx1_id));
        assert!(pool.is_cancellation_target_reserved(&transfer1));
        assert!(!pool.is_cancellation_target_reserved(&transfer2));

        // 2. Second Type 4 targeting the SAME transfer1 is rejected with ConflictingCancellation
        let res_dup = pool.admit(&cancel1_nonce11, &state);
        assert_eq!(
            res_dup,
            Err(MempoolError::ConflictingCancellation {
                transfer_id: transfer1,
                existing_tx: tx1_id,
            }),
            "Second cancellation targeting already-reserved transfer must be rejected"
        );

        // 3. Type 4 targeting DISTINCT transfer2 with sequential nonce is admitted
        let tx2_id = pool
            .admit(&cancel2_nonce11, &state)
            .expect("Cancellation targeting distinct transfer must be admitted");
        assert!(pool.contains(&tx2_id));
        assert!(pool.is_cancellation_target_reserved(&transfer1));
        assert!(pool.is_cancellation_target_reserved(&transfer2));

        // 4. Removal releases reservation accurately
        pool.remove(&tx1_id);
        assert!(
            !pool.is_cancellation_target_reserved(&transfer1),
            "Removing tx1 must release reservation on transfer1"
        );
        assert!(
            pool.is_cancellation_target_reserved(&transfer2),
            "Reservation on transfer2 must remain intact"
        );

        // Clean up and re-admit both in sequence for revalidation / block inclusion test
        pool.remove(&tx2_id);
        let id1_re = pool.admit(&cancel1_nonce10, &state).unwrap();
        let id2_re = pool.admit(&cancel2_nonce11, &state).unwrap();
        assert!(pool.is_cancellation_target_reserved(&transfer1));
        assert!(pool.is_cancellation_target_reserved(&transfer2));

        // 5. Revalidation rebuilds cancellation ledger without corruption
        pool.revalidate(&state);
        assert_eq!(pool.len(), 2);
        assert!(pool.is_cancellation_target_reserved(&transfer1));
        assert!(pool.is_cancellation_target_reserved(&transfer2));

        // 6. Confirmed cancellation in block removes stale reservation
        let mut state_after_block = state.clone();
        let acct_after = state_after_block.accounts.get_mut(&alice_addr).unwrap();
        acct_after.nonce = 11;
        acct_after.balance -= 50_000;
        acct_after
            .pending_transfers
            .retain(|p| p.transfer_id != transfer1);

        let blk = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 102,
                parent_block_id: Hash::new([0x01; 32]),
                transaction_root: Hash::new([0x02; 32]),
                orchard_commitment_root: Hash::new([0x03; 32]),
                timestamp: 1000,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![cancel1_nonce10.clone()],
        };

        pool.on_block_accepted(&blk, &state_after_block);

        // Confirmed tx1 removed, pending tx2 re-admitted against advanced nonce 11
        assert!(!pool.contains(&id1_re));
        assert!(pool.contains(&id2_re));
        assert!(
            !pool.is_cancellation_target_reserved(&transfer1),
            "Confirmed transfer1 must no longer be reserved"
        );
        assert!(
            pool.is_cancellation_target_reserved(&transfer2),
            "Unconfirmed transfer2 must still be reserved"
        );

        // Attempting to admit another cancellation for now-confirmed transfer1 fails
        let res_stale = pool.admit(&cancel1_nonce10, &state_after_block);
        assert!(
            matches!(res_stale, Err(MempoolError::Malformed(_))),
            "Cannot target transfer that is no longer pending on account"
        );
    }
    #[test]
    fn test_f03_cancellation_removal_ownership_regression() {
        use crate::account::PendingTransfer;
        let miner_sk = make_test_key(1);
        let (mut state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();

        let alice_sk = SigningKey::from_bytes(&[0xaa; 32]);
        let alice_pk = alice_sk.verifying_key().to_bytes();
        let alice_addr = derive_address(&alice_pk);

        let guardian_sks: Vec<SigningKey> = (0x10..0x17)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let mut guardians = [[0u8; 32]; 7];
        for i in 0..7 {
            guardians[i] = guardian_sks[i].verifying_key().to_bytes();
        }

        let transfer1 = Hash::new([0x41; 32]);

        let mut alice = AccountState::new();
        alice.balance = 1_000_000_000;
        alice.nonce = 10;
        alice.guardian_enabled = true;
        alice.guardians = guardians;
        alice.pending_transfers.push(PendingTransfer {
            transfer_id: transfer1,
            recipient: Hash::new([0xbb; 32]),
            amount: 100_000_000,
            release_height: 200,
        });
        state.accounts.insert(alice_addr, alice);

        let signers: Vec<(u8, &SigningKey)> = (0..4).map(|i| (i as u8, &guardian_sks[i])).collect();
        let cancel_tx = make_test_type4_tx(cid, &alice_sk, transfer1, 50_000, 10, &signers);

        let mut pool = Mempool::new();
        let real_tx_id = pool.admit(&cancel_tx, &state).expect("admit cancel_tx");
        assert_eq!(
            pool.cancellation_targets.get(&transfer1),
            Some(&real_tx_id),
            "Reservation must be owned by real_tx_id"
        );

        // Inject a foreign metadata entry referencing the same transfer target
        let foreign_tx_id = Hash::new([0xee; 32]);
        let foreign_meta = AdmittedTxMeta {
            tx_type: TxType::CancelPendingTransfer,
            size: 100,
            fee: 50_000,
            sender_account: Some(alice_addr),
            account_nonce: Some(9),
            account_spend: 50_000,
            nullifiers: Vec::new(),
            shielded_drain: 0,
            cancellation_target: Some(transfer1),
            allowance_consumption: 0,
            governance_lock: None,
        };
        pool.transactions.insert(foreign_tx_id, vec![0; 100]);
        pool.tx_meta.insert(foreign_tx_id, foreign_meta);

        // Removing the foreign transaction must NOT clear the reservation owned by real_tx_id
        let removed = pool.remove(&foreign_tx_id);
        assert!(removed.is_some());
        assert_eq!(
            pool.cancellation_targets.get(&transfer1),
            Some(&real_tx_id),
            "Ownership check must preserve real_tx_id's reservation when removing foreign tx"
        );
        assert!(
            pool.is_cancellation_target_reserved(&transfer1),
            "Target transfer1 must remain reserved"
        );
    }

    fn make_test_type3_tx(
        chain_id: Hash,
        target: Hash,
        action_type: u8,
        fee_atoms: u64,
        params: &[u8],
        guardian_signers: &[(u8, &SigningKey)],
    ) -> Vec<u8> {
        let mut unsigned_prefix = Vec::new();
        unsigned_prefix.push(3); // Type 3
        unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
        unsigned_prefix.extend_from_slice(chain_id.as_bytes());
        unsigned_prefix.extend_from_slice(target.as_bytes());
        unsigned_prefix.push(action_type);
        unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
        unsigned_prefix.extend_from_slice(&(params.len() as u32).to_le_bytes());
        unsigned_prefix.extend_from_slice(params);

        let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
        let unsigned_tx =
            crate::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
        let preimage = crate::auth::compute_signing_preimage(chain_id, &unsigned_tx);

        let mut tx = unsigned_prefix;
        tx.push(guardian_signers.len() as u8);
        for (idx, signer) in guardian_signers {
            tx.push(*idx);
            let g_sig = signer.sign(&preimage);
            tx.extend_from_slice(&g_sig.to_bytes());
        }
        tx
    }

    #[test]
    fn test_f02_pending_allowance_reservations() {
        let miner_sk = make_test_key(1);
        let (mut state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let cid = test_chain_id();

        let alice_sk = SigningKey::from_bytes(&[0xaa; 32]);
        let alice_pk = alice_sk.verifying_key().to_bytes();
        let alice_addr = derive_address(&alice_pk);

        let bob_sk = SigningKey::from_bytes(&[0xbb; 32]);
        let bob_pk = bob_sk.verifying_key().to_bytes();
        let bob_addr = derive_address(&bob_pk);

        let guardian_sks: Vec<SigningKey> = (0x10..0x17)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let mut guardians = [[0u8; 32]; 7];
        for i in 0..7 {
            guardians[i] = guardian_sks[i].verifying_key().to_bytes();
        }

        // Alice: balance 1B, allowance limit 1M, window len 50, window start 100, spent 0
        let mut alice = AccountState::new();
        alice.balance = 1_000_000_000;
        alice.nonce = 10;
        alice.guardian_enabled = true;
        alice.guardians = guardians;
        alice.allowance_limit = 1_000_000;
        alice.allowance_window_len = 50;
        alice.allowance_window_start = 100;
        alice.allowance_spent = 0;
        state.accounts.insert(alice_addr, alice);

        // Bob: balance 1B, allowance limit 1M, window len 50, window start 100, spent 0
        let mut bob = AccountState::new();
        bob.balance = 1_000_000_000;
        bob.nonce = 0;
        bob.allowance_limit = 1_000_000;
        bob.allowance_window_len = 50;
        bob.allowance_window_start = 100;
        bob.allowance_spent = 0;
        state.accounts.insert(bob_addr, bob);

        let mut pool = Mempool::new();
        let recipient = Hash::new([0x99; 32]);

        // 1. One transaction within allowance admitted
        // Alice tx1: amount 400_000, fee 50_000, total_spend 450_000
        let tx1 = make_type1_tx(cid, &alice_sk, recipient, 400_000, 50_000, 10);
        let tx1_id = pool
            .admit(&tx1, &state)
            .expect("tx1 within allowance admitted");
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            450_000,
            "Reservation must reflect tx1 allowance consumption"
        );

        // 2. Second transaction making aggregate pending allowance exceed limit is rejected
        // Alice tx2_too_large: amount 550_000, fee 50_000, total_spend 600_000 -> 450k + 600k = 1.05M > 1M
        let tx2_too_large = make_type1_tx(cid, &alice_sk, recipient, 550_000, 50_000, 11);
        let res2_fail = pool.admit(&tx2_too_large, &state);
        assert!(
            matches!(res2_fail, Err(MempoolError::AllowanceExceeded(_))),
            "Tx exceeding aggregate pending allowance limit must be rejected"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            450_000,
            "Failed admission must not alter existing allowance reservation"
        );

        // 3. Aggregate spending exactly equal to allowance limit accepted
        // Alice tx2_exact: amount 500_000, fee 50_000, total_spend 550_000 -> 450k + 550k = 1M == limit
        let tx2_exact = make_type1_tx(cid, &alice_sk, recipient, 500_000, 50_000, 11);
        let tx2_id = pool
            .admit(&tx2_exact, &state)
            .expect("tx2 at exact allowance boundary admitted");
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            1_000_000,
            "Aggregate reservation must reach exact allowance limit"
        );

        // 4. Removing a pending transaction releases its reservation
        let removed2 = pool.remove(&tx2_id);
        assert!(removed2.is_some());
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            450_000,
            "Removing tx2 must release its 550k reservation, leaving 450k"
        );

        // 5. Transactions from separate accounts have independent reservations
        let bob_tx = make_type1_tx(cid, &bob_sk, recipient, 300_000, 50_000, 0);
        let bob_tx_id = pool.admit(&bob_tx, &state).expect("bob_tx admitted");
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            450_000,
            "Alice's reservation remains unaffected by Bob's transaction"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&bob_addr),
            350_000,
            "Bob's reservation tracked independently"
        );

        // 6. Type 3 guardian-action fees consume allowance
        let dave_sk = SigningKey::from_bytes(&[0xdd; 32]);
        let dave_pk = dave_sk.verifying_key().to_bytes();
        let dave_addr = derive_address(&dave_pk);
        let mut dave = AccountState::new();
        dave.balance = 1_000_000_000;
        dave.nonce = 0;
        dave.guardian_enabled = true;
        dave.guardians = guardians;
        dave.allowance_limit = 1_000_000;
        dave.allowance_window_len = 50;
        dave.allowance_window_start = 100;
        dave.allowance_spent = 0;
        state.accounts.insert(dave_addr, dave);

        let signers: Vec<(u8, &SigningKey)> = (0..4).map(|i| (i as u8, &guardian_sks[i])).collect();
        let tx3_guardian = make_test_type3_tx(
            cid,
            dave_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let tx3_id = pool
            .admit(&tx3_guardian, &state)
            .expect("Type 3 guardian action admitted");
        assert_eq!(
            pool.pending_allowance_reservation(&dave_addr),
            50_000,
            "Dave's reservation must include Type 3 fee (50k)"
        );

        // 7. A zero available allowance cannot be bypassed by Type 3 actions
        let charlie_sk = SigningKey::from_bytes(&[0xcc; 32]);
        let charlie_pk = charlie_sk.verifying_key().to_bytes();
        let charlie_addr = derive_address(&charlie_pk);
        let mut charlie = AccountState::new();
        charlie.balance = 1_000_000_000;
        charlie.nonce = 0;
        charlie.guardian_enabled = true;
        charlie.guardians = guardians;
        charlie.allowance_limit = 50_000;
        charlie.allowance_window_len = 50;
        charlie.allowance_window_start = 100;
        charlie.allowance_spent = 50_000; // Zero available allowance
        state.accounts.insert(charlie_addr, charlie);

        let tx3_charlie = make_test_type3_tx(
            cid,
            charlie_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let res_charlie = pool.admit(&tx3_charlie, &state);
        assert!(
            matches!(res_charlie, Err(MempoolError::AllowanceExceeded(_))),
            "Type 3 guardian action cannot bypass zero remaining allowance"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&charlie_addr),
            0,
            "Charlie reservation must remain 0"
        );

        // 8. Revalidation clears and rebuilds reservations without double counting
        pool.revalidate(&state);
        assert!(pool.contains(&tx1_id));
        assert!(pool.contains(&bob_tx_id));
        assert!(pool.contains(&tx3_id));
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            450_000,
            "Revalidation must preserve Alice's exact reservation without double counting"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&bob_addr),
            350_000,
            "Revalidation must preserve Bob's exact reservation without double counting"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&dave_addr),
            50_000,
            "Revalidation must preserve Dave's exact reservation without double counting"
        );

        // 9. Changed chain state (increased allowance_spent) correctly evicts transactions that no longer fit
        let mut state_increased_spent = state.clone();
        let alice_acct_mod = state_increased_spent.accounts.get_mut(&alice_addr).unwrap();
        alice_acct_mod.allowance_spent = 1_000_000; // Exhaust all allowance
        pool.revalidate(&state_increased_spent);
        assert!(
            !pool.contains(&tx1_id),
            "tx1 must be evicted because allowance is fully exhausted"
        );
        assert!(
            pool.contains(&tx3_id),
            "Dave's tx3 remains admitted because Dave's state did not change"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            0,
            "Evicted transactions must clear Alice's pending allowance reservation"
        );
        assert!(
            pool.contains(&bob_tx_id),
            "Bob's tx remains admitted because Bob's state did not change"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&bob_addr),
            350_000,
            "Bob's reservation remains intact"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&dave_addr),
            50_000,
            "Dave's reservation remains intact"
        );

        // 10. Block inclusion (on_block_accepted) removes confirmed tx, revalidates remaining
        // pending txs against updated committed state, and avoids double-counting or stale reservations
        // Reset pool with tx1 (450k) and tx2_exact (550k) from fresh state
        let mut pool = Mempool::new();
        let id1 = pool.admit(&tx1, &state).unwrap();
        let id2 = pool.admit(&tx2_exact, &state).unwrap();
        assert_eq!(pool.pending_allowance_reservation(&alice_addr), 1_000_000);

        // A new block confirms tx1: Alice's committed allowance_spent becomes 450_000, nonce becomes 11
        let mut state_after_b1 = state.clone();
        let alice_after = state_after_b1.accounts.get_mut(&alice_addr).unwrap();
        alice_after.nonce = 11;
        alice_after.balance -= 450_000;
        alice_after.allowance_spent = 450_000;

        let blk1 = Block {
            header: Header {
                version: 1,
                chain_id: cid,
                height: 102,
                parent_block_id: Hash::new([0x01; 32]),
                transaction_root: Hash::new([0x02; 32]),
                orchard_commitment_root: Hash::new([0x03; 32]),
                timestamp: 1000,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![tx1.clone()],
        };

        pool.on_block_accepted(&blk1, &state_after_b1);

        assert!(!pool.contains(&id1), "Confirmed tx1 must be removed");
        assert!(pool.contains(&id2), "Pending tx2 must be retained");
        assert_eq!(
            pool.pending_allowance_reservation(&alice_addr),
            550_000,
            "Reservation must be tx2's 550k, not stale or double-counted"
        );

        // Attempting to admit another tx requiring 500k would exceed 1M (450k committed + 550k pending + 500k = 1.5M > 1M)
        let tx3_over = make_type1_tx(cid, &alice_sk, recipient, 450_000, 50_000, 12);
        let res_over = pool.admit(&tx3_over, &state_after_b1);
        assert!(
            matches!(res_over, Err(MempoolError::AllowanceExceeded(_))),
            "Cannot exceed allowance accounting for both committed spent and pending reservation"
        );

        // 11. F-07 overflow semantics remain intact:
        // Window end calculation overflow (checked_add is None) treats window as active (not expired).
        let mut unexpired_acct = AccountState::new();
        unexpired_acct.allowance_limit = 1_000_000;
        unexpired_acct.allowance_window_start = u64::MAX - 10;
        unexpired_acct.allowance_window_len = 50;
        unexpired_acct.allowance_spent = 300_000;

        // Current pending reservation = 200_000, new cost = 400_000 -> 300k + 200k + 400k = 900k <= 1M (Ok)
        assert!(check_account_allowance(&unexpired_acct, 100, 200_000, 400_000).is_ok());

        // New cost = 600_000 -> 300k + 200k + 600k = 1.1M > 1M (Err)
        assert!(matches!(
            check_account_allowance(&unexpired_acct, 100, 200_000, 600_000),
            Err(MempoolError::AllowanceExceeded(_))
        ));
    }

    // Helper constructs a raw Type 2 ConfigureGuardians transaction with full wire payload fields.
    #[allow(clippy::too_many_arguments)]
    fn make_test_type2_tx(
        chain_id: Hash,
        account_sk: &SigningKey,
        nonce: u64,
        fee_atoms: u64,
        new_guardians: &[[u8; 32]; 7],
        new_delay: u32,
        new_limit: u128,
        new_window: u64,
        recovery_key: &[u8; 32],
        guardian_signers: &[(u8, &SigningKey)],
    ) -> Vec<u8> {
        let mut unsigned_prefix = Vec::with_capacity(371);
        unsigned_prefix.push(2); // Type 2
        unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
        unsigned_prefix.extend_from_slice(chain_id.as_bytes());

        // Payload starts at offset 35
        unsigned_prefix.extend_from_slice(&account_sk.verifying_key().to_bytes()); // 32 bytes (account pubkey)
        unsigned_prefix.extend_from_slice(&nonce.to_le_bytes()); // 8 bytes
        unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes()); // 8 bytes
        for g in new_guardians {
            unsigned_prefix.extend_from_slice(g); // 7 * 32 = 224 bytes
        }
        unsigned_prefix.extend_from_slice(&new_delay.to_le_bytes()); // 4 bytes
        unsigned_prefix.extend_from_slice(&new_limit.to_le_bytes()); // 16 bytes
        unsigned_prefix.extend_from_slice(&new_window.to_le_bytes()); // 8 bytes
        unsigned_prefix.extend_from_slice(&[0u8; 4]); // 4 bytes padding to offset 304 (32+8+8+224+4+16+8 = 300; 300+4 = 304)
        unsigned_prefix.extend_from_slice(recovery_key); // 32 bytes (offset 304..336)
        assert_eq!(unsigned_prefix.len(), 371);

        let guardian_indices: Vec<u8> = guardian_signers.iter().map(|(idx, _)| *idx).collect();
        let unsigned_tx =
            crate::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
        let preimage = crate::auth::compute_signing_preimage(chain_id, &unsigned_tx);
        let owner_sig = account_sk.sign(&preimage);

        let mut tx = unsigned_prefix;
        tx.extend_from_slice(&owner_sig.to_bytes()); // 64 bytes (offset 371..435)
        tx.push(guardian_signers.len() as u8); // 1 byte count
        for (idx, signer) in guardian_signers {
            tx.push(*idx);
            let g_sig = signer.sign(&preimage);
            tx.extend_from_slice(&g_sig.to_bytes());
        }
        tx
    }

    fn make_test_type6_with_guardians_tx(
        chain_id: Hash,
        sender_sk: &SigningKey,
        nonce: u64,
        shielded_amount: u128,
        fee_atoms: u64,
        proven_bundle: &orchard::Bundle<InProgress<Proof, Unauthorized>, i64>,
        guardian_signers: &[(u8, &SigningKey)],
    ) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(42);
        let sender_pk = sender_sk.verifying_key().to_bytes();
        let auth_digest = compute_type6_bundle_auth_digest(
            *chain_id.as_bytes(),
            1u16,
            sender_pk,
            nonce,
            shielded_amount,
            fee_atoms,
            proven_bundle,
        );
        let authorized_bundle = proven_bundle
            .clone()
            .apply_signatures(&mut rng, auth_digest, &[])
            .unwrap();
        let bundle_bytes = serialize_bundle(&authorized_bundle);
        let sender_sig = sender_sk.sign(&auth_digest).to_bytes();

        let mut raw_tx = Vec::new();
        raw_tx.push(6u8); // Type 6
        raw_tx.extend_from_slice(&1u16.to_le_bytes());
        raw_tx.extend_from_slice(chain_id.as_bytes());

        raw_tx.extend_from_slice(&sender_pk);
        raw_tx.extend_from_slice(&nonce.to_le_bytes());
        raw_tx.extend_from_slice(&shielded_amount.to_le_bytes());
        raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
        raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
        raw_tx.extend_from_slice(&bundle_bytes);
        raw_tx.extend_from_slice(&sender_sig);
        raw_tx.push(guardian_signers.len() as u8);
        for (idx, signer) in guardian_signers {
            raw_tx.push(*idx);
            let g_sig = signer.sign(&auth_digest);
            raw_tx.extend_from_slice(&g_sig.to_bytes());
        }
        raw_tx
    }

    fn make_test_valid_type7_tx(
        chain_id: Hash,
        recipient: Hash,
        release_amount: u128,
        fee_atoms: u64,
        seed: u8,
    ) -> (Vec<u8>, Hash) {
        let user_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
        let (_b, note, cmx) = build_test_type6_bundle(100_000_000, seed);
        let (anchor, path) = single_leaf_witness(&cmx);
        let change = 100_000_000u64
            .checked_sub(release_amount as u64)
            .unwrap()
            .checked_sub(fee_atoms)
            .unwrap();
        let proven = build_test_type7_bundle(
            &user_sk,
            note,
            path,
            anchor,
            release_amount as u64,
            change,
            fee_atoms,
            seed.wrapping_add(1),
        );
        let raw = make_test_type7_tx(
            chain_id,
            &user_sk,
            recipient,
            release_amount,
            fee_atoms,
            &proven,
        );
        let anchor_hash = Hash::new(anchor.to_bytes());
        (raw, anchor_hash)
    }

    struct TestGovEnv {
        state: ChainState,
        chain_id: Hash,
        alice_sk: SigningKey,
        alice_addr: Hash,
        bob_sk: SigningKey,
        bob_addr: Hash,
        guardian_sks: Vec<SigningKey>,
        guardians: [[u8; 32]; 7],
        recipient: Hash,
    }

    impl TestGovEnv {
        fn signers(&self) -> Vec<(u8, &SigningKey)> {
            self.guardian_sks
                .iter()
                .enumerate()
                .take(4)
                .map(|(i, k)| (i as u8, k))
                .collect()
        }
    }

    fn setup_test_gov_env() -> TestGovEnv {
        let miner_sk = make_test_key(1);
        let (mut state, _last_block) = setup_chain_with_funded_account(&miner_sk);
        let chain_id = test_chain_id();

        let alice_sk = SigningKey::from_bytes(&[0xaa; 32]);
        let alice_pk = alice_sk.verifying_key().to_bytes();
        let alice_addr = derive_address(&alice_pk);

        let bob_sk = SigningKey::from_bytes(&[0xbb; 32]);
        let bob_pk = bob_sk.verifying_key().to_bytes();
        let bob_addr = derive_address(&bob_pk);

        let guardian_sks: Vec<SigningKey> = (0x10..0x17)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let mut guardians = [[0u8; 32]; 7];
        for i in 0..7 {
            guardians[i] = guardian_sks[i].verifying_key().to_bytes();
        }

        let mut alice = AccountState::new();
        alice.balance = 1_000_000_000;
        alice.nonce = 0;
        alice.guardian_enabled = true;
        alice.guardians = guardians;
        alice.allowance_limit = 1_000_000;
        alice.allowance_window_len = 50;
        alice.allowance_window_start = 100;
        let alice_rec_key = SigningKey::from_bytes(&[0x55; 32])
            .verifying_key()
            .to_bytes();
        let bob_rec_key = SigningKey::from_bytes(&[0x66; 32])
            .verifying_key()
            .to_bytes();

        alice.allowance_spent = 0;
        alice.recovery_key = alice_rec_key;
        state.accounts.insert(alice_addr, alice);

        let mut bob = AccountState::new();
        bob.balance = 1_000_000_000;
        bob.nonce = 0;
        bob.guardian_enabled = true;
        bob.guardians = guardians;
        bob.allowance_limit = 1_000_000;
        bob.allowance_window_len = 50;
        bob.allowance_window_start = 100;
        bob.allowance_spent = 0;
        bob.recovery_key = bob_rec_key;
        state.accounts.insert(bob_addr, bob);

        let recipient = Hash::new([0x99; 32]);

        TestGovEnv {
            state,
            chain_id,
            alice_sk,
            alice_addr,
            bob_sk,
            bob_addr,
            guardian_sks,
            guardians,
            recipient,
        }
    }
    // G01: Pending Type 1 transfer followed by Action 5 Freeze. Transfer evicted, reservations released.
    #[test]
    fn test_f05_g01_freeze_evicts_prior_transfer() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool.admit(&tx1, &env.state).expect("tx1 admitted");
        assert!(pool.contains(&tx1_id));
        assert_eq!(pool.pending_allowance_reservation(&env.alice_addr), 150_000);
        assert_eq!(pool.account_spends.get(&env.alice_addr), Some(&150_000));
        assert!(pool
            .account_nonces
            .get(&env.alice_addr)
            .unwrap()
            .contains(&0));

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("freeze admitted");

        assert!(!pool.contains(&tx1_id), "Prior transfer must be evicted");
        assert!(pool.contains(&freeze_id), "Freeze must be admitted");
        assert!(
            !pool.account_nonces.contains_key(&env.alice_addr),
            "Nonce reservation released"
        );
        assert_eq!(
            pool.account_spends.get(&env.alice_addr),
            Some(&50_000),
            "Only freeze fee reserved"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&env.alice_addr),
            50_000,
            "Only freeze fee reserved in allowance"
        );
        assert!(pool.is_account_governance_locked(&env.alice_addr));
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(freeze_id)
        );
        assert!(pool
            .governance_lock(&env.alice_addr)
            .unwrap()
            .is_emergency());
    }

    // G02: Pending Action 5 Freeze followed by Type 1 transfer. Transfer rejected.
    #[test]
    fn test_f05_g02_pending_freeze_blocks_subsequent_transfer() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("freeze admitted");
        assert!(pool.contains(&freeze_id));

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let res = pool.admit(&tx1, &env.state);
        assert_eq!(
            res,
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );
    }

    // G03: Pending Type 6 outgoing transaction followed by emergency freeze. Conflicting activity evicted.
    #[test]
    fn test_f05_g03_pending_type6_evicted_by_emergency_freeze() {
        let mut env = setup_test_gov_env();
        env.state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .allowance_limit = 2_000_000;
        let mut pool = Mempool::new();

        let (proven, _, _) = build_test_type6_bundle(100_000, 0x42);
        let tx6 = make_test_type6_with_guardians_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            100_000,
            1_000_000,
            &proven,
            &env.signers(),
        );
        let tx6_id = pool.admit(&tx6, &env.state).expect("tx6 admitted");
        assert!(pool.contains(&tx6_id));

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("freeze admitted");
        assert!(!pool.contains(&tx6_id), "Type 6 must be evicted");
        assert!(pool.contains(&freeze_id), "Freeze must be admitted");
        assert!(pool.is_account_governance_locked(&env.alice_addr));

        // Reverse order check: with freeze pending, new Type 6 is rejected
        let (proven2, _, _) = build_test_type6_bundle(100_000, 0x43);
        let tx6_subsequent = make_test_type6_with_guardians_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            100_000,
            1_000_000,
            &proven2,
            &env.signers(),
        );
        let res = pool.admit(&tx6_subsequent, &env.state);
        assert_eq!(
            res,
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );
    }

    // G04: Existing pending Type 1 transfer followed by Action 7 Recovery. Transfer evicted, recovery admitted.
    #[test]
    fn test_f05_g04_recovery_evicts_prior_transfer() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool.admit(&tx1, &env.state).expect("tx1 admitted");
        assert!(pool.contains(&tx1_id));

        let signers = env.signers();
        let rec_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_EMERGENCY_RECOVERY,
            50_000,
            &[],
            &signers,
        );
        let rec_id = pool.admit(&rec_tx, &env.state).expect("recovery admitted");
        assert!(!pool.contains(&tx1_id), "Prior transfer must be evicted");
        assert!(pool.contains(&rec_id), "Recovery admitted");
        assert!(pool.is_account_governance_locked(&env.alice_addr));
        assert!(pool
            .governance_lock(&env.alice_addr)
            .unwrap()
            .is_emergency());
    }

    // G05: Pending Recovery blocks subsequent Types 1, 2, 3, 4, 6 from target.
    #[test]
    fn test_f05_g05_pending_recovery_blocks_subsequent_transactions() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let rec_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_EMERGENCY_RECOVERY,
            50_000,
            &[],
            &signers,
        );
        let rec_id = pool.admit(&rec_tx, &env.state).expect("recovery admitted");

        // Type 1
        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        assert_eq!(
            pool.admit(&tx1, &env.state),
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );

        // Type 2
        let rec_key_2 = SigningKey::from_bytes(&[0x77; 32])
            .verifying_key()
            .to_bytes();
        let tx2 = make_test_type2_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            70_000,
            &env.guardians,
            100,
            1_000_000,
            50,
            &rec_key_2,
            &signers,
        );
        assert_eq!(
            pool.admit(&tx2, &env.state),
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: rec_id
            })
        );

        // Type 3
        let tx3 = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_STRENGTHEN_DELAYS,
            50_000,
            &100u32.to_le_bytes(),
            &signers[..3],
        );
        assert_eq!(
            pool.admit(&tx3, &env.state),
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: rec_id
            })
        );

        // Type 4
        let dummy_transfer = Hash::new([0x88; 32]);
        let tx4 = make_test_type4_tx(
            env.chain_id,
            &env.alice_sk,
            dummy_transfer,
            50_000,
            0,
            &signers,
        );
        assert_eq!(
            pool.admit(&tx4, &env.state),
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );

        // Type 6
        let (proven_t6, _, _) = build_test_type6_bundle(100_000, 0x44);
        let tx6 = make_test_type6_with_guardians_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            100_000,
            1_000_000,
            &proven_t6,
            &signers,
        );
        assert_eq!(
            pool.admit(&tx6, &env.state),
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );
    }

    // G06: Pending Recovery permits incoming Type 7 credit to the target account.
    #[test]
    fn test_f05_g06_pending_recovery_permits_incoming_type7() {
        let mut env = setup_test_gov_env();
        let mut pool = Mempool::new();

        env.state.shielded_pool_balance = 1_000_000_000;
        let (tx7, anchor) =
            make_test_valid_type7_tx(env.chain_id, env.alice_addr, 200_000, 1_000_000, 0x51);
        let tip = env.state.tip_height().unwrap();
        env.state.historical_anchors.insert(tip, anchor);

        let signers = env.signers();
        let rec_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_EMERGENCY_RECOVERY,
            50_000,
            &[],
            &signers,
        );
        pool.admit(&rec_tx, &env.state).expect("recovery admitted");
        let tx7_id = pool
            .admit(&tx7, &env.state)
            .expect("Type 7 crediting locked account admitted");
        assert!(pool.contains(&tx7_id));
    }

    // G07: Failed emergency admission does not evict existing transactions or change reservations.
    #[test]
    fn test_f05_g07_failed_emergency_admission_preserves_live_state() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool.admit(&tx1, &env.state).expect("tx1 admitted");

        let signers = env.signers();
        // A) Insufficient guardian quorum (3 instead of 4) fails signature verification
        let bad_freeze_quorum = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers[..3],
        );
        let res = pool.admit(&bad_freeze_quorum, &env.state);
        assert!(matches!(res, Err(MempoolError::InvalidSignature(_))));

        // B) Malformed payload (extra non-zero params for freeze) fails parameter length validation
        let bad_freeze_params = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[0x01; 4],
            &signers,
        );
        let res_params = pool.admit(&bad_freeze_params, &env.state);
        assert!(matches!(res_params, Err(MempoolError::Malformed(_))));

        assert!(pool.contains(&tx1_id), "tx1 must not be evicted");
        assert_eq!(pool.pending_allowance_reservation(&env.alice_addr), 150_000);
        assert_eq!(pool.account_spends.get(&env.alice_addr), Some(&150_000));
        assert!(pool
            .account_nonces
            .get(&env.alice_addr)
            .unwrap()
            .contains(&0));
        assert!(!pool.is_account_governance_locked(&env.alice_addr));
    }

    // G08: Pending guardian replacement blocks conflicting governance.
    #[test]
    fn test_f05_g08_guardian_replacement_serialization() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let new_guardian_sks: Vec<SigningKey> = (0x20..0x27)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let mut new_guardians = [[0u8; 32]; 7];
        for i in 0..7 {
            new_guardians[i] = new_guardian_sks[i].verifying_key().to_bytes();
        }
        let mut replace_params = Vec::with_capacity(224);
        for g in &new_guardians {
            replace_params.extend_from_slice(g);
        }

        let rep_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_REPLACE_GUARDIANS,
            70_000,
            &replace_params,
            &signers,
        );
        let rep_id = pool
            .admit(&rep_tx, &env.state)
            .expect("replace guardians admitted");

        let delay_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_STRENGTHEN_DELAYS,
            50_000,
            &100u32.to_le_bytes(),
            &signers[..3],
        );
        let res = pool.admit(&delay_tx, &env.state);
        assert_eq!(
            res,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: rep_id
            })
        );

        let mut pool2 = Mempool::new();
        let delay_id2 = pool2
            .admit(&delay_tx, &env.state)
            .expect("delay tx admitted");
        let res2 = pool2.admit(&rep_tx, &env.state);
        assert_eq!(
            res2,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: delay_id2
            })
        );
    }

    // G09: Pending Type 2 ConfigureGuardians conflicts with subsequent Type 3 actions.
    #[test]
    fn test_f05_g09_pending_type2_conflicts_with_type3() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let type2_tx = make_test_type2_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            70_000,
            &env.guardians,
            100,
            1_000_000,
            50,
            &SigningKey::from_bytes(&[0x77; 32])
                .verifying_key()
                .to_bytes(),
            &signers,
        );
        let type2_id = pool.admit(&type2_tx, &env.state).expect("Type 2 admitted");

        let delay_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_STRENGTHEN_DELAYS,
            50_000,
            &100u32.to_le_bytes(),
            &signers[..3],
        );
        let res = pool.admit(&delay_tx, &env.state);
        assert_eq!(
            res,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: type2_id
            })
        );

        let mut pool2 = Mempool::new();
        let delay_id2 = pool2
            .admit(&delay_tx, &env.state)
            .expect("delay tx admitted");
        let res2 = pool2.admit(&type2_tx, &env.state);
        assert_eq!(
            res2,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: delay_id2
            })
        );
    }

    // G10: Emergency preemption evicts maintenance action and takes lock.
    #[test]
    fn test_f05_g10_emergency_preemption_evicts_maintenance_action() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let delay_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_STRENGTHEN_DELAYS,
            50_000,
            &100u32.to_le_bytes(),
            &signers[..3],
        );
        let delay_id = pool
            .admit(&delay_tx, &env.state)
            .expect("delay tx admitted");
        assert!(pool.contains(&delay_id));
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(delay_id)
        );

        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("freeze admitted");
        assert!(
            !pool.contains(&delay_id),
            "Maintenance action must be evicted"
        );
        assert!(pool.contains(&freeze_id), "Freeze must be admitted");
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(freeze_id)
        );
        assert!(pool
            .governance_lock(&env.alice_addr)
            .unwrap()
            .is_emergency());
    }

    // G11: A pending maintenance governance action followed by an ordinary outgoing transaction is rejected.
    #[test]
    fn test_f05_g11_maintenance_action_waits_for_prior_transfers() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let delay_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_STRENGTHEN_DELAYS,
            50_000,
            &100u32.to_le_bytes(),
            &signers[..3],
        );
        pool.admit(&delay_tx, &env.state)
            .expect("delay tx admitted");

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let res = pool.admit(&tx1, &env.state);
        assert_eq!(
            res,
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );

        let mut pool2 = Mempool::new();
        let tx1_id2 = pool2.admit(&tx1, &env.state).expect("tx1 admitted");
        let res2 = pool2.admit(&delay_tx, &env.state);
        assert_eq!(
            res2,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: tx1_id2
            })
        );
    }

    // G12: An account frozen on-chain receives a valid pending Action 6 Unfreeze.
    #[test]
    fn test_f05_g12_frozen_account_admits_pending_unfreeze() {
        let mut env = setup_test_gov_env();
        let mut pool = Mempool::new();

        env.state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .is_frozen = true;

        let signers = env.signers();
        let unfreeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_UNFREEZE,
            50_000,
            &[],
            &signers,
        );
        let unfreeze_id = pool
            .admit(&unfreeze_tx, &env.state)
            .expect("unfreeze admitted");
        assert!(pool.contains(&unfreeze_id));
        assert!(pool.is_account_governance_locked(&env.alice_addr));
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(unfreeze_id)
        );
    }

    // G13: While unfreeze is pending, outgoing Type 1 transactions remain rejected.
    #[test]
    fn test_f05_g13_pending_unfreeze_keeps_outgoing_transfers_blocked() {
        let mut env = setup_test_gov_env();
        let mut pool = Mempool::new();

        env.state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .is_frozen = true;

        let signers = env.signers();
        let unfreeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_UNFREEZE,
            50_000,
            &[],
            &signers,
        );
        pool.admit(&unfreeze_tx, &env.state)
            .expect("unfreeze admitted");

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let res = pool.admit(&tx1, &env.state);
        assert_eq!(
            res,
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );
    }

    // G14: Confirm the unfreeze through on_block_accepted(). Lock clears and subsequent Type 1 succeeds.
    #[test]
    fn test_f05_g14_confirmed_unfreeze_clears_lock_and_allows_transfers() {
        let mut env = setup_test_gov_env();
        let mut pool = Mempool::new();

        env.state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .is_frozen = true;

        let signers = env.signers();
        let unfreeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_UNFREEZE,
            50_000,
            &[],
            &signers,
        );
        let unfreeze_id = pool
            .admit(&unfreeze_tx, &env.state)
            .expect("unfreeze admitted");

        let mut next_state = env.state.clone();
        let alice_next = next_state.accounts.get_mut(&env.alice_addr).unwrap();
        alice_next.is_frozen = false;
        alice_next.balance -= 50_000;

        let blk = Block {
            header: Header {
                version: 1,
                chain_id: env.chain_id,
                height: 101,
                parent_block_id: Hash::new([0x01; 32]),
                transaction_root: Hash::new([0x02; 32]),
                orchard_commitment_root: Hash::new([0x03; 32]),
                timestamp: 1000,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![unfreeze_tx.clone()],
        };

        pool.on_block_accepted(&blk, &next_state);
        assert!(!pool.contains(&unfreeze_id), "Confirmed unfreeze removed");
        assert!(
            !pool.is_account_governance_locked(&env.alice_addr),
            "Lock cleared"
        );

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool
            .admit(&tx1, &next_state)
            .expect("transfer admitted after unfreeze confirmation");
        assert!(pool.contains(&tx1_id));
    }

    // G15: A pending Freeze cannot coexist with a pending Unfreeze for the same account.
    #[test]
    fn test_f05_g15_pending_freeze_and_unfreeze_cannot_coexist() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let unfreeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_UNFREEZE,
            50_000,
            &[],
            &signers,
        );

        // Case A: Freeze pending -> Unfreeze rejected with PendingGovernanceConflict
        let freeze_id = pool.admit(&freeze_tx, &env.state).unwrap();
        let res_unfreeze = pool.admit(&unfreeze_tx, &env.state);
        assert_eq!(
            res_unfreeze,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: freeze_id
            })
        );

        // Case B: Unfreeze pending -> Freeze preempts and evicts Unfreeze
        let mut pool2 = Mempool::new();
        let unfreeze_id2 = pool2.admit(&unfreeze_tx, &env.state).unwrap();
        assert!(pool2.contains(&unfreeze_id2));

        let freeze_id2 = pool2.admit(&freeze_tx, &env.state).unwrap();
        assert!(
            !pool2.contains(&unfreeze_id2),
            "Unfreeze must be evicted by emergency freeze"
        );
        assert!(pool2.contains(&freeze_id2), "Freeze admitted");
        assert_eq!(
            pool2.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(freeze_id2)
        );
    }

    // G16: Ownership-checked governance-lock removal.
    #[test]
    fn test_f05_g16_ownership_checked_governance_lock_removal() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let real_tx_id = pool.admit(&freeze_tx, &env.state).unwrap();
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(real_tx_id)
        );

        let foreign_tx_id = Hash::new([0xfe; 32]);
        let foreign_meta = AdmittedTxMeta {
            tx_type: TxType::GuardianAction,
            size: 100,
            fee: 50_000,
            sender_account: Some(env.alice_addr),
            account_nonce: None,
            account_spend: 50_000,
            nullifiers: Vec::new(),
            shielded_drain: 0,
            cancellation_target: None,
            allowance_consumption: 0,
            governance_lock: Some(env.alice_addr),
        };
        pool.transactions.insert(foreign_tx_id, vec![0; 100]);
        pool.tx_meta.insert(foreign_tx_id, foreign_meta);

        let removed = pool.remove(&foreign_tx_id);
        assert!(removed.is_some());
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(real_tx_id),
            "Ownership check must preserve real lock"
        );

        pool.remove(&real_tx_id);
        assert!(pool.governance_lock(&env.alice_addr).is_none());
    }

    // G17: Revalidation rebuilds governance locks correctly.
    #[test]
    fn test_f05_g17_revalidation_rebuilds_governance_locks() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).unwrap();

        pool.revalidate(&env.state);
        assert!(pool.contains(&freeze_id));
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(freeze_id)
        );

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        assert_eq!(
            pool.admit(&tx1, &env.state),
            Err(MempoolError::AccountLockedByPendingGovernance(
                env.alice_addr
            ))
        );
    }

    // G18: Block inclusion clears the confirmed governance lock without stale entries.
    #[test]
    fn test_f05_g18_block_inclusion_clears_confirmed_lock() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).unwrap();

        let bob_tx = make_type1_tx(env.chain_id, &env.bob_sk, env.recipient, 100_000, 50_000, 0);
        let bob_id = pool.admit(&bob_tx, &env.state).unwrap();

        let mut next_state = env.state.clone();
        next_state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .is_frozen = true;

        let blk = Block {
            header: Header {
                version: 1,
                chain_id: env.chain_id,
                height: 101,
                parent_block_id: Hash::new([0x01; 32]),
                transaction_root: Hash::new([0x02; 32]),
                orchard_commitment_root: Hash::new([0x03; 32]),
                timestamp: 1000,
                difficulty: 1,
                nonce: 0,
            },
            transactions: vec![freeze_tx.clone()],
        };

        pool.on_block_accepted(&blk, &next_state);
        assert!(!pool.contains(&freeze_id));
        assert!(!pool.is_account_governance_locked(&env.alice_addr));
        assert!(pool.contains(&bob_id), "Unrelated Bob tx preserved");
    }

    // G19: Reorganization behaviour matches the actual API contract.
    #[test]
    fn test_f05_g19_reorganization_contract_verification() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).unwrap();
        assert!(pool.is_account_governance_locked(&env.alice_addr));

        let new_state = env.state.clone();
        pool.on_reorganization(&new_state);
        assert!(pool.contains(&freeze_id));
        assert!(pool.is_account_governance_locked(&env.alice_addr));
        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(freeze_id)
        );
    }

    // G20: Governance eviction releases existing F-02 allowance and F-03 cancellation reservations.
    #[test]
    fn test_f05_g20_emergency_eviction_releases_allowance_and_cancellation_reservations() {
        let mut env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let transfer_id = Hash::new([0x44; 32]);
        let pt = crate::account::PendingTransfer {
            transfer_id,
            recipient: env.recipient,
            amount: 500_000,
            release_height: 500,
        };
        env.state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .pending_transfers
            .push(pt);

        let signers = env.signers();
        let cancel_tx = make_test_type4_tx(
            env.chain_id,
            &env.alice_sk,
            transfer_id,
            50_000,
            0,
            &signers,
        );
        let cancel_id = pool
            .admit(&cancel_tx, &env.state)
            .expect("cancel_tx admitted");
        assert!(pool.is_cancellation_target_reserved(&transfer_id));
        assert_eq!(pool.pending_allowance_reservation(&env.alice_addr), 50_000);

        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("freeze admitted");

        assert!(!pool.contains(&cancel_id), "Type 4 must be evicted");
        assert!(pool.contains(&freeze_id), "Freeze must be admitted");
        assert!(
            !pool.is_cancellation_target_reserved(&transfer_id),
            "Cancellation target released"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&env.alice_addr),
            50_000,
            "Old reservation released and replaced by freeze fee"
        );
    }

    // G21: Two different accounts can independently hold governance locks without interfering.
    #[test]
    fn test_f05_g21_independent_governance_locks_separate_accounts() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let alice_freeze = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let bob_freeze = make_test_type3_tx(
            env.chain_id,
            env.bob_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );

        let alice_id = pool.admit(&alice_freeze, &env.state).unwrap();
        let bob_id = pool.admit(&bob_freeze, &env.state).unwrap();

        assert_eq!(
            pool.governance_lock(&env.alice_addr).map(|l| l.tx_id),
            Some(alice_id)
        );
        assert_eq!(
            pool.governance_lock(&env.bob_addr).map(|l| l.tx_id),
            Some(bob_id)
        );

        pool.remove(&alice_id);
        assert!(!pool.is_account_governance_locked(&env.alice_addr));
        assert_eq!(
            pool.governance_lock(&env.bob_addr).map(|l| l.tx_id),
            Some(bob_id)
        );
    }

    // G22: F-04 shielded-pool reservations remain correct after any applicable eviction or revalidation.
    #[test]
    fn test_f05_g22_shielded_pool_reservations_unaffected_by_governance_eviction() {
        let mut env = setup_test_gov_env();
        let mut pool = Mempool::new();

        env.state.shielded_pool_balance = 1_000_000_000;
        let (tx7, anchor) =
            make_test_valid_type7_tx(env.chain_id, env.bob_addr, 200_000, 1_000_000, 0x52);
        let tip = env.state.tip_height().unwrap();
        env.state.historical_anchors.insert(tip, anchor);
        let tx7_id = pool.admit(&tx7, &env.state).expect("tx7 admitted");
        assert_eq!(pool.total_pending_shielded_drain(), 1_200_000);

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool.admit(&tx1, &env.state).expect("tx1 admitted");
        assert_eq!(pool.total_pending_shielded_drain(), 1_200_000);

        let signers = env.signers();
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("freeze admitted");
        assert!(!pool.contains(&tx1_id), "Type 1 evicted");
        assert!(pool.contains(&tx7_id), "Type 7 intact");
        assert!(pool.contains(&freeze_id), "Freeze admitted");
        assert_eq!(
            pool.total_pending_shielded_drain(),
            1_200_000,
            "Shielded drain reservation must be completely unaffected by transparent eviction"
        );

        pool.revalidate(&env.state);
        assert_eq!(pool.total_pending_shielded_drain(), 1_200_000);
    }

    // F-05 Hardening: Emergency preemption of Type 2 ConfigureGuardians
    #[test]
    fn test_f05_emergency_preemption_of_type2() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let signers = env.signers();
        let rec_key_2 = SigningKey::from_bytes(&[0x77; 32])
            .verifying_key()
            .to_bytes();
        let type2_tx = make_test_type2_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            70_000,
            &env.guardians,
            100,
            1_000_000,
            50,
            &rec_key_2,
            &signers,
        );
        let type2_id = pool.admit(&type2_tx, &env.state).expect("Type 2 admitted");

        // Verify Type 2 state
        assert!(pool.contains(&type2_id));
        assert!(pool
            .account_nonces
            .get(&env.alice_addr)
            .unwrap()
            .contains(&0));
        assert_eq!(pool.account_spends.get(&env.alice_addr), Some(&70_000));
        assert_eq!(pool.pending_allowance_reservation(&env.alice_addr), 70_000);
        assert!(pool.is_account_governance_locked(&env.alice_addr));
        let initial_lock = pool.governance_lock(&env.alice_addr).unwrap();
        assert_eq!(initial_lock.tx_id, type2_id);
        assert!(!initial_lock.is_emergency());

        // Now admit a valid Type 3 ACTION_FREEZE
        let freeze_tx = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool.admit(&freeze_tx, &env.state).expect("Freeze admitted");

        // Verify:
        // 1. Type 2 is evicted
        assert!(
            !pool.contains(&type2_id),
            "Type 2 must be evicted by emergency freeze"
        );
        assert!(pool.contains(&freeze_id), "Freeze must be admitted");

        // 2. Its account nonce reservation is released
        assert!(
            !pool.account_nonces.contains_key(&env.alice_addr),
            "Nonce 0 reservation must be released"
        );

        // 3. Balance and allowance reservations released and replaced by freeze fee
        assert_eq!(
            pool.account_spends.get(&env.alice_addr),
            Some(&50_000),
            "Spend reservation must now only reflect freeze fee"
        );
        assert_eq!(
            pool.pending_allowance_reservation(&env.alice_addr),
            50_000,
            "Allowance reservation must now only reflect freeze fee"
        );

        // 4. The incoming emergency action acquires the governance lock
        let emergency_lock = pool.governance_lock(&env.alice_addr).expect("lock present");
        assert_eq!(emergency_lock.tx_id, freeze_id);
        assert!(emergency_lock.is_emergency());

        // 5. A later Type 2 cannot enter while that lock is held
        let later_type2 = make_test_type2_tx(
            env.chain_id,
            &env.alice_sk,
            0,
            70_000,
            &env.guardians,
            100,
            1_000_000,
            50,
            &rec_key_2,
            &signers,
        );
        let res_later = pool.admit(&later_type2, &env.state);
        assert_eq!(
            res_later,
            Err(MempoolError::PendingGovernanceConflict {
                account: env.alice_addr,
                existing_tx: freeze_id,
            }),
            "Later Type 2 must be rejected while emergency lock is held"
        );
    }

    // F-05 Hardening: Extended emergency failure atomicity across all failure paths
    #[test]
    fn test_f05_emergency_failure_atomicity_extended() {
        let env = setup_test_gov_env();
        let mut pool = Mempool::new();

        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool.admit(&tx1, &env.state).expect("tx1 admitted");
        let initial_spends = pool.account_spends.get(&env.alice_addr).copied().unwrap();
        let initial_allowance = pool.pending_allowance_reservation(&env.alice_addr);
        let signers = env.signers();

        // Path 1: InsufficientSpendableBalance failure
        let excessive_fee_freeze = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            2_000_000_000, // exceeds Alice's 1B balance
            &[],
            &signers,
        );
        let res_bal = pool.admit(&excessive_fee_freeze, &env.state);
        assert!(matches!(
            res_bal,
            Err(MempoolError::InsufficientSpendableBalance { .. })
        ));
        assert!(
            pool.contains(&tx1_id),
            "tx1 must not be evicted on balance failure"
        );
        assert_eq!(
            pool.account_spends.get(&env.alice_addr).copied().unwrap(),
            initial_spends
        );
        assert_eq!(
            pool.pending_allowance_reservation(&env.alice_addr),
            initial_allowance
        );
        assert!(!pool.is_account_governance_locked(&env.alice_addr));

        // Path 2: AllowanceExceeded failure
        let mut constrained_state = env.state.clone();
        constrained_state
            .accounts
            .get_mut(&env.alice_addr)
            .unwrap()
            .allowance_limit = 100_000;
        let over_allowance_freeze = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            200_000, // exceeds 100k allowance limit
            &[],
            &signers,
        );
        let res_allow = pool.admit(&over_allowance_freeze, &constrained_state);
        assert!(matches!(res_allow, Err(MempoolError::AllowanceExceeded(_))));
        assert!(
            pool.contains(&tx1_id),
            "tx1 must not be evicted on allowance failure"
        );
        assert_eq!(
            pool.account_spends.get(&env.alice_addr).copied().unwrap(),
            initial_spends
        );
        assert_eq!(
            pool.pending_allowance_reservation(&env.alice_addr),
            initial_allowance
        );
        assert!(!pool.is_account_governance_locked(&env.alice_addr));

        // Path 3: MempoolFull failure (capacity pre-check)
        let config = MempoolConfig {
            max_transactions: 1,
            max_bytes: 10_000,
        };
        let mut small_pool = Mempool::with_config(config);
        let tx_bob = make_type1_tx(env.chain_id, &env.bob_sk, env.recipient, 100_000, 50_000, 0);
        let bob_tx_id = small_pool.admit(&tx_bob, &env.state).expect("bob admitted");
        assert_eq!(small_pool.len(), 1);

        // Emergency action targeting Alice cannot evict Bob, so projected count is 1 - 0 + 1 = 2 > max (1)
        let alice_freeze = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let res_full = small_pool.admit(&alice_freeze, &env.state);
        assert_eq!(res_full, Err(MempoolError::MempoolFull));
        assert!(
            small_pool.contains(&bob_tx_id),
            "Bob's tx preserved on MempoolFull"
        );
        assert!(!small_pool.is_account_governance_locked(&env.alice_addr));

        // Path 4: Duplicate transaction ID failure
        let valid_freeze = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool
            .admit(&valid_freeze, &env.state)
            .expect("freeze admitted");
        assert_eq!(
            pool.admit(&valid_freeze, &env.state),
            Err(MempoolError::AlreadyInMempool(freeze_id))
        );
        assert!(pool.contains(&freeze_id));
    }

    // Focused regression test: Early capacity rejection for ordinary transactions,
    // with exemption and projected capacity verification for valid emergency actions.
    #[test]
    fn test_early_capacity_rejection_and_emergency_exemption() {
        let env = setup_test_gov_env();
        let config = MempoolConfig {
            max_transactions: 1,
            max_bytes: 10_000,
        };
        let mut pool = Mempool::with_config(config);

        // Admit Alice's initial valid transfer (fills mempool to 1/1 capacity)
        let tx1 = make_type1_tx(
            env.chain_id,
            &env.alice_sk,
            env.recipient,
            100_000,
            50_000,
            0,
        );
        let tx1_id = pool.admit(&tx1, &env.state).expect("tx1 admitted");
        assert_eq!(pool.len(), 1);

        // 1. Ordinary Type 1 transaction with a completely invalid signature
        // In an un-gated mempool, this would reach signature verification and return InvalidSignature.
        // Because the mempool is full, the early capacity gate MUST reject it with MempoolFull BEFORE
        // expensive type-specific validation.
        let mut bad_tx1 =
            make_type1_tx(env.chain_id, &env.bob_sk, env.recipient, 100_000, 50_000, 0);
        // Corrupt signature bytes (last 64 bytes)
        let sig_start = bad_tx1.len() - 64;
        bad_tx1[sig_start..].fill(0xff);
        let res_bad_tx1 = pool.admit(&bad_tx1, &env.state);
        assert_eq!(
            res_bad_tx1,
            Err(MempoolError::MempoolFull),
            "Ordinary Type 1 must be rejected by early capacity check before signature validation"
        );

        // 2. Type 3 Maintenance Action (ACTION_STRENGTHEN_DELAYS) with invalid quorum (0 signatures)
        // Should also be rejected with MempoolFull by early capacity gate because it is not an emergency action.
        let mut bad_maintenance = Vec::new();
        bad_maintenance.push(3u8); // Type 3
        bad_maintenance.extend_from_slice(&1u16.to_le_bytes());
        bad_maintenance.extend_from_slice(env.chain_id.as_bytes());
        bad_maintenance.extend_from_slice(env.alice_addr.as_bytes());
        bad_maintenance.push(crate::auth::ACTION_STRENGTHEN_DELAYS); // Maintenance action (1)
        bad_maintenance.extend_from_slice(&50_000u64.to_le_bytes()); // fee
        bad_maintenance.extend_from_slice(&4u32.to_le_bytes()); // params len
        bad_maintenance.extend_from_slice(&100u32.to_le_bytes()); // params
        bad_maintenance.push(0); // 0 guardian signatures (invalid quorum)
        let res_maint = pool.admit(&bad_maintenance, &env.state);
        assert_eq!(
            res_maint,
            Err(MempoolError::MempoolFull),
            "Type 3 maintenance action must be rejected by early capacity check before quorum validation"
        );

        // 3. Valid Type 3 Emergency Action (ACTION_FREEZE) targeting Alice
        // Bypasses early capacity gate, performs full signature/param validation,
        // projects eviction of tx1 (surviving_count = 1 - 1 = 0, projected_count = 0 + 1 = 1 <= 1),
        // evicts tx1, and successfully establishes the emergency lock!
        let signers = env.signers();
        let freeze_alice = make_test_type3_tx(
            env.chain_id,
            env.alice_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let freeze_id = pool
            .admit(&freeze_alice, &env.state)
            .expect("Valid emergency freeze must bypass early gate and evict conflicting tx");
        assert!(!pool.contains(&tx1_id), "Alice tx1 must be evicted");
        assert!(
            pool.contains(&freeze_id),
            "Emergency freeze must be admitted"
        );
        assert_eq!(pool.len(), 1);
        assert!(pool.is_account_governance_locked(&env.alice_addr));

        // 4. Emergency Action targeting Bob (who has no pending transactions to evict)
        // Bypasses early capacity gate, succeeds in validation, but fails at final projected capacity
        // check (surviving_count = 1 - 0 = 1, projected_count = 1 + 1 = 2 > max 1).
        // Must return MempoolFull without evicting Alice's freeze or mutating any state!
        let freeze_bob = make_test_type3_tx(
            env.chain_id,
            env.bob_addr,
            crate::auth::ACTION_FREEZE,
            50_000,
            &[],
            &signers,
        );
        let res_bob_freeze = pool.admit(&freeze_bob, &env.state);
        assert_eq!(
            res_bob_freeze,
            Err(MempoolError::MempoolFull),
            "Emergency action unable to evict enough transactions must fail final capacity check"
        );
        assert!(
            pool.contains(&freeze_id),
            "Alice's freeze must remain intact"
        );
        assert!(!pool.is_account_governance_locked(&env.bob_addr));
        assert_eq!(pool.len(), 1);
    }
}
