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
use crate::orchard_root::empty_commitment_root;
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
    deshield_amount: u128,
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
    /// Pending nullifiers mapped to the transaction ID that spends them.
    mempool_nullifiers: BTreeMap<Hash, Hash>,
    /// Total deshield amount currently pending across Type 7 transactions.
    total_pending_deshield: u128,
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
            mempool_nullifiers: BTreeMap::new(),
            total_pending_deshield: 0,
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

        // Bounded capacity checks
        if self.transactions.len() >= self.config.max_transactions {
            return Err(MempoolError::MempoolFull);
        }
        let new_total_bytes = self
            .total_bytes
            .checked_add(raw_tx.len())
            .ok_or(MempoolError::MempoolFull)?;
        if new_total_bytes > self.config.max_bytes {
            return Err(MempoolError::MempoolFull);
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

        // Type-specific stateful and conflict validation
        let meta = self.validate_and_build_meta(raw_tx, &env, fee, chain_state)?;

        // Register in mempool state
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

        if meta.deshield_amount > 0 {
            self.total_pending_deshield = self
                .total_pending_deshield
                .saturating_add(meta.deshield_amount);
        }

        self.total_bytes = new_total_bytes;
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
    ) -> Result<AdmittedTxMeta, MempoolError> {
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
                let expected_nonce = self.expected_next_nonce(&sender_addr, acct.nonce);
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
                check_mempool_allowance(acct, tip_h, total_spend)?;

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: Some(sender_addr),
                    account_nonce: Some(nonce),
                    account_spend: total_spend,
                    nullifiers: Vec::new(),
                    deshield_amount: 0,
                })
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

                let expected_nonce = self.expected_next_nonce(&account_addr, acct.nonce);
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

                check_mempool_allowance(acct, tip_h, fee as u128)?;

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

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: Some(account_addr),
                    account_nonce: Some(nonce),
                    account_spend: fee as u128,
                    nullifiers: Vec::new(),
                    deshield_amount: 0,
                })
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

                let current_pending = self.account_spends.get(&target_addr).copied().unwrap_or(0);
                let needed = current_pending
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

                check_mempool_allowance(target, tip_h, fee as u128)?;

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: Some(target_addr),
                    account_nonce: None,
                    account_spend: fee as u128,
                    nullifiers: Vec::new(),
                    deshield_amount: 0,
                })
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

                let expected_nonce = self.expected_next_nonce(&sender_addr, sender.nonce);
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

                check_mempool_allowance(sender, tip_h, fee as u128)?;

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: Some(sender_addr),
                    account_nonce: Some(nonce),
                    account_spend: fee as u128,
                    nullifiers: Vec::new(),
                    deshield_amount: 0,
                })
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

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: None,
                    account_nonce: None,
                    account_spend: 0,
                    nullifiers: nfs,
                    deshield_amount: 0,
                })
            }

            TxType::TransparentToShielded => {
                let payload = &raw_tx[tx::TX_ENVELOPE_LEN..];
                if payload.len() < 133 {
                    return Err(MempoolError::Malformed("truncated Type 6".into()));
                }
                let mut sender_key = [0u8; 32];
                sender_key.copy_from_slice(&payload[..32]);
                let sender_addr = derive_address(&sender_key);
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
                let expected_nonce = self.expected_next_nonce(&sender_addr, acct.nonce);
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

                check_mempool_allowance(acct, tip_h, total_spend)?;

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

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: Some(sender_addr),
                    account_nonce: Some(nonce),
                    account_spend: total_spend,
                    nullifiers: nfs,
                    deshield_amount: 0,
                })
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
                let current_deshield = self
                    .total_pending_deshield
                    .checked_add(total_deshield)
                    .ok_or_else(|| MempoolError::Malformed("deshield overflow".into()))?;
                let pool_balance = chain_state.shielded_pool_balance();
                if current_deshield > pool_balance {
                    return Err(MempoolError::InsufficientShieldedPoolBalance {
                        available: pool_balance,
                        required: current_deshield,
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

                Ok(AdmittedTxMeta {
                    tx_type: env.tx_type,
                    size: raw_tx.len(),
                    fee,
                    sender_account: None,
                    account_nonce: None,
                    account_spend: 0,
                    nullifiers: nfs,
                    deshield_amount: total_deshield,
                })
            }
        }
    }

    /// Computes the expected next nonce for `account`, taking pending mempool txs into account.
    fn expected_next_nonce(&self, account: &Hash, committed_nonce: u64) -> u64 {
        if let Some(nonces) = self.account_nonces.get(account) {
            if let Some(&max_nonce) = nonces.iter().max() {
                return max_nonce.saturating_add(1);
            }
        }
        committed_nonce
    }

    /// Returns the set of valid anchors in the active 10-block ancestor window.
    fn active_anchor_set(&self, chain_state: &ChainState) -> BTreeSet<Hash> {
        let tip_h = chain_state.tip_height().unwrap_or(0);
        let min_h = tip_h.saturating_sub(10);
        let mut anchors = BTreeSet::new();
        for h in min_h..=tip_h {
            if let Some(anc) = chain_state.historical_anchors().get(&h) {
                anchors.insert(*anc);
            }
        }
        if tip_h <= 10 {
            anchors.insert(empty_commitment_root());
        }
        anchors
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
            if meta.deshield_amount > 0 {
                self.total_pending_deshield = self
                    .total_pending_deshield
                    .saturating_sub(meta.deshield_amount);
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
        self.total_pending_deshield = 0;

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

/// Validates spend allowance limits for an account.
fn check_mempool_allowance(
    account: &AccountState,
    height: u64,
    cost: u128,
) -> Result<(), MempoolError> {
    if account.allowance_limit > 0 && account.allowance_window_len > 0 {
        let window_end = account
            .allowance_window_start
            .checked_add(account.allowance_window_len)
            .ok_or_else(|| MempoolError::AllowanceExceeded("window overflow".into()))?;
        let current_spent = if height >= window_end {
            0
        } else {
            account.allowance_spent
        };
        let new_spent = current_spent
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::scheduled_subsidy;
    use crate::block::Block;
    use crate::genesis::DEVNET;
    use crate::hash::{chain_id, transaction_id};
    use crate::header::Header;
    use crate::merkle;
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
}
