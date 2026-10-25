//! Production Orchard V2 transaction decoding and stateless cryptographic validation.
//!
//! This module provides canonical parsing, serialization, and stateless validation
//! of Orchard V2 transaction bundles in OwnChain protocol v1, adhering to:
//! - ZIP-225 Section 7 canonical component ordering.
//! - Canonical CompactSize integer encoding rules.
//! - Strict bounds on action counts, proof lengths, and transaction sizes.
//! - `OwnChain/ActionEffect/v1` and `OwnChain/TxAuth/v1` BLAKE2b-256 digest computations.
//! - Stateless zero-knowledge proof, spend authorization, and binding signature verification
//!   using the pinned `FixedPostNu6_2` Orchard circuit.
//!
//! # Stateful vs. Stateless Boundaries
//! This module deliberately handles ONLY stateless structural and cryptographic validation.
//! It does NOT perform:
//! - Historical commitment tree anchor validation.
//! - Duplicate nullifier detection against historical chain state.
//! - Commitment tree updates or block header `orchard_root` commitments.
//! - Pool balance or subsidy/fee consensus accounting across blocks.
//!
//! These stateful protections are deferred to Milestone M1-E Stage 2 (`ChainState`).

use core::fmt;
use std::sync::OnceLock;

use blake2::{Blake2b256, Digest};
use nonempty::NonEmpty;
use orchard::{
    bundle::{
        Authorization, Authorized, BatchError, BatchValidator, BundleError, BundleVersion, Flags,
    },
    circuit::{OrchardCircuitVersion, VerifyingKey},
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::{NoteBytesData, NoteCiphertextBytes},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::Anchor,
    value::ValueCommitment,
    Action, ActionFromPartsError, Bundle, Proof,
};

use crate::block::{MAX_BLOCK_SIZE, MAX_TRANSACTION_SIZE};
use crate::hash::Hash;
use crate::tx::{self, EnvelopeError, TxEnvelope, TxType, TX_ENVELOPE_LEN};

/// Maximum number of Orchard actions permitted per transaction (§6.3).
pub const MAX_ACTIONS_PER_TX: usize = 50;

/// Maximum number of Orchard actions permitted per block (§6.3).
pub const MAX_ACTIONS_PER_BLOCK: usize = 2000;

/// The canonical size of an Orchard action description in bytes (ZIP-225 Section 7).
///
/// 32 (cv_net) + 32 (nullifier) + 32 (rk) + 32 (cmx) + 32 (epk)
/// + 580 (enc_ciphertext) + 80 (out_ciphertext) = 820 bytes.
pub const ACTION_DESCRIPTION_LEN: usize = 820;

/// The domain string for an OwnChain action effect hash (§7.3).
pub const ACTION_EFFECT_DOMAIN: &[u8] = b"OwnChain/ActionEffect/v1";

/// The domain string for an OwnChain transaction authorization digest (§7.3).
pub const TX_AUTH_DOMAIN: &[u8] = b"OwnChain/TxAuth/v1";

/// The all-zero outgoing viewing key bytes used for coinbase note recovery (§4).
pub const ALL_ZERO_OVK_BYTES: [u8; 32] = [0u8; 32];

static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();

/// Returns a reference to the statically initialized Orchard verifying key for `FixedPostNu6_2`.
pub fn verifying_key() -> &'static VerifyingKey {
    VERIFYING_KEY.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
}

/// Returns the consensus all-zero outgoing viewing key used for coinbase outputs.
pub fn all_zero_ovk() -> OutgoingViewingKey {
    OutgoingViewingKey::from(ALL_ZERO_OVK_BYTES)
}

/// Errors produced when encoding or decoding canonical Orchard V2 bundles.
#[derive(Debug, PartialEq, Eq)]
pub enum BundleCodecError {
    /// The bundle declared zero actions.
    EmptyActions,
    /// The bundle declared more actions than permitted by protocol limits.
    TooManyActions,
    /// Input data ended unexpectedly before all fields could be read.
    UnexpectedEof,
    /// Unexpected unparsed bytes remain after parsing the bundle.
    TrailingBytes,
    /// A CompactSize integer was encoded in a non-canonical (non-minimal) form.
    NonCanonicalCompactSize,
    /// The flags byte is not valid for Orchard V2.
    InvalidFlags,
    /// The anchor is not a valid Pallas point encoding.
    InvalidAnchor,
    /// The value commitment is not a valid Pallas point encoding.
    InvalidValueCommitment,
    /// The nullifier is not a valid Pallas point encoding.
    InvalidNullifier,
    /// The randomized verification key is not a valid RedPallas point encoding.
    InvalidRk,
    /// The extracted commitment is not a valid Pallas base field element.
    InvalidCmx,
    /// Construction of an individual action failed validation rules.
    Action(ActionFromPartsError),
    /// Construction of the bundle failed validation rules.
    Bundle(BundleError),
    /// The serialized bundle exceeds the maximum permitted size.
    BundleTooLarge {
        /// Actual size in bytes.
        actual: usize,
        /// Maximum permitted limit.
        limit: usize,
    },
}

impl fmt::Display for BundleCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleCodecError::EmptyActions => write!(f, "bundle contains no actions"),
            BundleCodecError::TooManyActions => write!(f, "bundle exceeds maximum action limit"),
            BundleCodecError::UnexpectedEof => write!(f, "unexpected end of input"),
            BundleCodecError::TrailingBytes => write!(f, "unexpected trailing bytes after bundle"),
            BundleCodecError::NonCanonicalCompactSize => {
                write!(f, "non-canonical compact size encoding")
            }
            BundleCodecError::InvalidFlags => write!(f, "invalid bundle flags"),
            BundleCodecError::InvalidAnchor => write!(f, "invalid anchor encoding"),
            BundleCodecError::InvalidValueCommitment => {
                write!(f, "invalid value commitment encoding")
            }
            BundleCodecError::InvalidNullifier => write!(f, "invalid nullifier encoding"),
            BundleCodecError::InvalidRk => {
                write!(f, "invalid spend authorization validating key encoding")
            }
            BundleCodecError::InvalidCmx => write!(f, "invalid note commitment encoding"),
            BundleCodecError::Action(e) => write!(f, "action construction error: {e:?}"),
            BundleCodecError::Bundle(e) => write!(f, "bundle construction error: {e:?}"),
            BundleCodecError::BundleTooLarge { actual, limit } => {
                write!(f, "bundle size {actual} exceeds limit {limit}")
            }
        }
    }
}

impl std::error::Error for BundleCodecError {}

/// Encodes an unsigned integer as a canonical Bitcoin/Zcash CompactSize byte sequence.
pub fn encode_compact_size(val: usize, buf: &mut Vec<u8>) {
    if val <= 252 {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(val as u64).to_le_bytes());
    }
}

/// Decodes an unsigned integer from a canonical Bitcoin/Zcash CompactSize byte sequence.
///
/// Rejects non-canonical (non-minimal) encodings with [`BundleCodecError::NonCanonicalCompactSize`]
/// and truncated inputs with [`BundleCodecError::UnexpectedEof`].
pub fn decode_compact_size(data: &mut &[u8]) -> Result<usize, BundleCodecError> {
    if data.is_empty() {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let first = data[0];
    *data = &data[1..];
    match first {
        0..=252 => Ok(first as usize),
        0xfd => {
            if data.len() < 2 {
                return Err(BundleCodecError::UnexpectedEof);
            }
            let val = u16::from_le_bytes([data[0], data[1]]);
            if val < 253 {
                return Err(BundleCodecError::NonCanonicalCompactSize);
            }
            *data = &data[2..];
            Ok(val as usize)
        }
        0xfe => {
            if data.len() < 4 {
                return Err(BundleCodecError::UnexpectedEof);
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if val < 0x10000 {
                return Err(BundleCodecError::NonCanonicalCompactSize);
            }
            *data = &data[4..];
            usize::try_from(val).map_err(|_| BundleCodecError::NonCanonicalCompactSize)
        }
        0xff => {
            if data.len() < 8 {
                return Err(BundleCodecError::UnexpectedEof);
            }
            let val = u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            if val < 0x1_0000_0000 {
                return Err(BundleCodecError::NonCanonicalCompactSize);
            }
            *data = &data[8..];
            usize::try_from(val).map_err(|_| BundleCodecError::NonCanonicalCompactSize)
        }
    }
}

/// Serializes an Orchard V2 bundle in official ZIP-225 Section 7 order:
/// 1. actionCount: CompactSize
/// 2. actions: `[actionDescription; actionCount]` (each 820 bytes)
/// 3. flags: 1 byte
/// 4. valueBalanceOrchard: 8 bytes (`i64` little-endian)
/// 5. anchorOrchard: 32 bytes
/// 6. sizeProofsOrchard: CompactSize
/// 7. proofsOrchard: proof bytes
/// 8. spendAuthSigsOrchard: `[64 bytes; actionCount]`
/// 9. bindingSigOrchard: 64 bytes
pub fn serialize_bundle(bundle: &Bundle<Authorized, i64>) -> Vec<u8> {
    let mut buf = Vec::new();
    let actions = bundle.actions();
    encode_compact_size(actions.len(), &mut buf);

    for action in actions.iter() {
        buf.extend_from_slice(&action.cv_net().to_bytes());
        buf.extend_from_slice(&action.nullifier().to_bytes());
        buf.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        buf.extend_from_slice(&action.cmx().to_bytes());
        buf.extend_from_slice(&action.encrypted_note().epk_bytes);
        buf.extend_from_slice(&action.encrypted_note().enc_ciphertext.0);
        buf.extend_from_slice(&action.encrypted_note().out_ciphertext);
    }

    buf.push(bundle.flag_byte());
    buf.extend_from_slice(&bundle.value_balance().to_le_bytes());
    buf.extend_from_slice(&bundle.anchor().to_bytes());

    let proof_bytes = bundle.authorization().proof().as_ref();
    encode_compact_size(proof_bytes.len(), &mut buf);
    buf.extend_from_slice(proof_bytes);

    for action in actions.iter() {
        buf.extend_from_slice(&<[u8; 64]>::from(action.authorization()));
    }

    buf.extend_from_slice(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ));

    buf
}

/// Internal temporary container for action description fields before cryptographic validation.
struct ActionDesc {
    cv_net: ValueCommitment,
    nf: Nullifier,
    rk: redpallas::VerificationKey<SpendAuth>,
    cmx: ExtractedNoteCommitment,
    epk_bytes: [u8; 32],
    enc_ciphertext: NoteCiphertextBytes,
    out_ciphertext: [u8; 80],
}

/// Deserializes an Orchard V2 bundle in official ZIP-225 Section 7 order.
///
/// Enforces strict canonicality:
/// - Rejects non-canonical CompactSize encodings.
/// - Enforces maximum action count limits before allocating large buffers.
/// - Validates canonical field encodings (`cv_net`, `nullifier`, `rk`, `cmx`, `anchor`, `flags`).
/// - Rejects non-canonical proof length and non-curve/identity authorization keys.
/// - Rejects truncated data and trailing unparsed bytes.
pub fn deserialize_bundle(mut data: &[u8]) -> Result<Bundle<Authorized, i64>, BundleCodecError> {
    if data.len() > MAX_BLOCK_SIZE {
        return Err(BundleCodecError::BundleTooLarge {
            actual: data.len(),
            limit: MAX_BLOCK_SIZE,
        });
    }

    let n_actions = decode_compact_size(&mut data)?;
    if n_actions == 0 {
        return Err(BundleCodecError::EmptyActions);
    }
    if n_actions > MAX_ACTIONS_PER_TX {
        return Err(BundleCodecError::TooManyActions);
    }

    // Minimum bytes required for n_actions without proof:
    // actions: n_actions * 820
    // flags (1) + value_balance (8) + anchor (32) = 41
    // proof len: at least 1
    // spend auth sigs: n_actions * 64
    // binding sig: 64
    let min_needed = n_actions
        .checked_mul(ACTION_DESCRIPTION_LEN + 64)
        .and_then(|v| v.checked_add(1 + 8 + 32 + 1 + 64));
    match min_needed {
        Some(req) if data.len() < req => return Err(BundleCodecError::UnexpectedEof),
        None => return Err(BundleCodecError::TooManyActions),
        _ => {}
    }

    let mut descs = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        if data.len() < ACTION_DESCRIPTION_LEN {
            return Err(BundleCodecError::UnexpectedEof);
        }

        let mut cv_bytes = [0u8; 32];
        cv_bytes.copy_from_slice(&data[..32]);
        let cv_net = ValueCommitment::from_bytes(&cv_bytes)
            .into_option()
            .ok_or(BundleCodecError::InvalidValueCommitment)?;
        data = &data[32..];

        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(&data[..32]);
        let nf = Nullifier::from_bytes(&nf_bytes)
            .into_option()
            .ok_or(BundleCodecError::InvalidNullifier)?;
        data = &data[32..];

        let mut rk_bytes = [0u8; 32];
        rk_bytes.copy_from_slice(&data[..32]);
        let rk: redpallas::VerificationKey<SpendAuth> = rk_bytes
            .try_into()
            .map_err(|_| BundleCodecError::InvalidRk)?;
        data = &data[32..];

        let mut cmx_bytes = [0u8; 32];
        cmx_bytes.copy_from_slice(&data[..32]);
        let cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes)
            .into_option()
            .ok_or(BundleCodecError::InvalidCmx)?;
        data = &data[32..];

        let mut epk_bytes = [0u8; 32];
        epk_bytes.copy_from_slice(&data[..32]);
        data = &data[32..];

        let mut enc_bytes = [0u8; 580];
        enc_bytes.copy_from_slice(&data[..580]);
        let enc_ciphertext = NoteBytesData(enc_bytes);
        data = &data[580..];

        let mut out_ciphertext = [0u8; 80];
        out_ciphertext.copy_from_slice(&data[..80]);
        data = &data[80..];

        descs.push(ActionDesc {
            cv_net,
            nf,
            rk,
            cmx,
            epk_bytes,
            enc_ciphertext,
            out_ciphertext,
        });
    }

    if data.len() < 1 + 8 + 32 {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let flag_byte = data[0];
    let flags = Flags::from_byte(flag_byte, BundleVersion::orchard_v2())
        .ok_or(BundleCodecError::InvalidFlags)?;
    data = &data[1..];

    let mut vb_bytes = [0u8; 8];
    vb_bytes.copy_from_slice(&data[..8]);
    let value_balance = i64::from_le_bytes(vb_bytes);
    data = &data[8..];

    let mut anchor_bytes = [0u8; 32];
    anchor_bytes.copy_from_slice(&data[..32]);
    let anchor: Anchor = Anchor::from_bytes(anchor_bytes)
        .into_option()
        .ok_or(BundleCodecError::InvalidAnchor)?;
    data = &data[32..];

    let proof_len = decode_compact_size(&mut data)?;
    if proof_len > MAX_BLOCK_SIZE || data.len() < proof_len {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let proof_bytes = data[..proof_len].to_vec();
    data = &data[proof_len..];

    let mut spend_auth_sigs = Vec::with_capacity(n_actions);
    for _ in 0..n_actions {
        if data.len() < 64 {
            return Err(BundleCodecError::UnexpectedEof);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&data[..64]);
        spend_auth_sigs.push(redpallas::Signature::<SpendAuth>::from(sig_bytes));
        data = &data[64..];
    }

    if data.len() < 64 {
        return Err(BundleCodecError::UnexpectedEof);
    }
    let mut binding_sig_bytes = [0u8; 64];
    binding_sig_bytes.copy_from_slice(&data[..64]);
    let binding_sig = redpallas::Signature::<Binding>::from(binding_sig_bytes);
    data = &data[64..];

    if !data.is_empty() {
        return Err(BundleCodecError::TrailingBytes);
    }

    let mut actions = Vec::with_capacity(n_actions);
    for (desc, sig) in descs.into_iter().zip(spend_auth_sigs) {
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: desc.epk_bytes,
            enc_ciphertext: desc.enc_ciphertext,
            out_ciphertext: desc.out_ciphertext,
        };
        let action =
            Action::from_parts(desc.nf, desc.rk, desc.cmx, encrypted_note, desc.cv_net, sig)
                .map_err(BundleCodecError::Action)?;
        actions.push(action);
    }

    let non_empty_actions = match NonEmpty::from_vec(actions) {
        Some(ne) => ne,
        None => return Err(BundleCodecError::EmptyActions),
    };
    let auth = Authorized::from_parts(Proof::new(proof_bytes), binding_sig);

    Bundle::try_from_parts(
        non_empty_actions,
        flags,
        value_balance,
        anchor,
        auth,
        BundleVersion::orchard_v2(),
    )
    .map_err(BundleCodecError::Bundle)
}

/// Computes the 32-byte action effect digest for an Orchard action over the complete
/// canonical 820-byte action description in ZIP-225 order (§7.3):
/// `BLAKE2b-256("OwnChain/ActionEffect/v1" || cv_net || nullifier || rk || cmx || epk || enc_ciphertext || out_ciphertext)`
pub fn compute_action_effect(
    cv_net: &[u8; 32],
    nullifier: &[u8; 32],
    rk: &[u8; 32],
    cmx: &[u8; 32],
    epk: &[u8; 32],
    enc_ciphertext: &[u8; 580],
    out_ciphertext: &[u8; 80],
) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(ACTION_EFFECT_DOMAIN);
    hasher.update(cv_net);
    hasher.update(nullifier);
    hasher.update(rk);
    hasher.update(cmx);
    hasher.update(epk);
    hasher.update(enc_ciphertext);
    hasher.update(out_ciphertext);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Computes the 32-byte action effect digest directly from an Orchard [`Action`].
pub fn compute_action_effect_from_action<A>(action: &Action<A>) -> [u8; 32] {
    compute_action_effect(
        &action.cv_net().to_bytes(),
        &action.nullifier().to_bytes(),
        &<[u8; 32]>::from(action.rk()),
        &action.cmx().to_bytes(),
        &action.encrypted_note().epk_bytes,
        &action.encrypted_note().enc_ciphertext.0,
        &action.encrypted_note().out_ciphertext,
    )
}

/// Computes the domain-separated authorization digest for an OwnChain transaction (§7.3):
/// `BLAKE2b-256("OwnChain/TxAuth/v1" || chain_id || tx_type || tx_version || payload_prefix || bundle_flags || bundle_value_balance || bundle_anchor || repeated(action_effect_i))`
#[allow(clippy::too_many_arguments)]
pub fn compute_tx_auth_digest(
    chain_id: [u8; 32],
    tx_type: u8,
    tx_version: u16,
    payload_prefix: u64,
    bundle_flag_byte: u8,
    bundle_value_balance: i64,
    bundle_anchor: [u8; 32],
    action_effects: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(TX_AUTH_DOMAIN);
    hasher.update(chain_id);
    hasher.update([tx_type]);
    hasher.update(tx_version.to_le_bytes());
    hasher.update(payload_prefix.to_le_bytes());
    hasher.update([bundle_flag_byte]);
    hasher.update(bundle_value_balance.to_le_bytes());
    hasher.update(bundle_anchor);
    for effect in action_effects {
        hasher.update(effect);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Computes the domain-separated authorization digest directly from a bundle and outer context.
pub fn compute_bundle_auth_digest<A: Authorization>(
    chain_id: [u8; 32],
    tx_type: u8,
    tx_version: u16,
    payload_prefix: u64,
    bundle: &Bundle<A, i64>,
) -> [u8; 32] {
    let effects: Vec<[u8; 32]> = bundle
        .actions()
        .iter()
        .map(compute_action_effect_from_action)
        .collect();
    compute_tx_auth_digest(
        chain_id,
        tx_type,
        tx_version,
        payload_prefix,
        bundle.flag_byte(),
        *bundle.value_balance(),
        bundle.anchor().to_bytes(),
        &effects,
    )
}

/// Computes the exact public consensus fee in atoms for an Orchard transaction (§4):
/// `max(1_000, 1_000 * action_count + canonical_transaction_size_in_bytes)`.
///
/// Uses checked arithmetic; returns `None` on overflow.
pub fn consensus_fee(action_count: usize, canonical_tx_size: usize) -> Option<u64> {
    let count_u64 = u64::try_from(action_count).ok()?;
    let size_u64 = u64::try_from(canonical_tx_size).ok()?;
    let action_fee = count_u64.checked_mul(1_000)?;
    let base = action_fee.checked_add(size_u64)?;
    Some(core::cmp::max(1_000, base))
}

/// Errors produced during stateless validation of an Orchard transaction.
#[derive(Debug)]
pub enum OrchardValidationError {
    /// The transaction outer envelope is invalid.
    Envelope(EnvelopeError),
    /// The embedded Orchard bundle could not be decoded.
    Codec(BundleCodecError),
    /// A non-coinbase transaction exceeds the 1,000,000-byte consensus limit.
    TransactionTooLarge {
        /// Actual transaction size.
        actual: usize,
        /// Maximum permitted limit.
        limit: usize,
    },
    /// A transaction exceeds the 2,000,000-byte block consensus limit.
    BlockLimitExceeded {
        /// Actual transaction size.
        actual: usize,
        /// Maximum permitted limit.
        limit: usize,
    },
    /// A coinbase transaction declared an action count other than 1.
    InvalidCoinbaseActionCount {
        /// The action count found.
        actual: usize,
    },
    /// A coinbase transaction declared flags other than `SPENDS_DISABLED`.
    InvalidCoinbaseFlags {
        /// The flag byte found.
        actual: u8,
    },
    /// A coinbase transaction value balance was not negative.
    CoinbaseValueBalanceNotNegative {
        /// The value balance found.
        value_balance: i64,
    },
    /// The coinbase note plaintext could not be recovered with the consensus all-zero OVK.
    CoinbaseNoteRecoveryFailed,
    /// The coinbase value balance magnitude does not equal the recovered note value.
    CoinbaseValueMismatch {
        /// The declared value balance.
        value_balance: i64,
        /// The atoms recovered from the note.
        recovered_atoms: u64,
    },
    /// A transfer transaction declared an action count outside 1..=50.
    InvalidTransferActionCount {
        /// The action count found.
        actual: usize,
    },
    /// A transfer transaction did not enable both spends and outputs.
    InvalidTransferFlags {
        /// The flag byte found.
        actual: u8,
    },
    /// A transfer transaction value balance was not positive.
    TransferValueBalanceNotPositive {
        /// The value balance found.
        value_balance: i64,
    },
    /// A transfer transaction value balance does not match the declared fee payload prefix.
    TransferFeeMismatch {
        /// The value balance found.
        value_balance: i64,
        /// The fee declared in the payload prefix.
        fee_atoms: u64,
    },
    /// Zero-knowledge proof verification failed against the pinned circuit verifying key.
    ProofVerificationFailed(String),
    /// Spend authorization signature verification failed for an action.
    SpendAuthSignatureInvalid {
        /// The index of the failing action.
        action_index: usize,
    },
    /// Bundle binding signature verification failed.
    BindingSignatureInvalid,
}

impl fmt::Display for OrchardValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrchardValidationError::Envelope(e) => write!(f, "transaction envelope error: {e}"),
            OrchardValidationError::Codec(e) => write!(f, "bundle codec error: {e}"),
            OrchardValidationError::TransactionTooLarge { actual, limit } => {
                write!(f, "transaction is {actual} bytes, exceeds limit {limit}")
            }
            OrchardValidationError::BlockLimitExceeded { actual, limit } => {
                write!(
                    f,
                    "transaction is {actual} bytes, exceeds block limit {limit}"
                )
            }
            OrchardValidationError::InvalidCoinbaseActionCount { actual } => {
                write!(f, "coinbase must contain exactly 1 action, found {actual}")
            }
            OrchardValidationError::InvalidCoinbaseFlags { actual } => {
                write!(
                    f,
                    "coinbase must have SPENDS_DISABLED flags (0x02), found {actual:#04x}"
                )
            }
            OrchardValidationError::CoinbaseValueBalanceNotNegative { value_balance } => {
                write!(
                    f,
                    "coinbase valueBalanceOrchard must be negative, got {value_balance}"
                )
            }
            OrchardValidationError::CoinbaseNoteRecoveryFailed => {
                write!(
                    f,
                    "failed to recover coinbase output note with all-zero OVK"
                )
            }
            OrchardValidationError::CoinbaseValueMismatch {
                value_balance,
                recovered_atoms,
            } => {
                write!(
                    f,
                    "coinbase value balance {value_balance} does not match recovered note {recovered_atoms} atoms"
                )
            }
            OrchardValidationError::InvalidTransferActionCount { actual } => {
                write!(
                    f,
                    "transfer action count must be between 1 and 50, found {actual}"
                )
            }
            OrchardValidationError::InvalidTransferFlags { actual } => {
                write!(
                    f,
                    "transfer must have spends and outputs enabled, found flags {actual:#04x}"
                )
            }
            OrchardValidationError::TransferValueBalanceNotPositive { value_balance } => {
                write!(
                    f,
                    "transfer valueBalanceOrchard must be positive, got {value_balance}"
                )
            }
            OrchardValidationError::TransferFeeMismatch {
                value_balance,
                fee_atoms,
            } => {
                write!(
                    f,
                    "transfer value balance {value_balance} does not match declared fee {fee_atoms}"
                )
            }
            OrchardValidationError::ProofVerificationFailed(e) => {
                write!(f, "halo2 proof verification failed: {e:?}")
            }
            OrchardValidationError::SpendAuthSignatureInvalid { action_index } => {
                write!(
                    f,
                    "spend authorization signature invalid for action index {action_index}"
                )
            }
            OrchardValidationError::BindingSignatureInvalid => {
                write!(f, "binding signature invalid")
            }
        }
    }
}

impl std::error::Error for OrchardValidationError {}

impl From<EnvelopeError> for OrchardValidationError {
    fn from(e: EnvelopeError) -> Self {
        OrchardValidationError::Envelope(e)
    }
}

impl From<BundleCodecError> for OrchardValidationError {
    fn from(e: BundleCodecError) -> Self {
        OrchardValidationError::Codec(e)
    }
}

/// Validates the structural and value-balance consensus rules of an Orchard bundle statelessly,
/// computing and returning the 32-byte authorization digest (`sighash`).
///
/// This checks:
/// - Action count bounds (1 for Coinbase, 1..=50 for Transfer).
/// - Flag configurations (Coinbase: `SPENDS_DISABLED`; Transfer: `flags.spends_enabled() && flags.outputs_enabled()`).
/// - Value balance sign and payload prefix match:
///   - Transfer: `value_balance > 0`, `value_balance as u64 == fee_atoms`.
///   - Coinbase: `value_balance < 0`, output 0 recoverable with all-zero OVK and value == `-value_balance`.
///
/// Note: This function does NOT verify Halo2 proofs or RedPallas signatures.
/// Use [`validate_transaction_stateless`] or [`validate_bundle_stateless`] for full cryptographic verification,
/// or use this function prior to [`add_bundle_to_batch`].
pub fn validate_bundle_structure_stateless(
    envelope: &TxEnvelope,
    payload_prefix: u64,
    bundle: &Bundle<Authorized, i64>,
) -> Result<[u8; 32], OrchardValidationError> {
    let n_actions = bundle.actions().len();

    match envelope.tx_type {
        TxType::Coinbase => {
            if n_actions != 1 {
                return Err(OrchardValidationError::InvalidCoinbaseActionCount {
                    actual: n_actions,
                });
            }
            if *bundle.flags() != Flags::SPENDS_DISABLED {
                return Err(OrchardValidationError::InvalidCoinbaseFlags {
                    actual: bundle.flag_byte(),
                });
            }
            let vb = *bundle.value_balance();
            if vb >= 0 {
                return Err(OrchardValidationError::CoinbaseValueBalanceNotNegative {
                    value_balance: vb,
                });
            }

            // Recover note with all-zero OVK
            let zero_ovk = all_zero_ovk();
            let (recovered_note, _, _) = bundle
                .recover_output_with_ovk(0, &zero_ovk)
                .ok_or(OrchardValidationError::CoinbaseNoteRecoveryFailed)?;

            let recovered_atoms = recovered_note.value().inner();
            let expected_vb = -(i64::try_from(recovered_atoms).map_err(|_| {
                OrchardValidationError::CoinbaseValueMismatch {
                    value_balance: vb,
                    recovered_atoms,
                }
            })?);

            if vb != expected_vb {
                return Err(OrchardValidationError::CoinbaseValueMismatch {
                    value_balance: vb,
                    recovered_atoms,
                });
            }
        }
        TxType::OrchardTransfer => {
            if n_actions == 0 || n_actions > MAX_ACTIONS_PER_TX {
                return Err(OrchardValidationError::InvalidTransferActionCount {
                    actual: n_actions,
                });
            }
            if !bundle.flags().spends_enabled() || !bundle.flags().outputs_enabled() {
                return Err(OrchardValidationError::InvalidTransferFlags {
                    actual: bundle.flag_byte(),
                });
            }
            let vb = *bundle.value_balance();
            if vb <= 0 {
                return Err(OrchardValidationError::TransferValueBalanceNotPositive {
                    value_balance: vb,
                });
            }

            let expected_vb = i64::try_from(payload_prefix).map_err(|_| {
                OrchardValidationError::TransferFeeMismatch {
                    value_balance: vb,
                    fee_atoms: payload_prefix,
                }
            })?;

            if vb != expected_vb {
                return Err(OrchardValidationError::TransferFeeMismatch {
                    value_balance: vb,
                    fee_atoms: payload_prefix,
                });
            }
        }
    }

    let sighash = compute_bundle_auth_digest(
        *envelope.chain_id.as_bytes(),
        envelope.tx_type.tag(),
        envelope.version,
        payload_prefix,
        bundle,
    );

    Ok(sighash)
}

/// Performs full stateless validation on an Orchard bundle, including zero-knowledge
/// Halo2 proof verification, spend authorization signatures, and binding signature verification.
pub fn validate_bundle_stateless(
    envelope: &TxEnvelope,
    payload_prefix: u64,
    bundle: &Bundle<Authorized, i64>,
    vk: &VerifyingKey,
) -> Result<[u8; 32], OrchardValidationError> {
    let sighash = validate_bundle_structure_stateless(envelope, payload_prefix, bundle)?;

    // 1. Verify Halo2 proof
    bundle
        .verify_proof(vk)
        .map_err(|e| OrchardValidationError::ProofVerificationFailed(format!("{e:?}")))?;

    // 2. Verify spend authorization signatures
    for (index, action) in bundle.actions().iter().enumerate() {
        action
            .rk()
            .verify(&sighash, action.authorization())
            .map_err(|_| OrchardValidationError::SpendAuthSignatureInvalid {
                action_index: index,
            })?;
    }

    // 3. Verify binding signature
    bundle
        .binding_validating_key()
        .verify(&sighash, bundle.authorization().binding_signature())
        .map_err(|_| OrchardValidationError::BindingSignatureInvalid)?;

    Ok(sighash)
}

/// A decoded and statelessly validated OwnChain transaction containing its
/// outer envelope, payload prefix (height for Coinbase, fee_atoms for Transfer),
/// the authorized Orchard V2 bundle, and the verified authorization digest.
#[derive(Clone, Debug)]
pub struct ValidatedOrchardTx {
    /// The parsed outer transaction envelope.
    pub envelope: TxEnvelope,
    /// The decoded payload prefix (`height` for Coinbase, `fee_atoms` for Transfer).
    pub payload_prefix: u64,
    /// The decoded and verified authorized Orchard bundle.
    pub bundle: Bundle<Authorized, i64>,
    /// The verified 32-byte authorization digest.
    pub auth_digest: [u8; 32],
}

impl ValidatedOrchardTx {
    /// Returns the transaction type.
    pub fn tx_type(&self) -> TxType {
        self.envelope.tx_type
    }

    /// Returns the chain ID the transaction is bound to.
    pub fn chain_id(&self) -> Hash {
        self.envelope.chain_id
    }

    /// Returns the fee in atoms if this is an ordinary transfer.
    pub fn fee_atoms(&self) -> Option<u64> {
        match self.envelope.tx_type {
            TxType::OrchardTransfer => Some(self.payload_prefix),
            TxType::Coinbase => None,
        }
    }

    /// Returns the declared block height if this is a coinbase transaction.
    pub fn coinbase_height(&self) -> Option<u64> {
        match self.envelope.tx_type {
            TxType::Coinbase => Some(self.payload_prefix),
            TxType::OrchardTransfer => None,
        }
    }

    /// Returns a reference to the embedded authorized Orchard bundle.
    pub fn bundle(&self) -> &Bundle<Authorized, i64> {
        &self.bundle
    }

    /// Returns the 32-byte authorization digest.
    pub fn auth_digest(&self) -> [u8; 32] {
        self.auth_digest
    }

    /// Recovers the reward output note and miner address if this is a coinbase transaction.
    pub fn recover_coinbase_output(&self) -> Option<(orchard::note::Note, orchard::Address)> {
        if self.envelope.tx_type != TxType::Coinbase {
            return None;
        }
        let (note, addr, _) = self.bundle.recover_output_with_ovk(0, &all_zero_ovk())?;
        Some((note, addr))
    }
}

/// Parses and statelessly validates a canonical OwnChain transaction from untrusted bytes.
pub fn validate_transaction_stateless(
    tx_bytes: &[u8],
    expected_chain_id: Hash,
    vk: &VerifyingKey,
) -> Result<ValidatedOrchardTx, OrchardValidationError> {
    // 1. Enforce size limits before allocating or decoding
    if tx_bytes.len() > MAX_BLOCK_SIZE {
        return Err(OrchardValidationError::BlockLimitExceeded {
            actual: tx_bytes.len(),
            limit: MAX_BLOCK_SIZE,
        });
    }

    // 2. Parse outer envelope
    let envelope = tx::parse_envelope(tx_bytes, expected_chain_id)?;

    if envelope.tx_type == TxType::OrchardTransfer && tx_bytes.len() > MAX_TRANSACTION_SIZE {
        return Err(OrchardValidationError::TransactionTooLarge {
            actual: tx_bytes.len(),
            limit: MAX_TRANSACTION_SIZE,
        });
    }

    // 3. Extract payload prefix and bundle slice
    let payload = &tx_bytes[TX_ENVELOPE_LEN..];
    let payload_prefix = match envelope.tx_type {
        TxType::Coinbase => {
            tx::coinbase_height(tx_bytes).ok_or(EnvelopeError::TruncatedCoinbaseHeight)?
        }
        TxType::OrchardTransfer => {
            tx::transfer_fee(tx_bytes).ok_or(EnvelopeError::TruncatedTransferFee)?
        }
    };

    let bundle_bytes = &payload[8..];
    let bundle = deserialize_bundle(bundle_bytes)?;

    // 4. Validate bundle and cryptographic proofs/signatures
    let auth_digest = validate_bundle_stateless(&envelope, payload_prefix, &bundle, vk)?;

    Ok(ValidatedOrchardTx {
        envelope,
        payload_prefix,
        bundle,
        auth_digest,
    })
}

/// Adds an authorized bundle to an Orchard [`BatchValidator`].
pub fn add_bundle_to_batch<'a>(
    batch: &mut BatchValidator<'a>,
    bundle: &'a Bundle<Authorized, i64>,
    sighash: [u8; 32],
) -> Result<(), BatchError> {
    batch.add_bundle(bundle, sighash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_size_round_trip() {
        let values = [
            0,
            1,
            252,
            253,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX as usize,
        ];
        for &val in &values {
            let mut buf = Vec::new();
            encode_compact_size(val, &mut buf);
            let mut slice = &buf[..];
            let decoded = decode_compact_size(&mut slice).expect("decode");
            assert_eq!(decoded, val);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn test_consensus_fee_formula() {
        assert_eq!(consensus_fee(0, 0), Some(1_000));
        assert_eq!(consensus_fee(1, 0), Some(1_000));
        assert_eq!(consensus_fee(1, 100), Some(1_100));
        assert_eq!(consensus_fee(2, 500), Some(2_500));
        assert_eq!(consensus_fee(50, 10_000), Some(60_000));
        assert_eq!(consensus_fee(usize::MAX, usize::MAX), None);
    }

    #[test]
    fn test_deserialize_bundle_rejects_empty_data() {
        let empty: &[u8] = &[];
        assert_eq!(
            deserialize_bundle(empty).unwrap_err(),
            BundleCodecError::UnexpectedEof
        );
    }

    #[test]
    fn test_deserialize_bundle_rejects_zero_actions() {
        let zero_actions = [0x00]; // CompactSize 0
        assert_eq!(
            deserialize_bundle(&zero_actions).unwrap_err(),
            BundleCodecError::EmptyActions
        );
    }

    #[test]
    fn test_deserialize_bundle_rejects_excessive_actions_before_allocation() {
        let excessive_actions = [51u8]; // 51 > MAX_ACTIONS_PER_TX (50)
        assert_eq!(
            deserialize_bundle(&excessive_actions).unwrap_err(),
            BundleCodecError::TooManyActions
        );
    }

    #[test]
    fn test_deserialize_bundle_rejects_oversized_input_before_allocation() {
        let oversized = vec![0u8; MAX_BLOCK_SIZE + 1];
        match deserialize_bundle(&oversized).unwrap_err() {
            BundleCodecError::BundleTooLarge { actual, limit } => {
                assert_eq!(actual, MAX_BLOCK_SIZE + 1);
                assert_eq!(limit, MAX_BLOCK_SIZE);
            }
            other => panic!("Expected BundleTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn test_all_zero_ovk_constant() {
        assert_eq!(ALL_ZERO_OVK_BYTES, [0u8; 32]);
        let _ = all_zero_ovk();
    }

    #[test]
    fn test_error_display() {
        let err = BundleCodecError::NonCanonicalCompactSize;
        assert_eq!(format!("{err}"), "non-canonical compact size encoding");

        let val_err = OrchardValidationError::CoinbaseValueBalanceNotNegative { value_balance: 50 };
        assert_eq!(
            format!("{val_err}"),
            "coinbase valueBalanceOrchard must be negative, got 50"
        );
    }
}
