//! Structural validation of the canonical transaction envelope.
//!
//! `docs/protocol-v1.md` §7.0 defines the outer envelope of every
//! transaction:
//!
//! ```text
//! tx_type:u8 || tx_version:u16_le || chain_id:[u8;32] || payload
//! ```
//!
//! with `tx_version == 1`, `tx_type == 0` (Coinbase, payload
//! `height:u64_le || orchard_bundle`) or `tx_type == 1` (OrchardTransfer,
//! payload `fee_atoms:u64_le || orchard_bundle`).
//!
//! This module checks only the *envelope*: the type tag, the version, the
//! chain ID and the fixed-width payload prefix. It deliberately does not
//! parse, prove, or verify the embedded Orchard V2 bundle — that is the
//! Orchard integration gate of §12 and is out of scope for milestone
//! M1-B.

use crate::hash::Hash;

/// The size of the `tx_type` field, in bytes.
pub const TX_TYPE_LEN: usize = 1;

/// The size of the `tx_version` field, in bytes.
pub const TX_VERSION_LEN: usize = 2;

/// The size of the `chain_id` field, in bytes.
pub const TX_CHAIN_ID_LEN: usize = 32;

/// The size of the fixed part of the envelope, in bytes.
///
/// `tx_type || tx_version || chain_id`.
pub const TX_ENVELOPE_LEN: usize = TX_TYPE_LEN + TX_VERSION_LEN + TX_CHAIN_ID_LEN;

/// The only supported transaction version.
pub const TX_VERSION: u16 = 1;

/// Transaction type tag for a coinbase.
pub const TX_TYPE_COINBASE: u8 = 0;

/// Transaction type tag for an ordinary Orchard transfer.
pub const TX_TYPE_ORCHARD_TRANSFER: u8 = 1;

/// The transaction type of a canonical transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxType {
    /// A coinbase: block position 0 only.
    Coinbase,
    /// An ordinary shielded Orchard transfer.
    OrchardTransfer,
}

impl TxType {
    /// Parses a transaction type tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TX_TYPE_COINBASE => Some(TxType::Coinbase),
            TX_TYPE_ORCHARD_TRANSFER => Some(TxType::OrchardTransfer),
            _ => None,
        }
    }

    /// Returns the wire tag of this transaction type.
    pub fn tag(self) -> u8 {
        match self {
            TxType::Coinbase => TX_TYPE_COINBASE,
            TxType::OrchardTransfer => TX_TYPE_ORCHARD_TRANSFER,
        }
    }
}

/// The decoded outer envelope of a canonical transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxEnvelope {
    /// The transaction type.
    pub tx_type: TxType,
    /// The transaction version.
    pub version: u16,
    /// The chain ID the transaction is bound to.
    pub chain_id: Hash,
}

/// The reasons an envelope can be structurally invalid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeError {
    /// The transaction is shorter than the fixed envelope.
    TooShort {
        /// The actual length of the transaction.
        actual: usize,
    },
    /// The transaction type tag is not known.
    UnknownType {
        /// The tag that was found.
        tag: u8,
    },
    /// The transaction version is not the supported one.
    UnsupportedVersion {
        /// The version that was found.
        found: u16,
        /// The only supported version.
        expected: u16,
    },
    /// The transaction's chain ID is not the active network's chain ID.
    WrongChainId {
        /// The chain ID the transaction is bound to.
        found: Hash,
        /// The chain ID of the active network.
        expected: Hash,
    },
    /// The transaction carries no payload after its envelope.
    MissingPayload,
    /// A coinbase's height payload is truncated.
    TruncatedCoinbaseHeight,
    /// A transfer's fee payload is truncated.
    TruncatedTransferFee,
    /// A coinbase's height does not match the block height.
    CoinbaseHeightMismatch {
        /// The height the coinbase declares.
        found: u64,
        /// The height of the block containing it.
        expected: u64,
    },
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnvelopeError::TooShort { actual } => {
                write!(
                    f,
                    "transaction is {actual} bytes, shorter than the envelope"
                )
            }
            EnvelopeError::UnknownType { tag } => {
                write!(f, "unknown transaction type {tag}")
            }
            EnvelopeError::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported transaction version {found}, expected {expected}"
                )
            }
            EnvelopeError::WrongChainId { found, expected } => {
                write!(f, "wrong transaction chain ID {found}, expected {expected}")
            }
            EnvelopeError::MissingPayload => write!(f, "transaction carries no payload"),
            EnvelopeError::TruncatedCoinbaseHeight => {
                write!(f, "coinbase height field is truncated")
            }
            EnvelopeError::TruncatedTransferFee => {
                write!(f, "transfer fee field is truncated")
            }
            EnvelopeError::CoinbaseHeightMismatch { found, expected } => {
                write!(
                    f,
                    "coinbase height {found} does not match block height {expected}"
                )
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Parses the outer envelope of a canonical transaction.
///
/// Checks the type tag, the version and the chain ID. The payload that
/// follows is only checked for the fixed-width prefix each transaction
/// type defines; the embedded Orchard bundle is not parsed.
pub fn parse_envelope(tx: &[u8], expected_chain_id: Hash) -> Result<TxEnvelope, EnvelopeError> {
    if tx.len() < TX_ENVELOPE_LEN {
        return Err(EnvelopeError::TooShort { actual: tx.len() });
    }

    let tx_type = TxType::from_tag(tx[0]).ok_or(EnvelopeError::UnknownType { tag: tx[0] })?;

    let version = u16::from_le_bytes([tx[1], tx[2]]);
    if version != TX_VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            found: version,
            expected: TX_VERSION,
        });
    }

    let mut chain_bytes = [0u8; TX_CHAIN_ID_LEN];
    chain_bytes.copy_from_slice(&tx[3..TX_ENVELOPE_LEN]);
    let chain_id = Hash::new(chain_bytes);
    if chain_id != expected_chain_id {
        return Err(EnvelopeError::WrongChainId {
            found: chain_id,
            expected: expected_chain_id,
        });
    }

    let payload = &tx[TX_ENVELOPE_LEN..];
    match tx_type {
        TxType::Coinbase => {
            // `height:u64_le || orchard_bundle`
            if payload.len() < 8 {
                return Err(EnvelopeError::TruncatedCoinbaseHeight);
            }
            if payload.len() == 8 {
                return Err(EnvelopeError::MissingPayload);
            }
        }
        TxType::OrchardTransfer => {
            // `fee_atoms:u64_le || orchard_bundle`
            if payload.len() < 8 {
                return Err(EnvelopeError::TruncatedTransferFee);
            }
            if payload.len() == 8 {
                return Err(EnvelopeError::MissingPayload);
            }
        }
    }

    Ok(TxEnvelope {
        tx_type,
        version,
        chain_id,
    })
}

/// Reads the height declared by a coinbase transaction's payload.
///
/// The caller must have already validated the envelope with
/// [`parse_envelope`].
pub fn coinbase_height(tx: &[u8]) -> Option<u64> {
    let payload = tx.get(TX_ENVELOPE_LEN..)?;
    let bytes = payload.get(..8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Reads the fee declared by an ordinary transfer transaction's payload.
///
/// The caller must have already validated the envelope with
/// [`parse_envelope`].
pub fn transfer_fee(tx: &[u8]) -> Option<u64> {
    let payload = tx.get(TX_ENVELOPE_LEN..)?;
    let bytes = payload.get(..8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
