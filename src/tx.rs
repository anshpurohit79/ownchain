//! Structural validation of the canonical transaction envelope.
//!
//! `docs/protocol-v1.md` §7.0 defines the outer envelope of every
//! transaction:
//!
//! ```text
//! tx_type:u8 || tx_version:u16_le || chain_id:[u8;32] || payload
//! ```
//!
//! with `tx_version == 1` and authoritative transaction types 0..=7.

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

/// Transaction type tag for a coinbase (Type 0).
pub const TX_TYPE_COINBASE: u8 = 0;

/// Transaction type tag for a transparent transfer (Type 1).
pub const TX_TYPE_TRANSPARENT_TRANSFER: u8 = 1;

/// Transaction type tag for configure guardians (Type 2).
pub const TX_TYPE_CONFIGURE_GUARDIANS: u8 = 2;

/// Transaction type tag for guardian action (Type 3).
pub const TX_TYPE_GUARDIAN_ACTION: u8 = 3;

/// Transaction type tag for cancel pending transfer (Type 4).
pub const TX_TYPE_CANCEL_PENDING: u8 = 4;

/// Transaction type tag for shielded transfer (Type 5).
pub const TX_TYPE_SHIELDED_TRANSFER: u8 = 5;

/// Transaction type tag for transparent to shielded transfer (Type 6).
pub const TX_TYPE_TRANSPARENT_TO_SHIELDED: u8 = 6;

/// Transaction type tag for shielded to transparent transfer (Type 7).
pub const TX_TYPE_SHIELDED_TO_TRANSPARENT: u8 = 7;

/// The transaction type of a canonical transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxType {
    /// A coinbase: block position 0 only (Type 0).
    Coinbase,
    /// Transparent transfer between Ed25519 accounts (Type 1).
    TransparentTransfer,
    /// Configure guardian protection and rules for transparent account (Type 2).
    ConfigureGuardians,
    /// Guardian authorized action (Type 3).
    GuardianAction,
    /// Cancel a pending transfer to an unconfirmed recipient (Type 4).
    CancelPendingTransfer,
    /// Shielded transfer within Orchard pool (Type 5).
    ShieldedTransfer,
    /// Shielding transfer from transparent account to Orchard pool (Type 6).
    TransparentToShielded,
    /// Deshielding transfer from Orchard pool to transparent account (Type 7).
    ShieldedToTransparent,
}

impl TxType {
    /// Parses a transaction type tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TX_TYPE_COINBASE => Some(TxType::Coinbase),
            TX_TYPE_TRANSPARENT_TRANSFER => Some(TxType::TransparentTransfer),
            TX_TYPE_CONFIGURE_GUARDIANS => Some(TxType::ConfigureGuardians),
            TX_TYPE_GUARDIAN_ACTION => Some(TxType::GuardianAction),
            TX_TYPE_CANCEL_PENDING => Some(TxType::CancelPendingTransfer),
            TX_TYPE_SHIELDED_TRANSFER => Some(TxType::ShieldedTransfer),
            TX_TYPE_TRANSPARENT_TO_SHIELDED => Some(TxType::TransparentToShielded),
            TX_TYPE_SHIELDED_TO_TRANSPARENT => Some(TxType::ShieldedToTransparent),
            _ => None,
        }
    }

    /// Returns the wire tag of this transaction type.
    pub fn tag(self) -> u8 {
        match self {
            TxType::Coinbase => TX_TYPE_COINBASE,
            TxType::TransparentTransfer => TX_TYPE_TRANSPARENT_TRANSFER,
            TxType::ConfigureGuardians => TX_TYPE_CONFIGURE_GUARDIANS,
            TxType::GuardianAction => TX_TYPE_GUARDIAN_ACTION,
            TxType::CancelPendingTransfer => TX_TYPE_CANCEL_PENDING,
            TxType::ShieldedTransfer => TX_TYPE_SHIELDED_TRANSFER,
            TxType::TransparentToShielded => TX_TYPE_TRANSPARENT_TO_SHIELDED,
            TxType::ShieldedToTransparent => TX_TYPE_SHIELDED_TO_TRANSPARENT,
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
    /// A transaction payload is shorter than required for its transaction type.
    TruncatedPayload,
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
    /// The transaction payload length does not match the canonical length for its type.
    InvalidPayloadLength {
        /// The expected payload length in bytes.
        expected: usize,
        /// The actual payload length found.
        actual: usize,
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
            EnvelopeError::TruncatedPayload => write!(f, "transaction payload is truncated"),
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
            EnvelopeError::InvalidPayloadLength { expected, actual } => {
                write!(
                    f,
                    "invalid payload length: expected {expected} bytes, found {actual}"
                )
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Parses the outer envelope of a canonical transaction.
///
/// Checks the type tag, the version and the chain ID.
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
    if payload.is_empty() {
        return Err(EnvelopeError::MissingPayload);
    }

    match tx_type {
        TxType::Coinbase => {
            if payload.len() < 8 {
                return Err(EnvelopeError::TruncatedCoinbaseHeight);
            }
            if payload.len() == 8 {
                return Err(EnvelopeError::MissingPayload);
            }
        }
        TxType::TransparentTransfer => {
            if payload.len() != 160 {
                return Err(EnvelopeError::InvalidPayloadLength {
                    expected: 160,
                    actual: payload.len(),
                });
            }
        }
        TxType::ShieldedTransfer => {
            if payload.len() < 8 {
                return Err(EnvelopeError::TruncatedTransferFee);
            }
            if payload.len() == 8 {
                return Err(EnvelopeError::MissingPayload);
            }
        }
        TxType::TransparentToShielded if payload.len() < 133 => {
            // sender (32) + nonce (8) + amount (16) + fee (8) + bundle_len (4) + sender_sig (64) + quorum_count (1) = 133 min
            return Err(EnvelopeError::TruncatedPayload);
        }
        TxType::ShieldedToTransparent if payload.len() < 60 => {
            // recipient (32) + amount (16) + fee (8) + bundle_len (4) = 60 min
            return Err(EnvelopeError::TruncatedPayload);
        }
        _ => {}
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

/// Reads the fee declared by any transaction type according to its wire layout.
pub fn transaction_fee(tx: &[u8]) -> Option<u64> {
    let tag = *tx.first()?;
    let payload = tx.get(TX_ENVELOPE_LEN..)?;
    match tag {
        TX_TYPE_COINBASE => Some(0),
        TX_TYPE_TRANSPARENT_TRANSFER => {
            if payload.len() == 160 {
                // fee is at payload offset 80..88 (sender 32, recipient 32, amount 16)
                let bytes = payload.get(80..88)?;
                Some(u64::from_le_bytes(bytes.try_into().ok()?))
            } else {
                None
            }
        }
        TX_TYPE_CONFIGURE_GUARDIANS => {
            // nonce (8), fee (8)
            let bytes = payload.get(40..48)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }
        TX_TYPE_GUARDIAN_ACTION => {
            // account (32), action (1), fee (8)
            let bytes = payload.get(33..41)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }
        TX_TYPE_CANCEL_PENDING => {
            // sender (32), transfer_id (32), fee (8)
            let bytes = payload.get(64..72)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }
        TX_TYPE_SHIELDED_TRANSFER => {
            // fee is at payload offset 0..8
            let bytes = payload.get(..8)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }
        TX_TYPE_TRANSPARENT_TO_SHIELDED => {
            // sender (32), nonce (8), shielded_amount (16), fee (8)
            let bytes = payload.get(56..64)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }
        TX_TYPE_SHIELDED_TO_TRANSPARENT => {
            // recipient (32), release_amount (16), fee (8)
            let bytes = payload.get(48..56)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }
        _ => None,
    }
}

/// Computes the consensus minimum fee for a canonical signed transaction of `tx_len` bytes:
///
/// `minimum_fee = max(1 atom, 100 * canonical signed transaction byte length)`
///
/// Uses checked arithmetic to prevent integer overflow.
pub fn min_fee(tx_len: usize) -> Option<u64> {
    let len_u64 = u64::try_from(tx_len).ok()?;
    let calculated = len_u64.checked_mul(100)?;
    Some(calculated.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_fee_calculation() {
        assert_eq!(min_fee(0), Some(1));
        assert_eq!(min_fee(1), Some(100));
        assert_eq!(min_fee(195), Some(19_500));
        assert_eq!(min_fee(436), Some(43_600));
        assert_eq!(min_fee(usize::MAX), None);
    }
}
