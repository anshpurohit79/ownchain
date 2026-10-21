//! Error types for canonical encoding and decoding.

use core::fmt;

/// Errors produced while encoding or decoding canonical OwnChain structures.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EncodeError {
    /// The canonical serialized block exceeds the 2,000,000-byte consensus limit.
    BlockTooLarge {
        /// The actual size of the canonical encoding, in bytes.
        actual: usize,
        /// The maximum permitted size, in bytes.
        limit: usize,
    },
    /// The canonical serialized transaction exceeds the 1,000,000-byte limit.
    TransactionTooLarge {
        /// The actual size of the canonical transaction, in bytes.
        actual: usize,
        /// The maximum permitted size, in bytes.
        limit: usize,
    },
    /// The header byte slice did not have the canonical length of 170 bytes.
    InvalidHeaderLength {
        /// The length that was supplied.
        actual: usize,
    },
    /// A length-prefixed field was larger than the remaining input.
    Truncated {
        /// The number of bytes that were missing.
        missing: usize,
    },
    /// The input contained bytes past the end of the structure.
    TrailingBytes {
        /// The number of unexpected trailing bytes.
        extra: usize,
    },
    /// A count or length field could not be represented in `u32`.
    CountOverflow {
        /// The value that did not fit.
        value: u64,
    },
    /// A block declared more transactions than could be encoded.
    TooManyTransactions {
        /// The declared transaction count.
        count: u32,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::BlockTooLarge { actual, limit } => {
                write!(
                    f,
                    "canonical block is {actual} bytes, exceeds limit {limit}"
                )
            }
            EncodeError::TransactionTooLarge { actual, limit } => {
                write!(
                    f,
                    "canonical transaction is {actual} bytes, exceeds limit {limit}"
                )
            }
            EncodeError::InvalidHeaderLength { actual } => {
                write!(f, "header must be 170 bytes, got {actual}")
            }
            EncodeError::Truncated { missing } => {
                write!(f, "input truncated: {missing} bytes missing")
            }
            EncodeError::TrailingBytes { extra } => {
                write!(f, "{extra} unexpected trailing bytes")
            }
            EncodeError::CountOverflow { value } => {
                write!(f, "value {value} does not fit in a u32 count/length field")
            }
            EncodeError::TooManyTransactions { count } => {
                write!(f, "declared transaction count {count} is not encodable")
            }
        }
    }
}

impl std::error::Error for EncodeError {}
