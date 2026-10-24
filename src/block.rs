//! Canonical block encoding.
//!
//! From `docs/protocol-v1.md` §6.1:
//!
//! ```text
//! canonical_block = header_bytes
//!                 || tx_count:u32_le
//!                 || repeated(tx_length:u32_le || tx_bytes)
//! ```
//!
//! The 2,000,000-byte consensus block limit applies to this whole encoding,
//! including the header, the count field and every length prefix. It excludes
//! peer-to-peer transport framing.

use crate::error::EncodeError;
use crate::hash::Hash;
use crate::header::{Header, HEADER_LEN};

/// Maximum canonical serialized block size, in bytes.
pub const MAX_BLOCK_SIZE: usize = 2_000_000;

/// Maximum canonical serialized non-coinbase transaction size, in bytes.
pub const MAX_TRANSACTION_SIZE: usize = 1_000_000;

/// The size of the `tx_count` field, in bytes.
pub const TX_COUNT_LEN: usize = 4;

/// The size of each `tx_length` field, in bytes.
pub const TX_LENGTH_LEN: usize = 4;

/// A canonical OwnChain v1 block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    /// The block header.
    pub header: Header,
    /// The canonical transaction bytes, in block order.
    ///
    /// The coinbase, when present, is transaction index `0`.
    pub transactions: Vec<Vec<u8>>,
}

impl Block {
    /// Returns the size of the canonical serialization of this block, in bytes,
    /// without allocating it.
    ///
    /// Fails with the same errors as [`Block::to_bytes`] when the block
    /// exceeds a consensus limit.
    pub fn canonical_size(&self) -> Result<usize, EncodeError> {
        // The transaction count is encoded in a fixed-width `u32` field, so a
        // block carrying more than `u32::MAX` transactions cannot be encoded.
        // This cannot happen in practice, but the check is kept so that
        // `canonical_size` and `to_bytes` agree on every input.
        u32::try_from(self.transactions.len())
            .map_err(|_| EncodeError::TooManyTransactions { count: u32::MAX })?;

        let mut size = HEADER_LEN + TX_COUNT_LEN;
        for tx in &self.transactions {
            size += TX_LENGTH_LEN + tx.len();
        }

        if size > MAX_BLOCK_SIZE {
            return Err(EncodeError::BlockTooLarge {
                actual: size,
                limit: MAX_BLOCK_SIZE,
            });
        }

        // §6.3: Non-coinbase transactions are limited to 1,000,000 bytes.
        // The coinbase at index 0 is bounded only by the 2,000,000-byte block size.
        for tx in self.transactions.iter().skip(1) {
            if tx.len() > MAX_TRANSACTION_SIZE {
                return Err(EncodeError::TransactionTooLarge {
                    actual: tx.len(),
                    limit: MAX_TRANSACTION_SIZE,
                });
            }
        }

        debug_assert_eq!(
            size,
            HEADER_LEN
                + TX_COUNT_LEN
                + self
                    .transactions
                    .iter()
                    .map(|tx| TX_LENGTH_LEN + tx.len())
                    .sum::<usize>()
        );
        Ok(size)
    }

    /// Serializes the block into its canonical byte form.
    ///
    /// Fails if the encoding exceeds [`MAX_BLOCK_SIZE`] or if any transaction
    /// exceeds [`MAX_TRANSACTION_SIZE`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let count = u32::try_from(self.transactions.len())
            .map_err(|_| EncodeError::TooManyTransactions { count: u32::MAX })?;

        let mut size = HEADER_LEN + TX_COUNT_LEN;
        for tx in &self.transactions {
            size += TX_LENGTH_LEN + tx.len();
        }

        if size > MAX_BLOCK_SIZE {
            return Err(EncodeError::BlockTooLarge {
                actual: size,
                limit: MAX_BLOCK_SIZE,
            });
        }

        // §6.3: Non-coinbase transactions are limited to 1,000,000 bytes.
        // The coinbase at index 0 is bounded only by the 2,000,000-byte block size.
        for tx in self.transactions.iter().skip(1) {
            if tx.len() > MAX_TRANSACTION_SIZE {
                return Err(EncodeError::TransactionTooLarge {
                    actual: tx.len(),
                    limit: MAX_TRANSACTION_SIZE,
                });
            }
        }

        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for tx in &self.transactions {
            let len = u32::try_from(tx.len()).map_err(|_| EncodeError::CountOverflow {
                value: tx.len() as u64,
            })?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(tx);
        }
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }

    /// Parses a block from its canonical byte form.
    ///
    /// Rejects oversized blocks, truncated input, trailing bytes, and
    /// transaction counts or lengths that exceed the consensus limits.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        if bytes.len() > MAX_BLOCK_SIZE {
            return Err(EncodeError::BlockTooLarge {
                actual: bytes.len(),
                limit: MAX_BLOCK_SIZE,
            });
        }

        let header = Header::from_bytes(&bytes[..bytes.len().min(HEADER_LEN)])?;

        let mut o = HEADER_LEN;
        let count = read_u32(bytes, &mut o)?;
        let count = count as usize;

        // Each transaction costs at least its 4-byte length prefix, so a count
        // larger than the remaining bytes cannot be satisfied. This also
        // prevents unbounded allocation on malformed input.
        let remaining = bytes.len() - o;
        if count > remaining / TX_LENGTH_LEN {
            return Err(EncodeError::TooManyTransactions {
                count: count as u32,
            });
        }

        let mut transactions = Vec::with_capacity(count);
        for index in 0..count {
            let len = read_u32(bytes, &mut o)? as usize;
            // §6.3: Non-coinbase transactions (index > 0) are limited to 1,000,000 bytes.
            if index > 0 && len > MAX_TRANSACTION_SIZE {
                return Err(EncodeError::TransactionTooLarge {
                    actual: len,
                    limit: MAX_TRANSACTION_SIZE,
                });
            }
            let end = o
                .checked_add(len)
                .ok_or(EncodeError::Truncated { missing: len })?;
            if end > bytes.len() {
                return Err(EncodeError::Truncated {
                    missing: end - bytes.len(),
                });
            }
            transactions.push(bytes[o..end].to_vec());
            o = end;
        }

        if o != bytes.len() {
            return Err(EncodeError::TrailingBytes {
                extra: bytes.len() - o,
            });
        }

        Ok(Block {
            header,
            transactions,
        })
    }

    /// Returns the transaction IDs of the block, in block order.
    pub fn transaction_ids(&self) -> Vec<Hash> {
        self.transactions
            .iter()
            .map(|tx| crate::hash::transaction_id(tx))
            .collect()
    }

    /// Returns the transaction Merkle root over the block's transactions.
    pub fn transaction_root(&self) -> Hash {
        crate::merkle::tx_root(&self.transaction_ids())
    }

    /// Returns the block ID: BLAKE2b-256 over `"OwnChain/Block/v1" || header_bytes`.
    pub fn block_id(&self) -> Hash {
        self.header.block_id()
    }
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, EncodeError> {
    let end = offset
        .checked_add(4)
        .ok_or(EncodeError::Truncated { missing: 4 })?;
    if end > bytes.len() {
        return Err(EncodeError::Truncated {
            missing: end - bytes.len(),
        });
    }
    let value = u32::from_le_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset = end;
    Ok(value)
}
