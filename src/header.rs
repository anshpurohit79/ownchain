//! Canonical 170-byte block header.
//!
//! Field order and encoding follow `docs/protocol-v1.md` §6.1:
//!
//! | # | Field | Type | Bytes | Offset |
//! |---|---|---|---|---|
//! | 1 | `version` | `u16` | 2 | 0 |
//! | 2 | `chain_id` | bytes | 32 | 2 |
//! | 3 | `height` | `u64` | 8 | 34 |
//! | 4 | `parent_block_id` | bytes | 32 | 42 |
//! | 5 | `transaction_root` | bytes | 32 | 74 |
//! | 6 | `orchard_commitment_root` | bytes | 32 | 106 |
//! | 7 | `timestamp` | `u64` | 8 | 138 |
//! | 8 | `difficulty` | `u128` | 16 | 146 |
//! | 9 | `nonce` | `u64` | 8 | 162 |
//!
//! Total: 170 bytes. Every integer is little-endian.

use crate::error::EncodeError;
use crate::hash::Hash;

/// The exact canonical length of a serialized header, in bytes.
pub const HEADER_LEN: usize = 170;

/// The initial protocol version.
pub const VERSION_INITIAL: u16 = 1;

/// A canonical OwnChain v1 block header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// Protocol version. Initially `1`.
    pub version: u16,
    /// Active chain ID.
    pub chain_id: Hash,
    /// Block height. Genesis is `0`.
    pub height: u64,
    /// ID of the parent block. All zeros only for genesis.
    pub parent_block_id: Hash,
    /// Root of the transaction Merkle tree.
    pub transaction_root: Hash,
    /// Root of the Orchard commitment tree.
    pub orchard_commitment_root: Hash,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Difficulty target.
    pub difficulty: u128,
    /// RandomX nonce.
    pub nonce: u64,
}

impl Header {
    /// Serializes the header into its canonical 170-byte form.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let mut o = 0;

        out[o..o + 2].copy_from_slice(&self.version.to_le_bytes());
        o += 2;

        out[o..o + 32].copy_from_slice(self.chain_id.as_bytes());
        o += 32;

        out[o..o + 8].copy_from_slice(&self.height.to_le_bytes());
        o += 8;

        out[o..o + 32].copy_from_slice(self.parent_block_id.as_bytes());
        o += 32;

        out[o..o + 32].copy_from_slice(self.transaction_root.as_bytes());
        o += 32;

        out[o..o + 32].copy_from_slice(self.orchard_commitment_root.as_bytes());
        o += 32;

        out[o..o + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        o += 8;

        out[o..o + 16].copy_from_slice(&self.difficulty.to_le_bytes());
        o += 16;

        out[o..o + 8].copy_from_slice(&self.nonce.to_le_bytes());
        o += 8;

        debug_assert_eq!(o, HEADER_LEN);
        out
    }

    /// Parses a header from exactly 170 canonical bytes.
    ///
    /// Returns an error if the slice length is not exactly `170`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        if bytes.len() != HEADER_LEN {
            return Err(EncodeError::InvalidHeaderLength {
                actual: bytes.len(),
            });
        }
        let mut o = 0;

        let version = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        o += 2;

        let chain_id = read_hash(&bytes[o..o + 32]);
        o += 32;

        let height = u64::from_le_bytes(read_array8(&bytes[o..o + 8]));
        o += 8;

        let parent_block_id = read_hash(&bytes[o..o + 32]);
        o += 32;

        let transaction_root = read_hash(&bytes[o..o + 32]);
        o += 32;

        let orchard_commitment_root = read_hash(&bytes[o..o + 32]);
        o += 32;

        let timestamp = u64::from_le_bytes(read_array8(&bytes[o..o + 8]));
        o += 8;

        let difficulty = u128::from_le_bytes(read_array16(&bytes[o..o + 16]));
        o += 16;

        let nonce = u64::from_le_bytes(read_array8(&bytes[o..o + 8]));
        o += 8;

        debug_assert_eq!(o, HEADER_LEN);

        Ok(Header {
            version,
            chain_id,
            height,
            parent_block_id,
            transaction_root,
            orchard_commitment_root,
            timestamp,
            difficulty,
            nonce,
        })
    }

    /// Returns the block ID: BLAKE2b-256 over `"OwnChain/Block/v1" || header_bytes`.
    pub fn block_id(&self) -> Hash {
        crate::hash::block_id(&self.to_bytes())
    }
}

fn read_array8(slice: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(slice);
    out
}

fn read_array16(slice: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(slice);
    out
}

fn read_hash(slice: &[u8]) -> Hash {
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Hash::new(out)
}
