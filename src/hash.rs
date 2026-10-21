//! Protocol hashing (BLAKE2b-256) for OwnChain v1.
//!
//! Every OwnChain hash use is domain-separated with a distinct ASCII domain
//! prefix, as required by `docs/protocol-v1.md` §3. The prefixes are exact
//! byte strings; they are *not* NUL-terminated and carry no length prefix.

use blake2::digest::FixedOutput;
use blake2::Blake2b256;
use blake2::Digest;

/// The output size of every OwnChain protocol hash, in bytes.
pub const HASH_LEN: usize = 32;

/// A 32-byte protocol hash (BLAKE2b-256).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// The all-zero hash. Used as the genesis parent block ID.
    pub const ZERO: Hash = Hash([0u8; HASH_LEN]);

    /// Constructs a hash from its 32 raw bytes.
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Hash(bytes)
    }

    /// Returns the raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Returns the raw 32 bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns `true` if every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Returns the lowercase hexadecimal representation.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(HASH_LEN * 2);
        for byte in self.0 {
            s.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble is < 16"));
            s.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble is < 16"));
        }
        s
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<[u8; HASH_LEN]> for Hash {
    fn from(bytes: [u8; HASH_LEN]) -> Self {
        Hash(bytes)
    }
}

impl From<Hash> for [u8; HASH_LEN] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

/// Computes BLAKE2b-256 over `domain || data`.
///
/// The domain prefix is concatenated verbatim with the payload; there is no
/// separator, length prefix, or NUL terminator.
pub fn hash_domained(domain: &[u8], data: &[u8]) -> Hash {
    let mut hasher = Blake2b256::new();
    hasher.update(domain);
    hasher.update(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&hasher.finalize_fixed());
    Hash(out)
}

/// Computes BLAKE2b-256 over `data` with no domain prefix.
pub fn hash(data: &[u8]) -> Hash {
    hash_domained(&[], data)
}

/// Derives a chain ID from a network name.
///
/// The chain ID is `BLAKE2b-256(UTF8("OwnChain/<network-name>/v1"))`.
pub fn chain_id(network_name: &str) -> Hash {
    let domain = format!("OwnChain/{network_name}/v1");
    hash_domained(domain.as_bytes(), &[])
}

/// Domain prefix for transaction IDs.
pub const DOMAIN_TX: &[u8] = b"OwnChain/Tx/v1";
/// Domain prefix for transaction Merkle leaves.
pub const DOMAIN_TX_LEAF: &[u8] = b"OwnChain/TxLeaf/v1";
/// Domain prefix for transaction Merkle inner nodes.
pub const DOMAIN_TX_NODE: &[u8] = b"OwnChain/TxNode/v1";
/// Domain prefix for the empty transaction Merkle tree.
pub const DOMAIN_TX_EMPTY: &[u8] = b"OwnChain/TxEmpty/v1";
/// Domain prefix for block IDs.
pub const DOMAIN_BLOCK: &[u8] = b"OwnChain/Block/v1";

/// Computes the transaction ID of canonical transaction bytes.
pub fn transaction_id(tx_bytes: &[u8]) -> Hash {
    hash_domained(DOMAIN_TX, tx_bytes)
}

/// Computes the block ID of canonical header bytes.
pub fn block_id(header_bytes: &[u8]) -> Hash {
    hash_domained(DOMAIN_BLOCK, header_bytes)
}
