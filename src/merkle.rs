//! Transaction and State Merkle trees.
//!
//! Two distinct Merkle constructions are defined for OwnChain v1:
//!
//! 1. **Transaction Merkle Tree** (`docs/protocol-v1.md` §6.2):
//!    Pairwise bottom-up grouping with odd-node duplication, committing
//!    to transaction IDs in block header `transaction_root`.
//!
//! 2. **State Merkle Trees** (`docs/protocol-v1.md` §6.3, ADR-004 §5):
//!    RFC 6962-style domain-separated recursive-split binary trees without
//!    odd-node duplication, committing to:
//!    - Transparent account state (`state_merkle_root`)
//!    - Nullifier set (`nullifier_merkle_root`)
//!    - Shielded pool balance (`pool_balance_commitment`)
//!    - Composite state root (`composite_state_root`)

use blake2::digest::FixedOutput;
use blake2::Blake2b256;
use blake2::Digest;

use crate::hash::{self, Hash};

// ---------------------------------------------------------------------------
// 1. Transaction Merkle Tree (Block Header transaction_root)
// ---------------------------------------------------------------------------

/// Computes the Merkle leaf for a transaction ID.
///
/// `BLAKE2b-256("OwnChain/TxLeaf/v1" || transaction_id_bytes)`.
pub fn tx_leaf(transaction_id: &Hash) -> Hash {
    hash::hash_domained(hash::DOMAIN_TX_LEAF, transaction_id.as_bytes())
}

/// Computes an inner Merkle node from two child hashes.
///
/// `BLAKE2b-256("OwnChain/TxNode/v1" || left_bytes || right_bytes)`.
pub fn tx_node(left: &Hash, right: &Hash) -> Hash {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left.as_bytes());
    input[32..].copy_from_slice(right.as_bytes());
    hash::hash_domained(hash::DOMAIN_TX_NODE, &input)
}

/// The root of the empty transaction tree.
///
/// `BLAKE2b-256("OwnChain/TxEmpty/v1")`.
pub fn empty_root() -> Hash {
    hash::hash_domained(hash::DOMAIN_TX_EMPTY, &[])
}

/// Computes the transaction Merkle root over a slice of transaction IDs.
///
/// Returns the empty-tree root when `transaction_ids` is empty.
pub fn tx_root(transaction_ids: &[Hash]) -> Hash {
    if transaction_ids.is_empty() {
        return empty_root();
    }

    let mut level: Vec<Hash> = transaction_ids.iter().map(tx_leaf).collect();
    while level.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        let (pairs, remainder) = level.as_chunks::<2>();
        for pair in pairs {
            next.push(tx_node(&pair[0], &pair[1]));
        }
        if let Some(last) = remainder.first() {
            // Odd final node is duplicated.
            next.push(tx_node(last, last));
        }
        level = next;
    }
    level[0]
}

// ---------------------------------------------------------------------------
// 2. State Merkle Trees & Commitments (Composite State Root)
// ---------------------------------------------------------------------------

/// Domain separator for empty state Merkle tree.
pub const DOM_EMPTY: &[u8] = b"OwnChain/Merkle/Empty/v1";
/// Domain separator for state Merkle leaf: `BLAKE2b-256(DOM_LEAF || 0x00 || data)`.
pub const DOM_LEAF: &[u8] = b"OwnChain/Merkle/Leaf/v1";
/// Domain separator for state Merkle inner node: `BLAKE2b-256(DOM_NODE || 0x01 || left || right)`.
pub const DOM_NODE: &[u8] = b"OwnChain/Merkle/Node/v1";

/// Domain separator for empty nullifier Merkle tree.
pub const DOM_NF_EMPTY: &[u8] = b"OwnChain/Nullifier/Empty/v1";
/// Domain separator for nullifier leaf: `BLAKE2b-256(DOM_NF_LEAF || 0x00 || nullifier)`.
pub const DOM_NF_LEAF: &[u8] = b"OwnChain/Nullifier/Leaf/v1";
/// Domain separator for nullifier inner node: `BLAKE2b-256(DOM_NF_NODE || 0x01 || left || right)`.
pub const DOM_NF_NODE: &[u8] = b"OwnChain/Nullifier/Node/v1";

/// Domain separator for pool balance commitment: `BLAKE2b-256(DOM_POOL_BALANCE || balance_u128_le)`.
pub const DOM_POOL_BALANCE: &[u8] = b"OwnChain/PoolBalance/v1";

/// Domain separator for composite state root (30 bytes).
pub const DOM_COMPOSITE: &[u8] = b"OwnChain/CompositeStateRoot/v1";

/// The root of an empty state Merkle tree.
///
/// `BLAKE2b-256("OwnChain/Merkle/Empty/v1")`.
pub fn state_empty_root() -> Hash {
    hash::hash_domained(DOM_EMPTY, &[])
}

/// Computes a state Merkle leaf hash.
///
/// `BLAKE2b-256("OwnChain/Merkle/Leaf/v1" || 0x00 || data)`.
pub fn state_leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Blake2b256::new();
    hasher.update(DOM_LEAF);
    hasher.update([0x00]);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize_fixed());
    Hash::new(out)
}

/// Computes an inner state Merkle node hash from two child hashes.
///
/// `BLAKE2b-256("OwnChain/Merkle/Node/v1" || 0x01 || left || right)`.
pub fn state_node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Blake2b256::new();
    hasher.update(DOM_NODE);
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize_fixed());
    Hash::new(out)
}

/// Computes the recursive-split Merkle root over a sequence of items.
///
/// - 0 items: `state_empty_root()`
/// - 1 item: `state_leaf_hash(item)`
/// - $n \ge 2$ items: split at largest power of 2 strictly less than $n$
///   ($k = 1 \ll (n-1).\text{ilog2}()$).
pub fn state_merkle_root<T: AsRef<[u8]>>(items: &[T]) -> Hash {
    let n = items.len();
    if n == 0 {
        return state_empty_root();
    }
    if n == 1 {
        return state_leaf_hash(items[0].as_ref());
    }
    let k = 1usize << (n - 1).ilog2();
    let left = state_merkle_root(&items[..k]);
    let right = state_merkle_root(&items[k..]);
    state_node_hash(&left, &right)
}

/// The root of an empty nullifier Merkle tree.
///
/// `BLAKE2b-256("OwnChain/Nullifier/Empty/v1")`.
pub fn nullifier_empty_root() -> Hash {
    hash::hash_domained(DOM_NF_EMPTY, &[])
}

/// Computes a nullifier leaf hash.
///
/// `BLAKE2b-256("OwnChain/Nullifier/Leaf/v1" || 0x00 || nullifier)`.
pub fn nullifier_leaf_hash(nullifier: &Hash) -> Hash {
    let mut hasher = Blake2b256::new();
    hasher.update(DOM_NF_LEAF);
    hasher.update([0x00]);
    hasher.update(nullifier.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize_fixed());
    Hash::new(out)
}

/// Computes an inner nullifier Merkle node hash from two child hashes.
///
/// `BLAKE2b-256("OwnChain/Nullifier/Node/v1" || 0x01 || left || right)`.
pub fn nullifier_node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Blake2b256::new();
    hasher.update(DOM_NF_NODE);
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize_fixed());
    Hash::new(out)
}

/// Computes the recursive-split Merkle root over a sequence of nullifiers.
///
/// Nullifiers should be sorted in lexicographical ascending order.
pub fn nullifier_merkle_root(nullifiers: &[Hash]) -> Hash {
    let n = nullifiers.len();
    if n == 0 {
        return nullifier_empty_root();
    }
    if n == 1 {
        return nullifier_leaf_hash(&nullifiers[0]);
    }
    let k = 1usize << (n - 1).ilog2();
    let left = nullifier_merkle_root(&nullifiers[..k]);
    let right = nullifier_merkle_root(&nullifiers[k..]);
    nullifier_node_hash(&left, &right)
}

/// Computes the pool balance commitment for the cumulative shielded balance.
///
/// `BLAKE2b-256("OwnChain/PoolBalance/v1" || balance_u128_le)`.
pub fn pool_balance_commitment(balance_u128: u128) -> Hash {
    hash::hash_domained(DOM_POOL_BALANCE, &balance_u128.to_le_bytes())
}

/// Computes the composite state root from the 4 component roots.
///
/// `BLAKE2b-256("OwnChain/CompositeStateRoot/v1" || transparent_root || orchard_root || nullifier_root || pool_commitment)`.
pub fn composite_state_root(
    transparent_root: &Hash,
    orchard_root: &Hash,
    nullifier_root: &Hash,
    pool_commitment: &Hash,
) -> Hash {
    let mut input = [0u8; 128];
    input[..32].copy_from_slice(transparent_root.as_bytes());
    input[32..64].copy_from_slice(orchard_root.as_bytes());
    input[64..96].copy_from_slice(nullifier_root.as_bytes());
    input[96..128].copy_from_slice(pool_commitment.as_bytes());
    hash::hash_domained(DOM_COMPOSITE, &input)
}

/// The canonical composite state root at genesis height 0.
pub fn genesis_state_root() -> Hash {
    composite_state_root(
        &state_empty_root(),
        &crate::orchard_root::empty_commitment_root(),
        &nullifier_empty_root(),
        &pool_balance_commitment(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_state_root_matches_reference() {
        assert_eq!(DOM_COMPOSITE.len(), 30);
        let root = genesis_state_root();
        assert_eq!(
            root.to_hex(),
            "a6a88639bbf0a133b9398c6e4ac1a16bb490afeedb338d1cedbbcf427e68277d"
        );
    }
}
