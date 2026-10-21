//! Transaction Merkle tree.
//!
//! Rules from `docs/protocol-v1.md` §6.2, with the leaf definition pinned
//! explicitly by the M1-A decision record:
//!
//! * A leaf is `BLAKE2b-256("OwnChain/TxLeaf/v1" || transaction_id_bytes)`.
//!   The input is the 32 raw bytes of the transaction ID, not its hex text.
//! * An inner node is `BLAKE2b-256("OwnChain/TxNode/v1" || left || right)`,
//!   where `left` and `right` are the 32 raw bytes of the child hashes.
//! * When a level has an odd number of nodes, the final node is duplicated.
//! * The empty-tree root is `BLAKE2b-256("OwnChain/TxEmpty/v1")`.

use crate::hash::{self, Hash};

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
