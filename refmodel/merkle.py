"""
OwnChain Reference Model – Merkle tree construction.

Implements:
  1. Domain-separated recursive-split Merkle tree (transparent accounts & txs)
  2. Nullifier-set Merkle tree
  3. Pool-balance commitment
  4. Composite state root

All hashing: BLAKE2b-256 via ``hashlib.blake2b(digest_size=32)``.
Domain separators are raw UTF-8 bytes – no length prefix, no NUL terminator.
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Sequence

# ---------------------------------------------------------------------------
# Domain separators
# ---------------------------------------------------------------------------

# Transparent / generic Merkle tree
DOM_EMPTY = b"OwnChain/Merkle/Empty/v1"
DOM_LEAF = b"OwnChain/Merkle/Leaf/v1"
DOM_NODE = b"OwnChain/Merkle/Node/v1"

# Historical M1-A Transaction Merkle tree (Block Header transaction_root)
DOM_TX_LEAF = b"OwnChain/TxLeaf/v1"
DOM_TX_NODE = b"OwnChain/TxNode/v1"
DOM_TX_EMPTY = b"OwnChain/TxEmpty/v1"

# Nullifier-set Merkle tree
DOM_NF_EMPTY = b"OwnChain/Nullifier/Empty/v1"
DOM_NF_LEAF = b"OwnChain/Nullifier/Leaf/v1"
DOM_NF_NODE = b"OwnChain/Nullifier/Node/v1"

# Pool-balance commitment
DOM_POOL_BALANCE = b"OwnChain/PoolBalance/v1"

# Composite state root
DOM_COMPOSITE = b"OwnChain/CompositeStateRoot/v1"  # exactly 30 bytes
assert len(DOM_COMPOSITE) == 30, f"DOM_COMPOSITE must be 30 bytes, got {len(DOM_COMPOSITE)}"

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def blake2b_256(data: bytes) -> bytes:
    """Return BLAKE2b-256 digest of *data*."""
    return hashlib.blake2b(data, digest_size=32).digest()


def hash_domained(domain: bytes, data: bytes) -> bytes:
    """Return ``BLAKE2b-256(domain || data)``."""
    return blake2b_256(domain + data)


# ---------------------------------------------------------------------------
# 1. Transparent / generic recursive-split Merkle tree
# ---------------------------------------------------------------------------


def empty_root() -> bytes:
    """EmptyRoot = BLAKE2b-256(DOM_EMPTY)."""
    return blake2b_256(DOM_EMPTY)


def leaf_hash(data: bytes) -> bytes:
    """LeafHash(data) = BLAKE2b-256(DOM_LEAF || 0x00 || data)."""
    return blake2b_256(DOM_LEAF + b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """NodeHash(L, R) = BLAKE2b-256(DOM_NODE || 0x01 || L[32] || R[32])."""
    assert len(left) == 32 and len(right) == 32
    return blake2b_256(DOM_NODE + b"\x01" + left + right)


def merkle_root(items: Sequence[bytes]) -> bytes:
    """Compute the recursive-split Merkle root over *items*.

    * 0 items → ``empty_root()``
    * 1 item  → ``leaf_hash(item)``
    * n ≥ 2   → split at ``k = 1 << ((n-1).bit_length() - 1)``
                 then ``node_hash(merkle_root(items[:k]),
                                  merkle_root(items[k:]))``

    No odd-leaf duplication is performed.
    """
    n = len(items)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(items[0])
    # Recursive split: k is the largest power-of-2 < n
    k = 1 << ((n - 1).bit_length() - 1)
    left = merkle_root(items[:k])
    right = merkle_root(items[k:])
    return node_hash(left, right)


# ---------------------------------------------------------------------------
# 2. Nullifier-set Merkle tree
# ---------------------------------------------------------------------------


def nf_empty_root() -> bytes:
    """Empty root for the nullifier Merkle tree."""
    return blake2b_256(DOM_NF_EMPTY)


def nf_leaf_hash(nullifier: bytes) -> bytes:
    """NF LeafHash = BLAKE2b-256(DOM_NF_LEAF || 0x00 || nullifier[32])."""
    assert len(nullifier) == 32, "nullifier must be 32 bytes"
    return blake2b_256(DOM_NF_LEAF + b"\x00" + nullifier)


def nf_node_hash(left: bytes, right: bytes) -> bytes:
    """NF NodeHash = BLAKE2b-256(DOM_NF_NODE || 0x01 || L || R)."""
    assert len(left) == 32 and len(right) == 32
    return blake2b_256(DOM_NF_NODE + b"\x01" + left + right)


def nullifier_merkle_root(nullifiers: Sequence[bytes]) -> bytes:
    """Compute the nullifier-set Merkle root.

    *nullifiers* must be a sorted (lexicographic ascending) sequence of
    32-byte values.  The same recursive-split algorithm is used, but with
    nullifier-specific domain separators.
    """
    n = len(nullifiers)
    if n == 0:
        return nf_empty_root()
    if n == 1:
        return nf_leaf_hash(nullifiers[0])
    k = 1 << ((n - 1).bit_length() - 1)
    left = nullifier_merkle_root(nullifiers[:k])
    right = nullifier_merkle_root(nullifiers[k:])
    return nf_node_hash(left, right)


# ---------------------------------------------------------------------------
# 3. Pool-balance commitment
# ---------------------------------------------------------------------------


def pool_balance_commitment(balance_u128: int) -> bytes:
    """Compute ``BLAKE2b-256(DOM_POOL_BALANCE || balance_as_u128_le)``.

    Raises ``ValueError`` if *balance_u128* is negative or ≥ 2**128.
    """
    if balance_u128 < 0:
        raise ValueError("balance must be non-negative")
    if balance_u128 >= (1 << 128):
        raise ValueError("balance exceeds u128 range")
    balance_bytes = balance_u128.to_bytes(16, byteorder="little")
    return blake2b_256(DOM_POOL_BALANCE + balance_bytes)


# ---------------------------------------------------------------------------
# 4. Composite state root
# ---------------------------------------------------------------------------


def composite_state_root(
    transparent_root: bytes,
    orchard_root: bytes,
    nullifier_root: bytes,
    pool_commitment: bytes,
) -> bytes:
    """Compute the composite state root.

    ``BLAKE2b-256(DOM_COMPOSITE || transparent_root[32] || orchard_root[32]
                  || nullifier_root[32] || pool_balance_commitment[32])``
    """
    assert len(transparent_root) == 32
    assert len(orchard_root) == 32
    assert len(nullifier_root) == 32
    assert len(pool_commitment) == 32
    return blake2b_256(
        DOM_COMPOSITE
        + transparent_root
        + orchard_root
        + nullifier_root
        + pool_commitment
    )


# ---------------------------------------------------------------------------
# 5. Established M1-A Transaction Merkle Tree (Block Header transaction_root)
# ---------------------------------------------------------------------------


def m1a_tx_leaf(tx_id: bytes) -> bytes:
    """M1-A transaction leaf = BLAKE2b-256("OwnChain/TxLeaf/v1" || tx_id[32])."""
    assert len(tx_id) == 32, "tx_id must be 32 bytes"
    return blake2b_256(DOM_TX_LEAF + tx_id)


def m1a_tx_node(left: bytes, right: bytes) -> bytes:
    """M1-A transaction node = BLAKE2b-256("OwnChain/TxNode/v1" || left[32] || right[32])."""
    assert len(left) == 32 and len(right) == 32
    return blake2b_256(DOM_TX_NODE + left + right)


def m1a_empty_root() -> bytes:
    """M1-A empty transaction tree root = BLAKE2b-256("OwnChain/TxEmpty/v1")."""
    return blake2b_256(DOM_TX_EMPTY)


def m1a_tx_root(tx_ids: Sequence[bytes]) -> bytes:
    """Compute the M1-A transaction Merkle root over a sequence of 32-byte transaction IDs.

    - 0 transactions: returns m1a_empty_root().
    - Pairwise bottom-up grouping with odd-node duplication (Bitcoin-style).
    - Preserves historical M1-A vectors bit-for-bit.
    """
    if not tx_ids:
        return m1a_empty_root()

    level = [m1a_tx_leaf(tx_id) for tx_id in tx_ids]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                next_level.append(m1a_tx_node(level[i], level[i + 1]))
            else:
                next_level.append(m1a_tx_node(level[i], level[i]))
        level = next_level
    return level[0]

