#!/usr/bin/env python3
"""Independent OwnChain v1 golden-vector generator (M1-A).

This script does NOT use the Rust implementation. It re-derives every
canonical encoding and hash from the specification in `docs/protocol-v1.md`
using only Python's standard library (`hashlib.blake2b`).

Run:  python tools/gen_vectors.py > docs/test-vectors-m1a.json
"""

import hashlib
import json
import struct

HASH_LEN = 32
HEADER_LEN = 170
MAX_BLOCK_SIZE = 2_000_000
MAX_TX_SIZE = 1_000_000

DOMAIN_TX = b"OwnChain/Tx/v1"
DOMAIN_TX_LEAF = b"OwnChain/TxLeaf/v1"
DOMAIN_TX_NODE = b"OwnChain/TxNode/v1"
DOMAIN_TX_EMPTY = b"OwnChain/TxEmpty/v1"
DOMAIN_BLOCK = b"OwnChain/Block/v1"


def h(domain: bytes, data: bytes) -> bytes:
    """BLAKE2b-256 over domain || data."""
    return hashlib.blake2b(domain + data, digest_size=HASH_LEN).digest()


def chain_id(network: str) -> bytes:
    return h(f"OwnChain/{network}/v1".encode("utf-8"), b"")


def tx_id(tx: bytes) -> bytes:
    return h(DOMAIN_TX, tx)


def tx_leaf(tid: bytes) -> bytes:
    return h(DOMAIN_TX_LEAF, tid)


def tx_node(left: bytes, right: bytes) -> bytes:
    return h(DOMAIN_TX_NODE, left + right)


def empty_root() -> bytes:
    return h(DOMAIN_TX_EMPTY, b"")


def tx_root(tids):
    if not tids:
        return empty_root()
    level = [tx_leaf(t) for t in tids]
    while len(level) > 1:
        nxt = []
        i = 0
        while i + 1 < len(level):
            nxt.append(tx_node(level[i], level[i + 1]))
            i += 2
        if i < len(level):
            nxt.append(tx_node(level[i], level[i]))
        level = nxt
    return level[0]


def serialize_header(
    version=1,
    chain_id_bytes=b"\x00" * 32,
    height=0,
    parent=b"\x00" * 32,
    tx_root_bytes=b"\x00" * 32,
    orchard_root=b"\x00" * 32,
    timestamp=0,
    difficulty=0,
    nonce=0,
):
    assert len(chain_id_bytes) == 32
    assert len(parent) == 32
    assert len(tx_root_bytes) == 32
    assert len(orchard_root) == 32
    out = struct.pack("<H", version)
    out += chain_id_bytes
    out += struct.pack("<Q", height)
    out += parent
    out += tx_root_bytes
    out += orchard_root
    out += struct.pack("<Q", timestamp)
    out += (difficulty & ((1 << 128) - 1)).to_bytes(16, "little")
    out += struct.pack("<Q", nonce)
    assert len(out) == HEADER_LEN, len(out)
    return out


def serialize_block(header_bytes, txs):
    out = header_bytes + struct.pack("<I", len(txs))
    for tx in txs:
        out += struct.pack("<I", len(tx)) + tx
    return out


def hexs(b):
    return b.hex()



def main():
    devnet = chain_id("devnet")
    testnet = chain_id("testnet")

    vectors = {
        "spec": "OwnChain protocol v1, milestone M1-A",
        "generator": "tools/gen_vectors.py (Python hashlib.blake2b, independent of the Rust implementation)",
        "hash": "BLAKE2b-256, 32-byte output, no salt, no personalisation",
        "domain_prefixes": {
            "chain_id": "OwnChain/<network-name>/v1",
            "tx": "OwnChain/Tx/v1",
            "tx_leaf": "OwnChain/TxLeaf/v1",
            "tx_node": "OwnChain/TxNode/v1",
            "tx_empty": "OwnChain/TxEmpty/v1",
            "block": "OwnChain/Block/v1",
        },
        "chain_ids": {
            "devnet": hexs(devnet),
            "testnet": hexs(testnet),
        },
        "empty_tree_root": hexs(empty_root()),
    }

    # --- Transaction fixtures -------------------------------------------
    # Short deterministic payloads standing in for canonical transaction bytes.
    txs = {
        "tx_empty": b"",
        "tx_a": bytes(range(0x00, 0x20)),
        "tx_b": b"OwnChain test transaction B",
        "tx_c": bytes([0xFF] * 8) + b"cc",
        "tx_d": b"OwnChain test transaction D",
    }

    vectors["transactions"] = {}
    for name, tx in txs.items():
        vectors["transactions"][name] = {
            "bytes_hex": hexs(tx),
            "len": len(tx),
            "tx_id": hexs(tx_id(tx)),
        }

    # --- Merkle roots for 0..4 transactions -------------------------------
    ordered = ["tx_a", "tx_b", "tx_c", "tx_d"]
    vectors["merkle"] = {}
    for n in range(0, 5):
        names = ordered[:n]
        tids = [tx_id(txs[x]) for x in names]
        leaves = [tx_leaf(t) for t in tids]
        entry = {
            "tx_names": names,
            "tx_ids": [hexs(t) for t in tids],
            "leaves": [hexs(x) for x in leaves],
            "root": hexs(tx_root(tids)),
        }
        if n == 2:
            entry["level_1_inner_node"] = hexs(tx_node(leaves[0], leaves[1]))
        if n == 3:
            entry["level_1_inner_nodes"] = [
                hexs(tx_node(leaves[0], leaves[1])),
                hexs(tx_node(leaves[2], leaves[2])),
            ]
        vectors["merkle"][f"{n}_transactions"] = entry


    # --- Header / block vectors ------------------------------------------
    headers = {}

    def add_header(name, header_bytes, note, fields=None):
        bid = h(DOMAIN_BLOCK, header_bytes)
        entry = {
            "note": note,
            "header_bytes_hex": hexs(header_bytes),
            "header_len": len(header_bytes),
            "block_id": hexs(bid),
        }
        if fields is not None:
            entry["fields"] = fields
        headers[name] = entry
        return header_bytes

    # All-zero minimal header.
    add_header(
        "all_zero",
        serialize_header(),
        "version=1, every hash field zero, height/timestamp/difficulty/nonce zero",
        {
            "version": 1,
            "chain_id": "0" * 64,
            "height": 0,
            "parent_block_id": "0" * 64,
            "transaction_root": "0" * 64,
            "orchard_commitment_root": "0" * 64,
            "timestamp": 0,
            "difficulty": 0,
            "nonce": 0,
        },
    )

    # Genesis-like devnet header (spec 6.4 constants).
    genesis_header = serialize_header(
        chain_id_bytes=devnet,
        height=0,
        parent=b"\x00" * 32,
        tx_root_bytes=empty_root(),
        orchard_root=b"\x00" * 32,
        timestamp=1792454400,
        difficulty=1,
        nonce=0,
    )
    add_header(
        "devnet_genesis",
        genesis_header,
        "spec 6.4 genesis constants with the devnet chain ID and the empty tx root",
        {
            "version": 1,
            "chain_id": hexs(devnet),
            "height": 0,
            "parent_block_id": "0" * 64,
            "transaction_root": hexs(empty_root()),
            "orchard_commitment_root": "0" * 64,
            "timestamp": 1792454400,
            "difficulty": 1,
            "nonce": 0,
        },
    )

    # Mixed-field header exercising every field width.
    mixed_header = serialize_header(
        version=1,
        chain_id_bytes=devnet,
        height=1,
        parent=bytes(range(32)),
        tx_root_bytes=tx_root([tx_id(txs["tx_a"])]),
        orchard_root=bytes(range(32, 64)),
        timestamp=1792454401,
        difficulty=(1 << 64) + 12345,
        nonce=(1 << 63) + 7,
    )
    add_header(
        "mixed_fields",
        mixed_header,
        "exercises u16 version, u64 height, u128 difficulty, u64 nonce and all four 32-byte hashes",
        {
            "version": 1,
            "chain_id": hexs(devnet),
            "height": 1,
            "parent_block_id": hexs(bytes(range(32))),
            "transaction_root": hexs(tx_root([tx_id(txs["tx_a"])])),
            "orchard_commitment_root": hexs(bytes(range(32, 64))),
            "timestamp": 1792454401,
            "difficulty": (1 << 64) + 12345,
            "nonce": (1 << 63) + 7,
        },
    )

    # Maximum-width integer header.
    max_header = serialize_header(
        version=0xFFFF,
        chain_id_bytes=bytes([0xFF] * 32),
        height=(1 << 64) - 1,
        parent=bytes([0xAA] * 32),
        tx_root_bytes=bytes([0xBB] * 32),
        orchard_root=bytes([0xCC] * 32),
        timestamp=(1 << 64) - 1,
        difficulty=(1 << 128) - 1,
        nonce=(1 << 64) - 1,
    )

    add_header(
        "max_values",
        max_header,
        "every integer field at its maximum value",
        {
            "version": 0xFFFF,
            "chain_id": hexs(bytes([0xFF] * 32)),
            "height": (1 << 64) - 1,
            "parent_block_id": hexs(bytes([0xAA] * 32)),
            "transaction_root": hexs(bytes([0xBB] * 32)),
            "orchard_commitment_root": hexs(bytes([0xCC] * 32)),
            "timestamp": (1 << 64) - 1,
            "difficulty": (1 << 128) - 1,
            "nonce": (1 << 64) - 1,
        },
    )

    vectors["headers"] = headers

    # --- Canonical block encodings ---------------------------------------
    blocks = {}

    def add_block(name, header_bytes, txs_list, note):
        enc = serialize_block(header_bytes, txs_list)
        blocks[name] = {
            "note": note,
            "tx_count": len(txs_list),
            "canonical_bytes_hex": hexs(enc),
            "canonical_len": len(enc),
            "block_id": hexs(h(DOMAIN_BLOCK, header_bytes)),
        }

    add_block(
        "no_transactions",
        genesis_header,
        [],
        "header only plus tx_count = 0",
    )
    add_block(
        "one_transaction",
        mixed_header,
        [txs["tx_a"]],
        "one transaction, exercising the tx_length prefix",
    )
    add_block(
        "two_transactions",
        mixed_header,
        [txs["tx_a"], txs["tx_b"]],
        "two transactions",
    )
    add_block(
        "three_transactions",
        mixed_header,
        [txs["tx_a"], txs["tx_b"], txs["tx_c"]],
        "three transactions",
    )
    add_block(
        "empty_transaction",
        mixed_header,
        [txs["tx_empty"]],
        "one transaction whose canonical bytes are empty",
    )
    add_block(
        "four_transactions",
        mixed_header,
        [txs["tx_a"], txs["tx_b"], txs["tx_c"], txs["tx_d"]],
        "four transactions, two complete Merkle levels",
    )

    vectors["blocks"] = blocks

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
