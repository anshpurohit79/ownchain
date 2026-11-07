#!/usr/bin/env python3
"""Independent OwnChain v1 Transparent-Account Golden-Vector Generator.

This script uses only the Python standard library (hashlib, struct, json).
It does NOT use any Rust crate or third-party dependency.
It re-derives every canonical encoding, Merkle tree root, address, signature,
preimage, fee calculation, subsidy schedule, per-transfer lock state,
and coinbase maturity tracking from the OwnChain v1 transparent-account consensus specification.

Usage:
    python tools/gen_transparent_vectors.py [output_path]
"""

import hashlib
import json
import struct
import sys

# ---------------------------------------------------------------------------
# Cryptographic primitives: BLAKE2b-256 and pure-Python RFC 8032 Ed25519
# ---------------------------------------------------------------------------

HASH_LEN = 32
HEADER_LEN = 170

DOMAIN_BLOCK = b"OwnChain/Block/v1"
DOMAIN_TX = b"OwnChain/Tx/v1"
DOMAIN_TX_AUTH = b"OwnChain/TxAuth/v1"
DOMAIN_ADDRESS = b"OwnChain/Address/v1"
DOMAIN_MERKLE_EMPTY = b"OwnChain/Merkle/Empty/v1"
DOMAIN_MERKLE_LEAF = b"OwnChain/Merkle/Leaf/v1"
DOMAIN_MERKLE_NODE = b"OwnChain/Merkle/Node/v1"


def blake2b_256(data: bytes) -> bytes:
    """BLAKE2b with 32-byte output digest, unkeyed, no salt."""
    return hashlib.blake2b(data, digest_size=HASH_LEN).digest()


def chain_id(network: str) -> bytes:
    """Derive 32-byte network chain ID."""
    return blake2b_256(f"OwnChain/{network}/v1".encode("utf-8"))


# --- Pure-Python RFC 8032 Ed25519 implementation ---
_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _inv(x: int) -> int:
    return _expmod(x, _q - 2, _q)


_d = -121665 * _inv(121666)
_I = _expmod(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]


def _edwards(P: list[int], Q: list[int]) -> list[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]


def _scalarmult(P: list[int], e: int) -> list[int]:
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodepoint(P: list[int]) -> bytes:
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(
        [sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(_b // 8)]
    )


def ed25519_publickey(sk: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from 32-byte private key seed."""
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(
        2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _b - 2)
    )
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _Hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def ed25519_sign(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """Compute 64-byte Ed25519 signature."""
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(
        2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, _b - 2)
    )
    r = _Hint(h[32:] + m)
    R = _scalarmult(_B, r)
    R_bytes = _encodepoint(R)
    k = _Hint(R_bytes + pk + m)
    S = (r + k * a) % _l
    return R_bytes + S.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Merkle Tree: RFC 6962-style recursive split with no odd-leaf duplication
# ---------------------------------------------------------------------------


def empty_merkle_root() -> bytes:
    """Empty tree root: BLAKE2b-256(UTF8('OwnChain/Merkle/Empty/v1'))."""
    return blake2b_256(DOMAIN_MERKLE_EMPTY)


def leaf_hash(data: bytes) -> bytes:
    """Leaf hash: BLAKE2b-256(UTF8('OwnChain/Merkle/Leaf/v1') || 0x00 || data)."""
    return blake2b_256(DOMAIN_MERKLE_LEAF + b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """Node hash: BLAKE2b-256(UTF8('OwnChain/Merkle/Node/v1') || 0x01 || left || right)."""
    return blake2b_256(DOMAIN_MERKLE_NODE + b"\x01" + left + right)


def recursive_tree_hash(leaf_hashes: list[bytes]) -> bytes:
    """Recursive split with no odd-leaf duplication.

    k = 1 << ((n - 1).bit_length() - 1) for n >= 2.
    """
    n = len(leaf_hashes)
    if n == 0:
        return empty_merkle_root()
    if n == 1:
        return leaf_hashes[0]
    k = 1 << ((n - 1).bit_length() - 1)
    left_root = recursive_tree_hash(leaf_hashes[:k])
    right_root = recursive_tree_hash(leaf_hashes[k:])
    return node_hash(left_root, right_root)


# ---------------------------------------------------------------------------
# Transparent Account State Canonical Serialization
# ---------------------------------------------------------------------------


def serialize_pending_transfer(record: dict) -> bytes:
    """Serialize a pending transfer record (88 bytes):

    transfer_id[32] || recipient[32] || amount:u128_le (16) || release_height:u64_le (8)
    """
    tid = bytes.fromhex(record["transfer_id"])
    rec = bytes.fromhex(record["recipient"])
    amt = int(record["amount"]).to_bytes(16, "little")
    rel = struct.pack("<Q", int(record["release_height"]))
    assert len(tid) == 32 and len(rec) == 32
    return tid + rec + amt + rel


def serialize_coinbase_tranche(tranche: dict) -> bytes:
    """Serialize a coinbase maturity record (56 bytes):

    coinbase_tx_id[32] || amount:u128_le (16) || unlock_height:u64_le (8)
    """
    txid = bytes.fromhex(tranche["coinbase_tx_id"])
    amt = int(tranche["amount"]).to_bytes(16, "little")
    rel = struct.pack("<Q", int(tranche["unlock_height"]))
    assert len(txid) == 32
    return txid + amt + rel


def serialize_account_state(acc: dict) -> bytes:
    """Serialize canonical transparent account state.

    Fixed layout (346 bytes when both counts are 0):
      balance: u128_le (16)
      nonce: u64_le (8)
      allowance_limit: u128_le (16)
      allowance_window_start: u64_le (8)
      allowance_window_len: u64_le (8)
      allowance_spent: u128_le (16)
      is_frozen: u8 (1)
      recovery_key: [u8; 32] (32)
      guardian_enabled: u8 (1)
      new_recipient_delay: u32_le (4)
      withdrawal_delay: u32_le (4)
      guardians: [u8; 224] (7 * 32 = 224)
      pending_transfers_count: u32_le (4)
      pending_transfers: repeated(88 bytes)
      coinbase_tranches_count: u32_le (4)
      coinbase_tranches: repeated(56 bytes)
    """
    out = bytearray()
    out += int(acc.get("balance", 0)).to_bytes(16, "little")
    out += struct.pack("<Q", int(acc.get("nonce", 0)))
    out += int(acc.get("allowance_limit", 0)).to_bytes(16, "little")
    out += struct.pack("<Q", int(acc.get("allowance_window_start", 0)))
    out += struct.pack("<Q", int(acc.get("allowance_window_len", 0)))
    out += int(acc.get("allowance_spent", 0)).to_bytes(16, "little")
    out += struct.pack("<B", 1 if acc.get("is_frozen", False) else 0)

    rec_key = bytes.fromhex(acc.get("recovery_key", "00" * 32))
    assert len(rec_key) == 32
    out += rec_key

    out += struct.pack("<B", 1 if acc.get("guardian_enabled", False) else 0)
    out += struct.pack("<I", int(acc.get("new_recipient_delay", 10)))
    out += struct.pack("<I", int(acc.get("withdrawal_delay", 144)))

    guardians = acc.get("guardians", ["00" * 32] * 7)
    assert len(guardians) == 7
    for g in guardians:
        g_bytes = bytes.fromhex(g)
        assert len(g_bytes) == 32
        out += g_bytes

    pending = acc.get("pending_transfers", [])
    # Sorted deterministically by transfer_id ascending
    sorted_pending = sorted(pending, key=lambda x: bytes.fromhex(x["transfer_id"]))
    out += struct.pack("<I", len(sorted_pending))
    for p in sorted_pending:
        out += serialize_pending_transfer(p)

    tranches = acc.get("coinbase_tranches", [])
    # Sorted deterministically by unlock_height ascending, then coinbase_tx_id ascending
    sorted_tranches = sorted(
        tranches,
        key=lambda x: (
            int(x["unlock_height"]),
            bytes.fromhex(x["coinbase_tx_id"]),
        ),
    )
    out += struct.pack("<I", len(sorted_tranches))
    for t in sorted_tranches:
        out += serialize_coinbase_tranche(t)

    return bytes(out)


def compute_account_leaf_payload(address_bytes: bytes, acc: dict) -> bytes:
    assert len(address_bytes) == 32
    return address_bytes + serialize_account_state(acc)


# ---------------------------------------------------------------------------
# Canonical Header and Coinbase Transaction Serialization
# ---------------------------------------------------------------------------


def serialize_header(
    version: int,
    chain_id_bytes: bytes,
    height: int,
    parent_block_id: bytes,
    tx_root: bytes,
    state_root: bytes,
    timestamp: int,
    difficulty: int,
    nonce: int,
) -> bytes:
    assert len(chain_id_bytes) == 32
    assert len(parent_block_id) == 32
    assert len(tx_root) == 32
    assert len(state_root) == 32
    out = bytearray()
    out += struct.pack("<H", version)  # 2 bytes
    out += chain_id_bytes  # 32 bytes
    out += struct.pack("<Q", height)  # 8 bytes
    out += parent_block_id  # 32 bytes
    out += tx_root  # 32 bytes
    out += state_root  # 32 bytes
    out += struct.pack("<Q", timestamp)  # 8 bytes
    out += (difficulty & ((1 << 128) - 1)).to_bytes(
        16, "little"
    )  # 16 bytes u128_le
    out += struct.pack("<Q", nonce)  # 8 bytes
    assert len(out) == HEADER_LEN, f"Header size is {len(out)}, expected {HEADER_LEN}"
    return bytes(out)


def make_coinbase_tx(
    height: int, recipient_address: bytes, payout_atoms: int, chain_id_bytes: bytes
) -> bytes:
    """Canonical Coinbase transaction (type 0, 83 bytes fixed width):

    tx_type:u8 (1) || tx_version:u16_le (2) || chain_id (32) || height:u64_le (8) || recipient (32) || payout_atoms:u64_le (8)
    """
    raw = bytearray()
    raw += struct.pack("<B", 0)  # tx_type: 0
    raw += struct.pack("<H", 1)  # tx_version: 1
    raw += chain_id_bytes
    raw += struct.pack("<Q", height)
    raw += recipient_address
    raw += struct.pack("<Q", payout_atoms)
    assert len(raw) == 83
    return bytes(raw)


# ---------------------------------------------------------------------------
# Vector Generation
# ---------------------------------------------------------------------------


def generate_all_vectors() -> dict:
    devnet_chain_id = chain_id("devnet")
    testnet_chain_id = chain_id("testnet")
    empty_root = empty_merkle_root()

    # Sample addresses for test fixtures
    sample_privkeys = [
        bytes([0x10 + i] * 32) for i in range(4)
    ]  # 4 distinct seed keys
    sample_pubkeys = [ed25519_publickey(sk) for sk in sample_privkeys]
    sample_addresses = [
        blake2b_256(DOMAIN_ADDRESS + pk) for pk in sample_pubkeys
    ]

    # Compute deterministic coinbase transactions for Miner Dave (sample_addresses[3])
    miner_dave_addr = sample_addresses[3]
    cb_1_bytes = make_coinbase_tx(1, miner_dave_addr, 1_000_000_000, devnet_chain_id)
    tx_id_cb_1 = blake2b_256(DOMAIN_TX + cb_1_bytes)

    cb_100_bytes = make_coinbase_tx(100, miner_dave_addr, 1_000_000_000, devnet_chain_id)
    tx_id_cb_100 = blake2b_256(DOMAIN_TX + cb_100_bytes)

    # --- 1. Transaction Merkle Roots for 0-4 leaves ---
    raw_tx_payloads = [
        cb_1_bytes,  # Coinbase payout to miner Dave
        b"OwnChain test tx payload 1 (Transfer Alice -> Bob 100 OWN)",
        b"OwnChain test tx payload 2 (Transfer Bob -> Charlie 25 OWN)",
        b"OwnChain test tx payload 3 (ConfigureGuardians 7 keys)",
    ]
    tx_ids = [blake2b_256(DOMAIN_TX + payload) for payload in raw_tx_payloads]
    tx_leaf_hashes = [leaf_hash(tid) for tid in tx_ids]

    tx_merkle_cases = {}
    for count in range(5):
        current_tids = tx_ids[:count]
        current_leaves = tx_leaf_hashes[:count]
        root = recursive_tree_hash(current_leaves)

        details = {
            "tx_count": count,
            "tx_ids": [tid.hex() for tid in current_tids],
            "leaf_hashes": [lh.hex() for lh in current_leaves],
            "root": root.hex(),
        }
        if count == 0:
            details["structure"] = "empty_tree -> DOM_EMPTY"
        elif count == 1:
            details["structure"] = "single_leaf -> leaf_0"
        elif count == 2:
            h01 = node_hash(current_leaves[0], current_leaves[1])
            details["structure"] = "split at k=1: Node(leaf_0, leaf_1)"
            details["intermediate_nodes"] = {"node_0_1": h01.hex()}
        elif count == 3:
            h01 = node_hash(current_leaves[0], current_leaves[1])
            h_root = node_hash(h01, current_leaves[2])
            details["structure"] = (
                "split at k=2: Node(Node(leaf_0, leaf_1), leaf_2)"
            )
            details["intermediate_nodes"] = {
                "node_0_1": h01.hex(),
                "node_root": h_root.hex(),
            }
        elif count == 4:
            h01 = node_hash(current_leaves[0], current_leaves[1])
            h23 = node_hash(current_leaves[2], current_leaves[3])
            h_root = node_hash(h01, h23)
            details["structure"] = (
                "split at k=2: Node(Node(leaf_0, leaf_1), Node(leaf_2, leaf_3))"
            )
            details["intermediate_nodes"] = {
                "node_0_1": h01.hex(),
                "node_2_3": h23.hex(),
                "node_root": h_root.hex(),
            }
        tx_merkle_cases[f"{count}_leaves"] = details

    # --- 2. Account State Roots for 0-4 account entries ---
    accounts_data = [
        {
            "name": "Account 0 (Alice)",
            "address": sample_addresses[0].hex(),
            "pubkey": sample_pubkeys[0].hex(),
            "state": {
                "balance": 1_000_000_000,  # 10 OWN in atoms
                "nonce": 1,
                "allowance_limit": 500_000_000,
                "allowance_window_start": 100,
                "allowance_window_len": 720,
                "allowance_spent": 19_500,
                "is_frozen": False,
                "recovery_key": "11" * 32,
                "guardian_enabled": True,
                "new_recipient_delay": 10,
                "withdrawal_delay": 144,
                "guardians": [f"0{i}" * 32 for i in range(1, 8)],
                "pending_transfers": [
                    {
                        "transfer_id": "aa" * 32,
                        "recipient": sample_addresses[1].hex(),
                        "amount": 100_000_000,
                        "release_height": 110,
                    }
                ],
                "coinbase_tranches": [],
            },
        },
        {
            "name": "Account 1 (Bob)",
            "address": sample_addresses[1].hex(),
            "pubkey": sample_pubkeys[1].hex(),
            "state": {
                "balance": 500_000_000,  # 5 OWN
                "nonce": 0,
                "allowance_limit": 0,
                "allowance_window_start": 0,
                "allowance_window_len": 0,
                "allowance_spent": 0,
                "is_frozen": False,
                "recovery_key": "00" * 32,
                "guardian_enabled": False,
                "new_recipient_delay": 10,
                "withdrawal_delay": 144,
                "guardians": ["00" * 32] * 7,
                "pending_transfers": [],
                "coinbase_tranches": [],
            },
        },
        {
            "name": "Account 2 (Charlie)",
            "address": sample_addresses[2].hex(),
            "pubkey": sample_pubkeys[2].hex(),
            "state": {
                "balance": 250_000_000,
                "nonce": 3,
                "allowance_limit": 100_000_000,
                "allowance_window_start": 50,
                "allowance_window_len": 144,
                "allowance_spent": 50_000_000,
                "is_frozen": True,
                "recovery_key": "22" * 32,
                "guardian_enabled": True,
                "new_recipient_delay": 20,
                "withdrawal_delay": 288,
                "guardians": [f"1{i}" * 32 for i in range(1, 8)],
                "pending_transfers": [],
                "coinbase_tranches": [],
            },
        },
        {
            "name": "Account 3 (Miner Dave)",
            "address": sample_addresses[3].hex(),
            "pubkey": sample_pubkeys[3].hex(),
            "state": {
                "balance": 2_100_000_000,  # 1.1 OWN mature + 1.0 OWN immature
                "nonce": 0,
                "allowance_limit": 0,
                "allowance_window_start": 0,
                "allowance_window_len": 0,
                "allowance_spent": 0,
                "is_frozen": False,
                "recovery_key": "00" * 32,
                "guardian_enabled": False,
                "new_recipient_delay": 10,
                "withdrawal_delay": 144,
                "guardians": ["00" * 32] * 7,
                "pending_transfers": [],
                "coinbase_tranches": [
                    {
                        "coinbase_tx_id": tx_id_cb_100.hex(),
                        "amount": 1_000_000_000,
                        "unlock_height": 200,
                    }
                ],
            },
        },
    ]

    # Pre-serialize and compute payload for all sample accounts
    for acc in accounts_data:
        addr_b = bytes.fromhex(acc["address"])
        acc_b = serialize_account_state(acc["state"])
        leaf_payload = addr_b + acc_b
        acc["canonical_state_hex"] = acc_b.hex()
        acc["canonical_state_len"] = len(acc_b)
        acc["leaf_payload_hex"] = leaf_payload.hex()
        acc["leaf_hash"] = leaf_hash(leaf_payload).hex()

    state_merkle_cases = {}
    for count in range(5):
        subset = accounts_data[:count]
        # Deterministic ordering by address bytes ascending
        sorted_subset = sorted(
            subset, key=lambda x: bytes.fromhex(x["address"])
        )
        leaf_hashes = [bytes.fromhex(x["leaf_hash"]) for x in sorted_subset]
        s_root = recursive_tree_hash(leaf_hashes)

        state_merkle_cases[f"{count}_accounts"] = {
            "account_count": count,
            "sorted_addresses": [x["address"] for x in sorted_subset],
            "leaf_hashes": [lh.hex() for lh in leaf_hashes],
            "state_root": s_root.hex(),
        }

    # --- 3. Genesis and Header Encoding ---
    genesis_timestamp = 1_792_454_400  # 2026-10-20T00:00:00Z
    genesis_difficulty = 1
    genesis_nonce = 0
    genesis_parent = b"\x00" * 32

    genesis_header_bytes = serialize_header(
        version=1,
        chain_id_bytes=devnet_chain_id,
        height=0,
        parent_block_id=genesis_parent,
        tx_root=empty_root,
        state_root=empty_root,
        timestamp=genesis_timestamp,
        difficulty=genesis_difficulty,
        nonce=genesis_nonce,
    )
    genesis_block_id = blake2b_256(DOMAIN_BLOCK + genesis_header_bytes)

    # Example non-genesis block 1 header
    block1_tx_root = recursive_tree_hash([tx_leaf_hashes[0]])  # 1 coinbase tx
    block1_state_root = bytes.fromhex(
        state_merkle_cases["1_accounts"]["state_root"]
    )
    block1_timestamp = genesis_timestamp + 120
    block1_difficulty = 1
    block1_nonce = 12345
    block1_header_bytes = serialize_header(
        version=1,
        chain_id_bytes=devnet_chain_id,
        height=1,
        parent_block_id=genesis_block_id,
        tx_root=block1_tx_root,
        state_root=block1_state_root,
        timestamp=block1_timestamp,
        difficulty=block1_difficulty,
        nonce=block1_nonce,
    )
    block1_id = blake2b_256(DOMAIN_BLOCK + block1_header_bytes)

    # --- 4. Address Derivation & Realistic Signing Preimage Example ---
    alice_sk = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    alice_pk = ed25519_publickey(alice_sk)
    alice_address = blake2b_256(DOMAIN_ADDRESS + alice_pk)

    bob_sk = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    bob_pk = ed25519_publickey(bob_sk)
    bob_address = blake2b_256(DOMAIN_ADDRESS + bob_pk)

    # Transfer tx layout (type 1):
    # tx_type: u8 (1)
    # tx_version: u16_le (1)
    # chain_id: [u8; 32]
    # sender_pubkey: [u8; 32]
    # recipient: [u8; 32]
    # amount: u128_le (16)
    # fee_atoms: u64_le (8)
    # nonce: u64_le (8)
    # signature: [u8; 64]
    tx_type = 1
    tx_version = 1
    transfer_amount = 100_000_000  # 1 OWN
    transfer_fee = 19_500  # >= 100 * 195 = 19,500
    transfer_nonce = 0

    unsigned_tx = bytearray()
    unsigned_tx += struct.pack("<B", tx_type)
    unsigned_tx += struct.pack("<H", tx_version)
    unsigned_tx += devnet_chain_id
    unsigned_tx += alice_pk
    unsigned_tx += bob_address
    unsigned_tx += transfer_amount.to_bytes(16, "little")
    unsigned_tx += struct.pack("<Q", transfer_fee)
    unsigned_tx += struct.pack("<Q", transfer_nonce)
    canonical_unsigned_bytes = bytes(unsigned_tx)
    assert len(canonical_unsigned_bytes) == 131

    signing_preimage = (
        DOMAIN_TX_AUTH + devnet_chain_id + canonical_unsigned_bytes
    )
    signing_preimage_hash = blake2b_256(signing_preimage)

    # Sign with Alice's Ed25519 private key
    sig = ed25519_sign(signing_preimage, alice_sk, alice_pk)
    assert len(sig) == 64

    canonical_signed_tx = canonical_unsigned_bytes + sig
    assert len(canonical_signed_tx) == 195

    tx_id_transfer = blake2b_256(DOMAIN_TX + canonical_signed_tx)

    # --- 5. Minimum Fee Calculations ---
    fee_benchmarks = [
        {"desc": "Boundary zero-size", "size_bytes": 0, "min_fee_atoms": 1},
        {"desc": "Boundary 1-byte", "size_bytes": 1, "min_fee_atoms": 100},
        {
            "desc": "Coinbase tx (type 0, fixed 83 bytes)",
            "size_bytes": 83,
            "min_fee_atoms": 8300,
            "note": "Coinbase pays subsidy+fees to miner, fee is not paid by coinbase itself",
        },
        {
            "desc": "Standard Transfer tx (type 1, fixed 195 bytes)",
            "size_bytes": 195,
            "min_fee_atoms": 19500,
        },
        {
            "desc": "ConfigureGuardians tx (approx 363 bytes)",
            "size_bytes": 363,
            "min_fee_atoms": 36300,
        },
        {
            "desc": "CancelPendingTransfer tx (approx 443 bytes with 4 signatures)",
            "size_bytes": 443,
            "min_fee_atoms": 44300,
        },
        {
            "desc": "Arbitrary 1000-byte tx",
            "size_bytes": 1000,
            "min_fee_atoms": 100000,
        },
    ]

    # --- 6. Issuance Schedule and Cap Enforcement ---
    halving_interval = 1_050_000
    initial_subsidy_atoms = 1_000_000_000  # 10 OWN
    hard_cap_atoms = 2_100_000_000_000_000  # 21,000,000 OWN

    eras = []
    cumulative_atoms = 0
    for era in range(32):
        subsidy_atoms = initial_subsidy_atoms >> era
        era_start = era * halving_interval + 1
        era_end = (era + 1) * halving_interval
        blocks_in_era = halving_interval
        era_total_atoms = subsidy_atoms * blocks_in_era

        if cumulative_atoms + era_total_atoms > hard_cap_atoms:
            era_total_atoms = hard_cap_atoms - cumulative_atoms
            subsidy_atoms = 0

        cumulative_atoms += era_total_atoms
        eras.append(
            {
                "era": era,
                "start_height": era_start,
                "end_height": era_end,
                "subsidy_atoms": subsidy_atoms,
                "subsidy_own": f"{subsidy_atoms / 100_000_000:.8f}",
                "era_total_atoms": era_total_atoms,
                "cumulative_atoms": cumulative_atoms,
                "cumulative_own": f"{cumulative_atoms / 100_000_000:.8f}",
            }
        )
        if subsidy_atoms == 0:
            break

    # --- 7. Per-Transfer Lock and Guardian Semantics Scenario ---
    guardian_keys = [f"{i:02x}" * 32 for i in range(1, 8)]
    lock_scenario = {
        "description": "Deterministic step-by-step per-transfer pending lock, spendability of unrelated funds, maturity vs cancellation",
        "initial_state": {
            "alice": {
                "address": alice_address.hex(),
                "balance": 1_000_000_000,  # 10 OWN
                "nonce": 0,
                "guardian_enabled": True,
                "guardians": guardian_keys,
                "new_recipient_delay": 10,
                "withdrawal_delay": 144,
                "pending_transfers": [],
                "coinbase_tranches": [],
            },
            "bob": {
                "address": bob_address.hex(),
                "balance": 500_000_000,  # 5 OWN existing unrelated funds
                "nonce": 0,
                "guardian_enabled": False,
                "pending_transfers": [],
                "coinbase_tranches": [],
            },
        },
        "step_1_alice_sends_protected_first_time_transfer": {
            "block_height": 100,
            "action": "Alice sends 100,000,000 atoms (1 OWN) to Bob (new recipient)",
            "fee_atoms": 19_500,
            "transfer_id": tx_id_transfer.hex(),
            "delay_blocks": 10,
            "release_height": 110,
            "alice_state_after": {
                "balance": 1_000_000_000 - 100_000_000 - 19_500,  # 899,980,500
                "nonce": 1,
                "pending_transfers": [
                    {
                        "transfer_id": tx_id_transfer.hex(),
                        "recipient": bob_address.hex(),
                        "amount": 100_000_000,
                        "release_height": 110,
                    }
                ],
                "coinbase_tranches": [],
            },
            "bob_state_after": {
                "balance": 500_000_000,  # UNCHANGED! 100,000,000 is reserved in pending record
                "nonce": 0,
                "spendable_balance": 500_000_000,
            },
        },
        "step_2_bob_spends_unrelated_funds_while_transfer_is_pending": {
            "block_height": 105,
            "note": "105 < release_height 110. Bob's existing 500,000,000 atoms remain fully spendable!",
            "action": "Bob spends 50,000,000 atoms to Charlie",
            "bob_fee_atoms": 19_500,
            "bob_state_after": {
                "balance": 500_000_000 - 50_000_000 - 19_500,  # 449,980,500
                "nonce": 1,
                "spendable_balance": 449_980_500,
            },
            "pending_transfer_status": "Still pending in Alice account until height 110",
        },
        "step_3_branch_a_maturity_at_release_height": {
            "block_height": 110,
            "action": "Height 110 reached: pending transfer matures and is credited to Bob",
            "alice_state_after": {
                "balance": 899_980_500,
                "nonce": 1,
                "pending_transfers": [],  # record released and removed
                "coinbase_tranches": [],
            },
            "bob_state_after": {
                "balance": 449_980_500 + 100_000_000,  # 549,980,500
                "nonce": 1,
                "spendable_balance": 549_980_500,
            },
        },
        "step_3_branch_b_cancellation_before_maturity": {
            "block_height": 106,
            "action": "Alice detects unauthorized transfer and cancels with 4-of-7 guardian quorum",
            "authorization": "Alice sender signature + 4-of-7 distinct guardian signatures",
            "cancel_fee_atoms": 20_000,
            "rules": {
                "original_fee_refunded": False,
                "principal_restored": True,
                "nonce_reused": False,
                "cancel_consumes_new_nonce": True,
            },
            "alice_state_after": {
                "balance": 899_980_500 + 100_000_000 - 20_000,  # 999,960,500
                "nonce": 2,  # cancellation consumed nonce 1 -> 2
                "pending_transfers": [],  # record cancelled and removed
                "coinbase_tranches": [],
            },
            "bob_state_after": {
                "balance": 449_980_500,  # Bob never receives the 100,000,000 atoms
                "nonce": 1,
                "spendable_balance": 449_980_500,
            },
        },
        "overlapping_delays": {
            "note": "Multiple transfers from same account have independent pending records and release heights",
            "transfer_1": {"amount": 100_000_000, "release_height": 110},
            "transfer_2_delayed_withdrawal": {
                "amount": 200_000_000,
                "request_height": 102,
                "delay_blocks": 144,
                "release_height": 246,
            },
            "behavior": "Transfer 1 matures at 110, Transfer 2 matures at 246. Neither interferes with the other.",
        },
        "reorganization_rollback": {
            "rule": "If block 100 is reorganized out, all atomic transitions are reversed: Alice balance returns to 1,000,000,000, Alice nonce returns to 0, pending record is removed.",
        },
    }

    # --- 8. Coinbase Maturity Tracking Scenarios ---
    coinbase_maturity_cases = {
        "rule_summary": (
            "Coinbase rewards must mature for 100 blocks (unlock_height = height + 100). "
            "The transparent account ledger tracks immature rewards in canonical per-account coinbase_tranches. "
            "spendable_balance = balance - sum(immature_coinbase_tranches). "
            "A transaction must not spend immature coinbase value even when mingled with mature funds. "
            "At block height >= unlock_height, tranches mature and are removed from the account state."
        ),
        "case_1_new_coinbase_reward": {
            "description": "Miner receives block 1 coinbase reward (10 OWN). Reward is recorded as an immature tranche; spendable balance remains 0.",
            "block_height": 1,
            "coinbase_tx_id": tx_id_cb_1.hex(),
            "payout_atoms": 1_000_000_000,
            "maturity_delay_blocks": 100,
            "unlock_height": 101,  # 1 + 100
            "miner_state_after": {
                "balance": 1_000_000_000,
                "nonce": 0,
                "immature_coinbase_balance": 1_000_000_000,
                "spendable_balance": 0,
                "coinbase_tranches": [
                    {
                        "coinbase_tx_id": tx_id_cb_1.hex(),
                        "amount": 1_000_000_000,
                        "unlock_height": 101,
                    }
                ],
            },
            "spend_validation_at_height_1": {
                "attempted_spend_atoms": 100_000_000,
                "spendable_balance": 0,
                "result": "REJECTED (ErrImmatureCoinbaseSpend: spend exceeds spendable balance)",
            },
        },
        "case_2_partially_mature_account": {
            "description": "Miner has 500,000,000 mature atoms, then mines block 100 receiving 1,000,000,000 atoms reward. Total balance is 1,500,000,000, but only 500,000,000 is spendable.",
            "block_height": 100,
            "coinbase_tx_id": tx_id_cb_100.hex(),
            "payout_atoms": 1_000_000_000,
            "unlock_height": 200,  # 100 + 100
            "miner_state_after": {
                "balance": 1_500_000_000,
                "nonce": 0,
                "immature_coinbase_balance": 1_000_000_000,
                "spendable_balance": 500_000_000,
                "coinbase_tranches": [
                    {
                        "coinbase_tx_id": tx_id_cb_100.hex(),
                        "amount": 1_000_000_000,
                        "unlock_height": 200,
                    }
                ],
            },
        },
        "case_3_spending_mature_funds_while_reward_immature": {
            "description": "At height 105 (< 200), miner spends 200,000,000 atoms + 19,500 fee from mature balance. Spend succeeds; immature reward remains untouched.",
            "block_height": 105,
            "spend_amount_atoms": 200_000_000,
            "fee_atoms": 19_500,
            "total_spend_atoms": 200_019_500,
            "spendable_balance_before": 500_000_000,
            "result": "ACCEPTED (200,019,500 <= spendable_balance 500,000,000)",
            "miner_state_after": {
                "balance": 1_299_980_500,
                "nonce": 1,
                "immature_coinbase_balance": 1_000_000_000,
                "spendable_balance": 299_980_500,
                "coinbase_tranches": [
                    {
                        "coinbase_tx_id": tx_id_cb_100.hex(),
                        "amount": 1_000_000_000,
                        "unlock_height": 200,
                    }
                ],
            },
        },
        "case_4_rejection_of_spend_exceeding_mature_funds": {
            "description": "At height 106 (< 200), miner attempts to spend 400,000,000 atoms. Total spend 400,019,500 <= balance 1,299,980,500, but > spendable_balance 299,980,500. Attempted spend of immature coinbase value is rejected.",
            "block_height": 106,
            "attempted_spend_amount_atoms": 400_000_000,
            "fee_atoms": 19_500,
            "total_attempted_atoms": 400_019_500,
            "spendable_balance": 299_980_500,
            "total_balance": 1_299_980_500,
            "result": "REJECTED (ErrImmatureCoinbaseSpend: attempted spend exceeds spendable balance)",
            "miner_state_after": {
                "balance": 1_299_980_500,
                "nonce": 1,
                "spendable_balance": 299_980_500,
                "note": "State unchanged: transaction rejected before state modification",
            },
        },
        "case_5_exact_unlock_height_boundary": {
            "description": "At height 199, tranche remains immature. At height 200 (exact unlock_height), tranche matures and is removed; full balance becomes spendable.",
            "height_199_pre_maturity": {
                "block_height": 199,
                "tranche_status": "Immature (unlock_height 200 > 199)",
                "spendable_balance": 299_980_500,
                "immature_coinbase_balance": 1_000_000_000,
                "tranche_count": 1,
            },
            "height_200_exact_unlock": {
                "block_height": 200,
                "tranche_status": "Matured (unlock_height 200 <= 200)",
                "action": "Tranche is removed from coinbase_tranches at start of block 200 state transition",
                "miner_state_after": {
                    "balance": 1_299_980_500,
                    "nonce": 1,
                    "immature_coinbase_balance": 0,
                    "spendable_balance": 1_299_980_500,
                    "coinbase_tranches": [],
                },
                "post_maturity_spend_validation": {
                    "attempted_spend_atoms": 1_000_000_000,
                    "fee_atoms": 19_500,
                    "total_spend_atoms": 1_000_019_500,
                    "result": "ACCEPTED (1,000,019,500 <= spendable_balance 1,299,980,500)",
                },
            },
        },
    }

    # Assemble comprehensive vectors document
    output = {
        "spec": "OwnChain protocol v1 (Transparent Account Ledger Baseline)",
        "version": 1,
        "hash_primitive": "BLAKE2b-256 (32 bytes, unkeyed)",
        "signature_primitive": "Ed25519 (RFC 8032)",
        "header_size_bytes": HEADER_LEN,
        "domain_prefixes": {
            "block": DOMAIN_BLOCK.decode("utf-8"),
            "tx": DOMAIN_TX.decode("utf-8"),
            "tx_auth": DOMAIN_TX_AUTH.decode("utf-8"),
            "address": DOMAIN_ADDRESS.decode("utf-8"),
            "merkle_empty": DOMAIN_MERKLE_EMPTY.decode("utf-8"),
            "merkle_leaf": DOMAIN_MERKLE_LEAF.decode("utf-8"),
            "merkle_node": DOMAIN_MERKLE_NODE.decode("utf-8"),
        },
        "chain_ids": {
            "devnet": devnet_chain_id.hex(),
            "testnet": testnet_chain_id.hex(),
        },
        "empty_merkle_root": empty_root.hex(),
        "tx_merkle_roots": tx_merkle_cases,
        "sample_accounts": accounts_data,
        "state_merkle_roots": state_merkle_cases,
        "genesis": {
            "version": 1,
            "chain_id": devnet_chain_id.hex(),
            "height": 0,
            "parent_block_id": genesis_parent.hex(),
            "transaction_root": empty_root.hex(),
            "state_root": empty_root.hex(),
            "timestamp": genesis_timestamp,
            "difficulty": genesis_difficulty,
            "nonce": genesis_nonce,
            "header_bytes_hex": genesis_header_bytes.hex(),
            "header_len": len(genesis_header_bytes),
            "block_id": genesis_block_id.hex(),
        },
        "block_1_example": {
            "version": 1,
            "chain_id": devnet_chain_id.hex(),
            "height": 1,
            "parent_block_id": genesis_block_id.hex(),
            "transaction_root": block1_tx_root.hex(),
            "state_root": block1_state_root.hex(),
            "timestamp": block1_timestamp,
            "difficulty": block1_difficulty,
            "nonce": block1_nonce,
            "header_bytes_hex": block1_header_bytes.hex(),
            "header_len": len(block1_header_bytes),
            "block_id": block1_id.hex(),
        },
        "address_derivation": {
            "formula": "BLAKE2b-256(UTF8('OwnChain/Address/v1') || ed25519_public_key[32])",
            "alice_private_key_hex": alice_sk.hex(),
            "alice_public_key_hex": alice_pk.hex(),
            "alice_address_hex": alice_address.hex(),
            "bob_private_key_hex": bob_sk.hex(),
            "bob_public_key_hex": bob_pk.hex(),
            "bob_address_hex": bob_address.hex(),
        },
        "signing_preimage_and_transaction": {
            "tx_type": tx_type,
            "tx_version": tx_version,
            "chain_id": devnet_chain_id.hex(),
            "sender_pubkey": alice_pk.hex(),
            "sender_address": alice_address.hex(),
            "recipient_address": bob_address.hex(),
            "amount_atoms": transfer_amount,
            "fee_atoms": transfer_fee,
            "nonce": transfer_nonce,
            "canonical_unsigned_tx_hex": canonical_unsigned_bytes.hex(),
            "canonical_unsigned_tx_len": len(canonical_unsigned_bytes),
            "signing_preimage_hex": signing_preimage.hex(),
            "signing_preimage_len": len(signing_preimage),
            "signing_preimage_hash": signing_preimage_hash.hex(),
            "ed25519_signature_hex": sig.hex(),
            "canonical_signed_tx_hex": canonical_signed_tx.hex(),
            "canonical_signed_tx_len": len(canonical_signed_tx),
            "tx_id": tx_id_transfer.hex(),
        },
        "minimum_fee_benchmarks": fee_benchmarks,
        "issuance_and_subsidy_schedule": {
            "starting_subsidy_atoms": initial_subsidy_atoms,
            "starting_subsidy_own": 10,
            "halving_interval_blocks": halving_interval,
            "hard_cap_atoms": hard_cap_atoms,
            "hard_cap_own": 21_000_000,
            "subsidy_exhaustion_era": 30,
            "subsidy_exhaustion_height": 30 * halving_interval + 1,
            "final_cumulative_atoms": cumulative_atoms,
            "final_cumulative_own": f"{cumulative_atoms / 100_000_000:.8f}",
            "eras": eras,
        },
        "per_transfer_lock_and_guardian_scenario": lock_scenario,
        "coinbase_maturity_scenarios": coinbase_maturity_cases,
        "consensus_parameters_summary": {
            "header_size_bytes": 170,
            "block_size_limit_bytes": 2_000_000,
            "tx_size_limit_bytes": 1_000_000,
            "starting_subsidy_own": 10,
            "halving_interval_blocks": 1_050_000,
            "issuance_cap_own": 21_000_000,
            "min_fee_formula": "max(1, 100 * canonical_signed_tx_size)",
            "ordinary_maturity_blocks": 1,
            "coinbase_maturity_blocks": 100,
            "spendable_balance_formula": "balance - sum(immature_coinbase_tranches)",
            "new_recipient_delay_blocks": 10,
            "withdrawal_delay_blocks": 144,
            "guardian_count_per_account": 7,
            "quorum_strengthen_protections": "3-of-7",
            "quorum_weaken_protections_and_recovery": "4-of-7",
        },
    }

    return output


def main():
    vectors = generate_all_vectors()
    if len(sys.argv) > 1:
        out_path = sys.argv[1]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(vectors, f, indent=2)
            f.write("\n")
    else:
        json.dump(vectors, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
