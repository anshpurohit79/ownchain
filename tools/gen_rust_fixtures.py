#!/usr/bin/env python3
"""Emit the Rust golden-vector fixtures from `docs/test-vectors-m1a.json`.

This is a convenience emitter only: it performs no hashing and no encoding of
its own, it just transcribes the already-generated JSON vectors into Rust
`const` items so that the fixtures in `tests/vectors/mod.rs` cannot drift from
`docs/test-vectors-m1a.json` through manual copy/paste errors.

Run:  python tools/gen_rust_fixtures.py > tests/vectors.rs
"""

import json
import subprocess
import sys

HEADER_FIELD_ORDER = (
    "version:u16",
    "chain_id:32",
    "height:u64",
    "parent_block_id:32",
    "transaction_root:32",
    "orchard_commitment_root:32",
    "timestamp:u64",
    "difficulty:u128",
    "nonce:u64",
)


def rustfmt(source: str) -> str:
    """Format the generated module with `rustfmt` so regeneration is idempotent.

    Without this, `cargo fmt --check` would report drift between the emitted
    file and the checked-in one, because the raw emitter output is not
    rustfmt-normalised (long `const` lines get wrapped).
    """
    try:
        completed = subprocess.run(
            ["rustfmt", "--edition", "2021", "--emit", "stdout"],
            input=source,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, FileNotFoundError):
        # rustfmt is not available: fall back to the unformatted source.
        return source
    if completed.returncode != 0 or not completed.stdout:
        return source
    return completed.stdout


def main() -> int:
    with open("docs/test-vectors-m1a.json", encoding="utf-8") as fh:
        vectors = json.load(fh)

    txs = vectors["transactions"]
    merkle = vectors["merkle"]
    headers = vectors["headers"]
    blocks = vectors["blocks"]

    out: list[str] = []
    def write(line: str = "") -> None:
        out.append(line)

    def const(name: str, value: str) -> None:
        write(f'pub const {name}: &str = "{value}";')

    write("//! Golden-vector fixtures for OwnChain protocol v1, milestone M1-A.")
    write("//!")
    write("//! GENERATED FILE - do not edit by hand.")
    write("//!")
    write("//! Regenerate with: `python tools/gen_rust_fixtures.py > tests/vectors/mod.rs`")
    write("//!")
    write("//! The values are transcribed verbatim from `docs/test-vectors-m1a.json`,")
    write("//! which is produced by the independent generator `tools/gen_vectors.py`.")
    write()
    write("#![allow(dead_code)]")
    write()

    write("// --- Chain IDs (spec 6.4: BLAKE2b-256(UTF8(\"OwnChain/<network-name>/v1\"))) ---")
    const("DEVNET_CHAIN_ID", vectors["chain_ids"]["devnet"])
    const("TESTNET_CHAIN_ID", vectors["chain_ids"]["testnet"])
    write()

    write("// --- Empty transaction Merkle tree root ---")
    const("EMPTY_ROOT", vectors["empty_tree_root"])
    write()

    write("// --- Transaction fixtures ---")
    for name in ("tx_empty", "tx_a", "tx_b", "tx_c", "tx_d"):
        const(f"TX_{name[3:].upper()}_HEX", txs[name]["bytes_hex"])
    write()
    for name in ("tx_empty", "tx_a", "tx_b", "tx_c", "tx_d"):
        const(f"TX_{name[3:].upper()}_ID", txs[name]["tx_id"])
    write()

    write("// --- Merkle leaves (BLAKE2b-256(\"OwnChain/TxLeaf/v1\" || tx_id_bytes)) ---")
    for index, name in enumerate(("tx_a", "tx_b", "tx_c", "tx_d")):
        const(f"LEAF_{name[-1].upper()}", merkle["4_transactions"]["leaves"][index])
    write()

    write("// --- Merkle roots for 0..4 transactions ---")
    for count in range(5):
        const(f"ROOT_{count}", merkle[f"{count}_transactions"]["root"])
    write()

    write("// Inner node of the 2-transaction tree (also the left node of the 3-tx tree).")
    const("NODE_AB", merkle["2_transactions"]["level_1_inner_node"])
    write("// Inner node of the duplicated odd leaf (leaf C hashed with itself).")
    const("NODE_CC", merkle["3_transactions"]["level_1_inner_nodes"][1])
    write()

    write("// --- Header fixtures ---")
    write("//")
    write("// Field order (spec 6.1): " + " | ".join(HEADER_FIELD_ORDER))
    write()
    for key, prefix in (
        ("all_zero", "HEADER_ALL_ZERO"),
        ("devnet_genesis", "HEADER_GENESIS"),
        ("mixed_fields", "HEADER_MIXED"),
        ("max_values", "HEADER_MAX"),
    ):
        const(f"{prefix}_HEX", headers[key]["header_bytes_hex"])
        const(f"{prefix}_ID", headers[key]["block_id"])
        write()

    write("// --- Canonical block fixtures ---")
    write()
    for key, prefix in (
        ("no_transactions", "BLOCK_NO_TX"),
        ("one_transaction", "BLOCK_ONE_TX"),
        ("two_transactions", "BLOCK_TWO_TX"),
        ("three_transactions", "BLOCK_THREE_TX"),
        ("four_transactions", "BLOCK_FOUR_TX"),
        ("empty_transaction", "BLOCK_EMPTY_TX"),
    ):
        const(f"{prefix}_HEX", blocks[key]["canonical_bytes_hex"])
        write(f'pub const {prefix}_LEN: usize = {blocks[key]["canonical_len"]};')
    write()

    source = "\n".join(out) + "\n"
    sys.stdout.write(rustfmt(source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
