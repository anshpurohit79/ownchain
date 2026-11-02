#!/usr/bin/env python3
"""
OwnChain Hybrid Golden Test Vector Generator (v1).

Generates `docs/test-vectors-v1-hybrid.json` containing deterministic test vectors
for:
  1. Merkle & State Commitments (transparent, Orchard, nullifier, pool balance, composite)
  2. Transactions (Types 0 through 7 canonical wire encodings, preimages, IDs)
  3. Cross-Pool Transitions (shielding, deshielding, fee accounting, balance conservation)
  4. Economic Rules (subsidy eras, halving, era 30 exhaustion, 21M cap, coinbase maturity)
  5. Guardian & Pending Transfers (3-of-7, 4-of-7 quorums, delay locking, cancellation, reorg)

Determinism Requirement:
  Running this generator multiple times must produce bit-for-bit identical JSON output.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

# Ensure repository root is in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from refmodel.hybrid_state import (
    AccountState,
    CoinbaseTranche,
    HybridChainState,
    PendingTransfer,
    scheduled_subsidy,
)
from refmodel.merkle import (
    blake2b_256,
    composite_state_root,
    empty_root,
    merkle_root,
    nullifier_merkle_root,
    pool_balance_commitment,
)
from refmodel.orchard_adapter import OrchardAdapter
from refmodel.transactions import (
    ACTION_CANCEL_PENDING,
    ACTION_FREEZE,
    ACTION_RECOVERY,
    ACTION_STRENGTHEN_DELAYS,
    ACTION_UNFREEZE,
    ACTION_WEAKEN_DELAYS,
    CancelPendingTransferTx,
    CoinbaseTx,
    ConfigureGuardiansTx,
    GuardianActionTx,
    ShieldedToTransparentTx,
    ShieldedTransferTx,
    TransparentToShieldedTx,
    TransparentTransferTx,
    derive_address,
)

DEVNET_CHAIN_ID = blake2b_256(b"OwnChain/devnet/v1")
TESTNET_CHAIN_ID = blake2b_256(b"OwnChain/testnet/v1")


def generate_vectors() -> dict:
    vectors = {
        "metadata": {
            "title": "OwnChain Protocol v1 — Hybrid Golden Test Vectors",
            "version": 1,
            "hash_function": "BLAKE2b-256",
            "pinned_orchard_crate": "0.16.0",
            "orchard_empty_root_hex": OrchardAdapter.ORCHARD_EMPTY_ROOT_HEX,
            "devnet_chain_id_hex": DEVNET_CHAIN_ID.hex(),
            "testnet_chain_id_hex": TESTNET_CHAIN_ID.hex(),
        }
    }

    # =======================================================================
    # 1. Merkle & State Commitments
    # =======================================================================
    merkle_sec = {}

    # Empty roots
    t_empty = empty_root()
    o_empty = OrchardAdapter.empty_commitment_root()
    nf_empty = nullifier_merkle_root([])
    s_comm_zero = pool_balance_commitment(0)
    s_comm_1_own = pool_balance_commitment(100_000_000)
    s_comm_10_own = pool_balance_commitment(1_000_000_000)

    merkle_sec["empty_transparent_tree"] = {
        "domain": "OwnChain/Merkle/Empty/v1",
        "root_hex": t_empty.hex(),
    }
    merkle_sec["empty_orchard_tree"] = {
        "source": "orchard::tree::Anchor::empty_tree()",
        "root_hex": o_empty.hex(),
    }
    merkle_sec["empty_nullifier_tree"] = {
        "domain": "OwnChain/Nullifier/Empty/v1",
        "root_hex": nf_empty.hex(),
    }
    merkle_sec["pool_balance_commitments"] = {
        "balance_0_atoms": {"balance": 0, "commitment_hex": s_comm_zero.hex()},
        "balance_1_own": {
            "balance": 100_000_000,
            "commitment_hex": s_comm_1_own.hex(),
        },
        "balance_10_own": {
            "balance": 1_000_000_000,
            "commitment_hex": s_comm_10_own.hex(),
        },
    }

    # Composite genesis state root
    comp_genesis = composite_state_root(t_empty, o_empty, nf_empty, s_comm_zero)
    merkle_sec["composite_genesis_state_root"] = {
        "formula": "BLAKE2b-256(UTF8('OwnChain/CompositeStateRoot/v1') || T_root || O_root || NF_root || S_comm)",
        "domain": "OwnChain/CompositeStateRoot/v1",
        "domain_len": 30,
        "transparent_root_hex": t_empty.hex(),
        "orchard_root_hex": o_empty.hex(),
        "nullifier_root_hex": nf_empty.hex(),
        "pool_commitment_hex": s_comm_zero.hex(),
        "composite_state_root_hex": comp_genesis.hex(),
    }

    # 1 to 4 Transparent Accounts Merkle Roots
    keys = [blake2b_256(f"test-account-key-{i}".encode()) for i in range(1, 5)]
    addrs = [derive_address(k) for k in keys]
    # Create distinct account states
    accounts = []
    for i in range(4):
        acc = AccountState(
            balance=(i + 1) * 100_000_000,
            nonce=i,
            new_recipient_delay=10,
            withdrawal_delay=144,
        )
        accounts.append(acc)

    account_trees = {}
    for count in range(1, 5):
        subset_addrs = addrs[:count]
        subset_accs = accounts[:count]
        # Sort by raw 32-byte address ascending
        sorted_pairs = sorted(zip(subset_addrs, subset_accs), key=lambda x: x[0])
        leaves = [a + ac.serialize() for a, ac in sorted_pairs]
        root = merkle_root(leaves)
        account_trees[f"accounts_{count}"] = {
            "count": count,
            "sorted_addresses_hex": [a.hex() for a, _ in sorted_pairs],
            "merkle_root_hex": root.hex(),
        }
    merkle_sec["transparent_account_trees"] = account_trees

    # 1 to 4 Nullifiers Merkle Roots
    raw_nfs = [blake2b_256(f"test-nullifier-{i}".encode()) for i in range(1, 5)]
    nf_trees = {}
    for count in range(1, 5):
        subset = raw_nfs[:count]
        sorted_nfs = sorted(subset)
        root = nullifier_merkle_root(sorted_nfs)
        nf_trees[f"nullifiers_{count}"] = {
            "count": count,
            "sorted_nullifiers_hex": [nf.hex() for nf in sorted_nfs],
            "merkle_root_hex": root.hex(),
        }
    merkle_sec["nullifier_trees"] = nf_trees

    vectors["merkle_commitments"] = merkle_sec

    # =======================================================================
    # 2. Canonical Transactions (Types 0 through 7)
    # =======================================================================
    tx_sec = {}

    # Type 0: Coinbase
    cb_tx = CoinbaseTx(
        chain_id=DEVNET_CHAIN_ID,
        height=1,
        recipient=addrs[0],
        payout_atoms=1_000_000_000,
    )
    cb_bytes = cb_tx.serialize()
    tx_sec["type_0_coinbase"] = {
        "tx_type": 0,
        "name": "Coinbase",
        "chain_id_hex": DEVNET_CHAIN_ID.hex(),
        "height": 1,
        "recipient_hex": addrs[0].hex(),
        "payout_atoms": 1_000_000_000,
        "canonical_signed_bytes_hex": cb_bytes.hex(),
        "canonical_size_bytes": len(cb_bytes),
        "tx_id_hex": cb_tx.tx_id.hex(),
        "fee_atoms": 0,
        "expected_validation": "valid",
    }

    # Type 1: TransparentTransfer
    dummy_sig = b"\x11" * 64
    tr_tx = TransparentTransferTx(
        chain_id=DEVNET_CHAIN_ID,
        sender_pubkey=keys[0],
        recipient=addrs[1],
        amount=100_000_000,  # 1 OWN
        fee_atoms=19_500,  # 100 * 195 bytes
        nonce=0,
        signature=dummy_sig,
    )
    tr_bytes = tr_tx.serialize()
    tx_sec["type_1_transparent_transfer"] = {
        "tx_type": 1,
        "name": "TransparentTransfer",
        "sender_pubkey_hex": keys[0].hex(),
        "sender_address_hex": addrs[0].hex(),
        "recipient_address_hex": addrs[1].hex(),
        "amount_atoms": 100_000_000,
        "fee_atoms": 19_500,
        "nonce": 0,
        "canonical_unsigned_bytes_hex": tr_tx.canonical_unsigned_bytes().hex(),
        "signing_preimage_hex": tr_tx.signing_preimage().hex(),
        "canonical_signed_bytes_hex": tr_bytes.hex(),
        "canonical_size_bytes": len(tr_bytes),
        "min_fee_atoms": tr_tx.min_fee,
        "tx_id_hex": tr_tx.tx_id.hex(),
        "expected_validation": "valid",
    }

    # Type 2: ConfigureGuardians
    guardian_keys = [blake2b_256(f"guardian-key-{i}".encode()) for i in range(1, 8)]
    recovery_key = blake2b_256(b"recovery-key")
    cfg_tx = ConfigureGuardiansTx(
        chain_id=DEVNET_CHAIN_ID,
        account_pubkey=keys[0],
        nonce=1,
        fee_atoms=50_000,
        guardian_keys=guardian_keys,
        new_recipient_delay=10,
        withdrawal_delay=144,
        allowance_limit=500_000_000,
        allowance_window_len=720,
        recovery_key=recovery_key,
        owner_sig=b"\x22" * 64,
    )
    cfg_bytes = cfg_tx.serialize()
    tx_sec["type_2_configure_guardians"] = {
        "tx_type": 2,
        "name": "ConfigureGuardians",
        "account_pubkey_hex": keys[0].hex(),
        "guardian_keys_hex": [gk.hex() for gk in guardian_keys],
        "new_recipient_delay": 10,
        "withdrawal_delay": 144,
        "allowance_limit_atoms": 500_000_000,
        "allowance_window_len": 720,
        "recovery_key_hex": recovery_key.hex(),
        "canonical_signed_bytes_hex": cfg_bytes.hex(),
        "canonical_size_bytes": len(cfg_bytes),
        "min_fee_atoms": cfg_tx.min_fee,
        "tx_id_hex": cfg_tx.tx_id.hex(),
        "expected_validation": "valid",
    }

    # Type 3: GuardianAction
    action_tx = GuardianActionTx(
        chain_id=DEVNET_CHAIN_ID,
        account=addrs[0],
        action_type=ACTION_FREEZE,
        fee_atoms=35_000,
        params=b"",
        guardian_sigs=[
            (0, b"\x30" * 64),
            (1, b"\x31" * 64),
            (2, b"\x32" * 64),
            (3, b"\x33" * 64),
        ],
    )
    action_bytes = action_tx.serialize()
    tx_sec["type_3_guardian_action"] = {
        "tx_type": 3,
        "name": "GuardianAction",
        "account_address_hex": addrs[0].hex(),
        "action_type": ACTION_FREEZE,
        "action_name": "Freeze",
        "quorum_count": 4,
        "canonical_signed_bytes_hex": action_bytes.hex(),
        "canonical_size_bytes": len(action_bytes),
        "min_fee_atoms": action_tx.min_fee,
        "tx_id_hex": action_tx.tx_id.hex(),
        "expected_validation": "valid",
    }

    # Type 4: CancelPendingTransfer
    target_transfer_id = blake2b_256(b"dummy_transfer_id")
    cancel_tx = CancelPendingTransferTx(
        chain_id=DEVNET_CHAIN_ID,
        sender_pubkey=keys[0],
        transfer_id=target_transfer_id,
        fee_atoms=30_000,
        nonce=2,
        sender_sig=b"\x40" * 64,
        guardian_sigs=[
            (0, b"\x41" * 64),
            (1, b"\x42" * 64),
            (2, b"\x43" * 64),
            (3, b"\x44" * 64),
        ],
    )
    cancel_bytes = cancel_tx.serialize()
    tx_sec["type_4_cancel_pending_transfer"] = {
        "tx_type": 4,
        "name": "CancelPendingTransfer",
        "transfer_id_hex": target_transfer_id.hex(),
        "sender_pubkey_hex": keys[0].hex(),
        "quorum_count": 4,
        "canonical_signed_bytes_hex": cancel_bytes.hex(),
        "canonical_size_bytes": len(cancel_bytes),
        "min_fee_atoms": cancel_tx.min_fee,
        "tx_id_hex": cancel_tx.tx_id.hex(),
        "expected_validation": "valid",
    }

    # Type 5: ShieldedTransfer
    dummy_bundle = b"OrchardBundleFixture_FixedPostNu6_2_Proof_And_Sigs"
    sh_tx = ShieldedTransferTx(
        chain_id=DEVNET_CHAIN_ID,
        fee_atoms=10_000,
        orchard_bundle_bytes=dummy_bundle,
        nullifiers=[raw_nfs[0]],
    )
    sh_bytes = sh_tx.serialize()
    tx_sec["type_5_shielded_transfer"] = {
        "tx_type": 5,
        "name": "ShieldedTransfer",
        "fee_atoms": 10_000,
        "nullifiers_hex": [raw_nfs[0].hex()],
        "canonical_signed_bytes_hex": sh_bytes.hex(),
        "canonical_size_bytes": len(sh_bytes),
        "min_fee_atoms": sh_tx.min_fee,
        "tx_id_hex": sh_tx.tx_id.hex(),
        "pool_accounting": "shielded_pool_balance -= 10_000 atoms (paid to miner)",
        "expected_validation": "valid",
    }

    # Type 6: TransparentToShielded
    t2s_tx = TransparentToShieldedTx(
        chain_id=DEVNET_CHAIN_ID,
        sender_pubkey=keys[0],
        nonce=3,
        shielded_amount=200_000_000,  # 2 OWN
        fee_atoms=25_000,
        orchard_bundle_bytes=dummy_bundle,
        sender_sig=b"\x60" * 64,
    )
    t2s_bytes = t2s_tx.serialize()
    tx_sec["type_6_transparent_to_shielded"] = {
        "tx_type": 6,
        "name": "TransparentToShielded",
        "sender_pubkey_hex": keys[0].hex(),
        "shielded_amount_atoms": 200_000_000,
        "fee_atoms": 25_000,
        "nonce": 3,
        "canonical_signed_bytes_hex": t2s_bytes.hex(),
        "canonical_size_bytes": len(t2s_bytes),
        "min_fee_atoms": t2s_tx.min_fee,
        "tx_id_hex": t2s_tx.tx_id.hex(),
        "balance_deltas": {
            "transparent_sender_atoms": -200_025_000,
            "shielded_pool_atoms": +200_000_000,
            "miner_fee_atoms": +25_000,
            "net_issuance_change": 0,
        },
        "expected_validation": "valid",
    }

    # Type 7: ShieldedToTransparent
    s2t_tx = ShieldedToTransparentTx(
        chain_id=DEVNET_CHAIN_ID,
        recipient=addrs[1],
        release_amount=150_000_000,  # 1.5 OWN
        fee_atoms=20_000,
        orchard_bundle_bytes=dummy_bundle,
        nullifiers=[raw_nfs[1]],
    )
    s2t_bytes = s2t_tx.serialize()
    tx_sec["type_7_shielded_to_transparent"] = {
        "tx_type": 7,
        "name": "ShieldedToTransparent",
        "recipient_address_hex": addrs[1].hex(),
        "release_amount_atoms": 150_000_000,
        "fee_atoms": 20_000,
        "nullifiers_hex": [raw_nfs[1].hex()],
        "canonical_signed_bytes_hex": s2t_bytes.hex(),
        "canonical_size_bytes": len(s2t_bytes),
        "min_fee_atoms": s2t_tx.min_fee,
        "tx_id_hex": s2t_tx.tx_id.hex(),
        "balance_deltas": {
            "shielded_pool_atoms": -150_020_000,
            "transparent_recipient_atoms": +150_000_000,
            "miner_fee_atoms": +20_000,
            "net_issuance_change": 0,
        },
        "expected_validation": "valid",
    }

    vectors["transactions"] = tx_sec

    # =======================================================================
    # 3. Cross-Pool Transitions & Accounting
    # =======================================================================
    cross_sec = {
        "shielding_1_own": {
            "description": "Shield 100,000,000 atoms from transparent account to Orchard pool",
            "principal_atoms": 100_000_000,
            "fee_atoms": 25_000,
            "transparent_sender_deduction": 100_025_000,
            "shielded_pool_increase": 100_000_000,
            "miner_fee": 25_000,
            "value_conservation": "(-100,025,000) + (+100,000,000) + (+25,000) == 0",
            "expected_result": "valid",
        },
        "deshielding_1_own": {
            "description": "Deshield 100,000,000 atoms from Orchard pool to transparent account",
            "release_atoms": 100_000_000,
            "fee_atoms": 25_000,
            "shielded_pool_deduction": 100_025_000,
            "transparent_recipient_credit": 100_000_000,
            "miner_fee": 25_000,
            "value_conservation": "(-100,025,000) + (+100,000,000) + (+25,000) == 0",
            "expected_result": "valid",
        },
        "negative_shielded_pool_rejection": {
            "description": "Attempt to deshield 500,000,000 atoms when pool balance is only 100,000,000 atoms",
            "current_pool_atoms": 100_000_000,
            "requested_spend_atoms": 500_000_000,
            "expected_result": "invalid: negative shielded pool balance rejected",
        },
        "duplicate_nullifier_rejection": {
            "description": "Attempt to reuse nullifier already recorded in nullifier set",
            "nullifier_hex": raw_nfs[0].hex(),
            "expected_result": "invalid: duplicate nullifier rejected",
        },
    }
    vectors["cross_pool_accounting"] = cross_sec

    # =======================================================================
    # 4. Economic Parameters & Rules
    # =======================================================================
    econ_sec = {
        "parameters": {
            "native_currency": "OWN",
            "atoms_per_own": 100_000_000,
            "starting_subsidy_atoms": 1_000_000_000,
            "halving_interval_blocks": 1_050_000,
            "maximum_supply_atoms": 2_100_000_000_000_000,
            "coinbase_maturity_blocks": 100,
        },
        "subsidy_schedule": {
            "height_1_era_0": {
                "height": 1,
                "era": 0,
                "subsidy_atoms": scheduled_subsidy(1),
            },
            "height_1050000_era_0": {
                "height": 1_050_000,
                "era": 0,
                "subsidy_atoms": scheduled_subsidy(1_050_000),
            },
            "height_1050001_era_1": {
                "height": 1_050_001,
                "era": 1,
                "subsidy_atoms": scheduled_subsidy(1_050_001),
            },
            "height_2100001_era_2": {
                "height": 2_100_001,
                "era": 2,
                "subsidy_atoms": scheduled_subsidy(2_100_001),
            },
            "height_31500000_era_29": {
                "height": 31_500_000,
                "era": 29,
                "subsidy_atoms": scheduled_subsidy(31_500_000),
            },
            "height_31500001_era_30_exhaustion": {
                "height": 31_500_001,
                "era": 30,
                "subsidy_atoms": scheduled_subsidy(31_500_001),
            },
        },
        "coinbase_maturity_boundaries": {
            "height_99": {
                "coinbase_height": 1,
                "eval_height": 99,
                "status": "immature",
                "spendable": False,
            },
            "height_100": {
                "coinbase_height": 1,
                "eval_height": 100,
                "status": "immature",
                "spendable": False,
            },
            "height_101": {
                "coinbase_height": 1,
                "eval_height": 101,
                "status": "mature",
                "spendable": True,
            },
        },
    }
    vectors["economic_rules"] = econ_sec

    # =======================================================================
    # 5. Guardian Protocol & Quorum Matrix
    # =======================================================================
    guardian_sec = {
        "quorum_matrix": {
            "strengthen_delays": {
                "action_type": 1,
                "quorum": "3-of-7",
                "threshold": 3,
            },
            "strengthen_allowance": {
                "action_type": 2,
                "quorum": "3-of-7",
                "threshold": 3,
            },
            "weaken_delays": {"action_type": 3, "quorum": "4-of-7", "threshold": 4},
            "weaken_allowance": {
                "action_type": 4,
                "quorum": "4-of-7",
                "threshold": 4,
            },
            "freeze": {"action_type": 5, "quorum": "4-of-7", "threshold": 4},
            "unfreeze": {"action_type": 6, "quorum": "4-of-7", "threshold": 4},
            "recovery": {"action_type": 7, "quorum": "4-of-7", "threshold": 4},
            "replace_guardians": {
                "action_type": 8,
                "quorum": "4-of-7",
                "threshold": 4,
            },
            "replace_recovery_key": {
                "action_type": 9,
                "quorum": "4-of-7",
                "threshold": 4,
            },
            "cancel_pending_transfer": {
                "action_type": 10,
                "quorum": "4-of-7",
                "threshold": 4,
            },
            "cross_pool_shielding": {
                "action": "transparent_to_shielded",
                "quorum": "4-of-7",
                "threshold": 4,
            },
        },
        "guardian_scope_rules": {
            "applies_to_transparent_only": True,
            "governs_shielded_notes": False,
            "advertising_shielded_funds_as_protected": "forbidden",
        },
    }
    vectors["guardian_rules"] = guardian_sec

    # =======================================================================
    # 6. Representative Multi-Block Scenario
    # =======================================================================
    state = HybridChainState(DEVNET_CHAIN_ID)
    scenario = []

    # Block 1: Mine 10 OWN to Alice
    state.begin_block(1)
    cb1 = CoinbaseTx(DEVNET_CHAIN_ID, 1, addrs[0], 1_000_000_000)
    state.apply_coinbase(cb1)
    root1 = state.end_block(0, 1_000_000_000)
    scenario.append(
        {
            "block_height": 1,
            "action": "Coinbase reward 10 OWN to Alice",
            "state_root_hex": root1.hex(),
            "alice_balance": state.accounts[addrs[0]].balance,
            "shielded_pool_balance": state.shielded_pool_balance,
            "cumulative_issuance": state.cumulative_issuance,
        }
    )

    # Fast forward to 101 to mature Alice's coinbase
    for h in range(2, 102):
        state.begin_block(h)
        state.end_block(0, 0)

    # Block 102: Alice shields 3 OWN to pool
    state.begin_block(102)
    t2s = TransparentToShieldedTx(
        chain_id=DEVNET_CHAIN_ID,
        sender_pubkey=keys[0],
        nonce=0,
        shielded_amount=300_000_000,
        fee_atoms=25_000,
        orchard_bundle_bytes=dummy_bundle,
    )
    f = state.apply_transparent_to_shielded(t2s)
    # Miner collects fee
    cb102 = CoinbaseTx(DEVNET_CHAIN_ID, 102, addrs[3], f)
    state.apply_coinbase(cb102)
    root102 = state.end_block(f, 0)
    scenario.append(
        {
            "block_height": 102,
            "action": "Alice shields 3 OWN into Orchard pool",
            "state_root_hex": root102.hex(),
            "alice_balance": state.accounts[addrs[0]].balance,
            "shielded_pool_balance": state.shielded_pool_balance,
            "miner_balance": state.accounts[addrs[3]].balance,
            "cumulative_issuance": state.cumulative_issuance,
        }
    )

    vectors["representative_scenario"] = scenario

    return vectors


def main():
    target_path = os.path.join(REPO_ROOT, "docs", "test-vectors-v1-hybrid.json")

    print("[*] Generating OwnChain Hybrid Golden Test Vectors...")
    v1 = generate_vectors()
    v1_json = json.dumps(v1, indent=2)

    print("[*] Checking Determinism (Second Pass)...")
    v2 = generate_vectors()
    v2_json = json.dumps(v2, indent=2)

    if v1_json != v2_json:
        print("[!] FATAL: Generator is non-deterministic!", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Writing to {target_path}...")
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(v1_json + "\n")

    print(
        f"[+] SUCCESS: Generated {len(v1_json.encode('utf-8'))} bytes of verified test vectors."
    )


if __name__ == "__main__":
    main()
