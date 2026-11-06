"""
Cross-pool state-transition accounting, golden vector and invariant tests.
"""

import struct
import pytest

from refmodel.hybrid_state import HybridChainState, HybridStateError
from refmodel.merkle import (
    composite_state_root,
    nullifier_merkle_root,
    pool_balance_commitment,
)
from refmodel.transactions import (
    CoinbaseTx,
    DOM_ACTION_EFFECT,
    DOM_CROSS_POOL_AUTH,
    ORCHARD_EMPTY_ROOT_BYTES,
    ShieldedToTransparentTx,
    TransparentToShieldedTx,
    compute_action_effect,
    compute_type6_cross_pool_auth_digest,
    compute_type7_cross_pool_auth_digest,
    derive_address,
)

# ---------------------------------------------------------------------------
# Golden vector constants
# ---------------------------------------------------------------------------
EXPECTED_ACTION_EFFECT_HEX = (
    "1b1b02fdc6388ebcd76e37710d9879860de9f07ff0c877fa449bb17c5551f1cb"
)
EXPECTED_T6_AUTH_DIGEST_HEX = (
    "feaa48b99f8f8d1366c0e6f6fb4d8cd1e65a00506462e79dae320ae5a10932ea"
)
EXPECTED_T7_AUTH_DIGEST_HEX = (
    "d28409db4954b2eb942edc23bc211036ec399c412f97acc226df68c604ec11ef"
)


def test_action_effect_digest_golden():
    cv_net = b"\x11" * 32
    nf = b"\x22" * 32
    rk = b"\x33" * 32
    cmx = b"\x44" * 32
    epk = b"\x55" * 32
    enc = b"\x66" * 580
    out = b"\x77" * 80

    effect = compute_action_effect(cv_net, nf, rk, cmx, epk, enc, out)
    assert effect.hex() == EXPECTED_ACTION_EFFECT_HEX


def test_type6_cross_pool_auth_digest_golden():
    chain_id = b"\xaa" * 32
    sender_pub = b"\xbb" * 32
    effect1 = bytes.fromhex(EXPECTED_ACTION_EFFECT_HEX)

    t6_digest = compute_type6_cross_pool_auth_digest(
        chain_id=chain_id,
        tx_version=1,
        sender_pubkey=sender_pub,
        nonce=7,
        shielded_amount=100_000_000,
        fee_atoms=25_000,
        bundle_flag_byte=2,
        bundle_value_balance=-100_000_000,
        bundle_anchor=ORCHARD_EMPTY_ROOT_BYTES,
        action_effects=[effect1],
    )
    assert t6_digest.hex() == EXPECTED_T6_AUTH_DIGEST_HEX


def test_type7_cross_pool_auth_digest_golden():
    chain_id = b"\xaa" * 32
    recipient = b"\xcc" * 32
    effect1 = bytes.fromhex(EXPECTED_ACTION_EFFECT_HEX)
    effect2 = compute_action_effect(
        b"\x12" * 32,
        b"\x23" * 32,
        b"\x34" * 32,
        b"\x45" * 32,
        b"\x56" * 32,
        b"\x67" * 580,
        b"\x78" * 80,
    )

    t7_digest = compute_type7_cross_pool_auth_digest(
        chain_id=chain_id,
        tx_version=1,
        recipient=recipient,
        release_amount=60_000_000,
        fee_atoms=50_000,
        bundle_flag_byte=3,
        bundle_value_balance=60_050_000,
        bundle_anchor=b"\xdd" * 32,
        action_effects=[effect1, effect2],
    )
    assert t7_digest.hex() == EXPECTED_T7_AUTH_DIGEST_HEX


def test_cross_pool_multi_block_state_transition_and_golden_roots():
    chain_id = b"\x42" * 32
    state = HybridChainState(chain_id=chain_id)

    # Initialize Alice with 1,000,000,000 atoms at height 100
    alice_pub = b"\x01" * 32
    alice_addr = derive_address(alice_pub)
    alice = state.get_or_create_account(alice_addr)
    alice.balance = 1_000_000_000
    state.cumulative_issuance = 1_000_000_000
    state.height = 100
    state.historical_anchors[100] = ORCHARD_EMPTY_ROOT_BYTES

    # Verify initial conservation
    state.verify_global_invariant()
    assert state.shielded_pool_balance == 0
    assert len(state.nullifier_set) == 0

    # -----------------------------------------------------------------------
    # Block 101: Alice shields 200M atoms via Type 6
    # -----------------------------------------------------------------------
    state.begin_block(101)
    miner_addr = derive_address(b"\x99" * 32)
    nf1 = b"\x11" * 32

    t6 = TransparentToShieldedTx(
        chain_id=chain_id,
        sender_pubkey=alice_pub,
        nonce=0,
        shielded_amount=200_000_000,
        fee_atoms=30_000,
        orchard_bundle_bytes=b"\x00" * 100,
        nullifiers=[nf1],
    )
    fee1 = state.apply_transparent_to_shielded(t6)
    assert fee1 == 30_000

    # Apply coinbase for block 101 (collects fee)
    cb1 = CoinbaseTx(chain_id, 101, miner_addr, fee1)
    state.apply_coinbase(cb1)
    root1 = state.end_block(block_fee_collected=fee1, actual_subsidy_claimed=0)

    # Invariant and balance checks for Block 101
    state.verify_global_invariant()
    assert alice.balance == 1_000_000_000 - (200_000_000 + 30_000)  # 799,970,000
    assert alice.nonce == 1
    assert state.shielded_pool_balance == 200_000_000
    miner = state.get_or_create_account(miner_addr)
    assert miner.balance == 30_000
    assert nf1 in state.nullifier_set

    # Verify component roots at Block 101
    nf_root_101 = state.compute_nullifier_root()
    pool_comm_101 = state.compute_pool_commitment()
    assert pool_comm_101 == pool_balance_commitment(200_000_000)
    assert nf_root_101 == nullifier_merkle_root([nf1])
    assert root1 == state.compute_composite_state_root()

    # -----------------------------------------------------------------------
    # Block 102: Shielded funds exit to Bob via Type 7
    # -----------------------------------------------------------------------
    state.begin_block(102)
    bob_addr = derive_address(b"\x02" * 32)
    nf2 = b"\x22" * 32

    t7 = ShieldedToTransparentTx(
        chain_id=chain_id,
        recipient=bob_addr,
        release_amount=70_000_000,
        fee_atoms=30_000,
        orchard_bundle_bytes=b"\x00" * 100,
        nullifiers=[nf2],
        anchor=ORCHARD_EMPTY_ROOT_BYTES,
    )
    fee2 = state.apply_shielded_to_transparent(t7)
    assert fee2 == 30_000

    cb2 = CoinbaseTx(chain_id, 102, miner_addr, fee2)
    state.apply_coinbase(cb2)
    root2 = state.end_block(block_fee_collected=fee2, actual_subsidy_claimed=0)

    # Invariant and balance checks for Block 102
    state.verify_global_invariant()
    bob = state.get_or_create_account(bob_addr)
    assert bob.balance == 70_000_000
    assert state.shielded_pool_balance == 200_000_000 - (70_000_000 + 30_000)  # 129,970,000
    assert miner.balance == 30_000 + 30_000  # 60,000
    assert nf2 in state.nullifier_set
    assert len(state.nullifier_set) == 2

    # Verify sorted nullifier root
    sorted_nfs = sorted([nf1, nf2])
    assert state.compute_nullifier_root() == nullifier_merkle_root(sorted_nfs)
    assert state.compute_pool_commitment() == pool_balance_commitment(129_970_000)

    # -----------------------------------------------------------------------
    # Negative Test: Replay of Type 6 nullifier nf1 must fail
    # -----------------------------------------------------------------------
    state.begin_block(103)
    t6_replay = TransparentToShieldedTx(
        chain_id=chain_id,
        sender_pubkey=alice_pub,
        nonce=1,
        shielded_amount=50_000_000,
        fee_atoms=30_000,
        orchard_bundle_bytes=b"\x00" * 100,
        nullifiers=[nf1],  # Already consumed in Block 101!
    )
    with pytest.raises(HybridStateError, match="Duplicate nullifier"):
        state.apply_transparent_to_shielded(t6_replay)

    # -----------------------------------------------------------------------
    # Negative Test: Replay of Type 7 nullifier nf2 must fail
    # -----------------------------------------------------------------------
    t7_replay = ShieldedToTransparentTx(
        chain_id=chain_id,
        recipient=bob_addr,
        release_amount=20_000_000,
        fee_atoms=25_000,
        orchard_bundle_bytes=b"\x00" * 100,
        nullifiers=[nf2],  # Already consumed in Block 102!
        anchor=ORCHARD_EMPTY_ROOT_BYTES,
    )
    with pytest.raises(HybridStateError, match="Duplicate nullifier"):
        state.apply_shielded_to_transparent(t7_replay)
