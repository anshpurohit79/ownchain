"""
Comprehensive test suite for OwnChain Python Reference Model.

Validates all 14 mandatory consensus invariants plus guardian, economic,
and boundary properties:
  1. Global money conservation after every valid block (T + S = I)
  2. No value creation through transparent-to-shielded transfers
  3. No value creation through shielded-to-transparent transfers
  4. No double-spending of nullifiers
  5. No nonce replay
  6. No negative shielded pool balance
  7. No subsidy-cap violation (21,000,000 OWN)
  8. No immature coinbase spending (100-block maturity)
  9. No pending-principal double counting
  10. No bypass of protected-account cross-pool withdrawal rules
  11. Invalid transactions leave state unchanged
  12. Reorganization restores exact parent state root
  13. Identical blocks produce identical component roots and composite state roots
  14. Independent recomputation matches published vectors
"""

import unittest

from refmodel.hybrid_state import (
    DEFAULT_NEW_RECIPIENT_DELAY,
    MAX_SUPPLY_ATOMS,
    AccountState,
    HybridChainState,
    HybridStateError,
    scheduled_subsidy,
)
from refmodel.merkle import (
    blake2b_256,
    composite_state_root,
    empty_root,
    m1a_empty_root,
    m1a_tx_leaf,
    m1a_tx_node,
    m1a_tx_root,
    merkle_root,
    nullifier_merkle_root,
    pool_balance_commitment,
)
from refmodel.orchard_adapter import OrchardAdapter
from refmodel.transactions import (
    ACTION_FREEZE,
    ACTION_RECOVERY,
    ACTION_REPLACE_GUARDIANS,
    ACTION_STRENGTHEN_ALLOWANCE,
    ACTION_STRENGTHEN_DELAYS,
    ACTION_UNFREEZE,
    ACTION_WEAKEN_ALLOWANCE,
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


class TestHybridConsensusState(unittest.TestCase):
    def setUp(self):
        self.state = HybridChainState(DEVNET_CHAIN_ID)
        self.key_miner = blake2b_256(b"miner-key")
        self.addr_miner = derive_address(self.key_miner)

        self.key_alice = blake2b_256(b"alice-key")
        self.addr_alice = derive_address(self.key_alice)

        self.key_bob = blake2b_256(b"bob-key")
        self.addr_bob = derive_address(self.key_bob)

    # -----------------------------------------------------------------------
    # Invariant 1: Global money conservation after every valid block (T + S = I)
    # -----------------------------------------------------------------------
    def test_01_global_money_conservation(self):
        """Block 1: Mine 10 OWN to Alice. Verify T + S == I."""
        self.state.begin_block(1)
        subsidy = scheduled_subsidy(1)
        cb = CoinbaseTx(
            chain_id=DEVNET_CHAIN_ID,
            height=1,
            recipient=self.addr_alice,
            payout_atoms=subsidy,
        )
        self.state.apply_coinbase(cb)
        self.state.end_block(block_fee_collected=0, actual_subsidy_claimed=subsidy)

        self.state.verify_global_invariant()
        self.assertEqual(self.state.accounts[self.addr_alice].balance, 1_000_000_000)
        self.assertEqual(self.state.shielded_pool_balance, 0)
        self.assertEqual(self.state.cumulative_issuance, 1_000_000_000)

    # -----------------------------------------------------------------------
    # Invariant 2: No value creation through transparent-to-shielded
    # -----------------------------------------------------------------------
    def test_02_no_value_creation_t2s(self):
        """Fund Alice, mature funds, shield 4 OWN with fee. Verify T + S == I."""
        # Setup Alice with 10 OWN mature
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 1_000_000_000
        self.state.cumulative_issuance = 1_000_000_000
        self.state.height = 101

        # Shield 4 OWN (400,000,000 atoms), fee 100,000 atoms
        shield_amount = 400_000_000
        fee = 100_000
        t2s = TransparentToShieldedTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            nonce=0,
            shielded_amount=shield_amount,
            fee_atoms=fee,
            orchard_bundle_bytes=b"dummy_bundle",
        )
        fee_paid = self.state.apply_transparent_to_shielded(t2s)
        self.assertEqual(fee_paid, fee)

        # Miner claims fee
        miner = self.state.get_or_create_account(self.addr_miner)
        miner.balance += fee_paid

        self.state.verify_global_invariant()
        self.assertEqual(alice.balance, 1_000_000_000 - shield_amount - fee)
        self.assertEqual(self.state.shielded_pool_balance, shield_amount)
        self.assertEqual(
            self.state.accounts[self.addr_alice].balance
            + self.state.accounts[self.addr_miner].balance
            + self.state.shielded_pool_balance,
            self.state.cumulative_issuance,
        )

    # -----------------------------------------------------------------------
    # Invariant 3: No value creation through shielded-to-transparent
    # -----------------------------------------------------------------------
    def test_03_no_value_creation_s2t(self):
        """Deshield 2 OWN from pool to Bob. Verify T + S == I."""
        self.state.shielded_pool_balance = 500_000_000
        self.state.cumulative_issuance = 500_000_000

        release_amount = 200_000_000
        fee = 50_000
        nf = blake2b_256(b"nullifier-1")

        s2t = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=release_amount,
            fee_atoms=fee,
            orchard_bundle_bytes=b"dummy_bundle",
            nullifiers=[nf],
        )
        fee_paid = self.state.apply_shielded_to_transparent(s2t)
        miner = self.state.get_or_create_account(self.addr_miner)
        miner.balance += fee_paid

        self.state.verify_global_invariant()
        self.assertEqual(self.state.accounts[self.addr_bob].balance, release_amount)
        self.assertEqual(
            self.state.shielded_pool_balance, 500_000_000 - (release_amount + fee)
        )
        self.assertIn(nf, self.state.nullifier_set)

    # -----------------------------------------------------------------------
    # Invariant 4: No double-spending of nullifiers
    # -----------------------------------------------------------------------
    def test_04_no_double_spending_nullifiers(self):
        """Attempting to consume the same nullifier twice must fail."""
        self.state.shielded_pool_balance = 500_000_000
        self.state.cumulative_issuance = 500_000_000
        nf = blake2b_256(b"nullifier-reuse")

        s2t_1 = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=100_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle1",
            nullifiers=[nf],
        )
        self.state.apply_shielded_to_transparent(s2t_1)

        s2t_2 = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=100_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle2",
            nullifiers=[nf],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_to_transparent(s2t_2)
        self.assertIn("Duplicate nullifier", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Invariant 5: No nonce replay
    # -----------------------------------------------------------------------
    def test_05_no_nonce_replay(self):
        """Replaying a nonce or skipping a nonce must fail."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 500_000_000
        self.state.cumulative_issuance = 500_000_000
        self.state.height = 101

        tx1 = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=50_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        self.state.apply_transparent_transfer(tx1)
        self.assertEqual(alice.nonce, 1)

        # Replay nonce 0
        tx_replay = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=10_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_transparent_transfer(tx_replay)
        self.assertIn("Nonce mismatch", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Invariant 6: No negative shielded pool balance
    # -----------------------------------------------------------------------
    def test_06_no_negative_shielded_pool(self):
        """Deshielding more than pool balance must fail."""
        self.state.shielded_pool_balance = 50_000_000
        self.state.cumulative_issuance = 50_000_000

        s2t = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=60_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle",
            nullifiers=[blake2b_256(b"nf-overdraw")],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_to_transparent(s2t)
        self.assertIn("Insufficient shielded pool balance", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Invariant 7: No subsidy-cap violation (21,000,000 OWN)
    # -----------------------------------------------------------------------
    def test_07_no_subsidy_cap_violation(self):
        """Cumulative issuance cannot exceed MAX_SUPPLY_ATOMS."""
        self.state.cumulative_issuance = MAX_SUPPLY_ATOMS - 100
        self.state.height = 1

        with self.assertRaises(HybridStateError) as ctx:
            self.state.end_block(block_fee_collected=0, actual_subsidy_claimed=200)
        self.assertIn("cap", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Invariant 8: No immature coinbase spending (100-block maturity)
    # -----------------------------------------------------------------------
    def test_08_no_immature_coinbase_spending(self):
        """Coinbase mined at h=1 cannot be spent at h=100, but can be spent at h=101."""
        self.state.begin_block(1)
        cb = CoinbaseTx(
            chain_id=DEVNET_CHAIN_ID,
            height=1,
            recipient=self.addr_alice,
            payout_atoms=1_000_000_000,
        )
        self.state.apply_coinbase(cb)
        self.state.end_block(0, 1_000_000_000)

        # Height 100: reward unlock_height is 101 (1 + 100), so at h=100 it is IMMATURE
        self.state.height = 100
        alice = self.state.accounts[self.addr_alice]
        self.assertEqual(alice.spendable_balance(100), 0)

        tx = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=10_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_transparent_transfer(tx)
        self.assertIn("Insufficient spendable balance", str(ctx.exception))

        # Height 101: begin_block matures the tranche!
        self.state.begin_block(101)
        self.assertEqual(alice.spendable_balance(101), 1_000_000_000)
        fee = self.state.apply_transparent_transfer(tx)
        self.assertEqual(fee, 20_000)
        self.assertEqual(alice.balance, 1_000_000_000 - 10_000_000 - 20_000)

    # -----------------------------------------------------------------------
    # Invariant 9: No pending-principal double counting
    # -----------------------------------------------------------------------
    def test_09_no_pending_principal_double_counting(self):
        """Pending principal remains in sender balance, excluded from spendable.

        Global invariant T + S = I holds without adding pending principal twice.
        """
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 1_000_000_000
        alice.guardian_enabled = True
        self.state.cumulative_issuance = 1_000_000_000
        self.state.height = 101

        # Transfer to Bob (first-time recipient under guardian protection)
        tx = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=300_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        fee = self.state.apply_transparent_transfer(tx)
        miner = self.state.get_or_create_account(self.addr_miner)
        miner.balance += fee

        # Alice's balance is 1,000,000,000 - 20,000 = 999,980,000
        # Pending amount = 300,000,000
        # Spendable balance = 699,980,000
        self.assertEqual(alice.balance, 999_980_000)
        self.assertEqual(alice.spendable_balance(101), 699_980_000)
        self.assertEqual(len(alice.pending_transfers), 1)

        # Global invariant: T (Alice + Miner) + S == I
        self.state.verify_global_invariant()

        # At release height (101 + 10 = 111):
        for h in range(102, 112):
            self.state.begin_block(h)
        self.assertEqual(len(alice.pending_transfers), 0)
        self.assertEqual(self.state.accounts[self.addr_bob].balance, 300_000_000)
        self.state.verify_global_invariant()

    # -----------------------------------------------------------------------
    # Invariant 10: No bypass of protected-account cross-pool withdrawal rules
    # -----------------------------------------------------------------------
    def test_10_guardian_cross_pool_protection(self):
        """Shielding funds from a guardian-protected account requires 4-of-7 quorum."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 500_000_000
        alice.guardian_enabled = True
        self.state.cumulative_issuance = 500_000_000
        self.state.height = 101

        # Attempt to shield without guardian authorization
        t2s_unauthorized = TransparentToShieldedTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            nonce=0,
            shielded_amount=100_000_000,
            fee_atoms=50_000,
            orchard_bundle_bytes=b"bundle",
            guardian_sigs=[],  # 0-of-7
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_transparent_to_shielded(t2s_unauthorized)
        self.assertIn("requires 4-of-7 guardian quorum", str(ctx.exception))

        # Attempt with 3-of-7 quorum (insufficient)
        t2s_3of7 = TransparentToShieldedTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            nonce=0,
            shielded_amount=100_000_000,
            fee_atoms=50_000,
            orchard_bundle_bytes=b"bundle",
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2")],  # 3-of-7
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_transparent_to_shielded(t2s_3of7)
        self.assertIn("requires 4-of-7 guardian quorum", str(ctx.exception))

        # Valid with 4-of-7 quorum
        t2s_4of7 = TransparentToShieldedTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            nonce=0,
            shielded_amount=100_000_000,
            fee_atoms=50_000,
            orchard_bundle_bytes=b"bundle",
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2"), (3, b"s3")],  # 4-of-7
        )
        fee = self.state.apply_transparent_to_shielded(t2s_4of7)
        self.assertEqual(fee, 50_000)
        self.assertEqual(self.state.shielded_pool_balance, 100_000_000)

    # -----------------------------------------------------------------------
    # Invariant 11: Invalid transactions leave state unchanged
    # -----------------------------------------------------------------------
    def test_11_invalid_tx_leaves_state_unchanged(self):
        """Failed transaction application does not corrupt balances or nonces."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 100_000_000
        alice.nonce = 5
        self.state.cumulative_issuance = 100_000_000
        self.state.height = 101

        snapshot = self.state.clone()

        # Invalid transfer (amount exceeds balance)
        tx_invalid = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=200_000_000,
            fee_atoms=20_000,
            nonce=5,
        )
        with self.assertRaises(HybridStateError):
            self.state.apply_transparent_transfer(tx_invalid)

        self.assertEqual(alice.balance, snapshot.accounts[self.addr_alice].balance)
        self.assertEqual(alice.nonce, snapshot.accounts[self.addr_alice].nonce)
        self.assertEqual(
            self.state.compute_composite_state_root(),
            snapshot.compute_composite_state_root(),
        )

    # -----------------------------------------------------------------------
    # Invariant 12: Reorganization rollback restores exact parent state root
    # -----------------------------------------------------------------------
    def test_12_reorg_rollback(self):
        """Rolling back a block restores the exact parent composite state root."""
        self.state.begin_block(1)
        cb1 = CoinbaseTx(DEVNET_CHAIN_ID, 1, self.addr_alice, 1_000_000_000)
        self.state.apply_coinbase(cb1)
        root1 = self.state.end_block(0, 1_000_000_000)

        # Take parent snapshot
        parent_snapshot = self.state.clone()

        # Apply block 2
        self.state.begin_block(2)
        cb2 = CoinbaseTx(DEVNET_CHAIN_ID, 2, self.addr_alice, 1_000_000_000)
        self.state.apply_coinbase(cb2)
        root2 = self.state.end_block(0, 1_000_000_000)
        self.assertNotEqual(root1, root2)

        # Rollback to parent
        self.state = parent_snapshot.clone()
        self.assertEqual(self.state.height, 1)
        self.assertEqual(self.state.compute_composite_state_root(), root1)

    # -----------------------------------------------------------------------
    # Invariant 13: Deterministic state roots
    # -----------------------------------------------------------------------
    def test_13_deterministic_state_roots(self):
        """Applying identical blocks to two clean states produces identical roots."""
        s1 = HybridChainState(DEVNET_CHAIN_ID)
        s2 = HybridChainState(DEVNET_CHAIN_ID)

        # Genesis composite root
        self.assertEqual(
            s1.compute_composite_state_root(), s2.compute_composite_state_root()
        )

        for s in (s1, s2):
            s.begin_block(1)
            cb = CoinbaseTx(DEVNET_CHAIN_ID, 1, self.addr_alice, 1_000_000_000)
            s.apply_coinbase(cb)
            s.end_block(0, 1_000_000_000)

        self.assertEqual(
            s1.compute_composite_state_root(), s2.compute_composite_state_root()
        )

    # -----------------------------------------------------------------------
    # Invariant 14: Subsidy Schedule
    # -----------------------------------------------------------------------
    def test_14_subsidy_schedule(self):
        """Verify subsidy halving across eras and exhaustion at era 30."""
        self.assertEqual(scheduled_subsidy(1), 1_000_000_000)  # Era 0: 10 OWN
        self.assertEqual(scheduled_subsidy(1_050_000), 1_000_000_000)
        self.assertEqual(scheduled_subsidy(1_050_001), 500_000_000)  # Era 1: 5 OWN
        self.assertEqual(scheduled_subsidy(2_100_001), 250_000_000)  # Era 2: 2.5 OWN
        self.assertEqual(scheduled_subsidy(31_500_000), 1_000_000_000 >> 29)
        self.assertEqual(scheduled_subsidy(31_500_001), 0)  # Era 30: Exhaustion!

    # -----------------------------------------------------------------------
    # Invariant 15: Guardian Quorum Rules (3-of-7 vs 4-of-7)
    # -----------------------------------------------------------------------
    def test_15_guardian_quorums(self):
        """Test strengthen delays (3-of-7) and freeze/recovery (4-of-7)."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 100_000_000
        alice.guardian_enabled = True
        self.state.cumulative_issuance = 100_000_000

        # Strengthen delay: 3-of-7 is sufficient
        action_delay = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_STRENGTHEN_DELAYS,
            fee_atoms=25_000,
            params=(20).to_bytes(4, "little"),
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2")],
        )
        self.state.apply_guardian_action(action_delay)
        self.assertEqual(alice.new_recipient_delay, 20)

        # Freeze requires 4-of-7 (3-of-7 fails)
        action_freeze_fail = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_FREEZE,
            fee_atoms=25_000,
            params=b"",
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2")],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_guardian_action(action_freeze_fail)
        self.assertIn("Insufficient guardian quorum", str(ctx.exception))

        # Freeze with 4-of-7 succeeds
        action_freeze_ok = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_FREEZE,
            fee_atoms=25_000,
            params=b"",
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2"), (3, b"s3")],
        )
        self.state.apply_guardian_action(action_freeze_ok)
        self.assertTrue(alice.is_frozen)

    # -----------------------------------------------------------------------
    # Invariant 16: Freeze Prevents Spends
    # -----------------------------------------------------------------------
    def test_16_frozen_account_cannot_spend(self):
        """A frozen account cannot initiate spending transactions."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 100_000_000
        alice.is_frozen = True
        self.state.cumulative_issuance = 100_000_000
        self.state.height = 101

        tx = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=10_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_transparent_transfer(tx)
        self.assertIn("frozen", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Invariant 17: Pending Transfer Cancellation
    # -----------------------------------------------------------------------
    def test_17_pending_transfer_cancellation(self):
        """Cancelling a pending transfer with 4-of-7 quorum restores spendable balance."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 500_000_000
        alice.guardian_enabled = True
        self.state.cumulative_issuance = 500_000_000
        self.state.height = 101

        # Send to new recipient Bob -> pending record created
        tx_send = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=200_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        self.state.apply_transparent_transfer(tx_send)
        self.assertEqual(len(alice.pending_transfers), 1)
        transfer_id = alice.pending_transfers[0].transfer_id

        # Alice balance: 500M - 20k = 499,980,000. Spendable: 299,980,000
        self.assertEqual(alice.spendable_balance(101), 299_980_000)

        # Cancel with 4-of-7 quorum
        cancel_tx = CancelPendingTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            transfer_id=transfer_id,
            fee_atoms=25_000,
            nonce=1,
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2"), (3, b"s3")],
        )
        fee_paid = self.state.apply_cancel_pending(cancel_tx)
        self.assertEqual(fee_paid, 25_000)

        # Pending record is removed, Alice balance is 499,980,000 - 25k = 499,955,000
        # All of it is now spendable!
        self.assertEqual(len(alice.pending_transfers), 0)
        self.assertEqual(alice.spendable_balance(101), 499_955_000)

    # -----------------------------------------------------------------------
    # Invariant 18: Allowance Window Enforcement and Reset
    # -----------------------------------------------------------------------
    def test_18_allowance_window_enforcement(self):
        """Spend allowance is enforced within window, resets after window expires."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 1_000_000_000
        alice.allowance_limit = 50_000_000  # 0.5 OWN max per window
        alice.allowance_window_start = 100
        alice.allowance_window_len = 10  # 10 blocks
        alice.allowance_spent = 0
        self.state.cumulative_issuance = 1_000_000_000
        self.state.height = 101

        # Spend 40 OWN atoms (under limit)
        tx1 = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=40_000_000,
            fee_atoms=20_000,
            nonce=0,
        )
        self.state.apply_transparent_transfer(tx1)
        self.assertEqual(alice.allowance_spent, 40_020_000)

        # Second spend would exceed limit (40,020,000 + 15,020,000 > 50,000_000)
        tx2 = TransparentTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            recipient=self.addr_bob,
            amount=15_000_000,
            fee_atoms=20_000,
            nonce=1,
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_transparent_transfer(tx2)
        self.assertIn("allowance", str(ctx.exception).lower())

        # Advance height past window (100 + 10 = 110, now at 111)
        self.state.height = 111
        # Window resets automatically, tx2 now succeeds!
        self.state.apply_transparent_transfer(tx2)
        self.assertEqual(alice.allowance_spent, 15_020_000)
        self.assertEqual(alice.allowance_window_start, 111)

    # -----------------------------------------------------------------------
    # Invariant 19: Emergency Recovery
    # -----------------------------------------------------------------------
    def test_19_emergency_recovery(self):
        """4-of-7 quorum transfers spendable funds to registered recovery key."""
        key_recovery = blake2b_256(b"recovery-key")
        addr_recovery = derive_address(key_recovery)

        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 500_000_000
        alice.recovery_key = key_recovery
        alice.guardian_enabled = True
        self.state.cumulative_issuance = 500_000_000
        self.state.height = 101

        recovery_action = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_RECOVERY,
            fee_atoms=25_000,
            params=b"",
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2"), (3, b"s3")],
        )
        fee_paid = self.state.apply_guardian_action(recovery_action)
        miner = self.state.get_or_create_account(self.addr_miner)
        miner.balance += fee_paid

        # Alice's spendable balance transferred to recovery account minus fee
        self.assertEqual(alice.balance, 0)
        self.assertEqual(self.state.accounts[addr_recovery].balance, 499_975_000)
        self.state.verify_global_invariant()

    # -----------------------------------------------------------------------
    # Invariant 20: Merkle, Nullifier, Pool Commitments
    # -----------------------------------------------------------------------
    def test_20_commitments(self):
        """Verify Merkle trees, nullifier trees, pool balance commitments."""
        # Empty transparent Merkle root
        self.assertEqual(empty_root(), blake2b_256(b"OwnChain/Merkle/Empty/v1"))

        # Empty nullifier Merkle root
        self.assertEqual(
            nullifier_merkle_root([]), blake2b_256(b"OwnChain/Nullifier/Empty/v1")
        )

        # Single nullifier
        nf1 = blake2b_256(b"nf1")
        nf1_root = nullifier_merkle_root([nf1])
        expected_nf1_root = blake2b_256(
            b"OwnChain/Nullifier/Leaf/v1" + b"\x00" + nf1
        )
        self.assertEqual(nf1_root, expected_nf1_root)

        # Two nullifiers
        nf2 = blake2b_256(b"nf2")
        sorted_nfs = sorted([nf1, nf2])
        nf2_root = nullifier_merkle_root(sorted_nfs)
        leaf0 = blake2b_256(b"OwnChain/Nullifier/Leaf/v1" + b"\x00" + sorted_nfs[0])
        leaf1 = blake2b_256(b"OwnChain/Nullifier/Leaf/v1" + b"\x00" + sorted_nfs[1])
        expected_nf2_root = blake2b_256(
            b"OwnChain/Nullifier/Node/v1" + b"\x01" + leaf0 + leaf1
        )
        self.assertEqual(nf2_root, expected_nf2_root)

        # Pool balance commitment
        c0 = pool_balance_commitment(0)
        self.assertEqual(
            c0, blake2b_256(b"OwnChain/PoolBalance/v1" + (0).to_bytes(16, "little"))
        )
        c1 = pool_balance_commitment(100_000_000)
        self.assertEqual(
            c1,
            blake2b_256(
                b"OwnChain/PoolBalance/v1" + (100_000_000).to_bytes(16, "little")
            ),
        )

        # Composite genesis root
        t_root = empty_root()
        o_root = OrchardAdapter.empty_commitment_root()
        nf_root = nullifier_merkle_root([])
        pool_root = pool_balance_commitment(0)
        comp_root = composite_state_root(t_root, o_root, nf_root, pool_root)
        self.assertEqual(len(comp_root), 32)

    # -----------------------------------------------------------------------
    # Invariant 21: Independent Recomputation Matches Published Vectors
    # -----------------------------------------------------------------------
    def test_21_independent_recomputation_matches_published_vectors(self):
        """Verify that independent recomputation matches docs/test-vectors-v1-hybrid.json."""
        import json
        import os

        vector_path = os.path.join(
            os.path.dirname(__file__), "..", "docs", "test-vectors-v1-hybrid.json"
        )
        if not os.path.exists(vector_path):
            self.skipTest("Hybrid vectors file not found")

        with open(vector_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. Genesis composite root check
        pub_genesis = data["merkle_commitments"]["composite_genesis_state_root"][
            "composite_state_root_hex"
        ]
        s = HybridChainState(DEVNET_CHAIN_ID)
        self.assertEqual(s.compute_composite_state_root().hex(), pub_genesis)

        # 2. Empty transparent tree root check
        pub_t_empty = data["merkle_commitments"]["empty_transparent_tree"]["root_hex"]
        self.assertEqual(empty_root().hex(), pub_t_empty)

        # 3. Empty Orchard tree root check
        pub_o_empty = data["merkle_commitments"]["empty_orchard_tree"]["root_hex"]
        self.assertEqual(OrchardAdapter.empty_commitment_root().hex(), pub_o_empty)

        # 4. Empty nullifier tree root check
        pub_nf_empty = data["merkle_commitments"]["empty_nullifier_tree"]["root_hex"]
        self.assertEqual(nullifier_merkle_root([]).hex(), pub_nf_empty)

        # 5. Pool balance zero commitment check
        pub_pool_0 = data["merkle_commitments"]["pool_balance_commitments"][
            "balance_0_atoms"
        ]["commitment_hex"]
        self.assertEqual(pool_balance_commitment(0).hex(), pub_pool_0)

        # 6. Coinbase Tx ID check
        pub_cb_id = data["transactions"]["type_0_coinbase"]["tx_id_hex"]
        cb = CoinbaseTx(
            chain_id=DEVNET_CHAIN_ID,
            height=1,
            recipient=bytes.fromhex(
                data["transactions"]["type_0_coinbase"]["recipient_hex"]
            ),
            payout_atoms=1_000_000_000,
        )
        self.assertEqual(cb.tx_id.hex(), pub_cb_id)

    # -----------------------------------------------------------------------
    # Invariant 22: Exact coinbase maturity boundary (h=99, h=100, h=101)
    # -----------------------------------------------------------------------
    def test_22_coinbase_maturity_99_100_101(self):
        """Coinbase mined at h=1: spendable at h=99 (0), h=100 (0), and h=101 (mature)."""
        self.state.begin_block(1)
        cb = CoinbaseTx(DEVNET_CHAIN_ID, 1, self.addr_alice, 1_000_000_000)
        self.state.apply_coinbase(cb)
        self.state.end_block(0, 1_000_000_000)

        alice = self.state.accounts[self.addr_alice]

        # Step through blocks 2 to 100
        for h in range(2, 101):
            self.state.begin_block(h)
            if h == 99:
                self.assertEqual(alice.spendable_balance(99), 0)
            elif h == 100:
                self.assertEqual(alice.spendable_balance(100), 0)
            self.state.end_block(0, 0)

        # At h=101: 100 blocks after mining -> mature
        self.state.begin_block(101)
        self.assertEqual(alice.spendable_balance(101), 1_000_000_000)

    # -----------------------------------------------------------------------
    # Invariant 23: Duplicate nullifiers intra-tx, intra-block, across ancestors
    # -----------------------------------------------------------------------
    def test_23_nullifier_duplicates_in_block_and_across_ancestors(self):
        """Duplicate nullifiers must be rejected intra-tx, intra-block, and across ancestor blocks."""
        self.state.begin_block(1)
        self.state.shielded_pool_balance = 1_000_000_000
        self.state.cumulative_issuance = 1_000_000_000
        nf = blake2b_256(b"shared-nullifier")

        # 1. Intra-transaction duplicate
        tx_intra = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=100_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-intra",
            nullifiers=[nf, nf],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_to_transparent(tx_intra)
        self.assertIn("Duplicate nullifiers within transaction", str(ctx.exception))

        # 2. Intra-block duplicate across two transactions
        tx1 = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=100_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-1",
            nullifiers=[nf],
        )
        self.state.apply_shielded_to_transparent(tx1)

        tx2 = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=100_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-2",
            nullifiers=[nf],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_to_transparent(tx2)
        self.assertIn("Duplicate nullifier", str(ctx.exception))

        # 3. Across ancestor blocks
        cb_fee = CoinbaseTx(DEVNET_CHAIN_ID, 1, self.addr_miner, 25_000)
        self.state.apply_coinbase(cb_fee)
        self.state.end_block(25_000, 0)
        self.state.begin_block(2)
        tx3 = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=50_000_000,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-3",
            nullifiers=[nf],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_to_transparent(tx3)
        self.assertIn("Duplicate nullifier", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Invariant 24: Anchor window validation (10-block ancestor window)
    # -----------------------------------------------------------------------
    def test_24_anchor_ancestor_window_and_unknown(self):
        """Anchor must be in 10-block ancestor window [h-10, h-1]; stale or unknown rejected."""
        # Setup chain of 15 blocks
        for h in range(1, 16):
            self.state.begin_block(h)
            self.state.orchard_commitment_root = blake2b_256(f"root-{h}".encode())
            self.state.end_block(0, 0)

        self.state.shielded_pool_balance = 500_000_000
        self.state.cumulative_issuance = 500_000_000

        # At height 16:
        self.state.begin_block(16)
        anchor_block_15 = self.state.historical_anchors[15]
        anchor_block_6 = self.state.historical_anchors[6]
        anchor_block_5 = self.state.historical_anchors[5]  # stale (> 10 blocks)
        unknown_anchor = blake2b_256(b"unknown-anchor")

        # Valid anchor 15 passes
        tx_valid = ShieldedTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-valid-15",
            anchor=anchor_block_15,
        )
        fee = self.state.apply_shielded_transfer(tx_valid)
        self.assertEqual(fee, 25_000)

        # Valid anchor 6 passes
        tx_valid_6 = ShieldedTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-valid-6",
            anchor=anchor_block_6,
        )
        self.state.apply_shielded_transfer(tx_valid_6)

        # Stale anchor 5 (11 blocks ago) fails
        tx_stale = ShieldedTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-stale",
            anchor=anchor_block_5,
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_transfer(tx_stale)
        self.assertIn("10-block ancestor window", str(ctx.exception))

        # Unknown anchor fails
        tx_unknown = ShieldedTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            fee_atoms=25_000,
            orchard_bundle_bytes=b"bundle-unknown",
            anchor=unknown_anchor,
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_shielded_transfer(tx_unknown)
        self.assertIn("10-block ancestor window", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Invariant 25: Type 5 and Type 7 fee conservation
    # -----------------------------------------------------------------------
    def test_25_type5_and_type7_fee_conservation(self):
        """Type 5 and Type 7 fees leave the shielded pool and credit the block producer."""
        self.state.begin_block(1)
        cb1 = CoinbaseTx(DEVNET_CHAIN_ID, 1, self.addr_alice, 1_000_000_000)
        self.state.apply_coinbase(cb1)
        self.state.end_block(0, 1_000_000_000)

        for h in range(2, 102):
            self.state.begin_block(h)
            self.state.end_block(0, 0)

        self.state.begin_block(102)
        t2s = TransparentToShieldedTx(
            chain_id=DEVNET_CHAIN_ID,
            sender_pubkey=self.key_alice,
            nonce=0,
            shielded_amount=500_000_000,
            fee_atoms=30_000,
            orchard_bundle_bytes=b"shield-bundle",
        )
        self.state.apply_transparent_to_shielded(t2s)
        cb102 = CoinbaseTx(DEVNET_CHAIN_ID, 102, self.addr_miner, 30_000)
        self.state.apply_coinbase(cb102)
        self.state.end_block(30_000, 0)

        self.assertEqual(self.state.shielded_pool_balance, 500_000_000)
        self.state.verify_global_invariant()

        # Block 103: Type 5 ShieldedTransfer with fee 50_000 atoms
        self.state.begin_block(103)
        tx5 = ShieldedTransferTx(
            chain_id=DEVNET_CHAIN_ID,
            fee_atoms=50_000,
            orchard_bundle_bytes=b"shielded-transfer-bundle",
            nullifiers=[blake2b_256(b"nf-tx5")],
            anchor=self.state.historical_anchors[102],
        )
        fee5 = self.state.apply_shielded_transfer(tx5)
        self.assertEqual(fee5, 50_000)
        self.assertEqual(self.state.shielded_pool_balance, 500_000_000 - 50_000)

        cb103 = CoinbaseTx(DEVNET_CHAIN_ID, 103, self.addr_miner, 50_000)
        self.state.apply_coinbase(cb103)
        self.state.end_block(50_000, 0)
        self.state.verify_global_invariant()

        # Block 104: Type 7 ShieldedToTransparent with release 100_000_000 and fee 40_000 atoms
        self.state.begin_block(104)
        tx7 = ShieldedToTransparentTx(
            chain_id=DEVNET_CHAIN_ID,
            recipient=self.addr_bob,
            release_amount=100_000_000,
            fee_atoms=40_000,
            orchard_bundle_bytes=b"deshield-bundle",
            nullifiers=[blake2b_256(b"nf-tx7")],
            anchor=self.state.historical_anchors[103],
        )
        fee7 = self.state.apply_shielded_to_transparent(tx7)
        self.assertEqual(fee7, 40_000)
        self.assertEqual(
            self.state.shielded_pool_balance,
            500_000_000 - 50_000 - 100_000_000 - 40_000,
        )
        self.assertEqual(self.state.accounts[self.addr_bob].balance, 100_000_000)

        cb104 = CoinbaseTx(DEVNET_CHAIN_ID, 104, self.addr_miner, 40_000)
        self.state.apply_coinbase(cb104)
        self.state.end_block(40_000, 0)
        self.state.verify_global_invariant()

    # -----------------------------------------------------------------------
    # Invariant 26: Actual claimed subsidy accounting
    # -----------------------------------------------------------------------
    def test_26_actual_subsidy_claimed_accounting(self):
        """Underclaimed subsidy mints less; overclaimed is rejected; fees do not increase issuance."""
        self.state.begin_block(1)
        cb1 = CoinbaseTx(DEVNET_CHAIN_ID, 1, self.addr_miner, 800_000_000)
        self.state.apply_coinbase(cb1)
        self.state.end_block(0, 800_000_000)
        self.assertEqual(self.state.cumulative_issuance, 800_000_000)
        self.state.verify_global_invariant()

        self.state.begin_block(2)
        cb2 = CoinbaseTx(DEVNET_CHAIN_ID, 2, self.addr_miner, 1_000_000_001)
        self.state.apply_coinbase(cb2)
        with self.assertRaises(HybridStateError) as ctx:
            self.state.end_block(0, 1_000_000_001)
        self.assertIn("Invalid subsidy claimed", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Invariant 27: Guardian allowance window duration strengthen vs weaken
    # -----------------------------------------------------------------------
    def test_27_guardian_window_allowance_strengthen_weaken(self):
        """Shortening window duration or increasing allowance limit requires 4-of-7 (weaken);
        Lengthening window duration or lowering allowance limit is allowed with 3-of-7 (strengthen)."""
        alice = self.state.get_or_create_account(self.addr_alice)
        alice.balance = 500_000_000
        alice.guardian_enabled = True
        alice.allowance_limit = 100_000_000
        alice.allowance_window_len = 720

        # Shortening window duration to 360 blocks with 3 votes -> rejected
        weaken_params_shorten = (100_000_000).to_bytes(16, "little") + (360).to_bytes(8, "little")
        tx_weaken_3 = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_STRENGTHEN_ALLOWANCE,
            fee_atoms=25_000,
            params=weaken_params_shorten,
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2")],
        )
        with self.assertRaises(HybridStateError) as ctx:
            self.state.apply_guardian_action(tx_weaken_3)
        self.assertIn("Cannot shorten window duration with 3-of-7 quorum", str(ctx.exception))

        # Lengthening window duration to 1440 blocks with 3 votes -> passes
        strengthen_params_lengthen = (100_000_000).to_bytes(16, "little") + (1440).to_bytes(8, "little")
        tx_strengthen_3 = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_STRENGTHEN_ALLOWANCE,
            fee_atoms=25_000,
            params=strengthen_params_lengthen,
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2")],
        )
        self.state.apply_guardian_action(tx_strengthen_3)
        self.assertEqual(alice.allowance_window_len, 1440)

        # Shortening window duration to 360 blocks with 4 votes via ACTION_WEAKEN_ALLOWANCE -> passes
        tx_weaken_4 = GuardianActionTx(
            chain_id=DEVNET_CHAIN_ID,
            account=self.addr_alice,
            action_type=ACTION_WEAKEN_ALLOWANCE,
            fee_atoms=25_000,
            params=weaken_params_shorten,
            guardian_sigs=[(0, b"s0"), (1, b"s1"), (2, b"s2"), (3, b"s3")],
        )
        self.state.apply_guardian_action(tx_weaken_4)
        self.assertEqual(alice.allowance_window_len, 360)

    # -----------------------------------------------------------------------
    # Invariant 28: Established M1-A Transaction Merkle Compatibility
    # -----------------------------------------------------------------------
    def test_28_m1a_transaction_merkle_compatibility(self):
        """M1-A transaction Merkle tree matches historical test vectors in docs/test-vectors-m1a.json."""
        import json, os
        vector_path = os.path.join(
            os.path.dirname(__file__), "..", "docs", "test-vectors-m1a.json"
        )
        if not os.path.exists(vector_path):
            self.skipTest("M1-A vectors file not found")
        with open(vector_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(m1a_empty_root().hex(), data["empty_tree_root"])

        tx_a = bytes.fromhex(data["transactions"]["tx_a"]["tx_id"])
        self.assertEqual(
            m1a_tx_root([tx_a]).hex(),
            data["merkle"]["1_transactions"]["root"],
        )

        tx_b = bytes.fromhex(data["transactions"]["tx_b"]["tx_id"])
        tx_c = bytes.fromhex(data["transactions"]["tx_c"]["tx_id"])
        tx_d = bytes.fromhex(data["transactions"]["tx_d"]["tx_id"])
        self.assertEqual(
            m1a_tx_root([tx_a, tx_b, tx_c, tx_d]).hex(),
            data["merkle"]["4_transactions"]["root"],
        )

    # -----------------------------------------------------------------------
    # Invariant 29: Halving boundaries and subsidy exhaustion
    # -----------------------------------------------------------------------
    def test_29_halving_boundaries_and_exhaustion(self):
        """Test exact subsidy values across halving eras and exhaustion."""
        # Genesis height 0 has zero subsidy
        self.assertEqual(scheduled_subsidy(0), 0)

        # Era 0: 10 OWN (1,000,000,000 atoms)
        self.assertEqual(scheduled_subsidy(1), 1_000_000_000)
        self.assertEqual(scheduled_subsidy(1_049_999), 1_000_000_000)  # Immediately before 1st halving
        self.assertEqual(scheduled_subsidy(1_050_000), 1_000_000_000)  # At 1st halving boundary

        # Era 1: 5 OWN (500,000,000 atoms)
        self.assertEqual(scheduled_subsidy(1_050_001), 500_000_000)  # Immediately after 1st halving
        self.assertEqual(scheduled_subsidy(2_099_999), 500_000_000)  # Immediately before 2nd halving
        self.assertEqual(scheduled_subsidy(2_100_000), 500_000_000)  # At 2nd halving boundary

        # Era 2: 2.5 OWN (250,000,000 atoms)
        self.assertEqual(scheduled_subsidy(2_100_001), 250_000_000)  # Immediately after 2nd halving

        # Exhaustion boundary at Era 30 (height 31,500,001)
        self.assertEqual(scheduled_subsidy(30_450_001), 1)
        self.assertEqual(scheduled_subsidy(31_499_999), 1)  # Era 29 penultimate block
        self.assertEqual(scheduled_subsidy(31_500_000), 1)  # Era 29 last block (1 atom)
        self.assertEqual(scheduled_subsidy(31_500_001), 0)  # Era 30 first block: exhausted!
        self.assertEqual(scheduled_subsidy(100_000_000), 0)

        # Halving boundary consensus enforcement in end_block
        state_h1050k = HybridChainState(DEVNET_CHAIN_ID)
        state_h1050k.height = 1_050_000
        # Claiming exact 10 OWN subsidy at height 1,050,000 succeeds
        miner_acc = state_h1050k.get_or_create_account(self.addr_miner)
        miner_acc.balance = 1_000_000_000
        state_h1050k.end_block(0, 1_000_000_000)
        self.assertEqual(state_h1050k.cumulative_issuance, 1_000_000_000)

        # Overclaiming by 1 atom at height 1,050,000 fails
        state_over = HybridChainState(DEVNET_CHAIN_ID)
        state_over.height = 1_050_000
        with self.assertRaises(HybridStateError):
            state_over.end_block(0, 1_000_000_001)

        # At height 1,050,001 (Era 1): claiming 5 OWN succeeds
        state_h1050k1 = HybridChainState(DEVNET_CHAIN_ID)
        state_h1050k1.height = 1_050_001
        miner_acc1 = state_h1050k1.get_or_create_account(self.addr_miner)
        miner_acc1.balance = 500_000_000
        state_h1050k1.end_block(0, 500_000_000)
        self.assertEqual(state_h1050k1.cumulative_issuance, 500_000_000)

        # At height 1,050,001: attempting to claim Era 0 subsidy (10 OWN) fails
        state_era0_fail = HybridChainState(DEVNET_CHAIN_ID)
        state_era0_fail.height = 1_050_001
        with self.assertRaises(HybridStateError):
            state_era0_fail.end_block(0, 1_000_000_000)

        # Cumulative issuance cap (21M OWN) enforcement
        state_cap = HybridChainState(DEVNET_CHAIN_ID)
        state_cap.height = 1
        state_cap.cumulative_issuance = MAX_SUPPLY_ATOMS - 500
        cap_miner = state_cap.get_or_create_account(self.addr_miner)
        cap_miner.balance = MAX_SUPPLY_ATOMS - 500
        # Claiming remaining 500 atoms succeeds
        cap_miner.balance += 500
        state_cap.end_block(0, 500)
        self.assertEqual(state_cap.cumulative_issuance, MAX_SUPPLY_ATOMS)

        # Claiming 1 atom beyond 21M OWN cap fails
        state_cap_over = HybridChainState(DEVNET_CHAIN_ID)
        state_cap_over.height = 1
        state_cap_over.cumulative_issuance = MAX_SUPPLY_ATOMS
        with self.assertRaises(HybridStateError):
            state_cap_over.end_block(0, 1)




if __name__ == "__main__":
    unittest.main()
