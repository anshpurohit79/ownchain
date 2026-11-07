"""
OwnChain Reference Model – Hybrid Consensus State Machine.

Implements consensus state tracking and atomic block transitions per
OwnChain Protocol v1 (Hybrid Shielded-First Architecture):
  - Transparent accounts with nonces, allowances, guardian controls
  - Canonical account serialization matching protocol-v1.md §7.3
  - Spendable balance = balance - immature_coinbase - pending_outgoing
  - 100-block coinbase maturity tranches
  - Opt-in per-account guardian quorums (3-of-7 strengthen, 4-of-7 weaken/critical)
  - Shielded pool balance (Orchard) with checked non-negative arithmetic
  - Global monetary conservation invariant: T + S = I
  - Deterministic nullifier-set Merkle commitment
  - 4-component composite state root calculation
  - Block begin/apply/end transitions and reorganization rollback
"""

from __future__ import annotations

import copy
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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
    ACTION_REPLACE_GUARDIANS,
    ACTION_REPLACE_RECOVERY_KEY,
    ACTION_STRENGTHEN_ALLOWANCE,
    ACTION_STRENGTHEN_DELAYS,
    ACTION_UNFREEZE,
    ACTION_WEAKEN_ALLOWANCE,
    ACTION_WEAKEN_DELAYS,
    TX_TYPE_CANCEL_PENDING,
    TX_TYPE_COINBASE,
    TX_TYPE_CONFIGURE_GUARDIANS,
    TX_TYPE_GUARDIAN_ACTION,
    TX_TYPE_SHIELDED_TO_TRANSPARENT,
    TX_TYPE_SHIELDED_TRANSFER,
    TX_TYPE_TRANSPARENT_TO_SHIELDED,
    TX_TYPE_TRANSPARENT_TRANSFER,
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

# ---------------------------------------------------------------------------
# Economic Parameters
# ---------------------------------------------------------------------------

STARTING_SUBSIDY_ATOMS: int = 1_000_000_000  # 10 OWN
HALVING_INTERVAL_BLOCKS: int = 1_050_000
MAX_SUPPLY_ATOMS: int = 2_100_000_000_000_000  # 21,000,000 OWN
COINBASE_MATURITY_BLOCKS: int = 100
DEFAULT_NEW_RECIPIENT_DELAY: int = 10
DEFAULT_WITHDRAWAL_DELAY: int = 144


def scheduled_subsidy(height: int) -> int:
    """Return scheduled block subsidy in atoms for *height*.

    Height 0 (genesis) has subsidy 0.
    Height 1..1,050,000 is Era 0: 10 OWN (1,000,000,000 atoms).
    Era halves every 1,050,000 blocks.
    Era 30+ (height 31,500,001+) has 0 subsidy (exhaustion).
    """
    if height <= 0:
        return 0
    era = (height - 1) // HALVING_INTERVAL_BLOCKS
    if era >= 30:
        return 0
    return STARTING_SUBSIDY_ATOMS >> era


# ---------------------------------------------------------------------------
# Account State & Records
# ---------------------------------------------------------------------------


@dataclass
class PendingTransfer:
    transfer_id: bytes  # 32 bytes
    recipient: bytes  # 32 bytes
    amount: int  # u128 atoms
    release_height: int  # u64

    def serialize(self) -> bytes:
        assert len(self.transfer_id) == 32
        assert len(self.recipient) == 32
        return (
            self.transfer_id
            + self.recipient
            + self.amount.to_bytes(16, "little")
            + struct.pack("<Q", self.release_height)
        )


@dataclass
class CoinbaseTranche:
    coinbase_tx_id: bytes  # 32 bytes
    amount: int  # u128 atoms
    unlock_height: int  # u64

    def serialize(self) -> bytes:
        assert len(self.coinbase_tx_id) == 32
        return (
            self.coinbase_tx_id
            + self.amount.to_bytes(16, "little")
            + struct.pack("<Q", self.unlock_height)
        )


@dataclass
class AccountState:
    balance: int = 0  # u128: total balance (mature + immature coinbase + pending outgoing)
    nonce: int = 0  # u64: strictly sequential nonce
    allowance_limit: int = 0  # u128: 0 = disabled/unlimited
    allowance_window_start: int = 0  # u64
    allowance_window_len: int = 0  # u64
    allowance_spent: int = 0  # u128
    is_frozen: bool = False
    recovery_key: bytes = b"\x00" * 32
    guardian_enabled: bool = False
    new_recipient_delay: int = DEFAULT_NEW_RECIPIENT_DELAY
    withdrawal_delay: int = DEFAULT_WITHDRAWAL_DELAY
    guardians: list[bytes] = field(default_factory=lambda: [b"\x00" * 32] * 7)
    pending_transfers: list[PendingTransfer] = field(default_factory=list)
    coinbase_tranches: list[CoinbaseTranche] = field(default_factory=list)
    confirmed_recipients: set[bytes] = field(default_factory=set)

    def immature_coinbase_balance(self, height: int) -> int:
        """Sum of coinbase tranches where unlock_height > height."""
        return sum(t.amount for t in self.coinbase_tranches if t.unlock_height > height)

    def pending_outgoing_balance(self) -> int:
        """Sum of pending outgoing transfer amounts."""
        return sum(p.amount for p in self.pending_transfers)

    def spendable_balance(self, height: int) -> int:
        """Mature spendable balance = balance - immature_coinbase - pending_outgoing."""
        immature = self.immature_coinbase_balance(height)
        pending = self.pending_outgoing_balance()
        spendable = self.balance - immature - pending
        if spendable < 0:
            raise ValueError(
                f"Negative spendable balance: balance={self.balance}, "
                f"immature={immature}, pending={pending}"
            )
        return spendable

    def serialize(self) -> bytes:
        """Canonical account serialization matching protocol-v1.md §7.3."""
        # 0..16: balance u128_le
        out = self.balance.to_bytes(16, "little")
        # 16..24: nonce u64_le
        out += struct.pack("<Q", self.nonce)
        # 24..40: allowance_limit u128_le
        out += self.allowance_limit.to_bytes(16, "little")
        # 40..48: allowance_window_start u64_le
        out += struct.pack("<Q", self.allowance_window_start)
        # 48..56: allowance_window_len u64_le
        out += struct.pack("<Q", self.allowance_window_len)
        # 56..72: allowance_spent u128_le
        out += self.allowance_spent.to_bytes(16, "little")
        # 72..73: is_frozen u8
        out += struct.pack("<B", 1 if self.is_frozen else 0)
        # 73..105: recovery_key [u8; 32]
        assert len(self.recovery_key) == 32
        out += self.recovery_key
        # 105..106: guardian_enabled u8
        out += struct.pack("<B", 1 if self.guardian_enabled else 0)
        # 106..110: new_recipient_delay u32_le
        out += struct.pack("<I", self.new_recipient_delay)
        # 110..114: withdrawal_delay u32_le
        out += struct.pack("<I", self.withdrawal_delay)
        # 114..338: guardians [u8; 224] (7 * 32)
        assert len(self.guardians) == 7
        out += b"".join(self.guardians)
        # 338..342: pending_transfers_count u32_le
        sorted_pending = sorted(self.pending_transfers, key=lambda p: p.transfer_id)
        out += struct.pack("<I", len(sorted_pending))
        for p in sorted_pending:
            out += p.serialize()
        # coinbase_tranches_count u32_le
        sorted_tranches = sorted(
            self.coinbase_tranches, key=lambda t: (t.unlock_height, t.coinbase_tx_id)
        )
        out += struct.pack("<I", len(sorted_tranches))
        for t in sorted_tranches:
            out += t.serialize()
        return out


# ---------------------------------------------------------------------------
# Hybrid Consensus State Machine
# ---------------------------------------------------------------------------


class HybridStateError(Exception):
    """Consensus state transition error."""

    pass


class HybridChainState:
    """Consensus state machine for the OwnChain hybrid ledger."""

    def __init__(self, chain_id: bytes):
        assert len(chain_id) == 32
        self.chain_id: bytes = chain_id
        self.height: int = 0
        self.accounts: Dict[bytes, AccountState] = {}
        self.nullifier_set: Set[bytes] = set()
        self.shielded_pool_balance: int = 0  # atoms
        self.cumulative_issuance: int = 0  # atoms
        self.orchard_commitment_root: bytes = OrchardAdapter.empty_commitment_root()
        self.accepted_tx_ids: Set[bytes] = set()

        # Historical anchors for 10-block ancestor anchor window checks
        self.historical_anchors: Dict[int, bytes] = {0: OrchardAdapter.empty_commitment_root()}

        # Historical snapshots for reorganization rollback
        self._history: Dict[int, bytes] = {}  # height -> serialized snapshot

    def clone(self) -> HybridChainState:
        """Create a deep copy of the state."""
        return copy.deepcopy(self)

    # -----------------------------------------------------------------------
    # State Commitments
    # -----------------------------------------------------------------------

    def compute_transparent_root(self) -> bytes:
        """RFC 6962-style recursive-split Merkle root over sorted accounts.

        Sorted strictly by 32-byte address ascending.
        Leaf payload: address[32] || serialized_account_state.
        """
        if not self.accounts:
            return empty_root()
        sorted_addrs = sorted(self.accounts.keys())
        leaves = [addr + self.accounts[addr].serialize() for addr in sorted_addrs]
        return merkle_root(leaves)

    def compute_nullifier_root(self) -> bytes:
        """Recursive-split Merkle root over sorted 32-byte nullifiers."""
        if not self.nullifier_set:
            return nullifier_merkle_root([])
        sorted_nfs = sorted(self.nullifier_set)
        return nullifier_merkle_root(sorted_nfs)

    def compute_pool_commitment(self) -> bytes:
        """Domain-separated commitment to cumulative shielded pool balance."""
        return pool_balance_commitment(self.shielded_pool_balance)

    def compute_composite_state_root(self) -> bytes:
        """BLAKE2b-256(DOM_COMPOSITE || T_root || O_root || NF_root || S_comm)."""
        t_root = self.compute_transparent_root()
        o_root = self.orchard_commitment_root
        nf_root = self.compute_nullifier_root()
        s_comm = self.compute_pool_commitment()
        return composite_state_root(t_root, o_root, nf_root, s_comm)

    # -----------------------------------------------------------------------
    # Invariant Verification
    # -----------------------------------------------------------------------

    def verify_global_invariant(self) -> None:
        """Verify: T + S = I, S >= 0, I <= 21,000,000 OWN."""
        t_total = sum(acc.balance for acc in self.accounts.values())
        s_total = self.shielded_pool_balance
        i_total = self.cumulative_issuance

        if s_total < 0:
            raise HybridStateError(f"Shielded pool balance is negative: {s_total}")

        if t_total + s_total != i_total:
            raise HybridStateError(
                f"Global monetary conservation violated: "
                f"T({t_total}) + S({s_total}) = {t_total + s_total} != I({i_total})"
            )

        if i_total > MAX_SUPPLY_ATOMS:
            raise HybridStateError(
                f"Cumulative issuance exceeds 21M OWN cap: {i_total} > {MAX_SUPPLY_ATOMS}"
            )

    # -----------------------------------------------------------------------
    # Block Lifecycle
    # -----------------------------------------------------------------------

    def begin_block(self, new_height: int) -> None:
        """Execute start-of-block state transitions:

        1. Mature coinbase tranches where unlock_height <= new_height
        2. Release mature pending transfers where release_height <= new_height
        """
        if new_height != self.height + 1 and not (self.height == 0 and new_height == 1):
            raise HybridStateError(
                f"Height sequence error: expected {self.height + 1}, got {new_height}"
            )
        self.height = new_height

        for addr, acc in list(self.accounts.items()):
            # 1. Mature coinbase tranches
            remaining_tranches = []
            for t in acc.coinbase_tranches:
                if t.unlock_height <= new_height:
                    # Tranche matures: amount is already in acc.balance,
                    # removing from tranches makes it spendable!
                    pass
                else:
                    remaining_tranches.append(t)
            acc.coinbase_tranches = remaining_tranches

            # 2. Release pending transfers
            remaining_pending = []
            for p in acc.pending_transfers:
                if p.release_height <= new_height:
                    # Pending transfer matures: debit sender balance, credit recipient balance
                    acc.balance -= p.amount
                    rec_acc = self.get_or_create_account(p.recipient)
                    rec_acc.balance += p.amount
                    # Record confirmed recipient on sender
                    acc.confirmed_recipients.add(p.recipient)
                else:
                    remaining_pending.append(p)
            acc.pending_transfers = remaining_pending

    def end_block(self, block_fee_collected: int, actual_subsidy_claimed: int) -> bytes:
        """Finalize block execution and verify invariants."""
        # Subsidy limits
        sched = scheduled_subsidy(self.height)
        if actual_subsidy_claimed < 0 or actual_subsidy_claimed > sched:
            raise HybridStateError(
                f"Invalid subsidy claimed: {actual_subsidy_claimed} (max {sched})"
            )
        if self.cumulative_issuance + actual_subsidy_claimed > MAX_SUPPLY_ATOMS:
            raise HybridStateError("Subsidy claim would violate 21M OWN cap")

        self.cumulative_issuance += actual_subsidy_claimed
        self.historical_anchors[self.height] = self.orchard_commitment_root
        self.verify_global_invariant()
        return self.compute_composite_state_root()

    def get_or_create_account(self, address: bytes) -> AccountState:
        assert len(address) == 32
        if address not in self.accounts:
            self.accounts[address] = AccountState()
        return self.accounts[address]

    # -----------------------------------------------------------------------
    # Transaction Application
    # -----------------------------------------------------------------------

    def apply_coinbase(self, tx: CoinbaseTx) -> None:
        """Apply Type 0: Coinbase."""
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id on coinbase")
        if tx.height != self.height:
            raise HybridStateError(
                f"Coinbase declared height {tx.height} != block height {self.height}"
            )
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError(f"Duplicate transaction ID: {tx.tx_id.hex()}")

        # Credit miner's transparent balance and record immature tranche
        miner = self.get_or_create_account(tx.recipient)
        miner.balance += tx.payout_atoms
        unlock_height = self.height + COINBASE_MATURITY_BLOCKS
        miner.coinbase_tranches.append(
            CoinbaseTranche(
                coinbase_tx_id=tx.tx_id,
                amount=tx.payout_atoms,
                unlock_height=unlock_height,
            )
        )
        self.accepted_tx_ids.add(tx.tx_id)

    def apply_transparent_transfer(self, tx: TransparentTransferTx) -> int:
        """Apply Type 1: TransparentTransfer.

        Returns fee_atoms paid to block producer.
        """
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError(
                f"Fee {tx.fee_atoms} below minimum required {tx.min_fee}"
            )

        sender_addr = tx.sender_address
        sender = self.accounts.get(sender_addr)
        if sender is None:
            raise HybridStateError("Sender account does not exist")

        if sender.is_frozen:
            raise HybridStateError("Sender account is frozen")

        if tx.nonce != sender.nonce:
            raise HybridStateError(
                f"Nonce mismatch: expected {sender.nonce}, got {tx.nonce}"
            )

        total_cost = tx.amount + tx.fee_atoms
        if sender.spendable_balance(self.height) < total_cost:
            raise HybridStateError("Insufficient spendable balance")

        # Allowance check
        if sender.allowance_limit > 0 and sender.allowance_window_len > 0:
            if self.height >= sender.allowance_window_start + sender.allowance_window_len:
                sender.allowance_window_start = self.height
                sender.allowance_spent = 0
            if sender.allowance_spent + total_cost > sender.allowance_limit:
                raise HybridStateError("Allowance limit exceeded")
            sender.allowance_spent += total_cost

        # Execute spend
        sender.nonce += 1
        sender.balance -= tx.fee_atoms  # Fee leaves sender immediately

        # Recipient delivery or pending lock
        if sender.guardian_enabled and (tx.recipient not in sender.confirmed_recipients):
            # First-time recipient under guardian protection: lock principal in pending record
            transfer_id = blake2b_256(tx.tx_id + b"/pending")
            release_h = self.height + sender.new_recipient_delay
            # Note: principal remains in sender.balance, but excluded from spendable_balance!
            sender.pending_transfers.append(
                PendingTransfer(
                    transfer_id=transfer_id,
                    recipient=tx.recipient,
                    amount=tx.amount,
                    release_height=release_h,
                )
            )
        else:
            # Immediate transfer
            sender.balance -= tx.amount
            recipient = self.get_or_create_account(tx.recipient)
            recipient.balance += tx.amount
            sender.confirmed_recipients.add(tx.recipient)

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms

    def apply_configure_guardians(self, tx: ConfigureGuardiansTx) -> int:
        """Apply Type 2: ConfigureGuardians."""
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError("Fee below minimum")

        account_addr = tx.account_address
        account = self.get_or_create_account(account_addr)

        if account.is_frozen:
            raise HybridStateError("Account is frozen")
        if tx.nonce != account.nonce:
            raise HybridStateError("Nonce mismatch")
        if account.spendable_balance(self.height) < tx.fee_atoms:
            raise HybridStateError("Insufficient balance for fee")

        # Reconfiguring an active guardian set requires 4-of-7 quorum
        if account.guardian_enabled:
            if len(tx.guardian_sigs) < 4:
                raise HybridStateError(
                    "Reconfiguring active guardians requires 4-of-7 guardian quorum"
                )

        account.nonce += 1
        account.balance -= tx.fee_atoms
        account.guardians = list(tx.guardian_keys)
        account.new_recipient_delay = tx.new_recipient_delay
        account.withdrawal_delay = tx.withdrawal_delay
        account.allowance_limit = tx.allowance_limit
        account.allowance_window_len = tx.allowance_window_len
        account.recovery_key = tx.recovery_key
        account.guardian_enabled = True

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms

    def apply_guardian_action(self, tx: GuardianActionTx) -> int:
        """Apply Type 3: GuardianAction."""
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError("Fee below minimum")

        account = self.accounts.get(tx.account)
        if account is None or not account.guardian_enabled:
            raise HybridStateError("Account does not exist or has no guardians")

        # Quorum requirements per Part X:
        # 3-of-7 for strengthening
        # 4-of-7 for weakening, freeze, unfreeze, recovery, replacement
        if tx.action_type in (ACTION_STRENGTHEN_DELAYS, ACTION_STRENGTHEN_ALLOWANCE):
            req_quorum = 3
        else:
            req_quorum = 4

        # Validate unique guardian indices
        guardian_indices = [idx for idx, _ in tx.guardian_sigs]
        if len(guardian_indices) < req_quorum:
            raise HybridStateError(
                f"Insufficient guardian quorum: {len(guardian_indices)} < {req_quorum}"
            )
        if len(set(guardian_indices)) != len(guardian_indices):
            raise HybridStateError("Duplicate guardian vote")
        for idx in guardian_indices:
            if idx < 0 or idx >= 7:
                raise HybridStateError(f"Invalid guardian index {idx}")

        if account.spendable_balance(self.height) < tx.fee_atoms:
            raise HybridStateError("Insufficient balance for fee")

        # Validate ACTION_STRENGTHEN_ALLOWANCE before mutating account state to preserve atomicity on failure
        if tx.action_type == ACTION_STRENGTHEN_ALLOWANCE:
            new_limit = int.from_bytes(tx.params[:16], "little") if len(tx.params) >= 16 else account.allowance_limit
            new_duration = struct.unpack("<Q", tx.params[16:24])[0] if len(tx.params) >= 24 else account.allowance_window_len
            if new_limit == 0 or new_duration == 0:
                raise HybridStateError("Cannot disable allowance with 3-of-7 quorum")
            if account.allowance_limit > 0 and new_limit > account.allowance_limit:
                raise HybridStateError("Cannot increase allowance limit with 3-of-7 quorum")
            if account.allowance_window_len > 0 and new_duration < account.allowance_window_len:
                raise HybridStateError("Cannot shorten window duration with 3-of-7 quorum")

        account.balance -= tx.fee_atoms

        # Execute action
        if tx.action_type == ACTION_FREEZE:
            account.is_frozen = True
        elif tx.action_type == ACTION_UNFREEZE:
            account.is_frozen = False
        elif tx.action_type == ACTION_RECOVERY:
            # Transfer all spendable balance to registered recovery key
            rec_addr = derive_address(account.recovery_key)
            rec_acc = self.get_or_create_account(rec_addr)
            recoverable = account.spendable_balance(self.height)
            account.balance -= recoverable
            rec_acc.balance += recoverable
        elif tx.action_type == ACTION_STRENGTHEN_DELAYS:
            new_delay = struct.unpack("<I", tx.params[:4])[0]
            if new_delay < account.new_recipient_delay:
                raise HybridStateError("Cannot decrease delay with 3-of-7 quorum")
            account.new_recipient_delay = new_delay
        elif tx.action_type == ACTION_WEAKEN_DELAYS:
            new_delay = struct.unpack("<I", tx.params[:4])[0]
            account.new_recipient_delay = new_delay
        elif tx.action_type == ACTION_STRENGTHEN_ALLOWANCE:
            account.allowance_limit = new_limit
            account.allowance_window_len = new_duration
        elif tx.action_type == ACTION_WEAKEN_ALLOWANCE:
            new_limit = int.from_bytes(tx.params[:16], "little") if len(tx.params) >= 16 else account.allowance_limit
            new_duration = struct.unpack("<Q", tx.params[16:24])[0] if len(tx.params) >= 24 else account.allowance_window_len
            account.allowance_limit = new_limit
            account.allowance_window_len = new_duration
        elif tx.action_type == ACTION_REPLACE_GUARDIANS:
            if len(tx.params) < 7 * 32:
                raise HybridStateError("Replace guardians requires 7 pubkeys (224 bytes)")
            account.guardians = [tx.params[i * 32 : (i + 1) * 32] for i in range(7)]
        elif tx.action_type == ACTION_REPLACE_RECOVERY_KEY:
            account.recovery_key = tx.params[:32]

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms

    def apply_cancel_pending(self, tx: CancelPendingTransferTx) -> int:
        """Apply Type 4: CancelPendingTransfer."""
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError("Fee below minimum")

        sender_addr = tx.sender_address
        sender = self.accounts.get(sender_addr)
        if sender is None:
            raise HybridStateError("Sender not found")

        if sender.is_frozen:
            raise HybridStateError("Sender is frozen")
        if tx.nonce != sender.nonce:
            raise HybridStateError("Nonce mismatch")

        # 4-of-7 guardian quorum required
        guardian_indices = [idx for idx, _ in tx.guardian_sigs]
        if len(guardian_indices) < 4:
            raise HybridStateError("Cancel pending transfer requires 4-of-7 quorum")
        if len(set(guardian_indices)) != len(guardian_indices):
            raise HybridStateError("Duplicate guardian vote")

        # Find target pending transfer
        found_idx = None
        for i, p in enumerate(sender.pending_transfers):
            if p.transfer_id == tx.transfer_id:
                found_idx = i
                break
        if found_idx is None:
            raise HybridStateError("Pending transfer not found or already released")

        if sender.spendable_balance(self.height) < tx.fee_atoms:
            raise HybridStateError("Insufficient balance for cancellation fee")

        sender.nonce += 1
        sender.balance -= tx.fee_atoms
        # Cancel: remove record (principal was never deducted from balance,
        # so removing record immediately restores spendable balance!)
        sender.pending_transfers.pop(found_idx)

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms

    def apply_shielded_transfer(self, tx: ShieldedTransferTx) -> int:
        """Apply Type 5: ShieldedTransfer (Orchard-only).

        Fee leaves Orchard pool and is paid to block producer:
          shielded_pool_balance -= fee_atoms
        """
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError("Fee below minimum")

        # Anchor check: must be in 10-block ancestor window [max(0, height-10), max(0, height-1)]
        valid_anchors = {
            self.historical_anchors[h]
            for h in range(max(0, self.height - 10), max(1, self.height))
            if h in self.historical_anchors
        }
        if 0 in self.historical_anchors and self.height <= 10:
            valid_anchors.add(self.historical_anchors[0])

        if tx.anchor not in valid_anchors:
            raise HybridStateError(
                f"Anchor {tx.anchor.hex()} not in 10-block ancestor window"
            )

        # Intra-transaction duplicate nullifier check
        if len(tx.nullifiers) != len(set(tx.nullifiers)):
            raise HybridStateError("Duplicate nullifiers within transaction")

        # Nullifier double-spend check
        for nf in tx.nullifiers:
            if nf in self.nullifier_set:
                raise HybridStateError(f"Duplicate nullifier: {nf.hex()}")

        if self.shielded_pool_balance < tx.fee_atoms:
            raise HybridStateError(
                f"Insufficient shielded pool balance for fee: "
                f"{self.shielded_pool_balance} < {tx.fee_atoms}"
            )

        self.shielded_pool_balance -= tx.fee_atoms
        for nf in tx.nullifiers:
            self.nullifier_set.add(nf)

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms

    def apply_transparent_to_shielded(self, tx: TransparentToShieldedTx) -> int:
        """Apply Type 6: TransparentToShielded (Shielding).

        Transparent principal burned, fee paid to miner, principal enters Orchard:
          transparent_balance -= (shielded_amount + fee_atoms)
          shielded_pool_balance += shielded_amount
        """
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError("Fee below minimum")

        sender_addr = tx.sender_address
        sender = self.accounts.get(sender_addr)
        if sender is None:
            raise HybridStateError("Sender not found")

        if sender.is_frozen:
            raise HybridStateError("Sender is frozen")
        if tx.nonce != sender.nonce:
            raise HybridStateError("Nonce mismatch")

        # Guardian-protected cross-pool withdrawal check
        if sender.guardian_enabled:
            guardian_indices = [idx for idx, _ in tx.guardian_sigs]
            if len(guardian_indices) < 4:
                raise HybridStateError(
                    "Shielding funds from protected account requires 4-of-7 guardian quorum"
                )

        # Intra-transaction duplicate nullifier check
        if len(tx.nullifiers) != len(set(tx.nullifiers)):
            raise HybridStateError("Duplicate nullifiers within transaction")

        # Nullifier double-spend check
        for nf in tx.nullifiers:
            if nf in self.nullifier_set:
                raise HybridStateError(f"Duplicate nullifier: {nf.hex()}")

        total_cost = tx.shielded_amount + tx.fee_atoms
        if sender.spendable_balance(self.height) < total_cost:
            raise HybridStateError("Insufficient spendable balance to shield")

        sender.nonce += 1
        sender.balance -= total_cost
        self.shielded_pool_balance += tx.shielded_amount
        for nf in tx.nullifiers:
            self.nullifier_set.add(nf)

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms

    def apply_shielded_to_transparent(self, tx: ShieldedToTransparentTx) -> int:
        """Apply Type 7: ShieldedToTransparent (Deshielding).

        Orchard funds exit to transparent recipient:
          shielded_pool_balance -= (release_amount + fee_atoms)
          recipient_balance += release_amount
        """
        if tx.chain_id != self.chain_id:
            raise HybridStateError("Wrong chain_id")
        if tx.tx_id in self.accepted_tx_ids:
            raise HybridStateError("Duplicate tx ID")
        if tx.fee_atoms < tx.min_fee:
            raise HybridStateError("Fee below minimum")

        # Anchor check: must be in 10-block ancestor window [max(0, height-10), max(0, height-1)]
        valid_anchors = {
            self.historical_anchors[h]
            for h in range(max(0, self.height - 10), max(1, self.height))
            if h in self.historical_anchors
        }
        if 0 in self.historical_anchors and self.height <= 10:
            valid_anchors.add(self.historical_anchors[0])

        if tx.anchor not in valid_anchors:
            raise HybridStateError(
                f"Anchor {tx.anchor.hex()} not in 10-block ancestor window"
            )

        # Intra-transaction duplicate nullifier check
        if len(tx.nullifiers) != len(set(tx.nullifiers)):
            raise HybridStateError("Duplicate nullifiers within transaction")

        # Nullifier double-spend check
        for nf in tx.nullifiers:
            if nf in self.nullifier_set:
                raise HybridStateError(f"Duplicate nullifier: {nf.hex()}")

        total_shielded_deduction = tx.release_amount + tx.fee_atoms
        if self.shielded_pool_balance < total_shielded_deduction:
            raise HybridStateError(
                f"Insufficient shielded pool balance to deshield: "
                f"{self.shielded_pool_balance} < {total_shielded_deduction}"
            )

        self.shielded_pool_balance -= total_shielded_deduction
        recipient = self.get_or_create_account(tx.recipient)
        recipient.balance += tx.release_amount

        for nf in tx.nullifiers:
            self.nullifier_set.add(nf)

        self.accepted_tx_ids.add(tx.tx_id)
        return tx.fee_atoms
