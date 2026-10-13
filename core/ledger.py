"""Account-based ledger with deterministic balance validation.

This module implements a minimal, deterministic ledger for the educational
cryptocurrency project. It operates only on blocks that have already passed
``Chain.validate()`` and on transaction dictionaries that have already passed
the structural checks in ``core.transaction.Transaction``.

Determinism and state-reset contract
-------------------------------------
- ``Ledger`` stores one private copy of the original bootstrap balances.
- Every call to ``Ledger.replay()`` starts from a *fresh working copy* of those
  original balances. The working copy is discarded on failure, and the
  original snapshot is never mutated.
- ``replay()`` returns a separate balance dictionary on success. The
  internal state is not exposed directly.

Scope and security boundary
---------------------------
This component does NOT implement:
- signatures, sender authorization, or key management;
- transaction fees or mining / proof-of-work;
- issuance, wallets, networking, or consensus.

Bootstrap balances are treated as trusted external state. The ledger enforces
money movement rules, but it does not authenticate that a ``sender`` actually
owns the funds. External bootstrap values therefore determine state beyond
what the chain alone determines.

Security exclusions
--------------------
This milestone does NOT implement:
- Transaction nonces or replay protection.
- Private-key encryption or recovery.
- Issuance and rewards.
- Fees, mining, and consensus.
- Networking and real-funds use.
"""

from typing import Dict

from core.exceptions import (
    InsufficientFundsError,
    InvalidChainError,
    InvalidSignatureError,
    InvalidTransactionError,
)
from core.signed_transaction import (
    SignedTransaction,
    is_valid_address,
    decode_base64url,
)


class Ledger:
    """Deterministic account-based balance ledger."""

    def __init__(self, initial_balances: Dict[str, int]):
        if not isinstance(initial_balances, dict):
            raise TypeError(
                "initial_balances must be a dict mapping account name "
                "to non-negative integer balance"
            )
        normalized: Dict[str, int] = {}
        for raw_name, raw_balance in initial_balances.items():
            if not isinstance(raw_name, str):
                raise TypeError(
                    "account name must be a string, got "
                    f"{type(raw_name).__name__}"
                )
            name = raw_name.strip()
            if not name:
                raise ValueError("account name must not be empty or whitespace-only")
            if not is_valid_address(name):
                raise ValueError(
                    f"bootstrap account {name!r} must be a 40-char lowercase "
                    "hex wallet address"
                )
            if name in normalized:
                raise ValueError(f"duplicate account after normalization: {name!r}")
            if type(raw_balance) is not int:
                raise TypeError(
                    f"balance for {name!r} must be an int, got "
                    f"{type(raw_balance).__name__}"
                )
            if raw_balance < 0:
                raise ValueError(f"balance for {name!r} must be non-negative")
            normalized[name] = raw_balance

        self._initial_balances = normalized

    def replay(self, chain) -> Dict[str, int]:
        if not chain.validate():
            raise InvalidChainError(
                "cannot replay an invalid Chain (Chain.validate() returned False)"
            )

        balances = dict(self._initial_balances)

        for block in chain.blocks:
            for tx_dict in block.transactions:
                self._apply_transaction(balances, tx_dict)

        return dict(balances)

    def _reconstruct_signed_transaction(self, tx_dict):
        if not isinstance(tx_dict, dict):
            raise InvalidTransactionError(
                "transaction must be a JSON object (dict)"
            )
        required = {"sender", "recipient", "amount", "public_key", "signature"}
        if set(tx_dict.keys()) != required:
            raise InvalidTransactionError(
                f"transaction has unexpected keys: {sorted(tx_dict.keys())}"
            )

        sender = tx_dict["sender"]
        recipient = tx_dict["recipient"]
        amount = tx_dict["amount"]
        public_key_b64 = tx_dict["public_key"]
        signature_b64 = tx_dict["signature"]

        if not isinstance(sender, str) or not is_valid_address(sender):
            raise InvalidTransactionError(
                f"sender must be a valid 40-char hex address, got {sender!r}"
            )
        if not isinstance(recipient, str) or not is_valid_address(recipient):
            raise InvalidTransactionError(
                f"recipient must be a valid 40-char hex address, got {recipient!r}"
            )
        if type(amount) is not int or amount <= 0:
            raise InvalidTransactionError("amount must be a positive integer")
        if type(amount) is bool:
            raise InvalidTransactionError("amount must be an integer, not bool")

        try:
            public_key_bytes = decode_base64url(public_key_b64, 32)
            signature_bytes = decode_base64url(signature_b64, 64)
        except InvalidTransactionError:
            raise
        except Exception as exc:
            raise InvalidTransactionError("malformed encoding") from exc

        return SignedTransaction.from_fields(
            sender=sender,
            recipient=recipient,
            amount=amount,
            public_key_bytes=public_key_bytes,
            signature_bytes=signature_bytes,
        )

    def _apply_transaction(self, balances, tx_dict):
        signed = self._reconstruct_signed_transaction(tx_dict)
        signed.verify_strict()
        self._apply_transfer(balances, signed)

    def _apply_transfer(self, balances, tx):
        sender = tx.sender
        recipient = tx.recipient
        amount = tx.amount

        balance = balances.get(sender, 0)
        if balance < amount:
            raise InsufficientFundsError(
                f"insufficient funds for sender {sender!r}: "
                f"have {balance}, need {amount}"
            )

        new_balance = balance - amount
        if new_balance < 0:
            raise InsufficientFundsError(
                f"insufficient funds for sender {sender!r}"
            )

        if sender == recipient:
            return

        balances[sender] = new_balance
        balances[recipient] = balances.get(recipient, 0) + amount
