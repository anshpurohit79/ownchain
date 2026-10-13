"""Educational blockchain: Chain Integrity component (milestone 2).

A Chain is an ordered, hash-linked list of Block objects.

Invariants (enforced by validate()):
  1. Genesis rules: first block matches the fixed genesis spec
     (index=0, timestamp="2021-01-01T00:00:00Z",
      prev_hash="0"*64, transactions=[]).
  2. Sequential indices: blocks[i].index == i for every i.
  3. Self-verification: blocks[i].verify() is True for every i.
  4. Hash links: blocks[i].prev_hash == blocks[i-1].block_hash
     for every i >= 1, using each block's STORED hash snapshot.

Key design point: link checks compare a block's `prev_hash` field to the
*PREVIOUS* block's stored `block_hash` snapshot. That means a block whose
own contents were tampered with (and whose `verify()` then fails) can still
pass the link check for the next block, and vice versa. Chain validation is
deliberately a set of independent boolean checks, not a single property.
"""

from typing import List

from core.block import Block, genesis_block

GENESIS_TIMESTAMP = "2021-01-01T00:00:00Z"
GENESIS_PREV_HASH = "0" * 64


class Chain:
    """An ordered, hash-linked list of Block objects."""

    def __init__(self, genesis: Block) -> None:
        self._blocks: List[Block] = [genesis]
        self._validate_genesis(genesis)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def _validate_genesis(self, genesis: Block) -> None:
        """Raise ValueError if the genesis block violates the fixed spec."""
        if genesis.index != 0:
            raise ValueError(
                f"Genesis index must be 0, got {genesis.index!r}"
            )
        if genesis.timestamp != GENESIS_TIMESTAMP:
            raise ValueError(
                f"Genesis timestamp must be {GENESIS_TIMESTAMP!r}, "
                f"got {genesis.timestamp!r}"
            )
        if genesis.prev_hash != GENESIS_PREV_HASH:
            raise ValueError(
                "Genesis prev_hash must be 64 zero characters"
            )
        if genesis.transactions != []:
            raise ValueError(
                "Genesis transactions must be an empty list"
            )
        if not genesis.verify():
            raise ValueError("Genesis block fails its own self-verification")

    def append(self, timestamp: str, transactions: List) -> Block:
        """Add a block after the current chain, returning the new Block.

        Raises:
            RuntimeError: if the existing chain is not valid (e.g. it has
                been tampered with in memory).
        """
        if not self.validate():
            raise RuntimeError("cannot append to an invalid chain")
        last = self._blocks[-1]
        new_block = Block(
            index=len(self._blocks),
            timestamp=timestamp,
            prev_hash=last.block_hash,  # previous block's STORED hash
            transactions=transactions,
        )
        self._blocks.append(new_block)
        return new_block

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    @property
    def blocks(self):
        """Read-only view of the chain as an immutable tuple.

        The tuple protects the collection structure: it cannot be resized or
        reordered by a caller. It does NOT protect the Block objects inside
        (they are still mutable). The internal list is never shared with the
        caller.
        """
        return tuple(self._blocks)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate(self) -> bool:
        """Return True if every chain invariant holds, else False.

        Rules (all must hold):
          1. Genesis rules: index=0, fixed timestamp,
             prev_hash="0"*64, empty transactions, and genesis.verify() is True.
          2. Sequential indices: blocks[i].index == i.
          3. Self-verification: blocks[i].verify() is True for every i.
          4. Hash links: blocks[i].prev_hash == blocks[i-1].block_hash
             for every i >= 1, using the PREVIOUS block's stored hash.
        """
        blocks = self._blocks
        n = len(blocks)

        # Rule 1: genesis rules.
        if n == 0:
            return False
        first = blocks[0]
        if (
            first.index != 0
            or first.timestamp != GENESIS_TIMESTAMP
            or first.prev_hash != GENESIS_PREV_HASH
            or first.transactions != []
            or not first.verify()
        ):
            return False

        # Rules 2 and 3 plus the first link (if any).
        for i in range(1, n):
            if blocks[i].index != i:
                return False
            if not blocks[i].verify():
                return False
            if blocks[i].prev_hash != blocks[i - 1].block_hash:
                return False

        return True
