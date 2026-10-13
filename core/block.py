"""Educational blockchain: Block component (milestone 1).

A Block bundles some data together with a SHA-256 fingerprint (hash) of
that data. The fingerprint lets anyone later check whether the data was
changed after the block was created.

Standard library only: ``json`` for serialization, ``hashlib`` for hashing.
"""

import hashlib
import json

GENESIS_INDEX = 0
GENESIS_TIMESTAMP = "2021-01-01T00:00:00Z"
GENESIS_PREV_HASH = "0" * 64


class Block:
    """A single block: data plus a stored hash snapshot of that data."""

    def __init__(self, index, timestamp, prev_hash, transactions):
        """Create a block and freeze its hash snapshot.

        Args:
            index: Position of the block in the chain (genesis is 0).
            timestamp: ISO-8601 UTC string, e.g. "2021-01-01T00:00:00Z".
            prev_hash: Hex string linking to the previous block's hash.
            transactions: A list of JSON-compatible values
                (dicts/lists/strings/numbers/booleans/None).

        Note on copying: ``list(transactions)`` is a *shallow* copy. It
        copies the outer list so the caller cannot change the block by
        appending to their original list afterwards. It does NOT copy
        nested objects: if a transaction is a dict and the caller mutates
        that dict afterwards, the block sees the change too. That is
        accepted for this milestone because we only handle simple
        JSON-compatible data; a deep copy would add unneeded complexity.
        """
        self.index = index
        self.timestamp = timestamp
        self.prev_hash = prev_hash
        self.transactions = list(transactions)
        # Freeze the hash once, at creation time. This plain attribute is
        # just a stored snapshot string -- it is reassignable Python state,
        # not hardware-enforced immutability. Tamper detection assumes the
        # snapshot itself was not also overwritten (see verify()).
        self.block_hash = self.calculate_hash()

    def to_dict(self):
        """Return the block contents as a plain dict, WITHOUT block_hash.

        Why exclude block_hash? A hash cannot include itself: the input to
        the hash function must exist before the hash is computed. So the
        hashed payload is exactly these four fields.
        """
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            # Shallow copy of the outer list so callers cannot append to
            # our internal list through the returned dict.
            "transactions": list(self.transactions),
        }

    def to_bytes(self):
        """Serialize contents to deterministic JSON bytes for hashing.

        Uses sorted keys and compact separators so the same contents always
        produce the same bytes within this implementation. ``allow_nan=False``
        rejects non-standard NaN/Infinity floats, which are not valid JSON
        and would serialize inconsistently.
        """
        text = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return text.encode("utf-8")

    def calculate_hash(self):
        """Recompute the SHA-256 hex digest of the CURRENT contents.

        This is a pure function of whatever the fields hold right now; it
        never reads or writes the stored ``block_hash`` snapshot.
        """
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def verify(self):
        """Check the stored snapshot against a freshly calculated hash.

        Returns True when the block is untouched since creation, False when
        any content field was modified afterwards. Guarantee assumes the
        stored ``block_hash`` itself was not also overwritten: an attacker
        who rewrites both contents AND the snapshot would pass this check.
        Full protection comes later from chaining prev_hash values.
        """
        return self.block_hash == self.calculate_hash()


def genesis_block():
    """Create block 0 with fixed values for reproducible tests."""
    return Block(
        index=GENESIS_INDEX,
        timestamp=GENESIS_TIMESTAMP,
        prev_hash=GENESIS_PREV_HASH,
        transactions=[],
    )
