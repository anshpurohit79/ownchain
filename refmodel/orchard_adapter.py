"""
OwnChain Reference Model – Orchard adapter (stubs).

This module does **NOT** implement Orchard proof verification.  All
cryptographic heavy-lifting (Orchard Action proofs, spend-auth signatures,
binding signatures, note-commitment-tree updates) is delegated to the pinned
Rust/Orchard crate.

What *is* provided here:
  - Constants exported by the pinned crate (e.g. empty commitment-tree root).
  - Value-balance sign-convention documentation.
  - Interface specifications for future Rust↔Python FFI integration.
"""

from __future__ import annotations


class OrchardAdapter:
    """Stub interface for Orchard operations.

    Every method that touches real Orchard cryptography is marked
    ``DELEGATED TO RUST/ORCHARD CRATE`` and raises ``NotImplementedError``.
    """

    # The empty-tree root of the Orchard note-commitment Merkle tree (Sinsemilla).
    # Hex-encoded 32 bytes, little-endian field element.
    ORCHARD_EMPTY_ROOT_HEX: str = (
        "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"
    )

    # ------------------------------------------------------------------
    # Constants
    # ------------------------------------------------------------------

    @classmethod
    def empty_commitment_root(cls) -> bytes:
        """Return the 32-byte empty Orchard commitment-tree root."""
        return bytes.fromhex(cls.ORCHARD_EMPTY_ROOT_HEX)

    # ------------------------------------------------------------------
    # Proof verification  (DELEGATED TO RUST/ORCHARD CRATE)
    # ------------------------------------------------------------------

    @staticmethod
    def verify_action_proof(
        proof_bytes: bytes,
        anchor: bytes,
        nullifier: bytes,
        rk: bytes,
        cm_new: bytes,
        enable_spend: bool,
        enable_output: bool,
    ) -> bool:
        """Verify a single Orchard Action proof.

        DELEGATED TO RUST/ORCHARD CRATE – do NOT implement in Python.

        Parameters
        ----------
        proof_bytes : bytes
            Halo 2 proof (~2720 bytes).
        anchor : bytes
            32-byte anchor (root of the note-commitment tree at spend time).
        nullifier : bytes
            32-byte nullifier revealed by the spend.
        rk : bytes
            32-byte re-randomised spend-authorising verification key.
        cm_new : bytes
            32-byte commitment to the newly created note.
        enable_spend : bool
            Whether this action performs a spend.
        enable_output : bool
            Whether this action creates an output.

        Returns
        -------
        bool
            ``True`` iff the proof is valid.
        """
        raise NotImplementedError(
            "Orchard Action proof verification is delegated to the Rust crate."
        )

    @staticmethod
    def verify_spend_auth_signature(
        rk: bytes,
        sig: bytes,
        sighash: bytes,
    ) -> bool:
        """Verify a RedPallas spend-authorising signature.

        DELEGATED TO RUST/ORCHARD CRATE.
        """
        raise NotImplementedError(
            "RedPallas spend-auth signature verification is delegated "
            "to the Rust crate."
        )

    @staticmethod
    def verify_binding_signature(
        bvk: bytes,
        sig: bytes,
        sighash: bytes,
    ) -> bool:
        """Verify the Orchard binding signature over the bundle.

        DELEGATED TO RUST/ORCHARD CRATE.

        The binding signature proves that the value balance of all Actions
        sums to the publicly declared ``value_balance`` (the net flow into
        or out of the shielded pool).

        **Sign convention (Zcash / OwnChain):**
          positive value_balance → value flows *out* of the shielded pool
          negative value_balance → value flows *into* the shielded pool
        """
        raise NotImplementedError(
            "Orchard binding signature verification is delegated "
            "to the Rust crate."
        )

    @staticmethod
    def update_commitment_tree(
        current_root: bytes,
        new_commitments: list[bytes],
    ) -> bytes:
        """Append *new_commitments* to the Orchard note-commitment tree
        and return the new root.

        DELEGATED TO RUST/ORCHARD CRATE – requires Sinsemilla hashing.
        """
        raise NotImplementedError(
            "Orchard commitment-tree update is delegated to the Rust crate."
        )
