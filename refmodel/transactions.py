"""
OwnChain Reference Model – Canonical Transaction Registry and Encoding.

Part III & Part VIII Specification:
All transactions carry:
  - Canonical outer envelope:
      tx_type: u8 || tx_version: u16_le || chain_id: [u8; 32]  (35 bytes)
  - Canonical transaction identifier:
      tx_id = BLAKE2b-256(UTF8("OwnChain/Tx/v1") || canonical_signed_tx_bytes)
  - Transparent signing preimage:
      preimage = UTF8("OwnChain/TxAuth/v1") || chain_id[32] || canonical_unsigned_tx_bytes
  - Minimum fee rule:
      min_fee = max(1, 100 * canonical_signed_tx_size_bytes) atoms

Authoritative Transaction Types:
  Type 0: Coinbase (83 bytes)
  Type 1: TransparentTransfer (195 bytes)
  Type 2: ConfigureGuardians
  Type 3: GuardianAction
  Type 4: CancelPendingTransfer
  Type 5: ShieldedTransfer
  Type 6: TransparentToShielded
  Type 7: ShieldedToTransparent
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from refmodel.merkle import blake2b_256, hash_domained

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TX_VERSION_1: int = 1

TX_TYPE_COINBASE: int = 0
TX_TYPE_TRANSPARENT_TRANSFER: int = 1
TX_TYPE_CONFIGURE_GUARDIANS: int = 2
TX_TYPE_GUARDIAN_ACTION: int = 3
TX_TYPE_CANCEL_PENDING: int = 4
TX_TYPE_SHIELDED_TRANSFER: int = 5
TX_TYPE_TRANSPARENT_TO_SHIELDED: int = 6
TX_TYPE_SHIELDED_TO_TRANSPARENT: int = 7

DOM_TX: bytes = b"OwnChain/Tx/v1"
DOM_TX_AUTH: bytes = b"OwnChain/TxAuth/v1"

ORCHARD_EMPTY_ROOT_BYTES: bytes = bytes.fromhex(
    "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f"
)
DOM_ADDRESS: bytes = b"OwnChain/Address/v1"
DOM_ACTION_EFFECT: bytes = b"OwnChain/ActionEffect/v1"
DOM_CROSS_POOL_AUTH: bytes = b"OwnChain/CrossPoolAuth/v1"

# Guardian Action Types
ACTION_STRENGTHEN_DELAYS: int = 1
ACTION_STRENGTHEN_ALLOWANCE: int = 2
ACTION_WEAKEN_DELAYS: int = 3
ACTION_WEAKEN_ALLOWANCE: int = 4
ACTION_FREEZE: int = 5
ACTION_UNFREEZE: int = 6
ACTION_RECOVERY: int = 7
ACTION_REPLACE_GUARDIANS: int = 8
ACTION_REPLACE_RECOVERY_KEY: int = 9
ACTION_CANCEL_PENDING: int = 10


def derive_address(ed25519_pubkey: bytes) -> bytes:
    """address = BLAKE2b-256(UTF8('OwnChain/Address/v1') || ed25519_pubkey[32])."""
    assert len(ed25519_pubkey) == 32
    return hash_domained(DOM_ADDRESS, ed25519_pubkey)


def compute_tx_id(canonical_signed_tx_bytes: bytes) -> bytes:
    """tx_id = BLAKE2b-256(UTF8('OwnChain/Tx/v1') || canonical_signed_tx_bytes)."""
    return hash_domained(DOM_TX, canonical_signed_tx_bytes)


def minimum_fee(canonical_signed_size: int) -> int:
    """min_fee = max(1, 100 * canonical_signed_tx_size_bytes) atoms."""
    return max(1, 100 * canonical_signed_size)


def compute_action_effect(
    cv_net: bytes,
    nullifier: bytes,
    rk: bytes,
    cmx: bytes,
    epk: bytes,
    enc_ciphertext: bytes,
    out_ciphertext: bytes,
) -> bytes:
    """Computes the 32-byte action effect digest for an Orchard action (§7.3)."""
    assert len(cv_net) == 32
    assert len(nullifier) == 32
    assert len(rk) == 32
    assert len(cmx) == 32
    assert len(epk) == 32
    assert len(enc_ciphertext) == 580
    assert len(out_ciphertext) == 80
    payload = cv_net + nullifier + rk + cmx + epk + enc_ciphertext + out_ciphertext
    return hash_domained(DOM_ACTION_EFFECT, payload)


def compute_type6_cross_pool_auth_digest(
    chain_id: bytes,
    tx_version: int,
    sender_pubkey: bytes,
    nonce: int,
    shielded_amount: int,
    fee_atoms: int,
    bundle_flag_byte: int,
    bundle_value_balance: int,
    bundle_anchor: bytes,
    action_effects: Sequence[bytes],
) -> bytes:
    """Computes the domain-separated authorization digest for a Type 6 transaction (§7.3)."""
    assert len(chain_id) == 32
    assert len(sender_pubkey) == 32
    assert len(bundle_anchor) == 32
    payload = (
        chain_id
        + struct.pack("<B", TX_TYPE_TRANSPARENT_TO_SHIELDED)
        + struct.pack("<H", tx_version)
        + sender_pubkey
        + struct.pack("<Q", nonce)
        + shielded_amount.to_bytes(16, "little")
        + struct.pack("<Q", fee_atoms)
        + struct.pack("<B", bundle_flag_byte)
        + struct.pack("<q", bundle_value_balance)
        + bundle_anchor
        + struct.pack("<I", len(action_effects))
        + b"".join(action_effects)
    )
    return hash_domained(DOM_CROSS_POOL_AUTH, payload)


def compute_type7_cross_pool_auth_digest(
    chain_id: bytes,
    tx_version: int,
    recipient: bytes,
    release_amount: int,
    fee_atoms: int,
    bundle_flag_byte: int,
    bundle_value_balance: int,
    bundle_anchor: bytes,
    action_effects: Sequence[bytes],
) -> bytes:
    """Computes the domain-separated authorization digest for a Type 7 transaction (§7.3)."""
    assert len(chain_id) == 32
    assert len(recipient) == 32
    assert len(bundle_anchor) == 32
    payload = (
        chain_id
        + struct.pack("<B", TX_TYPE_SHIELDED_TO_TRANSPARENT)
        + struct.pack("<H", tx_version)
        + recipient
        + release_amount.to_bytes(16, "little")
        + struct.pack("<Q", fee_atoms)
        + struct.pack("<B", bundle_flag_byte)
        + struct.pack("<q", bundle_value_balance)
        + bundle_anchor
        + struct.pack("<I", len(action_effects))
        + b"".join(action_effects)
    )
    return hash_domained(DOM_CROSS_POOL_AUTH, payload)


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TxEnvelope:
    tx_type: int
    tx_version: int
    chain_id: bytes  # 32 bytes

    def serialize(self) -> bytes:
        assert len(self.chain_id) == 32
        return (
            struct.pack("<B", self.tx_type)
            + struct.pack("<H", self.tx_version)
            + self.chain_id
        )

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[TxEnvelope, bytes]:
        if len(data) < 35:
            raise ValueError("Envelope truncated")
        tx_type = data[0]
        tx_version = struct.unpack("<H", data[1:3])[0]
        chain_id = data[3:35]
        return cls(tx_type, tx_version, chain_id), data[35:]


# ---------------------------------------------------------------------------
# Type 0: Coinbase
# ---------------------------------------------------------------------------


@dataclass
class CoinbaseTx:
    chain_id: bytes
    height: int  # u64
    recipient: bytes  # 32 bytes (address)
    payout_atoms: int  # u64
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_COINBASE

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        payload = (
            struct.pack("<Q", self.height)
            + self.recipient
            + struct.pack("<Q", self.payout_atoms)
        )
        return envelope + payload

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def fee_atoms(self) -> int:
        return 0

    @classmethod
    def deserialize(cls, data: bytes) -> CoinbaseTx:
        env, rest = TxEnvelope.deserialize(data)
        if env.tx_type != TX_TYPE_COINBASE:
            raise ValueError(f"Expected Coinbase (0), got {env.tx_type}")
        if len(rest) != 48:
            raise ValueError(f"Coinbase payload length mismatch: {len(rest)} != 48")
        height = struct.unpack("<Q", rest[0:8])[0]
        recipient = rest[8:40]
        payout_atoms = struct.unpack("<Q", rest[40:48])[0]
        return cls(env.chain_id, height, recipient, payout_atoms, env.tx_version)


# ---------------------------------------------------------------------------
# Type 1: TransparentTransfer
# ---------------------------------------------------------------------------


@dataclass
class TransparentTransferTx:
    chain_id: bytes
    sender_pubkey: bytes  # 32 bytes
    recipient: bytes  # 32 bytes (address)
    amount: int  # u128
    fee_atoms: int  # u64
    nonce: int  # u64
    signature: bytes = b"\x00" * 64  # 64 bytes
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_TRANSPARENT_TRANSFER

    @property
    def sender_address(self) -> bytes:
        return derive_address(self.sender_pubkey)

    def unsigned_payload(self) -> bytes:
        return (
            self.sender_pubkey
            + self.recipient
            + self.amount.to_bytes(16, "little")
            + struct.pack("<Q", self.fee_atoms)
            + struct.pack("<Q", self.nonce)
        )

    def canonical_unsigned_bytes(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        return envelope + self.unsigned_payload()

    def signing_preimage(self) -> bytes:
        return DOM_TX_AUTH + self.chain_id + self.canonical_unsigned_bytes()

    def serialize(self) -> bytes:
        assert len(self.signature) == 64
        return self.canonical_unsigned_bytes() + self.signature

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))

    @classmethod
    def deserialize(cls, data: bytes) -> TransparentTransferTx:
        env, rest = TxEnvelope.deserialize(data)
        if env.tx_type != TX_TYPE_TRANSPARENT_TRANSFER:
            raise ValueError(f"Expected TransparentTransfer (1), got {env.tx_type}")
        if len(rest) != 96 + 64:
            raise ValueError(f"Payload length mismatch: {len(rest)} != 160")
        sender_pubkey = rest[0:32]
        recipient = rest[32:64]
        amount = int.from_bytes(rest[64:80], "little")
        fee_atoms = struct.unpack("<Q", rest[80:88])[0]
        nonce = struct.unpack("<Q", rest[88:96])[0]
        signature = rest[96:160]
        return cls(
            chain_id=env.chain_id,
            sender_pubkey=sender_pubkey,
            recipient=recipient,
            amount=amount,
            fee_atoms=fee_atoms,
            nonce=nonce,
            signature=signature,
            version=env.tx_version,
        )


# ---------------------------------------------------------------------------
# Type 2: ConfigureGuardians
# ---------------------------------------------------------------------------


@dataclass
class ConfigureGuardiansTx:
    chain_id: bytes
    account_pubkey: bytes  # 32 bytes
    nonce: int  # u64
    fee_atoms: int  # u64
    guardian_keys: list[bytes]  # 7 distinct 32-byte keys = 224 bytes
    new_recipient_delay: int  # u32
    withdrawal_delay: int  # u32
    allowance_limit: int  # u128
    allowance_window_len: int  # u64
    recovery_key: bytes  # 32 bytes
    owner_sig: bytes = b"\x00" * 64
    guardian_sigs: list[tuple[int, bytes]] = field(default_factory=list)  # (index, sig)
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_CONFIGURE_GUARDIANS

    @property
    def account_address(self) -> bytes:
        return derive_address(self.account_pubkey)

    def unsigned_payload(self) -> bytes:
        assert len(self.guardian_keys) == 7
        assert len(set(self.guardian_keys)) == 7
        guardians_raw = b"".join(self.guardian_keys)
        return (
            self.account_pubkey
            + struct.pack("<Q", self.nonce)
            + struct.pack("<Q", self.fee_atoms)
            + guardians_raw
            + struct.pack("<I", self.new_recipient_delay)
            + struct.pack("<I", self.withdrawal_delay)
            + self.allowance_limit.to_bytes(16, "little")
            + struct.pack("<Q", self.allowance_window_len)
            + self.recovery_key
        )

    def canonical_unsigned_bytes(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        quorum_count = struct.pack("<B", len(self.guardian_sigs))
        indices = b"".join(struct.pack("<B", idx) for idx, _ in sorted(self.guardian_sigs, key=lambda x: x[0]))
        return envelope + self.unsigned_payload() + quorum_count + indices

    def signing_preimage(self) -> bytes:
        return DOM_TX_AUTH + self.chain_id + self.canonical_unsigned_bytes()

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        raw = envelope + self.unsigned_payload() + self.owner_sig
        raw += struct.pack("<B", len(self.guardian_sigs))
        for idx, sig in sorted(self.guardian_sigs, key=lambda x: x[0]):
            raw += struct.pack("<B", idx) + sig
        return raw

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))


# ---------------------------------------------------------------------------
# Type 3: GuardianAction
# ---------------------------------------------------------------------------


@dataclass
class GuardianActionTx:
    chain_id: bytes
    account: bytes  # 32 bytes (address)
    action_type: int  # u8
    fee_atoms: int  # u64
    params: bytes  # arbitrary parameter bytes
    guardian_sigs: list[tuple[int, bytes]]  # (guardian_index, 64-byte sig)
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_GUARDIAN_ACTION

    def unsigned_payload(self) -> bytes:
        return (
            self.account
            + struct.pack("<B", self.action_type)
            + struct.pack("<Q", self.fee_atoms)
            + struct.pack("<I", len(self.params))
            + self.params
        )

    def canonical_unsigned_bytes(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        quorum_count = struct.pack("<B", len(self.guardian_sigs))
        indices = b"".join(struct.pack("<B", idx) for idx, _ in sorted(self.guardian_sigs, key=lambda x: x[0]))
        return envelope + self.unsigned_payload() + quorum_count + indices

    def signing_preimage(self) -> bytes:
        return DOM_TX_AUTH + self.chain_id + self.canonical_unsigned_bytes()

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        raw = envelope + self.unsigned_payload()
        raw += struct.pack("<B", len(self.guardian_sigs))
        for idx, sig in sorted(self.guardian_sigs, key=lambda x: x[0]):
            raw += struct.pack("<B", idx) + sig
        return raw

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))


# ---------------------------------------------------------------------------
# Type 4: CancelPendingTransfer
# ---------------------------------------------------------------------------


@dataclass
class CancelPendingTransferTx:
    chain_id: bytes
    sender_pubkey: bytes  # 32 bytes
    transfer_id: bytes  # 32 bytes
    fee_atoms: int  # u64
    nonce: int  # u64
    sender_sig: bytes = b"\x00" * 64
    guardian_sigs: list[tuple[int, bytes]] = field(default_factory=list)  # 4-of-7
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_CANCEL_PENDING

    @property
    def sender_address(self) -> bytes:
        return derive_address(self.sender_pubkey)

    def unsigned_payload(self) -> bytes:
        return (
            self.sender_pubkey
            + self.transfer_id
            + struct.pack("<Q", self.fee_atoms)
            + struct.pack("<Q", self.nonce)
        )

    def canonical_unsigned_bytes(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        quorum_count = struct.pack("<B", len(self.guardian_sigs))
        indices = b"".join(struct.pack("<B", idx) for idx, _ in sorted(self.guardian_sigs, key=lambda x: x[0]))
        return envelope + self.unsigned_payload() + quorum_count + indices

    def signing_preimage(self) -> bytes:
        return DOM_TX_AUTH + self.chain_id + self.canonical_unsigned_bytes()

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        raw = envelope + self.unsigned_payload() + self.sender_sig
        raw += struct.pack("<B", len(self.guardian_sigs))
        for idx, sig in sorted(self.guardian_sigs, key=lambda x: x[0]):
            raw += struct.pack("<B", idx) + sig
        return raw

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))


# ---------------------------------------------------------------------------
# Type 5: ShieldedTransfer (Orchard-only)
# ---------------------------------------------------------------------------


@dataclass
class ShieldedTransferTx:
    chain_id: bytes
    fee_atoms: int  # u64 (fee leaving Orchard pool to miner)
    orchard_bundle_bytes: bytes  # Canonical ZIP-225 Section 7 bundle
    nullifiers: list[bytes] = field(default_factory=list)  # Extracted for stateful checking
    anchor: bytes = ORCHARD_EMPTY_ROOT_BYTES
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_SHIELDED_TRANSFER

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        return envelope + struct.pack("<Q", self.fee_atoms) + self.orchard_bundle_bytes

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))


# ---------------------------------------------------------------------------
# Type 6: TransparentToShielded (Shielding)
# ---------------------------------------------------------------------------


@dataclass
class TransparentToShieldedTx:
    chain_id: bytes
    sender_pubkey: bytes  # 32 bytes
    nonce: int  # u64
    shielded_amount: int  # u128 (amount entering Orchard pool)
    fee_atoms: int  # u64 (fee to miner)
    orchard_bundle_bytes: bytes  # Output bundle creating shielded notes
    sender_sig: bytes = b"\x00" * 64
    guardian_sigs: list[tuple[int, bytes]] = field(default_factory=list)  # If guardian-protected
    nullifiers: list[bytes] = field(default_factory=list)
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_TRANSPARENT_TO_SHIELDED

    @property
    def sender_address(self) -> bytes:
        return derive_address(self.sender_pubkey)

    def unsigned_payload(self) -> bytes:
        return (
            self.sender_pubkey
            + struct.pack("<Q", self.nonce)
            + self.shielded_amount.to_bytes(16, "little")
            + struct.pack("<Q", self.fee_atoms)
            + struct.pack("<I", len(self.orchard_bundle_bytes))
            + self.orchard_bundle_bytes
        )

    def canonical_unsigned_bytes(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        quorum_count = struct.pack("<B", len(self.guardian_sigs))
        indices = b"".join(struct.pack("<B", idx) for idx, _ in sorted(self.guardian_sigs, key=lambda x: x[0]))
        return envelope + self.unsigned_payload() + quorum_count + indices

    def signing_preimage(self) -> bytes:
        return DOM_TX_AUTH + self.chain_id + self.canonical_unsigned_bytes()

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        raw = envelope + self.unsigned_payload() + self.sender_sig
        raw += struct.pack("<B", len(self.guardian_sigs))
        for idx, sig in sorted(self.guardian_sigs, key=lambda x: x[0]):
            raw += struct.pack("<B", idx) + sig
        return raw

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))


# ---------------------------------------------------------------------------
# Type 7: ShieldedToTransparent (Deshielding)
# ---------------------------------------------------------------------------


@dataclass
class ShieldedToTransparentTx:
    chain_id: bytes
    recipient: bytes  # 32 bytes (transparent address)
    release_amount: int  # u128 (net amount arriving at transparent account)
    fee_atoms: int  # u64 (fee to miner)
    orchard_bundle_bytes: bytes  # Spend bundle
    nullifiers: list[bytes] = field(default_factory=list)
    anchor: bytes = ORCHARD_EMPTY_ROOT_BYTES
    version: int = TX_VERSION_1

    @property
    def tx_type(self) -> int:
        return TX_TYPE_SHIELDED_TO_TRANSPARENT

    def serialize(self) -> bytes:
        envelope = TxEnvelope(self.tx_type, self.version, self.chain_id).serialize()
        payload = (
            self.recipient
            + self.release_amount.to_bytes(16, "little")
            + struct.pack("<Q", self.fee_atoms)
            + struct.pack("<I", len(self.orchard_bundle_bytes))
            + self.orchard_bundle_bytes
        )
        return envelope + payload

    @property
    def tx_id(self) -> bytes:
        return compute_tx_id(self.serialize())

    @property
    def min_fee(self) -> int:
        return minimum_fee(len(self.serialize()))
