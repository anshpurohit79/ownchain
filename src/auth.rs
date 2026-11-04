//! Cryptographic authentication for OwnChain v1 transactions.
//!
//! Defined in `docs/protocol-v1.md` §7.2, §7.5 and ADR-002 §2.1.
//!
//! Provides strict Ed25519 public-key parsing, strict signature verification,
//! centralized signing-preimage construction, guardian metadata binding,
//! and guardian quorum verification.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::account::derive_address;
use crate::hash::Hash;

/// Domain separator for transaction signing preimages: `b"OwnChain/TxAuth/v1"`.
pub const DOM_TX_AUTH: &[u8] = b"OwnChain/TxAuth/v1";

// ---------------------------------------------------------------------------
// Authoritative GuardianAction ID Registry (docs/protocol-v1.md §7.1, §7.5)
// ---------------------------------------------------------------------------

/// Action 1: Strengthen delays (3-of-7 quorum).
pub const ACTION_STRENGTHEN_DELAYS: u8 = 1;
/// Action 2: Strengthen allowance (3-of-7 quorum).
pub const ACTION_STRENGTHEN_ALLOWANCE: u8 = 2;
/// Action 3: Weaken delays (4-of-7 quorum).
pub const ACTION_WEAKEN_DELAYS: u8 = 3;
/// Action 4: Weaken allowance (4-of-7 quorum).
pub const ACTION_WEAKEN_ALLOWANCE: u8 = 4;
/// Action 5: Freeze account (4-of-7 quorum).
pub const ACTION_FREEZE: u8 = 5;
/// Action 6: Unfreeze account (4-of-7 quorum).
pub const ACTION_UNFREEZE: u8 = 6;
/// Action 7: Emergency recovery (4-of-7 quorum).
pub const ACTION_EMERGENCY_RECOVERY: u8 = 7;
/// Action 8: Replace guardian keys (4-of-7 quorum).
pub const ACTION_REPLACE_GUARDIANS: u8 = 8;
/// Action 9: Replace recovery key (4-of-7 quorum).
pub const ACTION_REPLACE_RECOVERY_KEY: u8 = 9;

/// Returns the required guardian quorum for a given `action_type`.
///
/// Quorum rules:
/// - Actions 1, 2 (strengthening): 3-of-7 quorum.
/// - Actions 3, 4 (weakening): 4-of-7 quorum.
/// - Actions 5, 6 (freeze/unfreeze): 4-of-7 quorum.
/// - Action 7 (emergency recovery): 4-of-7 quorum.
/// - Actions 8, 9 (guardian/recovery key replacement): 4-of-7 quorum.
pub fn guardian_action_quorum(action_type: u8) -> Result<usize, AuthError> {
    match action_type {
        ACTION_STRENGTHEN_DELAYS | ACTION_STRENGTHEN_ALLOWANCE => Ok(3),
        ACTION_WEAKEN_DELAYS
        | ACTION_WEAKEN_ALLOWANCE
        | ACTION_FREEZE
        | ACTION_UNFREEZE
        | ACTION_EMERGENCY_RECOVERY
        | ACTION_REPLACE_GUARDIANS
        | ACTION_REPLACE_RECOVERY_KEY => Ok(4),
        other => Err(AuthError::UnsupportedActionType { action_type: other }),
    }
}

/// Validates that parameters for `action_type` match the required consensus length.
pub fn validate_guardian_action_params(action_type: u8, params: &[u8]) -> Result<(), AuthError> {
    let expected = match action_type {
        ACTION_STRENGTHEN_DELAYS | ACTION_WEAKEN_DELAYS => 4,
        ACTION_STRENGTHEN_ALLOWANCE | ACTION_WEAKEN_ALLOWANCE => 24,
        ACTION_FREEZE | ACTION_UNFREEZE | ACTION_EMERGENCY_RECOVERY => 0,
        ACTION_REPLACE_GUARDIANS => 224,
        ACTION_REPLACE_RECOVERY_KEY => 32,
        other => return Err(AuthError::UnsupportedActionType { action_type: other }),
    };
    if params.len() != expected {
        return Err(AuthError::InvalidParamLength {
            action_type,
            expected,
            actual: params.len(),
        });
    }
    Ok(())
}

/// Authentication errors occurring during transaction authorization checks.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthError {
    /// Public key is invalid or fails strict point decompression.
    InvalidPublicKey,
    /// Signature is malformed or non-canonical.
    InvalidSignature,
    /// Strict signature verification failed.
    VerificationFailed,
    /// Public key does not derive the expected account address.
    AddressMismatch { expected: Hash, derived: Hash },
    /// Account does not have guardian protection enabled.
    GuardiansNotEnabled,
    /// Duplicate guardian index found in quorum signatures.
    DuplicateGuardianIndex { index: u8 },
    /// Guardian index out of bounds (must be 0..=6).
    GuardianIndexOutOfBounds { index: u8 },
    /// Number of valid guardian signatures does not meet required quorum.
    InsufficientGuardianQuorum { actual: usize, required: usize },
    /// Quorum count or signature list length is malformed.
    MalformedGuardianList,
    /// Payload has trailing unparsed bytes.
    TrailingData,
    /// Payload was truncated before all expected fields/signatures could be read.
    TruncatedPayload,
    /// Unsupported guardian action type.
    UnsupportedActionType { action_type: u8 },
    /// Invalid parameter length for guardian action.
    InvalidParamLength {
        action_type: u8,
        expected: usize,
        actual: usize,
    },
    /// Duplicate guardian public keys in 7-key configuration.
    DuplicateGuardianKey,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            AuthError::InvalidSignature => write!(f, "invalid Ed25519 signature format"),
            AuthError::VerificationFailed => write!(f, "Ed25519 signature verification failed"),
            AuthError::AddressMismatch { expected, derived } => {
                write!(
                    f,
                    "address mismatch: expected {}, derived {}",
                    expected.to_hex(),
                    derived.to_hex()
                )
            }
            AuthError::GuardiansNotEnabled => write!(f, "guardians not enabled on account"),
            AuthError::DuplicateGuardianIndex { index } => {
                write!(f, "duplicate guardian index in quorum: {index}")
            }
            AuthError::GuardianIndexOutOfBounds { index } => {
                write!(f, "guardian index out of bounds: {index} (must be 0..6)")
            }
            AuthError::InsufficientGuardianQuorum { actual, required } => {
                write!(
                    f,
                    "insufficient guardian quorum: {actual} signatures, required {required}"
                )
            }
            AuthError::MalformedGuardianList => write!(f, "malformed guardian signature list"),
            AuthError::TrailingData => write!(f, "unexpected trailing data in signature section"),
            AuthError::TruncatedPayload => write!(f, "truncated authorization payload"),
            AuthError::UnsupportedActionType { action_type } => {
                write!(f, "unsupported guardian action type: {action_type}")
            }
            AuthError::InvalidParamLength {
                action_type,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid param length for action {action_type}: expected {expected}, got {actual}"
                )
            }
            AuthError::DuplicateGuardianKey => {
                write!(f, "duplicate guardian public key in 7-key set")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Centralized construction of the canonical signing preimage:
///
/// `preimage = UTF8("OwnChain/TxAuth/v1") || chain_id[32] || canonical_unsigned_tx_bytes`
///
/// The actual concatenated message bytes are returned without applying any
/// additional hashing (such as BLAKE3 or SHA-256).
pub fn compute_signing_preimage(chain_id: Hash, canonical_unsigned_tx: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(DOM_TX_AUTH.len() + 32 + canonical_unsigned_tx.len());
    preimage.extend_from_slice(DOM_TX_AUTH);
    preimage.extend_from_slice(chain_id.as_bytes());
    preimage.extend_from_slice(canonical_unsigned_tx);
    preimage
}

/// Constructs canonical unsigned transaction bytes binding guardian metadata:
///
/// `canonical_unsigned_tx = prefix || quorum_count: u8 || repeated(guardian_index: u8)`
///
/// Deterministically binds declared quorum count and all guardian indices
/// while omitting 64-byte signature values.
pub fn canonical_unsigned_with_indices(prefix: &[u8], guardian_indices: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 1 + guardian_indices.len());
    out.extend_from_slice(prefix);
    out.push(guardian_indices.len() as u8);
    out.extend_from_slice(guardian_indices);
    out
}

/// Constructs canonical unsigned transaction bytes binding parsed guardian entries:
///
/// `canonical_unsigned_tx = prefix || quorum_count: u8 || repeated(guardian_index: u8)`
pub fn canonical_unsigned_with_guardians(prefix: &[u8], entries: &[GuardianSigEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 1 + entries.len());
    out.extend_from_slice(prefix);
    out.push(entries.len() as u8);
    for entry in entries {
        out.push(entry.index);
    }
    out
}

/// Strict Ed25519 signature verification using `verify_strict`.
///
/// Rejects non-canonical points, small-order points, and non-canonical signatures.
/// The raw unhashed `preimage` message bytes are passed directly to `verify_strict`.
pub fn verify_signature(
    pubkey_bytes: &[u8; 32],
    preimage: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), AuthError> {
    // 1. Strict public key parsing
    let verifying_key =
        VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| AuthError::InvalidPublicKey)?;

    // 2. Strict signature parsing
    let signature = Signature::from_bytes(sig_bytes);

    // 3. Strict RFC 8032 signature verification
    verifying_key
        .verify_strict(preimage, &signature)
        .map_err(|_| AuthError::VerificationFailed)?;

    Ok(())
}

/// Verifies that `pubkey_bytes` strictly parses and derives `expected_address`.
///
/// Derivation rule:
/// `BLAKE2b-256("OwnChain/Address/v1" || ed25519_public_key[32])`.
pub fn verify_address_derivation(
    pubkey_bytes: &[u8; 32],
    expected_address: Hash,
) -> Result<VerifyingKey, AuthError> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| AuthError::InvalidPublicKey)?;
    let derived = derive_address(pubkey_bytes);
    if derived != expected_address {
        return Err(AuthError::AddressMismatch {
            expected: expected_address,
            derived,
        });
    }
    Ok(vk)
}

/// A parsed guardian signature entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuardianSigEntry {
    /// 0-based index of the guardian in the 7-key set (`0..=6`).
    pub index: u8,
    /// 64-byte Ed25519 signature.
    pub signature: [u8; 64],
}

/// Parses the trailing guardian signature list from `slice`.
///
/// Layout: `quorum_count: u8 || repeated(guardian_index: u8 || signature: [u8; 64])`.
/// Enforces exact length matching and rejects trailing bytes.
pub fn parse_guardian_sigs(slice: &[u8]) -> Result<Vec<GuardianSigEntry>, AuthError> {
    if slice.is_empty() {
        return Err(AuthError::TruncatedPayload);
    }
    let count = slice[0] as usize;
    let expected_len = 1 + count * 65;
    if slice.len() < expected_len {
        return Err(AuthError::TruncatedPayload);
    }
    if slice.len() > expected_len {
        return Err(AuthError::TrailingData);
    }

    let mut entries = Vec::with_capacity(count);
    let mut offset = 1;
    for _ in 0..count {
        let index = slice[offset];
        offset += 1;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&slice[offset..offset + 64]);
        offset += 64;
        entries.push(GuardianSigEntry {
            index,
            signature: sig,
        });
    }

    Ok(entries)
}

/// Validates and verifies a set of guardian signatures against registered guardian keys:
///
/// 1. Requires `entries.len() >= required_quorum`.
/// 2. Requires all `guardian_index < 7`.
/// 3. Requires all `guardian_index` to be pairwise distinct (no duplicate votes).
/// 4. Verifies each signature using `verify_strict` over `preimage` against `registered_guardians[index]`.
pub fn verify_guardian_quorum(
    registered_guardians: &[[u8; 32]; 7],
    preimage: &[u8],
    entries: &[GuardianSigEntry],
    required_quorum: usize,
) -> Result<(), AuthError> {
    if entries.len() < required_quorum {
        return Err(AuthError::InsufficientGuardianQuorum {
            actual: entries.len(),
            required: required_quorum,
        });
    }

    let mut seen_indices = [false; 7];

    for entry in entries {
        if entry.index >= 7 {
            return Err(AuthError::GuardianIndexOutOfBounds { index: entry.index });
        }
        let idx = entry.index as usize;
        if seen_indices[idx] {
            return Err(AuthError::DuplicateGuardianIndex { index: entry.index });
        }
        seen_indices[idx] = true;

        let guardian_pubkey = &registered_guardians[idx];
        verify_signature(guardian_pubkey, preimage, &entry.signature)?;
    }

    Ok(())
}

/// Validates that 7 guardian public keys are all strictly valid Ed25519 keys
/// and are pairwise distinct.
pub fn validate_guardian_keys_set(guardians: &[[u8; 32]; 7]) -> Result<(), AuthError> {
    for (i, g1) in guardians.iter().enumerate() {
        VerifyingKey::from_bytes(g1).map_err(|_| AuthError::InvalidPublicKey)?;
        for g2 in &guardians[i + 1..] {
            if g1 == g2 {
                return Err(AuthError::DuplicateGuardianKey);
            }
        }
    }
    Ok(())
}

/// Validates that a 32-byte key is a strictly valid Ed25519 public key.
pub fn validate_pubkey(key: &[u8; 32]) -> Result<VerifyingKey, AuthError> {
    VerifyingKey::from_bytes(key).map_err(|_| AuthError::InvalidPublicKey)
}

/// Parsed header fields and authorization of a Type 6 (TransparentToShielded) transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type6AuthInfo {
    pub sender_key: [u8; 32],
    pub sender_address: Hash,
    pub nonce: u64,
    pub shielded_amount: u128,
    pub fee_atoms: u64,
    pub bundle_bytes: Vec<u8>,
    pub guardian_entries: Vec<GuardianSigEntry>,
}

/// Verifies Type 6 (TransparentToShielded) sender and guardian authorization.
///
/// Preserves the cryptographic authentication implementation for Type 6 while consensus
/// enforces a fail-closed gate pending full Orchard proof verification.
pub fn verify_type6_authorization(
    chain_id: Hash,
    raw_tx: &[u8],
    is_guardian_protected: bool,
    registered_guardians: &[[u8; 32]; 7],
) -> Result<Type6AuthInfo, AuthError> {
    if raw_tx.len() < crate::tx::TX_ENVELOPE_LEN + 68 {
        return Err(AuthError::TruncatedPayload);
    }
    let payload = &raw_tx[crate::tx::TX_ENVELOPE_LEN..];
    let mut sender_key = [0u8; 32];
    sender_key.copy_from_slice(&payload[..32]);

    let nonce = u64::from_le_bytes(payload[32..40].try_into().unwrap());
    let shielded_amount = u128::from_le_bytes(payload[40..56].try_into().unwrap());
    let fee_atoms = u64::from_le_bytes(payload[56..64].try_into().unwrap());
    let bundle_len = u32::from_le_bytes(payload[64..68].try_into().unwrap()) as usize;

    let fixed_unsigned_len = 68usize;
    let unsigned_payload_len = fixed_unsigned_len
        .checked_add(bundle_len)
        .ok_or(AuthError::TruncatedPayload)?;
    let sender_sig_end = unsigned_payload_len
        .checked_add(64)
        .ok_or(AuthError::TruncatedPayload)?;

    if payload.len() < sender_sig_end + 1 {
        return Err(AuthError::TruncatedPayload);
    }

    let unsigned_end = crate::tx::TX_ENVELOPE_LEN + unsigned_payload_len;
    let unsigned_prefix = &raw_tx[..unsigned_end];

    let sender_sig_offset = crate::tx::TX_ENVELOPE_LEN + unsigned_payload_len;
    let mut sender_sig = [0u8; 64];
    sender_sig.copy_from_slice(&raw_tx[sender_sig_offset..sender_sig_offset + 64]);

    let guardian_section = &raw_tx[sender_sig_offset + 64..];
    let guardian_entries = parse_guardian_sigs(guardian_section)?;

    let unsigned_tx = canonical_unsigned_with_guardians(unsigned_prefix, &guardian_entries);
    let preimage = compute_signing_preimage(chain_id, &unsigned_tx);

    verify_signature(&sender_key, &preimage, &sender_sig)?;

    if is_guardian_protected {
        verify_guardian_quorum(registered_guardians, &preimage, &guardian_entries, 4)?;
    } else if !guardian_entries.is_empty() {
        return Err(AuthError::TrailingData);
    }

    let bundle_bytes = payload[68..68 + bundle_len].to_vec();
    let sender_address = derive_address(&sender_key);

    Ok(Type6AuthInfo {
        sender_key,
        sender_address,
        nonce,
        shielded_amount,
        fee_atoms,
        bundle_bytes,
        guardian_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_address_derivation_known_vectors() {
        // Known vector 1: Alice from docs/test-vectors-v1-transparent.json
        let alice_pk =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let alice_addr_expected =
            hex::decode("7e62649584947abab19fb34633e990ce49dbbda3e80e7bb6848d88d4928f40d0")
                .unwrap();
        let mut alice_pk_bytes = [0u8; 32];
        alice_pk_bytes.copy_from_slice(&alice_pk);
        let alice_derived = derive_address(&alice_pk_bytes);
        assert_eq!(alice_derived.as_bytes(), &alice_addr_expected[..]);
        assert!(verify_address_derivation(&alice_pk_bytes, alice_derived).is_ok());

        // Known vector 2: Bob from docs/test-vectors-v1-transparent.json
        let bob_pk =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap();
        let bob_addr_expected =
            hex::decode("010b76206e2af1dd1b2f84cb9c9f3ebf7d37f7065f1373a71f244a7790369ab4")
                .unwrap();
        let mut bob_pk_bytes = [0u8; 32];
        bob_pk_bytes.copy_from_slice(&bob_pk);
        let bob_derived = derive_address(&bob_pk_bytes);
        assert_eq!(bob_derived.as_bytes(), &bob_addr_expected[..]);
        assert!(verify_address_derivation(&bob_pk_bytes, bob_derived).is_ok());

        // Address mismatch detection
        assert!(verify_address_derivation(&alice_pk_bytes, bob_derived).is_err());
    }

    #[test]
    fn test_preimage_computation_golden_vector() {
        // Golden vector from docs/test-vectors-v1-transparent.json
        let chain_id_bytes =
            hex::decode("0459d324aafefe44f9281e585b91b8fb4fde3a1dfb945db6370c18c11b1a5ccc")
                .unwrap();
        let mut chain_id_arr = [0u8; 32];
        chain_id_arr.copy_from_slice(&chain_id_bytes);
        let chain_id = Hash::from(chain_id_arr);

        let unsigned_tx = hex::decode(
            "0101000459d324aafefe44f9281e585b91b8fb4fde3a1dfb945db6370c18c11b1a5cccd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010b76206e2af1dd1b2f84cb9c9f3ebf7d37f7065f1373a71f244a7790369ab400e1f5050000000000000000000000002c4c0000000000000000000000000000",
        )
        .unwrap();

        let expected_preimage = hex::decode(
            "4f776e436861696e2f5478417574682f76310459d324aafefe44f9281e585b91b8fb4fde3a1dfb945db6370c18c11b1a5ccc0101000459d324aafefe44f9281e585b91b8fb4fde3a1dfb945db6370c18c11b1a5cccd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010b76206e2af1dd1b2f84cb9c9f3ebf7d37f7065f1373a71f244a7790369ab400e1f5050000000000000000000000002c4c0000000000000000000000000000",
        )
        .unwrap();

        let computed = compute_signing_preimage(chain_id, &unsigned_tx);
        assert_eq!(computed, expected_preimage);

        // Verify known signature over this exact unhashed preimage
        let alice_pk_bytes: [u8; 32] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();

        let sig_bytes: [u8; 64] = hex::decode(
            "5ce5376b58ffac25d51f1542ee088e05711335f01991517a2cbbb85b6973b390ec254b207d1bc2d57dbce08ff08afde88a580c0549247ac3a109a4bb08ae670d",
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            verify_signature(&alice_pk_bytes, &computed, &sig_bytes),
            Ok(())
        );
    }

    #[test]
    fn test_guardian_action_quorums_and_param_validation() {
        // Action 1: Strengthen delays (3-of-7, 4 bytes)
        assert_eq!(guardian_action_quorum(1), Ok(3));
        assert!(validate_guardian_action_params(1, &[1, 2, 3, 4]).is_ok());
        assert!(validate_guardian_action_params(1, &[1, 2, 3]).is_err());

        // Action 2: Strengthen allowance (3-of-7, 24 bytes)
        assert_eq!(guardian_action_quorum(2), Ok(3));
        assert!(validate_guardian_action_params(2, &[0u8; 24]).is_ok());
        assert!(validate_guardian_action_params(2, &[0u8; 20]).is_err());

        // Action 3: Weaken delays (4-of-7, 4 bytes)
        assert_eq!(guardian_action_quorum(3), Ok(4));
        assert!(validate_guardian_action_params(3, &[1, 2, 3, 4]).is_ok());

        // Action 4: Weaken allowance (4-of-7, 24 bytes)
        assert_eq!(guardian_action_quorum(4), Ok(4));
        assert!(validate_guardian_action_params(4, &[0u8; 24]).is_ok());

        // Action 5: Freeze (4-of-7, 0 bytes)
        assert_eq!(guardian_action_quorum(5), Ok(4));
        assert!(validate_guardian_action_params(5, &[]).is_ok());
        assert!(validate_guardian_action_params(5, &[1]).is_err());

        // Action 6: Unfreeze (4-of-7, 0 bytes)
        assert_eq!(guardian_action_quorum(6), Ok(4));
        assert!(validate_guardian_action_params(6, &[]).is_ok());
        assert!(validate_guardian_action_params(6, &[1]).is_err());

        // Action 7: Emergency recovery (4-of-7, 0 bytes)
        assert_eq!(guardian_action_quorum(7), Ok(4));
        assert!(validate_guardian_action_params(7, &[]).is_ok());
        assert!(validate_guardian_action_params(7, &[1]).is_err());

        // Action 8: Replace guardian keys (4-of-7, 224 bytes)
        assert_eq!(guardian_action_quorum(8), Ok(4));
        assert!(validate_guardian_action_params(8, &[0u8; 224]).is_ok());
        assert!(validate_guardian_action_params(8, &[0u8; 200]).is_err());

        // Action 9: Replace recovery key (4-of-7, 32 bytes)
        assert_eq!(guardian_action_quorum(9), Ok(4));
        assert!(validate_guardian_action_params(9, &[0u8; 32]).is_ok());
        assert!(validate_guardian_action_params(9, &[0u8; 16]).is_err());

        // Action 0 or 10: unsupported
        assert!(guardian_action_quorum(0).is_err());
        assert!(guardian_action_quorum(10).is_err());
        assert!(validate_guardian_action_params(0, &[]).is_err());
        assert!(validate_guardian_action_params(10, &[]).is_err());
    }

    #[test]
    fn test_verify_signature_strict() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let preimage = b"valid message";
        let sig = signing_key.sign(preimage).to_bytes();

        // Valid signature passes
        assert_eq!(verify_signature(&pubkey, preimage, &sig), Ok(()));

        // Tampered message fails
        assert_eq!(
            verify_signature(&pubkey, b"invalid message", &sig),
            Err(AuthError::VerificationFailed)
        );

        // All-zero signature fails
        assert_eq!(
            verify_signature(&pubkey, preimage, &[0u8; 64]),
            Err(AuthError::VerificationFailed)
        );

        // Invalid public key (decompression fails because not on curve)
        let invalid_pk = [2u8; 32];
        assert_eq!(
            verify_signature(&invalid_pk, preimage, &sig),
            Err(AuthError::InvalidPublicKey)
        );
    }

    #[test]
    fn test_parse_guardian_sigs() {
        let mut raw = Vec::new();
        raw.push(2); // 2 guardians
        raw.push(0);
        raw.extend_from_slice(&[1u8; 64]);
        raw.push(1);
        raw.extend_from_slice(&[2u8; 64]);

        let entries = parse_guardian_sigs(&raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[0].signature, [1u8; 64]);
        assert_eq!(entries[1].index, 1);
        assert_eq!(entries[1].signature, [2u8; 64]);

        // Truncated list fails
        assert_eq!(
            parse_guardian_sigs(&raw[..raw.len() - 1]),
            Err(AuthError::TruncatedPayload)
        );

        // Trailing data fails
        raw.push(0);
        assert_eq!(parse_guardian_sigs(&raw), Err(AuthError::TrailingData));
    }

    #[test]
    fn test_guardian_quorum_validation() {
        let signers: Vec<SigningKey> = (0..7)
            .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
            .collect();
        let pubkeys: [[u8; 32]; 7] = [
            signers[0].verifying_key().to_bytes(),
            signers[1].verifying_key().to_bytes(),
            signers[2].verifying_key().to_bytes(),
            signers[3].verifying_key().to_bytes(),
            signers[4].verifying_key().to_bytes(),
            signers[5].verifying_key().to_bytes(),
            signers[6].verifying_key().to_bytes(),
        ];

        let msg = b"quorum check";
        let sig0 = signers[0].sign(msg).to_bytes();
        let sig1 = signers[1].sign(msg).to_bytes();
        let sig2 = signers[2].sign(msg).to_bytes();

        let entries = vec![
            GuardianSigEntry {
                index: 0,
                signature: sig0,
            },
            GuardianSigEntry {
                index: 1,
                signature: sig1,
            },
            GuardianSigEntry {
                index: 2,
                signature: sig2,
            },
        ];

        // 3-of-7 passes when required is 3
        assert_eq!(verify_guardian_quorum(&pubkeys, msg, &entries, 3), Ok(()));

        // 3-of-7 fails when required is 4
        assert_eq!(
            verify_guardian_quorum(&pubkeys, msg, &entries, 4),
            Err(AuthError::InsufficientGuardianQuorum {
                actual: 3,
                required: 4
            })
        );

        // Duplicate index fails
        let dup_entries = vec![
            GuardianSigEntry {
                index: 0,
                signature: sig0,
            },
            GuardianSigEntry {
                index: 0,
                signature: sig0,
            },
            GuardianSigEntry {
                index: 2,
                signature: sig2,
            },
        ];
        assert_eq!(
            verify_guardian_quorum(&pubkeys, msg, &dup_entries, 3),
            Err(AuthError::DuplicateGuardianIndex { index: 0 })
        );

        // Index out of bounds fails
        let oob_entries = vec![
            GuardianSigEntry {
                index: 7,
                signature: sig0,
            },
            GuardianSigEntry {
                index: 1,
                signature: sig1,
            },
            GuardianSigEntry {
                index: 2,
                signature: sig2,
            },
        ];
        assert_eq!(
            verify_guardian_quorum(&pubkeys, msg, &oob_entries, 3),
            Err(AuthError::GuardianIndexOutOfBounds { index: 7 })
        );

        // Invalid signature fails
        let bad_sig_entries = vec![
            GuardianSigEntry {
                index: 0,
                signature: sig1,
            }, // wrong signature for guardian 0
            GuardianSigEntry {
                index: 1,
                signature: sig1,
            },
            GuardianSigEntry {
                index: 2,
                signature: sig2,
            },
        ];
        assert_eq!(
            verify_guardian_quorum(&pubkeys, msg, &bad_sig_entries, 3),
            Err(AuthError::VerificationFailed)
        );
    }

    #[test]
    fn test_validate_guardian_keys_set() {
        let keys: Vec<[u8; 32]> = (0..7)
            .map(|i| {
                SigningKey::from_bytes(&[i + 1; 32])
                    .verifying_key()
                    .to_bytes()
            })
            .collect();
        let mut set = [
            keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6],
        ];

        assert_eq!(validate_guardian_keys_set(&set), Ok(()));

        // Duplicate key fails
        set[1] = set[0];
        assert_eq!(
            validate_guardian_keys_set(&set),
            Err(AuthError::DuplicateGuardianKey)
        );
    }

    #[test]
    fn test_type6_authorization_helpers() {
        let chain_id = crate::hash::chain_id("devnet");
        let sender_key = SigningKey::from_bytes(&[0x42; 32]);
        let sender_pub = sender_key.verifying_key().to_bytes();
        let sender_addr = derive_address(&sender_pub);

        let guardian_keys: Vec<SigningKey> = (0x10..0x17)
            .map(|b| SigningKey::from_bytes(&[b; 32]))
            .collect();
        let guardian_pubs: [[u8; 32]; 7] = [
            guardian_keys[0].verifying_key().to_bytes(),
            guardian_keys[1].verifying_key().to_bytes(),
            guardian_keys[2].verifying_key().to_bytes(),
            guardian_keys[3].verifying_key().to_bytes(),
            guardian_keys[4].verifying_key().to_bytes(),
            guardian_keys[5].verifying_key().to_bytes(),
            guardian_keys[6].verifying_key().to_bytes(),
        ];

        // 1. Unprotected account: valid sender signature, 0 guardian sigs
        let mut unsigned_prefix = Vec::new();
        unsigned_prefix.push(crate::tx::TX_TYPE_TRANSPARENT_TO_SHIELDED);
        unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
        unsigned_prefix.extend_from_slice(chain_id.as_bytes());
        unsigned_prefix.extend_from_slice(&sender_pub);
        unsigned_prefix.extend_from_slice(&1u64.to_le_bytes()); // nonce
        unsigned_prefix.extend_from_slice(&50_000_000u128.to_le_bytes()); // shielded_amount
        unsigned_prefix.extend_from_slice(&20_000u64.to_le_bytes()); // fee_atoms
        unsigned_prefix.extend_from_slice(&0u32.to_le_bytes()); // bundle_len = 0

        let unsigned_tx = canonical_unsigned_with_indices(&unsigned_prefix, &[]);
        let preimage = compute_signing_preimage(chain_id, &unsigned_tx);
        let sender_sig = sender_key.sign(&preimage);

        let mut raw_tx = unsigned_prefix.clone();
        raw_tx.extend_from_slice(&sender_sig.to_bytes());
        raw_tx.push(0); // 0 guardian signatures

        let info = verify_type6_authorization(chain_id, &raw_tx, false, &guardian_pubs).unwrap();
        assert_eq!(info.sender_address, sender_addr);
        assert_eq!(info.nonce, 1);
        assert_eq!(info.shielded_amount, 50_000_000);
        assert_eq!(info.fee_atoms, 20_000);
        assert!(info.bundle_bytes.is_empty());
        assert!(info.guardian_entries.is_empty());

        // Unprotected account carrying guardian signatures fails with TrailingData
        let unsigned_tx_spur = canonical_unsigned_with_indices(&unsigned_prefix, &[0]);
        let preimage_spur = compute_signing_preimage(chain_id, &unsigned_tx_spur);
        let sender_sig_spur = sender_key.sign(&preimage_spur);

        let mut raw_spurious = unsigned_prefix.clone();
        raw_spurious.extend_from_slice(&sender_sig_spur.to_bytes());
        raw_spurious.push(1); // count = 1
        raw_spurious.push(0); // idx = 0
        raw_spurious.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            verify_type6_authorization(chain_id, &raw_spurious, false, &guardian_pubs),
            Err(AuthError::TrailingData)
        );

        // Protected account requires 4-of-7 quorum
        let indices = [0u8, 1, 2, 3];
        let unsigned_tx_prot = canonical_unsigned_with_indices(&unsigned_prefix, &indices);
        let preimage_prot = compute_signing_preimage(chain_id, &unsigned_tx_prot);
        let sender_sig_prot = sender_key.sign(&preimage_prot);

        let mut raw_prot = unsigned_prefix.clone();
        raw_prot.extend_from_slice(&sender_sig_prot.to_bytes());
        raw_prot.push(4);
        for &idx in &indices {
            raw_prot.push(idx);
            let g_sig = guardian_keys[idx as usize].sign(&preimage_prot);
            raw_prot.extend_from_slice(&g_sig.to_bytes());
        }

        let info_prot =
            verify_type6_authorization(chain_id, &raw_prot, true, &guardian_pubs).unwrap();
        assert_eq!(info_prot.guardian_entries.len(), 4);

        // Protected account with insufficient quorum (3-of-7) fails
        let indices_3 = [0u8, 1, 2];
        let unsigned_tx_3 = canonical_unsigned_with_indices(&unsigned_prefix, &indices_3);
        let preimage_3 = compute_signing_preimage(chain_id, &unsigned_tx_3);
        let sender_sig_3 = sender_key.sign(&preimage_3);

        let mut raw_3 = unsigned_prefix;
        raw_3.extend_from_slice(&sender_sig_3.to_bytes());
        raw_3.push(3);
        for &idx in &indices_3 {
            raw_3.push(idx);
            let g_sig = guardian_keys[idx as usize].sign(&preimage_3);
            raw_3.extend_from_slice(&g_sig.to_bytes());
        }
        assert_eq!(
            verify_type6_authorization(chain_id, &raw_3, true, &guardian_pubs),
            Err(AuthError::InsufficientGuardianQuorum {
                actual: 3,
                required: 4
            })
        );
    }
}
