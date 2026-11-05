//! Production stateless validation and adversarial digest-tampering test suite
//! for OwnChain Protocol v1 Cross-Pool transactions:
//! - Type 6 (TransparentToShielded)
//! - Type 7 (ShieldedToTransparent)

use ed25519_dalek::{Signer, SigningKey};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use ownchain::{
    hash::Hash,
    orchard_tree::EMPTY_ROOTS,
    orchard_tx::{
        self, compute_type6_bundle_auth_digest, compute_type7_bundle_auth_digest, serialize_bundle,
        validate_type6_transaction_stateless, validate_type7_transaction_stateless,
        verify_type6_guardian_signatures, OrchardValidationError,
    },
    tx::{EnvelopeError, TX_ENVELOPE_LEN},
};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn devnet_chain_id() -> Hash {
    Hash::new([0x42; 32])
}

fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

#[allow(dead_code)]
struct TestType6Data {
    raw_tx: Vec<u8>,
    sender_sk: SigningKey,
    sender_pk: [u8; 32],
    nonce: u64,
    shielded_amount: u128,
    fee_atoms: u64,
    bundle_bytes: Vec<u8>,
    sender_sig: [u8; 64],
    chain_id: Hash,
}

#[allow(clippy::too_many_arguments)]
fn build_valid_type6_tx(
    rng: &mut StdRng,
    pk: &ProvingKey,
    chain_id: Hash,
    sender_sk: &SigningKey,
    nonce: u64,
    shielded_amount: u64,
    fee_atoms: u64,
    guardian_signers: &[(u8, &SigningKey)],
) -> TestType6Data {
    let sender_pk = sender_sk.verifying_key().to_bytes();

    let recipient_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
    let recipient_fvk = FullViewingKey::from(&recipient_sk);
    let recipient_address = recipient_fvk.address_at(0u32, Scope::External);

    // Build Type 6 bundle: SPENDS_DISABLED, empty tree anchor
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .unwrap();

    let ovk = OutgoingViewingKey::from([0x55; 32]);
    builder
        .add_output(
            Some(ovk),
            recipient_address,
            NoteValue::from_raw(shielded_amount),
            [0u8; 512],
        )
        .unwrap();

    let (unauth_bundle, _) = builder.build::<i64>(&mut *rng).unwrap().unwrap();
    let proven_bundle = unauth_bundle.create_proof(pk, &mut *rng).unwrap();

    // Compute cross-pool authorization digest over the bundle
    let auth_digest = compute_type6_bundle_auth_digest(
        *chain_id.as_bytes(),
        1u16,
        sender_pk,
        nonce,
        shielded_amount as u128,
        fee_atoms,
        &proven_bundle,
    );

    // Apply signatures: Orchard binding signature signs auth_digest
    let authorized_bundle = proven_bundle
        .apply_signatures(&mut *rng, auth_digest, &[])
        .unwrap();
    let bundle_bytes = serialize_bundle(&authorized_bundle);

    // Sender signs auth_digest with Ed25519
    let sender_sig = sender_sk.sign(&auth_digest).to_bytes();

    // Assemble canonical wire format
    let mut raw_tx = Vec::new();
    // Envelope (35 bytes)
    raw_tx.push(6u8); // Type 6
    raw_tx.extend_from_slice(&1u16.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());

    // Payload
    raw_tx.extend_from_slice(&sender_pk);
    raw_tx.extend_from_slice(&nonce.to_le_bytes());
    raw_tx.extend_from_slice(&(shielded_amount as u128).to_le_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);
    raw_tx.extend_from_slice(&sender_sig);

    // Guardian quorum
    raw_tx.push(guardian_signers.len() as u8);
    for (idx, g_sk) in guardian_signers {
        raw_tx.push(*idx);
        let g_sig = g_sk.sign(&auth_digest).to_bytes();
        raw_tx.extend_from_slice(&g_sig);
    }

    TestType6Data {
        raw_tx,
        sender_sk: sender_sk.clone(),
        sender_pk,
        nonce,
        shielded_amount: shielded_amount as u128,
        fee_atoms,
        bundle_bytes,
        sender_sig,
        chain_id,
    }
}

#[allow(dead_code)]
struct TestType7Data {
    raw_tx: Vec<u8>,
    recipient: Hash,
    release_amount: u128,
    fee_atoms: u64,
    bundle_bytes: Vec<u8>,
    chain_id: Hash,
}

fn build_valid_type7_tx(
    rng: &mut StdRng,
    pk: &ProvingKey,
    chain_id: Hash,
    recipient: Hash,
    release_amount: u64,
    fee_atoms: u64,
) -> TestType7Data {
    let user_sk = SpendingKey::from_bytes([0xbb; 32]).unwrap();
    let user_fvk = FullViewingKey::from(&user_sk);
    let user_address = user_fvk.address_at(0u32, Scope::External);

    // Seed note with 100M atoms
    let note_value = 100_000_000u64;
    let mut seed_builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .unwrap();

    let ovk = OutgoingViewingKey::from([0x11; 32]);
    seed_builder
        .add_output(
            Some(ovk.clone()),
            user_address,
            NoteValue::from_raw(note_value),
            [0u8; 512],
        )
        .unwrap();

    let (seed_unauth, meta) = seed_builder.build::<i64>(&mut *rng).unwrap().unwrap();
    let seed_note = seed_unauth
        .recover_output_with_ovk(meta.output_action_index(0).unwrap(), &ovk)
        .unwrap()
        .0;

    let cmx: ExtractedNoteCommitment = seed_note.commitment().into();
    let (anchor, merkle_path) = single_leaf_witness(&cmx);

    let change_amount = note_value - (release_amount + fee_atoms);

    let mut t7_builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::ENABLED,
        anchor,
    )
    .unwrap();

    t7_builder
        .add_spend(user_fvk.clone(), seed_note, merkle_path)
        .unwrap();

    t7_builder
        .add_output(
            Some(ovk),
            user_address,
            NoteValue::from_raw(change_amount),
            [0u8; 512],
        )
        .unwrap();

    let (t7_unauth, _) = t7_builder.build::<i64>(&mut *rng).unwrap().unwrap();
    let t7_proven = t7_unauth.create_proof(pk, &mut *rng).unwrap();

    // Compute cross-pool authorization digest
    let auth_digest = compute_type7_bundle_auth_digest(
        *chain_id.as_bytes(),
        1u16,
        *recipient.as_bytes(),
        release_amount as u128,
        fee_atoms,
        &t7_proven,
    );

    // Apply signatures: user spend key + binding signature over auth_digest
    let spend_auth_key = SpendAuthorizingKey::from(&user_sk);
    let t7_authorized = t7_proven
        .apply_signatures(&mut *rng, auth_digest, &[spend_auth_key])
        .unwrap();

    let bundle_bytes = serialize_bundle(&t7_authorized);

    // Assemble canonical wire format
    let mut raw_tx = Vec::new();
    // Envelope (35 bytes)
    raw_tx.push(7u8); // Type 7
    raw_tx.extend_from_slice(&1u16.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());

    // Payload
    raw_tx.extend_from_slice(recipient.as_bytes());
    raw_tx.extend_from_slice(&(release_amount as u128).to_le_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);

    TestType7Data {
        raw_tx,
        recipient,
        release_amount: release_amount as u128,
        fee_atoms,
        bundle_bytes,
        chain_id,
    }
}

// ---------------------------------------------------------------------------
// 1. Positive Tests: Valid Type 6 and Type 7 Stateless Validation
// ---------------------------------------------------------------------------

#[test]
fn test_valid_type6_stateless_validation() {
    let mut rng = StdRng::seed_from_u64(42);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let sender_sk = SigningKey::from_bytes(&[0x11; 32]);
    let shielded_amount = 50_000_000u64; // 0.5 OWN
    let fee_atoms = 1_000_000u64; // Well above min_fee

    let t6 = build_valid_type6_tx(
        &mut rng,
        &pk,
        chain_id,
        &sender_sk,
        0,
        shielded_amount,
        fee_atoms,
        &[],
    );

    let validated = validate_type6_transaction_stateless(&t6.raw_tx, chain_id, &vk)
        .expect("valid Type 6 must pass stateless validation");

    assert_eq!(validated.sender_pubkey, t6.sender_pk);
    assert_eq!(validated.nonce, 0);
    assert_eq!(validated.shielded_amount, 50_000_000);
    assert_eq!(validated.fee_atoms, fee_atoms);
    assert_eq!(validated.guardian_entries.len(), 0);
    assert_eq!(*validated.bundle.flags(), Flags::SPENDS_DISABLED);
    assert_eq!(*validated.bundle.value_balance(), -(shielded_amount as i64));
    assert_eq!(*validated.bundle.anchor(), Anchor::empty_tree());
}

#[test]
fn test_valid_type6_with_guardian_quorum() {
    let mut rng = StdRng::seed_from_u64(43);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let sender_sk = SigningKey::from_bytes(&[0x22; 32]);
    let guardian_sks: Vec<SigningKey> = (0x30..0x37)
        .map(|b| SigningKey::from_bytes(&[b; 32]))
        .collect();
    let registered_guardians: [[u8; 32]; 7] = [
        guardian_sks[0].verifying_key().to_bytes(),
        guardian_sks[1].verifying_key().to_bytes(),
        guardian_sks[2].verifying_key().to_bytes(),
        guardian_sks[3].verifying_key().to_bytes(),
        guardian_sks[4].verifying_key().to_bytes(),
        guardian_sks[5].verifying_key().to_bytes(),
        guardian_sks[6].verifying_key().to_bytes(),
    ];

    let guardians_to_sign = vec![
        (0u8, &guardian_sks[0]),
        (1u8, &guardian_sks[1]),
        (2u8, &guardian_sks[2]),
        (3u8, &guardian_sks[3]),
    ];

    let t6 = build_valid_type6_tx(
        &mut rng,
        &pk,
        chain_id,
        &sender_sk,
        1,
        25_000_000,
        1_000_000,
        &guardians_to_sign,
    );

    let validated = validate_type6_transaction_stateless(&t6.raw_tx, chain_id, &vk)
        .expect("valid Type 6 with 4-of-7 guardians must pass stateless validation");

    assert_eq!(validated.guardian_entries.len(), 4);

    // Verify 4-of-7 guardian signatures against registered guardian keys over auth_digest
    assert!(verify_type6_guardian_signatures(
        &validated.auth_digest,
        &validated.guardian_entries,
        &registered_guardians
    )
    .is_ok());
}

#[test]
fn test_valid_type7_stateless_validation() {
    let mut rng = StdRng::seed_from_u64(44);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let recipient = Hash::new([0x99; 32]);
    let release_amount = 60_000_000u64; // 0.6 OWN
    let fee_atoms = 1_000_000u64;

    let t7 = build_valid_type7_tx(
        &mut rng,
        &pk,
        chain_id,
        recipient,
        release_amount,
        fee_atoms,
    );

    let validated = validate_type7_transaction_stateless(&t7.raw_tx, chain_id, &vk)
        .expect("valid Type 7 must pass stateless validation");

    assert_eq!(validated.recipient, recipient);
    assert_eq!(validated.release_amount, release_amount as u128);
    assert_eq!(validated.fee_atoms, fee_atoms);
    assert_eq!(*validated.bundle.flags(), Flags::ENABLED);
    assert_eq!(
        *validated.bundle.value_balance(),
        (release_amount + fee_atoms) as i64
    );
}

// ---------------------------------------------------------------------------
// 2. Adversarial Tests: Digest Tampering and Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_type6_tampering() {
    let mut rng = StdRng::seed_from_u64(45);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let sender_sk = SigningKey::from_bytes(&[0x11; 32]);
    let t6 = build_valid_type6_tx(
        &mut rng,
        &pk,
        chain_id,
        &sender_sk,
        0,
        50_000_000,
        1_000_000,
        &[],
    );

    // 1. Mutate chain_id in envelope -> WrongChainId
    let mut bad_chain = t6.raw_tx.clone();
    bad_chain[3] ^= 0xff;
    let err = validate_type6_transaction_stateless(&bad_chain, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Envelope(EnvelopeError::WrongChainId { .. })
    ));

    // 2. Mutate sender_pubkey on wire -> Address and signature fail
    let mut bad_pk = t6.raw_tx.clone();
    bad_pk[TX_ENVELOPE_LEN] ^= 0x01; // flip bit in sender pubkey
    let err = validate_type6_transaction_stateless(&bad_pk, chain_id, &vk).unwrap_err();
    assert!(
        matches!(err, OrchardValidationError::SenderSignatureInvalid)
            || matches!(err, OrchardValidationError::BindingSignatureInvalid)
            || matches!(err, OrchardValidationError::InvalidSenderPublicKey(_))
    );

    // 3. Mutate nonce -> Sender signature and binding signature fail
    let mut bad_nonce = t6.raw_tx.clone();
    bad_nonce[TX_ENVELOPE_LEN + 32] ^= 0x01;
    let err = validate_type6_transaction_stateless(&bad_nonce, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::SenderSignatureInvalid
    ));

    // 4. Mutate shielded_amount -> Value balance mismatch
    let mut bad_amount = t6.raw_tx.clone();
    bad_amount[TX_ENVELOPE_LEN + 40] ^= 0x01;
    let err = validate_type6_transaction_stateless(&bad_amount, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Type6AmountMismatch { .. }
    ));

    // 5. Zero shielded_amount -> ZeroShieldedAmount
    let mut zero_amount = t6.raw_tx.clone();
    zero_amount[TX_ENVELOPE_LEN + 40..TX_ENVELOPE_LEN + 56].fill(0);
    let err = validate_type6_transaction_stateless(&zero_amount, chain_id, &vk).unwrap_err();
    assert!(matches!(err, OrchardValidationError::ZeroShieldedAmount));

    // 6. Fee below min_fee -> FeeTooLow
    let mut low_fee = t6.raw_tx.clone();
    low_fee[TX_ENVELOPE_LEN + 56..TX_ENVELOPE_LEN + 64].fill(0);
    let err = validate_type6_transaction_stateless(&low_fee, chain_id, &vk).unwrap_err();
    assert!(matches!(err, OrchardValidationError::FeeTooLow { .. }));

    // 7. Mutate sender Ed25519 signature -> SenderSignatureInvalid
    let mut bad_sig = t6.raw_tx.clone();
    let bundle_len = u32::from_le_bytes(
        bad_sig[TX_ENVELOPE_LEN + 64..TX_ENVELOPE_LEN + 68]
            .try_into()
            .unwrap(),
    ) as usize;
    let sig_offset = TX_ENVELOPE_LEN + 68 + bundle_len;
    bad_sig[sig_offset] ^= 0xff;
    let err = validate_type6_transaction_stateless(&bad_sig, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::SenderSignatureInvalid
    ));

    // 8. Weak public key (all zeros) -> InvalidSenderPublicKey
    let mut weak_pk_tx = t6.raw_tx.clone();
    weak_pk_tx[TX_ENVELOPE_LEN..TX_ENVELOPE_LEN + 32].fill(0);
    let err = validate_type6_transaction_stateless(&weak_pk_tx, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::InvalidSenderPublicKey(_)
    ));

    // 9. Truncated payload -> TruncatedPayload
    let truncated = &t6.raw_tx[..TX_ENVELOPE_LEN + 100];
    let err = validate_type6_transaction_stateless(truncated, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Envelope(EnvelopeError::TruncatedPayload)
    ));

    // 10. Insufficient guardian quorum (e.g. quorum_count = 2) -> InvalidGuardianQuorum
    let mut bad_quorum = t6.raw_tx.clone();
    let q_offset = sig_offset + 64;
    bad_quorum[q_offset] = 2; // declare 2 guardian signatures (invalid quorum)
    bad_quorum.extend_from_slice(&[0u8; 130]); // add 2 dummy entries
    let err = validate_type6_transaction_stateless(&bad_quorum, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::InvalidGuardianQuorum(_)
    ));
}

#[test]
fn test_adversarial_type7_tampering() {
    let mut rng = StdRng::seed_from_u64(46);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let recipient = Hash::new([0x88; 32]);
    let release_amount = 60_000_000u64;
    let fee_atoms = 1_000_000u64;

    let t7 = build_valid_type7_tx(
        &mut rng,
        &pk,
        chain_id,
        recipient,
        release_amount,
        fee_atoms,
    );

    // 1. Mutate recipient -> Spend auth signature or binding signature fails
    let mut bad_recip = t7.raw_tx.clone();
    bad_recip[TX_ENVELOPE_LEN] ^= 0xff;
    let err = validate_type7_transaction_stateless(&bad_recip, chain_id, &vk).unwrap_err();
    assert!(
        matches!(
            err,
            OrchardValidationError::SpendAuthSignatureInvalid { .. }
        ) || matches!(err, OrchardValidationError::BindingSignatureInvalid)
    );

    // 2. Zero release_amount -> ZeroReleaseAmount
    let mut zero_rel = t7.raw_tx.clone();
    zero_rel[TX_ENVELOPE_LEN + 32..TX_ENVELOPE_LEN + 48].fill(0);
    let err = validate_type7_transaction_stateless(&zero_rel, chain_id, &vk).unwrap_err();
    assert!(matches!(err, OrchardValidationError::ZeroReleaseAmount));

    // 3. Mutate release_amount -> Value balance mismatch
    let mut bad_rel = t7.raw_tx.clone();
    bad_rel[TX_ENVELOPE_LEN + 32] ^= 0x01;
    let err = validate_type7_transaction_stateless(&bad_rel, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Type7ValueBalanceMismatch { .. }
    ));

    // 4. Mutate fee_atoms -> Value balance mismatch
    let mut bad_fee = t7.raw_tx.clone();
    bad_fee[TX_ENVELOPE_LEN + 48] ^= 0x01;
    let err = validate_type7_transaction_stateless(&bad_fee, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Type7ValueBalanceMismatch { .. }
    ));

    // 5. Fee below min_fee -> FeeTooLow
    let mut low_fee = t7.raw_tx.clone();
    low_fee[TX_ENVELOPE_LEN + 48..TX_ENVELOPE_LEN + 56].fill(0);
    let err = validate_type7_transaction_stateless(&low_fee, chain_id, &vk).unwrap_err();
    assert!(matches!(err, OrchardValidationError::FeeTooLow { .. }));

    // 6. Truncated payload -> TruncatedPayload
    let truncated = &t7.raw_tx[..TX_ENVELOPE_LEN + 50];
    let err = validate_type7_transaction_stateless(truncated, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Envelope(EnvelopeError::TruncatedPayload)
    ));

    // 7. Trailing bytes after bundle -> TrailingBytes
    let mut trailing = t7.raw_tx.clone();
    trailing.push(0xde);
    trailing.push(0xad);
    let err = validate_type7_transaction_stateless(&trailing, chain_id, &vk).unwrap_err();
    assert!(matches!(
        err,
        OrchardValidationError::Codec(orchard_tx::BundleCodecError::TrailingBytes)
    ));
}

// ---------------------------------------------------------------------------
// 3. Consensus Anchor and Dummy vs Real Nullifier Rules Verification
// ---------------------------------------------------------------------------

#[test]
fn test_type6_anchor_and_dummy_nullifier_rules() {
    let mut rng = StdRng::seed_from_u64(47);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let sender_sk = SigningKey::from_bytes(&[0x11; 32]);
    let t6 = build_valid_type6_tx(
        &mut rng,
        &pk,
        chain_id,
        &sender_sk,
        0,
        50_000_000,
        1_000_000,
        &[],
    );

    let validated = validate_type6_transaction_stateless(&t6.raw_tx, chain_id, &vk)
        .expect("Type 6 valid transaction must pass");

    // Anchor Rule: Type 6 bundle MUST commit to Anchor::empty_tree()
    assert_eq!(*validated.bundle.anchor(), Anchor::empty_tree());

    // Nullifier Rule: Actions in Type 6 have SPENDS_DISABLED flags
    assert_eq!(*validated.bundle.flags(), Flags::SPENDS_DISABLED);
    // The nullifiers generated are dummy nullifiers per ZIP-225 Section 7.
    // They are not real spends, so they must not be tracked or committed to active nullifier sets.
    let action = &validated.bundle.actions()[0];
    let dummy_nf = action.nullifier();
    assert_eq!(dummy_nf.to_bytes().len(), 32);
}

#[test]
fn test_type7_anchor_and_real_nullifier_rules() {
    let mut rng = StdRng::seed_from_u64(48);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let chain_id = devnet_chain_id();

    let recipient = Hash::new([0x77; 32]);
    let t7 = build_valid_type7_tx(&mut rng, &pk, chain_id, recipient, 60_000_000, 1_000_000);

    let validated = validate_type7_transaction_stateless(&t7.raw_tx, chain_id, &vk)
        .expect("Type 7 valid transaction must pass");

    // Anchor Rule: Type 7 anchor is NOT empty tree (it commits to real note commitment path)
    assert_ne!(*validated.bundle.anchor(), Anchor::empty_tree());

    // Nullifier Rule: Spends are ENABLED, so action nullifier represents a REAL spent note
    assert_eq!(*validated.bundle.flags(), Flags::ENABLED);
    let action = &validated.bundle.actions()[0];
    let real_nf = action.nullifier();
    assert_eq!(real_nf.to_bytes().len(), 32);
}
