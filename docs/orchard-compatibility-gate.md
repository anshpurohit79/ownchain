# OwnChain Milestone M1-D — Orchard V2 Compatibility Gate Report (with M1-D.2 Corrections)

**Date:** 2026-10-25
**Baseline Commit:** `4072f45fa4f4ef4493306ce7bce14dedc4faacf5` (M1-D.1 baseline)
**Crate:** `orchard = 0.16.0` (pinned in `Cargo.lock`)
**Status:** **PASS**

---

## 1. Executive Summary

Milestone M1-D (incorporating M1-D.1 and M1-D.2 corrections) proves that the pinned `orchard = 0.16.0` crate successfully satisfies all shielded payment cryptography requirements specified in `docs/protocol-v1.md` (§§3, 5, 6.3, 7, and 12).

An isolated, reproducible compatibility harness in `tests/orchard_compat.rs` demonstrates:
- Correct zero-knowledge proof generation and verification using `OrchardCircuitVersion::FixedPostNu6_2`.
- Canonical wire encoding and decoding in strict compliance with official ZIP-225 Section 7 component order.
- Canonical CompactSize decoding rejecting non-minimal representations, truncation, and trailing data.
- Domain-separated transaction authorization digest using unkeyed BLAKE2b-256 (`OwnChain/TxAuth/v1`) binding active `chain_id` and all consensus-relevant effects, including structured action effect digests (`OwnChain/ActionEffect/v1`) over the **complete 820-byte canonical action description**.
- Cryptographic proof that Halo2 circuit verification alone does **not** protect note ciphertexts from tampering, and that OwnChain's full action-effect digest is what binds note ciphertexts to spend authorization and binding signatures.
- Consensus-recoverable output-only shielded coinbase notes under an all-zero outgoing viewing key (OVK).
- Value-balance sign conventions (`valueBalanceOrchard = +fee_atoms` for transfer, `-payout_atoms` for coinbase) and ZIP-209 pool balance accounting.
- Precise separation between crate-level cryptographic verifications, harness-only policy simulations, and future production `ChainState` consensus integration.

No mocks or dummy proofs were used. All 14 compatibility tests pass in ~33 seconds alongside the full existing consensus test suite (145 total tests passing).

---

## 2. Pinned Orchard API Types & Method Signatures

The following public APIs from `orchard = 0.16.0` were verified and integrated:

### 2.1 Bundle Construction & Versions
- **Bundle Version:** `orchard::bundle::BundleVersion::orchard_v2()`
- **Circuit Version:** `orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2`
- **Action Flags:**
  - Ordinary transfer: `orchard::bundle::Flags::ENABLED` (flag byte `0x03`, spends enabled, outputs enabled)
  - Coinbase: `orchard::bundle::Flags::SPENDS_DISABLED` (flag byte `0x02`, spends disabled, outputs enabled)
- **Note Plaintext Version:** `orchard::note::NoteVersion::V2` (enforced internally by Orchard V2 builder and bundle verification)
- **Builder API:**
  ```rust
  pub fn Builder::new(
      bundle_type: orchard::builder::BundleType,
      bundle_version: orchard::bundle::BundleVersion,
      flags: orchard::bundle::Flags,
      anchor: orchard::Anchor,
  ) -> Builder
  ```
  - `BundleType::Transactional { flags: Flags::ENABLED, bundle_version: BundleVersion::orchard_v2(), anchor }`
  - `BundleType::Coinbase` (with `Flags::SPENDS_DISABLED` and `Anchor::empty_tree()`)

### 2.2 Proof Generation & Verification
- **Proving Key:** `orchard::circuit::ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2)`
- **Verifying Key:** `proving_key.verifying_key()` -> `&orchard::circuit::VerifyingKey`
- **Proof Creation:**
  ```rust
  pub fn UnauthorizedBundle<BundleType, V>::create_proof(
      &self,
      pk: &ProvingKey,
      rng: &mut R,
  ) -> Result<Bundle<InProgress<Unproven, Unauthorized>, V>, halo2_proofs::plonk::Error>
  ```
- **Proof Verification:**
  ```rust
  pub fn Bundle<Authorized, V>::verify_proof(&self, vk: &VerifyingKey) -> Result<(), halo2_proofs::plonk::Error>
  pub fn BatchValidator::new(vk: &'a VerifyingKey) -> BatchValidator<'a>
  pub fn BatchValidator::add_bundle(&mut self, bundle: &'a Bundle<Authorized, V>, sighash: [u8; 32]) -> Result<(), BatchError>
  pub fn BatchValidator::validate(self, rng: &mut R) -> bool
  ```

### 2.3 Signatures & Authorization
- **Spend Authorization Signing Key:** `orchard::keys::SpendAuthorizingKey`
- **Randomized Validating Key:** `action.rk()` -> `&redpallas::VerificationKey<SpendAuth>`
- **Binding Signature Key:** `bundle.binding_validating_key()` -> `redpallas::VerificationKey<Binding>`
- **Applying Signatures:**
  ```rust
  pub fn Bundle<InProgress<Proven, Signable>, V>::apply_signatures<R: RngCore>(
      self,
      rng: &mut R,
      sighash: [u8; 32],
      signing_keys: &[SpendAuthorizingKey],
  ) -> Result<Bundle<Authorized, V>, SignatureError>
  ```

### 2.4 Wire Deserialization & Canonical Parts
- **Action Construction:**
  ```rust
  pub fn orchard::Action::from_parts(
      nf: Nullifier,
      rk: redpallas::VerificationKey<SpendAuth>,
      cmx: ExtractedNoteCommitment,
      encrypted_note: TransmittedNoteCiphertext,
      cv_net: ValueCommitment,
      authorization: redpallas::Signature<SpendAuth>,
  ) -> Result<Self, ActionFromPartsError>
  ```
  *Validates:* Rejects identity `rk` (`ActionFromPartsError::IdentityRk`) and invalid `epk` (`ActionFromPartsError::InvalidEpk`).
- **Bundle Construction from Parts:**
  ```rust
  pub fn orchard::Bundle::try_from_parts(
      actions: nonempty::NonEmpty<Action<redpallas::Signature<SpendAuth>>>,
      flags: Flags,
      value_balance: V,
      anchor: Anchor,
      authorization: Authorized,
      version: BundleVersion,
  ) -> Result<Self, BundleError>
  ```
  *Validates:* Canonical proof size (`Proof::expected_proof_size(n_actions)`), bundle version compatibility, flags consistency.

---

## 3. Valid Bundles & Coinbase Construction

### 3.1 Shielded Transfer Bundle (Spend & Output)
1. **Anchor:** Set to an existing root from the Orchard commitment tree.
2. **Spend:** Spends a previous note using `SpendInfo::new(fvk, note, merkle_path)`.
3. **Output:** Sends `(note_value - fee)` to recipient address `recipient_addr` with user's OVK.
4. **Value Balance:** `+5_000` atoms (the public transaction fee).
5. **Flags:** `Flags::ENABLED` (`0x03`).
6. **Actions:** Exactly 1 action (single paired spend/output).
7. **Verification:**
   - Proof verified with `FixedPostNu6_2` verifying key (`bundle.verify_proof(vk)`).
   - Spend auth signature verified against `action.rk()` and OwnChain `sighash`.
   - Binding signature verified against `bundle.binding_validating_key()` and OwnChain `sighash`.
   - `BatchValidator` succeeds with all proofs and signatures.

### 3.2 Output-Only Shielded Coinbase
1. **Builder Invocation:**
   ```rust
   Builder::new(BundleType::Coinbase, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, Anchor::empty_tree())
   ```
2. **No Padding:** The builder produces **exactly 1 action** for a single coinbase output without requiring dummy spends or padding actions.
3. **Reward Output:** 10 OWN (`1_000_000_000` atoms) sent to the miner's shielded address.
4. **All-Zero Outgoing Viewing Key:**
   Constructed using `ovk = Some(OutgoingViewingKey::from([0u8; 32]))`.
5. **Consensus Note & Value Recovery:**
   Verifying nodes recover the coinbase note plaintext and validate the payout amount and recipient using the public all-zero OVK:
   ```rust
   let zero_ovk = OutgoingViewingKey::from([0u8; 32]);
   let (recovered_note, recovered_addr, recovered_memo) = bundle
       .recover_output_with_ovk(0, &zero_ovk)
       .expect("Recover output 0 under zero OVK");
   assert_eq!(recovered_note.value().inner(), 1_000_000_000);
   ```
6. **Stateless Verification vs Chain-State Nullifier Tracking:**
   For output-only actions with `Flags::SPENDS_DISABLED`, the action nullifier is derived by the circuit over a dummy note commitment. The isolated proof verifier validates the circuit proof. Tracking and duplicate rejection across blocks is the responsibility of the node's `ChainState` (deferred to M1-E).

---

## 4. Corrected ZIP-225 Section 7 Wire Encoding & Evidence

The wire encoding follows the official ZIP-225 Section 7 Orchard component order:

```
1. actionCount: CompactSize
2. actions: [actionDescription; actionCount]
   Each actionDescription (820 bytes):
     - cv_net: 32 bytes
     - nullifier: 32 bytes
     - rk: 32 bytes
     - cmx: 32 bytes
     - epk: 32 bytes
     - enc_ciphertext: 580 bytes
     - out_ciphertext: 80 bytes
3. flagsOrchard: 1 byte (0x02 for Coinbase, 0x03 for Transfer)
4. valueBalanceOrchard: 8 bytes (i64 little-endian)
5. anchorOrchard: 32 bytes
6. sizeProofsOrchard: CompactSize
7. proofsOrchard: proof bytes (2720 + 2272 * n_actions for FixedPostNu6_2)
8. spendAuthSigsOrchard: [64 bytes; actionCount]
9. bindingSigOrchard: 64 bytes
```

### 4.1 Independent Layout & Offset Evidence (`test_zip225_field_order_and_byte_offsets`)
For a 1-action bundle (total length 5,985 bytes), the harness independently asserts every byte range against the model:
- `bytes[0]`: `actionCount` = `0x01`
- `bytes[1..821]`: Action description (820 bytes: cv_net, nullifier, rk, cmx, epk, enc_ciphertext, out_ciphertext)
- `bytes[821]`: `flags` = `0x03`
- `bytes[822..830]`: `valueBalanceOrchard` = `5_000i64` (little-endian)
- `bytes[830..862]`: `anchor` = 32-byte tree root
- `bytes[862..865]`: `sizeProofsOrchard` = `[0xfd, 0x80, 0x13]` (CompactSize for 4,992)
- `bytes[865..5857]`: `proofsOrchard` = 4,992 Halo2 proof bytes
- `bytes[5857..5921]`: `spendAuthSigsOrchard` = 64-byte RedPallas signature
- `bytes[5921..5985]`: `bindingSigOrchard` = 64-byte RedPallas binding signature

A negative permutation test deliberately swaps the field order (e.g. placing flags/value_balance/anchor before action descriptions); `deserialize_bundle` rejects the permuted stream.

### 4.2 Strict CompactSize Canonical Validation (`test_compact_size_rejections`)
The decoder enforces Bitcoin/Zcash canonical CompactSize rules:
- Non-minimal representations rejected with `BundleCodecError::NonCanonicalCompactSize`:
  - `[0xfd, 0x01, 0x00]` (value $1 < 253$ in 3 bytes)
  - `[0xfd, 0xfc, 0x00]` (value $252 < 253$ in 3 bytes)
  - `[0xfe, 0xff, 0xff, 0x00, 0x00]` (value $\le 0\text{xFFFF}$ in 5 bytes)
  - `[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]` (value $\le 0\text{xFFFFFFFF}$ in 9 bytes)
  - Non-minimal proof length (4,992 encoded with `0xfe` prefix)
- Truncated prefixes and values rejected with `BundleCodecError::UnexpectedEof`.
- Trailing bytes rejected with `BundleCodecError::TrailingBytes`.

---

## 5. Domain-Separated Transaction Authorization Digest (§7.3)

The transaction authorization digest uses unkeyed BLAKE2b-256 (consistent with `src/hash.rs`) and binds the transaction to the active chain ID and all consensus-relevant effects:

### 5.1 Action Effect Digest over Complete 820-Byte Action Description
For each action $i \in [0, n\_actions-1]$, the action effect digest binds all 7 fields of the canonical 820-byte action description in established ZIP-225 order:
$$\text{action\_effect}_i = \text{BLAKE2b-256}(\text{UTF8("OwnChain/ActionEffect/v1")} \parallel cv\_net_i \parallel nullifier_i \parallel rk_i \parallel cmx_i \parallel epk_i \parallel enc\_ciphertext_i \parallel out\_ciphertext_i)$$
Where:
- Domain string: `OwnChain/ActionEffect/v1` (exactly 24 bytes).
- Canonical action fields:
  - `cv_net`: 32 bytes
  - `nullifier`: 32 bytes
  - `rk`: 32 bytes
  - `cmx`: 32 bytes
  - `epk`: 32 bytes (ephemeral public key)
  - `enc_ciphertext`: 580 bytes (encrypted note, including value, diversifier, rcm, 512-byte memo, and 16-byte Poly1305 tag)
  - `out_ciphertext`: 80 bytes (outgoing viewing key ciphertext)
Total action-effect input to BLAKE2b-256: $24 + 820 = 844$ bytes (correcting the previous document's 22-byte calculation). Output: 32 bytes.

### 5.2 Transaction Authorization Digest (`sighash`)
$$\text{sighash} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/TxAuth/v1")} \parallel chain\_id \parallel tx\_type \parallel tx\_version \parallel payload\_prefix \parallel flags \parallel value\_balance \parallel anchor \parallel \text{action\_effect}_0 \parallel \dots \parallel \text{action\_effect}_{n-1})$$
Where:
- `chain_id`: 32 bytes (active network ID)
- `tx_type`: 1 byte (`0` for Coinbase, `1` for OrchardTransfer)
- `tx_version`: 2 bytes unsigned little-endian (`1`)
- `payload_prefix`: 8 bytes unsigned little-endian (`height` for Coinbase, `fee_atoms` for OrchardTransfer)
- `flags`: 1 byte Orchard flags
- `value_balance`: 8 bytes signed little-endian `valueBalanceOrchard` (`i64_le`)
- `anchor`: 32 bytes Orchard tree anchor
- `action_effect_i`: 32 bytes per action in action order

### 5.3 Comprehensive Mutation Testing (`test_authorization_digest_mutations_and_invalidation`)
The test suite systematically proves that mutating any committed field produces a distinct `sighash` and cryptographically invalidates existing authorizations:
1. Mutating `chain_id` $\to$ digest changes, spend auth and binding verification fail.
2. Mutating `tx_type` $\to$ digest changes, authorization invalid.
3. Mutating `tx_version` $\to$ digest changes, authorization invalid.
4. Mutating `payload_prefix` (`fee_atoms`) $\to$ digest changes, authorization invalid.
5. Mutating `flags` $\to$ digest changes, authorization invalid.
6. Mutating `value_balance` $\to$ digest changes, authorization invalid.
7. Mutating `anchor` $\to$ digest changes, authorization invalid.
8. Mutating individual action-effect fields:
   - `cv_net` mutation $\to$ action effect changes, digest changes, authorization invalid.
   - `nullifier` mutation $\to$ action effect changes, digest changes, authorization invalid.
   - `rk` mutation $\to$ action effect changes, digest changes, authorization invalid.
   - `cmx` mutation $\to$ action effect changes, digest changes, authorization invalid.
   - `epk` mutation (valid-point mutation) $\to$ action effect changes, digest changes, authorization invalid.
   - `enc_ciphertext` lead byte mutation $\to$ action effect changes, digest changes, authorization invalid.
   - `enc_ciphertext` memo mutation (byte 100 within 52..564) $\to$ action effect changes, digest changes, authorization invalid.
   - `enc_ciphertext` authentication tag mutation (byte 570 within 564..580) $\to$ action effect changes, digest changes, authorization invalid.
   - `out_ciphertext` mutation (byte 10) $\to$ action effect changes, digest changes, authorization invalid.

### 5.4 Proof Verification vs Authorization Binding (`test_ciphertexts_not_covered_by_halo2_proof_alone`)
Orchard's Halo2 circuit proves relations over commitments, values, nullifiers, and spend authorizations, but note encryption (`epk`, `enc_ciphertext`, `out_ciphertext`) occurs outside the circuit.
The harness demonstrates this concretely:
1. Reconstructing an action with mutated `enc_ciphertext` and generating a bundle with the original proof results in `bundle.verify_proof(vk).is_ok()` (the Halo2 verifier alone accepts the bundle).
2. However, because OwnChain commits all 820 bytes of the action description into `action_effect`, the mutated bundle has a distinct authorization digest.
3. The original spend authorization signature and binding signature fail verification against the mutated digest, proving that authorization binding prevents ciphertext tampering where ZK proof verification alone cannot.
4. Separately, non-canonical curve encodings for `epk` (`[0xff; 32]`) fail decompression and are rejected at point decoding by `Action::from_parts` with `ActionFromPartsError::InvalidEpk`.

---

## 6. Negative Test Results & Layer Attribution

The test suite rigorously classifies checks into their appropriate enforcement layer:

| Test Condition | Observed Result | Enforcing Layer | Scope & Limitations |
|---|---|---|---|
| **Altered / Corrupted Proof Bytes** | `bundle.verify_proof()` fails (`VerificationError`); `BatchValidator` returns `false` | **Orchard Crate (Circuit/Proof)** | Verified by Halo2 verifier. |
| **Non-Canonical Proof Length** | `Bundle::try_from_parts` fails with `NonCanonicalProofSize` | **Orchard Crate (Constructor)** | Verified by crate constructor assertions. |
| **Non-Canonical CompactSize** | `decode_compact_size` fails with `NonCanonicalCompactSize` | **Wire Codec** | Rejects non-minimal integer encodings. |
| **Truncated Bundle / Fields** | `deserialize_bundle` fails with `UnexpectedEof` | **Wire Codec** | Rejects incomplete payloads. |
| **Trailing Bytes** | `deserialize_bundle` fails with `TrailingBytes` | **Wire Codec** | Prevents unparsed data attachment. |
| **Identity Authorization Key (`rk == 0`)** | `Action::from_parts` fails with `IdentityRk` | **Orchard Crate (Action Constructor)** | Rejects identity group element. |
| **Non-Canonical Authorization Key** | `redpallas::VerificationKey::try_from` returns `Err` | **RedPallas / Crate** | Rejects invalid curve point decompression. |
| **Non-Canonical Ephemeral Key (`epk = [0xff; 32]`)** | `Action::from_parts` fails with `InvalidEpk` | **Orchard Crate (Action Constructor)** | Rejects non-curve ephemeral keys. |
| **Mismatched Authorization Key** | `rk.verify()` returns `Err` | **Orchard Crate (Signature)** | Signature verification failure. |
| **Cross-Chain Replay (`chain_id` mismatch)** | Signatures and `BatchValidator` fail against testnet sighash | **Orchard Crate / OwnChain Digest** | Domain separation prevents cross-chain replay. |
| **Ciphertext Tampering with Original Proof** | `verify_proof` passes, but signature and BVK reject mutated sighash | **OwnChain ActionEffect / Digest** | Proves proof verification alone does not protect ciphertexts. |
| **Mutated Effects / Ciphertext Fields** | Signatures and binding verification fail on altered digest | **Orchard Crate / OwnChain Digest** | Any field change invalidates authorizations. |
| **Incorrect Fee / Value Balance Sign** | Mutated `value_balance` alters expected BVK; `bvk.verify()` fails | **Orchard Crate (Value Commitment)** | BVK derivation commits to value balance. |
| **Duplicate Nullifier** | Isolated crate verifier succeeds; harness simulation rejects | **Harness Simulation (Future `ChainState`)** | **CRATE DOES NOT ENFORCE.** The stateless crate verifier accepts duplicate nullifiers. Production tracking belongs to M1-E. |
| **Stale / Unknown Historical Anchor** | Isolated crate verifier succeeds; harness simulation rejects | **Harness Simulation (Future `ChainState`)** | **CRATE DOES NOT ENFORCE.** The crate only validates internal anchor consistency. Production ancestor-root validation belongs to M1-E. |

---

## 7. Confirmed Value-Balance & Pool Conservation Conventions

All signed and verified test fixtures confirm protocol rules:
- **Transfer:** `valueBalanceOrchard = +fee_atoms = +5_000` (value leaves pool to pay fee).
- **Coinbase:** `valueBalanceOrchard = -payout_atoms = -1_000_000_000` (value enters pool as subsidy).
- **Pool Balance:** $\text{pool\_balance}_{h} = \text{pool\_balance}_{h-1} - \text{valueBalanceOrchard}$.
  - Genesis: 0 atoms
  - Block 1 (Coinbase 10 OWN): $+1{,}000{,}000{,}000$ atoms
  - Block 2 (Transfer with 5,000 fee): $+999{,}995{,}000$ atoms
  - Range Invariant: $0 \le \text{pool\_balance} \le 2{,}102{,}400{,}000{,}000{,}000$ atoms.

---

## 8. Verification Results

### Quality Checks
- `cargo fmt --all -- --check`: **Pass**
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: **Pass**
- `git diff --check`: **Pass**

### Test Suite Execution
- `cargo test --locked --all-targets`: **Pass** (145 total tests across 5 targets, 0 failed):
  - `ownchain` lib unittests: 8 passed
  - `difficulty`: 22 passed
  - `golden_vectors`: 37 passed
  - `orchard_compat`: 14 passed
  - `randomx`: 9 passed
  - `validation`: 55 passed

---

## 9. Remaining M1-E Work (Future Consensus Integration)

Passing the M1-D/M1-D.1/M1-D.2 compatibility gate proves that the pinned Orchard API can implement OwnChain's shielded rules. It does **not** integrate shielded transactions into production consensus. The following work remains for Milestone M1-E:

1. **Commitment Tree State Tracking in `ChainState`:** Implement an incremental depth-32 Sinsemilla/Orchard commitment tree that appends `action.cmx()` in block order and produces the canonical header `orchard_root`.
2. **Historical Anchor Ring Buffer:** Maintain historical tree roots across ancestor blocks to validate transaction anchors during block validation and fork reorgs.
3. **Nullifier Persistence in `ChainState`:** Implement permanent nullifier tracking to detect and reject duplicate nullifiers within a block and against the active chain.
4. **Transaction Envelope Parser in Block Validation:** Wire `tx_type`, `tx_version`, `chain_id`, `fee_atoms`, and `height` parsing into `src/validation.rs` for block bodies.
5. **Subsidy & Fee Accounting in Consensus:** Verify that block coinbase payouts do not exceed `scheduled_subsidy(h) + sum(tx.fee_atoms)` and that atomic rollback occurs upon any validation failure.
