# Continuity Proof v1.2 — Publication Specification

**Version:** 1.2.0
**Status:** LAB RECONCILED — REFERENCE IMPLEMENTATION COMPLETE
**Date:** 2026-09-17
**Supersedes:** Continuity Proof v1.1-RECONCILED (SHA256: D92B8E795A0515DE25C9DE86A9177AE48150E24BE9BF34744F530D0D4BD30F32)
**Reference Implementation:** session-continuity-engine v0.2.0

## Abstract

This document specifies Continuity Proof v1.2, a vendor-neutral Session Continuity Evidence protocol. The protocol establishes cryptographic continuity from a trusted authenticated session root through an ordered proof chain, durable witness observations, and independently verifiable portable evidence.

V1.2 builds on V1.1 with three additions: (a) explicit binding to a normative reference implementation whose SHA-256 source-tree digest is published and independently reproducible, (b) a machine-readable Conformance Declaration format, and (c) a formal Coexistence Model defining how the v1 proof-certificate namespace and the v1.1 / v1.2 continuity-proof namespace operate concurrently within a single deployment.

The protocol does NOT claim first-in-world status, globally unique design, universal non-equivocation outside a configured witness trust domain, proof of the legitimacy of the original authentication, device ownership, absence of credential compromise, or legal admissibility. Section 35 defines the precise scope.

## Versioning Note

Sections 1 through 36 describe the core continuity-proof protocol as first specified in v1.1. The body text of those sections is preserved verbatim from the v1.1-RECONCILED draft because v1.2 does not alter the core protocol; v1.2 adds Sections 37-40 which bind the specification to a normative reference implementation, publish a machine-readable Conformance Declaration format, and define coexistence with the v1 production namespace. A reader evaluating the core protocol should treat Sections 1-36 as the v1.1 core, and Sections 37-40 as v1.2 additions. The change from v1.1 to v1.2 is additive and non-breaking.

## Table of Contents

Sections 1 through 36 are preserved verbatim from Continuity Proof v1.1-RECONCILED.

- Sections 1–36: Core Protocol
- Section 37: Reference Implementation
- Section 38: Reference Test Vectors
- Section 39: Conformance Declaration Format
- Section 40: Coexistence with v1
- Evidence Status
- Revision History

---
## 1. Security Objective
V1.1 defines a vendor-neutral Session Continuity Evidence protocol. It establishes cryptographic continuity from a trusted authenticated session root through an ordered proof chain, durable witness observations, and independently verifiable portable evidence. V1.1 does not claim that cryptographic continuity proves the legitimacy of the original authentication.

## 2. Root Establishment
A continuity root MUST be derived from an authenticated session root object. The root object MUST bind the identifiers required by the deployment, including session_id, subject, issuer, authentication time, and relevant client context. The root object MUST be immutable after establishment. The verifier MUST receive or already trust explicit root trust material sufficient to establish ROOT_NOT_TRUSTED versus an accepted root.

## 3. Root Trust Material
Root trust MUST be represented by explicit trust material or a trust reference that identifies the trusted root, its fingerprint, version, and trust status. A root hash alone MUST NOT be treated as proof that the root was legitimately established. Root establishment remains a deployment trust boundary.

## 4. Proof Object
Each proof MUST contain: schema, continuity_root, sequence, parent_hash, state_hash, decision_hash, issued_at, signer_key_id, policy_fingerprint_sha256, and continuity_hash. For sequence 1, parent_hash MUST be JSON null. For n greater than 1, parent_hash MUST equal the continuity_hash of the immediately preceding verified proof. issued_at MUST conform to the V1.1 fixed timestamp profile: RFC 3339-compatible UTC representation with an uppercase Z timezone indicator and exactly three fractional-second digits (milliseconds). No offsets, lowercase z, missing fractional seconds, or fractional precision other than exactly three digits are accepted. Implementations MUST also reject semantically invalid calendar or clock values; accepted values MUST round-trip through UTC timestamp serialization without normalization. This fixed profile is protocol-defined and MUST NOT be replaced by deployment-specific timestamp formats.

## 5. Canonical Serialization Profile
V1.1 defines a JCS-compatible canonical serialization profile based on RFC 8785. The protocol MUST use the explicitly versioned profile and its conformance vectors. Implementations MUST NOT apply additional Unicode normalization. Protocol counters MUST be JSON integers. A deployment MUST NOT claim full RFC 8785 implementation conformance solely from passing the V1.1 profile vectors.

## 6. Canonical Proof Core
The V1.1 proof core consists exactly of schema, continuity_root, sequence, parent_hash, state_hash, decision_hash, issued_at, signer_key_id, and policy_fingerprint_sha256. continuity_hash MUST equal SHA-256 over the canonical serialized proof core and MUST NOT include continuity_hash itself. The proof signature MUST cover the complete canonical proof body including continuity_hash.

## 7. Domain Separation
Proof, witness receipt, checkpoint, and package signatures MUST use explicitly domain-separated protocol structures. A valid signature from one protocol object type MUST NOT be accepted as a signature over another object type merely because the serialized fields are otherwise compatible.

## 8. Sequence Guard
A new accepted sequence MUST equal lastAcceptedSequence + 1. A lower sequence MUST be rejected according to replay or rollback policy. An equal sequence with the same proof hash MAY be IDEMPOTENT_REPLAY. An equal sequence with a different proof hash MUST be treated as EQUIVOCATION_FORK by the witness. A sequence greater than lastAcceptedSequence + 1 MUST be rejected as SEQUENCE_GAP.

## 9. Parent Binding
A verifier MUST verify the immediately preceding proof before accepting proof n. Sequence values alone MUST NOT establish parentage. Missing, substituted, or unverifiable parent material MUST cause rejection. An isolated proof n MUST NOT be reported as CONTINUITY_PROVEN merely because its signature and commitments are valid.

## 10. Historical Verification
CONTINUITY_PROVEN means that the requested proof interval is cryptographically valid: trusted root, valid signer signatures, valid continuity hashes, exact sequence progression, valid parent links, valid policy bindings, and valid referenced commitments. Historical verification is all-or-nothing for the requested interval.

## 11. Completeness and Truncation
A valid prefix MUST NOT be interpreted as the complete history. PREFIX_VALID proves only the supplied interval. CONTINUITY_COMPLETE requires independent finality evidence, such as a trusted final checkpoint or explicit session-closure statement, bound to the final continuity hash. chain_length alone MUST NOT establish completeness.

## 12. Checkpoints
A checkpoint MUST contain schema, continuity_root, sequence, continuity_hash, proof_hash, checkpoint_kind, signer or witness key identity, and signature. A checkpoint is an authenticated statement about a verified head; it MUST NOT replace parent-binding semantics inside the verified interval. A CLOSED checkpoint establishes completeness only within its explicitly declared scope and trust domain.

## 13. Witness Non-Equivocation
A trusted witness MUST maintain durable state per continuity_root and witness_domain_id. Same root, same sequence, same continuity_hash is IDEMPOTENT_REPLAY. Same root, same sequence, different continuity_hash is EQUIVOCATION_FORK. A sequence gap, rollback, or incorrect parent MUST be rejected. Witness state MUST survive restart and MUST be validated before new acceptance.

## 14. Witness Equivocation Evidence
A witness compromise MUST NOT be inferred from a single receipt. Witness equivocation is externally provable when two validly signed witness receipts share the same witness identity, continuity_root, and sequence but contain different continuity_hash or proof hash values. The resulting evidence MUST be verifiable without trusting the witness to report its own misbehavior. This proves equivocation, not necessarily the root cause of key compromise. Cross-witness-domain observations MUST remain domain-scoped: two valid receipts from different witness_domain_id values that share the same continuity_root and sequence but contain different continuity_hash or proof hash values MUST NOT, by themselves, be classified as EQUIVOCATION_FORK or as proof of global non-equivocation failure. A global non-equivocation claim requires an explicitly defined common trust or aggregation domain beyond the scope of this protocol.

## 15. Witness Failure and Recovery
The witness MUST use durable write-ahead or equivalent crash-safe persistence. After restart it MUST reconstruct and validate its authoritative head before accepting new proofs. If recovery fails, the witness MUST fail closed for new acceptance and new receipts. Historical read-only verification MAY remain available. A crash MUST resolve to either an observable committed receipt or no accepted state; partial acceptance MUST NOT be exposed.

## 16. Witness Receipt
A witness receipt MUST bind continuity_root, sequence, observed proof hash, continuity_hash, witness head state, witness_domain_id, and witness_key_id, and MUST be signed by the witness key. Receipt verification MUST be possible with trusted witness material without contacting the witness.

## 17. Key Lifecycle
Every signing and witness identity MUST have a stable key identifier or fingerprint. Key state MUST distinguish active, retired, and revoked. Historical proofs MAY remain cryptographically verifiable after retirement when trust at the relevant sequence is established. A retired key MUST NOT produce newly accepted proofs outside its authorized issuance interval. Revoked keys MUST NOT produce newly accepted proofs after effective revocation. Deployments MUST define effective lifecycle points.

## 18. Key Compromise Window
A deployment MAY define a compromise effective point and a policy disposition of VALID, QUARANTINED, or REJECTED for proofs associated with a compromised identity. Cryptographic signature validity and compromise disposition MUST remain separate concepts. A key compromise declaration MUST NOT retroactively rewrite historical signatures.

## 19. Time Semantics
sequence is the authoritative continuity order. issued_at is protocol-defined temporal metadata and MUST conform to the fixed V1.1 timestamp profile specified in Section 4. Freshness is a deployment-level verification policy, not an intrinsic property of proof validity. A deployment MAY define an ABSOLUTE freshness policy, a RELATIVE inter-proof interval policy, BOTH, or NONE. If ABSOLUTE freshness is enabled, the deployment MUST define MAX_AGE_SECONDS and MUST reject proofs whose age is negative or exceeds the configured maximum; the exact boundary MAY be inclusive only if explicitly specified by the deployment profile. If RELATIVE freshness is enabled, the deployment MUST define the maximum permitted interval between consecutive verified proof timestamps. Freshness policy MUST NOT replace sequence validation, parent binding, signature validation, witness verification, or historical proof validity. Changes to freshness policy MUST be represented through the deployment policy binding and MUST NOT rewrite historical proofs.

## 20. Policy Binding
Each proof MUST contain the policy fingerprint used for its decision. Policy changes MUST NOT silently rewrite historical proofs. A policy transition MAY occur within the same continuity root when explicitly represented and verifiable. A new root is required only when the deployment defines the policy transition as a new trust or continuity context.

## 21. Portable Evidence Package
A portable package MUST contain package schema/version, trusted root material or reference, ordered proof chain for the requested scope, witness receipts for that scope, signer trust material, witness trust material, policy references, and package signature material. The package signature protects package authenticity but MUST NOT substitute for verification of the contained evidence.

## 22. Independent Receiver
An independent receiver MUST verify using only the portable package, trusted signer material, trusted witness material, root trust material, and stated policy. Source application state, witness live state, and network access MUST NOT be required. The receiver MUST distinguish package authenticity, proof validity, witness evidence validity, policy disposition, and completeness.

## 23. Long-Chain Handling
The normative verifier MUST support full verification from trusted root to requested sequence n. Checkpoints, cached verification, Merkle proofs, or other acceleration MAY be added later, but MUST NOT alter parent-binding semantics. V1.1 does not require Merkle acceleration at the current tested 10,000-proof scale.

## 24. Package and Evidence Decisions
PACKAGE_AUTHENTIC, EVIDENCE_VALID, WITNESS_EVIDENCE_VALID, POLICY_VALID, CONTINUITY_PROVEN, and CONTINUITY_COMPLETE are distinct states. A package signature alone MUST NOT produce a continuity decision.

## 25. Trust Anchor Semantics
Trust anchors MUST identify key or root fingerprints, versions, status, and the trust domain in which they are accepted. Bootstrap of trust is deployment-specific and MUST be documented. An independent verifier MUST fail closed when required trust material is missing or untrusted.

## 26. Privacy and Data Minimization
Implementations SHOULD minimize directly identifying session data in portable evidence and SHOULD prefer commitments where disclosure is not required. V1.1 does not define selective disclosure, but package design MUST NOT preclude later privacy-preserving extensions.

## 27. Error Taxonomy
Normative errors include SEQUENCE_GAP, SEQUENCE_ROLLBACK, REPLAY_DETECTED, IDEMPOTENT_REPLAY, PARENT_MISMATCH, EQUIVOCATION_FORK, SIGNATURE_INVALID, CONTINUITY_HASH_MISMATCH, ROOT_NOT_TRUSTED, WITNESS_STATE_CORRUPT, WITNESS_NOT_READY, WITNESS_RECOVERY_FAILED, WITNESS_RECEIPT_TAMPERED, RECEIPT_BINDING_MISMATCH, KEY_REVOKED, KEY_RETIRED, POLICY_VIOLATION, TRUST_ANCHOR_MISSING, PACKAGE_VERSION_MISMATCH, PACKAGE_INVALID, PACKAGE_SIGNATURE_INVALID, and INCOMPLETE_HISTORY.

## 28. Threat Model
The adversary MAY read, modify, delay, delete, reorder, replay, fork, or present different valid proofs to different verifiers. The adversary MAY attempt witness-state corruption or witness-key compromise. V1.1 does not assume compromise-resistant hardware and does not prevent all consequences of trusted-key compromise.

## 29. Conformance Levels
Level 1 requires canonical proof objects, signatures, and sequence tests. Level 2 adds parent binding and historical verification. Level 3 adds durable witness and receipts. Level 4 adds independent receiver and portable-package verification. Level 5 adds key lifecycle, deterministic interoperability vectors, completeness/finality vectors, and P0 security vectors. Each declaration MUST identify the level and required test artifact set.

## 30. Test Vector Determinism
Vectors MUST fix keys, inputs, timestamps, roots, expected hashes, signatures, witness identities, and expected results. Ed25519 deterministic behavior MUST be tested with fixed keys and RFC-based golden vectors where applicable. Test vectors MUST NOT depend on wall-clock time, runtime randomness, or environment-specific path state.

## 31. Adversarial Requirements
V1.1 conformance testing MUST cover sequence gaps, rollback, same-sequence fork, parent substitution, alternate valid branch, reordered chain, forged signature, rebuilt evidence, signer substitution, witness restart, witness corruption, recovery failure, receipt tampering, key rotation, retirement, revocation, key compromise disposition, checkpoint tampering, truncation/completeness, package tampering, missing proof, wrong trust anchor, wrong witness key, cross-context replay, and offline verification.

## 32. Formal Verification Plan
Formalization SHOULD target no_sequence_gap, parent_binding_soundness, witness_non_equivocation, historical_consistency, replay_resistance, completeness_soundness, and signature unforgeability under stated cryptographic assumptions. Formal results MUST distinguish protocol invariants from cryptographic assumptions.

## 33. Backward Compatibility
The existing proof-certificate.v1 contract MUST retain its current meaning. V1.1 MUST use explicit schema/protocol versioning and MUST NOT silently reinterpret V1 fields. Existing production and release artifacts MUST remain unchanged during lab development.

## 34. Relationship to Existing Standards
V1.1 may reuse RFC 8785 JCS, RFC 8032 EdDSA/Ed25519, RFC 9162 Certificate Transparency consistency concepts, RFC 9942 receipt and verifiable-data-structure concepts, RFC 9943 SCITT architecture, RFC 3161 trusted timestamps where deployed, and NIST key-management guidance. These standards provide mechanisms or related transparency concepts; they do not define this session-continuity protocol.

## 35. Scope and Non-Claims
V1.1 does not prove the legitimacy of the original authentication beyond the trusted root establishment. It does not replace IAM, OIDC, CAEP, or session-risk systems. It does not prove device ownership, absence of credential compromise, or global non-equivocation outside the configured witness trust domain. It proves only the evidence properties and scopes explicitly established by the verifier and trust configuration.

## 36. Acceptance Gate
No source-code integration is permitted until the reconciled reference model, P0 security vectors, independent receiver, durable witness, key lifecycle, deterministic vectors, completeness/finality semantics, and adversarial suites pass. Production and release artifacts MUST remain unchanged.

## 37. Reference Implementation

V1.2 is accompanied by a normative reference implementation whose source-tree digest is published to enable independent verification.

The reference implementation consists of nine JavaScript modules under `src/`:

- `src/core/canonical-v1_1.js` — JCS canonical serialization profile
- `src/core/continuity-proof-v1_1.js` — proof core construction and chain verification
- `src/core/sequence-guard-v1_1.js` — in-memory exact-sequence verification
- `src/core/durable-sequence-guard-v1_1.js` — durable sequence journal with crash safety
- `src/evidence/proof-signature-v1_1.js` — Ed25519 signer and signature verifier
- `src/evidence/trusted-proof-verifier-v1_1.js` — trusted chain verification with lifecycle integration
- `src/evidence/witness-v1_1.js` — durable witness with equivocation detection
- `src/evidence/portable-package-v1_1.js` — portable evidence package builder and verifier
- `src/evidence/key-lifecycle-v1_1.js` — active / retired / revoked key state machine

The reference implementation preserves the existing v1 production modules without modification. Section 40 defines the coexistence model.

### 37.1 Reference Implementation Tree Digest

The digest below covers every file under `src/` excluding files whose names contain `.backup_`. Each file's relative path and content are hashed into a single SHA-256 digest, in lexicographic path order, separated by single newlines.

Reference tree digest at V1.2 publication:

    SRC_TREE_SHA256 = 941DE3DAC25B80B82D8ECC38D6A1C3F8F0BE085205A1AC339E2CB99D3CD7DE5F

This digest is normative. A deployment claiming V1.2 conformance at Level 4 or higher SHOULD publish a matching digest computed by the same rule, or explicitly declare the divergence.

### 37.2 Reference Behaviour Guarantees

The reference implementation satisfies, at minimum, the following executable guarantees, each verified by an automated test:

| Guarantee | Evidence |
|---|---|
| Canonical serialization rejects `-0`, `NaN`, `Infinity`, lone surrogates | `lab/PROOF.mjs` Section E |
| Ed25519 golden vector RFC 8032 Section 7.1 Test 1 matches byte-for-byte | `lab/PROOF.mjs` Section D |
| Signature verification is deterministic across independent processes | `lab/PROOF.mjs` determinism check |
| Chain verification is all-or-nothing | `lab/PROOF.mjs` NC4, NC5 |
| Witness detects same-root / same-sequence / different-hash as `EQUIVOCATION_FORK` | `lab/PROOF.mjs` Section G |
| Witness emits a signed receipt on `EQUIVOCATION_FORK` | `lab/PROOF.mjs` Section G |
| Durable sequence journal rejects rollback and corruption | `lab/v1_1-durable-sequence-probe.mjs` |
| Witness fails closed on state corruption | `lab/v1_1-witness-fail-closed-probe.mjs` |
| Portable package verifies offline without source application, live witness, or network | `lab/v1_1-portable-package-probe-v2.mjs` |
| Key lifecycle distinguishes active, retired, revoked | `lab/v1_1-key-lifecycle-probe.mjs` |
| Historical proofs remain valid after retirement | `lab/v1_1-lifecycle-integration-probe.mjs` |
| Compromise window rejects proofs within the declared interval | `lab/v1_1-key-lifecycle-probe.mjs` |

## 38. Reference Test Vectors

V1.2 publishes a set of deterministic test vectors that any conformant implementation MAY use to verify interoperability.

### 38.1 Deterministic Test Vector Properties

Every reference test vector MUST fix:

- The private key seed (32 bytes, hexadecimal).
- The expected public key (32 bytes, hexadecimal).
- All input objects (canonical proof core, timestamps, policy fingerprint).
- The expected `continuity_hash`.
- The expected signature (base64).
- The expected verification result.

Test vectors MUST NOT depend on wall-clock time, runtime randomness, or environment-specific filesystem state.

### 38.2 Published Vector Sets

| Set | Reference | Purpose |
|---|---|---|
| RFC 8032 Section 7.1 | RFC 8032 | Ed25519 golden vector (Test 1) |
| JCS numeric | RFC 8785 Appendix B | JSON number serialization |
| V1.1 profile vectors | `lab/continuity-proof-vnext/jcs-profile-v1_1.mjs` | Canonical serialization restrictions |
| Continuity chain vectors | `lab/v1_1-chain-probe.mjs` | Sequence, parent, tamper rejection |
| Witness equivocation vectors | `lab/v1_1-witness-probe-v2.mjs` | Fork detection and receipt emission |
| Package vectors | `lab/v1_1-portable-package-probe-v2.mjs` | Offline verification and tamper rejection |

### 38.3 Verification Command

Any conformant implementation SHOULD be able to reproduce the reference implementation's test-vector results by executing the following from the project root:

    node lab/PROOF.mjs

The output is deterministic. Two consecutive runs MUST produce byte-identical output.

Reference output digest at V1.2 publication:

    PROOF_RUN_SHA256 = 48FF8147BEADE14AA74697B70532185DF276100B592676DC06E769F4C40B12C5

## 39. Conformance Declaration Format

A deployment claiming V1.2 conformance MUST publish a machine-readable Conformance Declaration.

### 39.1 Declaration Schema

The declaration is a JSON object with the following required fields:

    {
      "schema_id": "continuity-proof.conformance.declaration.v1.2",
      "version": 1,
      "implementation_name": "<string>",
      "implementation_version": "<string>",
      "conformance_level": <integer 1..5>,
      "src_tree_sha256": "<64-hex>",
      "test_artifacts": ["<relative-path>", "..."],
      "test_vector_sha256": "<64-hex>",
      "declared_at": "<RFC3339 timestamp>",
      "declaration_signature": {
        "algorithm": "Ed25519",
        "public_key_spki_base64": "<base64>",
        "signature_base64": "<base64>"
      }
    }

### 39.2 Level Requirements

| Level | Required Capabilities |
|---|---|
| 1 | Canonical proof objects, signatures, exact sequence |
| 2 | Level 1 + parent binding + historical verification |
| 3 | Level 2 + durable witness + receipts |
| 4 | Level 3 + independent receiver + portable package |
| 5 | Level 4 + key lifecycle + deterministic vectors + completeness |

### 39.3 Declaration Verification

A third party MUST be able to verify a Conformance Declaration by:

1. Checking the declaration signature against the declared public key.
2. Recomputing the implementation's `src_tree_sha256` by the same rule defined in Section 37.1.
3. Verifying that every declared test artifact exists and reproduces the expected output.
4. Confirming that the declared conformance level matches the capabilities demonstrated by the test artifacts.

## 40. Coexistence with v1

V1.1 and V1.2 coexist with the v1 `session-continuity.proof-certificate.v1` namespace without redefinition or silent reinterpretation.

### 40.1 Namespace Separation

| Namespace | Purpose | Format |
|---|---|---|
| v1 (`session-continuity.proof-certificate.v1`) | Existing production proof-certificate contract | Unchanged |
| v1.1 / v1.2 (`continuity-proof.v1.1`) | Continuity proof chain with witness evidence | New |

The two namespaces MUST NOT be silently merged. A v1 proof MUST NOT be accepted as a v1.1 or v1.2 proof, and vice versa.

### 40.2 Dual Operation

A deployment MAY operate both namespaces concurrently:

- v1 handles existing proof-certificate flows.
- v1.1 / v1.2 handles continuity-evidence flows where witness evidence is required.
- A continuity root MAY be established independently from any v1 proof-certificate.

The choice is a deployment decision and MUST be documented in the deployment's trust configuration.

### 40.3 Migration

Deployments migrating from v1 to v1.1 / v1.2:

- MUST NOT retroactively reinterpret historical v1 proof-certificates.
- MAY continue issuing v1 proof-certificates for existing flows.
- MAY issue v1.1 / v1.2 continuity proofs in parallel for continuity-sensitive flows.

### 40.4 Reference Coexistence Evidence

The reference implementation demonstrates coexistence by:

- Preserving all v1 SHA-256 digests unchanged since V1.1 publication.
- Adding v1.1 modules under distinct filenames (`*-v1_1.js`).
- Passing the full v1 regression suite (38 tests) without modification.

## Evidence Status

### Status at V1.2 Publication

**PROVEN (executable evidence, reproducible):**

- V1 regression suite: 38 tests PASS, product state STABLE_BASELINE
- V1.1 regression suite: 12 probes PASS, zero failures
- RFC 8032 Section 7.1 Test 1: public key, signature, and verification match byte-for-byte
- JCS profile: `-0`, `NaN`, `Infinity`, lone surrogates rejected; recursive ordering correct
- Unicode / UTF-16 ordering: identical between v1 and v1.1 canonical functions
- Witness equivocation: same root + same sequence + different hash detected, signed receipt emitted, external proof valid
- Key lifecycle: active, retired, revoked distinguished; compromise window enforced
- Portable package: builds, verifies offline, rejects tampered proof, rejects undeclared signer, rejects forged packager
- Scale: 1,000-proof chain builds in 71 ms, verifies in 130 ms
- Package manifest: private `session-continuity-engine@0.2.0`; no current compressed-size or file-count claim is asserted without a retained package artifact
- Determinism: two consecutive runs of `lab/PROOF.mjs` produce byte-identical output

**SUPPORTED (design consistent, partially tested):**

- Checkpoint semantics
- Compromise disposition policy model
- Completeness / finality model
- Cross-witness-domain scoping

**NOT YET FORMALLY PROVEN:**

- Complete RFC 8785 implementation conformance
- Crash fault injection across every commit boundary
- Formal Tamarin / ProVerif proofs of protocol invariants
- Interoperable multi-implementation vectors (only one reference implementation exists)
- Large-scale Merkle acceleration behavior (not required at tested scale)

**NOT CLAIMED:**

- First-in-world status
- Globally unique design
- Universal non-equivocation outside a witness trust domain
- Legal admissibility
- Replacement of existing IAM, OIDC, CAEP, or session-risk systems

## Revision History

### V1.2 (2026-09-17)

- Added Section 37: Reference Implementation binding with normative tree digest
- Added Section 38: Reference Test Vectors
- Added Section 39: Conformance Declaration Format
- Added Section 40: Coexistence with v1
- Updated Evidence Status with V1.2 publication audit results
- Preserved Sections 1–36 verbatim from V1.1-RECONCILED

### V1.1 (2026-09-15)

- Reconciled specification with all lab evidence
- Added Sections 3, 7, 11, 14, 15, 18, 22, 24, 25, 26, 27
- See V1.1-RECONCILED for full history

### V1.0

- Initial protocol specification
