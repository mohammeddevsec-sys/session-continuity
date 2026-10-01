# Continuity Proof v1.1 - Reconciled Specification

## Status
LAB RECONCILED DRAFT - NOT INTEGRATED

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
A witness compromise MUST NOT be inferred from a single receipt. Witness equivocation is externally provable when two validly signed witness receipts share the same witness identity, continuity_root, and sequence but contain different continuity_hash or proof hash values. The resulting evidence MUST be verifiable without trusting the witness to report its own misbehavior. This proves equivocation, not necessarily the root cause of key compromise.

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

## Evidence Status
PROVEN: Phase 1 canonicalization profile tests; Phase 2 durable witness behaviors; Phase 2-Hardened signer/witness separation and offline receipt verification; Phase 3 historical verification at 1,000 proofs; Phase 4 portable package and isolated verification path; Phase 4.5 isolated verification at 10,000 proofs; Phase 5 key lifecycle behaviors; P0 critical-gap vectors.
SUPPORTED: portable package model, checkpoint semantics, compromise disposition policy model, completeness/finality model.
NOT YET FORMALLY PROVEN: complete RFC 8785 implementation conformance, crash fault injection across every commit boundary, formal Tamarin/ProVerif proofs, interoperable multi-implementation vectors, large-scale Merkle acceleration behavior.
NOT CLAIMED: first in world, globally unique, universal non-equivocation, legal admissibility, or replacement of existing IAM/session-control standards.
