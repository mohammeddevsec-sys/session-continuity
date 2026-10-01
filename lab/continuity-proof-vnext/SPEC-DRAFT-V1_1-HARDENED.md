# Continuity Proof v1.1 - Hardened Specification Draft
## Status
LAB HARDENED DRAFT - NOT INTEGRATED

## 1. Security Objective
For a configured continuity root and trusted witness domain, an independently verified proof at sequence n is accepted as a historical descendant only when sequence progression is exact, the proof is cryptographically bound to the immediately preceding verified proof, and all required signatures and state commitments verify. The witness detects two distinct accepted proof hashes for the same continuity root and sequence within its trust domain.

## 2. Root Establishment
A continuity_root MUST be established from an authenticated session root object. The root object MUST canonically bind the identifiers required to establish the authenticated continuity context, including session_id, subject, issuer, authentication time, and relevant client context. The root MUST be immutable after establishment. Root establishment is a trust boundary; V1.1 does not claim that root establishment proves continued legitimacy after authentication.

## 3. Proof Objects
Each continuity proof MUST contain: schema, continuity_root, sequence, parent_hash, state_hash, decision_hash, issued_at, and continuity_hash. For sequence 1, parent_hash MUST be empty. For n > 1, parent_hash MUST equal the continuity_hash of the immediately preceding verified proof. issued_at MUST be an RFC 3339 UTC timestamp represented as a string. Timestamp freshness is an optional policy control and MUST NOT replace sequence, parent binding, or witness checks.

## 4. Canonical Serialization Profile
V1.1 uses JSON Canonicalization Scheme (JCS, RFC 8785) for cryptographic canonicalization. Implementations MUST preserve Unicode string data as supplied; V1.1 MUST NOT apply an additional Unicode normalization step. JSON numbers used in canonicalized cryptographic fields MUST be restricted to interoperable values; protocol-defined counters and sequence values MUST be JSON integers. Property ordering MUST follow the JCS rules. Any future alternative encoding MUST be introduced under an explicit protocol version.

## 5. Canonical Proof Core
The canonical proof core consists exactly of: schema, continuity_root, sequence, parent_hash, state_hash, decision_hash, and issued_at. continuity_hash MUST equal SHA-256 over the canonical serialized proof core and MUST NOT include continuity_hash itself. The proof signature MUST cover the complete canonical proof body including continuity_hash.

## 6. Sequence Guard
For an established continuity root, a new accepted sequence MUST equal lastAcceptedSequence + 1. A lower sequence MUST be rejected as SEQUENCE_ROLLBACK or REPLAY_DETECTED according to implementation state. An equal sequence with the same proof hash MAY be treated as IDEMPOTENT_REPLAY. An equal sequence with a different proof hash MUST be treated as EQUIVOCATION_FORK when submitted to a witness. A sequence greater than lastAcceptedSequence + 1 MUST be rejected as SEQUENCE_GAP.

## 7. Parent Binding
A verifier MUST verify the immediately preceding proof before accepting proof n. Sequence numbers alone MUST NOT establish parentage. For n > 1, parent_hash MUST equal the verified continuity_hash of proof n-1. Missing, substituted, or unverifiable parent material MUST cause rejection. A verifier MUST NOT accept an isolated proof n as CONTINUITY_PROVEN merely because its signature and state commitments are individually valid.

## 8. Historical Verification
CONTINUITY_PROVEN is valid only when the continuity root is trusted and consistent; every proof signature verifies; every continuity_hash verifies; sequence values are exact; every parent_hash matches the immediately preceding verified proof; issued_at values satisfy configured policy if freshness policy is enabled; and referenced state and decision commitments verify. Historical verification is all-or-nothing for the requested chain.

## 9. Witness Non-Equivocation
A trusted witness maintains durable state for each continuity_root. same root + same sequence + same continuity_hash -> IDEMPOTENT_REPLAY. same root + same sequence + different continuity_hash -> EQUIVOCATION_FORK. sequence greater than head + 1 -> SEQUENCE_GAP. sequence lower than head -> ROLLBACK. valid next sequence with incorrect parent_hash -> PARENT_MISMATCH. Witness state MUST survive restart and MUST be revalidated before new acceptance after recovery.

## 10. Witness Failure and Recovery
The witness MUST use durable write-ahead or equivalent crash-safe persistence for accepted state and receipts. After restart, the witness MUST reconstruct and validate its authoritative head before accepting new proofs. A crash after receiving but before durably committing a proof MUST resolve to either an observable committed receipt or no accepted state; partial acceptance MUST NOT be exposed. Replication, quorum consensus, or multi-node deployment MAY be used as an implementation architecture but is not a V1.1 protocol requirement.

## 11. Witness Receipt
A witness receipt MUST bind a witness signature to at least: continuity_root, sequence, observed proof hash, continuity_hash, and witness head state. The receipt MUST identify the witness verification key or trust reference needed for independent verification. A receiver MUST verify the receipt signature and field bindings before treating witness non-equivocation as established.

## 12. Key Lifecycle
Every signing identity used by V1.1 MUST have a stable key identifier or fingerprint. The trust configuration MUST define whether a key is currently active, retired, or revoked. Historical proofs MAY remain verifiable after key retirement provided the verifier can establish that the key was trusted for the relevant proof. Revoked keys MUST NOT produce newly accepted proofs after their effective revocation point. V1.1 does not mandate a universal key-rotation interval; deployments MUST define a lifecycle policy appropriate to their threat model.

## 13. Portable Evidence Package
A portable package MUST provide enough material for independent verification without access to the source application database. Minimum logical contents are: package schema/version, continuity_root, ordered proof_chain, witness_receipts for the requested verification scope, signer trust references, witness trust references, and policy reference or embedded policy fingerprint. Packaging and transport encoding MAY be ZIP, TAR, CBOR, or another deterministic container; the cryptographic protocol MUST NOT depend on filesystem ordering or archive implementation details.

## 14. Long-Chain Handling
The normative V1.1 verifier MUST be able to validate the requested chain from the trusted root to sequence n. Implementations MAY add checkpoints, cached verification results, Merkle inclusion proofs, or other acceleration structures for long histories. Such optimizations MUST NOT change the underlying parent-binding semantics. continuity_root remains the identifier established for the continuity history; it is NOT redefined as a Merkle root by this specification.

## 15. Independent Receiver
The receiver MUST verify the proof chain and witness receipt using only the portable evidence package, trusted signer material, trusted witness material, and stated policy. Source application database availability MUST NOT be required for historical verification. Verification at sequence n MUST validate every required predecessor unless the package contains a separately specified, cryptographically verifiable checkpoint mechanism.

## 16. Error Taxonomy
Normative error categories include: SEQUENCE_GAP, SEQUENCE_ROLLBACK, REPLAY_DETECTED, IDEMPOTENT_REPLAY, PARENT_MISMATCH, EQUIVOCATION_FORK, SIGNATURE_INVALID, CONTINUITY_HASH_MISMATCH, ROOT_NOT_TRUSTED, WITNESS_STATE_CORRUPT, WITNESS_RECEIPT_TAMPERED, KEY_REVOKED, POLICY_VIOLATION, and PACKAGE_INVALID.

## 17. Threat Model
The adversary MAY read, modify, delay, delete, reorder, or replay messages and MAY present different valid proofs to different verifiers. The adversary MAY attempt to corrupt witness state but is not assumed able to forge a valid signature for a trusted signing key or witness key, nor to defeat the cryptographic assumptions of the configured hash and signature algorithms. V1.1 does not protect against compromise of a trusted signing key unless key revocation and lifecycle controls detect and constrain the compromise.

## 18. Adversarial Requirements
V1.1 MUST test: sequence gap, rollback, same-sequence fork, parent substitution, alternate valid branch, reordered chain, forged signature, rebuilt evidence, signer substitution, witness restart, witness state corruption, witness receipt tampering, key revocation behavior, and source application deletion.

## 19. Formal Verification Plan
The lab formalization SHOULD target at least: no_sequence_gap, parent_binding_soundness, witness_non_equivocation, historical_consistency, replay_resistance, and signature_unforgeability under the stated cryptographic assumptions. Formal results MUST distinguish cryptographic assumptions from protocol invariants.

## 20. Test Vector Format
Conformance tests SHOULD use a deterministic vector structure containing test_id, protocol_version, initial_state, submitted_proofs, witness_actions, expected_result, expected_error, and verification_artifacts. Test vectors MUST NOT depend on wall-clock time or random values unless those values are explicitly fixed in the vector.

## 21. Conformance Levels
Level 1: core proof objects and sequence guard. Level 2: parent binding and historical verification. Level 3: witness non-equivocation and receipts. Level 4: independent historical verification. Level 5: portable evidence package and interoperability vectors.

## 22. Policy Binding
Each proof MUST identify the policy version or policy fingerprint used to produce its decision. Policy changes MUST NOT silently rewrite historical proofs. A deployment MAY define whether a new policy version creates a new continuity root or is permitted within the existing root, but that rule MUST be explicit and verifiable.

## 23. Backward Compatibility
The existing proof-certificate.v1 contract MUST retain its current meaning. V1.1 MUST use an explicit schema/protocol version and MUST NOT silently reinterpret v1 fields. Existing release artifacts MUST remain unchanged during lab development.

## 24. Relationship to Existing Standards
V1.1 may reuse established mechanisms without claiming to originate them: RFC 8785 defines JCS for deterministic JSON canonicalization; RFC 3161 defines trusted time-stamping; RFC 7515 defines JWS structures; RFC 8032 specifies EdDSA including Ed25519; RFC 9162 defines Certificate Transparency v2 and obsoletes RFC 6962; RFC 8949 defines deterministic CBOR; RFC 9943 defines SCITT architecture for transparent signed statements. These standards provide reusable mechanisms or related transparency concepts; they do not by themselves define this session-continuity protocol.

## 25. Scope and Non-Claims
V1.1 does not claim to prove the legitimacy of the original authentication beyond the trust placed in root establishment. It does not prove device ownership, absence of credential compromise, replacement of IAM/OIDC/CAEP, or global non-equivocation outside the configured witness trust domain. A witness can establish non-equivocation only within the scope of the witness trust and state it actually maintains.

## 26. Acceptance Gate
No source-code integration is permitted until the V1.1 lab reference model, baseline comparisons, independent historical verifier, witness receipt model, crash/restart tests, adversarial tests, and deterministic interoperability vectors all pass. Existing production and release artifacts MUST remain unchanged during this phase.
