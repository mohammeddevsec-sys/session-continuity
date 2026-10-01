# Continuity Proof v1.1 - Specification Review
## Status
LAB REVIEW - NOT INTEGRATED

## 1. Security Objective
For a configured continuity root and trusted witness domain, an independently verified proof at sequence n is accepted as a historical descendant only when sequence progression is exact, the proof is cryptographically bound to the immediately preceding proof, and all required signatures and state commitments verify. The witness prevents two different accepted proof hashes for the same continuity root and sequence within its trust domain.

## 2. Root Establishment
A continuity_root MUST be established from an authenticated session root object. The root object MUST canonically bind the identifiers required to identify the authenticated continuity context, including session_id, subject, issuer, authentication time, and the relevant client context. The root MUST be immutable after establishment. V1.1 MUST NOT claim that root establishment alone proves continued legitimacy after authentication.

## 3. Proof Objects
Each continuity proof contains: schema, continuity_root, sequence, parent_hash, state_hash, decision_hash, and continuity_hash. For sequence 1, parent_hash is empty. For n > 1, parent_hash MUST equal the continuity_hash of the immediately preceding verified proof.

## 4. Canonical Hashing
continuity_hash MUST be SHA-256 over the canonical proof core excluding continuity_hash itself. The proof signature MUST cover the complete canonical proof body including continuity_hash. Canonical serialization MUST be deterministic and MUST be defined by the protocol version.

## 5. Sequence Guard
For an established continuity root, a new accepted sequence MUST equal lastAcceptedSequence + 1. A sequence lower than or equal to the accepted sequence MUST be rejected according to the protocol replay/rollback rules. A sequence greater than lastAcceptedSequence + 1 MUST be rejected as SEQUENCE_GAP.

## 6. Parent Binding
A verifier MUST verify the immediately preceding proof before accepting proof n. Sequence numbers alone MUST NOT establish parentage. A proof with a missing, substituted, or unverifiable parent MUST be rejected as PARENT_MISMATCH or the applicable protocol error.

## 7. Historical Verification
CONTINUITY_PROVEN is valid only when: the continuity root is trusted and consistent; every proof signature verifies; every continuity_hash verifies; sequence values are exact; every parent_hash matches the immediately preceding verified proof; and the referenced state and decision commitments verify.

## 8. Witness Non-Equivocation
A trusted witness maintains durable state for each continuity_root. For a submitted proof: same root + same sequence + same continuity_hash -> IDEMPOTENT_REPLAY; same root + same sequence + different continuity_hash -> EQUIVOCATION_FORK; sequence greater than head + 1 -> SEQUENCE_GAP; sequence lower than head -> ROLLBACK; next sequence with incorrect parent_hash -> PARENT_MISMATCH. Witness acceptance MUST be durable and restart-verifiable.

## 9. Witness Receipt
A witness receipt MUST bind the witness signature to the continuity_root, sequence, observed proof hash, continuity_hash, and witness head state. A receiver MUST verify the witness receipt before treating witness non-equivocation as established.

## 10. Independent Receiver
The receiver MUST verify the proof chain and witness receipt using only the portable evidence package, trusted signer material, trusted witness material, and the stated policy. Source application database availability MUST NOT be required for historical verification.

## 11. Adversarial Tests
V1.1 MUST test: sequence gap, rollback, same-sequence fork, parent substitution, alternate valid branch, reordered chain, forged signature, rebuilt evidence, signer substitution, witness restart, witness state corruption, witness receipt tampering, and source application deletion.

## 12. Scope and Non-Claims
V1.1 does not claim to prove the legitimacy of the original authentication beyond the trust placed in root establishment. It does not prove device ownership, absence of credential compromise, replacement of IAM/OIDC/CAEP, or global non-equivocation outside the configured witness trust domain.

## 13. Backward Compatibility
The existing proof-certificate.v1 contract MUST retain its current meaning. V1.1 SHOULD use an explicit protocol/schema version rather than silently changing v1 semantics.

## 14. Acceptance Gate
No source integration is permitted until the lab reference model, baseline comparisons, independent historical verifier, witness receipt model, and adversarial tests all pass. Existing release artifacts MUST remain unchanged during this phase.
