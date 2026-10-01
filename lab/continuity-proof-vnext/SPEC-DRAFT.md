# Continuity Proof v1.1 — Specification Draft

## Status
LAB DRAFT — NOT INTEGRATED INTO PRODUCT

## Security Objective
For a configured continuity root and trusted witness domain, an independently verified proof at sequence n is accepted as a historical descendant only when its parent binding references the immediately preceding verified proof and sequence progression is exact. A witness rejects two distinct accepted proof hashes for the same continuity root and sequence.

## Proven Baseline Findings
- Current durable session state accepts a sequence gap such as 1 -> 3.
- Current product can produce two locally accepted proofs at sequence 2 from the same accepted P1 state.
- The two P2 certificates can differ while both remain locally verifiable.
- The two branches can continue independently to sequence 3 and remain locally verifiable.
- The current provenance certificate contains no explicit parent_hash or previous_proof_hash field.
- These findings are baseline observations from lab tests only; they are not claims of universal weakness across all session systems.

## V1.1 Objects
1. continuity_root — immutable root identifier for one continuity history.
2. sequence — positive integer beginning at 1.
3. parent_hash — cryptographic identifier of the immediately preceding verified continuity proof; empty only for sequence 1.
4. state_hash — hash of the canonical accepted session state relevant to the proof.
5. decision_hash — hash of the canonical decision and policy context.
6. continuity_hash — hash of the canonical proof core excluding continuity_hash itself.
7. continuity_proof — signed proof containing the fields above.
8. witness_receipt — independently signed statement recording the observed proof hash, root, sequence, continuity_hash, and witness head.

## Proof Core
The canonical proof core is: schema, continuity_root, sequence, parent_hash, state_hash, decision_hash. continuity_hash = SHA-256(canonical proof core). The proof signature covers the complete canonical proof body including continuity_hash.

## Sequence Guard
For an established root, accepted sequence must satisfy: sequence = lastAcceptedSequence + 1. A lower or equal sequence is rejected as rollback/replay. A greater sequence is rejected as SEQUENCE_GAP.

## Parent Binding
For n > 1: parent_hash(n) MUST equal continuity_hash(n-1) of the immediately preceding verified proof. A verifier MUST NOT infer parentage from sequence numbers alone.

## Historical Verification
A chain is CONTINUITY_PROVEN only when every proof signature is valid, the continuity root is consistent, sequence values are exact, each parent_hash matches the immediately previous verified proof, and all state/decision hashes are valid.

## Witness Non-Equivocation
The witness maintains one accepted head per continuity_root.
- same root + same sequence + same continuity_hash -> IDEMPOTENT_REPLAY
- same root + same sequence + different continuity_hash -> EQUIVOCATION_FORK
- sequence > head + 1 -> SEQUENCE_GAP
- sequence < head -> ROLLBACK
- valid next sequence with incorrect parent_hash -> PARENT_MISMATCH

## Independent Receiver
The receiver MUST be able to verify the proof chain and witness receipt using only the portable proof package, trusted signer/witness material, and stated policy. Source application database availability is not a prerequisite for historical verification.

## Adversarial Requirements
V1.1 MUST test: sequence gap, rollback, same-sequence fork, parent substitution, alternate valid branch, reordered chain, forged signature, rebuilt evidence, signer substitution, witness restart, witness state corruption, and source application deletion.

## Non-Claims
This specification does not claim to prove the legitimacy of the original authentication event, device ownership, absence of credential compromise, replacement of IAM/OIDC/CAEP, or global non-equivocation outside the configured witness trust domain.

## Integration Rule
The existing proof-certificate.v1 contract remains backward-compatible. V1.1 SHOULD be introduced as an explicit protocol/version rather than silently changing the meaning of v1.

## Acceptance Criterion
No source-code integration is approved until the V1.1 lab reference model, baseline comparisons, adversarial tests, and independent historical verifier all pass without modifying the current release artifacts.
