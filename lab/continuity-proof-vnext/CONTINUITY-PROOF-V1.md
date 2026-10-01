# Continuity Proof V1

## 1. Security Objective

Prove that an accepted session state is a cryptographic descendant of one authenticated continuity root and that the accepted history is non-equivocating within the configured witness trust domain.

## 2. Required Objects

- `continuity_root`: immutable identifier derived from the authenticated session anchor.
- `sequence`: strictly increasing integer beginning at 1.
- `parent_hash`: hash of the immediately preceding accepted continuity proof.
- `state_hash`: hash of the canonical current continuity state.
- `decision_hash`: hash of the exact accepted decision and policy binding.
- `continuity_hash`: hash over root, sequence, parent, state, and decision commitments.
- `continuity_proof`: signed statement containing the above commitments.
- `witness_receipt`: independently signed statement that the witness accepted this exact continuity hash at this sequence.

## 3. Continuity Rule

For sequence `n > 1`:

`parent_hash(n) = H(continuity_proof(n-1))`

`sequence(n) = sequence(n-1) + 1`

`continuity_hash(n) = H(continuity_root || sequence || parent_hash || state_hash || decision_hash)`

A verifier MUST reject any proof whose parent or sequence does not match the previously witnessed head.

## 4. Witness Rule

For a given `continuity_root` and trust domain, a witness MUST maintain one accepted head.

For the same sequence:
- identical continuity hash MAY be replayed idempotently;
- different continuity hash MUST be rejected as `EQUIVOCATION_FORK`.

A sequence greater than `head + 1` MUST be rejected as `SEQUENCE_GAP`.
A sequence lower than `head` MUST be rejected as `ROLLBACK`.

## 5. Independent Verification

The receiver MUST verify:

1. signer authenticity and trust;
2. continuity root;
3. sequence continuity;
4. parent hash;
5. state hash;
6. decision/policy binding;
7. witness receipt;
8. consistency between witness head and presented proof.

The receiver MUST NOT require access to the originating application database to establish the continuity claim.

## 6. Non-Equivocation Property

For one `continuity_root`, a configured witness trust domain MUST NOT accept two different continuity hashes for the same sequence.

This property depends on the witness trust assumption. A single compromised witness can violate availability or report false state; threshold witnesses may be required for stronger trust assumptions.

## 7. What This Protocol Does NOT Claim

- It does not prove that the original authentication was legitimate unless the authentication anchor is trusted.
- It does not prove that a device is uncompromised.
- It does not replace OIDC, CAEP, IAM, or application session management.
- It does not prove absence of compromise; it proves the continuity relation represented by the accepted chain.
- It does not claim global uniqueness over existing standards or products.

## 8. Mandatory Adversarial Tests

- sequence gap: `1 -> 3`;
- rollback: `1 -> 2 -> 1`;
- same-sequence fork: `2A != 2B`;
- parent substitution;
- rebuilt evidence;
- signer substitution;
- witness restart;
- witness state corruption;
- stale witness receipt;
- source application unavailable;
- independent receiver verification.

## 9. Success Condition

`CONTINUITY_PROVEN` is valid only when the proof, parent chain, witness receipt, trust decision, and independent verification all succeed.

`NON_EQUIVOCATION_PROVEN` is valid only when the witness trust assumptions are satisfied and no conflicting accepted history exists for the same root and sequence.
