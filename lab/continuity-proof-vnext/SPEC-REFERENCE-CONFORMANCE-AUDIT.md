# SPEC <-> LAB Reference Conformance Audit v1.1

## Status
LAB AUDIT - NO PRODUCT INTEGRATION

## Result
The hardened specification is NOT yet fully represented by the current reference models. The existing models remain valid as historical primitive tests, but they are not conformance evidence for the hardened specification.

## Confirmed Matches
- Exact sequence progression is modeled by the parent-bound reference witness and chain verifier.
- Parent binding is modeled through parent_hash -> continuity_hash.
- Same-sequence alternate proof detection is modeled as EQUIVOCATION_FORK.
- Historical reordered-chain and parent-substitution rejection are modeled.
- Witness receipt signature and proof binding are modeled for a single proof.

## Confirmed Gaps
1. CANONICALIZATION: the reference uses JSON.stringify rather than RFC 8785 JCS; this is not conformant evidence for the hardened specification.
2. ISSUED_AT: the current parent-bound reference does not include issued_at in the proof core and therefore does not test the timestamp field required by the hardened specification.
3. ROOT_ESTABLISHMENT: the reference computes a test root but does not implement and verify the normative authenticated root-establishment object.
4. WITNESS_DURABILITY: the current witness reference is in-memory and therefore does not prove durable restart recovery.
5. WITNESS_RECEIPT_SCOPE: the current receipt model covers sequence 1 only and does not prove receipt behavior across a multi-proof chain.
6. KEY_LIFECYCLE: the reference does not test active, retired, or revoked signer states.
7. PORTABLE_PACKAGE: no independent package verifier yet consumes an ordered proof chain plus witness receipts and trust references as a protocol object.
8. LONG_CHAIN: no reference or test vector currently covers verification from root through an arbitrary n beyond the small fixtures.
9. FORMAL_MODEL: no formal verifier/model currently establishes the stated invariants under explicit assumptions.

## Required Next Reference Version
The next reference implementation MUST implement JCS-compatible canonicalization, issued_at, explicit root establishment, parent-bound proofs, exact sequence progression, durable witness state, signed witness receipts for multiple sequences, key lifecycle states, and independent verification of a portable proof package.

## Integration Gate
No source-code integration is permitted until the next reference implementation and its conformance tests satisfy the hardened specification and the existing baselines remain reproducible.

## Safety
Only lab artifacts may change during this phase. src and release artifacts remain untouched.
