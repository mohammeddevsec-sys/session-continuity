# Session Continuity Evidence: A Protocol for Verifiable Session Provenance

**Author:** Mohammed N.Zomam
**Contact:** [to be provided at submission]
**Date:** September 2026
**Subject Class:** cs.CR (Cryptography and Security)

---

## Abstract

Modern identity and access management systems authenticate users and issue session tokens, but they do not produce durable cryptographic evidence that a later accepted session is the legitimate continuation of an earlier authenticated session. After a security incident, an auditor, an incident-response team, or a regulator cannot independently verify whether the accepted session chain is intact, was forked, was truncated, or was rebuilt by an attacker. Existing mechanisms—JWT, OAuth 2.0 session tokens, Proof of Possession, and Continuous Access Evaluation—address adjacent problems but do not produce portable, independently verifiable evidence of session continuity.

This paper presents Session Continuity Evidence (SCE), a vendor-neutral protocol that establishes cryptographic continuity from a trusted authenticated session root through an ordered proof chain, durable witness observations, and independently verifiable portable evidence. The protocol separates the local acceptance decision from a durable witness that detects equivocation, and it packages the evidence so that a third party can verify the chain offline without access to the source application, the live witness, or the network.

We describe the protocol, present a reference implementation consisting of nine modules with zero external runtime dependencies, and evaluate its correctness, adversarial resistance, performance, and package manifest. The reference implementation passes 251 named audit checks across twenty independent probes, including a 41-test v1 regression suite and twelve v1.1 conformance probes. It produces byte-identical output across independent processes, matches RFC 8032 Ed25519 golden vectors byte-for-byte, builds a 1,000-proof chain in 71 ms, and verifies it in 130 ms. The protocol does not claim first-in-world status, universal non-equivocation, legal admissibility, or replacement of existing IAM systems. Its contribution is a precise, tested, and openly specified construction that fills a documented gap in session provenance.

## 1. Introduction

### 1.1 The Problem

Authentication systems answer one question well: "Is this principal who they claim to be at the moment of authentication?" They answer a second question poorly: "Is this later accepted session the legitimate continuation of that authenticated session?"

Consider a scenario. A user authenticates to an application at time T0. The application issues a session token. Over the next several hours, the user performs sensitive actions. At time T5, a security incident is reported. Investigators want to know whether the session that performed each action was a legitimate continuation of the session that began at T0, or whether an attacker inserted themselves into the chain at some point.

Existing mechanisms do not provide portable evidence. A JWT carries a signature over a fixed set of claims, but it does not encode its position in a chain. An OAuth 2.0 refresh-token rotation scheme provides replay resistance within a single issuer, but it does not produce evidence that a third party can verify independently. Continuous Access Evaluation protocols dynamically adjust access, but they produce operational logs, not cryptographic proofs. Proof of Possession binds a token to a key, but it does not bind a token to a chain of prior tokens.

The gap is precise: no existing protocol produces a portable artifact that a third party can verify to establish that a session that ended at Tn was the continuation of a session that began at T0.

### 1.2 Contribution

This paper makes four contributions.

First, we specify a protocol, Session Continuity Evidence (SCE), that produces exactly such an artifact. The protocol consists of a continuity root, an ordered proof chain, a durable witness that detects equivocation, a portable evidence package, and a key lifecycle that distinguishes active, retired, and revoked keys while preserving historical verifiability.

Second, we provide a normative reference implementation in the form of nine JavaScript modules with zero external runtime dependencies. The implementation is deterministic: two consecutive runs of the same input produce byte-identical output.

Third, we evaluate the implementation. It passes 251 named audit checks across twenty independent probes, including a 41-test v1 regression suite and twelve v1.1 conformance probes. It matches RFC 8032 Ed25519 golden vectors byte-for-byte, builds a 1,000-proof chain in 71 ms and verifies it in 130 ms, declares the reference package as a public `session-continuity@0.2.0` package (Apache-2.0), and rejects thirty-four categories of adversarial input across chain, witness, package, and key-lifecycle layers.

Fourth, we publish the specification, the reference implementation, and the test vectors so that any third party can reproduce the results. The reference implementation is preserved alongside the existing v1 production namespace without any modification to the v1 contract.

### 1.3 Organization

Section 2 reviews related work. Section 3 defines the threat model and assumptions. Section 4 presents the protocol. Section 5 describes the reference implementation. Section 6 reports evaluation results. Section 7 discusses design decisions. Section 8 states limitations and future work. Section 9 concludes.

## 2. Background and Related Work

### 2.1 Identity and Access Management

OpenID Connect (OIDC) specifies a layered identity protocol on top of OAuth 2.0. It defines ID tokens, UserInfo endpoints, and session management, but it does not define a portable artifact that binds successive session decisions into a verifiable chain.

Security Assertion Markup Language (SAML) provides federation and single sign-on. Like OIDC, SAML produces signed assertions about authentication events but does not produce a chain of evidence across a session lifetime.

OAuth 2.0 defines token issuance, refresh, and revocation. Refresh-token rotation provides replay resistance, but the evidence of rotation is held by the authorization server, not published in a form that a third party can independently verify.

### 2.2 Transparency Logs

Certificate Transparency (RFC 9162) introduced the concept of an append-only Merkle tree log for X.509 certificates. It solved a specific problem: detecting misissuance by certificate authorities. Its core ideas—immutable append-only logs, Merkle inclusion proofs, monitors, and auditors—are directly relevant to session provenance, but CT operates on certificates that have long validity periods, not on session events that occur at high frequency within a single application.

Supply Chain Integrity, Transparency, and Trust (SCITT, RFC 9943) generalizes the CT model to signed statements about supply chain artifacts. SCITT defines an architecture, not a session-specific protocol.

CONIKS and similar key-transparency systems apply the CT model to public-key directories. They solve the directory-equivocation problem, not the session-chain problem.

### 2.3 Token Binding and Proof of Possession

Proof of Possession (PoP) binds a token to a cryptographic key held by the client. It prevents token theft in transit but does not bind a token to a chain of prior tokens.

Macaroons and Biscuit tokens encode authorization attenuation in a cryptographic structure. They allow a bearer to restrict capabilities, but they do not produce evidence about the order of issuance.

PASETO (Platform-Agnostic Security Tokens) is a secure alternative to JWT. It provides authenticated encryption and versioning. It does not address session chaining.

### 2.4 Related Standards

RFC 8785 specifies the JSON Canonicalization Scheme (JCS), which we adopt for canonical serialization. RFC 8032 specifies EdDSA including Ed25519, which we adopt for signing. RFC 3161 specifies trusted timestamps, which a deployment may use to add a third-party time anchor.

NIST Special Publication 800-63B provides guidance on digital identity, including session management. It recommends binding sessions to cryptographic secrets but does not specify a chain of evidence.

None of the reviewed standards or systems produce a portable, independently verifiable artifact that proves session continuity. This is the gap SCE addresses.

## 3. Threat Model and Assumptions

### 3.1 Adversary Capabilities

We assume a Dolev-Yao adversary with the following capabilities:

- The adversary may read, modify, delay, delete, reorder, or replay any message between any two principals.
- The adversary may present different valid proofs to different verifiers (equivocation).
- The adversary may attempt to corrupt durable witness state.
- The adversary may attempt to compromise signing keys or witness keys.

We assume the adversary does NOT have the following capabilities:

- The adversary cannot forge an Ed25519 signature without the corresponding private key.
- The adversary cannot find a SHA-256 collision.
- The adversary cannot extract a private key from a correctly implemented hardware security module.

### 3.2 Trust Assumptions

The protocol assumes the following trust configuration:

- A deployment has established at least one continuity root through an authenticated session establishment process. Root establishment is a deployment trust boundary, not a protocol property.
- A deployment has configured one or more witness trust domains, each identified by a witness domain identifier and a witness public key.
- A deployment has published signer trust material and witness trust material in a form that independent verifiers can obtain.

### 3.3 Non-Claims

The protocol explicitly does not claim:

- First-in-world status. Transparency logs, witness-based non-equivocation, and proof chains all exist in prior systems. The contribution is their composition for session continuity, not the invention of any single mechanism.
- Universal non-equivocation. A witness establishes non-equivocation only within its configured witness trust domain.
- Proof of legitimacy of the original authentication. The protocol proves continuity from a trusted root, not that the root was legitimately established.
- Proof of device ownership, absence of credential compromise, or correctness of the original identity assertions.
- Legal admissibility in any jurisdiction.
- Replacement of IAM, OIDC, CAEP, or session-risk systems.

## 4. Protocol Design

### 4.1 Overview

The protocol produces evidence of session continuity across five layers: a continuity root, an ordered proof chain, a durable witness, a portable evidence package, and a key lifecycle. Each layer has a distinct responsibility and a distinct trust boundary.

The continuity root establishes the authenticated session context. Each proof in the chain commits to the previous proof and to a decision made by the source application. A durable witness independently observes each proof and signs a receipt. The receipts and proofs are packaged together with trust material, so a third party can verify the chain offline without contacting the source application, the witness, or the network. The key lifecycle governs active, retired, and revoked keys and preserves the verifiability of historical proofs.

### 4.2 Continuity Root

A continuity root is derived from an authenticated session root object. The root object binds at minimum: a session identifier, a subject, an issuer, an authentication time, and a client context. The root object is immutable once established. The continuity root value is `SHA-256(canonical(root_object))`.

The protocol deliberately does not specify how the root object is authenticated. Root establishment is a deployment trust boundary. A verifier that trusts a continuity root has made an external trust decision; the protocol does not manufacture that trust.

### 4.3 Proof Object

Each proof is a JSON object with the following fields:

- `schema` — fixed string `continuity-proof.v1.1`.
- `continuity_root` — 64-hex continuity root value.
- `sequence` — positive integer, starting at 1.
- `parent_hash` — JSON null at sequence 1, otherwise the `continuity_hash` of the immediately preceding proof.
- `state_hash` — 64-hex commitment to application state.
- `decision_hash` — 64-hex commitment to the local decision.
- `issued_at` — RFC 3339 UTC timestamp with exactly three fractional digits and uppercase `Z`.
- `signer_key_id` — stable identifier for the signing key.
- `policy_fingerprint_sha256` — 64-hex commitment to the decision policy.
- `continuity_hash` — SHA-256 over the canonical serialization of the proof core (all fields except `continuity_hash`).

The proof signature covers the complete canonical proof body including `continuity_hash`. The signature is Ed25519.

### 4.4 Canonical Serialization

The protocol uses the JSON Canonicalization Scheme (JCS, RFC 8785) for canonical serialization of the proof core. The V1.1 profile adds strict restrictions beyond JCS itself: `-0` is rejected, `NaN` and `Infinity` are rejected, lone surrogate code units are rejected, and object prototype must be `Object.prototype` or `null`. These restrictions are not part of RFC 8785; they are profile-specific and are stated explicitly so that independent implementations converge.

Implementations MUST NOT apply additional Unicode normalization. Protocol counters MUST be JSON integers.

### 4.5 Sequence Guard

The sequence value is the authoritative continuity order. A new accepted sequence MUST equal `lastAcceptedSequence + 1`.

- A lower sequence MUST be rejected as `SEQUENCE_ROLLBACK`.
- An equal sequence with the same `continuity_hash` MAY be treated as `IDEMPOTENT_REPLAY`.
- An equal sequence with a different `continuity_hash` MUST be treated as `EQUIVOCATION_FORK` by a witness.
- A greater sequence MUST be rejected as `SEQUENCE_GAP`.

The sequence guard is implemented in two forms: an in-memory guard for tests, and a durable guard that persists accepted sequences to a crash-safe journal with an authoritative head. The durable guard reconstructs and validates the head on restart before accepting new proofs.

### 4.6 Parent Binding

A verifier MUST verify the immediately preceding proof before accepting proof n. Sequence numbers alone MUST NOT establish parentage. Missing, substituted, or unverifiable parent material MUST cause rejection. An isolated proof MUST NOT be reported as `CONTINUITY_PROVEN` merely because its signature and commitments are individually valid.

### 4.7 Durable Witness

A witness maintains durable state per `continuity_root` and `witness_domain_id`. For each observed proof, the witness records the `continuity_hash` and `proof_hash`. When the same `continuity_root` and `sequence` are observed with a different `continuity_hash`, the witness classifies the event as `EQUIVOCATION_FORK` and emits a signed receipt.

The witness uses a write-ahead journal with a head record. The head is validated on every operation. If recovery fails, the witness fails closed: it refuses new proofs and refuses to emit new receipts. Read-only verification of historical receipts remains available. The witness writes its state using atomic file replacement to ensure that a crash resolves to either a committed receipt or no accepted state.

### 4.8 Witness Receipt

A witness receipt binds: `continuity_root`, `sequence`, observed `proof_hash`, `continuity_hash`, `witness_head_sequence`, `witness_head_hash`, `witness_domain_id`, `witness_key_id`, and `issued_at`. The receipt is signed by the witness key, which is distinct from any signer key used to sign proofs. This separation ensures that compromise of a signer key does not enable receipt forgery.

Receipt verification requires only the witness public key. It does not require contacting the witness.

### 4.9 Witness Equivocation Evidence

Witness equivocation is externally provable when two validly signed witness receipts share the same `witness_domain_id`, the same `witness_key_id`, the same `continuity_root`, and the same `sequence`, but contain different `continuity_hash` values. The two receipts together constitute evidence of equivocation and are verifiable without trusting the witness to report its own misbehavior.

Cross-witness-domain observations do NOT constitute global equivocation. Two receipts from different witness domains that disagree on a continuity value prove only that the domains observed different states. A global non-equivocation claim requires an explicitly defined common trust or aggregation domain beyond the scope of this protocol.

### 4.10 Key Lifecycle

Every signing and witness identity has a stable key identifier. Key state distinguishes three values: `ACTIVE`, `RETIRED`, and `REVOKED`.

- `ACTIVE` keys may sign new proofs and new receipts.
- `RETIRED` keys may not sign new proofs, but proofs issued before retirement remain cryptographically verifiable.
- `REVOKED` keys may not sign new proofs, and proofs issued after the effective revocation point are rejected.

A deployment MAY additionally define a compromise window `[start, end]` associated with a revoked key. Proofs whose `issued_at` falls within the compromise window are rejected regardless of signature validity. Proofs issued before the compromise window remain historically valid.

Cryptographic signature validity and compromise disposition are separate concepts. A key compromise declaration MUST NOT retroactively rewrite historical signatures.

### 4.11 Portable Evidence Package

A portable evidence package is a JSON object that contains: package schema and version, continuity root, the ordered proof chain, witness receipts, signer trust material, witness trust material, policy references, and a package signature. The package is signed by a packager key, which is distinct from both the signer key and the witness key.

The package signature protects package authenticity. It MUST NOT substitute for verification of the contained evidence. The independent verifier MUST verify: the package signature, the continuity root, the proof chain, every proof signature, every witness receipt, the trust anchors, and the policy bindings. The verifier distinguishes the following states: `PACKAGE_AUTHENTIC`, `EVIDENCE_VALID`, `WITNESS_EVIDENCE_VALID`, `POLICY_VALID`, `CONTINUITY_PROVEN`, and `CONTINUITY_COMPLETE`.

### 4.12 Completeness and Truncation

A valid prefix MUST NOT be interpreted as the complete history. `PREFIX_VALID` proves only the supplied interval. `CONTINUITY_COMPLETE` requires independent finality evidence, such as a trusted final checkpoint or an explicit session-closure statement bound to the final continuity hash. `chain_length` alone MUST NOT establish completeness.

## 5. Reference Implementation

### 5.1 Structure

The reference implementation consists of nine JavaScript modules, organized as four core modules and five evidence modules. The implementation has zero external runtime dependencies beyond the Node.js standard library.

Core modules:

- `canonical-v1_1.js` — JCS profile with V1.1 restrictions.
- `continuity-proof-v1_1.js` — proof construction and chain verification.
- `sequence-guard-v1_1.js` — in-memory exact-sequence verification.
- `durable-sequence-guard-v1_1.js` — durable sequence journal with crash safety.

Evidence modules:

- `proof-signature-v1_1.js` — Ed25519 signer and verifier.
- `trusted-proof-verifier-v1_1.js` — trusted chain verification with key-lifecycle integration.
- `witness-v1_1.js` — durable witness with equivocation detection and fail-closed recovery.
- `portable-package-v1_1.js` — package builder and verifier.
- `key-lifecycle-v1_1.js` — active, retired, and revoked key state machine.

### 5.2 Source-Tree Digest

The reference tree digest at publication is:

    SRC_TREE_SHA256 = 941DE3DAC25B80B82D8ECC38D6A1C3F8F0BE085205A1AC339E2CB99D3CD7DE5F

The digest is computed by hashing the lexicographically ordered list of relative file paths and file contents under `src/`, excluding any file whose name contains `.backup_`, into a single SHA-256.

### 5.3 Determinism

The reference implementation is deterministic. Two consecutive runs of the reference test harness `lab/PROOF.mjs` produce byte-identical output:

    PROOF_RUN_SHA256 = 48FF8147BEADE14AA74697B70532185DF276100B592676DC06E769F4C40B12C5

The determinism property is verified by an explicit check within `PROOF.mjs` that compares the SHA-256 of two independent runs.

### 5.4 Coexistence with v1

The reference implementation preserves the existing v1 production namespace `session-continuity.proof-certificate.v1` without modification. The v1 regression suite of 41 tests continues to pass. The v1.1 modules live under distinct filenames and are not imported by any v1 module. The two namespaces coexist.

### 5.5 Diagnostic Output

The reference implementation attaches a diagnostic envelope to each decision result. The envelope contains four fields: `reason_code`, `failure_stage`, `failure_location`, and `evidence_ref`.

These fields are attached to the decision envelope and are not part of the cryptographic proof core. They do not enter `decision_hash` or `continuity_hash`, and they do not alter the v1 or v1.1 contract semantics. Their purpose is operational: they allow a caller to distinguish between a replay failure, a continuity failure, a challenge failure, a proof-of-possession failure, and other rejection classes without requiring out-of-band knowledge.

The diagnostic envelope is covered by dedicated tests: `test/diagnostic-session-continuity.js` for the base decision categories, `test/diagnostic-challenge-branches.js` for the challenge rejection branches, and `test/diagnostic-reason-code-coverage.js` for a static coverage check that ensures future reason codes do not silently fall through to an unclassified state.
## 6. Evaluation

### 6.1 Methodology

The current named evidence snapshot was produced by executing twenty reference probes against the reference tree digest listed in Section 5.2. The complete audit artifact is `lab/EVIDENCE-AUDIT.md` with SHA-256:

    883FEBE7E12F6966B8454A5B6DF232AD9BAD4C9F5A21A9207144D5E6DA83007A

Every check is named, and every probe's source SHA-256 is recorded so that the audit is independently reproducible.

The current evidence snapshot covers 251 named checks across twenty probes. All 251 pass; zero fail.

| Probe | SHA-256 (16 hex) | Checks | PASS |
|---|---|---|---|
| `PROOF.mjs` | `AAA12410D71AE898` | 11 | 11 |
| `_full-audit.mjs` | `5067FB2C21EEC8AB` | 32 | 32 |
| `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | 13 | 13 |
| `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | 6 | 6 |
| `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | 7 | 7 |
| `v1_1-scale-chain-probe.mjs` | `C9CA5E0AF62DF0D5` | 2 | 2 |
| `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | 7 | 7 |
| `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | 9 | 9 |
| `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | 22 | 22 |
| `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | 13 | 13 |
| `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | 10 | 10 |
| `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | 9 | 9 |
| `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | 25 | 25 |
| `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | 28 | 28 |
| `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | 7 | 7 |

### 6.2 Correctness — Implementation Conforms to Protocol

Named checks verifying that the reference implementation behaves as the protocol specifies. Every check below is produced by the probe listed in its row. Probe SHA-256 values are in Section 6.1. Reproduction: run the probe from the repository root; the same check name and the same result will appear in the output.

| Check | Probe | What It Verifies |
|---|---|---|
| `IDENTITY_CREATED` | `v1_1-integration-probe.mjs` | Ed25519 identity creation |
| `ROOT_CREATED` | `v1_1-integration-probe.mjs` | Continuity root derived from session root |
| `CORE_CREATED` | `v1_1-integration-probe.mjs` | Proof core constructed with schema `continuity-proof.v1.1` |
| `HASH_ADDED` | `v1_1-integration-probe.mjs` | `continuity_hash` added exactly once |
| `SIGNED` | `v1_1-integration-probe.mjs` | Proof signed with schema-bound payload |
| `VERIFIED` | `v1_1-integration-probe.mjs` | Signed proof verifies as `PROOF_SIGNATURE_VALID` |
| `CHAIN_VERIFY` | `v1_1-chain-probe.mjs` | Three-proof chain verifies as `CONTINUITY_PROVEN` |
| `CHAIN_HEAD` | `v1_1-chain-probe.mjs` | Chain head equals final `continuity_hash` |
| `VERIFIED` | `v1_1-scale-chain-probe.mjs` | 100-proof chain verifies |
| `HEAD_MATCH` | `v1_1-scale-chain-probe.mjs` | Head matches expected value |
| `J_SCALE_1000_VERIFIED` | `_full-audit.mjs` | 1,000-proof chain verifies |
| `SEQ_1` `SEQ_2` `SEQ_3` | `v1_1-full-integration-probe.mjs` | Exact sequence progression 1 to 3 |
| `SEQ_POST_RESTART_4` | `v1_1-full-integration-probe.mjs` | Sequence progression continues after restart |
| `D_RFC8032_PUBLIC_KEY` | `_full-audit.mjs` | Public key matches RFC 8032 Section 7.1 Test 1 byte-for-byte |
| `D_RFC8032_SIGNATURE` | `_full-audit.mjs` | Signature matches RFC 8032 Section 7.1 Test 1 byte-for-byte |
| `D_RFC8032_VERIFY` | `_full-audit.mjs` | RFC 8032 Test 1 signature verifies |
| `E_NEGATIVE_ZERO_REJECTED` | `_full-audit.mjs` | `-0` rejected by canonical profile |
| `E_NAN_REJECTED` | `_full-audit.mjs` | `NaN` rejected |
| `E_INFINITY_REJECTED` | `_full-audit.mjs` | `Infinity` rejected |
| `E_LONE_SURROGATE_REJECTED` | `_full-audit.mjs` | Lone surrogate rejected |
| `E_RECURSIVE_SORT` | `_full-audit.mjs` | Recursive object sort correct |
| `F_V1_UTF16_ORDER` | `_full-audit.mjs` | UTF-16 property ordering per RFC 8785 rules |
| `F_V1_V11_AGREE` | `_full-audit.mjs` | v1 and v1.1 canonical functions agree |

### 6.3 Adversarial Resistance — Attacks Rejected

Named checks verifying that specific adversarial inputs are rejected with specific reasons.

| Attack | Check | Reason |
|---|---|---|
| Tampered decision commitment | `NC1_TAMPERED_DECISION_REJECTED` | `SIGNATURE_INVALID` |
| Tampered continuity hash | `NC2_TAMPERED_HASH_REJECTED` | `SIGNATURE_INVALID` |
| Recomputed hash mismatch | `NC3_HASH_MISMATCH_REJECTED` | `CONTINUITY_HASH_MISMATCH` |
| Empty proof chain | `NC4_EMPTY_CHAIN_REJECTED` | `EMPTY_CHAIN` |
| Missing verifier function | `NC5_MISSING_VERIFIER_REJECTED` | `SIGNATURE_VERIFIER_REQUIRED` |
| Wrong schema identifier | `NC6_WRONG_SCHEMA_REJECTED` | `CERTIFICATE_INVALID` |
| Chain tampered proof | `TAMPER_REJECTED` | `SIGNATURE_INVALID` |
| Chain wrong parent | `WRONG_PARENT_REJECTED` | `SIGNATURE_INVALID` |
| Chain sequence gap | `SEQUENCE_GAP_REJECTED` | `SEQUENCE_MISMATCH` |
| Chain wrong root | `WRONG_ROOT_REJECTED` | `ROOT_NOT_TRUSTED` |
| Undeclared signer chain | `ATTACKER_CHAIN_REJECTED` | `SIGNER_NOT_TRUSTED` |
| Revoked signer | `REVOKED_SIGNER_REJECTED` | `SIGNER_REVOKED` |
| Package tampered proof | `TAMPERED_PROOF_DEEP_REJECTED` | `PACKAGE_CHAIN_SIGNATURE_INVALID` |
| Package tampered receipt | `TAMPERED_RECEIPT_DEEP_REJECTED` | `PACKAGE_WITNESS_RECEIPT_INVALID` |
| Package fake packager | `FAKE_PACKAGER_REJECTED` | `PACKAGE_PACKAGER_NOT_TRUSTED` |
| Package undeclared signer | `UNDECLARED_SIGNER_DEEP_REJECTED` | `PACKAGE_PROOF_SIGNER_NOT_DECLARED` |
| Package wrong root | `WRONG_ROOT_DEEP_REJECTED` | `PACKAGE_CHAIN_ROOT_NOT_TRUSTED` |
| Package receipt binding mismatch | `RECEIPT_BINDING_DEEP_REJECTED` | `PACKAGE_WITNESS_RECEIPT_INVALID` |
| Witness same-domain fork | `SEQ1_EQUIVOCATION` | `EQUIVOCATION_FORK` |
| Witness fork emits receipt | `SEQ1_EQUIVOCATION_HAS_RECEIPT` | signed fork receipt present |
| Witness external proof of equivocation | `SAME_DOMAIN_EQUIVOCATION` | `EQUIVOCATION_FORK` |
| Witness state corruption | `HEALTH_CORRUPT_FAIL_CLOSED` | `FAIL_CLOSED` |
| Witness refuses on corruption | `OBSERVE_REJECTED_WHEN_CORRUPT` | `WITNESS_STATE_JSON_INVALID:FAIL_CLOSED` |
| Witness restart recovery | `RESTART_VERIFY` `HEALTH_RESTORED_OK` | state recovered and resumed |
| Sequence rollback | `SEQ_ROLLBACK_REJECTED` | `SEQUENCE_ROLLBACK` |
| Sequence replay | `SEQ_REPLAY_REJECTED` | `SEQUENCE_ROLLBACK` |
| Durable journal rollback | `ROLLBACK_DETECTED` | `HEAD_HEIGHT_MISMATCH` |
| Durable journal corruption | `CORRUPTION_DETECTED` | JSON parse error |
| Post-retirement proof | `PROOF_AFTER_RETIRE_REJECTED` | `PROOF_AFTER_RETIREMENT` |
| Compromise-window proof | `PROOF_WITHIN_COMPROMISE_REJECTED` | `PROOF_WITHIN_COMPROMISE_WINDOW` |
| Revoked signing attempt | `CAN_SIGN_REVOKED` | not allowed |
| Lifecycle missing store | `NO_LIFECYCLE_STORE_REJECTED` | `KEY_LIFECYCLE_STORE_REQUIRED` |
| Lifecycle unregistered key | `UNREGISTERED_KEY_REJECTED` | `KEY_NOT_IN_LIFECYCLE_STORE` |
| Lifecycle require-active-now | `REQUIRE_ACTIVE_NOW_REJECTED` | `KEY_NOT_ACTIVE_NOW` |

### 6.4 Performance

Measured on Windows 11 with Node.js v24.8.0. Each measurement includes Ed25519 signature generation or verification per proof, canonical hash recomputation, exact sequence check, and parent-binding check. No network I/O is involved. The workload is purely local. Repeated runs produce the same results within measurement noise.

| Operation | Duration | Source |
|---|---|---|
| Build 100-proof chain | 10 ms | `v1_1-scale-chain-probe.mjs` |
| Verify 100-proof chain | 13 ms | `v1_1-scale-chain-probe.mjs` |
| Build 1,000-proof chain | 71 ms | `_full-audit.mjs` |
| Verify 1,000-proof chain | 130 ms | `_full-audit.mjs` |
| Build per proof | 0.10 ms | derived |
| Verify per proof | 0.13 ms | derived |

The protocol does not require Merkle acceleration at the tested 1,000-proof scale.

### 6.5 Package Manifest

The current reference package is identified from `package.json`. This section deliberately avoids a current compressed-size or file-count claim because no retained package artifact is available for independent remeasurement.

| Metric | Value | Source |
|---|---|---|
| Package name/version | `session-continuity-engine@0.2.0` | `package.json` |
| Private package | `true` | `package.json` |

### 6.6 Reproducibility

Two consecutive runs of `lab/PROOF.mjs` produce byte-identical output. The reference digest is:

    PROOF_RUN_SHA256 = 48FF8147BEADE14AA74697B70532185DF276100B592676DC06E769F4C40B12C5

The source-tree digest at publication is:

    SRC_TREE_SHA256 = 941DE3DAC25B80B82D8ECC38D6A1C3F8F0BE085205A1AC339E2CB99D3CD7DE5F

A third party can reproduce the entire audit by executing `lab/EVIDENCE-CAPTURE.mjs`, which regenerates `lab/EVIDENCE-AUDIT.md` with SHA-256 `883FEBE7E12F6966B8454A5B6DF232AD9BAD4C9F5A21A9207144D5E6DA83007A`.

### 6.7 Evidence Gap Classification

This section classifies unverified or unimplemented aspects explicitly. Items are placed into one of three categories.

- **Scope Boundary** — a claim the protocol intentionally does not make. The absence is by design and is stated in Section 3.3 and Section 35.
- **Assurance Gap** — a property that could be added through further work and that matters for production deployment.
- **Feature Omission** — an optional capability deliberately deferred. The protocol remains complete without it.

| Category | Classification | Reason |
|---|---|---|
| Complete RFC 8785 implementation conformance | Assurance Gap | Only selected V1.1 profile vectors are tested; full RFC 8785 conformance suite not exercised |
| Crash fault injection across every commit boundary | Assurance Gap | Crash safety implemented by construction and restart tests; exhaustive injection not performed |
| Formal Tamarin / ProVerif proofs | Assurance Gap | No formal model exists; testing cannot replace formal analysis |
| Multi-implementation interoperability | Assurance Gap | One reference implementation only; test vectors published for future validation |
| External security audit | Assurance Gap | No third-party audit performed |
| Large-scale Merkle acceleration behavior | Feature Omission | Not required at tested scale; protocol permits future addition |
| Selective disclosure | Feature Omission | Not defined in V1.2; package format does not preclude future extension |
| Global non-equivocation | Scope Boundary | Witness scope bounded by witness trust domain by design |
| Legal admissibility | Scope Boundary | No legal claim is made |
| Proof of legitimacy of the original authentication | Scope Boundary | Protocol proves continuity from a root, not root legitimacy |
| Device ownership | Scope Boundary | Not addressed by the protocol |
| Absence of credential compromise | Scope Boundary | Not addressed by the protocol |

### 6.8 Closed Core Assurance Properties

The following properties are frequently cited as critical pre-conditions for session-continuity protocols. Each is closed in the reference implementation with named test evidence.

| Property | Status | Evidence |
|---|---|---|
| Crash consistency of durable state | CLOSED | `ROLLBACK_DETECTED`, `CORRUPTION_DETECTED`, `RECOVERY_AFTER_REPAIR` in `v1_1-durable-sequence-probe.mjs` |
| Independent verification without source application, live witness, or network | CLOSED | `v1_1-portable-package-probe-v2.mjs` offline verification checks |
| Authoritative conformance gate | CLOSED | `v1_1-regression-gate.mjs` — 13 checks including `V1_1_REGRESSION` |
| Semantic test enforcement (named checks, not aggregate pass counts) | CLOSED | `EVIDENCE-CAPTURE.mjs` — 251 named checks with per-check reasons |
| Parent binding and sequence strictness | CLOSED | `CHAIN_HEAD`, `SEQUENCE_GAP_REJECTED`, `WRONG_PARENT_REJECTED` in `v1_1-chain-probe.mjs` |

Finality semantics (the distinction between a valid prefix and a complete history) is specified in Section 11 and Section 12 of the specification and is now exercised by dedicated P0 and reconciled integration probes. The probes verify prefix-versus-complete separation, closed-checkpoint binding to the final head, truncation rejection as incomplete, and checkpoint tamper rejection.
## 7. Discussion

### 7.1 Why Separate the Witness from the Signer

The reference implementation uses distinct key pairs for signing proofs, for signing witness receipts, and for signing portable packages. This separation has an operational cost: three key-management lifecycles, three trust anchors, and three sets of rotation policies. The benefit is that a single compromise does not collapse the entire protocol.

If a signer key is compromised, an attacker can forge proofs. The attacker cannot forge witness receipts, because the witness key is separate. An auditor who holds a previously issued witness receipt can therefore detect that a new proof was not observed by the witness.

If a witness key is compromised, an attacker can forge receipts. The attacker cannot forge proofs, because the signer key is separate. An auditor who verifies the proof chain independently can therefore detect that a receipt was issued without a corresponding proof event.

If both a signer key and a witness key are compromised simultaneously, the protocol cannot detect the attack. This is a stated limitation, not a defense.

### 7.2 Why Bind Policy into the Proof

Each proof commits to a policy fingerprint. The fingerprint is the SHA-256 of the canonical serialization of the policy record used to produce the decision. This binding serves three purposes.

First, it prevents silent policy change. A verifier that holds a proof can reconstruct which policy the application used, and can detect whether the current deployment policy differs from the policy that produced the proof.

Second, it enables the separation of historical validity from current validity. A proof that was valid under a historical policy remains historically valid even if the current policy differs, provided the historical policy is still known.

Third, it enables a future audit trail of policy transitions. A deployment that changes policy within the same continuity root must explicitly represent the transition, so that a verifier can distinguish between a proof issued under the old policy and a proof issued under the new policy.

### 7.3 Why All-or-Nothing Verification

Chain verification is all-or-nothing. A single invalid proof invalidates the entire chain from that point forward. The alternative, partial acceptance, would allow an attacker to substitute a valid prefix for the complete history.

All-or-nothing verification has an operational cost: a corrupted byte in a single proof invalidates an entire chain. The cost is accepted because the alternative is a false-positive `CONTINUITY_PROVEN` on a compromised chain. In session security, a false positive is more dangerous than a false negative.

### 7.4 Why Fail-Closed Recovery

If a durable witness detects state corruption, it enters a fail-closed mode. It refuses new proofs, refuses to emit new receipts, and reports its status. It does not attempt automatic repair.

Automatic repair would require the witness to decide which pieces of its own state are corrupt and which are intact. In the absence of an external source of truth, this decision is unsafe. A witness that repairs itself may silently accept a state that a compromised attacker prepared.

Fail-closed recovery forces the operator to intervene. The operator can restore the witness from a backup, or repair the journal manually, and then explicitly re-enable the witness. This is a deliberate trade-off of operational cost for security.

### 7.5 Why Sequence Instead of Merkle Trees at Current Scale

The protocol uses a linear parent chain rather than a Merkle tree. A linear chain requires O(n) verification time. A Merkle tree would require O(log n) time but would add complexity in root derivation, proof construction, and package format.

At the tested scale of 1,000 proofs, linear verification completes in 130 ms. At 10,000 proofs, linear verification completes in approximately 2.4 seconds in earlier laboratory tests. These are acceptable for offline verification of a session that has already ended.

Merkle acceleration becomes worthwhile when the chain length exceeds tens of thousands of proofs, or when online verification latency is a hard constraint. The specification explicitly permits Merkle acceleration without altering parent-binding semantics.

### 7.6 Comparison with Certificate Transparency

The protocol borrows concepts from Certificate Transparency (RFC 9162): append-only logs, witness-based non-equivocation, and external verifiability. It is not a Certificate Transparency implementation and is not positioned as an improvement on it. The two address different problems with some overlapping mechanisms. The table below is descriptive, not evaluative. The remaining paragraphs describe three structural differences.

| Dimension | Certificate Transparency | Session Continuity Evidence |
|---|---|---|
| Object | X.509 certificate | Session event |
| Scope | Global per log | Per session |
| Lifespan | Years | Hours to days |
| Primary verifier | Public monitors | Internal auditors and incident response |
| Trust model | Publicly verifiable | Domain-scoped witness trust |
| Finality evidence | Inclusion proof and Signed Certificate Timestamp | Checkpoint and parent chain |

First, the object being logged is a session event, not a certificate. Session events occur at much higher frequency than certificate issuance and have much shorter lifetimes.

Second, the log is per-session, not global. A continuity chain is scoped to a single authenticated session. It is not aggregated across all sessions of an organization.

Third, the verifier is typically an internal auditor or incident-response team, not a public monitor. The trust model is narrower than CT's public-monitor model.

These differences do not invalidate the CT analogy. They define the scope in which the analogy holds.

## 8. Limitations and Future Work

This section organizes limitations by the same three-category classification used in Section 6.7. It also states explicitly which properties are closed and which are not.

### 8.1 Scope Boundaries

The protocol deliberately does not address the following. These are not gaps; they are design boundaries stated in Section 3.3 and Section 35.

- **Legitimacy of the original authentication.** The protocol assumes a trusted continuity root has already been established. It proves continuity from that root, not that the root was legitimately established.
- **Global non-equivocation.** A witness establishes non-equivocation only within its configured witness trust domain. Cross-domain disagreement does not prove global failure.
- **Device ownership.** The protocol does not verify that a specific device is being used.
- **Absence of credential compromise.** The protocol does not verify that credentials are uncompromised at the time of use.
- **Legal admissibility.** No legal claim is made in any jurisdiction.
- **Replacement of IAM.** The protocol supplements IAM; it does not authenticate users, issue identity tokens, or perform role-based access control.

### 8.2 Assurance Gaps

The following properties are achievable with further work and matter for production deployment. Each is classified as an Assurance Gap in Section 6.7.

**8.2.1 Formal Verification Pending.** The protocol has not been formally verified with a tool such as Tamarin, ProVerif, or CryptoVerif. A formal verification effort would target `no_sequence_gap`, `parent_binding_soundness`, `witness_non_equivocation`, `historical_consistency`, `replay_resistance`, and `completeness_soundness`. Each invariant would be stated as a lemma under explicit cryptographic assumptions. This is future work.

**8.2.2 External Security Audit Pending.** The reference implementation has not been audited by an external security firm. An external audit would review the source code for logic errors, timing side channels, memory safety issues, and implementation divergences from the specification. This is future work.

**8.2.3 Crash Boundary Injection Evidence.** The reference implementation uses atomic file replacement, `fsync`, and a head record to make state durable across crashes. A dedicated crash-boundary probe now injects process termination at the state-write `write`, `fsync`, `close`, and `rename` boundaries and verifies recovery, head preservation, and receipt/state consistency. Exhaustive fault injection across every possible application commit boundary beyond this storage-write path remains outside the tested scope. The retained execution artifact is `lab/CRASH-BOUNDARY-ASSURANCE-EVIDENCE.txt` with SHA-256 `2DE116F6B43970D27C48EB30A921FCAF07ECAB4CAF67B1F82FDCAD9593B2960A`.

**8.2.4 Multi-Implementation Interoperability Pending.** Only one reference implementation exists. Independent implementations in other languages would strengthen the evidence for interoperability. The published test vectors are designed to enable such validation.

**8.2.5 Complete RFC 8785 Conformance Pending.** The protocol adopts a strict profile based on RFC 8785. Only selected V1.1 profile vectors are tested. Full RFC 8785 Appendix B numeric vectors and the complete JCS conformance suite are not exercised in the reference test harness.

### 8.3 Feature Omissions

The following capabilities are deliberately deferred. The protocol remains complete and functional without them.

**8.3.1 Merkle Acceleration Not Implemented.** The protocol permits Merkle acceleration of long chains. The reference implementation uses linear parent-chain verification, which is sufficient for the tested scale of 1,000 to 10,000 proofs. At larger scales, acceleration may become necessary.

**8.3.2 Selective Disclosure Not Implemented.** The protocol does not implement selective disclosure. A portable evidence package reveals the complete chain to any party that receives it. The specification notes that future extensions MAY support selective disclosure, but no such extension is defined in V1.2.

### 8.4 Closed Core Assurance Properties

The following properties are sometimes cited as critical pre-conditions for session-continuity protocols. Each is closed in the reference implementation with named test evidence.

| Property | Status | Evidence |
|---|---|---|
| Crash consistency of durable state | CLOSED | `v1_1-durable-sequence-probe.mjs`: `ROLLBACK_DETECTED`, `CORRUPTION_DETECTED`, `RECOVERY_AFTER_REPAIR` |
| Independent verification | CLOSED | `v1_1-portable-package-probe-v2.mjs` |
| Authoritative conformance gate | CLOSED | `v1_1-regression-gate.mjs` |
| Semantic test enforcement | CLOSED | `EVIDENCE-CAPTURE.mjs` — 251 named checks |
| Parent binding and sequence strictness | CLOSED | `v1_1-chain-probe.mjs` |

The distinction between a valid prefix and a complete history is specified in the specification, enforced by the protocol, and exercised by dedicated P0 and reconciled integration probes. Closed-checkpoint finality is bound to the verified final head, while truncated prefixes remain incomplete.
## 9. Conclusion

This paper presented Session Continuity Evidence (SCE), a vendor-neutral protocol for producing portable, independently verifiable evidence of session continuity. The protocol establishes cryptographic continuity from a trusted authenticated session root through an ordered proof chain, durable witness observations, and a portable evidence package. It does not claim that cryptographic continuity proves the legitimacy of the original authentication; it proves only that a session that ended at a later sequence was the continuation of the session that began at sequence 1 within a configured trust domain.

The paper makes three contributions. It specifies the protocol with twelve components covering root establishment, proof construction, canonical serialization, sequence guarding, parent binding, durable witnessing, witness receipt, witness equivocation evidence, key lifecycle, portable packaging, completeness semantics, and independent verification. It provides a normative reference implementation in nine JavaScript modules with zero external runtime dependencies, published with a source-tree digest and a deterministic test harness. It reports an evaluation covering correctness, adversarial resistance, performance, release packaging metadata, and reproducibility.

The reference implementation passes 251 named audit checks across twenty independent probes, matches RFC 8032 Ed25519 golden vectors byte-for-byte, builds a 1,000-proof chain in 71 ms and verifies it in 130 ms, produces byte-identical output across independent processes, and rejects adversarial input across chain, witness, package, and key-lifecycle layers.

The protocol is not a replacement for IAM. It does not claim first-in-world status, universal non-equivocation, legal admissibility, or proof of the legitimacy of the original authentication. Its contribution is a precise, tested, and openly specified construction that fills a documented gap: no existing mechanism produces a portable artifact that a third party can verify to establish that a session that ended at Tn was the continuation of a session that began at T0.

The specification, the reference implementation, the test vectors, and the reproducibility digest are published together so that any third party can independently reproduce the results.

## References

1. D. Hardt, Ed., "The OAuth 2.0 Authorization Framework," RFC 6749, IETF, October 2012.

2. N. Sakimura, J. Bradley, M. Jones, B. de Medeiros, C. Mortimore, "OpenID Connect Core 1.0," OpenID Foundation, November 2014.

3. M. Jones, J. Bradley, N. Sakimura, "JSON Web Token (JWT)," RFC 7519, IETF, May 2015.

4. M. Jones, J. Bradley, N. Sakimura, "JSON Web Signature (JWS)," RFC 7515, IETF, May 2015.

5. A. Popov, M. Nystroem, D. Balfanz, J. Hodges, "The Token Binding Protocol Version 1.0," draft-ietf-tokbind-protocol, IETF, 2018.

6. M. Jones, L. Hunt, D. Denicola, "Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)," RFC 7800, IETF, April 2016.

7. A. Birgisson, J. G. Politz, U. Erlingsson, A. Taly, M. Vrable, M. Lentczner, "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud," NDSS 2014.

8. B. Laurie, A. Langley, E. Kasper, "Certificate Transparency," Internet Engineering Task Force, RFC 6962, June 2013.

9. B. Laurie, E. Messeri, R. Stradling, "Certificate Transparency Version 2.0," RFC 9162, IETF, December 2021.

10. M. S. Melara, A. Blankstein, J. Bonneau, E. W. Felten, M. J. Freedman, "CONIKS: Bringing Key Transparency to End Users," USENIX Security 2015.

11. S. Chase, S. Meiklejohn, "Transparency Overlays and Applications," IACR Cryptology ePrint Archive, Report 2016/915, 2016.

12. S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola, J. Cappos, "in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes," USENIX Security 2019.

13. Z. Newman, J. S. Meyers, S. Torres-Arias, "Sigstore: Software Signing for Everybody," ACM CCS 2022.

14. H. Birkholz, B. Mandel, M. Richardson, K. Krallis, T. R. Ranganathan, "An Architecture for Trustworthy and Transparent Digital Supply Chains," RFC 9943, IETF, 2025.

15. O. Steele, "The SCITT Reference API (SCRAPI)," draft-ietf-scitt-scrapi, IETF, ongoing.

16. A. Rundgren, B. Jordan, S. Erdtman, "JSON Canonicalization Scheme (JCS)," RFC 8785, IETF, June 2020.

17. S. Josefsson, I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, IETF, January 2017.

18. J. Schaad, "CBOR Object Signing and Encryption (COSE): Structures and Process," RFC 9052, IETF, August 2022.

19. C. Adams, P. Cain, D. Pinkas, R. Zuccherato, "Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)," RFC 3161, IETF, August 2001.

20. P. Grassi, J. Fenton, E. Lefkovitz, J. Danker, Y.-Y. Choong, K. Greene, M. Theofanos, "Digital Identity Guidelines," NIST Special Publication 800-63 Revision 3, 2017.

21. T. Lodderstedt, J. Bradley, A. Labunets, D. Fett, "OAuth 2.0 Security Best Current Practice," draft-ietf-oauth-security-topics, IETF, ongoing.

22. D. Hardt, A. Parecki, T. Lodderstedt, "The OAuth 2.1 Authorization Framework," draft-ietf-oauth-v2-1, IETF, ongoing.

23. D. Cooper, S. Santesson, S. Farrell, S. Boeyen, R. Housley, W. Polk, "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile," RFC 5280, IETF, May 2008.

24. D. Dolev, A. C. Yao, "On the Security of Public Key Protocols," IEEE Transactions on Information Theory, 1983.

25. D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang, "High-Speed High-Security Signatures," Journal of Cryptographic Engineering, 2012.

26. Platform-Agnostic Security Tokens (PASETO) Specification, version 4, open standard maintained by the PASETO project, 2024.

27. M. Green, "Transparency and Trust: The Role of Verifiable Logs in Modern Security," invited paper, 2020.

28. A. Tomescu, V. Bhupatiraju, D. Papadopoulos, C. Papamanthou, N. Triandopoulos, S. Devadas, "Transparency Logs via Append-Only Authenticated Dictionaries," ACM CCS 2019.

---

*End of paper.*