# FREEZE - arXiv Preprint Submission

**Freeze Timestamp (UTC):** 2026-09-27T05:44:21Z
**Workspace:** E:\SESSION-CONTINUITY -2.02
**Purpose:** Immutable snapshot for arXiv preprint submission.

## Critical File Hashes

    SRC_TREE_SHA256                  = 941DE3DAC25B80B82D8ECC38D6A1C3F8F0BE085205A1AC339E2CB99D3CD7DE5F
    PAPER_TEX_SHA256                 = 2F6A5CA1B6795E7EEDF8B4346E3B8C33083B0512E0725C0A1E30DF5C67FAEFC6
    PAPER_MD_SHA256                  = 2F6BDFB0B62C375FDFEE10EDC9C7DF98104C346AA5E4FFD88D2C08C4B4E83C8D
    SPEC_DRAFT_V1_2_SHA256           = CBDF5CB80E5361DD0ED9640D32ABAE28D897F53179BFB2BF0DF93B344BC3C5B3
    PACKAGE_JSON_SHA256              = A300614148FFB7E675B08F5079C10018C03F2E25D950FAAD2A3DEE3B8C4BE10C
    EVIDENCE_AUDIT_SHA256            = 883FEBE7E12F6966B8454A5B6DF232AD9BAD4C9F5A21A9207144D5E6DA83007A

## Gate Results at Freeze

| Gate | Result |
|------|--------|
| LATEX-AUDIT | PASS |
| ALIGNMENT-AUDIT | PASS |
| CLAIM-EVIDENCE-AUDIT | PASS (11/11) |
| ENTERPRISE_RELEASE_GATE | PASS (0 failures) |
| FULL_AUDIT | PASS |
| STRICT_AUDIT | PASS (0 integrity failures) |

## Operational State

- 251 named audit checks across 20 probes
- 41 v1 regression tests
- 12 v1.1 conformance probes
- RFC 8032 Test 1 golden vector verified byte-for-byte
- Deterministic output confirmed across independent runs
- All lab scripts use relative path resolution (no hard-coded workspace path)

## Known Gaps at Freeze

The following gaps are documented and deferred (none invalidate cryptographic
contracts or audit claims):

- G2: REAUTH_REASONS set in policy.js is a documentation-time snapshot and is
  not synchronized with buildDiagnostic reason codes. Effective behavior is
  correct because engineDecision is checked first.
- G5/G21: Pattern of "mutate staging artifact then throw" in commitSessionAcceptance
  and appendEvidenceLineage. Rollback via stagingRoot removes the partial state;
  no persistent corruption.
- G16: Loss of underlying reason at pipeline boundary (trusted.reason replaced
  by TRANSACTIONAL_TRUST_FAILED). Diagnostics only.
- P9: evidence-lineage.js uses canonicalStringify for entry hashing;
  offline-verifier.js uses a manual single-level JSON.stringify sort. They are
  byte-identical for flat entries (current design). Adding any nested object
  to entry would break verification. Documented as technical debt.
- P15: appendEvidenceLineage has no lock file. Non-issue for current pipeline
  because stagingRoot is unique per invocation.
- P18: sha256File (hash.js) has no try/catch; raw ENOENT/EACCES would surface
  as UNCLASSIFIED in diagnostic.

## Diagnostic Coverage Fix at Freeze

src/product/session-continuity-decision.js was modified to classify five
additional reason families in buildDiagnostic:

    EVIDENCE_*          -> EVIDENCE / evidence-contract
    CANONICAL_*         -> CANONICAL / canonicalize
    TRUST_/SIGNER_/SIGNING_ -> TRUST / durable-trust-store
    LINEAGE_/HEAD_     -> LINEAGE / evidence-lineage
    BUNDLE_/MANIFEST_/SUM_/FILE_MISSING/HASH_MISMATCH/UNSAFE_FILE_NAME -> BUNDLE / evidence-bundle

This is a diagnostic projection change only. No cryptographic binding,
decision_hash, continuity_hash, bundle_root, lineage_root, merkle_root,
evidence fingerprint, signature, or certificate semantics were modified.

Previous SHA256: 376044B11C2DBFA8EC3A862893F88C649102318775DD6D6C6E6797B07F966267
New SHA256:      F2447CAE256CB06C977C447A1D3F38B3B5AEABECF2E82159937A6DF021F73FE5

Regression: 41/41 PASS after fix (FINAL_REGRESSION=PASS|TESTS=41).

## Freeze Rule

No file under src/, test/, bin/, or lab/ shall be modified after this
freeze until the arXiv preprint is submitted. Any subsequent change
invalidates this freeze and requires a new freeze record with updated
hashes.
