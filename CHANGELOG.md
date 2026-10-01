# Changelog

## 0.2.0

- Added diagnostic output to session decision results: reason_code, failure_stage, failure_location, evidence_ref. These fields are attached to the decision envelope and are not part of the cryptographic proof core; V1 and V1.1 contract semantics are unchanged.
- Added challenge branch diagnostic tests: CHALLENGE_UNKNOWN, CHALLENGE_SESSION_MISMATCH, CHALLENGE_EXPIRED, CHALLENGE_ALREADY_CONSUMED.
- Added a static reason-code coverage test to detect future reason codes that would otherwise fall through to UNCLASSIFIED without explicit classification.
- Added SECURITY-POLICY.md documenting vulnerability reporting, triage, supported scope, and out-of-scope items.
- Replaced LICENSE.txt with a clean proprietary license retaining all rights and permitting independent security review under a written non-disclosure agreement.
- Added license metadata to package.json (SEE LICENSE IN LICENSE.txt).
- Test count increased from 39 to 41.
- Path resolution fixed in all lab audit scripts (ALIGNMENT-AUDIT, CLAIM-EVIDENCE-AUDIT, enterprise-release-gate, EVIDENCE-CAPTURE, LATEX-AUDIT, _full-audit, _strict-audit): hard-coded Copy path replaced with path.resolve(__dirname, "..") so scripts always operate on the workspace they live in.
- Synced SRC_TREE_SHA256, EVIDENCE_AUDIT_SHA256, and PROOF_RUN_SHA256 in PAPER.md, PAPER.tex, and SPEC-DRAFT-V1_2.md to the current workspace values.
- Updated v1 regression test count from 38 to 41 in PAPER.md and PAPER.tex.
- Synchronized the Conclusion paragraph of PAPER.md with PAPER.tex (251 named audit checks across twenty independent probes).
- CLI: `--version` now reads the version from package.json instead of a hard-coded constant. Previously the constant could drift from the published version.
- CLI: `prove` now emits diagnostic fields on failure (DIAGNOSTIC_REASON_CODE, DIAGNOSTIC_FAILURE_STAGE, DIAGNOSTIC_FAILURE_LOCATION, DIAGNOSTIC_EVIDENCE_REF) to stderr before exiting. This is a defensive exposure; normal CLI operation does not trigger it.

## 0.1.0

Initial product release candidate with durable session continuity, proof-of-possession, evidence integrity, provenance certificates, external trust authority, signer revocation, independent verification, and CLI operation.