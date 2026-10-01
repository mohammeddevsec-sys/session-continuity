# Security Model

The receipt is untrusted input.

Trust is established from an externally provisioned signing authority. The receipt does not contain the authoritative trust store.

The signing private key must remain protected by the operator and must never be distributed with a receipt.

The current CLI supports authority provisioning, status inspection, and signer revocation. Trust rotation is not exposed as a CLI operation in this release and is therefore not described as an end-user command.

The engine does not validate OIDC JWT signatures. Identity-provider authentication and claim verification remain outside this product boundary.

Durable challenge, sequence, proof-of-possession, evidence, lineage, certificate, and trust checks are independently verified by the receiver.

A revoked signer must be rejected even when its receipt remains cryptographically intact.

No security product can guarantee detection of every attack. This product provides deterministic proof for the properties implemented and tested by the release.


--- POLICY CONTENT ---

# Security Policy

This document describes how security vulnerabilities in SESSION-CONTINUITY are reported and handled.

The technical security model is documented separately in SECURITY.md.

## Reporting a Vulnerability

Security reports should be sent to:

    nono_gate@zohomail.com

Please include, when available:

- A description of the issue.
- Steps to reproduce or a minimal proof of concept.
- The affected component or specification area.
- Any known impact or relevant evidence.

Do not include secrets, private signing keys, or credentials in a report.

## Triage and Handling

Reports are reviewed for reproducibility, security impact, affected components, and relationship to the documented security boundaries.

Where appropriate, remediation is prepared and incorporated into a future release or release candidate.

Response and disclosure timing depends on severity, reproducibility, affected scope, and available remediation information.

Coordinated disclosure is preferred. Reporter credit is provided only when appropriate and with the reporter's consent.

## Supported Scope

The project is currently pre-1.0.

Security reports are welcome for the current controlled release candidate made available to authorized reviewers and its documented security-relevant components.

There is no long-term support commitment at this stage.

## Out of Scope

The project cannot make claims beyond the security properties explicitly implemented and tested by the release.

Issues that require compromise of an explicitly documented trust boundary should be reported only when they demonstrate a security-relevant consequence within the project's stated scope.

Third-party systems outside the project's documented boundary are not part of this policy unless the project's implementation introduces a directly affected condition.

## Relationship to Other Security Documentation

- SECURITY.md — technical security model and trust boundaries.
- lab\continuity-proof-vnext\SPEC-DRAFT-V1_2.md — current lab specification.
- lab\PAPER.md / lab\PAPER.tex — technical paper and evidence description.

## Policy Review

This policy is reviewed when material changes are made to the project's release or security reporting process.
