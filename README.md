# session-continuity

**Cryptographic proof that an accepted application session is the legitimate continuation of the authenticated session that created it.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](package.json)

---

## The Problem

Modern applications authenticate users once, then hand them long-lived session tokens. Between authentication and the last request, **nothing cryptographically proves** that session #N is the same user as session #1.

Attackers exploit this gap:

- **Session hijacking** — stolen cookie works for full session lifetime
- **Replay attacks** — captured proofs replay in different contexts
- **Fork attacks** — two divergent session chains from one origin
- **Historical tampering** — evidence altered after the fact

Existing tools (JWT, PASETO, Macaroons) prove **authorization**, not **continuity**. This engine fills that gap.

---

## What It Does

Given a verified OIDC/JWT claim, `session-continuity` produces a **signed, append-only proof** that:

1. Binds session N to session N-1 via parent references
2. Uses ephemeral challenges (no static tokens)
3. Requires proof-of-possession for each transition
4. Writes a Merkle-linked, tamper-evident evidence bundle
5. Can be verified **offline by a third party** without the authority

---

## Quick Start

```bash
npm install
node bin/session-continuity.mjs authority-init --output ./authority
node bin/demo.mjs
```

Output: a verified provenance certificate under `./receipt/`.

---

## Architecture

```
  OIDC/JWT   -->   session-continuity  -->   Receipt
  (external)       Engine                   (portable)
                          |
                          v
                   Trust Authority
                   (external, immutable)
```

**Key design:** The trust authority is *external* to the receipt. Verification does not require calling home.

---

## Security Model

- **Ephemeral keys** — no static signing keys at rest
- **Durable challenges** — replay-safe across restarts
- **Atomic acceptance** — no partial state on crash
- **Trust revocation** — authorities can revoke past proofs
- **Independent verification** — third party verifies without engine

See [SECURITY.md](SECURITY.md) for the full model.

---

## What This Is NOT

- Not an identity provider
- Not an OAuth/OIDC implementation
- Not a SIEM/UEBA platform
- Not a vulnerability scanner

**OIDC/JWT validation is outside this engine.** Caller supplies claims only after independent verification.

---

## Status

**v0.2.0** — specification-stable, test-covered, not yet audited by a third party. See [CHANGELOG.md](CHANGELOG.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Fork Protection (Opt-in)

Fork protection is implemented but **disabled by default** for backward compatibility.

Enable via environment variable:

    SC_FORK_PROTECTION=enabled node your-app.js

When enabled, the engine uses `fork-registry` to block a second continuation from the same `(anchor_fingerprint, parent_sequence)`. The verifier returns `REAUTH_REQUIRED / FORK_DETECTED`.

Isolated registry (useful in tests):

    SC_FORK_REGISTRY_ROOT=/tmp/my-app node your-app.js

Note: the default registry uses `os.tmpdir()`. Deployments on the same machine share it, which is what you want. For isolated per-instance registries, set `SC_FORK_REGISTRY_ROOT`.

See `test/continuity-fork-attack.js` for a verified scenario.

---

## Known Limitations

This is an early-stage library. The following limitations are documented explicitly.

1. **No strict sequence enforcement.** The engine accepts sequence jumps (e.g., 1 to 3) without verifying 2 exists.

2. **No third-party security audit.** The code has not been reviewed by an independent security team.

3. **No BBS+ or ZK-SNARK privacy layer.** Session identifiers and subjects are visible in the evidence bundle.

4. **No hardware binding.** Sessions are not bound to TPM, Secure Enclave, or any hardware root of trust.

5. **Performance testing is limited.** Revocation reachability was measured at 100 edges (11 ms). Larger graphs have not been benchmarked.

6. **Fork protection is opt-in and shares state via the filesystem.** Works within one machine or a shared mount, but is not distributed. A centralized service is planned for v0.4.0.

## Roadmap

### v0.3.0 (planned)

- Integrate parent-binding and binding-store into the core engine.
- Strict sequence enforcement (n+1).
- Update continuity-fork-attack.js to expect rejection.

### v0.4.0 (planned)

- Hardware-bound sessions (TPM on Windows, Secure Enclave on macOS).

### v0.5.0+ (exploratory)

- BBS+ selective disclosure for privacy-preserving proofs.
- Cross-domain delegation support.

---

## Additional Modules

Beyond the core engine, three standalone cryptographic modules are implemented and tested independently.

### Delegation Chain (Ed25519)

src/delegation/ — signed chain of delegated authority. Verifier needs only the public key. Depth limit: 5.

Run tests: npm run test:delegation

### Transparency Log (RFC 6962)

src/transparency/ — append-only Merkle log for session events. Compatible with Certificate Transparency tooling.

Run tests: npm run test:transparency

### Revocation Reachability Proof

src/revocation/ — given a revoked delegation edge, proves offline which agents lose authority and which survive via an independent path.

Run tests: npm run test:revocation

### Supporting Primitives (Not Yet Integrated)

src/core/parent-binding.mjs and src/core/binding-store.mjs provide signed single-use commitments and a hash-chained consumed list. Tested in isolation but not yet wired into the core engine. Integration planned for v0.3.0.

src/core/fork-guard.mjs provides an exclusive lock per (session_id, parent_sequence). Tested in isolation. Integration deferred to v0.3.0.

---

## What This Is NOT

- Not an identity provider
- Not an OAuth/OIDC implementation
- Not a SIEM/UEBA platform
- Not a vulnerability scanner
- Not a session hijacking prevention system (in this version)

**OIDC/JWT validation is outside this engine.** Caller supplies claims only after independent verification.

### About the fork attack test

The test `test/continuity-fork-attack.js` demonstrates that the current
engine (v0.2.0) accepts two valid continuations from the same parent with
the same sequence.

This is **documented and intentional** for v0.2.0. It is NOT a bug.

Fork prevention requires a **centralized coordination service** (shared state
across instances). Building this would change the project from a library into
a stateful system. That decision is deferred to v0.3.0 and beyond.

The engine itself remains useful for:
- Session continuity within a single trusted state
- Delegation chains
- Transparency logs
- Offline revocation proofs

It does **not** prevent an attacker who controls the same state from forking.
