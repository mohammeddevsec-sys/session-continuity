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
