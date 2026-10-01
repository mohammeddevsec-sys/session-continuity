import fs from "fs";
import crypto from "crypto";
import {
  createSessionAnchor
} from "../src/core/session-anchor.js";
import {
  createBindingKey,
  createSignedPresentation
} from "../src/core/proof-of-possession.js";
import {
  createSecureSessionState,
  issueChallenge
} from "../src/core/durable-secure-session-state.js";
import {
  createSigningIdentity
} from "../src/evidence/proof-signature.js";
import {
  createTrustAnchorStore,
  registerTrustAnchor,
  revokeTrustAnchor
} from "../src/evidence/trust-anchor.js";
import {
  evaluateAndCertifyDurableSession
} from "../src/core/trusted-durable-session-engine.js";

const root =
  "E:\\SESSION-CONTINUITY\\test\\fixtures\\trusted-durable-engine";

fs.rmSync(root, {
  recursive: true,
  force: true
});

const sessionKey =
  createBindingKey();

const proofSigner =
  createSigningIdentity();

const trustedStore =
  createTrustAnchorStore();

registerTrustAnchor(
  trustedStore,
  proofSigner.publicKeySpkiBase64,
  {
    version: 1,
    created_at: "2026-09-13T13:00:00Z",
    label: "proof-signer"
  }
);

const anchorBase =
  createSessionAnchor({
    sessionId: "sess-final-001",
    subject: "user-001",
    issuer: "issuer-A",
    authTime: "2026-09-13T09:00:00Z",
    clientId: "client-A",
    deviceId: "device-A"
  });

const anchor = {
  ...anchorBase,
  publicKeySpkiBase64:
    sessionKey.publicKeySpkiBase64,
  publicKeyFingerprintSha256:
    sessionKey.publicKeyFingerprint
};

const state =
  createSecureSessionState(
    root,
    60000
  );

const challenge =
  issueChallenge(
    state,
    anchor.sessionId,
    100000
  );

const signedPresentation =
  createSignedPresentation(
    sessionKey,
    {
      session_id:
        anchor.sessionId,
      subject:
        anchor.subject,
      issuer:
        anchor.issuer,
      client_id:
        anchor.clientId,
      device_id:
        anchor.deviceId,
      sequence: 1,
      challenge:
        challenge.challenge,
      timestamp:
        "2026-09-13T13:00:00Z"
    }
  );

const presented = {
  sessionId:
    anchor.sessionId,
  subject:
    anchor.subject,
  issuer:
    anchor.issuer,
  clientId:
    anchor.clientId,
  deviceId:
    anchor.deviceId,
  sequence: 1
};

const result =
  evaluateAndCertifyDurableSession(
    anchor,
    state,
    presented,
    signedPresentation,
    "2026-09-13T13:00:00Z",
    100001,
    proofSigner,
    trustedStore
  );

if (
  result.session.decision !==
  "CONTINUOUS"
) {
  throw new Error(
    "FINAL_SESSION_DECISION_FAILED"
  );
}

if (!result.certificate) {
  throw new Error(
    "FINAL_CERTIFICATE_MISSING"
  );
}

if (!result.trust?.verified) {
  throw new Error(
    "FINAL_TRUST_VERIFICATION_FAILED"
  );
}

const revokedStore =
  createTrustAnchorStore();

registerTrustAnchor(
  revokedStore,
  proofSigner.publicKeySpkiBase64,
  {
    version: 1,
    created_at: "2026-09-13T13:00:00Z"
  }
);

revokeTrustAnchor(
  revokedStore,
  proofSigner.publicKeyFingerprintSha256
);

const revokedResult =
  evaluateAndCertifyDurableSession(
    anchor,
    createSecureSessionState(
      root,
      60000
    ),
    {
      ...presented,
      sequence: 2
    },
    createSignedPresentation(
      sessionKey,
      {
        session_id:
          anchor.sessionId,
        subject:
          anchor.subject,
        issuer:
          anchor.issuer,
        client_id:
          anchor.clientId,
        device_id:
          anchor.deviceId,
        sequence: 2,
        challenge:
          issueChallenge(
            createSecureSessionState(
              root,
              60000
            ),
            anchor.sessionId,
            200000
          ).challenge,
        timestamp:
          "2026-09-13T13:01:00Z"
      }
    ),
    "2026-09-13T13:01:00Z",
    200001,
    proofSigner,
    revokedStore
  );

if (
  revokedResult.trust?.verified
) {
  throw new Error(
    "REVOKED_PROOF_SIGNER_ACCEPTED"
  );
}

console.log(
  "DURABLE_SESSION_DECISION=PASS"
);
console.log(
  "SIGNED_PROOF_CREATED=PASS"
);
console.log(
  "TRUSTED_PROOF_ACCEPTED=PASS"
);
console.log(
  "REVOKED_PROOF_SIGNER_REJECTED=PASS"
);
console.log(
  "TRUSTED_DURABLE_SESSION_PIPELINE=PASS"
);
console.log(
  "PROOF_SIGNER_FINGERPRINT=" +
    proofSigner.publicKeyFingerprintSha256
);
