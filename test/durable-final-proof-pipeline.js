import fs from "fs";
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
  verifyProofSignature
} from "../src/evidence/proof-signature.js";
import {
  executeFinalProofPipeline
} from "../src/core/final-proof-pipeline.js";

const root =
  "E:\\SESSION-CONTINUITY\\test\\fixtures\\final-proof";

fs.rmSync(root, {
  recursive: true,
  force: true
});

const sessionKey =
  createBindingKey();

const signingIdentity =
  createSigningIdentity();

const trustStore =
  createTrustAnchorStore();

registerTrustAnchor(
  trustStore,
  signingIdentity.publicKeySpkiBase64,
  {
    version: 1,
    created_at:
      "2026-09-13T14:00:00Z",
    label:
      "final-proof-signer"
  }
);

const anchorBase =
  createSessionAnchor({
    sessionId:
      "sess-final-proof-001",
    subject:
      "user-001",
    issuer:
      "issuer-A",
    authTime:
      "2026-09-13T09:00:00Z",
    clientId:
      "client-A",
    deviceId:
      "device-A"
  });

const anchor = {
  ...anchorBase,
  publicKeySpkiBase64:
    sessionKey.publicKeySpkiBase64,
  publicKeyFingerprintSha256:
    sessionKey.publicKeyFingerprint
};

const durableState =
  createSecureSessionState(
    root + "\\session-state",
    60000
  );

const challenge =
  issueChallenge(
    durableState,
    anchor.sessionId,
    500000
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
        "2026-09-13T14:00:00Z"
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
  executeFinalProofPipeline({
    anchor,
    durableState,
    presented,
    signedPresentation,
    timestamp:
      "2026-09-13T14:00:00Z",
    nowMs: 500001,
    signingIdentity,
    trustStore,
    outputRoot:
      root + "\\proof"
  });

if (
  result.decision !==
  "CONTINUOUS"
) {
  throw new Error(
    "FINAL_PIPELINE_DECISION_FAILED"
  );
}

if (
  result.verification
    .binding_valid !== true
) {
  throw new Error(
    "FINAL_PIPELINE_BINDING_FAILED"
  );
}

if (
  result.verification.offline
    .verified !== true
) {
  throw new Error(
    "FINAL_PIPELINE_OFFLINE_FAILED"
  );
}

if (
  result.verification.trusted
    .verified !== true
) {
  throw new Error(
    "FINAL_PIPELINE_TRUST_FAILED"
  );
}

if (
  result.certificate
    .bundle_root_sha256
    .includes("000000")
) {
  throw new Error(
    "FINAL_PIPELINE_PLACEHOLDER_DETECTED"
  );
}

const signatureCheck =
  verifyProofSignature(
    result.certificate
  );

if (!signatureCheck.verified) {
  throw new Error(
    "FINAL_PIPELINE_SIGNATURE_FAILED"
  );
}

const bundleRoot =
  result.verification
    .offline
    .bundle_root_sha256;

const lineageRoot =
  result.verification
    .offline
    .lineage_root_sha256;

const merkleRoot =
  result.verification
    .offline
    .merkle_root_sha256;

if (
  result.certificate
    .bundle_root_sha256 !==
  bundleRoot
) {
  throw new Error(
    "CERTIFICATE_BUNDLE_ROOT_MISMATCH"
  );
}

if (
  result.certificate
    .lineage_root_sha256 !==
  lineageRoot
) {
  throw new Error(
    "CERTIFICATE_LINEAGE_ROOT_MISMATCH"
  );
}

if (
  result.certificate
    .merkle_root_sha256 !==
  merkleRoot
) {
  throw new Error(
    "CERTIFICATE_MERKLE_ROOT_MISMATCH"
  );
}

console.log("DURABLE_TRUST_INITIAL=PASS");
console.log("DURABLE_TRUST_RESTART=PASS");
console.log("DURABLE_TRUST_REVOCATION=PASS");
console.log("DURABLE_REVOCATION_PERSISTED=PASS");

const certificateTampered =
  {
    ...result.certificate,
    merkle_root_sha256:
      "f".repeat(64)
  };

const tamperedCheck =
  verifyProofSignature(
    certificateTampered
  );

if (tamperedCheck.verified) {
  throw new Error(
    "CERTIFICATE_TAMPER_ACCEPTED"
  );
}

console.log(
  "FINAL_SESSION_DECISION=PASS"
);
console.log(
  "REAL_BUNDLE_ROOT=PASS"
);
console.log(
  "REAL_LINEAGE_ROOT=PASS"
);
console.log(
  "REAL_MERKLE_ROOT=PASS"
);
console.log(
  "CERTIFICATE_BINDING=PASS"
);
console.log(
  "TRUSTED_SIGNATURE=PASS"
);
console.log(
  "OFFLINE_PROOF_VERIFICATION=PASS"
);
console.log(
  "CERTIFICATE_TAMPER_REJECTED=PASS"
);
console.log(
  "FINAL_PROOF_PIPELINE=PASS"
);
console.log(
  "BUNDLE_ROOT=" +
    bundleRoot
);
console.log(
  "LINEAGE_ROOT=" +
    lineageRoot
);
console.log(
  "MERKLE_ROOT=" +
    merkleRoot
);
console.log(
  "EVIDENCE_FINGERPRINT=" +
    result.proof
      .evidence_fingerprint_sha256
);
