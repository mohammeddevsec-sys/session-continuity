import { createEvidenceContract, verifyEvidenceFingerprint } from "../src/evidence/evidence-contract.js";

const base = {
  sessionId: "sess-secure-001",
  anchorFingerprint: "a".repeat(64),
  presentationFingerprint: "b".repeat(64),
  sequence: 1,
  timestamp: "2026-09-13T10:00:00Z",
  checks: {
    sessionId: true,
    subject: true,
    issuer: true,
    clientId: true,
    deviceId: true,
    sequence: true,
    proofOfPossession: true,
    challenge: true
  },
  failedChecks: [],
  decision: "CONTINUOUS",
  reason: "SECURE_CONTINUITY_CONFIRMED",
  security: {
    popKeyFingerprintSha256: "c".repeat(64),
    challengeResult: "CHALLENGE_ACCEPTED",
    replayResult: "SEQUENCE_ACCEPTED",
    continuityResult: "ANCHOR_MATCH"
  }
};

const first = createEvidenceContract(base);

if (!verifyEvidenceFingerprint(first.evidence, first.fingerprint)) {
  throw new Error("SECURITY_EVIDENCE_VERIFY_FAILED");
}

const changedChallenge = createEvidenceContract({
  ...base,
  security: {
    ...base.security,
    challengeResult: "CHALLENGE_ALREADY_CONSUMED"
  }
});

if (changedChallenge.fingerprint === first.fingerprint) {
  throw new Error("CHALLENGE_CHANGE_NOT_FINGERPRINTED");
}

const changedKey = createEvidenceContract({
  ...base,
  security: {
    ...base.security,
    popKeyFingerprintSha256: "d".repeat(64)
  }
});

if (changedKey.fingerprint === first.fingerprint) {
  throw new Error("POP_KEY_CHANGE_NOT_FINGERPRINTED");
}

let secretRejected = false;

try {
  createEvidenceContract({
    ...base,
    security: {
      ...base.security,
      rawToken: "SECRET-TOKEN"
    }
  });
} catch {
  secretRejected = true;
}

if (!secretRejected) {
  throw new Error("RAW_SECURITY_SECRET_ACCEPTED");
}

console.log("SECURITY_EVIDENCE_VERIFY=PASS");
console.log("CHALLENGE_CHANGE_DETECTED=PASS");
console.log("POP_KEY_CHANGE_DETECTED=PASS");
console.log("RAW_SECRET_REJECTED=PASS");
console.log("SECURITY_EVIDENCE_CONTRACT=PASS");
console.log("EVIDENCE_FINGERPRINT="+first.fingerprint);
