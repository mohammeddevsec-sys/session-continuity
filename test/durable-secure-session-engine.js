import fs from "fs";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import {
  createBindingKey,
  createSignedPresentation
} from "../src/core/proof-of-possession.js";
import {
  createSecureSessionState,
  issueChallenge,
  verifySecureSessionState
} from "../src/core/durable-secure-session-state.js";
import {
  evaluateDurableSecureSession
} from "../src/core/durable-secure-session-engine.js";

const root = "E:\\SESSION-CONTINUITY\\test\\fixtures\\durable-engine";
fs.rmSync(root, { recursive: true, force: true });

const binding = createBindingKey();

const anchorBase = createSessionAnchor({
  sessionId: "sess-durable-engine-001",
  subject: "user-001",
  issuer: "issuer-A",
  authTime: "2026-09-13T09:00:00Z",
  clientId: "client-A",
  deviceId: "device-A"
});

const anchor = {
  ...anchorBase,
  publicKeySpkiBase64: binding.publicKeySpkiBase64,
  publicKeyFingerprintSha256: binding.publicKeyFingerprint
};

const state1 =
  createSecureSessionState(
    root,
    60000
  );

const challenge1 =
  issueChallenge(
    state1,
    anchor.sessionId,
    100000
  );

const signed1 =
  createSignedPresentation(binding, {
    session_id: anchor.sessionId,
    subject: anchor.subject,
    issuer: anchor.issuer,
    client_id: anchor.clientId,
    device_id: anchor.deviceId,
    sequence: 1,
    challenge: challenge1.challenge,
    timestamp: "2026-09-13T12:30:00Z"
  });

const presented1 = {
  sessionId: anchor.sessionId,
  subject: anchor.subject,
  issuer: anchor.issuer,
  clientId: anchor.clientId,
  deviceId: anchor.deviceId,
  sequence: 1
};

const legitimate =
  evaluateDurableSecureSession(
    anchor,
    state1,
    presented1,
    signed1,
    "2026-09-13T12:30:00Z",
    100001
  );

if (legitimate.decision !== "CONTINUOUS") {
  throw new Error("DURABLE_ENGINE_LEGITIMATE_FAILED");
}

if (!legitimate.evidence.evidence.checks.sequence) {
  throw new Error("DURABLE_ENGINE_SEQUENCE_EVIDENCE_MISSING");
}

if (!legitimate.evidence.evidence.checks.challenge) {
  throw new Error("DURABLE_ENGINE_CHALLENGE_EVIDENCE_MISSING");
}

const replay =
  evaluateDurableSecureSession(
    anchor,
    state1,
    presented1,
    signed1,
    "2026-09-13T12:30:01Z",
    100002
  );

if (
  replay.decision !== "REAUTH_REQUIRED" ||
  replay.reason !== "REPLAY_DETECTED"
) {
  throw new Error("DURABLE_ENGINE_REPLAY_ACCEPTED");
}

const state2 =
  createSecureSessionState(
    root,
    60000
  );

if (!verifySecureSessionState(state2).verified) {
  throw new Error("DURABLE_ENGINE_RESTART_INVALID");
}

const challenge2 =
  issueChallenge(
    state2,
    anchor.sessionId,
    200000
  );

const signed2 =
  createSignedPresentation(binding, {
    session_id: anchor.sessionId,
    subject: anchor.subject,
    issuer: anchor.issuer,
    client_id: anchor.clientId,
    device_id: anchor.deviceId,
    sequence: 2,
    challenge: challenge2.challenge,
    timestamp: "2026-09-13T12:31:00Z"
  });

const presented2 = {
  ...presented1,
  sequence: 2
};

const afterRestart =
  evaluateDurableSecureSession(
    anchor,
    state2,
    presented2,
    signed2,
    "2026-09-13T12:31:00Z",
    200001
  );

if (afterRestart.decision !== "CONTINUOUS") {
  throw new Error("DURABLE_ENGINE_POST_RESTART_FAILED");
}

const altered =
  evaluateDurableSecureSession(
    anchor,
    state2,
    {
      ...presented2,
      deviceId: "device-B",
      sequence: 3
    },
    signed2,
    "2026-09-13T12:32:00Z",
    200002
  );

if (
  altered.decision !== "REAUTH_REQUIRED" ||
  altered.reason !== "CONTINUITY_BROKEN"
) {
  throw new Error("DURABLE_ENGINE_CONTEXT_TAMPER_ACCEPTED");
}

const unknownChallengePresentation =
  createSignedPresentation(binding, {
    session_id: anchor.sessionId,
    subject: anchor.subject,
    issuer: anchor.issuer,
    client_id: anchor.clientId,
    device_id: anchor.deviceId,
    sequence: 3,
    challenge: "unknown-challenge",
    timestamp: "2026-09-13T12:33:00Z"
  });

const unknownChallenge =
  evaluateDurableSecureSession(
    anchor,
    state2,
    {
      ...presented2,
      sequence: 3
    },
    unknownChallengePresentation,
    "2026-09-13T12:33:00Z",
    200003
  );

if (
  unknownChallenge.decision !== "REAUTH_REQUIRED" ||
  unknownChallenge.reason !== "CHALLENGE_UNKNOWN"
) {
  throw new Error("UNKNOWN_CHALLENGE_ACCEPTED");
}

console.log("DURABLE_ENGINE_LEGITIMATE=PASS");
console.log("DURABLE_ENGINE_REPLAY_REJECTED=PASS");
console.log("DURABLE_ENGINE_RESTART_RECOVERY=PASS");
console.log("DURABLE_ENGINE_CONTEXT_REJECTED=PASS");
console.log("DURABLE_ENGINE_UNKNOWN_CHALLENGE_REJECTED=PASS");
console.log("DURABLE_ENGINE_INTEGRATION=PASS");
console.log(
  "EVIDENCE_FINGERPRINT=" +
  legitimate.evidence.fingerprint
);
