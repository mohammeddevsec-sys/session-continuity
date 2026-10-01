import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createReplayState } from "../src/core/replay-guard.js";
import {
  createBindingKey,
  createSignedPresentation
} from "../src/core/proof-of-possession.js";
import {
  createChallengeAuthority,
  issueChallenge
} from "../src/core/challenge-authority.js";
import {
  evaluateSecureSessionWithEvidence
} from "../src/core/secure-session-engine.js";

const binding = createBindingKey();

const anchorBase = createSessionAnchor({
  sessionId: "sess-engine-001",
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

const authority = createChallengeAuthority();
let state = createReplayState();

const challenge1 = issueChallenge(
  authority,
  anchor.sessionId,
  100000
);

const signed1 = createSignedPresentation(binding, {
  session_id: anchor.sessionId,
  subject: anchor.subject,
  issuer: anchor.issuer,
  client_id: anchor.clientId,
  device_id: anchor.deviceId,
  sequence: 1,
  challenge: challenge1.challenge,
  timestamp: "2026-09-13T10:00:00Z"
});

const presented1 = {
  sessionId: anchor.sessionId,
  subject: anchor.subject,
  issuer: anchor.issuer,
  clientId: anchor.clientId,
  deviceId: anchor.deviceId,
  sequence: 1
};

const legitimate = evaluateSecureSessionWithEvidence(
  anchor,
  state,
  authority,
  presented1,
  signed1,
  "2026-09-13T10:00:00Z",
  100001
);

if (legitimate.decision !== "CONTINUOUS") {
  throw new Error("SECURE_ENGINE_LEGITIMATE_REJECTED");
}

state = legitimate.nextReplayState;

const challenge2 = issueChallenge(
  authority,
  anchor.sessionId,
  200000
);

const replayPresentation = createSignedPresentation(binding, {
  session_id: anchor.sessionId,
  subject: anchor.subject,
  issuer: anchor.issuer,
  client_id: anchor.clientId,
  device_id: anchor.deviceId,
  sequence: 1,
  challenge: challenge2.challenge,
  timestamp: "2026-09-13T10:00:01Z"
});

const replay = evaluateSecureSessionWithEvidence(
  anchor,
  state,
  authority,
  presented1,
  replayPresentation,
  "2026-09-13T10:00:01Z",
  200001
);

if (replay.decision !== "REAUTH_REQUIRED") {
  throw new Error("SECURE_ENGINE_REPLAY_ACCEPTED");
}

if (replay.reason !== "REPLAY_DETECTED") {
  throw new Error("SECURE_ENGINE_REPLAY_REASON_INVALID");
}

if (!replay.evidence.evidence.failed_checks.includes("sequence")) {
  throw new Error("REPLAY_EVIDENCE_SEQUENCE_MISSING");
}

const challenge2ReuseWithFreshSequence = createSignedPresentation(binding, {
  session_id: anchor.sessionId,
  subject: anchor.subject,
  issuer: anchor.issuer,
  client_id: anchor.clientId,
  device_id: anchor.deviceId,
  sequence: 2,
  challenge: challenge2.challenge,
  timestamp: "2026-09-13T10:00:02Z"
});

const afterRejectedReplay = evaluateSecureSessionWithEvidence(
  anchor,
  state,
  authority,
  {
    ...presented1,
    sequence: 2
  },
  challenge2ReuseWithFreshSequence,
  "2026-09-13T10:00:02Z",
  200002
);

if (afterRejectedReplay.decision !== "CONTINUOUS") {
  throw new Error("CHALLENGE_CONSUMED_BY_REJECTED_REPLAY");
}

if (afterRejectedReplay.reason !== "SECURE_CONTINUITY_CONFIRMED") {
  throw new Error("POST_REPLAY_REASON_INVALID");
}

const challenge3 = issueChallenge(
  authority,
  anchor.sessionId,
  300000
);

const altered = createSignedPresentation(binding, {
  session_id: anchor.sessionId,
  subject: anchor.subject,
  issuer: anchor.issuer,
  client_id: anchor.clientId,
  device_id: "device-B",
  sequence: 3,
  challenge: challenge3.challenge,
  timestamp: "2026-09-13T10:00:03Z"
});

const alteredResult = evaluateSecureSessionWithEvidence(
  anchor,
  afterRejectedReplay.nextReplayState,
  authority,
  {
    ...presented1,
    deviceId: "device-B",
    sequence: 3
  },
  altered,
  "2026-09-13T10:00:03Z",
  300001
);

if (alteredResult.decision !== "REAUTH_REQUIRED") {
  throw new Error("SECURE_ENGINE_CONTEXT_TAMPER_ACCEPTED");
}

if (!alteredResult.evidence.evidence.failed_checks.includes("deviceId")) {
  throw new Error("CONTEXT_TAMPER_EVIDENCE_MISSING");
}

console.log("SECURE_ENGINE_LEGITIMATE=PASS");
console.log("SECURE_ENGINE_REPLAY_REJECTED=PASS");
console.log("REPLAY_REASON_CORRECT=PASS");
console.log("CHALLENGE_NOT_CONSUMED_BY_REPLAY=PASS");
console.log("CONTEXT_TAMPER_REJECTED=PASS");
console.log("SECURE_ENGINE_INTEGRATION=PASS");
console.log("FINAL_EVIDENCE_FINGERPRINT="+legitimate.evidence.fingerprint);
