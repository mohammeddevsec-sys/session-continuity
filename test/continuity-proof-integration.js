import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createReplayState } from "../src/core/replay-guard.js";
import { evaluateSession } from "../src/core/continuity-engine.js";

const anchor = createSessionAnchor({
  sessionId: "sess-001",
  subject: "user-001",
  issuer: "issuer-A",
  authTime: "2026-09-13T09:00:00Z",
  clientId: "client-A",
  deviceId: "device-A"
});

const legitimate = {
  sessionId: "sess-001",
  subject: "user-001",
  issuer: "issuer-A",
  clientId: "client-A",
  deviceId: "device-A",
  sequence: 1
};

const alteredDevice = {
  ...legitimate,
  deviceId: "device-B",
  sequence: 2
};

let state = createReplayState();

const first = evaluateSession(anchor, state, legitimate, "2026-09-13T09:10:00Z");
state = first.nextReplayState;

const tampered = evaluateSession(anchor, state, alteredDevice, "2026-09-13T09:11:00Z");

const replay = evaluateSession(anchor, state, legitimate, "2026-09-13T09:12:00Z");

if (first.decision !== "CONTINUOUS") throw new Error("LEGITIMATE_FAILED");
if (first.evidence.fingerprint.length !== 64) throw new Error("EVIDENCE_FINGERPRINT_INVALID");
if (tampered.decision !== "REAUTH_REQUIRED") throw new Error("ALTERED_CONTEXT_ACCEPTED");
if (!tampered.failedChecks.includes("deviceId")) throw new Error("DEVICE_CHANGE_NOT_DETECTED");
if (replay.decision !== "REAUTH_REQUIRED") throw new Error("REPLAY_ACCEPTED");
if (!replay.failedChecks.includes("sequence")) throw new Error("REPLAY_NOT_RECORDED");

console.log("LEGITIMATE_DECISION="+first.decision);
console.log("ALTERED_DEVICE_DECISION="+tampered.decision);
console.log("REPLAY_DECISION="+replay.decision);
console.log("EVIDENCE_FINGERPRINT="+first.evidence.fingerprint);
console.log("CONTINUITY_PROOF_INTEGRATION=PASS");
