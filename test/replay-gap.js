import { createSessionAnchor } from "../src/core/session-anchor.js";
import { verifyContinuity } from "../src/core/continuity-verifier.js";

const anchor = createSessionAnchor({
  sessionId: "sess-replay-001",
  subject: "user-001",
  issuer: "https://issuer.example",
  authTime: "2026-09-13T08:09:07.482Z",
  clientId: "client-001",
  deviceId: "device-001"
});

const presentation = {
  sessionId: "sess-replay-001",
  subject: "user-001",
  issuer: "https://issuer.example",
  clientId: "client-001",
  deviceId: "device-001"
};

const first = verifyContinuity(anchor, presentation);
const replay = verifyContinuity(anchor, presentation);

console.log("FIRST_PRESENTATION=", JSON.stringify(first));
console.log("REPLAY_PRESENTATION=", JSON.stringify(replay));

if (first.decision !== "CONTINUOUS" || replay.decision !== "CONTINUOUS") {
  process.exit(1);
}

console.log("REPLAY_GAP_CONFIRMED=TRUE");

