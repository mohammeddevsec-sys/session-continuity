import { createSessionAnchor } from "../../src/core/session-anchor.js";
import { verifyContinuity } from "../../src/core/continuity-verifier.js";

const anchor = createSessionAnchor({
  sessionId: "sess-001",
  subject: "user-001",
  issuer: "https://issuer.example",
  authTime: "2026-09-13T08:09:07.482Z",
  clientId: "client-001",
  deviceId: "device-001"
});

const legitimate = verifyContinuity(anchor, {
  sessionId: "sess-001",
  subject: "user-001",
  issuer: "https://issuer.example",
  clientId: "client-001",
  deviceId: "device-001"
});

const alteredDevice = verifyContinuity(anchor, {
  sessionId: "sess-001",
  subject: "user-001",
  issuer: "https://issuer.example",
  clientId: "client-001",
  deviceId: "device-ATTACKER"
});

const alteredSession = verifyContinuity(anchor, {
  sessionId: "sess-ATTACKER",
  subject: "user-001",
  issuer: "https://issuer.example",
  clientId: "client-001",
  deviceId: "device-001"
});

console.log("BASELINE_LEGITIMATE=", JSON.stringify(legitimate));
console.log("BASELINE_ALTERED_DEVICE=", JSON.stringify(alteredDevice));
console.log("BASELINE_ALTERED_SESSION=", JSON.stringify(alteredSession));

if (
  legitimate.decision !== "CONTINUOUS" ||
  alteredDevice.decision !== "REAUTH_REQUIRED" ||
  alteredSession.decision !== "REAUTH_REQUIRED"
) {
  process.exit(1);
}

console.log("BASELINE_RESULT=PASS");
