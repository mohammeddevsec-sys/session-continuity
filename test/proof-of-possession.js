import crypto from "crypto";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import {
  createBindingKey,
  createSignedPresentation,
  verifySignedPresentation
} from "../src/core/proof-of-possession.js";

const binding = createBindingKey();

const anchor = createSessionAnchor({
  sessionId: "sess-pop-001",
  subject: "user-001",
  issuer: "issuer-A",
  authTime: "2026-09-13T09:00:00Z",
  clientId: "client-A",
  deviceId: "device-A"
});

const boundAnchor = {
  ...anchor,
  publicKeySpkiBase64: binding.publicKeySpkiBase64,
  publicKeyFingerprintSha256: binding.publicKeyFingerprint
};

const legitimate = createSignedPresentation(binding, {
  session_id: "sess-pop-001",
  subject: "user-001",
  issuer: "issuer-A",
  client_id: "client-A",
  device_id: "device-A",
  sequence: 1,
  challenge: "challenge-A",
  timestamp: "2026-09-13T09:10:00Z"
});

const valid = verifySignedPresentation(boundAnchor, legitimate);

if (!valid.verified) {
  throw new Error("LEGITIMATE_POP_FAILED");
}

const alteredContext = {
  ...legitimate,
  payload: {
    ...legitimate.payload,
    device_id: "device-B"
  }
};

const altered = verifySignedPresentation(boundAnchor, alteredContext);

if (altered.verified) {
  throw new Error("ALTERED_CONTEXT_ACCEPTED");
}

if (altered.reason !== "PRESENTATION_SIGNATURE_INVALID") {
  throw new Error("ALTERED_CONTEXT_REASON_INVALID");
}

const alteredChallenge = createSignedPresentation(binding, {
  ...legitimate.payload,
  challenge: "challenge-B"
});

const challengeValid = verifySignedPresentation(boundAnchor, alteredChallenge);

if (!challengeValid.verified) {
  throw new Error("NEW_CHALLENGE_VALID_PRESENTATION_FAILED");
}

const attackerKey = createBindingKey();

let attackerAccepted = false;

try {
  const attackerPresentation = createSignedPresentation(attackerKey, {
    ...legitimate.payload,
    challenge: "challenge-C",
    sequence: 2
  });

  attackerAccepted = verifySignedPresentation(boundAnchor, attackerPresentation).verified;
} catch {}

if (attackerAccepted) {
  throw new Error("ATTACKER_WITHOUT_BOUND_KEY_ACCEPTED");
}

const replayToFreshChallenge = {
  ...legitimate,
  payload: {
    ...legitimate.payload,
    challenge: "challenge-Z"
  }
};

const replayResult = verifySignedPresentation(boundAnchor, replayToFreshChallenge);

if (replayResult.verified) {
  throw new Error("REPLAY_TO_FRESH_CHALLENGE_ACCEPTED");
}

const tamperedTimestamp = {
  ...legitimate,
  payload: {
    ...legitimate.payload,
    timestamp: "2026-09-13T09:20:00Z"
  }
};

const timestampResult = verifySignedPresentation(boundAnchor, tamperedTimestamp);

if (timestampResult.verified) {
  throw new Error("TAMPERED_TIMESTAMP_ACCEPTED");
}

console.log("LEGITIMATE_POP=PASS");
console.log("ALTERED_CONTEXT_REJECTED=PASS");
console.log("ATTACKER_WITHOUT_KEY_REJECTED=PASS");
console.log("FRESH_CHALLENGE_REPLAY_REJECTED=PASS");
console.log("TAMPERED_TIMESTAMP_REJECTED=PASS");
console.log("POP_CRYPTOGRAPHIC_PROOF=PASS");
console.log("KEY_FINGERPRINT="+binding.publicKeyFingerprint);
