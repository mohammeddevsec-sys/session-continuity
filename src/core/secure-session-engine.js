import crypto from "crypto";
import { verifyContinuity } from "./continuity-verifier.js";
import { verifySequence, advanceReplayState } from "./replay-guard.js";
import { verifySignedPresentation } from "./proof-of-possession.js";
import { consumeChallenge } from "./challenge-authority.js";
import { createEvidenceContract } from "../evidence/evidence-contract.js";
import { canonicalStringify } from "./canonical.js";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text),"utf8")).digest("hex").toLowerCase();
}

function fingerprint(value) {
  return sha256Text(canonicalStringify(value));
}

function fail(anchor, presented, replayState, decision, reason, failedChecks, checks, security, timestamp) {
  const evidence = createEvidenceContract({
    sessionId: anchor.sessionId,
    anchorFingerprint: fingerprint(anchor),
    presentationFingerprint: fingerprint(presented),
    sequence: Number.isInteger(presented?.sequence) && presented.sequence >= 0 ? presented.sequence : 0,
    timestamp,
    checks,
    failedChecks,
    decision,
    reason,
    security
  });

  return Object.freeze({
    decision,
    reason,
    failedChecks,
    nextReplayState: replayState,
    evidence
  });
}

export function evaluateSecureSessionWithEvidence(
  anchor,
  replayState,
  challengeAuthority,
  presented,
  signedPresentation,
  timestamp,
  nowMs,
  ttlMs = 60000
) {
  const checks = {
    sessionId: false,
    subject: false,
    issuer: false,
    clientId: false,
    deviceId: false,
    sequence: false,
    proofOfPossession: false,
    challenge: false
  };

  const security = {
    challengeResult: "NOT_EVALUATED",
    replayResult: "NOT_EVALUATED",
    continuityResult: "NOT_EVALUATED"
  };

  const continuity = verifyContinuity(anchor, presented);

  for (const key of ["sessionId","subject","issuer","clientId","deviceId"]) {
    checks[key] = continuity.failedChecks?.includes(key) !== true;
  }

  security.continuityResult = continuity.reason;

  if (continuity.decision !== "CONTINUOUS") {
    return fail(
      anchor,
      presented,
      replayState,
      "REAUTH_REQUIRED",
      continuity.reason,
      [...(continuity.failedChecks || [])],
      checks,
      security,
      timestamp
    );
  }

  const proof = verifySignedPresentation(anchor, signedPresentation);

  checks.proofOfPossession = proof.verified;

  if (
    typeof signedPresentation?.public_key_fingerprint_sha256 === "string" &&
    /^[0-9a-f]{64}$/i.test(signedPresentation.public_key_fingerprint_sha256)
  ) {
    security.popKeyFingerprintSha256 =
      signedPresentation.public_key_fingerprint_sha256.toLowerCase();
  }

  if (!proof.verified) {
    return fail(
      anchor,
      presented,
      replayState,
      "REAUTH_REQUIRED",
      proof.reason,
      ["proofOfPossession"],
      checks,
      security,
      timestamp
    );
  }

  const replay = verifySequence(replayState, presented.sequence);

  security.replayResult = replay.reason;
  checks.sequence = replay.decision === "CONTINUOUS";

  if (replay.decision !== "CONTINUOUS") {
    return fail(
      anchor,
      presented,
      replayState,
      "REAUTH_REQUIRED",
      replay.reason,
      ["sequence"],
      checks,
      security,
      timestamp
    );
  }

  const challenge = consumeChallenge(
    challengeAuthority,
    signedPresentation.payload.challenge,
    anchor.sessionId,
    nowMs,
    ttlMs
  );

  security.challengeResult = challenge.reason;
  checks.challenge = challenge.accepted;

  if (!challenge.accepted) {
    return fail(
      anchor,
      presented,
      replayState,
      "REAUTH_REQUIRED",
      challenge.reason,
      ["challenge"],
      checks,
      security,
      timestamp
    );
  }

  const advanced = advanceReplayState(
    replayState,
    presented.sequence
  );

  return Object.freeze({
    decision: "CONTINUOUS",
    reason: "SECURE_CONTINUITY_CONFIRMED",
    failedChecks: [],
    nextReplayState: advanced.state,
    evidence: createEvidenceContract({
      sessionId: anchor.sessionId,
      anchorFingerprint: fingerprint(anchor),
      presentationFingerprint: fingerprint(presented),
      sequence: presented.sequence,
      timestamp,
      checks,
      failedChecks: [],
      decision: "CONTINUOUS",
      reason: "SECURE_CONTINUITY_CONFIRMED",
      security
    })
  });
}
