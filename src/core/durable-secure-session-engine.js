import crypto from "crypto";
import { verifyContinuity } from "./continuity-verifier.js";
import { verifySignedPresentation } from "./proof-of-possession.js";
import { commitSessionAcceptance } from "./durable-secure-session-state.js";
import { createEvidenceContract } from "../evidence/evidence-contract.js";
import { canonicalStringify } from "./canonical.js";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex").toLowerCase();
}

function fingerprint(value) {
  return sha256Text(canonicalStringify(value));
}

function buildEvidence(anchor, presented, timestamp, checks, failedChecks, decision, reason, security) {
  return createEvidenceContract({
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
}

export function evaluateDurableSecureSession(
  anchor,
  durableState,
  presented,
  signedPresentation,
  timestamp,
  nowMs
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

  const continuity = verifyContinuity(
    anchor,
    presented
  );

  for (const key of [
    "sessionId",
    "subject",
    "issuer",
    "clientId",
    "deviceId"
  ]) {
    checks[key] =
      continuity.failedChecks?.includes(key) !== true;
  }

  security.continuityResult =
    continuity.reason;

  if (continuity.decision !== "CONTINUOUS") {
    return Object.freeze({
      decision: "REAUTH_REQUIRED",
      reason: continuity.reason,
      failedChecks: [
        ...(continuity.failedChecks || [])
      ],
      evidence: buildEvidence(
        anchor,
        presented,
        timestamp,
        checks,
        [...(continuity.failedChecks || [])],
        "REAUTH_REQUIRED",
        continuity.reason,
        security
      )
    });
  }

  const proof = verifySignedPresentation(
    anchor,
    signedPresentation
  );

  checks.proofOfPossession =
    proof.verified;

  if (
    typeof signedPresentation?.public_key_fingerprint_sha256 === "string" &&
    /^[0-9a-f]{64}$/i.test(
      signedPresentation.public_key_fingerprint_sha256
    )
  ) {
    security.popKeyFingerprintSha256 =
      signedPresentation.public_key_fingerprint_sha256.toLowerCase();
  }

  if (!proof.verified) {
    return Object.freeze({
      decision: "REAUTH_REQUIRED",
      reason: proof.reason,
      failedChecks: ["proofOfPossession"],
      evidence: buildEvidence(
        anchor,
        presented,
        timestamp,
        checks,
        ["proofOfPossession"],
        "REAUTH_REQUIRED",
        proof.reason,
        security
      )
    });
  }

  const committed =
    commitSessionAcceptance(
      durableState,
      anchor.sessionId,
      presented.sequence,
      signedPresentation.payload.challenge,
      nowMs
    );

  security.replayResult =
    committed.reason;

  security.challengeResult =
    committed.reason;

  if (committed.decision !== "CONTINUOUS") {
    if (committed.reason === "REPLAY_DETECTED") {
      checks.sequence = false;
    }

    if (
      committed.reason === "CHALLENGE_UNKNOWN" ||
      committed.reason === "CHALLENGE_SESSION_MISMATCH" ||
      committed.reason === "CHALLENGE_ALREADY_CONSUMED" ||
      committed.reason === "CHALLENGE_EXPIRED"
    ) {
      checks.challenge = false;
    }

    const failedChecks =
      committed.reason === "REPLAY_DETECTED"
        ? ["sequence"]
        : ["challenge"];

    return Object.freeze({
      decision: "REAUTH_REQUIRED",
      reason: committed.reason,
      failedChecks,
      evidence: buildEvidence(
        anchor,
        presented,
        timestamp,
        checks,
        failedChecks,
        "REAUTH_REQUIRED",
        committed.reason,
        security
      )
    });
  }

  checks.sequence = true;
  checks.challenge = true;

  return Object.freeze({
    decision: "CONTINUOUS",
    reason: "SECURE_CONTINUITY_COMMITTED",
    failedChecks: [],
    evidence: buildEvidence(
      anchor,
      presented,
      timestamp,
      checks,
      [],
      "CONTINUOUS",
      "SECURE_CONTINUITY_COMMITTED",
      security
    )
  });
}
