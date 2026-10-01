import crypto from "crypto";
import { verifyContinuity } from "./continuity-verifier.js";
import { verifySequence, advanceReplayState } from "./replay-guard.js";
import { canonicalStringify } from "./canonical.js";
import { createEvidenceContract } from "../evidence/evidence-contract.js";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex").toLowerCase();
}

function fingerprint(value) {
  return sha256Text(canonicalStringify(value));
}

export function evaluateSession(anchor, replayState, presented, timestamp) {
  if (typeof timestamp !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(timestamp)) {
    throw new TypeError("TIMESTAMP_INVALID");
  }

  const continuity = verifyContinuity(anchor, presented);

  const checks = {
    sessionId: continuity.failedChecks?.includes("sessionId") !== true,
    subject: continuity.failedChecks?.includes("subject") !== true,
    issuer: continuity.failedChecks?.includes("issuer") !== true,
    clientId: continuity.failedChecks?.includes("clientId") !== true,
    deviceId: continuity.failedChecks?.includes("deviceId") !== true,
    sequence: false
  };

  let nextReplayState = replayState;
  let decision = continuity.decision;
  let reason = continuity.reason;
  let failedChecks = [...(continuity.failedChecks || [])];

  if (continuity.decision === "CONTINUOUS") {
    const replay = verifySequence(replayState, presented.sequence);
    checks.sequence = replay.decision === "CONTINUOUS";

    if (replay.decision !== "CONTINUOUS") {
      decision = "REAUTH_REQUIRED";
      reason = replay.reason;
      failedChecks.push("sequence");
    } else {
      const advanced = advanceReplayState(replayState, presented.sequence);
      nextReplayState = advanced.state;
    }
  }

  failedChecks = [...new Set(failedChecks)].sort();

  const evidence = createEvidenceContract({
    sessionId: anchor.sessionId,
    anchorFingerprint: fingerprint(anchor),
    presentationFingerprint: fingerprint(presented),
    sequence: Number.isInteger(presented.sequence) && presented.sequence >= 0 ? presented.sequence : 0,
    timestamp,
    checks,
    failedChecks,
    decision,
    reason
  });

  return Object.freeze({
    decision,
    reason,
    failedChecks,
    nextReplayState,
    evidence
  });
}
