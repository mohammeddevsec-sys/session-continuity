import { SESSION_STATES, validateSessionAnchor } from "./session-anchor.js";

export function verifyContinuity(anchor, presented) {
  if (!validateSessionAnchor(anchor)) return { decision: "REAUTH_REQUIRED", reason: "INVALID_ANCHOR" };
  if (!presented || typeof presented !== "object") return { decision: "REAUTH_REQUIRED", reason: "MISSING_PRESENTATION" };
  const checks = {
    sessionId: presented.sessionId === anchor.sessionId,
    subject: presented.subject === anchor.subject,
    issuer: presented.issuer === anchor.issuer,
    clientId: anchor.clientId === null || presented.clientId === anchor.clientId,
    deviceId: anchor.deviceId === null || presented.deviceId === anchor.deviceId
  };
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([key]) => key);
  if (failed.length > 0) return { decision: "REAUTH_REQUIRED", reason: "CONTINUITY_BROKEN", failedChecks: failed };
  return { decision: "CONTINUOUS", reason: "ANCHOR_MATCH", failedChecks: [] };
}

export { SESSION_STATES };
