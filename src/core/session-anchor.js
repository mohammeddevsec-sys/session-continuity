export const SESSION_STATES = Object.freeze({ ACTIVE: "ACTIVE", BROKEN: "BROKEN", REAUTH_REQUIRED: "REAUTH_REQUIRED" });

export function createSessionAnchor(input) {
  if (!input || typeof input !== "object") throw new TypeError("session input required");
  const required = ["sessionId", "subject", "issuer", "authTime"];
  for (const key of required) {
    if (typeof input[key] !== "string" || input[key].length === 0) throw new TypeError(`missing ${key}`);
  }
  return Object.freeze({
    version: 1,
    sessionId: input.sessionId,
    subject: input.subject,
    issuer: input.issuer,
    authTime: input.authTime,
    clientId: input.clientId ?? null,
    deviceId: input.deviceId ?? null,
    networkContext: input.networkContext ?? null,
    state: SESSION_STATES.ACTIVE
  });
}

export function validateSessionAnchor(anchor) {
  if (!anchor || anchor.version !== 1) return false;
  return typeof anchor.sessionId === "string" && anchor.sessionId.length > 0 && typeof anchor.subject === "string" && anchor.subject.length > 0 && typeof anchor.issuer === "string" && anchor.issuer.length > 0 && typeof anchor.authTime === "string" && anchor.authTime.length > 0;
}
