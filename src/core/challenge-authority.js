import crypto from "crypto";

function randomChallenge() {
  return crypto.randomBytes(32).toString("base64url");
}

export function createChallengeAuthority() {
  return {
    issued: new Map()
  };
}

export function issueChallenge(authority, sessionId, nowMs = Date.now()) {
  if (!authority || !(authority.issued instanceof Map)) {
    throw new Error("CHALLENGE_AUTHORITY_INVALID");
  }

  if (typeof sessionId !== "string" || !sessionId.length) {
    throw new Error("CHALLENGE_SESSION_INVALID");
  }

  const challenge = randomChallenge();

  authority.issued.set(challenge, {
    sessionId,
    issuedAt: nowMs,
    consumed: false
  });

  return Object.freeze({
    challenge,
    sessionId,
    issuedAt: nowMs
  });
}

export function consumeChallenge(authority, challenge, sessionId, nowMs = Date.now(), ttlMs = 60000) {
  if (!authority || !(authority.issued instanceof Map)) {
    return { accepted: false, reason: "CHALLENGE_AUTHORITY_INVALID" };
  }

  if (typeof challenge !== "string" || !challenge.length) {
    return { accepted: false, reason: "CHALLENGE_INVALID" };
  }

  const record = authority.issued.get(challenge);

  if (!record) {
    return { accepted: false, reason: "CHALLENGE_UNKNOWN" };
  }

  if (record.sessionId !== sessionId) {
    return { accepted: false, reason: "CHALLENGE_SESSION_MISMATCH" };
  }

  if (record.consumed) {
    return { accepted: false, reason: "CHALLENGE_ALREADY_CONSUMED" };
  }

  if (!Number.isInteger(ttlMs) || ttlMs < 1) {
    return { accepted: false, reason: "CHALLENGE_TTL_INVALID" };
  }

  if (nowMs - record.issuedAt > ttlMs) {
    return { accepted: false, reason: "CHALLENGE_EXPIRED" };
  }

  record.consumed = true;

  return {
    accepted: true,
    reason: "CHALLENGE_ACCEPTED",
    issuedAt: record.issuedAt,
    consumedAt: nowMs
  };
}
