import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";

const ALLOWED_DECISIONS = Object.freeze([
  "CONTINUOUS",
  "REAUTH_REQUIRED",
  "REVOKE"
]);

const ALLOWED_CHECKS = Object.freeze([
  "sessionId",
  "subject",
  "issuer",
  "clientId",
  "deviceId",
  "sequence",
  "authTime",
  "proofOfPossession",
  "challenge"
]);

const ALLOWED_SECURITY_FIELDS = Object.freeze([
  "popKeyFingerprintSha256",
  "challengeResult",
  "replayResult",
  "continuityResult"
]);

const HEX64 = /^[0-9a-f]{64}$/i;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function sha256Text(text) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(String(text), "utf8"))
    .digest("hex")
    .toLowerCase();
}

function requireString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`EVIDENCE_${field.toUpperCase()}_INVALID`);
  }
}

function requireSha256(value, field) {
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new TypeError(`EVIDENCE_${field.toUpperCase()}_SHA256_INVALID`);
  }
}

function normalizeChecks(input) {
  if (input === undefined) return {};

  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("EVIDENCE_CHECKS_INVALID");
  }

  const out = {};

  for (const key of Object.keys(input)) {
    if (!ALLOWED_CHECKS.includes(key)) {
      throw new TypeError(`EVIDENCE_CHECK_NOT_ALLOWED:${key}`);
    }

    if (typeof input[key] !== "boolean") {
      throw new TypeError(`EVIDENCE_CHECK_VALUE_INVALID:${key}`);
    }

    out[key] = input[key];
  }

  return out;
}

function normalizeSecurity(input) {
  if (input === undefined) return {};

  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("EVIDENCE_SECURITY_INVALID");
  }

  const out = {};

  for (const key of Object.keys(input)) {
    if (!ALLOWED_SECURITY_FIELDS.includes(key)) {
      throw new TypeError(`EVIDENCE_SECURITY_FIELD_NOT_ALLOWED:${key}`);
    }

    const value = input[key];

    if (key === "popKeyFingerprintSha256") {
      requireSha256(value, "popKeyFingerprint");
      out[key] = value.toLowerCase();
      continue;
    }

    requireString(value, key);
    out[key] = value;
  }

  return out;
}

export function createEvidenceContract(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("EVIDENCE_INPUT_INVALID");
  }

  requireString(input.sessionId, "sessionId");
  requireSha256(input.anchorFingerprint, "anchorFingerprint");
  requireSha256(input.presentationFingerprint, "presentationFingerprint");
  requireString(input.timestamp, "timestamp");
  requireInteger(input.sequence, "sequence");
  requireString(input.decision, "decision");
  requireString(input.reason, "reason");

  if (!ISO_UTC.test(input.timestamp)) {
    throw new TypeError("EVIDENCE_TIMESTAMP_INVALID");
  }

  if (!ALLOWED_DECISIONS.includes(input.decision)) {
    throw new TypeError("EVIDENCE_DECISION_INVALID");
  }

  const failedChecks = Array.isArray(input.failedChecks)
    ? [...new Set(input.failedChecks.map(String))].sort()
    : [];

  for (const key of failedChecks) {
    if (!ALLOWED_CHECKS.includes(key)) {
      throw new TypeError(`EVIDENCE_FAILED_CHECK_NOT_ALLOWED:${key}`);
    }
  }

  const evidence = {
    schema_id: "session-continuity.evidence.v2",
    version: 2,
    session_id: input.sessionId,
    anchor_fingerprint_sha256: input.anchorFingerprint.toLowerCase(),
    presentation_fingerprint_sha256: input.presentationFingerprint.toLowerCase(),
    sequence: input.sequence,
    timestamp: input.timestamp,
    checks: normalizeChecks(input.checks),
    security: normalizeSecurity(input.security),
    failed_checks: failedChecks,
    decision: input.decision,
    reason: input.reason
  };

  const canonical = canonicalStringify(evidence);
  const fingerprint = sha256Text(canonical);

  return Object.freeze({
    evidence: Object.freeze(evidence),
    canonical,
    fingerprint
  });
}

function requireInteger(value, field) {
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError(`EVIDENCE_${field.toUpperCase()}_INVALID`);
  }
}

export function verifyEvidenceFingerprint(evidence, expectedFingerprint) {
  if (
    typeof expectedFingerprint !== "string" ||
    !HEX64.test(expectedFingerprint)
  ) {
    return false;
  }

  return (
    sha256Text(canonicalStringify(evidence)) ===
    expectedFingerprint.toLowerCase()
  );
}

export { ALLOWED_DECISIONS, ALLOWED_CHECKS, ALLOWED_SECURITY_FIELDS };
