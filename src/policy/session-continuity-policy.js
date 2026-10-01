import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";

export const POLICY_DECISIONS = Object.freeze({
  ALLOW: "ALLOW",
  REAUTH: "REAUTH",
  REVOKE: "REVOKE"
});

const REAUTH_REASONS = new Set([
  "INVALID_ANCHOR",
  "MISSING_PRESENTATION",
  "CONTINUITY_BROKEN",
  "REPLAY_DETECTED",
  "INVALID_SEQUENCE",
  "CHALLENGE_UNKNOWN",
  "CHALLENGE_SESSION_MISMATCH",
  "CHALLENGE_ALREADY_CONSUMED",
  "CHALLENGE_EXPIRED",
  "CHALLENGE_INVALID",
  "PROOF_OF_POSSESSION_INVALID",
  "PROOF_INVALID",
  "SIGNATURE_INVALID"
]);

const REVOKE_REASONS = new Set([
  "FINAL_PROOF_CERTIFICATE_BINDING_FAILED",
  "FINAL_PROOF_TRUST_FAILED",
  "FINAL_PROOF_OFFLINE_VERIFY_FAILED",
  "TRANSACTIONAL_CERTIFICATE_BINDING_FAILED",
  "TRANSACTIONAL_TRUST_FAILED",
  "TRANSACTIONAL_OFFLINE_VERIFY_FAILED"
]);

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text),"utf8")).digest("hex").toLowerCase();
}

function policyFingerprint(value) {
  return sha256Text(canonicalStringify(value));
}

function normalizeReason(reason) {
  return typeof reason === "string" && reason.length ? reason : "UNSPECIFIED";
}

export function evaluateSessionContinuityPolicy(input) {
  if (!input || typeof input !== "object") throw new TypeError("POLICY_INPUT_REQUIRED");

  const reason = normalizeReason(input.reason);
  const certificatePresent = input.certificatePresent === true;
  const bindingValid = input.bindingValid === true;
  const offlineVerified = input.offlineVerified === true;
  const trustedVerified = input.trustedVerified === true;
  const committed = input.committed === true;
  const engineDecision = input.engineDecision;

  let decision;
  let decisionReason;

  if (REVOKE_REASONS.has(reason) || (certificatePresent && (!bindingValid || !offlineVerified || !trustedVerified))) {
    decision = POLICY_DECISIONS.REVOKE;
    decisionReason = "PROOF_INTEGRITY_OR_TRUST_FAILURE";
  } else if (engineDecision === "CONTINUOUS" && committed && certificatePresent && bindingValid && offlineVerified && trustedVerified) {
    decision = POLICY_DECISIONS.ALLOW;
    decisionReason = "SESSION_CONTINUITY_PROVEN";
  } else if (engineDecision === "REAUTH_REQUIRED" || REAUTH_REASONS.has(reason)) {
    decision = POLICY_DECISIONS.REAUTH;
    decisionReason = reason;
  } else {
    decision = POLICY_DECISIONS.REVOKE;
    decisionReason = "POLICY_EVIDENCE_INSUFFICIENT";
  }

  const policyRecord = {
    schema_id: "session-continuity.policy-decision.v1",
    version: 1,
    decision,
    reason: decisionReason,
    engine_decision: engineDecision ?? null,
    engine_reason: reason,
    committed,
    certificate_present: certificatePresent,
    binding_valid: bindingValid,
    offline_verified: offlineVerified,
    trusted_verified: trustedVerified
  };

  return Object.freeze({
    ...policyRecord,
    policy_fingerprint_sha256: policyFingerprint(policyRecord)
  });
}

export function verifySessionContinuityPolicyDecision(decision) {
  if (!decision || typeof decision !== "object") return { verified: false, reason: "POLICY_DECISION_INVALID" };
  if (decision.schema_id !== "session-continuity.policy-decision.v1" || decision.version !== 1) return { verified: false, reason: "POLICY_SCHEMA_INVALID" };
  if (!Object.values(POLICY_DECISIONS).includes(decision.decision)) return { verified: false, reason: "POLICY_DECISION_INVALID" };
  if (typeof decision.policy_fingerprint_sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(decision.policy_fingerprint_sha256)) return { verified: false, reason: "POLICY_FINGERPRINT_INVALID" };
  const { policy_fingerprint_sha256, ...body } = decision;
  const expected = policyFingerprint(body);
  if (expected !== policy_fingerprint_sha256.toLowerCase()) return { verified: false, reason: "POLICY_FINGERPRINT_MISMATCH" };
  return Object.freeze({ verified: true, reason: "POLICY_DECISION_VALID" });
}