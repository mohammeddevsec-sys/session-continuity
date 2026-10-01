import { executeTransactionalFinalProofPipeline } from "../core/transactional-final-proof-pipeline.js";
import { evaluateSessionContinuityPolicy } from "../policy/session-continuity-policy.js";
import { signSessionProvenanceCertificate } from "../evidence/session-provenance-certificate.js";

function buildDiagnostic(reason, pipeline) {
  let reasonCode = "UNSPECIFIED";
  if (typeof reason === "string" && reason.length > 0) { reasonCode = reason; }
  let failureStage = "UNCLASSIFIED";
  let failureLocation = "UNCLASSIFIED";
  if (reasonCode === "INVALID_ANCHOR" || reasonCode === "MISSING_PRESENTATION" || reasonCode === "CONTINUITY_BROKEN") {
    failureStage = "CONTINUITY";
    failureLocation = "verifyContinuity";
  } else if (reasonCode === "INVALID_PRESENTATION" || reasonCode === "ANCHOR_PUBLIC_KEY_MISSING" || reasonCode === "BINDING_KEY_MISMATCH" || reasonCode === "PRESENTATION_SIGNATURE_INVALID" || reasonCode === "SESSION_ID_MISMATCH" || reasonCode === "SUBJECT_MISMATCH" || reasonCode === "ISSUER_MISMATCH" || reasonCode === "PROOF_OF_POSSESSION_INVALID" || reasonCode === "PROOF_INVALID" || reasonCode === "SIGNATURE_INVALID" || reasonCode.startsWith("PRESENTATION_FIELD_MISSING:")) {
    failureStage = "PROOF_OF_POSSESSION";
    failureLocation = "verifySignedPresentation";
  } else if (reasonCode === "INVALID_REPLAY_STATE" || reasonCode === "INVALID_SEQUENCE" || reasonCode === "REPLAY_DETECTED") {
    failureStage = "REPLAY";
    failureLocation = reasonCode === "INVALID_REPLAY_STATE" ? "verifySequence" : "sequence";
  } else if (reasonCode === "CHALLENGE_INVALID" || reasonCode === "CHALLENGE_UNKNOWN") {
    failureStage = "CHALLENGE";
    failureLocation = "challenge.lookup";
  } else if (reasonCode === "CHALLENGE_SESSION_MISMATCH") {
    failureStage = "CHALLENGE";
    failureLocation = "challenge.session_binding";
  } else if (reasonCode === "CHALLENGE_ALREADY_CONSUMED") {
    failureStage = "CHALLENGE";
    failureLocation = "challenge.consumed";
  } else if (reasonCode === "CHALLENGE_EXPIRED") {
    failureStage = "CHALLENGE";
    failureLocation = "challenge.expiry";
  } else if (reasonCode === "TRANSACTIONAL_CERTIFICATE_BINDING_FAILED" || reasonCode === "FINAL_PROOF_CERTIFICATE_BINDING_FAILED") {
    failureStage = "FINAL_PROOF";
    failureLocation = "certificate.binding";
  } else if (reasonCode === "TRANSACTIONAL_OFFLINE_VERIFY_FAILED" || reasonCode === "FINAL_PROOF_OFFLINE_VERIFY_FAILED") {
    failureStage = "FINAL_PROOF";
    failureLocation = "offline.verify";
  } else if (reasonCode === "TRANSACTIONAL_TRUST_FAILED" || reasonCode === "FINAL_PROOF_TRUST_FAILED") {
    failureStage = "FINAL_PROOF";
    failureLocation = "trust.verify";
  } else if (reasonCode === "SECURE_STATE_SESSION_INVALID" || reasonCode === "NOW_INVALID" || reasonCode.startsWith("SECURE_STATE_COMMIT_") || reasonCode === "SECURE_STATE_COMMIT_PERSISTENCE_MISMATCH" || reasonCode === "SECURE_STATE_CHALLENGE_PERSISTENCE_MISMATCH") {
    failureStage = "COMMIT";
    failureLocation = "commitSessionAcceptance";
  } else if (reasonCode.startsWith("SECURE_STATE_")) {
    failureStage = "DURABLE_STATE";
    failureLocation = "verifySecureSessionState";
  } else if (reasonCode.startsWith("PROVENANCE_")) {
    failureStage = "PROVENANCE";
    failureLocation = "session-provenance-certificate";
  } else if (reasonCode.startsWith("POLICY_")) {
    failureStage = "POLICY";
    failureLocation = "evaluateSessionContinuityPolicy";
  } else if (reasonCode.startsWith("EVIDENCE_")) {
    failureStage = "EVIDENCE";
    failureLocation = "evidence-contract";
  } else if (reasonCode.startsWith("CANONICAL_")) {
    failureStage = "CANONICAL";
    failureLocation = "canonicalize";
  } else if (reasonCode.startsWith("TRUST_") || reasonCode.startsWith("SIGNER_") || reasonCode.startsWith("SIGNING_")) {
    failureStage = "TRUST";
    failureLocation = "durable-trust-store";
  } else if (reasonCode.startsWith("LINEAGE_") || reasonCode.startsWith("HEAD_")) {
    failureStage = "LINEAGE";
    failureLocation = "evidence-lineage";
  } else if (reasonCode.startsWith("BUNDLE_") || reasonCode.startsWith("MANIFEST_") || reasonCode.startsWith("SUM_LINE") || reasonCode.startsWith("SUMS_") || reasonCode.startsWith("FILE_MISSING") || reasonCode.startsWith("HASH_MISMATCH") || reasonCode.startsWith("UNSAFE_FILE_NAME")) {
    failureStage = "BUNDLE";
    failureLocation = "evidence-bundle";
  }
  const evidenceRef = typeof pipeline?.evidence?.fingerprint === "string" ? pipeline.evidence.fingerprint : null;
  return Object.freeze({ reason_code: reasonCode, failure_stage: failureStage, failure_location: failureLocation, evidence_ref: evidenceRef });
}

export function executeSessionContinuityDecision(input) {
  try {
    const pipeline = executeTransactionalFinalProofPipeline(input);

    const policy = evaluateSessionContinuityPolicy({
      engineDecision: pipeline.decision,
      reason: pipeline.reason,
      committed: pipeline.committed === true,
      certificatePresent: pipeline.certificate !== null && pipeline.certificate !== undefined,
      bindingValid: pipeline.verification?.binding_valid === true,
      offlineVerified: pipeline.verification?.offline?.verified === true,
      trustedVerified: pipeline.verification?.trusted?.verified === true
    });

    const provenanceCertificate =
      policy.decision === "ALLOW"
        ? signSessionProvenanceCertificate(input.signingIdentity, {
            session_id: input.anchor.sessionId,
            subject: input.anchor.subject,
            issuer: input.anchor.issuer,
            decision: policy.decision,
            policy_fingerprint_sha256: policy.policy_fingerprint_sha256,
            bundle_root_sha256: pipeline.proof.bundle_root_sha256,
            lineage_root_sha256: pipeline.proof.lineage_root_sha256,
            merkle_root_sha256: pipeline.proof.merkle_root_sha256,
            evidence_fingerprint_sha256: pipeline.proof.evidence_fingerprint_sha256,
            sequence: input.presented.sequence
          })
        : null;

    return Object.freeze({
      decision: policy.decision,
      reason: policy.reason,
      policy,
      provenanceCertificate,
      pipeline,
      diagnostic: policy.decision === "ALLOW" ? null : buildDiagnostic(pipeline.reason, pipeline)
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    const policy = evaluateSessionContinuityPolicy({
      engineDecision: "CONTINUOUS",
      reason: message,
      committed: false,
      certificatePresent: true,
      bindingValid: false,
      offlineVerified: false,
      trustedVerified: false
    });

    return Object.freeze({
      decision: policy.decision,
      reason: policy.reason,
      policy,
      provenanceCertificate: null,
      pipeline: null,
      error: message,
      diagnostic: buildDiagnostic(message, null)
    });
  }
}
