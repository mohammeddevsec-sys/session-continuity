import {
  evaluateDurableSecureSession
} from "./durable-secure-session-engine.js";
import {
  signProof
} from "../evidence/proof-signature.js";
import {
  verifyTrustedProof
} from "../evidence/trusted-proof-verifier.js";

export function evaluateAndCertifyDurableSession(
  anchor,
  durableState,
  presented,
  signedPresentation,
  timestamp,
  nowMs,
  signingIdentity,
  trustStore
) {
  const sessionResult =
    evaluateDurableSecureSession(
      anchor,
      durableState,
      presented,
      signedPresentation,
      timestamp,
      nowMs
    );

  if (
    !sessionResult.evidence ||
    typeof sessionResult.evidence.fingerprint !== "string"
  ) {
    throw new Error("SESSION_EVIDENCE_MISSING");
  }

  if (sessionResult.decision !== "CONTINUOUS") {
    return Object.freeze({
      session: sessionResult,
      certificate: null,
      trust: null
    });
  }

  const proof = {
    bundle_root_sha256:
      sessionResult.evidence.fingerprint,
    lineage_root_sha256:
      "0".repeat(64),
    merkle_root_sha256:
      "0".repeat(64),
    evidence_fingerprint_sha256:
      sessionResult.evidence.fingerprint
  };

  const certificate =
    signProof(
      signingIdentity,
      proof
    );

  const trust =
    verifyTrustedProof(
      certificate,
      trustStore
    );

  if (!trust.verified) {
    return Object.freeze({
      session: sessionResult,
      certificate,
      trust
    });
  }

  return Object.freeze({
    session: sessionResult,
    certificate,
    trust
  });
}
