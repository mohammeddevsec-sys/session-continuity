import fs from "fs";
import path from "path";
import {
  evaluateDurableSecureSession
} from "./durable-secure-session-engine.js";
import {
  writeEvidenceBundle
} from "../evidence/evidence-bundle.js";
import {
  appendEvidenceLineage
} from "../evidence/evidence-lineage.js";
import {
  verifyEvidenceProof
} from "../evidence/offline-verifier.js";
import {
  signProof
} from "../evidence/proof-signature.js";
import {
  verifyTrustedProof
} from "../evidence/trusted-proof-verifier.js";

export function executeFinalProofPipeline({
  anchor,
  durableState,
  presented,
  signedPresentation,
  timestamp,
  nowMs,
  signingIdentity,
  trustStore,
  outputRoot
}) {
  const session =
    evaluateDurableSecureSession(
      anchor,
      durableState,
      presented,
      signedPresentation,
      timestamp,
      nowMs
    );

  if (session.decision !== "CONTINUOUS") {
    return Object.freeze({
      decision: session.decision,
      reason: session.reason,
      session,
      certificate: null,
      verification: null
    });
  }

  const bundleDir =
    path.join(outputRoot, "bundle");

  const lineageDir =
    path.join(outputRoot, "lineage");

  fs.rmSync(outputRoot, {
    recursive: true,
    force: true
  });

  const bundle =
    writeEvidenceBundle(
      bundleDir,
      {
        "decision.json": {
          schema_id:
            "session-continuity.decision.v1",
          version: 1,
          decision: session.decision,
          reason: session.reason,
          sequence: presented.sequence,
          timestamp
        },
        "evidence.json":
          session.evidence.evidence
      }
    );

  const lineage =
    appendEvidenceLineage(
      lineageDir,
      {
        session_id:
          anchor.sessionId,
        decision:
          session.decision,
        reason:
          session.reason,
        sequence:
          presented.sequence,
        evidence_fingerprint_sha256:
          session.evidence.fingerprint,
        bundle_root_sha256:
          bundle.bundle_root_sha256,
        timestamp
      }
    );

  const proof = {
    bundle_root_sha256:
      bundle.bundle_root_sha256,
    lineage_root_sha256:
      lineage.lineage_root_sha256,
    merkle_root_sha256:
      lineage.merkle_root_sha256,
    evidence_fingerprint_sha256:
      session.evidence.fingerprint
  };

  const certificate =
    signProof(
      signingIdentity,
      proof
    );

  const offline =
    verifyEvidenceProof(
      bundleDir,
      lineageDir
    );

  const trusted =
    verifyTrustedProof(
      certificate,
      trustStore
    );

  const bindingValid =
    certificate.bundle_root_sha256 ===
      offline.bundle_root_sha256 &&
    certificate.lineage_root_sha256 ===
      offline.lineage_root_sha256 &&
    certificate.merkle_root_sha256 ===
      offline.merkle_root_sha256 &&
    certificate.evidence_fingerprint_sha256 ===
      session.evidence.fingerprint;

  if (!bindingValid) {
    throw new Error(
      "FINAL_PROOF_CERTIFICATE_BINDING_FAILED"
    );
  }

  if (!trusted.verified) {
    throw new Error(
      "FINAL_PROOF_TRUST_FAILED"
    );
  }

  if (!offline.verified) {
    throw new Error(
      "FINAL_PROOF_OFFLINE_VERIFY_FAILED"
    );
  }

  return Object.freeze({
    decision: session.decision,
    reason: session.reason,
    session,
    bundle,
    lineage,
    proof,
    certificate,
    verification: {
      offline,
      trusted,
      binding_valid: bindingValid
    }
  });
}
