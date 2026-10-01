import { verifyProofSignature } from "./proof-signature.js";
import { verifyDurableTrustedProof } from "./durable-trusted-proof-verifier.js";
import { verifyEvidenceProof } from "./offline-verifier.js";
import { verifySessionContinuityPolicyDecision } from "../policy/session-continuity-policy.js";

export function verifyIndependentSessionProof({
  certificate,
  durableTrustStore,
  bundleDir,
  lineageDir,
  policyDecision
}) {
  if (!certificate) return Object.freeze({ verified:false, reason:"CERTIFICATE_MISSING" });
  if (!policyDecision) return Object.freeze({ verified:false, reason:"POLICY_DECISION_MISSING" });

  const signature=verifyProofSignature(certificate);
  if(!signature.verified){
    return Object.freeze({verified:false,reason:signature.reason});
  }

  const trusted=verifyDurableTrustedProof(certificate,durableTrustStore);
  if(!trusted.verified){
    return Object.freeze({verified:false,reason:trusted.reason});
  }

  let offline;
  try {
    offline=verifyEvidenceProof(bundleDir,lineageDir);
  } catch(error) {
    return Object.freeze({
      verified:false,
      reason:error instanceof Error ? error.message : String(error)
    });
  }

  if(certificate.bundle_root_sha256!==offline.bundle_root_sha256){
    return Object.freeze({verified:false,reason:"RECEIVER_BUNDLE_ROOT_MISMATCH"});
  }
  if(certificate.lineage_root_sha256!==offline.lineage_root_sha256){
    return Object.freeze({verified:false,reason:"RECEIVER_LINEAGE_ROOT_MISMATCH"});
  }
  if(certificate.merkle_root_sha256!==offline.merkle_root_sha256){
    return Object.freeze({verified:false,reason:"RECEIVER_MERKLE_ROOT_MISMATCH"});
  }
  const policy=verifySessionContinuityPolicyDecision(policyDecision);
  if(!policy.verified){
    return Object.freeze({verified:false,reason:policy.reason});
  }
  if(policyDecision.decision!=="ALLOW"){
    return Object.freeze({verified:false,reason:"POLICY_DECISION_NOT_ALLOW",policy_decision:policyDecision.decision});
  }

  return Object.freeze({
    verified:true,
    reason:"INDEPENDENT_SESSION_PROOF_VALID",
    signer_public_key_fingerprint_sha256:signature.signer_public_key_fingerprint_sha256,
    bundle_root_sha256:offline.bundle_root_sha256,
    lineage_root_sha256:offline.lineage_root_sha256,
    merkle_root_sha256:offline.merkle_root_sha256,
    policy_fingerprint_sha256:policyDecision.policy_fingerprint_sha256
  });
}