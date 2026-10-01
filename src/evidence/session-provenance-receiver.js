import { verifySessionProvenanceCertificate } from "./session-provenance-certificate.js";
import { verifyDurableTrust } from "./durable-trust-store.js";
import { verifyEvidenceProof } from "./offline-verifier.js";
import { verifyEvidenceFingerprint } from "./evidence-contract.js";
import fs from "fs";
import path from "path";
import { verifySessionContinuityPolicyDecision } from "../policy/session-continuity-policy.js";

export function verifySessionProvenanceReceipt({ certificate, durableTrustStore, bundleDir, lineageDir, policyDecision, expectedSessionId, expectedSubject, expectedIssuer }) {
  if(!certificate) return Object.freeze({verified:false,reason:"PROVENANCE_CERTIFICATE_MISSING"});

  const signature=verifySessionProvenanceCertificate(certificate);
  if(!signature.verified) return Object.freeze({verified:false,reason:signature.reason});
  if(certificate.decision!=="ALLOW") return Object.freeze({verified:false,reason:"PROVENANCE_DECISION_NOT_ALLOW"});

  if(typeof expectedSessionId==="string" && certificate.session_id!==expectedSessionId) return Object.freeze({verified:false,reason:"PROVENANCE_SESSION_ID_MISMATCH"});
  if(typeof expectedSubject==="string" && certificate.subject!==expectedSubject) return Object.freeze({verified:false,reason:"PROVENANCE_SUBJECT_MISMATCH"});
  if(typeof expectedIssuer==="string" && certificate.issuer!==expectedIssuer) return Object.freeze({verified:false,reason:"PROVENANCE_ISSUER_MISMATCH"});

  const trust=verifyDurableTrust(durableTrustStore,certificate.signer_public_key_fingerprint_sha256);
  if(!trust.trusted) return Object.freeze({verified:false,reason:trust.reason});

  let offline;
  try {
    offline=verifyEvidenceProof(bundleDir,lineageDir);
  } catch(error) {
    return Object.freeze({verified:false,reason:error instanceof Error ? error.message : String(error)});
  }

  if(certificate.bundle_root_sha256!==offline.bundle_root_sha256) return Object.freeze({verified:false,reason:"PROVENANCE_BUNDLE_ROOT_MISMATCH"});
  if(certificate.lineage_root_sha256!==offline.lineage_root_sha256) return Object.freeze({verified:false,reason:"PROVENANCE_LINEAGE_ROOT_MISMATCH"});
  if(certificate.merkle_root_sha256!==offline.merkle_root_sha256) return Object.freeze({verified:false,reason:"PROVENANCE_MERKLE_ROOT_MISMATCH"});
  let evidence;
  try {
    evidence=JSON.parse(fs.readFileSync(path.join(bundleDir,"evidence.json"),"utf8"));
  } catch(error) {
    return Object.freeze({verified:false,reason:error instanceof Error ? error.message : String(error)});
  }
  if(!verifyEvidenceFingerprint(evidence,certificate.evidence_fingerprint_sha256)) return Object.freeze({verified:false,reason:"PROVENANCE_EVIDENCE_FINGERPRINT_MISMATCH"});
  if(evidence.session_id!==certificate.session_id) return Object.freeze({verified:false,reason:"PROVENANCE_EVIDENCE_SESSION_MISMATCH"});
  if(evidence.sequence!==certificate.sequence) return Object.freeze({verified:false,reason:"PROVENANCE_EVIDENCE_SEQUENCE_MISMATCH"});
  const policy=verifySessionContinuityPolicyDecision(policyDecision);
  if(!policy.verified) return Object.freeze({verified:false,reason:policy.reason});
  if(policyDecision.decision!=="ALLOW") return Object.freeze({verified:false,reason:"RECEIVER_POLICY_NOT_ALLOW"});
  if(policyDecision.policy_fingerprint_sha256!==certificate.policy_fingerprint_sha256) return Object.freeze({verified:false,reason:"PROVENANCE_POLICY_FINGERPRINT_MISMATCH"});

  return Object.freeze({
    verified:true,
    reason:"SESSION_PROVENANCE_RECEIPT_VALID",
    decision:certificate.decision,
    session_id:certificate.session_id,
    subject:certificate.subject,
    issuer:certificate.issuer,
    sequence:certificate.sequence,
    policy_fingerprint_sha256:certificate.policy_fingerprint_sha256,
    bundle_root_sha256:certificate.bundle_root_sha256,
    lineage_root_sha256:certificate.lineage_root_sha256,
    merkle_root_sha256:certificate.merkle_root_sha256,
    evidence_fingerprint_sha256:certificate.evidence_fingerprint_sha256,
    signer_public_key_fingerprint_sha256:certificate.signer_public_key_fingerprint_sha256
  });
}