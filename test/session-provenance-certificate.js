import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { signSessionProvenanceCertificate, verifySessionProvenanceCertificate } from "../src/evidence/session-provenance-certificate.js";

const identity=createSigningIdentity();
const base={session_id:"sess-cert-001",subject:"user-001",issuer:"issuer-A",decision:"ALLOW",policy_fingerprint_sha256:"1".repeat(64),bundle_root_sha256:"2".repeat(64),lineage_root_sha256:"3".repeat(64),merkle_root_sha256:"4".repeat(64),evidence_fingerprint_sha256:"5".repeat(64),sequence:7};
const certificate=signSessionProvenanceCertificate(identity,base);
const valid=verifySessionProvenanceCertificate(certificate);
if(!valid.verified) throw new Error("PROVENANCE_VALID_FAILED");
console.log("PROVENANCE_VALID=PASS");

const decisionTampered={...certificate,decision:"REVOKE"};
const decisionResult=verifySessionProvenanceCertificate(decisionTampered);
if(decisionResult.verified) throw new Error("PROVENANCE_DECISION_TAMPER_ACCEPTED");
console.log("PROVENANCE_DECISION_TAMPER_REJECTED=PASS");

const policyTampered={...certificate,policy_fingerprint_sha256:"f".repeat(64)};
const policyResult=verifySessionProvenanceCertificate(policyTampered);
if(policyResult.verified) throw new Error("PROVENANCE_POLICY_TAMPER_ACCEPTED");
console.log("PROVENANCE_POLICY_TAMPER_REJECTED=PASS");

const rootTampered={...certificate,bundle_root_sha256:"f".repeat(64)};
const rootResult=verifySessionProvenanceCertificate(rootTampered);
if(rootResult.verified) throw new Error("PROVENANCE_ROOT_TAMPER_ACCEPTED");
console.log("PROVENANCE_ROOT_TAMPER_REJECTED=PASS");

const signerTampered={...certificate,signer_public_key_fingerprint_sha256:"f".repeat(64)};
const signerResult=verifySessionProvenanceCertificate(signerTampered);
if(signerResult.verified) throw new Error("PROVENANCE_SIGNER_TAMPER_ACCEPTED");
console.log("PROVENANCE_SIGNER_TAMPER_REJECTED=PASS");

console.log("SESSION_PROVENANCE_CERTIFICATE=PASS");