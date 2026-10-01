import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";

function payloadForCertificate(value) {
  return canonicalStringify({
    schema_id:"session-continuity.session-provenance-certificate.v1",
    version:1,
    session_id:value.session_id,
    subject:value.subject,
    issuer:value.issuer,
    decision:value.decision,
    policy_fingerprint_sha256:value.policy_fingerprint_sha256,
    bundle_root_sha256:value.bundle_root_sha256,
    lineage_root_sha256:value.lineage_root_sha256,
    merkle_root_sha256:value.merkle_root_sha256,
    evidence_fingerprint_sha256:value.evidence_fingerprint_sha256,
    sequence:value.sequence
  });
}

export function signSessionProvenanceCertificate(identity,input) {
  if(!identity?.privateKey) throw new Error("PROVENANCE_SIGNING_PRIVATE_KEY_REQUIRED");
  if(!input || typeof input!=="object") throw new TypeError("PROVENANCE_INPUT_REQUIRED");
  const required=["session_id","subject","issuer","decision","policy_fingerprint_sha256","bundle_root_sha256","lineage_root_sha256","merkle_root_sha256","evidence_fingerprint_sha256"];
  for(const field of required){ if(typeof input[field]!=="string" || !input[field].length) throw new TypeError(`PROVENANCE_${field.toUpperCase()}_REQUIRED`); }
  if(!Number.isInteger(input.sequence) || input.sequence<1) throw new TypeError("PROVENANCE_SEQUENCE_INVALID");
  if(!["ALLOW","REAUTH","REVOKE"].includes(input.decision)) throw new TypeError("PROVENANCE_DECISION_INVALID");
  const payload=payloadForCertificate(input);
  const signature=crypto.sign(null,Buffer.from(payload,"utf8"),identity.privateKey).toString("base64");
  return Object.freeze({
    schema_id:"session-continuity.session-provenance-certificate.v1",
    version:1,
    session_id:input.session_id,
    subject:input.subject,
    issuer:input.issuer,
    decision:input.decision,
    policy_fingerprint_sha256:input.policy_fingerprint_sha256,
    bundle_root_sha256:input.bundle_root_sha256,
    lineage_root_sha256:input.lineage_root_sha256,
    merkle_root_sha256:input.merkle_root_sha256,
    evidence_fingerprint_sha256:input.evidence_fingerprint_sha256,
    sequence:input.sequence,
    signer_public_key_fingerprint_sha256:identity.publicKeyFingerprintSha256,
    signer_public_key_spki_base64:identity.publicKeySpkiBase64,
    signature_base64:signature
  });
}

export function verifySessionProvenanceCertificate(certificate) {
  if(!certificate || certificate.schema_id!=="session-continuity.session-provenance-certificate.v1" || certificate.version!==1) return {verified:false,reason:"PROVENANCE_CERTIFICATE_INVALID"};
  for(const field of ["policy_fingerprint_sha256","bundle_root_sha256","lineage_root_sha256","merkle_root_sha256","evidence_fingerprint_sha256","signer_public_key_fingerprint_sha256"]){ if(typeof certificate[field]!=="string" || !/^[0-9a-f]{64}$/i.test(certificate[field])) return {verified:false,reason:`PROVENANCE_${field.toUpperCase()}_INVALID`}; }
  if(!["ALLOW","REAUTH","REVOKE"].includes(certificate.decision)) return {verified:false,reason:"PROVENANCE_DECISION_INVALID"};
  if(typeof certificate.session_id!=="string" || !certificate.session_id.length) return {verified:false,reason:"PROVENANCE_SESSION_ID_INVALID"};
  if(typeof certificate.subject!=="string" || !certificate.subject.length) return {verified:false,reason:"PROVENANCE_SUBJECT_INVALID"};
  if(typeof certificate.issuer!=="string" || !certificate.issuer.length) return {verified:false,reason:"PROVENANCE_ISSUER_INVALID"};
  if(!Number.isInteger(certificate.sequence) || certificate.sequence<1) return {verified:false,reason:"PROVENANCE_SEQUENCE_INVALID"};
  if(typeof certificate.signer_public_key_spki_base64!=="string" || !certificate.signer_public_key_spki_base64.length) return {verified:false,reason:"PROVENANCE_SIGNER_KEY_MISSING"};
  if(typeof certificate.signature_base64!=="string" || !certificate.signature_base64.length) return {verified:false,reason:"PROVENANCE_SIGNATURE_MISSING"};
  let der;
  try { der=Buffer.from(certificate.signer_public_key_spki_base64,"base64"); } catch { return {verified:false,reason:"PROVENANCE_SIGNER_KEY_INVALID"}; }
  const actual=crypto.createHash("sha256").update(der).digest("hex").toLowerCase();
  if(actual!==certificate.signer_public_key_fingerprint_sha256.toLowerCase()) return {verified:false,reason:"PROVENANCE_SIGNER_FINGERPRINT_MISMATCH"};
  let publicKey;
  try { publicKey=crypto.createPublicKey({key:der,type:"spki",format:"der"}); } catch { return {verified:false,reason:"PROVENANCE_SIGNER_KEY_INVALID"}; }
  const payload=payloadForCertificate(certificate);
  let valid=false;
  try { valid=crypto.verify(null,Buffer.from(payload,"utf8"),publicKey,Buffer.from(certificate.signature_base64,"base64")); } catch { return {verified:false,reason:"PROVENANCE_SIGNATURE_INVALID"}; }
  return valid ? {verified:true,reason:"SESSION_PROVENANCE_CERTIFICATE_VALID",signer_public_key_fingerprint_sha256:actual} : {verified:false,reason:"PROVENANCE_SIGNATURE_INVALID"};
}