import crypto from "crypto";
import { jcsCanonicalize } from "../core/canonical-v1_1.js";

const SCHEMA_ID = "continuity-proof.v1.1";
const REQUIRED_CORE_FIELDS = [
  "schema",
  "continuity_root",
  "sequence",
  "parent_hash",
  "state_hash",
  "decision_hash",
  "issued_at",
  "signer_key_id",
  "policy_fingerprint_sha256",
  "continuity_hash"
];

function assertHex64(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new TypeError(`PROOF_SIGNATURE_${field.toUpperCase()}_INVALID`);
  }
}

function signedPayload(proof) {
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
    throw new TypeError("PROOF_REQUIRED");
  }
  for (const field of REQUIRED_CORE_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(proof, field)) {
      throw new TypeError(`PROOF_SIGNATURE_${field.toUpperCase()}_MISSING`);
    }
  }
  if (proof.schema !== SCHEMA_ID) {
    throw new TypeError("PROOF_SIGNATURE_SCHEMA_INVALID");
  }
  if (!Number.isInteger(proof.sequence) || proof.sequence < 1) {
    throw new TypeError("PROOF_SIGNATURE_SEQUENCE_INVALID");
  }
  if (proof.sequence === 1) {
    if (proof.parent_hash !== null) throw new TypeError("PROOF_SIGNATURE_PARENT_INVALID");
  } else {
    assertHex64(proof.parent_hash, "parent_hash");
  }
  assertHex64(proof.continuity_root, "continuity_root");
  assertHex64(proof.state_hash, "state_hash");
  assertHex64(proof.decision_hash, "decision_hash");
  assertHex64(proof.policy_fingerprint_sha256, "policy_fingerprint_sha256");
  assertHex64(proof.continuity_hash, "continuity_hash");
  if (typeof proof.issued_at !== "string" || ! /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(proof.issued_at)) {
    throw new TypeError("PROOF_SIGNATURE_ISSUED_AT_INVALID");
  }
  if (typeof proof.signer_key_id !== "string" || !proof.signer_key_id.length) {
    throw new TypeError("PROOF_SIGNATURE_SIGNER_KEY_ID_INVALID");
  }
  return jcsCanonicalize({ ...proof });
}

function fingerprintPublicKeyDer(publicKeyDer) {
  return crypto.createHash("sha256").update(publicKeyDer).digest("hex").toLowerCase();
}

export function createSigningIdentity({ keyId = null } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeySpkiBase64 = publicKeyDer.toString("base64");
  const publicKeyFingerprintSha256 = fingerprintPublicKeyDer(publicKeyDer);
  return Object.freeze({
    keyId: keyId ?? publicKeyFingerprintSha256,
    privateKey,
    publicKey,
    publicKeySpkiBase64,
    publicKeyFingerprintSha256
  });
}

export function signProof(identity, proof) {
  if (!identity?.privateKey) throw new Error("SIGNING_PRIVATE_KEY_REQUIRED");
  const payload = signedPayload(proof);
  const signatureBase64 = crypto.sign(null, Buffer.from(payload, "utf8"), identity.privateKey).toString("base64");
  return Object.freeze({
    ...proof,
    schema: SCHEMA_ID,
    signer_public_key_fingerprint_sha256: identity.publicKeyFingerprintSha256,
    signer_public_key_spki_base64: identity.publicKeySpkiBase64,
    signature_base64: signatureBase64
  });
}

export function verifyProofSignature(certificate) {
  if (!certificate || certificate.schema !== SCHEMA_ID) return { verified: false, reason: "CERTIFICATE_INVALID" };
  try {
    const { signature_base64, signer_public_key_fingerprint_sha256, signer_public_key_spki_base64, ...proof } = certificate;
    const payload = signedPayload(proof);
    if (typeof certificate.signer_public_key_spki_base64 !== "string" || !certificate.signer_public_key_spki_base64.length) {
      return { verified: false, reason: "SIGNER_PUBLIC_KEY_MISSING" };
    }
    if (typeof certificate.signer_public_key_fingerprint_sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(certificate.signer_public_key_fingerprint_sha256)) {
      return { verified: false, reason: "SIGNER_KEY_FINGERPRINT_INVALID" };
    }
    if (typeof certificate.signature_base64 !== "string" || !certificate.signature_base64.length) {
      return { verified: false, reason: "SIGNATURE_MISSING" };
    }
    const publicKeyDer = Buffer.from(certificate.signer_public_key_spki_base64, "base64");
    const actualFingerprint = fingerprintPublicKeyDer(publicKeyDer);
    if (actualFingerprint !== certificate.signer_public_key_fingerprint_sha256.toLowerCase()) {
      return { verified: false, reason: "SIGNER_KEY_FINGERPRINT_MISMATCH" };
    }
    const publicKey = crypto.createPublicKey({ key: publicKeyDer, type: "spki", format: "der" });
    const verified = crypto.verify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(certificate.signature_base64, "base64"));
    return verified ? { verified: true, reason: "PROOF_SIGNATURE_VALID", signer_public_key_fingerprint_sha256: actualFingerprint } : { verified: false, reason: "SIGNATURE_INVALID" };
  } catch {
    return { verified: false, reason: "SIGNATURE_INVALID" };
  }
}


