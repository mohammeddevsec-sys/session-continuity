import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";

function payloadForSignature(proof) {
  return canonicalStringify({
    schema_id: "session-continuity.proof-certificate.v1",
    version: 1,
    bundle_root_sha256: proof.bundle_root_sha256,
    lineage_root_sha256: proof.lineage_root_sha256,
    merkle_root_sha256: proof.merkle_root_sha256,
    evidence_fingerprint_sha256: proof.evidence_fingerprint_sha256
  });
}

export function createSigningIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  const publicKeyDer = publicKey.export({
    type: "spki",
    format: "der"
  });

  const publicKeyBase64 = publicKeyDer.toString("base64");
  const publicKeyFingerprintSha256 = crypto
    .createHash("sha256")
    .update(publicKeyDer)
    .digest("hex")
    .toLowerCase();

  return Object.freeze({
    privateKey,
    publicKey,
    publicKeySpkiBase64: publicKeyBase64,
    publicKeyFingerprintSha256
  });
}

export function signProof(identity, proof) {
  if (!identity?.privateKey) {
    throw new Error("SIGNING_PRIVATE_KEY_REQUIRED");
  }

  const payload = payloadForSignature(proof);
  const signatureBase64 = crypto
    .sign(null, Buffer.from(payload, "utf8"), identity.privateKey)
    .toString("base64");

  return Object.freeze({
    schema_id: "session-continuity.proof-certificate.v1",
    version: 1,
    bundle_root_sha256: proof.bundle_root_sha256,
    lineage_root_sha256: proof.lineage_root_sha256,
    merkle_root_sha256: proof.merkle_root_sha256,
    evidence_fingerprint_sha256: proof.evidence_fingerprint_sha256,
    signer_public_key_fingerprint_sha256: identity.publicKeyFingerprintSha256,
    signer_public_key_spki_base64: identity.publicKeySpkiBase64,
    signature_base64: signatureBase64
  });
}

export function verifyProofSignature(certificate) {
  if (
    !certificate ||
    certificate.schema_id !== "session-continuity.proof-certificate.v1" ||
    certificate.version !== 1
  ) {
    return { verified: false, reason: "CERTIFICATE_INVALID" };
  }

  const requiredHashes = [
    "bundle_root_sha256",
    "lineage_root_sha256",
    "merkle_root_sha256",
    "evidence_fingerprint_sha256",
    "signer_public_key_fingerprint_sha256"
  ];

  for (const field of requiredHashes) {
    if (
      typeof certificate[field] !== "string" ||
      !/^[0-9a-f]{64}$/i.test(certificate[field])
    ) {
      return {
        verified: false,
        reason: `CERTIFICATE_${field.toUpperCase()}_INVALID`
      };
    }
  }

  if (
    typeof certificate.signer_public_key_spki_base64 !== "string" ||
    !certificate.signer_public_key_spki_base64.length
  ) {
    return {
      verified: false,
      reason: "SIGNER_PUBLIC_KEY_MISSING"
    };
  }

  if (
    typeof certificate.signature_base64 !== "string" ||
    !certificate.signature_base64.length
  ) {
    return {
      verified: false,
      reason: "SIGNATURE_MISSING"
    };
  }

  const publicKeyDer = Buffer.from(
    certificate.signer_public_key_spki_base64,
    "base64"
  );

  const actualFingerprint = crypto
    .createHash("sha256")
    .update(publicKeyDer)
    .digest("hex")
    .toLowerCase();

  if (
    actualFingerprint !==
    certificate.signer_public_key_fingerprint_sha256.toLowerCase()
  ) {
    return {
      verified: false,
      reason: "SIGNER_KEY_FINGERPRINT_MISMATCH"
    };
  }

  let publicKey;

  try {
    publicKey = crypto.createPublicKey({
      key: publicKeyDer,
      type: "spki",
      format: "der"
    });
  } catch {
    return {
      verified: false,
      reason: "SIGNER_PUBLIC_KEY_INVALID"
    };
  }

  const proof = {
    bundle_root_sha256: certificate.bundle_root_sha256,
    lineage_root_sha256: certificate.lineage_root_sha256,
    merkle_root_sha256: certificate.merkle_root_sha256,
    evidence_fingerprint_sha256: certificate.evidence_fingerprint_sha256
  };

  const payload = payloadForSignature(proof);

  let verified;

  try {
    verified = crypto.verify(
      null,
      Buffer.from(payload, "utf8"),
      publicKey,
      Buffer.from(certificate.signature_base64, "base64")
    );
  } catch {
    return {
      verified: false,
      reason: "SIGNATURE_INVALID"
    };
  }

  return verified
    ? {
        verified: true,
        reason: "PROOF_SIGNATURE_VALID",
        signer_public_key_fingerprint_sha256:
          actualFingerprint
      }
    : {
        verified: false,
        reason: "SIGNATURE_INVALID"
      };
}
