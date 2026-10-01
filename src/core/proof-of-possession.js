import crypto from "crypto";
import { canonicalStringify } from "./canonical.js";

export function createBindingKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  const publicKeyDer = publicKey.export({
    type: "spki",
    format: "der"
  });

  return Object.freeze({
    publicKey,
    privateKey,
    publicKeySpkiBase64: publicKeyDer.toString("base64"),
    publicKeyFingerprint: crypto
      .createHash("sha256")
      .update(publicKeyDer)
      .digest("hex")
      .toLowerCase()
  });
}

function signingPayload(data) {
  return canonicalStringify(data);
}

export function createSignedPresentation(bindingKey, data) {
  if (!bindingKey || !bindingKey.privateKey) {
    throw new Error("BINDING_PRIVATE_KEY_REQUIRED");
  }

  const payload = {
    session_id: String(data.session_id),
    subject: String(data.subject),
    issuer: String(data.issuer),
    client_id: data.client_id == null ? null : String(data.client_id),
    device_id: data.device_id == null ? null : String(data.device_id),
    sequence: Number(data.sequence),
    challenge: String(data.challenge),
    timestamp: String(data.timestamp)
  };

  const bytes = Buffer.from(signingPayload(payload), "utf8");
  const signature = crypto.sign(null, bytes, bindingKey.privateKey).toString("base64");

  return Object.freeze({
    payload: Object.freeze(payload),
    public_key_spki_base64: bindingKey.publicKeySpkiBase64,
    public_key_fingerprint_sha256: bindingKey.publicKeyFingerprint,
    signature_base64: signature
  });
}

export function verifySignedPresentation(anchor, presentation) {
  if (!anchor || !presentation || !presentation.payload) {
    return { verified: false, reason: "INVALID_PRESENTATION" };
  }

  if (
    typeof anchor.publicKeySpkiBase64 !== "string" ||
    !anchor.publicKeySpkiBase64.length
  ) {
    return { verified: false, reason: "ANCHOR_PUBLIC_KEY_MISSING" };
  }

  if (
    presentation.public_key_spki_base64 !== anchor.publicKeySpkiBase64
  ) {
    return { verified: false, reason: "BINDING_KEY_MISMATCH" };
  }

  const publicKeyDer = Buffer.from(anchor.publicKeySpkiBase64, "base64");
  const publicKey = crypto.createPublicKey({
    key: publicKeyDer,
    type: "spki",
    format: "der"
  });

  const bytes = Buffer.from(signingPayload(presentation.payload), "utf8");
  const signature = Buffer.from(String(presentation.signature_base64 || ""), "base64");

  const verified = crypto.verify(null, bytes, publicKey, signature);

  if (!verified) {
    return { verified: false, reason: "PRESENTATION_SIGNATURE_INVALID" };
  }

  const required = [
    "session_id",
    "subject",
    "issuer",
    "sequence",
    "challenge",
    "timestamp"
  ];

  for (const field of required) {
    if (presentation.payload[field] === undefined) {
      return { verified: false, reason: `PRESENTATION_FIELD_MISSING:${field}` };
    }
  }

  if (presentation.payload.session_id !== anchor.sessionId) {
    return { verified: false, reason: "SESSION_ID_MISMATCH" };
  }

  if (presentation.payload.subject !== anchor.subject) {
    return { verified: false, reason: "SUBJECT_MISMATCH" };
  }

  if (presentation.payload.issuer !== anchor.issuer) {
    return { verified: false, reason: "ISSUER_MISMATCH" };
  }

  return { verified: true, reason: "PROOF_OF_POSSESSION_VALID" };
}
