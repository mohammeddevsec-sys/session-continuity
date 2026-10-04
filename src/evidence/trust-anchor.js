import crypto from "crypto";

const HEX64 = /^[0-9a-f]{64}$/i;

function fingerprintPublicKey(publicKeySpkiBase64) {
  if (typeof publicKeySpkiBase64 !== "string" || !publicKeySpkiBase64.length) {
    throw new Error("TRUST_PUBLIC_KEY_INVALID");
  }

  const der = Buffer.from(publicKeySpkiBase64, "base64");

  return crypto
    .createHash("sha256")
    .update(der)
    .digest("hex")
    .toLowerCase();
}

function requireFingerprint(value, field) {
  if (typeof value !== "string" || !HEX64.test(value)) {
    throw new Error(`${field}_INVALID`);
  }
}

export function createTrustAnchorStore() {
  return {
    version: 1,
    active: null,
    accepted: new Map(),
    revoked: new Set()
  };
}

export function registerTrustAnchor(store, publicKeySpkiBase64, metadata = {}) {
  if (!store || store.version !== 1) {
    throw new Error("TRUST_STORE_INVALID");
  }

  const fingerprint = fingerprintPublicKey(publicKeySpkiBase64);

  if (store.revoked.has(fingerprint)) {
    throw new Error("TRUST_KEY_REVOKED");
  }

  const record = Object.freeze({
    fingerprint,
    public_key_spki_base64: publicKeySpkiBase64,
    status: "TRUSTED",
    version: Number(metadata.version ?? 1),
    created_at: String(metadata.created_at ?? ""),
    label: metadata.label == null ? null : String(metadata.label)
  });

  store.accepted.set(fingerprint, record);

  if (store.active === null) {
    store.active = fingerprint;
  }

  return record;
}

export function rotateTrustAnchor(store, publicKeySpkiBase64, metadata = {}) {
  if (!store || store.version !== 1) {
    throw new Error("TRUST_STORE_INVALID");
  }

  const next = registerTrustAnchor(store, publicKeySpkiBase64, {
    ...metadata,
    version: Number(metadata.version ?? 1)
  });

  const previous = store.active;
  store.active = next.fingerprint;

  return Object.freeze({
    previous_fingerprint: previous,
    active_fingerprint: next.fingerprint
  });
}

export function revokeTrustAnchor(store, fingerprint) {
  requireFingerprint(fingerprint, "TRUST_FINGERPRINT");

  if (!store.accepted.has(fingerprint)) {
    throw new Error("TRUST_KEY_NOT_FOUND");
  }

  store.revoked.add(fingerprint);
  store.accepted.delete(fingerprint);

  if (store.active === fingerprint) {
    store.active = null;
  }

  return Object.freeze({
    revoked_fingerprint: fingerprint,
    active_fingerprint: store.active
  });
}

export function verifyTrustedSigner(store, fingerprint) {
  if (!store || store.version !== 1) {
    return {
      trusted: false,
      reason: "TRUST_STORE_INVALID"
    };
  }

  if (!HEX64.test(String(fingerprint || ""))) {
    return {
      trusted: false,
      reason: "SIGNER_FINGERPRINT_INVALID"
    };
  }

  const normalized = fingerprint.toLowerCase();

  if (store.revoked.has(normalized)) {
    return {
      trusted: false,
      reason: "SIGNER_REVOKED"
    };
  }

  const record = store.accepted.get(normalized);

  if (!record) {
    return {
      trusted: false,
      reason: "SIGNER_NOT_TRUSTED"
    };
  }

  return {
    trusted: true,
    reason: "SIGNER_TRUSTED",
    record
  };
}
