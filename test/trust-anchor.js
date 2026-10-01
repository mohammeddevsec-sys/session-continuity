import crypto from "crypto";
import {
  createTrustAnchorStore,
  registerTrustAnchor,
  rotateTrustAnchor,
  revokeTrustAnchor,
  verifyTrustedSigner
} from "../src/evidence/trust-anchor.js";

function newIdentity() {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");

  const der = publicKey.export({
    type: "spki",
    format: "der"
  });

  return der.toString("base64");
}

const store = createTrustAnchorStore();

const keyA = newIdentity();
const keyB = newIdentity();
const keyC = newIdentity();

const a = registerTrustAnchor(store, keyA, {
  version: 1,
  created_at: "2026-09-13T10:00:00Z",
  label: "primary"
});

const trustedA = verifyTrustedSigner(store, a.fingerprint);

if (!trustedA.trusted || trustedA.reason !== "SIGNER_TRUSTED") {
  throw new Error("TRUSTED_KEY_REJECTED");
}

const unknownB = verifyTrustedSigner(
  store,
  crypto.createHash("sha256")
    .update(Buffer.from(keyB, "base64"))
    .digest("hex")
);

if (unknownB.trusted || unknownB.reason !== "SIGNER_NOT_TRUSTED") {
  throw new Error("UNTRUSTED_KEY_ACCEPTED");
}

const rotation = rotateTrustAnchor(store, keyB, {
  version: 2,
  created_at: "2026-09-13T10:01:00Z",
  label: "rotated"
});

if (rotation.previous_fingerprint !== a.fingerprint) {
  throw new Error("ROTATION_PREVIOUS_INVALID");
}

if (store.active !== rotation.active_fingerprint) {
  throw new Error("ROTATION_ACTIVE_INVALID");
}

const trustedB = verifyTrustedSigner(
  store,
  rotation.active_fingerprint
);

if (!trustedB.trusted) {
  throw new Error("ROTATED_KEY_NOT_TRUSTED");
}

const oldStillTrusted = verifyTrustedSigner(
  store,
  a.fingerprint
);

if (!oldStillTrusted.trusted) {
  throw new Error("OLD_KEY_SHOULD_REMAIN_TRUSTED_DURING_ROLLOVER");
}

revokeTrustAnchor(store, a.fingerprint);

const revokedA = verifyTrustedSigner(
  store,
  a.fingerprint
);

if (revokedA.trusted || revokedA.reason !== "SIGNER_REVOKED") {
  throw new Error("REVOKED_OLD_KEY_ACCEPTED");
}

const cFingerprint = crypto
  .createHash("sha256")
  .update(Buffer.from(keyC, "base64"))
  .digest("hex");

const unknownC = verifyTrustedSigner(
  store,
  cFingerprint
);

if (unknownC.trusted) {
  throw new Error("UNKNOWN_THIRD_KEY_ACCEPTED");
}

console.log("TRUST_ANCHOR_REGISTER=PASS");
console.log("UNTRUSTED_KEY_REJECTED=PASS");
console.log("KEY_ROTATION=PASS");
console.log("OLD_KEY_ROLLOVER_TRUST=PASS");
console.log("REVOKED_OLD_KEY_REJECTED=PASS");
console.log("UNKNOWN_THIRD_KEY_REJECTED=PASS");
console.log("TRUST_ANCHOR_CONTRACT=PASS");
console.log("ACTIVE_KEY="+store.active);
