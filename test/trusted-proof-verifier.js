import crypto from "crypto";
import {
  createSigningIdentity,
  signProof
} from "../src/evidence/proof-signature.js";
import {
  createTrustAnchorStore,
  registerTrustAnchor,
  revokeTrustAnchor
} from "../src/evidence/trust-anchor.js";
import {
  verifyTrustedProof
} from "../src/evidence/trusted-proof-verifier.js";

const trustedIdentity = createSigningIdentity();
const attackerIdentity = createSigningIdentity();

const trustedStore = createTrustAnchorStore();

registerTrustAnchor(
  trustedStore,
  trustedIdentity.publicKeySpkiBase64,
  {
    version: 1,
    created_at: "2026-09-13T11:00:00Z",
    label: "trusted-proof-signer"
  }
);

const proof = {
  bundle_root_sha256: "1".repeat(64),
  lineage_root_sha256: "2".repeat(64),
  merkle_root_sha256: "3".repeat(64),
  evidence_fingerprint_sha256: "4".repeat(64)
};

const trustedCertificate = signProof(trustedIdentity, proof);
const trustedResult = verifyTrustedProof(
  trustedCertificate,
  trustedStore
);

if (!trustedResult.verified) {
  throw new Error("TRUSTED_CERTIFICATE_REJECTED");
}

const attackerCertificate = signProof(attackerIdentity, proof);
const attackerResult = verifyTrustedProof(
  attackerCertificate,
  trustedStore
);

if (attackerResult.verified) {
  throw new Error("UNTRUSTED_SIGNER_ACCEPTED");
}

if (attackerResult.reason !== "SIGNER_NOT_TRUSTED") {
  throw new Error("UNTRUSTED_SIGNER_REASON_INVALID");
}

const trustedFingerprint =
  trustedCertificate.signer_public_key_fingerprint_sha256;

revokeTrustAnchor(
  trustedStore,
  trustedFingerprint
);

const revokedResult = verifyTrustedProof(
  trustedCertificate,
  trustedStore
);

if (revokedResult.verified) {
  throw new Error("REVOKED_SIGNER_ACCEPTED");
}

if (revokedResult.reason !== "SIGNER_REVOKED") {
  throw new Error("REVOKED_SIGNER_REASON_INVALID");
}

const fakeStore = createTrustAnchorStore();

const forgedStoreResult = verifyTrustedProof(
  trustedCertificate,
  fakeStore
);

if (forgedStoreResult.verified) {
  throw new Error("TRUST_WITHOUT_ANCHOR_ACCEPTED");
}

if (forgedStoreResult.reason !== "SIGNER_NOT_TRUSTED") {
  throw new Error("MISSING_TRUST_ANCHOR_REASON_INVALID");
}

console.log("TRUSTED_PROOF_ACCEPTED=PASS");
console.log("UNTRUSTED_SIGNER_REJECTED=PASS");
console.log("REVOKED_SIGNER_REJECTED=PASS");
console.log("MISSING_TRUST_ANCHOR_REJECTED=PASS");
console.log("TRUSTED_PROOF_VERIFIER=PASS");
