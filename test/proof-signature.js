import {
  createSigningIdentity,
  signProof,
  verifyProofSignature
} from "../src/evidence/proof-signature.js";

const identity = createSigningIdentity();

const proof = {
  bundle_root_sha256: "1".repeat(64),
  lineage_root_sha256: "2".repeat(64),
  merkle_root_sha256: "3".repeat(64),
  evidence_fingerprint_sha256: "4".repeat(64)
};

const certificate = signProof(identity, proof);
const valid = verifyProofSignature(certificate);

if (!valid.verified) {
  throw new Error("VALID_PROOF_SIGNATURE_REJECTED");
}

const alteredBundle = verifyProofSignature({
  ...certificate,
  bundle_root_sha256: "f".repeat(64)
});

if (alteredBundle.verified) {
  throw new Error("ALTERED_BUNDLE_ACCEPTED");
}

if (alteredBundle.reason !== "SIGNATURE_INVALID") {
  throw new Error("ALTERED_BUNDLE_REASON_INVALID");
}

const alteredEvidence = verifyProofSignature({
  ...certificate,
  evidence_fingerprint_sha256: "e".repeat(64)
});

if (alteredEvidence.verified) {
  throw new Error("ALTERED_EVIDENCE_ACCEPTED");
}

const alteredKey = createSigningIdentity();

const forged = signProof(alteredKey, proof);

const forgedAgainstOriginal = verifyProofSignature({
  ...forged,
  signer_public_key_spki_base64: certificate.signer_public_key_spki_base64,
  signer_public_key_fingerprint_sha256:
    certificate.signer_public_key_fingerprint_sha256
});

if (forgedAgainstOriginal.verified) {
  throw new Error("FORGED_SIGNER_ACCEPTED");
}

const tamperedSignature = verifyProofSignature({
  ...certificate,
  signature_base64:
    certificate.signature_base64.slice(0, -2) + "AA"
});

if (tamperedSignature.verified) {
  throw new Error("TAMPERED_SIGNATURE_ACCEPTED");
}

console.log("PROOF_SIGNATURE_VALID=PASS");
console.log("ALTERED_BUNDLE_REJECTED=PASS");
console.log("ALTERED_EVIDENCE_REJECTED=PASS");
console.log("FORGED_SIGNER_REJECTED=PASS");
console.log("TAMPERED_SIGNATURE_REJECTED=PASS");
console.log("PROOF_AUTHENTICITY=PASS");
console.log(
  "SIGNER_FINGERPRINT=" +
    certificate.signer_public_key_fingerprint_sha256
);
