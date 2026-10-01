import { verifyProofSignature } from "./proof-signature.js";
import { verifyTrustedSigner } from "./trust-anchor.js";

export function verifyTrustedProof(certificate, trustStore) {
  const signature = verifyProofSignature(certificate);

  if (!signature.verified) {
    return {
      verified: false,
      reason: signature.reason
    };
  }

  const trust = verifyTrustedSigner(
    trustStore,
    signature.signer_public_key_fingerprint_sha256
  );

  if (!trust.trusted) {
    return {
      verified: false,
      reason: trust.reason
    };
  }

  return {
    verified: true,
    reason: "TRUSTED_PROOF_SIGNATURE_VALID",
    signer_public_key_fingerprint_sha256:
      signature.signer_public_key_fingerprint_sha256,
    trust_record: trust.record
  };
}
