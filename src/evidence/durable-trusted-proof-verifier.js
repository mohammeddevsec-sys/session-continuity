import { verifyProofSignature } from "./proof-signature.js";
import { verifyDurableTrust } from "./durable-trust-store.js";

export function verifyDurableTrustedProof(certificate, durableTrustStore) {
  const signature = verifyProofSignature(certificate);

  if (!signature.verified) {
    return {
      verified: false,
      reason: signature.reason
    };
  }

  const trust = verifyDurableTrust(
    durableTrustStore,
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
    reason: "DURABLE_TRUSTED_PROOF_VALID",
    signer_public_key_fingerprint_sha256:
      signature.signer_public_key_fingerprint_sha256,
    trust_record: trust.record
  };
}
