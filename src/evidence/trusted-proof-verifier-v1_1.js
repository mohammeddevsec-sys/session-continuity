import { verifyProofSignature } from "./proof-signature-v1_1.js";
import { verifyTrustedSigner } from "./trust-anchor.js";
import { verifyProofChain } from "../core/continuity-proof-v1_1.js";
import { getKey, verifyKeyForProof } from "./key-lifecycle-v1_1.js";

function verifySignatureAndTrust(certificate, trustStore) {
  const signature = verifyProofSignature(certificate);
  if (!signature.verified) {
    return { verified: false, reason: signature.reason };
  }
  const trust = verifyTrustedSigner(
    trustStore,
    signature.signer_public_key_fingerprint_sha256
  );
  if (!trust.trusted) {
    return { verified: false, reason: trust.reason };
  }
  return {
    verified: true,
    reason: "TRUSTED_PROOF_SIGNATURE_VALID",
    signer_public_key_fingerprint_sha256: signature.signer_public_key_fingerprint_sha256,
    trust_record: trust.record
  };
}

export function verifyTrustedProofChainV1_1(chain, options) {
  const opts = options || {};
  const trustStore = opts.trustStore;
  const expectedContinuityRoot = opts.expectedContinuityRoot;
  if (!Array.isArray(chain) || chain.length === 0) {
    return { verified: false, reason: "EMPTY_CHAIN" };
  }
  if (!trustStore || trustStore.version !== 1) {
    return { verified: false, reason: "TRUST_STORE_INVALID" };
  }
  for (let i = 0; i < chain.length; i++) {
    const check = verifySignatureAndTrust(chain[i], trustStore);
    if (!check.verified) {
      return {
        verified: false,
        reason: check.reason,
        failedSequence: i + 1
      };
    }
  }
  const chainResult = verifyProofChain(chain, {
    expectedContinuityRoot: expectedContinuityRoot,
    verifySignature: verifyProofSignature
  });
  if (!chainResult.verified) {
    return chainResult;
  }
  return {
    verified: true,
    reason: "TRUSTED_CONTINUITY_PROVEN",
    sequence: chainResult.sequence,
    head_hash: chainResult.head_hash
  };
}
export function verifyTrustedProofChainWithLifecycleV1_1(chain, options) {
  const opts = options || {};
  const keyLifecycleStore = opts.keyLifecycleStore;
  if (!keyLifecycleStore) return { verified: false, reason: "KEY_LIFECYCLE_STORE_REQUIRED" };
  if (!Array.isArray(chain) || chain.length === 0) return { verified: false, reason: "EMPTY_CHAIN" };
  for (let i = 0; i < chain.length; i++) {
    const sig = verifyProofSignature(chain[i]);
    if (!sig.verified) return { verified: false, reason: sig.reason, failedSequence: i + 1 };
    const fp = sig.signer_public_key_fingerprint_sha256;
    const record = getKey(keyLifecycleStore, fp);
    if (!record) return { verified: false, reason: "KEY_NOT_IN_LIFECYCLE_STORE", failedSequence: i + 1 };
    const lc = verifyKeyForProof(keyLifecycleStore, fp, chain[i].issued_at);
    if (!lc.valid) return { verified: false, reason: "KEY_LIFECYCLE_REJECTED:" + lc.reason, failedSequence: i + 1 };
    if (opts.requireActiveNow && record.status !== "ACTIVE") {
      return { verified: false, reason: "KEY_NOT_ACTIVE_NOW", failedSequence: i + 1, status: record.status };
    }
  }
  const trusted = verifyTrustedProofChainV1_1(chain, {
    trustStore: opts.trustStore,
    expectedContinuityRoot: opts.expectedContinuityRoot
  });
  if (!trusted.verified) return trusted;
  return {
    verified: true,
    reason: "TRUSTED_CONTINUITY_PROVEN_WITH_LIFECYCLE",
    sequence: trusted.sequence,
    head_hash: trusted.head_hash
  };
}