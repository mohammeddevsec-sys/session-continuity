import crypto from "crypto";
import { jcsCanonicalize } from "../core/canonical-v1_1.js";
import { verifyProofSignature } from "./proof-signature-v1_1.js";
import { verifyProofChain } from "../core/continuity-proof-v1_1.js";
import { verifyWitnessReceipt } from "./witness-v1_1.js";
import { verifyTrustedSigner } from "./trust-anchor.js";

const PACKAGE_SCHEMA_ID = "session-continuity.v1_1.portable.package";
const PACKAGE_VERSION = 1;
const SIG_FIELDS = ["package_signature_base64", "packager_public_key_spki_base64", "packager_public_key_fingerprint_sha256"];

function assertHex64(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new TypeError("PACKAGE_" + field.toUpperCase() + "_INVALID");
  }
}

function assertUtcMillis(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new TypeError("PACKAGE_CREATED_AT_INVALID");
  }
}

function packageSignedPayload(pkg) {
  const body = {};
  const keys = Object.keys(pkg).sort();
  for (const k of keys) {
    if (SIG_FIELDS.indexOf(k) === -1) body[k] = pkg[k];
  }
  return jcsCanonicalize(body);
}

function fingerprintDer(der) {
  return crypto.createHash("sha256").update(der).digest("hex").toLowerCase();
}

export function buildPortablePackage(options) {
  const opts = options || {};
  const continuityRoot = opts.continuityRoot;
  const proofChain = opts.proofChain;
  const witnessReceipts = opts.witnessReceipts;
  const signerTrustFingerprints = opts.signerTrustFingerprints;
  const witnessTrustFingerprints = opts.witnessTrustFingerprints;
  const policyReferences = opts.policyReferences || {};
  const packagerIdentity = opts.packagerIdentity;
  const createdAt = opts.createdAt;

  assertHex64(continuityRoot, "continuity_root");
  assertUtcMillis(createdAt);
  if (!Array.isArray(proofChain) || proofChain.length === 0) throw new TypeError("PACKAGE_PROOF_CHAIN_INVALID");
  if (!Array.isArray(witnessReceipts)) throw new TypeError("PACKAGE_WITNESS_RECEIPTS_INVALID");
  if (!Array.isArray(signerTrustFingerprints)) throw new TypeError("PACKAGE_SIGNER_TRUST_INVALID");
  if (!Array.isArray(witnessTrustFingerprints)) throw new TypeError("PACKAGE_WITNESS_TRUST_INVALID");
  if (!packagerIdentity || !packagerIdentity.privateKey) throw new TypeError("PACKAGE_PACKAGER_IDENTITY_REQUIRED");

  for (const fp of signerTrustFingerprints) assertHex64(fp, "signer_trust_fingerprint");
  for (const fp of witnessTrustFingerprints) assertHex64(fp, "witness_trust_fingerprint");

  const body = {
    schema_id: PACKAGE_SCHEMA_ID,
    version: PACKAGE_VERSION,
    created_at: createdAt,
    continuity_root: continuityRoot,
    proof_chain: proofChain,
    witness_receipts: witnessReceipts,
    signer_trust_fingerprints: signerTrustFingerprints.slice().sort(),
    witness_trust_fingerprints: witnessTrustFingerprints.slice().sort(),
    policy_references: policyReferences
  };

  const payload = jcsCanonicalize(body);
  const sig = crypto.sign(null, Buffer.from(payload, "utf8"), packagerIdentity.privateKey).toString("base64");

  return Object.freeze({
    ...body,
    package_signature_base64: sig,
    packager_public_key_spki_base64: packagerIdentity.publicKeySpkiBase64,
    packager_public_key_fingerprint_sha256: packagerIdentity.publicKeyFingerprintSha256
  });
}

function verifyPackageSignature(pkg, packagerTrustStore) {
  if (typeof pkg.package_signature_base64 !== "string" || !pkg.package_signature_base64.length) {
    return {verified: false, reason: "PACKAGE_SIGNATURE_MISSING"};
  }
  if (typeof pkg.packager_public_key_spki_base64 !== "string" || !pkg.packager_public_key_spki_base64.length) {
    return {verified: false, reason: "PACKAGE_PACKAGER_KEY_MISSING"};
  }
  if (typeof pkg.packager_public_key_fingerprint_sha256 !== "string" || !/^[0-9a-f]{64}$/i.test(pkg.packager_public_key_fingerprint_sha256)) {
    return {verified: false, reason: "PACKAGE_PACKAGER_FINGERPRINT_INVALID"};
  }
  const der = Buffer.from(pkg.packager_public_key_spki_base64, "base64");
  const actual = fingerprintDer(der);
  if (actual !== pkg.packager_public_key_fingerprint_sha256.toLowerCase()) {
    return {verified: false, reason: "PACKAGE_PACKAGER_FINGERPRINT_MISMATCH"};
  }
  let publicKey;
  try { publicKey = crypto.createPublicKey({key: der, type: "spki", format: "der"}); } catch { return {verified: false, reason: "PACKAGE_PACKAGER_KEY_INVALID"}; }
  const payload = Buffer.from(packageSignedPayload(pkg), "utf8");
  let ok = false;
  try { ok = crypto.verify(null, payload, publicKey, Buffer.from(pkg.package_signature_base64, "base64")); } catch { return {verified: false, reason: "PACKAGE_SIGNATURE_INVALID"}; }
  if (!ok) return {verified: false, reason: "PACKAGE_SIGNATURE_INVALID"};
  if (packagerTrustStore) {
    const trust = verifyTrustedSigner(packagerTrustStore, actual);
    if (!trust.trusted) return {verified: false, reason: "PACKAGE_PACKAGER_NOT_TRUSTED", trustReason: trust.reason};
  }
  return {verified: true, reason: "PACKAGE_SIGNATURE_VALID", packager_fingerprint: actual};
}

export function verifyPortablePackage(pkg, options) {
  const opts = options || {};
  const signerTrustStore = opts.signerTrustStore;
  const witnessTrustStore = opts.witnessTrustStore;
  const packagerTrustStore = opts.packagerTrustStore || null;
  const expectedContinuityRoot = opts.expectedContinuityRoot || null;

  if (!pkg || typeof pkg !== "object") return {verified: false, reason: "PACKAGE_MISSING"};
  if (pkg.schema_id !== PACKAGE_SCHEMA_ID) return {verified: false, reason: "PACKAGE_SCHEMA_INVALID"};
  if (pkg.version !== PACKAGE_VERSION) return {verified: false, reason: "PACKAGE_VERSION_INVALID"};

  const pkgSig = verifyPackageSignature(pkg, packagerTrustStore);
  if (!pkgSig.verified) return pkgSig;

  if (expectedContinuityRoot !== null && pkg.continuity_root !== expectedContinuityRoot) {
    return {verified: false, reason: "PACKAGE_ROOT_MISMATCH"};
  }

  const chainResult = verifyProofChain(pkg.proof_chain, {expectedContinuityRoot: pkg.continuity_root, verifySignature: verifyProofSignature});
  if (!chainResult.verified) {
    return {verified: false, reason: "PACKAGE_CHAIN_" + chainResult.reason, failedSequence: chainResult.failedSequence};
  }

  const declaredSignerFps = new Set((pkg.signer_trust_fingerprints || []).map(f => f.toLowerCase()));
  for (let i = 0; i < pkg.proof_chain.length; i++) {
    const sig = verifyProofSignature(pkg.proof_chain[i]);
    if (!sig.verified) return {verified: false, reason: "PACKAGE_PROOF_SIGNATURE_INVALID", failedSequence: i + 1};
    const fp = sig.signer_public_key_fingerprint_sha256;
    if (!declaredSignerFps.has(fp)) return {verified: false, reason: "PACKAGE_PROOF_SIGNER_NOT_DECLARED", failedSequence: i + 1};
    if (signerTrustStore) {
      const t = verifyTrustedSigner(signerTrustStore, fp);
      if (!t.trusted) return {verified: false, reason: "PACKAGE_PROOF_SIGNER_NOT_TRUSTED", failedSequence: i + 1, trustReason: t.reason};
    }
  }

  const declaredWitnessFps = new Set((pkg.witness_trust_fingerprints || []).map(f => f.toLowerCase()));
  const chainBySequence = new Map();
  for (const p of pkg.proof_chain) chainBySequence.set(p.sequence, p);

  for (let i = 0; i < pkg.witness_receipts.length; i++) {
    const receipt = pkg.witness_receipts[i];
    const v = verifyWitnessReceipt(receipt);
    if (!v.verified) return {verified: false, reason: "PACKAGE_WITNESS_RECEIPT_INVALID", failedReceipt: i, receiptReason: v.reason};
    const wfp = v.witness_public_key_fingerprint_sha256;
    if (!declaredWitnessFps.has(wfp)) return {verified: false, reason: "PACKAGE_WITNESS_NOT_DECLARED", failedReceipt: i};
    if (witnessTrustStore) {
      const t = verifyTrustedSigner(witnessTrustStore, wfp);
      if (!t.trusted) return {verified: false, reason: "PACKAGE_WITNESS_NOT_TRUSTED", failedReceipt: i, trustReason: t.reason};
    }
    const body = receipt.body;
    if (!body || typeof body !== "object") return {verified: false, reason: "PACKAGE_RECEIPT_BODY_INVALID", failedReceipt: i};
    if (body.continuity_root !== pkg.continuity_root) return {verified: false, reason: "PACKAGE_RECEIPT_ROOT_MISMATCH", failedReceipt: i};
    const proof = chainBySequence.get(body.sequence);
    if (!proof) return {verified: false, reason: "PACKAGE_RECEIPT_SEQUENCE_MISSING", failedReceipt: i};
    if (proof.continuity_hash !== body.continuity_hash) return {verified: false, reason: "PACKAGE_RECEIPT_HASH_MISMATCH", failedReceipt: i};
  }

  return {
    verified: true,
    reason: "PORTABLE_PACKAGE_VALID",
    chain_length: pkg.proof_chain.length,
    receipts: pkg.witness_receipts.length,
    head_hash: chainResult.head_hash
  };
}