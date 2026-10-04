import fs from "fs";
import path from "path";
import crypto from "crypto";
import { canonicalStringify } from "../src/core/canonical.js";
import { writeEvidenceBundle } from "../src/evidence/evidence-bundle.js";
import { appendEvidenceLineage } from "../src/evidence/evidence-lineage.js";
import { verifyEvidenceProof } from "../src/evidence/offline-verifier.js";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text),"utf8")).digest("hex").toLowerCase();
}

function readBundleRoot(bundleDir) {
  return fs.readFileSync(path.join(bundleDir,"BUNDLE_ROOT_SHA256.txt"),"utf8").trim().toLowerCase();
}

const root = "E:\\SESSION-CONTINUITY\\test\\fixtures\\cross-binding";
const bundle = path.join(root,"bundle");
const lineage = path.join(root,"lineage");

fs.rmSync(root,{recursive:true,force:true});

const bundleData = {
  "decision.json": {
    schema_id:"session-continuity.decision.v1",
    decision:"CONTINUOUS",
    reason:"ANCHOR_MATCH",
    sequence:1
  },
  "evidence.json": {
    session_id:"sess-001",
    decision:"CONTINUOUS",
    reason:"ANCHOR_MATCH"
  }
};

const created = writeEvidenceBundle(bundle,bundleData);
const bundleRoot = created.bundle_root_sha256;

const evidenceFingerprint = sha256Text(
  canonicalStringify(bundleData["evidence.json"])
);

const lineageEntry = appendEvidenceLineage(lineage,{
  session_id:"sess-001",
  decision:"CONTINUOUS",
  reason:"ANCHOR_MATCH",
  sequence:1,
  evidence_fingerprint_sha256:evidenceFingerprint,
  bundle_root_sha256:bundleRoot,
  timestamp:"2026-09-13T09:10:00Z"
});

const lineageLog = path.join(lineage,"LINEAGE.ndjson");
const originalLineage = fs.readFileSync(lineageLog,"utf8");

const record = JSON.parse(originalLineage.trim());
if (record.entry.bundle_root_sha256 !== bundleRoot) {
  throw new Error("BUNDLE_LINEAGE_BINDING_MISSING");
}

const proof = verifyEvidenceProof(bundle,lineage);

if (!proof.verified) throw new Error("CROSS_BOUND_PROOF_FAILED");
if (readBundleRoot(bundle) !== record.entry.bundle_root_sha256) {
  throw new Error("BUNDLE_ROOT_CROSS_BINDING_FAILED");
}

const alteredBundlePath = path.join(bundle,"decision.json");
const originalDecision = fs.readFileSync(alteredBundlePath,"utf8");
fs.writeFileSync(alteredBundlePath,originalDecision.replace("CONTINUOUS","REAUTH_REQUIRED"),"utf8");

let bundleAttackDetected = false;
try { verifyEvidenceProof(bundle,lineage); } catch { bundleAttackDetected = true; }

if (!bundleAttackDetected) throw new Error("BUNDLE_CROSS_BINDING_TAMPER_NOT_DETECTED");

fs.writeFileSync(alteredBundlePath,originalDecision,"utf8");
fs.writeFileSync(lineageLog,originalLineage.replace(bundleRoot, "f".repeat(64)),"utf8");

let lineageAttackDetected = false;
try { verifyEvidenceProof(bundle,lineage); } catch { lineageAttackDetected = true; }

if (!lineageAttackDetected) throw new Error("LINEAGE_CROSS_BINDING_TAMPER_NOT_DETECTED");

console.log("CROSS_BINDING=PASS");
console.log("BUNDLE_TAMPER_DETECTION=PASS");
console.log("LINEAGE_TAMPER_DETECTION=PASS");
console.log("BUNDLE_ROOT="+bundleRoot);
console.log("LINEAGE_ROOT="+lineageEntry.lineage_root_sha256);
console.log("MERKLE_ROOT="+lineageEntry.merkle_root_sha256);

