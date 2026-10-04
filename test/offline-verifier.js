import fs from "fs";
import path from "path";
import { writeEvidenceBundle } from "../src/evidence/evidence-bundle.js";
import { appendEvidenceLineage } from "../src/evidence/evidence-lineage.js";
import { verifyEvidenceProof } from "../src/evidence/offline-verifier.js";

const root = "E:\\SESSION-CONTINUITY\\test\\fixtures\\offline-proof";
const bundle = path.join(root, "bundle");
const lineage = path.join(root, "lineage");

fs.rmSync(root, { recursive: true, force: true });

const created = writeEvidenceBundle(bundle, {
  "decision.json": {
    schema_id: "session-continuity.decision.v1",
    decision: "CONTINUOUS",
    reason: "ANCHOR_MATCH",
    sequence: 1
  },
  "evidence.json": {
    session_id: "sess-001",
    decision: "CONTINUOUS",
    reason: "ANCHOR_MATCH"
  }
});

const entry = appendEvidenceLineage(lineage, {
  session_id: "sess-001",
  decision: "CONTINUOUS",
  reason: "ANCHOR_MATCH",
  sequence: 1,
  evidence_fingerprint_sha256: "c".repeat(64),
  bundle_root_sha256: created.bundle_root_sha256,
  timestamp: "2026-09-13T09:10:00Z"
});

const proof = verifyEvidenceProof(bundle, lineage);

if (!proof.verified) {
  throw new Error("OFFLINE_VERIFY_FAILED");
}

if (proof.bundle_root_sha256 !== created.bundle_root_sha256) {
  throw new Error("BUNDLE_ROOT_VERIFY_FAILED");
}

if (proof.lineage_root_sha256 !== entry.lineage_root_sha256) {
  throw new Error("LINEAGE_ROOT_VERIFY_FAILED");
}

if (proof.merkle_root_sha256 !== entry.merkle_root_sha256) {
  throw new Error("MERKLE_ROOT_VERIFY_FAILED");
}

if (proof.lineage_height !== 1) {
  throw new Error("LINEAGE_HEIGHT_VERIFY_FAILED");
}

const decisionPath = path.join(bundle, "decision.json");
const originalDecision = fs.readFileSync(decisionPath, "utf8");

fs.writeFileSync(
  decisionPath,
  originalDecision.replace("CONTINUOUS", "REVOKE"),
  "utf8"
);

let tamperDetected = false;

try {
  verifyEvidenceProof(bundle, lineage);
} catch {
  tamperDetected = true;
}

if (!tamperDetected) {
  throw new Error("OFFLINE_TAMPER_NOT_DETECTED");
}

fs.writeFileSync(decisionPath, originalDecision, "utf8");

console.log("OFFLINE_VERIFIER=PASS");
console.log("OFFLINE_TAMPER_DETECTION=PASS");
console.log("BUNDLE_ROOT=" + created.bundle_root_sha256);
console.log("LINEAGE_ROOT=" + entry.lineage_root_sha256);
console.log("MERKLE_ROOT=" + entry.merkle_root_sha256);
