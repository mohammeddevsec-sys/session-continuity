import fs from "fs";
import path from "path";
import { writeEvidenceBundle } from "../src/evidence/evidence-bundle.js";
import { appendEvidenceLineage } from "../src/evidence/evidence-lineage.js";
import { verifyEvidenceProof } from "../src/evidence/offline-verifier.js";

const root = "E:\\SESSION-CONTINUITY\\test\\fixtures\\cross-binding-strict";
const bundle = path.join(root,"bundle");
const lineage = path.join(root,"lineage");

fs.rmSync(root,{recursive:true,force:true});

const created = writeEvidenceBundle(bundle,{
  "decision.json":{
    schema_id:"session-continuity.decision.v1",
    decision:"CONTINUOUS",
    reason:"ANCHOR_MATCH",
    sequence:1
  },
  "evidence.json":{
    session_id:"sess-001",
    decision:"CONTINUOUS",
    reason:"ANCHOR_MATCH"
  }
});

const good = appendEvidenceLineage(lineage,{
  session_id:"sess-001",
  decision:"CONTINUOUS",
  reason:"ANCHOR_MATCH",
  sequence:1,
  evidence_fingerprint_sha256:"c".repeat(64),
  bundle_root_sha256:created.bundle_root_sha256,
  timestamp:"2026-09-13T09:10:00Z"
});

const proof = verifyEvidenceProof(bundle,lineage);

if (!proof.verified) throw new Error("STRICT_CROSS_BINDING_VALID_FAILED");
if (proof.bundle_root_sha256 !== created.bundle_root_sha256) throw new Error("STRICT_BUNDLE_ROOT_FAILED");

const bad = appendEvidenceLineage(lineage,{
  session_id:"sess-001",
  decision:"REAUTH_REQUIRED",
  reason:"REPLAY_DETECTED",
  sequence:1,
  evidence_fingerprint_sha256:"d".repeat(64),
  bundle_root_sha256:"f".repeat(64),
  timestamp:"2026-09-13T09:11:00Z"
});

let mismatchDetected = false;
try {
  verifyEvidenceProof(bundle,lineage);
} catch (e) {
  mismatchDetected = String(e.message).startsWith("LINEAGE_BUNDLE_ROOT_MISMATCH");
}

if (!mismatchDetected) throw new Error("STRICT_CROSS_BINDING_NOT_ENFORCED");

console.log("STRICT_CROSS_BINDING=PASS");
console.log("WRONG_BUNDLE_ROOT_DETECTION=PASS");
console.log("BUNDLE_ROOT="+created.bundle_root_sha256);
console.log("VALID_LINEAGE_ROOT="+good.lineage_root_sha256);
console.log("INVALID_APPEND_ROOT="+bad.lineage_root_sha256);
