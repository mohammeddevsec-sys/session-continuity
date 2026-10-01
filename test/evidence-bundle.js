import fs from "fs";
import path from "path";
import { writeEvidenceBundle, verifyEvidenceBundle } from "../src/evidence/evidence-bundle.js";

const dir = "E:\\SESSION-CONTINUITY\\test\\fixtures\\evidence-bundle";
fs.rmSync(dir,{recursive:true,force:true});

const created = writeEvidenceBundle(dir,{
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
});

const verified = verifyEvidenceBundle(dir);
if (!verified.verified) throw new Error("BUNDLE_VERIFY_FAILED");

const decisionPath = path.join(dir,"decision.json");
const original = fs.readFileSync(decisionPath,"utf8");
fs.writeFileSync(decisionPath,original.replace("CONTINUOUS","REAUTH_REQUIRED"),"utf8");

let tamperDetected = false;
try { verifyEvidenceBundle(dir); } catch { tamperDetected = true; }

if (!tamperDetected) throw new Error("TAMPER_NOT_DETECTED");

fs.writeFileSync(decisionPath,original,"utf8");
const restored = verifyEvidenceBundle(dir);

if (restored.bundle_root_sha256 !== created.bundle_root_sha256) {
  throw new Error("BUNDLE_ROOT_NOT_STABLE");
}

console.log("EVIDENCE_BUNDLE_VERIFY=PASS");
console.log("TAMPER_DETECTION=PASS");
console.log("BUNDLE_ROOT_STABLE=PASS");
console.log("BUNDLE_ROOT="+created.bundle_root_sha256);
