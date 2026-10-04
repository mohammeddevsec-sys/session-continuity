import fs from "fs";
import { appendEvidenceLineage, verifyEvidenceLineage } from "../src/evidence/evidence-lineage.js";

const dir = "E:\\SESSION-CONTINUITY\\test\\fixtures\\lineage";
fs.rmSync(dir,{recursive:true,force:true});

const one = appendEvidenceLineage(dir,{
  session_id:"sess-001",
  decision:"CONTINUOUS",
  reason:"ANCHOR_MATCH",
  sequence:1,
  evidence_fingerprint_sha256:"a".repeat(64),
  timestamp:"2026-09-13T09:10:00Z"
});

const two = appendEvidenceLineage(dir,{
  session_id:"sess-001",
  decision:"REAUTH_REQUIRED",
  reason:"REPLAY_DETECTED",
  sequence:1,
  evidence_fingerprint_sha256:"b".repeat(64),
  timestamp:"2026-09-13T09:11:00Z"
});

const verified = verifyEvidenceLineage(dir);

if (!verified.verified) throw new Error("LINEAGE_VERIFY_FAILED");
if (verified.height !== 2) throw new Error("LINEAGE_HEIGHT_INVALID");
if (verified.lineage_root_sha256 !== two.lineage_root_sha256) throw new Error("LINEAR_ROOT_INVALID");
if (verified.merkle_root_sha256 !== two.merkle_root_sha256) throw new Error("MERKLE_ROOT_INVALID");

const logPath = dir + "\\LINEAGE.ndjson";
const original = fs.readFileSync(logPath,"utf8");
fs.writeFileSync(logPath,original.replace("REPLAY_DETECTED","ALTERED_REASON"),"utf8");

let tamperDetected = false;
try { verifyEvidenceLineage(dir); } catch { tamperDetected = true; }

if (!tamperDetected) throw new Error("LINEAGE_TAMPER_NOT_DETECTED");

console.log("LINEAGE_VERIFY=PASS");
console.log("LINEAGE_TAMPER_DETECTION=PASS");
console.log("LINEAGE_HEIGHT="+verified.height);
console.log("LINEAR_ROOT="+two.lineage_root_sha256);
console.log("MERKLE_ROOT="+two.merkle_root_sha256);
