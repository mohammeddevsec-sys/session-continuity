import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import { verifyEvidenceProof } from "../src/evidence/offline-verifier.js";

const project = process.cwd();
const pipelineTest = path.join(project,"test","durable-final-proof-pipeline.js");
execFileSync(process.execPath,[pipelineTest],{stdio:"inherit"});

const source = path.join(project,"test","fixtures","final-proof","proof");
const root = fs.mkdtempSync(path.join(os.tmpdir(),"sce-adversarial-"));

function copyCase(name){
  const dir = path.join(root,name);
  fs.cpSync(source,dir,{recursive:true});
  return dir;
}

function expectReject(name,mutate){
  const dir = copyCase(name);
  mutate(dir);
  let rejected = false;
  try {
    verifyEvidenceProof(path.join(dir,"bundle"),path.join(dir,"lineage"));
  } catch (error) {
    rejected = true;
    console.log(name + "_REJECTED=PASS|" + error.message);
  }
  if (!rejected) throw new Error(name + "_TAMPER_ACCEPTED");
}

const baseline = verifyEvidenceProof(path.join(source,"bundle"),path.join(source,"lineage"));
if (!baseline.verified) throw new Error("BASELINE_PROOF_FAILED");
console.log("BASELINE_PROOF=PASS");

expectReject("EVIDENCE_FILE_TAMPER",dir => {
  fs.appendFileSync(path.join(dir,"bundle","evidence.json"),"X");
});

expectReject("DECISION_FILE_TAMPER",dir => {
  const file = path.join(dir,"bundle","decision.json");
  const value = JSON.parse(fs.readFileSync(file,"utf8"));
  value.decision = "REVOKE";
  fs.writeFileSync(file,JSON.stringify(value) + "\\n");
});

expectReject("BUNDLE_ROOT_TAMPER",dir => {
  const file = path.join(dir,"bundle","BUNDLE_ROOT_SHA256.txt");
  const value = fs.readFileSync(file,"utf8").trim();
  fs.writeFileSync(file,(value[0] === "0" ? "1" : "0") + value.slice(1) + "\\n");
});

expectReject("CHECKSUMS_TAMPER",dir => {
  const file = path.join(dir,"bundle","SHA256SUMS.txt");
  const value = fs.readFileSync(file,"utf8");
  fs.writeFileSync(file,"x" + value.slice(1));
});

expectReject("LINEAGE_ENTRY_TAMPER",dir => {
  const file = path.join(dir,"lineage","LINEAGE.ndjson");
  const lines = fs.readFileSync(file,"utf8").split(/\r?\n/).filter(Boolean);
  const record = JSON.parse(lines[0]);
  record.entry.decision = "REVOKE";
  lines[0] = JSON.stringify(record);
  fs.writeFileSync(file,lines.join("\n") + "\n");
});

expectReject("LINEAGE_HEAD_TAMPER",dir => {
  const file = path.join(dir,"lineage","HEAD.json");
  const value = JSON.parse(fs.readFileSync(file,"utf8"));
  value.lineage_root_sha256 = "f".repeat(64);
  fs.writeFileSync(file,JSON.stringify(value) + "\n");
});

console.log("ADVERSARIAL_EVIDENCE_SUITE=PASS");
fs.rmSync(root,{recursive:true,force:true});