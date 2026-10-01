import path from "node:path";
import fs from "fs";
import crypto from "crypto";
import { execFileSync } from "child_process";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const LAB = ROOT + "\\lab";

const expectedHashes = {
  "src/core/canonical.js":"8EC372C56A4A40941DDC167CAFFFF576079A391DD54A2ADC73BBC40E0984A8B8",
  "src/evidence/proof-signature.js":"B3D2D393C9594A6FD7A899714FC3B5014C59666694C68C7ED7D2C45730F20795",
  "lab/continuity-proof-vnext/SPEC-DRAFT-V1_1-RECONCILED.md":"D92B8E795A0515DE25C9DE86A9177AE48150E24BE9BF34744F530D0D4BD30F32",
  "lab/continuity-proof-vnext/SPEC-DRAFT-V1_2.md":"CBDF5CB80E5361DD0ED9640D32ABAE28D897F53179BFB2BF0DF93B344BC3C5B3",
  "package.json":"A300614148FFB7E675B08F5079C10018C03F2E25D950FAAD2A3DEE3B8C4BE10C",
  "src/evidence/witness-v1_1.js":"628F6A6084EA8017CCF07106A6114DC6756FEFD0E315DF0F842CB001169EB9FD"
};

const modules = [
  "src/core/canonical-v1_1.js",
  "src/core/continuity-proof-v1_1.js",
  "src/core/sequence-guard-v1_1.js",
  "src/core/durable-sequence-guard-v1_1.js",
  "src/evidence/proof-signature-v1_1.js",
  "src/evidence/key-lifecycle-v1_1.js",
  "src/evidence/witness-v1_1.js",
  "src/evidence/trusted-proof-verifier-v1_1.js",
  "src/evidence/portable-package-v1_1.js"
];

const probes = [
  {file:"PROOF.mjs", tests:[/OVERALL=PASS/,/PROOF_DONE=1/,/V1_RESULT=PASS/,/V1_1_RESULT=PASS/,/V1_1_FAIL=0/], reject:[/OVERALL=FAIL/,/V1_RESULT=FAIL/,/V1_1_RESULT=FAIL/,/V1_1_FAIL=[1-9]/,/\bFAIL\b/]},
  {file:"LATEX-AUDIT.mjs", tests:[/LATEX_AUDIT=PASS/,/ERROR_COUNT=0/]},
  {file:"ALIGNMENT-AUDIT.mjs", tests:[/ALIGNMENT_AUDIT=PASS/,/TOTAL_ISSUES=0/,/SECTION_MISMATCHES=0/]},
  {file:"CLAIM-EVIDENCE-AUDIT.mjs", tests:[/TOTAL_CLAIMS=11/,/CLAIMS_PASS=11/,/CLAIMS_FAIL=0/,/CLAIM_EVIDENCE_AUDIT=PASS/]},
  {file:"v1_1-regression-gate.mjs", tests:[/V1_1_REGRESSION=PASS/,/TOTAL_FAIL=0/]},
  {file:"v1_1-key-lifecycle-probe.mjs", tests:[/KEY_LIFECYCLE_PROBE_DONE=1/]},
  {file:"v1_1-lifecycle-integration-probe.mjs", tests:[/LIFECYCLE_INTEGRATION_PROBE_DONE=1/]},
  {file:"v1_1-witness-probe-v2.mjs", tests:[/WITNESS_PROBE_V2_DONE=1/,/SAME_DOMAIN_EQUIVOCATION=PASS/]},
  {file:"v1_1-witness-fail-closed-probe.mjs", tests:[/WITNESS_FAIL_CLOSED_PROBE_DONE=1/,/HEALTH_CORRUPT_FAIL_CLOSED=PASS/,/OBSERVE_REJECTED_WHEN_CORRUPT=PASS/]},
  {file:"v1_1-portable-package-probe-v2.mjs", tests:[/PORTABLE_PACKAGE_PROBE_V2_DONE=1/,/GOOD_PKG=PASS/,/TAMPERED_PROOF_DEEP_REJECTED=PASS/,/FAKE_PACKAGER_REJECTED=PASS/]},
  {file:"v1_1-full-integration-probe.mjs", tests:[/FULL_INTEGRATION_DONE=1/,/PACKAGE_VALID=PASS/,/WITNESS_RESTART_IDEMPOTENT=PASS/,/SEQ_POST_RESTART_4=PASS/]},
  {file:"non-equivocation-witness-lab/witness-restart-clean.mjs", tests:[/WITNESS_RESTART_RESULT=PASS/,/FORK_BLOCKED=PASS/,/GAP_BLOCKED=PASS/,/ROLLBACK_BLOCKED=PASS/]},
  {file:"continuity-proof-vnext/real-chain-integration.mjs", tests:[/INDEPENDENT_PROOFS=PASS\|PASS\|PASS/,/FULL_CHAIN_VERIFIED=PASS/]},
  {file:"continuity-proof-vnext/source-app-gone-integration.mjs", tests:[/SOURCE_APP_GONE_RESULT=PASS/,/PORTABLE_PACKAGE_ONLY=PASS/]},
  {file:"comparative-gap-lab/comparative-gap-lab.mjs", tests:[/EXPECTATION_CHECK=PASS/,/LAB_RESULT=PASS/]},
  {file:"v1_1-oidc-adapter-probe.mjs", tests:[/OIDC_ANCHOR=PASS/,/OIDC_BOOTSTRAP=PASS/,/OIDC_INVALID_CLAIMS=PASS/,/OIDC_ADAPTER_PROBE_DONE=1/]},
  {file:"v1_1-witness-atomic-receipt-probe.mjs", tests:[/WITNESS_ATOMIC_RECEIPT_PROBE_DONE=1/,/RECEIPT_SAVED_WITH_HEAD=PASS/,/SAVED_RECEIPT_VERIFIES=PASS/,/RESTART_REPLAY_IDEMPOTENT=PASS/,/REPLAY_RECEIPT_IDENTICAL=PASS/,/HEAD_STABLE_AFTER_RESTART=PASS/]},
  {file:"v1_1-witness-crash-boundary-probe.mjs", tests:[/CRASH_BOUNDARY_PROBE_DONE=1/,/AFTER_WRITE=PASS/,/AFTER_FSYNC=PASS/,/AFTER_CLOSE=PASS/,/AFTER_RENAME=PASS/]},
  {file:"continuity-proof-v1_1-p0-critical-gaps.mjs", tests:[/REFERENCE_P0=PASS/,/CHECKPOINT_FINALITY_SCOPE=PASS/,/CHECKPOINT_TAMPER_REJECTED=PASS/]},
  {file:"continuity-proof-v1_1-reconciled-integration.mjs", tests:[/RECONCILED_INTEGRATION=PASS/,/CONTINUITY_COMPLETE_WITH_CLOSED_CHECKPOINT=PASS/,/TRUNCATED_NOT_COMPLETE=PASS/]}
];

let failures = 0;

function hash(path){
  return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex").toUpperCase();
}

function runProbe(probe){
  const path = LAB + "\\" + probe.file;
  if(!fs.existsSync(path)){
    console.log("PROBE="+probe.file+"|UNVERIFIED|MISSING");
    failures++;
    return;
  }
  let stdout = "";
  let stderr = "";
  let exitCode = 0;
  try{
    stdout = execFileSync(process.execPath,[path],{cwd:LAB,encoding:"utf8",stdio:["ignore","pipe","pipe"]});
  }catch(e){
    stdout = String(e.stdout || "");
    stderr = String(e.stderr || "");
    exitCode = Number.isInteger(e.status) ? e.status : 1;
  }
  const forbidden = (probe.reject || []).some(r => r.test(stdout));
  const required = probe.tests.every(r => r.test(stdout));
  const ok = exitCode === 0 && required && !forbidden;
  console.log("PROBE="+probe.file+"|"+(ok ? "PASS" : "FAIL")+"|EXIT="+exitCode);
  if(!ok){
    failures++;
    if(stderr.trim()) console.log("STDERR="+stderr.trim());
    console.log("OUTPUT_BEGIN");
    console.log(stdout.trim());
    console.log("OUTPUT_END");
  }
}

console.log("=== SESSION CONTINUITY :: ENTERPRISE RELEASE GATE ===");
console.log("MODE=READ_ONLY_INTEGRATION_GATE");

for(const [rel,expected] of Object.entries(expectedHashes)){
  const path = ROOT + "\\" + rel.replaceAll("/","\\");
  if(!fs.existsSync(path)){
    console.log("HASH="+rel+"|MISSING");
    failures++;
    continue;
  }
  const actual = hash(path);
  const ok = actual === expected;
  console.log("HASH="+rel+"|"+(ok ? "PASS" : "FAIL"));
  if(!ok) failures++;
}

for(const rel of modules){
  const path = ROOT + "\\" + rel.replaceAll("/","\\");
  const ok = fs.existsSync(path);
  console.log("MODULE="+rel+"|"+(ok ? "PRESENT" : "MISSING"));
  if(!ok) failures++;
}

for(const probe of probes){
  runProbe(probe);
}

const proofPath = LAB + "\\PROOF.mjs";
if (!fs.existsSync(proofPath)) { console.log("DETERMINISM=FAIL|PROOF_MISSING"); failures++; } else {
  let a = ""; let b = ""; let ea = 1; let eb = 1;
  try { a = execFileSync(process.execPath,[proofPath],{cwd:LAB,encoding:"utf8"}); ea = 0; } catch(e) { a = String(e.stdout || ""); ea = Number.isInteger(e.status) ? e.status : 1; }
  try { b = execFileSync(process.execPath,[proofPath],{cwd:LAB,encoding:"utf8"}); eb = 0; } catch(e) { b = String(e.stdout || ""); eb = Number.isInteger(e.status) ? e.status : 1; }
  const ha = crypto.createHash("sha256").update(a,"utf8").digest("hex").toUpperCase();
  const hb = crypto.createHash("sha256").update(b,"utf8").digest("hex").toUpperCase();
  const deterministic = ea === 0 && eb === 0 && ha === hb;
  console.log("DETERMINISM="+(deterministic ? "PASS" : "FAIL")+"|RUN1="+ha+"|RUN2="+hb);
  if (!deterministic) failures++;
}

const releaseDir = ROOT + "\\release";
const releaseExists = fs.existsSync(releaseDir);
console.log("RELEASE_TREE="+(releaseExists ? "PRESENT" : "MISSING"));
if(!releaseExists) failures++;

console.log("FAILURES="+failures);
console.log("ENTERPRISE_RELEASE_GATE="+(failures === 0 ? "PASS" : "FAIL"));
console.log("NOTE=EXTERNAL_SECURITY_REVIEW_IS_NOT_A_LOCAL_GATE");
console.log("GATE_SHA256="+hash(ROOT + "\\lab\\enterprise-release-gate.mjs"));
process.exitCode = failures === 0 ? 0 : 1;
