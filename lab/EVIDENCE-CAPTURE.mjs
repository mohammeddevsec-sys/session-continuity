import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const LAB = path.join(ROOT, "lab");

function sha256File(p){ return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex").toUpperCase(); }

const PROBES = [
  "PROOF.mjs",
  "_full-audit.mjs",
  "v1_1-regression-gate.mjs",
  "v1_1-integration-probe.mjs",
  "v1_1-chain-probe.mjs",
  "v1_1-scale-chain-probe.mjs",
  "v1_1-trusted-chain-probe.mjs",
  "v1_1-sequence-guard-probe.mjs",
  "v1_1-durable-sequence-probe.mjs",
  "v1_1-witness-probe-v2.mjs",
  "v1_1-witness-fail-closed-probe.mjs",
  "v1_1-portable-package-probe-v2.mjs",
  "v1_1-full-integration-probe.mjs",
  "v1_1-key-lifecycle-probe.mjs",
  "v1_1-lifecycle-integration-probe.mjs",
  "v1_1-oidc-adapter-probe.mjs",
  "v1_1-witness-atomic-receipt-probe.mjs",
  "v1_1-witness-crash-boundary-probe.mjs",
  "continuity-proof-v1_1-p0-critical-gaps.mjs",
  "continuity-proof-v1_1-reconciled-integration.mjs"
];

const results = [];
for (const probe of PROBES) {
  const full = path.join(LAB, probe);
  if (!fs.existsSync(full)) {
    results.push({ probe, sha256: "MISSING", checks: [] });
    continue;
  }
  const sha = sha256File(full);
  let out = "";
  try {
    out = execFileSync(process.execPath, [full], { cwd: ROOT, encoding: "utf8", timeout: 600000, maxBuffer: 50*1024*1024 });
  } catch (e) {
    out = String(e.stdout || "") + String(e.stderr || "");
  }
  const lines = out.split(/\r?\n/);
  const checks = [];
  for (const line of lines) {
    let m = line.match(/^([A-Z][A-Z0-9_]+)=(PASS|FAIL)(?:\|(.*))?$/);
    if (m) { checks.push({ name: m[1], result: m[2], reason: m[3] || "" }); continue; }
    m = line.match(/^PROBE=(.+?)\|(PASS|FAIL)$/);
    if (m) { checks.push({ name: "PROBE::" + m[1], result: m[2], reason: "" }); continue; }
  }
  results.push({ probe, sha256: sha, checks });
}

const total = results.reduce((a,r)=>a+r.checks.length, 0);
const passCount = results.reduce((a,r)=>a+r.checks.filter(c=>c.result==="PASS").length, 0);
const failCount = total - passCount;

const out = [];
out.push("# Evidence Audit - Named Checks");
out.push("");
out.push("Generated from executing each probe listed below. The probe SHA-256 is recorded so that any third party can verify that the probe file has not changed between the run and the audit.");
out.push("");
out.push("Total checks: " + total);
out.push("Pass: " + passCount);
out.push("Fail: " + failCount);
out.push("");
out.push("| # | Probe | Probe SHA-256 (16) | Check | Result | Reason |");
out.push("|---|-------|--------------------|-------|--------|--------|");
let n = 0;
for (const r of results) {
  for (const c of r.checks) {
    n++;
    const sha = r.sha256 === "MISSING" ? "MISSING" : r.sha256.slice(0, 16);
    out.push("| " + n + " | `" + r.probe + "` | `" + sha + "` | `" + c.name + "` | " + c.result + " | " + c.reason + " |");
  }
}
out.push("");
out.push("---");
out.push("");
out.push("## Per-Probe Summary");
out.push("");
out.push("| Probe | SHA-256 | Checks | PASS | FAIL |");
out.push("|-------|---------|--------|------|------|");
for (const r of results) {
  const p = r.checks.filter(c=>c.result==="PASS").length;
  const fl = r.checks.filter(c=>c.result==="FAIL").length;
  out.push("| `" + r.probe + "` | `" + r.sha256 + "` | " + r.checks.length + " | " + p + " | " + fl + " |");
}

const outFile = path.join(LAB, "EVIDENCE-AUDIT.md");
fs.writeFileSync(outFile, out.join("\n") + "\n", "utf8");

console.log("EVIDENCE_PROBES_RUN=" + results.length);
console.log("EVIDENCE_TOTAL_CHECKS=" + total);
console.log("EVIDENCE_PASS=" + passCount);
console.log("EVIDENCE_FAIL=" + failCount);
console.log("EVIDENCE_OUTPUT=" + outFile);
console.log("EVIDENCE_OUTPUT_SHA256=" + sha256File(outFile));
console.log("EVIDENCE_CAPTURE_DONE=1");