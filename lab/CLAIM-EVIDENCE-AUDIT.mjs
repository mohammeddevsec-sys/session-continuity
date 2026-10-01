import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const PAPER_MD  = path.join(ROOT, "lab", "PAPER.md");
const PAPER_TEX = path.join(ROOT, "lab", "PAPER.tex");
const AUDIT_MD  = path.join(ROOT, "lab", "EVIDENCE-AUDIT.md");

const rows = [];
function check(name, expected, actual, source) {
  const exp = String(expected), act = String(actual);
  rows.push({name, expected: exp, actual: act, verdict: exp === act ? "PASS" : "FAIL", source});
}

const paperMd  = fs.readFileSync(PAPER_MD,  "utf8");
const paperTex = fs.readFileSync(PAPER_TEX, "utf8");
const auditMd  = fs.readFileSync(AUDIT_MD,  "utf8");

// 1. 247 named audit checks
{
  const m = auditMd.match(/^Total checks:\s*(\d+)$/m);
  check("251_named_audit_checks", "251", m ? m[1] : "NOT_FOUND", "EVIDENCE-AUDIT.md");
}

// 2. 19 probes (per-probe summary table)
{
  const lines = auditMd.split(/\r?\n/);
  let inSummary = false, n = 0;
  for (const line of lines) {
    if (line.startsWith("## Per-Probe Summary")) { inSummary = true; continue; }
    if (!inSummary) continue;
    if (/^\| `[^`]+\.mjs` \| `[0-9A-F]{64}` \| \d+ \| \d+ \| \d+ \|$/.test(line.trim())) n++;
  }
  check("20_probes", "20", n, "EVIDENCE-AUDIT.md");
}

// 3. 38 v1 regression tests (run actual test suite)
{
  let actual = "RUN_FAILED";
  try {
    const out = execFileSync(process.execPath, [path.join(ROOT, "test", "run-all-tests.mjs")],
      {cwd: ROOT, encoding: "utf8", timeout: 600000, maxBuffer: 64*1024*1024});
    const m = out.match(/TESTS=(\d+)/);
    actual = m ? m[1] : "NOT_FOUND";
  } catch(e) {
    const out = String(e.stdout || "") + String(e.stderr || "");
    const m = out.match(/TESTS=(\d+)/);
    if (m) actual = m[1];
  }
  check("41_v1_regression_tests", "41", actual, "test/run-all-tests.mjs");
}

// 4. 12 v1.1 probes (run regression gate)
{
  let actual = "RUN_FAILED";
  try {
    const out = execFileSync(process.execPath, [path.join(ROOT, "lab", "v1_1-regression-gate.mjs")],
      {cwd: ROOT, encoding: "utf8", timeout: 600000, maxBuffer: 64*1024*1024});
    const m = out.match(/TOTAL_PASS=(\d+)/);
    actual = m ? m[1] : "NOT_FOUND";
  } catch(e) {
    const out = String(e.stdout || "") + String(e.stderr || "");
    const m = out.match(/TOTAL_PASS=(\d+)/);
    if (m) actual = m[1];
  }
  check("12_v1_1_conformance", "12", actual, "lab/v1_1-regression-gate.mjs");
}

// 5. 34 adversarial categories (count table rows in PAPER.md Section 6.3)
{
  const start = paperMd.indexOf("### 6.3 Adversarial Resistance");
  const end   = paperMd.indexOf("### 6.4 Performance");
  let n = 0;
  if (start >= 0 && end > start) {
    const block = paperMd.substring(start, end);
    const lines = block.split(/\r?\n/);
    let seenHeader = false, seenSep = false;
    for (const line of lines) {
      const t = line.trim();
      if (!t.startsWith("|")) continue;
      if (/^\|[-\s|]+\|$/.test(t)) { seenSep = true; continue; }
      if (!seenHeader) { seenHeader = true; continue; }
      if (!seenSep) continue;
      n++;
    }
  }
  check("34_adversarial_categories", "34", n, "PAPER.md Section 6.3");
}

// 6. 9 v1.1 modules (excluding backups)
{
  const srcDir = path.join(ROOT, "src");
  let n = 0;
  (function walk(d){
    for (const e of fs.readdirSync(d, {withFileTypes: true})) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name.includes("v1_1") && e.name.endsWith(".js") && !e.name.includes(".backup_")) n++;
    }
  })(srcDir);
  check("9_v1_1_modules", "9", n, "src/**/*v1_1*.js (no .backup)");
}

// 7. 28 references (PAPER.tex bibitems)
{
  const n = (paperTex.match(/\\bibitem\{/g) || []).length;
  check("28_bibitems_tex", "28", n, "PAPER.tex");
}

// 8. SRC_TREE_SHA256 recompute
{
  const srcDir = path.join(ROOT, "src");
  const files = [];
  (function walk(d){
    for (const e of fs.readdirSync(d, {withFileTypes: true})) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && !e.name.includes(".backup_")) files.push(full);
    }
  })(srcDir);
  files.sort();
  const h = crypto.createHash("sha256");
  for (const fpath of files) {
    const rel = path.relative(ROOT, fpath).split(path.sep).join("/");
    h.update(rel); h.update("\n");
    h.update(fs.readFileSync(fpath)); h.update("\n");
  }
  const actual = h.digest("hex").toUpperCase();
  check("SRC_TREE_SHA256", "941DE3DAC25B80B82D8ECC38D6A1C3F8F0BE085205A1AC339E2CB99D3CD7DE5F", actual, "src/ recompute");
}

// 9. EVIDENCE-AUDIT.md SHA256
{
  const actual = crypto.createHash("sha256").update(fs.readFileSync(AUDIT_MD)).digest("hex").toUpperCase();
  check("EVIDENCE_AUDIT_SHA256", "883FEBE7E12F6966B8454A5B6DF232AD9BAD4C9F5A21A9207144D5E6DA83007A", actual, "EVIDENCE-AUDIT.md");
}

// 10. Package manifest identity
{
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  check("package_name_version", "session-continuity-engine@0.2.0", `${pkg.name}@${pkg.version}`, "package.json");
  check("package_private", "true", String(pkg.private === true), "package.json");
}
// Print results

// Print results
const w1 = 30, w2 = 40, w3 = 40, w4 = 8;
console.log("CLAIM".padEnd(w1) + " | " + "EXPECTED".padEnd(w2) + " | " + "ACTUAL".padEnd(w3) + " | " + "VERDICT");
console.log("-".repeat(w1 + w2 + w3 + w4));
for (const r of rows) {
  console.log(r.name.padEnd(w1) + " | " + r.expected.padEnd(w2) + " | " + r.actual.padEnd(w3) + " | " + r.verdict);
}
console.log("");
for (const r of rows) {
  console.log("SOURCE " + r.name.padEnd(w1) + " = " + r.source);
}
const failCount = rows.filter(r => r.verdict === "FAIL").length;
console.log("");
console.log("TOTAL_CLAIMS=" + rows.length);
console.log("CLAIMS_PASS=" + (rows.length - failCount));
console.log("CLAIMS_FAIL=" + failCount);
console.log("CLAIM_EVIDENCE_AUDIT=" + (failCount === 0 ? "PASS" : "FAIL"));
