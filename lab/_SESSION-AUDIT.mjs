import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const LAB = path.join(ROOT, "lab");

let passCount = 0, failCount = 0;
function check(name, ok, details) {
  const d = details || "";
  console.log("[" + name + "]=" + (ok ? "PASS" : "FAIL") + (d ? "|" + d : ""));
  if (ok) passCount++; else failCount++;
}
function head(title) {
  console.log("");
  console.log("=== " + title + " ===");
}
function sha256File(p) {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex").toUpperCase();
}
function sha256Tree(dir) {
  const files = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && !e.name.includes(".backup_")) files.push(full);
    }
  })(dir);
  files.sort();
  const h = crypto.createHash("sha256");
  for (const f of files) {
    const rel = path.relative(ROOT, f).split(path.sep).join("/");
    h.update(rel); h.update("\n");
    h.update(fs.readFileSync(f)); h.update("\n");
  }
  return h.digest("hex").toUpperCase();
}
function runNode(relPath, timeoutMs) {
  const full = path.join(ROOT, relPath);
  if (!fs.existsSync(full)) return { ok: false, out: "MISSING", code: -1 };
  try {
    const out = execFileSync(process.execPath, [full], {
      cwd: ROOT, encoding: "utf8",
      timeout: timeoutMs || 300000,
      maxBuffer: 64 * 1024 * 1024
    });
    return { ok: true, out, code: 0 };
  } catch (e) {
    return { ok: false, out: String(e.stdout || "") + String(e.stderr || ""), code: e.status || 1 };
  }
}

// ============================================================
head("1. STRUCTURE");
// ============================================================
for (const d of ["src","bin","test","lab","release","authority","examples"]) {
  check("DIR_" + d, fs.existsSync(path.join(ROOT, d)));
}
for (const f of ["package.json","README.md","SECURITY.md","SECURITY-POLICY.md","CHANGELOG.md","LICENSE.txt",".npmignore"]) {
  check("FILE_" + f, fs.existsSync(path.join(ROOT, f)));
}

// ============================================================
head("2. CRITICAL SRC FILES");
// ============================================================
const srcFiles = [
  "src/core/canonical.js",
  "src/core/canonical-v1_1.js",
  "src/core/continuity-proof-v1_1.js",
  "src/core/sequence-guard-v1_1.js",
  "src/core/durable-sequence-guard-v1_1.js",
  "src/evidence/proof-signature.js",
  "src/evidence/proof-signature-v1_1.js",
  "src/evidence/witness-v1_1.js",
  "src/evidence/key-lifecycle-v1_1.js",
  "src/evidence/trusted-proof-verifier-v1_1.js",
  "src/evidence/portable-package-v1_1.js",
  "src/product/session-continuity-decision.js",
  "src/policy/session-continuity-policy.js"
];
for (const f of srcFiles) {
  check("SRC_" + path.basename(f), fs.existsSync(path.join(ROOT, f)));
}

// ============================================================
head("3. SRC TREE INTEGRITY");
// ============================================================
const srcHash = sha256Tree(path.join(ROOT, "src"));
const srcExpected = "941DE3DAC25B80B82D8ECC38D6A1C3F8F0BE085205A1AC339E2CB99D3CD7DE5F";
check("SRC_TREE_SHA256", srcHash === srcExpected, srcHash === srcExpected ? "" : "GOT=" + srcHash);

// ============================================================
head("4. FILE INTEGRITY");
// ============================================================
const fileChecks = [
  { rel: "package.json", exp: "A300614148FFB7E675B08F5079C10018C03F2E25D950FAAD2A3DEE3B8C4BE10C" },
  { rel: "lab/EVIDENCE-AUDIT.md", exp: "883FEBE7E12F6966B8454A5B6DF232AD9BAD4C9F5A21A9207144D5E6DA83007A" },
  { rel: "src/evidence/witness-v1_1.js", exp: "628F6A6084EA8017CCF07106A6114DC6756FEFD0E315DF0F842CB001169EB9FD" }
];
for (const fc of fileChecks) {
  const full = path.join(ROOT, fc.rel);
  if (!fs.existsSync(full)) { check("HASH_" + path.basename(fc.rel), false, "MISSING"); continue; }
  const h = sha256File(full);
  check("HASH_" + path.basename(fc.rel), h === fc.exp, h === fc.exp ? "" : "GOT=" + h);
}

// ============================================================
head("5. GATES");
// ============================================================
const gates = [
  { n: "LATEX-AUDIT",        p: "lab/LATEX-AUDIT.mjs",              e: "LATEX_AUDIT=PASS" },
  { n: "ALIGNMENT-AUDIT",    p: "lab/ALIGNMENT-AUDIT.mjs",          e: "ALIGNMENT_AUDIT=PASS" },
  { n: "CLAIM-EVIDENCE",     p: "lab/CLAIM-EVIDENCE-AUDIT.mjs",     e: "CLAIM_EVIDENCE_AUDIT=PASS" },
  { n: "ENTERPRISE-GATE",    p: "lab/enterprise-release-gate.mjs",  e: "ENTERPRISE_RELEASE_GATE=PASS" },
  { n: "FULL-AUDIT",         p: "lab/_full-audit.mjs",              e: "FULL_AUDIT=PASS" },
  { n: "STRICT-AUDIT",       p: "lab/_strict-audit.mjs",            e: "STRICT_AUDIT_VERDICT=PASS" },
  { n: "V1_1-REGRESSION",    p: "lab/v1_1-regression-gate.mjs",     e: "V1_1_REGRESSION=PASS" },
  { n: "PROOF",              p: "lab/PROOF.mjs",                    e: "OVERALL=PASS" }
];
for (const g of gates) {
  const r = runNode(g.p);
  const hit = r.out.includes(g.e);
  check("GATE_" + g.n, r.ok && hit, "EXIT=" + r.code + (hit ? "" : "|EXPECTED_NOT_FOUND"));
}

// ============================================================
head("6. DETERMINISM");
// ============================================================
const detLog1 = path.join(LAB, "_backups", "_audit-det-run1.txt");
const detLog2 = path.join(LAB, "_backups", "_audit-det-run2.txt");
try {
  const out1 = execFileSync(process.execPath, [path.join(LAB, "EVIDENCE-CAPTURE.mjs")], {
    cwd: ROOT, encoding: "utf8", timeout: 300000, maxBuffer: 64 * 1024 * 1024
  });
  fs.writeFileSync(detLog1, out1, "utf8");
  const out2 = execFileSync(process.execPath, [path.join(LAB, "EVIDENCE-CAPTURE.mjs")], {
    cwd: ROOT, encoding: "utf8", timeout: 300000, maxBuffer: 64 * 1024 * 1024
  });
  fs.writeFileSync(detLog2, out2, "utf8");
  const m1 = out1.match(/EVIDENCE_OUTPUT_SHA256=([0-9A-F]+)/);
  const m2 = out2.match(/EVIDENCE_OUTPUT_SHA256=([0-9A-F]+)/);
  const s1 = m1 ? m1[1] : "NONE";
  const s2 = m2 ? m2[1] : "NONE";
  check("EVIDENCE_CAPTURE_DETERMINISTIC", s1 === s2 && s1 !== "NONE", "RUN1=" + s1.substring(0,16) + "|RUN2=" + s2.substring(0,16));
} catch (e) {
  check("EVIDENCE_CAPTURE_DETERMINISTIC", false, "EXEC_FAILED=" + String(e.message).substring(0,60));
}

// ============================================================
head("7. STALE CONTENT");
// ============================================================
const stalePatterns = ["BC73F145", "67A1C302", "C988CA3A"];
const staleFiles = ["lab/PAPER.md", "lab/PAPER.tex", "lab/continuity-proof-vnext/SPEC-DRAFT-V1_2.md"];
for (const rel of staleFiles) {
  const full = path.join(ROOT, rel);
  const c = fs.readFileSync(full, "utf8");
  for (const sp of stalePatterns) {
    const has = c.includes(sp);
    if (has) check("STALE_" + path.basename(rel) + "_" + sp, false, "FOUND");
  }
  check("STALE_SCAN_" + path.basename(rel), !stalePatterns.some(s => c.includes(s)), "CLEAN_IF_PASS");
}

// ============================================================
head("8. ROOT CLEANLINESS");
// ============================================================
const rootItems = fs.readdirSync(ROOT);
const rootBackups = rootItems.filter(n => n.includes(".backup_"));
check("ROOT_NO_BACKUPS", rootBackups.length === 0, "FOUND=" + rootBackups.length);
check("ROOT_NO_LAB_RESULT", !rootItems.includes("lab-result.json"));
const fixturesDir = path.join(ROOT, "test", "fixtures");
const fixtures = fs.readdirSync(fixturesDir);
check("FIXTURES_NO_TRUST_DEBUG", !fixtures.includes("_trust-debug"));
check("ROOT_HAS_NPMIGNORE", rootItems.includes(".npmignore"));

// ============================================================
head("9. COUNTS");
// ============================================================
const testDir = path.join(ROOT, "test");
const testFiles = fs.readdirSync(testDir).filter(n => n.endsWith(".js") && n !== "run-all-tests.mjs");
check("TEST_FILE_COUNT_41", testFiles.length === 41, "GOT=" + testFiles.length);

const srcCount = (function count(d) {
  let n = 0;
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    if (e.isDirectory()) n += count(path.join(d, e.name));
    else if (e.isFile() && !e.name.includes(".backup_")) n++;
  }
  return n;
})(path.join(ROOT, "src"));
check("SRC_FILE_COUNT_42", srcCount === 42, "GOT=" + srcCount);

// ============================================================
head("FINAL VERDICT");
// ============================================================
console.log("");
console.log("TOTAL_CHECKS=" + (passCount + failCount));
console.log("PASS_COUNT=" + passCount);
console.log("FAIL_COUNT=" + failCount);
console.log("SESSION_AUDIT=" + (failCount === 0 ? "PASS" : "FAIL"));