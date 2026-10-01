import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), "..");

const DECISION_FILE = "src/product/session-continuity-decision.js";

const SCAN_FILES = [
  "src/core/transactional-final-proof-pipeline.js",
  "src/core/durable-secure-session-state.js",
  "src/core/proof-of-possession.js",
  "src/core/continuity-verifier.js",
  "src/policy/session-continuity-policy.js"
];

const EXCLUSIONS = new Set([
  "SEQUENCE_ACCEPTED",
  "IDEMPOTENT_REPLAY",
  "ANCHOR_MATCH",
  "SECURE_CONTINUITY_COMMITTED",
  "PROOF_OF_POSSESSION_VALID",
  "UNSPECIFIED"
]);

function readRequired(rel) {
  const full = path.join(ROOT, rel);
  if (!fs.existsSync(full)) throw new Error("MISSING_FILE:" + rel);
  return fs.readFileSync(full, "utf8");
}

function readOptional(rel) {
  const full = path.join(ROOT, rel);
  if (!fs.existsSync(full)) return null;
  return fs.readFileSync(full, "utf8");
}

const decisionSrc = readRequired(DECISION_FILE);

const exactMatches = new Set();
{
  const re = /reasonCode\s*===\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(decisionSrc)) !== null) exactMatches.add(m[1]);
}

const prefixes = [];
{
  const re = /reasonCode\.startsWith\("([^"]+)"\)/g;
  let m;
  while ((m = re.exec(decisionSrc)) !== null) prefixes.push(m[1]);
}

const candidates = new Set();
for (const rel of SCAN_FILES) {
  const src = readOptional(rel);
  if (!src) continue;
  let m;
  const failRe = /failure\(\s*[^,]+,\s*"([^"]+)"/g;
  while ((m = failRe.exec(src)) !== null) candidates.add(m[1]);
  const reasonRe = /reason\s*:\s*"([^"]+)"/g;
  while ((m = reasonRe.exec(src)) !== null) candidates.add(m[1]);
}

function isCovered(code) {
  if (EXCLUSIONS.has(code)) return true;
  if (exactMatches.has(code)) return true;
  for (const p of prefixes) {
    if (code.startsWith(p)) return true;
  }
  return false;
}

const uncovered = [];
for (const c of candidates) {
  if (!isCovered(c)) uncovered.push(c);
}

console.log("EXACT_MATCHES=" + exactMatches.size);
console.log("PREFIX_MATCHES=" + prefixes.length);
console.log("SCAN_FILES=" + SCAN_FILES.length);
console.log("EXCLUSIONS=" + EXCLUSIONS.size);
console.log("CANDIDATE_REASON_CODES=" + candidates.size);
console.log("UNCOVERED_COUNT=" + uncovered.length);
if (uncovered.length > 0) {
  for (const u of uncovered) console.log("UNCOVERED=" + u);
  console.log("REASON_CODE_COVERAGE=FAIL");
  process.exit(1);
} else {
  console.log("REASON_CODE_COVERAGE=PASS");
}