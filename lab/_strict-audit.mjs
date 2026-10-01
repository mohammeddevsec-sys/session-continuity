import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const log = (k,v)=>console.log(k+"="+v);

function sha256File(p){ return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex").toUpperCase(); }

const expected = {
  "src\\core\\canonical.js":                          "8EC372C56A4A40941DDC167CAFFFF576079A391DD54A2ADC73BBC40E0984A8B8",
  "src\\core\\continuity-engine.js":                  "FDE44B2005E1C7E50ABB62BF366754455DE39D1C7D93273E8EA406C61D49B7AC",
  "src\\core\\durable-replay-state.js":               "DF3A232652D9E3FF22800DDCA91A6DAD476368092D29B19E5503361B987A6497",
  "src\\evidence\\proof-signature.js":                "B3D2D393C9594A6FD7A899714FC3B5014C59666694C68C7ED7D2C45730F20795",
  "src\\evidence\\session-provenance-certificate.js": "5F65E0B20A0D47F258F0B95E8024EB3755FC4975C66C5D6524189BDCD64356F2",
  "src\\core\\canonical-v1_1.js":                     "4DEA93DDDC5C4E885E10D6968F9E4C9F8A9EDBC4F46D04A04A8D30ED66A71FBF",
  "src\\core\\continuity-proof-v1_1.js":              "01F891AB59C497E865383CFB9F3111D774161F7962521F73A96927BC6E246722",
  "src\\core\\sequence-guard-v1_1.js":                "13A86DAAF4728AE7F032F48BF9A96E3CBCCB782B7D78DB928C40D117AE14EBF1",
  "src\\core\\durable-sequence-guard-v1_1.js":        "039E6536E8AA1B79B65BCE6400A4AEEB3AF9613C35A9005F1BEE84FF67378030",
  "src\\evidence\\proof-signature-v1_1.js":           "5659946DF7C566B046EF287A11142F24ED4216F9A5F186E39CA5C6C75352A0EC",
  "src\\evidence\\trusted-proof-verifier-v1_1.js":    "CE06E1535952CE71D49103911173BBAF8A3344E7BAF57EE8B9F43550487B872C",
  "src\\evidence\\witness-v1_1.js":                   "628F6A6084EA8017CCF07106A6114DC6756FEFD0E315DF0F842CB001169EB9FD",
  "src\\evidence\\portable-package-v1_1.js":          "C75B7AD0DCFEFFA43E211BA34326929565474F1E9B954D0BEF2A34FC7E9CFBDC",
  "src\\evidence\\key-lifecycle-v1_1.js":             "B59DE1144111069C7A977A2486F081E37DC9D0F9A88ED730D19528071CBA07A9",
  "package.json":                                     "A300614148FFB7E675B08F5079C10018C03F2E25D950FAAD2A3DEE3B8C4BE10C"
};

let ip = 0, ifail = 0;
for (const rel of Object.keys(expected)) {
  const full = path.join(ROOT, rel);
  const key = "INTEGRITY_" + rel.replace(/[\\\/\.\-]/g, "_");
  if (!fs.existsSync(full)) { log(key, "MISSING"); ifail++; continue; }
  let actual = "";
  try { actual = sha256File(full); } catch(e) { log(key, "READ_ERROR:" + e.message); ifail++; continue; }
  const ok = actual === expected[rel];
  if (ok) ip++; else ifail++;
  log(key, ok ? "PASS" : "MISMATCH:" + actual);
}
log("INTEGRITY_PASS_COUNT", ip);
log("INTEGRITY_FAIL_COUNT", ifail);

let v1Out = "";
try { v1Out = execFileSync(process.execPath, ["test\\run-all-tests.mjs"], {cwd: ROOT, encoding: "utf8", timeout: 600000}); }
catch(e) { v1Out = String(e.stdout || "") + String(e.stderr || ""); }
log("V1_FINAL_REGRESSION", (v1Out.match(/FINAL_REGRESSION=(\S+)/) || [])[1] || "MISSING");
log("V1_PRODUCT_STATE",    (v1Out.match(/PRODUCT_STATE=(\S+)/) || [])[1] || "MISSING");

let v11Out = "";
try { v11Out = execFileSync(process.execPath, ["lab\\v1_1-regression-gate.mjs"], {cwd: ROOT, encoding: "utf8", timeout: 600000}); }
catch(e) { v11Out = String(e.stdout || "") + String(e.stderr || ""); }
log("V1_1_TOTAL_PASS", (v11Out.match(/TOTAL_PASS=(\d+)/) || [])[1] || "MISSING");
log("V1_1_TOTAL_FAIL", (v11Out.match(/TOTAL_FAIL=(\d+)/) || [])[1] || "MISSING");
log("V1_1_REGRESSION", (v11Out.match(/V1_1_REGRESSION=(\S+)/) || [])[1] || "MISSING");

let npmOut = "";
try {
  const r = spawnSync("npm", ["pack", "--dry-run"], {cwd: ROOT, encoding: "utf8", shell: true, timeout: 180000});
  npmOut = String(r.stdout || "") + String(r.stderr || "");
} catch(e) { npmOut = String(e.stdout || "") + String(e.stderr || ""); }
log("PACKAGE_SIZE",   ((npmOut.match(/package size:\s*([^\r\n]+)/) || [])[1] || "MISSING").trim());
log("UNPACKED_SIZE",  ((npmOut.match(/unpacked size:\s*([^\r\n]+)/) || [])[1] || "MISSING").trim());
log("TOTAL_FILES",    (npmOut.match(/total files:\s*(\d+)/) || [])[1] || "MISSING");

const dangerous = ["signer-private.pem", ".backup_", "authority/", "authority\\", "/lab/", "/release/", "SESSION-CONTINUITYlab", "_trust-debug"];
let dFound = 0;
for (const d of dangerous) { if (npmOut.includes(d)) { dFound++; log("DANGEROUS_FOUND", d); } }
log("DANGEROUS_COUNT", dFound);

const v1 = (v1Out.match(/FINAL_REGRESSION=([A-Z]+)/) || [])[1] || "";
const v11 = (v11Out.match(/V1_1_REGRESSION=(\S+)/) || [])[1] || "";
const pass = (ifail === 0 && v1 === "PASS" && v11 === "PASS" && dFound === 0);
log("STRICT_AUDIT_VERDICT", pass ? "PASS" : "FAIL");
log("AUDIT_DONE", 1);