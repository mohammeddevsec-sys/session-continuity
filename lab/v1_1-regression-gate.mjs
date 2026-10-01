import { execFileSync } from "node:child_process";
import fs from "node:fs";

const probes = [
  {file:"v1_1-integration-probe.mjs", marker:"PROBE_DONE"},
  {file:"v1_1-chain-probe.mjs", marker:"CHAIN_PROBE_DONE"},
  {file:"v1_1-scale-chain-probe.mjs", marker:"SCALE_PROBE_DONE=1"},
  {file:"v1_1-trusted-chain-probe.mjs", marker:"TRUSTED_PROBE_DONE=1"},
  {file:"v1_1-sequence-guard-probe.mjs", marker:"SEQ_PROBE_DONE=1"},
  {file:"v1_1-durable-sequence-probe.mjs", marker:"DURABLE_SEQ_PROBE_DONE=1"},
  {file:"v1_1-witness-probe-v2.mjs", marker:"WITNESS_PROBE_V2_DONE=1"},
  {file:"v1_1-witness-fail-closed-probe.mjs", marker:"WITNESS_FAIL_CLOSED_PROBE_DONE=1"},
  {file:"v1_1-portable-package-probe-v2.mjs", marker:"PORTABLE_PACKAGE_PROBE_V2_DONE=1"},
  {file:"v1_1-full-integration-probe.mjs", marker:"FULL_INTEGRATION_DONE=1"},
  {file:"v1_1-key-lifecycle-probe.mjs", marker:"KEY_LIFECYCLE_PROBE_DONE=1"},
  {file:"v1_1-lifecycle-integration-probe.mjs", marker:"LIFECYCLE_INTEGRATION_PROBE_DONE=1"}
];

const base = "E:\\SESSION-CONTINUITY - Copy\\lab\\";
let pass = 0, fail = 0;

for (const p of probes) {
  const path = base + p.file;
  if (!fs.existsSync(path)) {
    console.log("PROBE=" + p.file + "|MISSING");
    fail++;
    continue;
  }
  let out = "";
  try {
    out = execFileSync(process.execPath, [path], {encoding:"utf8", cwd:base});
  } catch (e) {
    out = String(e.stdout || "") + String(e.stderr || "");
  }
  const ok = out.indexOf(p.marker) !== -1;
  if (ok) pass++; else fail++;
  console.log("PROBE=" + p.file + "|" + (ok?"PASS":"FAIL"));
}

console.log("TOTAL_PASS=" + pass);
console.log("TOTAL_FAIL=" + fail);
console.log("V1_1_REGRESSION=" + (fail === 0 ? "PASS" : "FAIL"));
console.log("GATE_DONE=1");