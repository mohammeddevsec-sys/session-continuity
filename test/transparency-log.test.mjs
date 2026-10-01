import { TransparencyLog } from "../src/transparency/log-builder.mjs";
import { LogVerifier } from "../src/transparency/log-verifier.mjs";

function main() {
  console.log("=== TRANSPARENCY LOG — TEST ===\n");

  const log = new TransparencyLog();

  // Append 5 session entries
  log.append("sess_001", { user: "alice", action: "login" });
  log.append("sess_002", { user: "alice", action: "read" });
  log.append("sess_003", { user: "bob",   action: "login" });
  log.append("sess_004", { user: "bob",   action: "write" });
  log.append("sess_005", { user: "carol", action: "login" });
  console.log("[1] Appended 5 entries, size=" + log.size());

  const root = log.currentRoot();
  console.log("[2] Root: " + root.slice(0, 20) + "...");

  // Proof for sess_003 (middle)
  const proof = log.proofFor("sess_003");
  console.log("[3] Proof for sess_003: " + proof.proof.length + " steps");

  const ok1 = LogVerifier.verifyEntry(proof.leaf, proof.proof, proof.root);
  console.log("[4] Inclusion verify (sess_003): " + ok1);

  // Proof for sess_001 (first)
  const proof1 = log.proofFor("sess_001");
  const ok2 = LogVerifier.verifyEntry(proof1.leaf, proof1.proof, proof1.root);
  console.log("[5] Inclusion verify (sess_001): " + ok2);

  // Proof for sess_005 (last)
  const proof5 = log.proofFor("sess_005");
  const ok3 = LogVerifier.verifyEntry(proof5.leaf, proof5.proof, proof5.root);
  console.log("[6] Inclusion verify (sess_005): " + ok3);

  // Full log verify
  const b64 = log.toBase64();
  const full = LogVerifier.verifyLog(b64);
  console.log("[7] Full log verify: valid=" + full.valid + ", size=" + full.size);

  // Tampered log
  const tampered = b64.slice(0, -20) + "XXXXXXXX";
  const bad = LogVerifier.verifyLog(tampered);
  console.log("[8] Tampered log (expected: false): valid=" + bad.valid);

  // Tampered leaf data
  const wrongLeaf = JSON.stringify({ id: "sess_003", payload: { user: "EVIL" }, timestamp: "2020-01-01" });
  const okBad = LogVerifier.verifyEntry(wrongLeaf, proof.proof, proof.root);
  console.log("[9] Wrong leaf (expected: false): " + okBad);

  const passed = ok1 && ok2 && ok3 && full.valid === true && bad.valid === false && okBad === false;
  console.log("\n" + (passed ? "[PASS]" : "[FAIL]") + " Transparency Log");
  console.log("       Entries:     5");
  console.log("       Merkle:      RFC 6962 style");
  console.log("       Tamper det.: YES");
  process.exit(passed ? 0 : 1);
}

main();
