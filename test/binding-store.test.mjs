import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { createParentBinding } from "../src/core/parent-binding.mjs";
import { BindingStore, consumeAndVerifyBinding } from "../src/core/binding-store.mjs";

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sc-binding-"));
}

function assertEq(actual, expected, label) {
  if (actual !== expected) {
    console.error("  FAIL: " + label + " — expected " + expected + ", got " + actual);
    process.exitCode = 1;
  } else {
    console.log("  PASS: " + label);
  }
}

function main() {
  console.log("=== BINDING STORE TEST ===\n");

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });

  // ── Test 1: fresh store
  const dir1 = tmpDir();
  const storePath1 = path.join(dir1, "consumed.ndjson");
  const store1 = new BindingStore(storePath1);
  assertEq(store1.size(), 0, "fresh store size = 0");
  console.log("");

  // ── Test 2: consume once
  const r1 = store1.consume("binding_001", { test: true });
  assertEq(r1.consumed, true, "first consume succeeds");
  assertEq(store1.size(), 1, "store size = 1");
  assertEq(store1.isConsumed("binding_001"), true, "isConsumed returns true");
  console.log("");

  // ── Test 3: re-consume rejected
  const r2 = store1.consume("binding_001", { test: true });
  assertEq(r2.consumed, false, "re-consume rejected");
  assertEq(r2.reason, "ALREADY_CONSUMED", "reason = ALREADY_CONSUMED");
  console.log("");

  // ── Test 4: persistence across new instances
  const store1b = new BindingStore(storePath1);
  store1b.load();
  assertEq(store1b.size(), 1, "reloaded store size = 1");
  assertEq(store1b.isConsumed("binding_001"), true, "still consumed after reload");
  console.log("");

  // ── Test 5: full fork-attempt scenario
  const dir5 = tmpDir();
  const storePath5 = path.join(dir5, "consumed.ndjson");
  const nextChallenge = "challenge_xyz_987";
  const binding = createParentBinding({
    parentSessionId: "sess_alice_001",
    parentSequence: 41,
    nextChallenge,
    privateKeyPem: privPem
  });
  const store5 = new BindingStore(storePath5);

  const first = consumeAndVerifyBinding({
    binding,
    parentPublicKeyPem: pubPem,
    presentedChallenge: nextChallenge,
    store: store5,
    metadata: { session_id: "sess_alice_001" }
  });
  assertEq(first.valid, true, "first presentation accepted");
  assertEq(first.reason, "BINDING_CONSUMED", "reason = BINDING_CONSUMED");
  console.log("");

  const second = consumeAndVerifyBinding({
    binding,
    parentPublicKeyPem: pubPem,
    presentedChallenge: nextChallenge,
    store: store5,
    metadata: { session_id: "sess_alice_001" }
  });
  assertEq(second.valid, false, "second presentation rejected (FORK BLOCKED)");
  assertEq(second.reason, "BINDING_ALREADY_CONSUMED", "reason = BINDING_ALREADY_CONSUMED");
  console.log("");

  // ── Test 6: multiple independent bindings
  const dir6 = tmpDir();
  const storePath6 = path.join(dir6, "consumed.ndjson");
  const store6 = new BindingStore(storePath6);
  const b1 = createParentBinding({ parentSessionId: "s1", parentSequence: 1, nextChallenge: "c1", privateKeyPem: privPem });
  const b2 = createParentBinding({ parentSessionId: "s2", parentSequence: 5, nextChallenge: "c2", privateKeyPem: privPem });
  const r6a = consumeAndVerifyBinding({ binding: b1, parentPublicKeyPem: pubPem, presentedChallenge: "c1", store: store6 });
  const r6b = consumeAndVerifyBinding({ binding: b2, parentPublicKeyPem: pubPem, presentedChallenge: "c2", store: store6 });
  assertEq(r6a.valid, true, "binding 1 accepted");
  assertEq(r6b.valid, true, "binding 2 accepted");
  assertEq(store6.size(), 2, "store has 2 entries");
  console.log("");

  // ── Test 7: journal tampering detected
  const dir7 = tmpDir();
  const storePath7 = path.join(dir7, "consumed.ndjson");
  const store7 = new BindingStore(storePath7);
  store7.consume("b1");
  store7.consume("b2");
  const content = fs.readFileSync(storePath7, "utf8");
  const lines = content.split("\n").filter(Boolean);
  lines[0] = lines[0].replace('"b1"', '"b1_evil"');
  fs.writeFileSync(storePath7, lines.join("\n") + "\n", "utf8");

  let threw = false;
  try {
    const store7b = new BindingStore(storePath7);
    store7b.load();
  } catch (e) {
    threw = true;
  }
  assertEq(threw, true, "tampered journal rejected on load");
  console.log("");

  // ── Result
  if (process.exitCode === 1) {
    console.log("[FAIL] Binding store test failed");
    process.exit(1);
  } else {
    console.log("[PASS] Binding store works correctly");
    console.log("       - Single-use enforcement (FORK BLOCKED)");
    console.log("       - Persistence across restarts");
    console.log("       - Hash-chained journal (tamper detection)");
    console.log("       - Multiple bindings independent");
    process.exit(0);
  }
}

main();
