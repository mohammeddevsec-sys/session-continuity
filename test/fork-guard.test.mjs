import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { acquireForkGuard, releaseForkGuard, isForkGuardHeld } from "../src/core/fork-guard.mjs";

// Isolate guard root for this test
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sc-fg-test-"));
process.env.SC_FORK_GUARD_ROOT = tmpRoot;

function assertEq(actual, expected, label) {
  if (actual !== expected) {
    console.error("  FAIL: " + label + " — expected " + expected + ", got " + actual);
    process.exitCode = 1;
  } else {
    console.log("  PASS: " + label);
  }
}

function main() {
  console.log("=== FORK GUARD TEST ===\n");

  // Test 1: acquire succeeds
  const a1 = acquireForkGuard({ sessionId: "sess_A", parentSequence: 1 });
  assertEq(a1.allowed, true, "first acquire succeeds");
  assertEq(a1.reason, "FORK_GUARD_ACQUIRED", "reason = ACQUIRED");
  assertEq(isForkGuardHeld({ sessionId: "sess_A", parentSequence: 1 }), true, "guard is held");
  console.log("");

  // Test 2: second acquire fails
  const a2 = acquireForkGuard({ sessionId: "sess_A", parentSequence: 1 });
  assertEq(a2.allowed, false, "second acquire rejected (FORK BLOCKED)");
  assertEq(a2.reason, "FORK_GUARD_ALREADY_HELD", "reason = ALREADY_HELD");
  console.log("");

  // Test 3: different sequence for same session is independent
  const a3 = acquireForkGuard({ sessionId: "sess_A", parentSequence: 2 });
  assertEq(a3.allowed, true, "different sequence acquires independently");
  console.log("");

  // Test 4: different session is independent
  const a4 = acquireForkGuard({ sessionId: "sess_B", parentSequence: 1 });
  assertEq(a4.allowed, true, "different session acquires independently");
  console.log("");

  // Test 5: release frees the slot
  releaseForkGuard({ sessionId: "sess_B", parentSequence: 1 });
  assertEq(isForkGuardHeld({ sessionId: "sess_B", parentSequence: 1 }), false, "guard released");
  const a5 = acquireForkGuard({ sessionId: "sess_B", parentSequence: 1 });
  assertEq(a5.allowed, true, "re-acquire after release succeeds");
  console.log("");

  // Test 6: invalid input rejected
  const a6 = acquireForkGuard({ sessionId: "", parentSequence: 1 });
  assertEq(a6.allowed, false, "empty sessionId rejected");
  const a7 = acquireForkGuard({ sessionId: "sess_A", parentSequence: -1 });
  assertEq(a7.allowed, false, "negative sequence rejected");
  console.log("");

  // Result
  if (process.exitCode === 1) {
    console.log("[FAIL] Fork guard test failed");
    process.exit(1);
  } else {
    console.log("[PASS] Fork guard works correctly");
    console.log("       - Exclusive lock per (session_id, parent_sequence)");
    console.log("       - Concurrent continuation BLOCKED");
    console.log("       - Release on demand");
    process.exit(0);
  }
}

main();
