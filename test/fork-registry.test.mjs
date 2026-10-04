import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { claimContinuationSlot, releaseContinuationSlot, isSlotHeld } from "../src/core/fork-registry.mjs";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sc-fr-test-"));
process.env.SC_FORK_REGISTRY_ROOT = tmpRoot;

function assertEq(actual, expected, label) {
  if (actual !== expected) {
    console.error("  FAIL: " + label + " | expected " + expected + " | got " + actual);
    process.exitCode = 1;
  } else {
    console.log("  PASS: " + label);
  }
}

function main() {
  console.log("=== FORK REGISTRY TEST ===\n");

  const fpA = "anchor_fp_A";
  const fpB = "anchor_fp_B";

  // Test 1: first claim on (fpA, 1) succeeds
  const c1 = claimContinuationSlot({ anchorFingerprint: fpA, parentSequence: 1 });
  assertEq(c1.claimed, true, "first claim succeeds");
  assertEq(c1.reason, "SLOT_CLAIMED", "reason = SLOT_CLAIMED");
  assertEq(isSlotHeld({ anchorFingerprint: fpA, parentSequence: 1 }), true, "slot is held");
  console.log("");

  // Test 2: second claim on (fpA, 1) → FORK_DETECTED
  const c2 = claimContinuationSlot({ anchorFingerprint: fpA, parentSequence: 1 });
  assertEq(c2.claimed, false, "second claim rejected");
  assertEq(c2.reason, "FORK_DETECTED", "reason = FORK_DETECTED");
  console.log("");

  // Test 3: different parent sequence is independent
  const c3 = claimContinuationSlot({ anchorFingerprint: fpA, parentSequence: 2 });
  assertEq(c3.claimed, true, "different sequence succeeds");
  console.log("");

  // Test 4: different anchor fingerprint is independent
  const c4 = claimContinuationSlot({ anchorFingerprint: fpB, parentSequence: 1 });
  assertEq(c4.claimed, true, "different anchor succeeds");
  console.log("");

  // Test 5: release works
  releaseContinuationSlot({ anchorFingerprint: fpB, parentSequence: 1 });
  assertEq(isSlotHeld({ anchorFingerprint: fpB, parentSequence: 1 }), false, "slot released");
  const c5 = claimContinuationSlot({ anchorFingerprint: fpB, parentSequence: 1 });
  assertEq(c5.claimed, true, "reclaim after release succeeds");
  console.log("");

  // Test 6: invalid inputs
  assertEq(claimContinuationSlot({ anchorFingerprint: "", parentSequence: 1 }).claimed, false, "empty fingerprint rejected");
  assertEq(claimContinuationSlot({ anchorFingerprint: fpA, parentSequence: -1 }).claimed, false, "negative sequence rejected");
  assertEq(claimContinuationSlot({ anchorFingerprint: fpA, parentSequence: 1.5 }).claimed, false, "non-integer sequence rejected");
  console.log("");

  if (process.exitCode === 1) {
    console.log("[FAIL] Fork registry test failed");
    process.exit(1);
  } else {
    console.log("[PASS] Fork registry works correctly");
    console.log("       - Exclusive slot per (anchor_fingerprint, parent_sequence)");
    console.log("       - Second claim triggers FORK_DETECTED");
    console.log("       - Isolated by anchor fingerprint (no cross-test pollution)");
    process.exit(0);
  }
}

main();
