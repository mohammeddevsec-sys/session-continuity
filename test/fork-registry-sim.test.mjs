/**
 * SIMULATED FORK SCENARIO — Proves that fork-registry works
 * when integrated at the correct point in a pipeline.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { claimContinuationSlot, releaseContinuationSlot } from "../src/core/fork-registry.mjs";

// Simulate an isolated registry per "session"
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sc-sim-fork-"));
process.env.SC_FORK_REGISTRY_ROOT = tmpRoot;

function assertEq(actual, expected, label) {
  if (actual !== expected) {
    console.error("  FAIL: " + label);
    process.exitCode = 1;
  } else {
    console.log("  PASS: " + label);
  }
}

// Simulated decision function (mimics real pipeline)
function simulateDecision({ anchorFingerprint, presentedSequence, branchName }) {
  // Step 1: verify sequence (assumed valid here)
  if (presentedSequence < 1) {
    return { decision: "REAUTH_REQUIRED", reason: "REPLAY_DETECTED" };
  }

  // Step 2: claim fork slot
  const parentSequence = presentedSequence - 1;
  const claim = claimContinuationSlot({
    anchorFingerprint,
    parentSequence,
    metadata: { branch: branchName }
  });

  if (!claim.claimed) {
    return { decision: "REAUTH_REQUIRED", reason: "FORK_DETECTED" };
  }

  // Step 3: simulate pipeline (assume ALLOW)
  // In real code, if pipeline fails, we'd release here.
  return { decision: "ALLOW", reason: "OK" };
}

function main() {
  console.log("=== SIMULATED FORK SCENARIO ===\n");

  const anchorFp = "unique_anchor_fingerprint_xyz";

  // P1 at seq 1
  const p1 = simulateDecision({ anchorFingerprint: anchorFp, presentedSequence: 1, branchName: "P1" });
  assertEq(p1.decision, "ALLOW", "P1 (seq=1) ALLOW");
  console.log("");

  // Branch A at seq 2
  const a = simulateDecision({ anchorFingerprint: anchorFp, presentedSequence: 2, branchName: "A" });
  assertEq(a.decision, "ALLOW", "Branch A (seq=2) ALLOW");
  console.log("");

  // Branch B at seq 2 → must be rejected
  const b = simulateDecision({ anchorFingerprint: anchorFp, presentedSequence: 2, branchName: "B" });
  assertEq(b.decision, "REAUTH_REQUIRED", "Branch B (seq=2) REJECTED");
  assertEq(b.reason, "FORK_DETECTED", "Branch B reason = FORK_DETECTED");
  console.log("");

  // Branch A continues to seq 3 (legitimate)
  const aNext = simulateDecision({ anchorFingerprint: anchorFp, presentedSequence: 3, branchName: "A-next" });
  assertEq(aNext.decision, "ALLOW", "Branch A (seq=3) ALLOW (legitimate continuation)");
  console.log("");

  if (process.exitCode === 1) {
    console.log("[FAIL] Simulated fork scenario failed");
    process.exit(1);
  } else {
    console.log("[PASS] Simulated fork scenario works correctly");
    console.log("       - First continuation allowed");
    console.log("       - Fork from same parent BLOCKED");
    console.log("       - Legitimate continuation after allow works");
    process.exit(0);
  }
}

main();
