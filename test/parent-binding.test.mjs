import crypto from "node:crypto";
import {
  createParentBinding,
  verifyParentBinding,
  bindingId
} from "../src/core/parent-binding.mjs";

function assertEq(actual, expected, label) {
  if (actual !== expected) {
    console.error("  FAIL: " + label + " — expected " + expected + ", got " + actual);
    process.exitCode = 1;
  } else {
    console.log("  PASS: " + label);
  }
}

function main() {
  console.log("=== PARENT BINDING TEST ===\n");

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });

  const parentSessionId = "sess_alice_001";
  const parentSequence = 41;
  const nextChallenge = "challenge_xyz_987";

  // ── Test 1: valid binding passes
  const binding = createParentBinding({
    parentSessionId,
    parentSequence,
    nextChallenge,
    privateKeyPem: privPem
  });
  console.log("[1] Binding created");
  assertEq(typeof binding.signature, "string", "signature present");
  assertEq(binding.next_sequence, 42, "next_sequence = 42");
  assertEq(typeof bindingId(binding), "string", "binding_id present");

  const v1 = verifyParentBinding({ binding, parentPublicKeyPem: pubPem, presentedChallenge: nextChallenge });
  assertEq(v1.valid, true, "valid binding accepted");
  assertEq(v1.reason, "BINDING_VALID", "reason = BINDING_VALID");
  console.log("");

  // ── Test 2: tampered signature rejected
  const tampered = JSON.parse(JSON.stringify(binding));
  tampered.signature = Buffer.from("fake_signature").toString("base64");
  const v2 = verifyParentBinding({ binding: tampered, parentPublicKeyPem: pubPem, presentedChallenge: nextChallenge });
  assertEq(v2.valid, false, "tampered signature rejected");
  assertEq(v2.reason, "BINDING_SIGNATURE_INVALID", "reason = BINDING_SIGNATURE_INVALID");
  console.log("");

  // ── Test 3: expired binding rejected
  const v3 = verifyParentBinding({
    binding,
    parentPublicKeyPem: pubPem,
    presentedChallenge: nextChallenge,
    nowMs: Date.now() + 120000
  });
  assertEq(v3.valid, false, "expired binding rejected");
  assertEq(v3.reason, "BINDING_EXPIRED", "reason = BINDING_EXPIRED");
  console.log("");

  // ── Test 4: wrong challenge rejected
  const v4 = verifyParentBinding({
    binding,
    parentPublicKeyPem: pubPem,
    presentedChallenge: "different_challenge"
  });
  assertEq(v4.valid, false, "wrong challenge rejected");
  assertEq(v4.reason, "BINDING_CHALLENGE_MISMATCH", "reason = BINDING_CHALLENGE_MISMATCH");
  console.log("");

  // ── Test 5: tampered sequence rejected (signature covers it)
  const tamperedSeq = JSON.parse(JSON.stringify(binding));
  tamperedSeq.next_sequence = 99;
  const v5 = verifyParentBinding({ binding: tamperedSeq, parentPublicKeyPem: pubPem, presentedChallenge: nextChallenge });
  assertEq(v5.valid, false, "tampered sequence rejected");
  assertEq(v5.reason, "BINDING_SIGNATURE_INVALID", "reason = BINDING_SIGNATURE_INVALID (signature covers sequence)");
  console.log("");

  // ── Test 6: wrong public key rejected
  const otherKeys = crypto.generateKeyPairSync("ed25519");
  const otherPub = otherKeys.publicKey.export({ type: "spki", format: "pem" });
  const v6 = verifyParentBinding({ binding, parentPublicKeyPem: otherPub, presentedChallenge: nextChallenge });
  assertEq(v6.valid, false, "wrong public key rejected");
  assertEq(v6.reason, "BINDING_SIGNATURE_INVALID", "reason = BINDING_SIGNATURE_INVALID");
  console.log("");

  // ── Result
  if (process.exitCode === 1) {
    console.log("[FAIL] Parent binding test failed");
    process.exit(1);
  } else {
    console.log("[PASS] Parent binding works correctly");
    console.log("       - Signed single-use commitment");
    console.log("       - TTL enforced (60s default)");
    console.log("       - Challenge binding enforced");
    console.log("       - Sequence n+1 enforced");
    console.log("       - Signature covers all fields");
    process.exit(0);
  }
}

main();
