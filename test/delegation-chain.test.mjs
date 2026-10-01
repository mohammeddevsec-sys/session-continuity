import { DelegationChain } from "../src/delegation/chain-builder.mjs";
import { ChainVerifier } from "../src/delegation/chain-verifier.mjs";

function main() {
  console.log("=== DELEGATION CHAIN (Ed25519) — TEST ===\n");

  // Generate fresh keypair
  const { privateKeyPem, publicKeyPem } = DelegationChain.generateKeyPair();
  console.log("[1] KeyPair generated (Ed25519)");
  console.log("    Public key starts with: " + publicKeyPem.split("\n")[0]);

  const chain = DelegationChain.createRoot(privateKeyPem, "alice");
  console.log("[2] Root: alice");

  chain.delegate("agent_A", ["read:public"]);
  console.log("[3] -> agent_A [read:public]");

  chain.delegate("agent_B", ["read:public"]);
  console.log("[4] -> agent_B [read:public]");

  const b64 = chain.toBase64();
  console.log("[5] Encoded: " + b64.length + " chars");

  const verifier = new ChainVerifier(publicKeyPem);

  // Test 1: valid
  const r1 = verifier.verify(b64, { requiredSubject: "agent_B", requiredScope: "read:public" });
  console.log("\n[6] agent_B + read:public (expected: true):");
  console.log("    authorized: " + r1.authorized + ", depth: " + r1.depth);

  // Test 2: wrong subject
  const r2 = verifier.verify(b64, { requiredSubject: "charlie" });
  console.log("\n[7] charlie (expected: false):");
  console.log("    authorized: " + r2.authorized + ", error: " + r2.error);

  // Test 3: tampered token
  const tampered = b64.slice(0, -8) + "AAAAAAAA";
  const r3 = verifier.verify(tampered);
  console.log("\n[8] tampered (expected: false):");
  console.log("    authorized: " + r3.authorized + ", error: " + r3.error);

  // Test 4: wrong public key (different keypair)
  const other = DelegationChain.generateKeyPair();
  const wrongVerifier = new ChainVerifier(other.publicKeyPem);
  const r4 = wrongVerifier.verify(b64);
  console.log("\n[9] wrong public key (expected: false):");
  console.log("    authorized: " + r4.authorized + ", error: " + r4.error);

  const passed = r1.authorized === true && r2.authorized === false && r3.authorized === false && r4.authorized === false;
  console.log("\n" + (passed ? "[PASS]" : "[FAIL]") + " Delegation Chain (Ed25519)");
  console.log("       Asymmetric: verifier needs only public key");
  console.log("       Tamper detection: YES");
  console.log("       Wrong-key rejection: YES");
  process.exit(passed ? 0 : 1);
}

main();
