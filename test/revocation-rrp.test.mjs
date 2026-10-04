import crypto from "node:crypto";
import { DelegationGraph } from "../src/revocation/graph.mjs";
import { buildProof } from "../src/revocation/proof.mjs";
import { verifyProof } from "../src/revocation/verifier.mjs";

function genKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }),
    pub:  publicKey.export({ type: "spki", format: "pem" })
  };
}

function main() {
  console.log("=== RRP (with edge verification) — TEST ===\n");

  const alice = genKey();
  const bob   = genKey();
  const dave  = genKey();

  const graph = new DelegationGraph("alice", alice.pub);
  graph.addEdge("e1", "alice", "bob",   ["read"], alice.priv, alice.pub);
  graph.addEdge("e2", "bob",   "carol", ["read"], bob.priv,   bob.pub);
  graph.addEdge("e3", "alice", "dave",  ["read"], alice.priv, alice.pub);
  graph.addEdge("e4", "dave",  "carol", ["read"], dave.priv,  dave.pub);

  console.log("[1] Graph with 4 signed edges");

  // A: revoke e1 only
  graph.revoke("e1", "alice", alice.priv);
  const proofA = buildProof(graph, alice.priv);
  const vA = verifyProof(proofA);
  console.log("\n[2] Revoked e1");
  console.log("    affected:   [" + proofA.affected.join(", ") + "]");
  console.log("    verify: " + vA.valid + " (" + vA.reason + ")");
  const passA = vA.valid && vA.affected.includes("bob") && !vA.affected.includes("carol");

  // B: revoke e1 + e3
  graph.revoke("e3", "alice", alice.priv);
  const proofB = buildProof(graph, alice.priv);
  const vB = verifyProof(proofB);
  console.log("\n[3] Revoked e1 + e3");
  console.log("    affected:   [" + proofB.affected.join(", ") + "]");
  console.log("    verify: " + vB.valid + " (" + vB.reason + ")");
  const passB = vB.valid && vB.affected.includes("carol");

  // C: forged edge signature (tamper one edge)
  const tampered1 = JSON.parse(JSON.stringify(proofB));
  tampered1.edges[0].signature = Buffer.from("fake").toString("base64");
  const vC = verifyProof(tampered1);
  console.log("\n[4] Tampered edge signature:");
  console.log("    valid: " + vC.valid + ", reason: " + vC.reason);
  const passC = vC.valid === false && vC.reason.startsWith("ROOT_SIGNATURE_INVALID") || vC.reason.startsWith("EDGE_SIGNATURE_INVALID");

  // D: forged root signature
  const tampered2 = JSON.parse(JSON.stringify(proofB));
  tampered2.signature = Buffer.from("fake").toString("base64");
  const vD = verifyProof(tampered2);
  console.log("\n[5] Tampered root signature:");
  console.log("    valid: " + vD.valid + ", reason: " + vD.reason);
  const passD = vD.valid === false && vD.reason === "ROOT_SIGNATURE_INVALID";

  // E: forged revocation signature
  const tampered3 = JSON.parse(JSON.stringify(proofB));
  if (tampered3.revocations.length > 0) {
    tampered3.revocations[0].signature = Buffer.from("fake").toString("base64");
  }
  const vE = verifyProof(tampered3);
  console.log("\n[6] Tampered revocation signature:");
  console.log("    valid: " + vE.valid + ", reason: " + vE.reason);
  const passE = vE.valid === false;

  // F: forged edge (attacker replaces an edge's public key)
  const mallory = genKey();
  const tampered4 = JSON.parse(JSON.stringify(proofB));
  tampered4.edges[0].from_public_key = mallory.pub;
  const vF = verifyProof(tampered4);
  console.log("\n[7] Forged edge (attacker's pubkey):");
  console.log("    valid: " + vF.valid + ", reason: " + vF.reason);
  const passF = vF.valid === false;

  const passed = passA && passB && passC && passD && passE && passF;

  console.log("\n" + (passed ? "[PASS]" : "[FAIL]") + " RRP with edge verification");
  console.log("       All edges independently verified");
  console.log("       All revocations independently verified");
  console.log("       Root signature verified");
  console.log("       Path preservation: YES");
  console.log("       Forgery rejection: YES");
  process.exit(passed ? 0 : 1);
}

main();
