import crypto from "node:crypto";
import { computeReachability, diffReachability } from "./reachability.mjs";

/**
 * Build a Revocation Reachability Proof.
 *
 * The proof contains:
 *   - The graph (edges + revocations) at the time of proof
 *   - A snapshot of reachability before and after revocation
 *   - The set of affected and unaffected nodes
 *
 * The proof is signed by the root's private key so verifiers
 * can attest the graph state.
 */
export function buildProof(graph, rootPrivateKeyPem) {
  const allEdges = graph.allEdges();

  // Reachability BEFORE any revocation
  const beforeReach = computeReachability(graph.rootId, allEdges);

  // Reachability AFTER revocations
  const activeEdges = graph.getActiveEdges();
  const afterReach = computeReachability(graph.rootId, activeEdges);

  const { affected, unaffected } = diffReachability(beforeReach, afterReach);

  const body = {
    protocol: "revocation-reachability-proof-v1",
    root: graph.rootId,
    root_public_key: graph.exportPublicRoot(),
    edges: allEdges,
    revocations: graph.allRevocations(),
    affected,
    unaffected,
    timestamp: new Date().toISOString()
  };

  const canonical = JSON.stringify(body);
  const signature = crypto.sign(
    null,
    Buffer.from(canonical),
    rootPrivateKeyPem
  );

  return {
    ...body,
    signature: signature.toString("base64")
  };
}
