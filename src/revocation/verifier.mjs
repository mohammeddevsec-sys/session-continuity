import crypto from "node:crypto";
import { computeReachability, diffReachability } from "./reachability.mjs";

export function verifyProof(proof) {
  try {
    // 1. Verify root signature over body
    const { signature, ...body } = proof;
    const canonical = JSON.stringify(body);
    const rootKey = crypto.createPublicKey(proof.root_public_key);

    const rootOk = crypto.verify(
      null,
      Buffer.from(canonical),
      rootKey,
      Buffer.from(signature, "base64")
    );
    if (!rootOk) {
      return { valid: false, reason: "ROOT_SIGNATURE_INVALID" };
    }

    // 2. Verify each edge's signature against its own from_public_key
    for (const edge of proof.edges) {
      if (!edge.from_public_key) {
        return { valid: false, reason: `EDGE_NO_PUBKEY:${edge.edgeId}` };
      }
      const statement = {
        edgeId: edge.edgeId,
        from: edge.from,
        to: edge.to,
        scope: edge.scope
      };
      const payload = JSON.stringify(statement);
      const edgeKey = crypto.createPublicKey(edge.from_public_key);
      const edgeOk = crypto.verify(
        null,
        Buffer.from(payload),
        edgeKey,
        Buffer.from(edge.signature, "base64")
      );
      if (!edgeOk) {
        return { valid: false, reason: `EDGE_SIGNATURE_INVALID:${edge.edgeId}` };
      }
    }

    // 3. Verify each revocation's signature against the revoker's key
    //    (revoker must be a node in the graph — find their key from an outgoing edge)
    const nodeKeys = new Map();
    for (const e of proof.edges) {
      if (!nodeKeys.has(e.from)) nodeKeys.set(e.from, e.from_public_key);
    }
    for (const rev of proof.revocations) {
      const key = nodeKeys.get(rev.revokedBy);
      if (!key) {
        return { valid: false, reason: `REVOKER_NO_KEY:${rev.revokedBy}` };
      }
      const statement = {
        edgeId: rev.edgeId,
        revokedBy: rev.revokedBy,
        timestamp: rev.timestamp
      };
      const payload = JSON.stringify(statement);
      const ok = crypto.verify(
        null,
        Buffer.from(payload),
        crypto.createPublicKey(key),
        Buffer.from(rev.signature, "base64")
      );
      if (!ok) {
        return { valid: false, reason: `REVOCATION_SIGNATURE_INVALID:${rev.edgeId}` };
      }
    }

    // 4. Recompute reachability
    const revokedIds = new Set(proof.revocations.map(r => r.edgeId));
    const beforeEdges = proof.edges;
    const afterEdges = proof.edges.filter(e => !revokedIds.has(e.edgeId));

    const beforeReach = computeReachability(proof.root, beforeEdges);
    const afterReach = computeReachability(proof.root, afterEdges);

    const { affected: computedAffected, unaffected: computedUnaffected } =
      diffReachability(beforeReach, afterReach);

    // 5. Compare with claimed
    const claimedAffected = [...proof.affected].sort();
    const claimedUnaffected = [...proof.unaffected].sort();

    if (JSON.stringify(computedAffected) !== JSON.stringify(claimedAffected)) {
      return { valid: false, reason: "AFFECTED_MISMATCH" };
    }
    if (JSON.stringify(computedUnaffected) !== JSON.stringify(claimedUnaffected)) {
      return { valid: false, reason: "UNAFFECTED_MISMATCH" };
    }

    return {
      valid: true,
      reason: "RRP_VERIFIED",
      affected: computedAffected,
      unaffected: computedUnaffected,
      revokedEdges: [...revokedIds]
    };
  } catch (e) {
    return { valid: false, reason: (e && e.message) ? e.message : String(e) };
  }
}
