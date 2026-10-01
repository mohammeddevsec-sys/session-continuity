import { verifyInclusion, buildTree } from "./merkle-tree.mjs";

export class LogVerifier {
  static verifyEntry(leafData, proof, rootBase64) {
    const root = Buffer.from(rootBase64, "base64");
    const proofDecoded = proof.map(p => ({
      hash: Buffer.from(p.hash, "base64"),
      side: p.side
    }));
    return verifyInclusion(leafData, proofDecoded, root);
  }

  static verifyLog(logBase64) {
    try {
      const json = Buffer.from(logBase64, "base64").toString("utf8");
      const parsed = JSON.parse(json);
      if (!parsed.entries || !Array.isArray(parsed.entries)) {
        return { valid: false, error: "malformed: no entries" };
      }
      const leafData = parsed.entries.map(e => JSON.stringify(e));
      const { root } = buildTree(leafData);
      const computed = root ? root.toString("base64") : null;
      if (computed !== parsed.root) {
        return { valid: false, error: "root mismatch — log tampered" };
      }
      return {
        valid: true,
        size: parsed.entries.length,
        root: parsed.root,
        error: null
      };
    } catch (e) {
      return { valid: false, error: (e && e.message) ? e.message : String(e) };
    }
  }
}
