import { buildTree, inclusionProof } from "./merkle-tree.mjs";

/**
 * Append-only transparency log.
 * Entries never deleted; root changes on each append.
 */
export class TransparencyLog {
  constructor() {
    this.entries = [];      // { id, payload, timestamp }
    this.roots = [];        // historical roots, one per entry count
  }

  append(id, payload) {
    if (this.entries.some(e => e.id === id)) {
      throw new Error(`duplicate entry id: ${id}`);
    }
    const entry = {
      id,
      payload,
      timestamp: new Date().toISOString()
    };
    this.entries.push(entry);
    const { root } = buildTree(this._leafData());
    this.roots.push({
      size: this.entries.length,
      root: root.toString("base64")
    });
    return entry;
  }

  _leafData() {
    return this.entries.map(e => JSON.stringify(e));
  }

  currentRoot() {
    if (this.entries.length === 0) return null;
    const { root } = buildTree(this._leafData());
    return root.toString("base64");
  }

  size() { return this.entries.length; }

  proofFor(id) {
    const idx = this.entries.findIndex(e => e.id === id);
    if (idx === -1) throw new Error(`entry not found: ${id}`);
    const proof = inclusionProof(this._leafData(), idx);
    return {
      id,
      leaf: JSON.stringify(this.entries[idx]),
      proof: proof.map(p => ({ hash: p.hash.toString("base64"), side: p.side })),
      root: this.currentRoot()
    };
  }

  toJSON() {
    return JSON.stringify({
      version: "1.0.0",
      size: this.entries.length,
      root: this.currentRoot(),
      entries: this.entries
    });
  }

  toBase64() {
    return Buffer.from(this.toJSON(), "utf8").toString("base64");
  }
}
