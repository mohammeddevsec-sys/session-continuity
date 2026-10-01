import crypto from "node:crypto";

export class DelegationGraph {
  constructor(rootId, rootPublicKeyPem) {
    this.rootId = rootId;
    this.rootPublicKeyPem = rootPublicKeyPem;
    this.edges = new Map();
    this.revocations = new Map();
  }

  addEdge(edgeId, from, to, scope, privateKeyPem, fromPublicKeyPem) {
    if (this.edges.has(edgeId)) {
      throw new Error(`duplicate edge: ${edgeId}`);
    }
    if (!fromPublicKeyPem) {
      throw new Error("fromPublicKeyPem required for verifiable edges");
    }
    const statement = {
      edgeId,
      from,
      to,
      scope: [...scope].sort(),
      from_public_key: fromPublicKeyPem
    };
    const payload = JSON.stringify({
      edgeId: statement.edgeId,
      from: statement.from,
      to: statement.to,
      scope: statement.scope
    });
    const signature = crypto.sign(null, Buffer.from(payload), privateKeyPem);
    this.edges.set(edgeId, {
      ...statement,
      signature: signature.toString("base64")
    });
  }

  revoke(edgeId, revokedBy, privateKeyPem) {
    if (!this.edges.has(edgeId)) {
      throw new Error(`unknown edge: ${edgeId}`);
    }
    if (this.revocations.has(edgeId)) {
      throw new Error(`already revoked: ${edgeId}`);
    }
    const statement = {
      edgeId,
      revokedBy,
      timestamp: new Date().toISOString()
    };
    const payload = JSON.stringify(statement);
    const signature = crypto.sign(null, Buffer.from(payload), privateKeyPem);
    this.revocations.set(edgeId, {
      ...statement,
      signature: signature.toString("base64")
    });
  }

  getActiveEdges() {
    const active = [];
    for (const [id, edge] of this.edges) {
      if (!this.revocations.has(id)) active.push(edge);
    }
    return active;
  }

  allEdges() { return [...this.edges.values()]; }
  allRevocations() { return [...this.revocations.values()]; }
  exportPublicRoot() { return this.rootPublicKeyPem; }
}
