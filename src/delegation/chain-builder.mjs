import crypto from "node:crypto";

export const MAX_DEPTH = 5;

export class DelegationChain {
  constructor(privateKeyPem) {
    if (!privateKeyPem || !privateKeyPem.includes("PRIVATE KEY")) {
      throw new Error("privateKeyPem must be a PEM-encoded Ed25519 private key");
    }
    this.privateKeyPem = privateKeyPem;
    this.links = [];
  }

  static generateKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    return {
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" })
    };
  }

  static createRoot(privateKeyPem, subjectId) {
    const chain = new DelegationChain(privateKeyPem);
    chain.links.push({
      subject: subjectId,
      scope: [],
      depth: 0,
      parentHash: null
    });
    return chain;
  }

  delegate(subjectId, scope = []) {
    if (this.links.length >= MAX_DEPTH) {
      throw new Error(`Delegation depth exceeds maximum (${MAX_DEPTH})`);
    }
    const parent = this.links[this.links.length - 1];
    const parentHash = this._hashLink(parent);
    this.links.push({
      subject: subjectId,
      scope: Array.isArray(scope) ? scope : [scope],
      depth: this.links.length,
      parentHash
    });
    return this;
  }

  _hashLink(link) {
    const data = JSON.stringify({
      subject: link.subject,
      scope: link.scope,
      depth: link.depth,
      parentHash: link.parentHash
    });
    return crypto.createHash("sha256").update(data).digest("hex");
  }

  seal() {
    const payload = {
      version: "1.0.0",
      algorithm: "ed25519",
      links: this.links.map(l => ({
        subject: l.subject,
        scope: l.scope,
        depth: l.depth,
        parentHash: l.parentHash
      }))
    };
    const canonical = JSON.stringify(payload);
    const signature = crypto.sign(null, Buffer.from(canonical), this.privateKeyPem);
    payload.signature = signature.toString("base64");
    return payload;
  }

  toJSON() { return JSON.stringify(this.seal()); }
  toBase64() { return Buffer.from(this.toJSON(), "utf8").toString("base64"); }
}
