import crypto from "node:crypto";

export const MAX_DEPTH = 5;

export class ChainVerifier {
  constructor(publicKeyPem) {
    if (!publicKeyPem || !publicKeyPem.includes("PUBLIC KEY")) {
      throw new Error("publicKeyPem must be a PEM-encoded Ed25519 public key");
    }
    this.publicKeyPem = publicKeyPem;
  }

  verify(tokenBase64, options = {}) {
    try {
      const json = Buffer.from(tokenBase64, "base64").toString("utf8");
      const parsed = JSON.parse(json);

      if (!parsed.links || !Array.isArray(parsed.links)) {
        return { authorized: false, error: "malformed token: no links" };
      }
      if (parsed.links.length > MAX_DEPTH) {
        return { authorized: false, error: "depth exceeds maximum" };
      }
      if (!parsed.signature) {
        return { authorized: false, error: "missing signature" };
      }

      // Verify signature over the payload (without signature field)
      const signatureB64 = parsed.signature;
      const payloadForSigning = {
        version: parsed.version,
        algorithm: parsed.algorithm,
        links: parsed.links
      };
      const canonical = JSON.stringify(payloadForSigning);

      const sigBuf = Buffer.from(signatureB64, "base64");
      const ok = crypto.verify(
        null,
        Buffer.from(canonical),
        this.publicKeyPem,
        sigBuf
      );
      if (!ok) {
        return { authorized: false, error: "signature verification failed" };
      }

      // Subject check
      if (options.requiredSubject) {
        const found = parsed.links.some(l => l.subject === options.requiredSubject);
        if (!found) {
          return { authorized: false, error: `subject not found: ${options.requiredSubject}` };
        }
      }

      // Scope check
      if (options.requiredScope) {
        const required = Array.isArray(options.requiredScope) ? options.requiredScope : [options.requiredScope];
        const last = parsed.links[parsed.links.length - 1];
        for (const req of required) {
          if (!last.scope.includes(req)) {
            return { authorized: false, error: `scope missing: ${req}` };
          }
        }
      }

      return {
        authorized: true,
        depth: parsed.links.length - 1,
        subject: parsed.links[parsed.links.length - 1].subject,
        error: null
      };
    } catch (e) {
      return { authorized: false, error: (e && e.message) ? e.message : String(e) };
    }
  }
}
