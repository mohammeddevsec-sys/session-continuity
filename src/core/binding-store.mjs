import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { verifyParentBinding } from "./parent-binding.mjs";

const GENESIS_HASH = "GENESIS";

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(Buffer.from(input, "utf8")).digest("hex");
}

export class BindingStore {
  constructor(storePath) {
    if (!storePath || typeof storePath !== "string") {
      throw new Error("BindingStore: storePath required");
    }
    this.storePath = storePath;
    this._entries = new Map();
    this._lastHash = GENESIS_HASH;
    this._loaded = false;
  }

  load() {
    if (this._loaded) return;
    if (!fs.existsSync(this.storePath)) {
      this._loaded = true;
      return;
    }
    const content = fs.readFileSync(this.storePath, "utf8");
    const lines = content.split("\n").filter(l => l.length > 0);
    let expectedPrev = GENESIS_HASH;
    for (let i = 0; i < lines.length; i++) {
      let entry;
      try {
        entry = JSON.parse(lines[i]);
      } catch (e) {
        throw new Error("BindingStore: malformed line " + (i + 1));
      }
      if (entry.prev_hash !== expectedPrev) {
        throw new Error("BindingStore: chain break at line " + (i + 1));
      }
      const { self_hash, ...rest } = entry;
      const expectedSelf = sha256Hex(canonicalize(rest));
      if (self_hash !== expectedSelf) {
        throw new Error("BindingStore: self_hash mismatch at line " + (i + 1));
      }
      this._entries.set(entry.binding_id, entry);
      expectedPrev = self_hash;
    }
    this._lastHash = expectedPrev;
    this._loaded = true;
  }

  isConsumed(bindingId) {
    this.load();
    return this._entries.has(bindingId);
  }

  size() {
    this.load();
    return this._entries.size;
  }

  consume(bindingId, metadata = {}) {
    this.load();
    if (typeof bindingId !== "string" || bindingId.length === 0) {
      return { consumed: false, reason: "INVALID_BINDING_ID" };
    }
    if (this._entries.has(bindingId)) {
      return { consumed: false, reason: "ALREADY_CONSUMED" };
    }

    const entry = {
      binding_id: bindingId,
      consumed_at: Date.now(),
      metadata,
      prev_hash: this._lastHash
    };

    const self_hash = sha256Hex(canonicalize(entry));
    const finalEntry = { ...entry, self_hash };

    this._appendLine(finalEntry);

    this._entries.set(bindingId, finalEntry);
    this._lastHash = self_hash;

    return { consumed: true, entry: finalEntry };
  }

  _appendLine(entry) {
    const dir = path.dirname(this.storePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const line = JSON.stringify(entry) + "\n";
    const fd = fs.openSync(this.storePath, "a");
    try {
      fs.writeSync(fd, line, null, "utf8");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }
}

export function consumeAndVerifyBinding({
  binding,
  parentPublicKeyPem,
  presentedChallenge,
  store,
  nowMs = Date.now(),
  metadata = {}
}) {
  if (!store || !(store instanceof BindingStore)) {
    return { valid: false, reason: "MISSING_STORE" };
  }

  const verification = verifyParentBinding({
    binding,
    parentPublicKeyPem,
    presentedChallenge,
    nowMs
  });
  if (!verification.valid) return verification;

  const consumeResult = store.consume(verification.binding_id, metadata);
  if (!consumeResult.consumed) {
    return {
      valid: false,
      reason: consumeResult.reason === "ALREADY_CONSUMED"
        ? "BINDING_ALREADY_CONSUMED"
        : consumeResult.reason
    };
  }

  return {
    valid: true,
    reason: "BINDING_CONSUMED",
    binding_id: verification.binding_id,
    parent_sequence: verification.parent_sequence,
    next_sequence: verification.next_sequence
  };
}
