import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

const ENV_ROOT = "SC_FORK_REGISTRY_ROOT";
const DEFAULT_SUBDIR = "sc-fork-registry";

function registryRoot() {
  const env = process.env[ENV_ROOT];
  if (env && typeof env === "string" && env.length > 0) {
    return path.join(env, DEFAULT_SUBDIR);
  }
  return path.join(os.tmpdir(), DEFAULT_SUBDIR);
}

function slotHash(anchorFingerprint, parentSequence) {
  const raw = String(anchorFingerprint) + "|" + String(parentSequence);
  return crypto.createHash("sha256").update(raw, "utf8").digest("hex");
}

function slotPath(anchorFingerprint, parentSequence) {
  return path.join(registryRoot(), slotHash(anchorFingerprint, parentSequence) + ".slot");
}

export function claimContinuationSlot({ anchorFingerprint, parentSequence, metadata = {} }) {
  if (typeof anchorFingerprint !== "string" || anchorFingerprint.length === 0) {
    return { claimed: false, reason: "INVALID_ANCHOR_FINGERPRINT" };
  }
  if (!Number.isInteger(parentSequence) || parentSequence < 0) {
    return { claimed: false, reason: "INVALID_PARENT_SEQUENCE" };
  }

  const root = registryRoot();
  try {
    fs.mkdirSync(root, { recursive: true });
  } catch (e) {
    return { claimed: false, reason: "REGISTRY_MKDIR_FAILED: " + e.message };
  }

  const target = slotPath(anchorFingerprint, parentSequence);

  try {
    const fd = fs.openSync(target, "wx");
    try {
      fs.writeSync(fd, JSON.stringify({
        anchor_fingerprint: anchorFingerprint,
        parent_sequence: parentSequence,
        claimed_at: Date.now(),
        metadata
      }));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return { claimed: true, reason: "SLOT_CLAIMED", slot_path: target };
  } catch (e) {
    if (e.code === "EEXIST") {
      return { claimed: false, reason: "FORK_DETECTED", slot_path: target };
    }
    return { claimed: false, reason: "REGISTRY_ERROR: " + e.message };
  }
}

export function releaseContinuationSlot({ anchorFingerprint, parentSequence }) {
  const target = slotPath(anchorFingerprint, parentSequence);
  try {
    fs.unlinkSync(target);
    return { released: true };
  } catch (e) {
    if (e.code === "ENOENT") return { released: false, reason: "NOT_HELD" };
    return { released: false, reason: e.message };
  }
}

export function isSlotHeld({ anchorFingerprint, parentSequence }) {
  return fs.existsSync(slotPath(anchorFingerprint, parentSequence));
}
