import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

const GUARD_ROOT_ENV = "SC_FORK_GUARD_ROOT";

function getGuardRoot() {
  const envRoot = process.env[GUARD_ROOT_ENV];
  if (envRoot && typeof envRoot === "string" && envRoot.length > 0) return envRoot;
  return path.join(os.tmpdir(), "sc-fork-guard");
}

function guardKey(sessionId, parentSequence) {
  const raw = String(sessionId) + "|" + String(parentSequence);
  return crypto.createHash("sha256").update(raw, "utf8").digest("hex");
}

export function acquireForkGuard({ sessionId, parentSequence, metadata = {} }) {
  if (!sessionId || typeof parentSequence !== "number" || parentSequence < 0) {
    return { allowed: false, reason: "FORK_GUARD_INVALID_INPUT" };
  }
  const root = getGuardRoot();
  const key = guardKey(sessionId, parentSequence);
  const lockFile = path.join(root, key + ".lock");

  try {
    fs.mkdirSync(root, { recursive: true });
  } catch (e) {
    return { allowed: false, reason: "FORK_GUARD_MKDIR_FAILED: " + (e && e.message) };
  }

  try {
    const fd = fs.openSync(lockFile, "wx");
    try {
      fs.writeSync(fd, JSON.stringify({
        session_id: sessionId,
        parent_sequence: parentSequence,
        acquired_at: Date.now(),
        metadata
      }));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return { allowed: true, reason: "FORK_GUARD_ACQUIRED", lock_file: lockFile };
  } catch (e) {
    if (e && e.code === "EEXIST") {
      return { allowed: false, reason: "FORK_GUARD_ALREADY_HELD", lock_file: lockFile };
    }
    return { allowed: false, reason: "FORK_GUARD_ERROR: " + (e && e.message) };
  }
}

export function releaseForkGuard({ sessionId, parentSequence }) {
  const root = getGuardRoot();
  const key = guardKey(sessionId, parentSequence);
  const lockFile = path.join(root, key + ".lock");
  try {
    fs.unlinkSync(lockFile);
    return { released: true };
  } catch (e) {
    if (e && e.code === "ENOENT") return { released: false, reason: "NOT_HELD" };
    return { released: false, reason: (e && e.message) || String(e) };
  }
}

export function isForkGuardHeld({ sessionId, parentSequence }) {
  const root = getGuardRoot();
  const key = guardKey(sessionId, parentSequence);
  const lockFile = path.join(root, key + ".lock");
  return fs.existsSync(lockFile);
}
