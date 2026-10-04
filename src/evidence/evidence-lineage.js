import fs from "fs";
import path from "path";
import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex").toLowerCase();
}

function hashEntry(entry) {
  return sha256Text(canonicalStringify(entry) + "\n");
}

function merkleRoot(entryHashes) {
  if (entryHashes.length === 0) return "";

  let level = entryHashes.map(h =>
    crypto.createHash("sha256")
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(h, "hex")]))
      .digest()
  );

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) {
        next.push(level[i]);
      } else {
        next.push(
          crypto.createHash("sha256")
            .update(Buffer.concat([Buffer.from([0x01]), level[i], level[i + 1]]))
            .digest()
        );
      }
    }
    level = next;
  }

  return level[0].toString("hex").toLowerCase();
}

function loadLines(filePath) {
  if (!fs.existsSync(filePath)) return [];

  return fs.readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

function calculateState(records) {
  let previousRoot = "";
  const entryHashes = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    if (!record || typeof record !== "object" || !record.entry) {
      throw new Error(`LINEAGE_ENTRY_INVALID:${i}`);
    }

    const entry = record.entry;

    if (String(entry.prev_root_sha256 || "") !== previousRoot) {
      throw new Error(`LINEAGE_PREV_ROOT_MISMATCH:${i}`);
    }

    const expectedEntryHash = hashEntry(entry);

    if (String(record.entry_sha256 || "").toLowerCase() !== expectedEntryHash) {
      throw new Error(`LINEAGE_ENTRY_HASH_MISMATCH:${i}`);
    }

    previousRoot = sha256Text(`${previousRoot}|${expectedEntryHash}`);
    entryHashes.push(expectedEntryHash);
  }

  return {
    height: records.length,
    lineage_root_sha256: previousRoot,
    merkle_root_sha256: merkleRoot(entryHashes),
    entry_hashes: entryHashes
  };
}

export function appendEvidenceLineage(lineageDir, payload) {
  if (!lineageDir || typeof lineageDir !== "string") {
    throw new Error("LINEAGE_DIR_INVALID");
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("LINEAGE_PAYLOAD_INVALID");
  }

  fs.mkdirSync(lineageDir, { recursive: true });

  const logPath = path.join(lineageDir, "LINEAGE.ndjson");
  const records = loadLines(logPath);
  const current = calculateState(records);
  const previousRoot = current.lineage_root_sha256;

  const entry = {
    schema_id: "session-continuity.lineage.entry.v1",
    version: 1,
    prev_root_sha256: previousRoot,
    session_id: String(payload.session_id || ""),
    decision: String(payload.decision || ""),
    reason: String(payload.reason || ""),
    sequence: Number(payload.sequence),
    evidence_fingerprint_sha256: String(payload.evidence_fingerprint_sha256 || ""),
    bundle_root_sha256: String(payload.bundle_root_sha256 || ""),
    timestamp: String(payload.timestamp || "")
  };

  const entryHash = hashEntry(entry);

  const record = {
    entry,
    entry_sha256: entryHash
  };

  fs.appendFileSync(
    logPath,
    canonicalStringify(record) + "\n",
    "utf8"
  );

  const verified = calculateState(loadLines(logPath));

  if (verified.lineage_root_sha256 !== sha256Text(`${previousRoot}|${entryHash}`)) {
    throw new Error("LINEAGE_POST_APPEND_MISMATCH");
  }

  const head = {
    schema_id: "session-continuity.lineage.head.v1",
    version: 1,
    lineage_root_sha256: verified.lineage_root_sha256,
    merkle_root_sha256: verified.merkle_root_sha256,
    height: verified.height
  };

  fs.writeFileSync(
    path.join(lineageDir, "HEAD.json"),
    canonicalStringify(head) + "\n",
    "utf8"
  );

  return Object.freeze({
    entry_sha256: entryHash,
    lineage_root_sha256: verified.lineage_root_sha256,
    merkle_root_sha256: verified.merkle_root_sha256,
    height: verified.height
  });
}

export function verifyEvidenceLineage(lineageDir) {
  const logPath = path.join(lineageDir, "LINEAGE.ndjson");
  const headPath = path.join(lineageDir, "HEAD.json");

  if (!fs.existsSync(logPath)) throw new Error("LINEAGE_LOG_MISSING");
  if (!fs.existsSync(headPath)) throw new Error("LINEAGE_HEAD_MISSING");

  const records = loadLines(logPath);
  const state = calculateState(records);
  const head = JSON.parse(fs.readFileSync(headPath, "utf8"));

  if (head.lineage_root_sha256 !== state.lineage_root_sha256) {
    throw new Error("HEAD_LINEAGE_ROOT_MISMATCH");
  }

  if (head.merkle_root_sha256 !== state.merkle_root_sha256) {
    throw new Error("HEAD_MERKLE_ROOT_MISMATCH");
  }

  if (Number(head.height) !== state.height) {
    throw new Error("HEAD_HEIGHT_MISMATCH");
  }

  return Object.freeze({
    verified: true,
    height: state.height,
    lineage_root_sha256: state.lineage_root_sha256,
    merkle_root_sha256: state.merkle_root_sha256
  });
}
