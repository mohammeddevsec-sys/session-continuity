import fs from "fs";
import path from "path";
import crypto from "crypto";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex").toLowerCase();
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex").toLowerCase();
}

function hex64(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
}

function safeName(name) {
  if (
    typeof name !== "string" ||
    !name.length ||
    name.includes("/") ||
    name.includes("\\") ||
    name.includes("\0") ||
    name === "." ||
    name === ".." ||
    path.basename(name) !== name
  ) {
    throw new Error("UNSAFE_FILE_NAME");
  }
}

function verifyBundle(bundleDir) {
  const manifestPath = path.join(bundleDir, "manifest.json");
  const sumsPath = path.join(bundleDir, "SHA256SUMS.txt");
  const rootPath = path.join(bundleDir, "BUNDLE_ROOT_SHA256.txt");

  if (!fs.existsSync(manifestPath)) throw new Error("MANIFEST_MISSING");
  if (!fs.existsSync(sumsPath)) throw new Error("SUMS_MISSING");
  if (!fs.existsSync(rootPath)) throw new Error("BUNDLE_ROOT_MISSING");

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  if (manifest.schema_id !== "session-continuity.evidence.manifest.v1") {
    throw new Error("MANIFEST_SCHEMA_INVALID");
  }

  if (!Array.isArray(manifest.files)) {
    throw new Error("MANIFEST_FILES_INVALID");
  }

  const sums = new Map();

  for (const line of fs.readFileSync(sumsPath, "utf8").split(/\r?\n/).filter(Boolean)) {
    const match = line.match(/^([0-9a-f]{64})\s+(.+)$/i);
    if (!match) throw new Error("SUM_LINE_INVALID");
    sums.set(match[2], match[1].toLowerCase());
  }

  const protectedFiles = [...manifest.files, "manifest.json"].sort();
  const protectedSums = [];

  for (const name of protectedFiles) {
    safeName(name);

    const filePath = path.join(bundleDir, name);
    if (!fs.existsSync(filePath)) {
      throw new Error(`FILE_MISSING:${name}`);
    }

    const actual = sha256File(filePath);

    if (sums.get(name) !== actual) {
      throw new Error(`HASH_MISMATCH:${name}`);
    }

    protectedSums.push(`${actual} ${name}`);
  }

  const computedRoot = sha256Text(protectedSums.join("\n") + "\n");
  const storedRoot = fs.readFileSync(rootPath, "utf8").trim().toLowerCase();

  if (!hex64(storedRoot)) throw new Error("BUNDLE_ROOT_INVALID");
  if (computedRoot !== storedRoot) throw new Error("BUNDLE_ROOT_MISMATCH");

  return storedRoot;
}

function verifyLineage(lineageDir, expectedBundleRoot) {
  const logPath = path.join(lineageDir, "LINEAGE.ndjson");
  const headPath = path.join(lineageDir, "HEAD.json");

  if (!fs.existsSync(logPath)) throw new Error("LINEAGE_LOG_MISSING");
  if (!fs.existsSync(headPath)) throw new Error("LINEAGE_HEAD_MISSING");

  const records = fs.readFileSync(logPath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => JSON.parse(line));

  const head = JSON.parse(fs.readFileSync(headPath, "utf8"));

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

    if (
      expectedBundleRoot !== undefined &&
      String(entry.bundle_root_sha256 || "").toLowerCase() !== String(expectedBundleRoot).toLowerCase()
    ) {
      throw new Error(`LINEAGE_BUNDLE_ROOT_MISMATCH:${i}`);
    }

    const entryHash = sha256Text(
      JSON.stringify(
        Object.keys(entry).sort().reduce((out, key) => {
          out[key] = entry[key];
          return out;
        }, {})
      ) + "\n"
    );

    if (String(record.entry_sha256 || "").toLowerCase() !== entryHash) {
      throw new Error(`LINEAGE_ENTRY_HASH_MISMATCH:${i}`);
    }

    previousRoot = sha256Text(`${previousRoot}|${entryHash}`);
    entryHashes.push(entryHash);
  }

  let level = entryHashes.map(hash =>
    crypto.createHash("sha256")
      .update(Buffer.concat([
        Buffer.from([0x00]),
        Buffer.from(hash, "hex")
      ]))
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
            .update(Buffer.concat([
              Buffer.from([0x01]),
              level[i],
              level[i + 1]
            ]))
            .digest()
        );
      }
    }

    level = next;
  }

  const merkleRoot = level.length
    ? level[0].toString("hex").toLowerCase()
    : "";

  if (head.lineage_root_sha256 !== previousRoot) {
    throw new Error("LINEAGE_ROOT_MISMATCH");
  }

  if (head.merkle_root_sha256 !== merkleRoot) {
    throw new Error("MERKLE_ROOT_MISMATCH");
  }

  if (Number(head.height) !== records.length) {
    throw new Error("LINEAGE_HEIGHT_MISMATCH");
  }

  return {
    height: records.length,
    lineage_root_sha256: previousRoot,
    merkle_root_sha256: merkleRoot
  };
}

export function verifyEvidenceProof(bundleDir, lineageDir) {
  const bundleRoot = verifyBundle(bundleDir);
  const lineage = verifyLineage(lineageDir, bundleRoot);

  return Object.freeze({
    verified: true,
    bundle_root_sha256: bundleRoot,
    lineage_root_sha256: lineage.lineage_root_sha256,
    merkle_root_sha256: lineage.merkle_root_sha256,
    lineage_height: lineage.height
  });
}
