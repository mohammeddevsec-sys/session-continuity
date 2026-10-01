import fs from "fs";
import path from "path";
import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";
import { sha256File } from "../core/hash.js";

const GENERATED = new Set(["manifest.json","SHA256SUMS.txt","BUNDLE_ROOT_SHA256.txt"]);

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text),"utf8")).digest("hex").toLowerCase();
}

function safeName(name) {
  if (typeof name !== "string" || !name.length || name.includes("/") || name.includes("\\") || name.includes("\0") || name === "." || name === ".." || path.basename(name) !== name) {
    throw new Error(`EVIDENCE_FILENAME_UNSAFE:${name}`);
  }
  return name;
}

function writeNoBom(filePath, text) {
  fs.writeFileSync(filePath, Buffer.from(String(text),"utf8"));
}

export function writeEvidenceBundle(outDir, payload) {
  if (!outDir || typeof outDir !== "string") throw new Error("BUNDLE_OUTDIR_INVALID");
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("BUNDLE_PAYLOAD_INVALID");

  fs.mkdirSync(outDir,{recursive:true});

  const primary = Object.keys(payload).map(safeName).filter(name => !GENERATED.has(name)).sort();

  for (const name of primary) {
    const value = payload[name];
    const text = typeof value === "string" ? value : canonicalStringify(value) + "\n";
    writeNoBom(path.join(outDir,name),text);
  }

  const manifest = {
    schema_id: "session-continuity.evidence.manifest.v1",
    version: 1,
    files: primary
  };

  const manifestText = canonicalStringify(manifest) + "\n";
  writeNoBom(path.join(outDir,"manifest.json"),manifestText);

  const protectedFiles = [...primary,"manifest.json"].sort();
  const protectedSums = protectedFiles.map(name => `${sha256File(path.join(outDir,name)).toLowerCase()} ${name}`);
  const bundleRoot = sha256Text(protectedSums.join("\n") + "\n");

  writeNoBom(path.join(outDir,"BUNDLE_ROOT_SHA256.txt"),bundleRoot + "\n");

  const finalFiles = [...protectedFiles,"BUNDLE_ROOT_SHA256.txt"].sort();
  const finalSums = finalFiles.map(name => `${sha256File(path.join(outDir,name)).toLowerCase()} ${name}`);
  writeNoBom(path.join(outDir,"SHA256SUMS.txt"),finalSums.join("\n") + "\n");

  return Object.freeze({
    schema_id: manifest.schema_id,
    bundle_root_sha256: bundleRoot,
    protected_files: protectedFiles,
    final_files: finalFiles
  });
}

export function verifyEvidenceBundle(bundleDir) {
  if (!fs.existsSync(bundleDir)) throw new Error("BUNDLE_NOT_FOUND");

  const manifestPath = path.join(bundleDir,"manifest.json");
  const sumsPath = path.join(bundleDir,"SHA256SUMS.txt");
  const rootPath = path.join(bundleDir,"BUNDLE_ROOT_SHA256.txt");

  if (!fs.existsSync(manifestPath)) throw new Error("MANIFEST_MISSING");
  if (!fs.existsSync(sumsPath)) throw new Error("SUMS_MISSING");
  if (!fs.existsSync(rootPath)) throw new Error("BUNDLE_ROOT_MISSING");

  const manifest = JSON.parse(fs.readFileSync(manifestPath,"utf8"));
  if (manifest.schema_id !== "session-continuity.evidence.manifest.v1") throw new Error("MANIFEST_SCHEMA_INVALID");
  if (!Array.isArray(manifest.files)) throw new Error("MANIFEST_FILES_INVALID");

  const lines = fs.readFileSync(sumsPath,"utf8").split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  const sums = new Map();

  for (const line of lines) {
    const m = line.match(/^([0-9a-f]{64})\s+(.+)$/i);
    if (!m) throw new Error("SUM_LINE_INVALID");
    sums.set(m[2],m[1].toLowerCase());
  }

  const protectedFiles = [...manifest.files,"manifest.json"].sort();
  const protectedSums = [];

  for (const name of protectedFiles) {
    safeName(name);
    const fp = path.join(bundleDir,name);
    if (!fs.existsSync(fp)) throw new Error(`FILE_MISSING:${name}`);
    const actual = sha256File(fp).toLowerCase();
    if (sums.get(name) !== actual) throw new Error(`HASH_MISMATCH:${name}`);
    protectedSums.push(`${actual} ${name}`);
  }

  const expectedRoot = sha256Text(protectedSums.join("\n") + "\n");
  const storedRoot = fs.readFileSync(rootPath,"utf8").trim().toLowerCase();

  if (expectedRoot !== storedRoot) throw new Error("BUNDLE_ROOT_MISMATCH");

  return Object.freeze({
    verified: true,
    bundle_root_sha256: storedRoot,
    protected_files: protectedFiles
  });
}
