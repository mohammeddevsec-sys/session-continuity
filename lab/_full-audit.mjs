import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const TMP = path.join(ROOT, "lab", "_full_audit_tmp");
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

const pass = [], fail = [];
function check(name, cond) {
  console.log(name + "=" + (cond ? "PASS" : "FAIL"));
  if (cond) pass.push(name); else fail.push(name);
}

function sha256File(p){ return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex").toUpperCase(); }

// ===== A INTEGRITY =====
console.log("--- A INTEGRITY ---");
const expected = {
  "src\\core\\canonical.js":                          "8EC372C56A4A40941DDC167CAFFFF576079A391DD54A2ADC73BBC40E0984A8B8",
  "src\\core\\continuity-engine.js":                  "FDE44B2005E1C7E50ABB62BF366754455DE39D1C7D93273E8EA406C61D49B7AC",
  "src\\core\\durable-replay-state.js":               "DF3A232652D9E3FF22800DDCA91A6DAD476368092D29B19E5503361B987A6497",
  "src\\evidence\\proof-signature.js":                "B3D2D393C9594A6FD7A899714FC3B5014C59666694C68C7ED7D2C45730F20795",
  "src\\evidence\\session-provenance-certificate.js": "5F65E0B20A0D47F258F0B95E8024EB3755FC4975C66C5D6524189BDCD64356F2",
  "src\\core\\canonical-v1_1.js":                     "4DEA93DDDC5C4E885E10D6968F9E4C9F8A9EDBC4F46D04A04A8D30ED66A71FBF",
  "src\\core\\continuity-proof-v1_1.js":              "01F891AB59C497E865383CFB9F3111D774161F7962521F73A96927BC6E246722",
  "src\\core\\sequence-guard-v1_1.js":                "13A86DAAF4728AE7F032F48BF9A96E3CBCCB782B7D78DB928C40D117AE14EBF1",
  "src\\core\\durable-sequence-guard-v1_1.js":        "039E6536E8AA1B79B65BCE6400A4AEEB3AF9613C35A9005F1BEE84FF67378030",
  "src\\evidence\\proof-signature-v1_1.js":           "5659946DF7C566B046EF287A11142F24ED4216F9A5F186E39CA5C6C75352A0EC",
  "src\\evidence\\trusted-proof-verifier-v1_1.js":    "CE06E1535952CE71D49103911173BBAF8A3344E7BAF57EE8B9F43550487B872C",
  "src\\evidence\\witness-v1_1.js": "628F6A6084EA8017CCF07106A6114DC6756FEFD0E315DF0F842CB001169EB9FD",
  "src\\evidence\\portable-package-v1_1.js":          "C75B7AD0DCFEFFA43E211BA34326929565474F1E9B954D0BEF2A34FC7E9CFBDC",
  "src\\evidence\\key-lifecycle-v1_1.js":             "B59DE1144111069C7A977A2486F081E37DC9D0F9A88ED730D19528071CBA07A9",
  "package.json":                                     "A300614148FFB7E675B08F5079C10018C03F2E25D950FAAD2A3DEE3B8C4BE10C"
};
let integrityFail = 0;
for (const rel of Object.keys(expected)) {
  const full = path.join(ROOT, rel);
  let actual = "READ_ERROR";
  try { actual = sha256File(full); } catch(e) {}
  const ok = actual === expected[rel];
  if (!ok) integrityFail++;
  console.log("INTEGRITY_" + rel.replace(/[\\\/\.\-]/g, "_") + "=" + (ok ? "PASS" : "FAIL"));
}
check("A_INTEGRITY_ALL", integrityFail === 0);

// ===== B V1 REGRESSION =====
console.log("--- B V1 REGRESSION ---");
let v1Out = "";
try { v1Out = execFileSync(process.execPath, ["test\\run-all-tests.mjs"], { cwd: ROOT, encoding: "utf8", timeout: 600000 }); }
catch(e) { v1Out = String(e.stdout || "") + String(e.stderr || ""); }
const v1Result = (v1Out.match(/FINAL_REGRESSION=([A-Z]+)/) || [])[1] || "MISSING";
const v1Tests = (v1Out.match(/TESTS=(\d+)/) || [])[1] || "0";
const v1State = (v1Out.match(/PRODUCT_STATE=([A-Z_]+)/) || [])[1] || "MISSING";
console.log("B_V1_FINAL_REGRESSION=" + v1Result);
console.log("B_V1_TESTS=" + v1Tests);
console.log("B_V1_STATE=" + v1State);
check("B_V1_REGRESSION", v1Result === "PASS" && v1State === "STABLE_BASELINE");

// ===== C V1.1 REGRESSION =====
console.log("--- C V1.1 REGRESSION ---");
let v11Out = "";
try { v11Out = execFileSync(process.execPath, ["lab\\v1_1-regression-gate.mjs"], { cwd: ROOT, encoding: "utf8", timeout: 600000 }); }
catch(e) { v11Out = String(e.stdout || "") + String(e.stderr || ""); }
const v11Pass = (v11Out.match(/TOTAL_PASS=(\d+)/) || [])[1] || "0";
const v11Fail = (v11Out.match(/TOTAL_FAIL=(\d+)/) || [])[1] || "0";
const v11Result = (v11Out.match(/V1_1_REGRESSION=([A-Z]+)/) || [])[1] || "MISSING";
console.log("C_V1_1_TOTAL_PASS=" + v11Pass);
console.log("C_V1_1_TOTAL_FAIL=" + v11Fail);
console.log("C_V1_1_RESULT=" + v11Result);
check("C_V1_1_REGRESSION", v11Result === "PASS" && v11Fail === "0");

// ===== D RFC 8032 GOLDEN VECTOR =====
console.log("--- D RFC 8032 ---");
function ed25519FromSeed(seedHex) {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex")
  ]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey };
}
const rfc8032seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const rfc8032pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const rfc8032sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
try {
  const kp = ed25519FromSeed(rfc8032seed);
  const pubDer = kp.publicKey.export({ type: "spki", format: "der" });
  const pubHex = pubDer.slice(-32).toString("hex");
  check("D_RFC8032_PUBLIC_KEY", pubHex === rfc8032pub);
  const sig = crypto.sign(null, Buffer.alloc(0), kp.privateKey);
  check("D_RFC8032_SIGNATURE", sig.toString("hex") === rfc8032sig);
  const verify = crypto.verify(null, Buffer.alloc(0), kp.publicKey, Buffer.from(rfc8032sig, "hex"));
  check("D_RFC8032_VERIFY", verify === true);
} catch(e) {
  check("D_RFC8032_PUBLIC_KEY", false);
  check("D_RFC8032_SIGNATURE", false);
  check("D_RFC8032_VERIFY", false);
}

// ===== E JCS PROFILE V1.1 =====
console.log("--- E JCS PROFILE V1.1 ---");
const { jcsCanonicalize } = await import("file:///" + path.join(ROOT, "src/core/canonical-v1_1.js").replace(/\\/g, "/"));
try { jcsCanonicalize(-0); check("E_NEGATIVE_ZERO_REJECTED", false); } catch(e) { check("E_NEGATIVE_ZERO_REJECTED", e.message === "JCS_NEGATIVE_ZERO_REJECTED"); }
try { jcsCanonicalize(NaN); check("E_NAN_REJECTED", false); } catch(e) { check("E_NAN_REJECTED", e.message === "JCS_NUMBER_INVALID"); }
try { jcsCanonicalize(Infinity); check("E_INFINITY_REJECTED", false); } catch(e) { check("E_INFINITY_REJECTED", e.message === "JCS_NUMBER_INVALID"); }
try { jcsCanonicalize("\uD800"); check("E_LONE_SURROGATE_REJECTED", false); } catch(e) { check("E_LONE_SURROGATE_REJECTED", e.message === "JCS_LONE_HIGH_SURROGATE"); }
try {
  const out = jcsCanonicalize({ b: 1, a: 2, nested: { z: true, a: null } });
  check("E_RECURSIVE_SORT", out === "{\"a\":2,\"b\":1,\"nested\":{\"a\":null,\"z\":true}}");
} catch(e) { check("E_RECURSIVE_SORT", false); }

// ===== F UNICODE ORDERING V1 + V1.1 =====
console.log("--- F UNICODE ORDERING ---");
const { canonicalStringify } = await import("file:///" + path.join(ROOT, "src/core/canonical.js").replace(/\\/g, "/"));
try {
  const input = {};
  input["\u20AC"] = "Euro";
  input["\r"] = "CR";
  input["\uFB33"] = "Hebrew";
  input["1"] = "One";
  input["\uD83D\uDE00"] = "Emoji";
  input["\u0080"] = "Control";
  input["\u00F6"] = "ouml";
  const sorted = Object.keys(input).sort();
  const expectedOrder = ["\r", "1", "\u0080", "\u00F6", "\u20AC", "\uD83D\uDE00", "\uFB33"];
  check("F_V1_UTF16_ORDER", JSON.stringify(sorted) === JSON.stringify(expectedOrder));
} catch(e) { check("F_V1_UTF16_ORDER", false); }
try {
  const input = {};
  input["\u20AC"] = "Euro";
  input["\r"] = "CR";
  input["\u00F6"] = "ouml";
  const v1Out = canonicalStringify(input);
  const v11Out = jcsCanonicalize(input);
  check("F_V1_V11_AGREE", v1Out === v11Out);
} catch(e) { check("F_V1_V11_AGREE", false); }

// ===== G WITNESS EQUIVOCATION =====
console.log("--- G WITNESS EQUIVOCATION ---");
const { createWitnessIdentity, createDurableWitness, witnessObserve, detectWitnessEquivocation } = await import("file:///" + path.join(ROOT, "src/evidence/witness-v1_1.js").replace(/\\/g, "/"));
const wDir = path.join(TMP, "witness");
const wId = createWitnessIdentity({ keyId: "audit-witness" });
const w = createDurableWitness({ directory: wDir, witnessDomainId: "audit-domain", identity: wId });
const rootA = "a".repeat(64);
const h1A = "1".repeat(64);
const h1B = "2".repeat(64);
const ts = "2026-09-17T00:00:00.000Z";
const r1 = witnessObserve(w, { continuityRoot: rootA, sequence: 1, continuityHash: h1A, proofHash: "f".repeat(64), issuedAt: ts });
check("G_WITNESS_FIRST", r1.result === "ADVANCED");
const r1Fork = witnessObserve(w, { continuityRoot: rootA, sequence: 1, continuityHash: h1B, proofHash: "f".repeat(64), issuedAt: ts });
check("G_WITNESS_FORK_DETECTED", r1Fork.result === "EQUIVOCATION_FORK");
check("G_WITNESS_FORK_HAS_RECEIPT", r1Fork.receipt !== null && r1Fork.receipt !== undefined);
if (r1.receipt && r1Fork.receipt) {
  const eq = detectWitnessEquivocation(r1.receipt, r1Fork.receipt);
  check("G_WITNESS_EQUIVOCATION_PROVEN", eq.equivocation === true && eq.reason === "EQUIVOCATION_FORK");
} else { check("G_WITNESS_EQUIVOCATION_PROVEN", false); }

// ===== H KEY LIFECYCLE =====
console.log("--- H KEY LIFECYCLE ---");
const { createKeyLifecycleStore, registerKey, retireKey, revokeKey, verifyKeyForProof } = await import("file:///" + path.join(ROOT, "src/evidence/key-lifecycle-v1_1.js").replace(/\\/g, "/"));
const kl = createKeyLifecycleStore();
const fpA = "a".repeat(64), fpB = "b".repeat(64), fpC = "c".repeat(64);
registerKey(kl, fpA, { valid_from: "2026-09-01T00:00:00.000Z", valid_until: "2027-09-01T00:00:00.000Z" });
registerKey(kl, fpB, { valid_from: "2026-09-01T00:00:00.000Z" });
registerKey(kl, fpC, { valid_from: "2026-09-01T00:00:00.000Z", valid_until: "2027-09-01T00:00:00.000Z" });
retireKey(kl, fpB, { retired_at: "2026-09-15T00:00:00.000Z" });
revokeKey(kl, fpC, { revoked_at: "2026-09-16T00:00:00.000Z", compromise_window: { start: "2026-09-10T00:00:00.000Z", end: "2026-09-16T00:00:00.000Z" } });
check("H_ACTIVE_PROOF_VALID", verifyKeyForProof(kl, fpA, "2026-09-15T12:00:00.000Z").valid === true);
check("H_HISTORICAL_RETIRED_VALID", verifyKeyForProof(kl, fpB, "2026-09-10T12:00:00.000Z").valid === true);
check("H_POST_RETIREMENT_REJECTED", verifyKeyForProof(kl, fpB, "2026-09-20T12:00:00.000Z").valid === false);
check("H_COMPROMISE_WINDOW_REJECTED", verifyKeyForProof(kl, fpC, "2026-09-12T12:00:00.000Z").valid === false);
check("H_PRE_COMPROMISE_VALID", verifyKeyForProof(kl, fpC, "2026-09-05T12:00:00.000Z").valid === true);

// ===== I PACKAGE BUILD AND VERIFY =====
console.log("--- I PACKAGE ---");
const { createSigningIdentity, signProof } = await import("file:///" + path.join(ROOT, "src/evidence/proof-signature-v1_1.js").replace(/\\/g, "/"));
const { createTrustAnchorStore, registerTrustAnchor } = await import("file:///" + path.join(ROOT, "src/evidence/trust-anchor.js").replace(/\\/g, "/"));
const { buildPortablePackage, verifyPortablePackage } = await import("file:///" + path.join(ROOT, "src/evidence/portable-package-v1_1.js").replace(/\\/g, "/"));
const { createContinuityRoot, createProofCore, addContinuityHash, verifyProofChain } = await import("file:///" + path.join(ROOT, "src/core/continuity-proof-v1_1.js").replace(/\\/g, "/"));

const signer = createSigningIdentity({ keyId: "audit-signer" });
const packager = createSigningIdentity({ keyId: "audit-packager" });
const signerStore = createTrustAnchorStore();
registerTrustAnchor(signerStore, signer.publicKeySpkiBase64, { version: 1 });
const witnessStore = createTrustAnchorStore();
registerTrustAnchor(witnessStore, wId.publicKeySpkiBase64, { version: 1 });
const packagerStore = createTrustAnchorStore();
registerTrustAnchor(packagerStore, packager.publicKeySpkiBase64, { version: 1 });

const rootObj = createContinuityRoot({ session_id: "s", subject: "u", issuer: "i", auth_time: "2026-09-17T00:00:00.000Z", client_context: { d: "d1" } });
const chain = [];
let parent = null;
const pkgWitnessDir = path.join(TMP, "pkg-witness");
const pkgWitness = createDurableWitness({ directory: pkgWitnessDir, witnessDomainId: "pkg-domain", identity: wId });
const receipts = [];
for (let i = 1; i <= 5; i++) {
  const c = addContinuityHash(createProofCore({
    continuity_root: rootObj.continuity_root, sequence: i, parent_hash: parent,
    state_hash: "1".repeat(64), decision_hash: "2".repeat(64),
    issued_at: "2026-09-17T00:00:0" + i + ".000Z",
    signer_key_id: signer.keyId, policy_fingerprint_sha256: "3".repeat(64)
  }));
  const p = signProof(signer, c);
  chain.push(p);
  parent = p.continuity_hash;
  const wr = witnessObserve(pkgWitness, { continuityRoot: rootObj.continuity_root, sequence: i, continuityHash: p.continuity_hash, proofHash: "f".repeat(64), issuedAt: "2026-09-17T00:00:0" + i + ".000Z" });
  receipts.push(wr.receipt);
}
const trustedChain = verifyProofChain(chain, { expectedContinuityRoot: rootObj.continuity_root, verifySignature: (await import("file:///" + path.join(ROOT, "src/evidence/proof-signature-v1_1.js").replace(/\\/g, "/"))).verifyProofSignature });
check("I_CHAIN_5_PROOFS", trustedChain.verified === true);
const pkg = buildPortablePackage({
  continuityRoot: rootObj.continuity_root, proofChain: chain, witnessReceipts: receipts,
  signerTrustFingerprints: [signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints: [wId.publicKeyFingerprintSha256],
  policyReferences: { policy_fingerprint_sha256: "3".repeat(64) },
  packagerIdentity: packager, createdAt: "2026-09-17T00:01:00.000Z"
});
const pkgVerify = verifyPortablePackage(pkg, { signerTrustStore: signerStore, witnessTrustStore: witnessStore, packagerTrustStore: packagerStore, expectedContinuityRoot: rootObj.continuity_root });
check("I_PACKAGE_VALID", pkgVerify.verified === true && pkgVerify.reason === "PORTABLE_PACKAGE_VALID");

// Adversarial: attacker signs P1 with attacker's key, package re-signed by legit packager
const attackerSigner = createSigningIdentity({ keyId: "audit-attacker" });
const attackerCore = createProofCore({
  continuity_root: rootObj.continuity_root, sequence: 1, parent_hash: null,
  state_hash: "1".repeat(64), decision_hash: "2".repeat(64),
  issued_at: "2026-09-17T00:00:01.000Z",
  signer_key_id: attackerSigner.keyId, policy_fingerprint_sha256: "3".repeat(64)
});
const attackerP1 = signProof(attackerSigner, addContinuityHash(attackerCore));
const attackerChain = [attackerP1, ...chain.slice(1)];
const attackerPkg = buildPortablePackage({
  continuityRoot: rootObj.continuity_root, proofChain: attackerChain, witnessReceipts: receipts,
  signerTrustFingerprints: [signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints: [wId.publicKeyFingerprintSha256],
  policyReferences: {}, packagerIdentity: packager, createdAt: "2026-09-17T00:01:00.000Z"
});
const attackerResult = verifyPortablePackage(attackerPkg, { signerTrustStore: signerStore, witnessTrustStore: witnessStore, packagerTrustStore: packagerStore });
console.log("I_ATTACKER_REASON=" + attackerResult.reason);
check("I_ATTACKER_PROOF_REJECTED", attackerResult.verified === false);

// ===== J SCALE 1000 =====
console.log("--- J SCALE 1000 ---");
const scaleRoot = createContinuityRoot({ session_id: "scale", subject: "u", issuer: "i", auth_time: "2026-09-17T00:00:00.000Z", client_context: {} });
const t0 = Date.now();
const scaleChain = [];
let sp = null;
for (let i = 1; i <= 1000; i++) {
  const c = addContinuityHash(createProofCore({
    continuity_root: scaleRoot.continuity_root, sequence: i, parent_hash: sp,
    state_hash: "1".repeat(64), decision_hash: "2".repeat(64),
    issued_at: "2026-09-17T00:00:00.000Z",
    signer_key_id: signer.keyId, policy_fingerprint_sha256: "3".repeat(64)
  }));
  const p = signProof(signer, c);
  scaleChain.push(p);
  sp = p.continuity_hash;
}
const tBuild = Date.now() - t0;
const t1 = Date.now();
const { verifyProofSignature } = await import("file:///" + path.join(ROOT, "src/evidence/proof-signature-v1_1.js").replace(/\\/g, "/"));
const scaleResult = verifyProofChain(scaleChain, { expectedContinuityRoot: scaleRoot.continuity_root, verifySignature: verifyProofSignature });
const tVerify = Date.now() - t1;
console.log("J_BUILD_MS=" + tBuild);
console.log("J_VERIFY_MS=" + tVerify);
check("J_SCALE_1000_VERIFIED", scaleResult.verified === true && scaleResult.sequence === 1000);
check("J_SCALE_BUILD_UNDER_5S", tBuild < 5000);
check("J_SCALE_VERIFY_UNDER_1S", tVerify < 1000);

// ===== K PACKAGE MANIFEST =====
console.log("--- K PACKAGE MANIFEST ---");
const packageManifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
check("K_PACKAGE_NAME_VERSION", packageManifest.name === "session-continuity-engine" && packageManifest.version === "0.2.0");
check("K_PACKAGE_PRIVATE", packageManifest.private === true);
// ===== VERDICT =====

// ===== VERDICT =====
console.log("--- VERDICT ---");
console.log("TOTAL_PASS=" + pass.length);
console.log("TOTAL_FAIL=" + fail.length);
if (fail.length > 0) { console.log("FAILED_CHECKS:"); for (const f of fail) console.log("  " + f); }
console.log("FULL_AUDIT=" + (fail.length === 0 ? "PASS" : "FAIL"));
fs.rmSync(TMP, { recursive: true, force: true });
console.log("AUDIT_DONE=1");
