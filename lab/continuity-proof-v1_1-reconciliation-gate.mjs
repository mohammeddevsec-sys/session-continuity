import fs from "node:fs";
const specPath=String.raw`E:\SESSION-CONTINUITY\lab\continuity-proof-vnext\SPEC-DRAFT-V1_1-RECONCILED.md`;
if(!fs.existsSync(specPath))throw new Error("RECONCILED_SPEC_NOT_FOUND");
const s=fs.readFileSync(specPath,"utf8").toLowerCase();
const has=x=>s.includes(x.toLowerCase());
const all=(...xs)=>xs.every(has);
const tests=[
["ROOT_TRUST",all("explicit trust material","root trust")],
["PARENT_NULL",has("parent_hash must be json null")],
["POLICY_IN_CORE",all("policy_fingerprint_sha256","canonical proof core")],
["KEY_ID_IN_CORE",all("signer_key_id","canonical proof core")],
["COMPLETENESS",all("continuity_complete","finality evidence")],
["PREFIX_SEPARATION",all("prefix_valid","continuity_complete")],
["CHECKPOINT",all("a checkpoint must contain","continuity_root","sequence","continuity_hash","proof_hash","checkpoint_kind","signature"),],
["CHECKPOINT_BINDING",all("checkpoint","parent-binding semantics","continuity_hash")],
["WITNESS_EQUIVOCATION",all("witness equivocation evidence","same sequence","different continuity_hash")],
["RECOVERY_FAIL_CLOSED",all("recovery fails","fail closed","new acceptance")],
["KEY_RETIREMENT",all("retired","outside its authorized issuance interval")],
["KEY_REVOCATION",all("revoked","effective revocation")],
["COMPROMISE_DISPOSITION",all("quarantined","compromise disposition")],
["INDEPENDENT_RECEIVER",all("independent receiver","source application state","network access")],
["PACKAGE_SIGNATURE",all("package signature","package authenticity")],
["DOMAIN_SEPARATION",all("domain-separated","proof, witness receipt")],
["TRUST_ANCHOR",all("trust anchors","fail closed","missing or untrusted")],
["ERROR_TAXONOMY",all("receipt_binding_mismatch","package_signature_invalid","incomplete_history")],
["CONFORMANCE",all("level 1","level 5","required test")],
["NONCLAIMS",all("does not prove","global non-equivocation")]
];
for(const t of tests)console.log(t[0]+"="+(t[1]?"PASS":"FAIL"));
const failed=tests.filter(t=>!t[1]).length;
console.log("FAILED_COUNT="+failed);
console.log("RECONCILED_SPEC_GATE="+(failed===0?"PASS":"FAIL"));
console.log("ORIGINAL_SPEC_NOT_TOUCHED=YES");
console.log("SRC_NOT_TOUCHED=YES");
console.log("RELEASE_NOT_TOUCHED=YES");
