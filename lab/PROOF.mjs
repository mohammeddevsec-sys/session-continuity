import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), "..");

function sha256File(p){ return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex").toUpperCase(); }
function sha256Tree(dir){
  const files=[];
  (function walk(d){
    for(const e of fs.readdirSync(d,{withFileTypes:true})){
      const full=path.join(d,e.name);
      if(e.isDirectory()) walk(full);
      else if(e.isFile() && !e.name.includes(".backup_")) files.push(full);
    }
  })(dir);
  files.sort();
  const h=crypto.createHash("sha256");
  for(const f of files){
    h.update(path.relative(ROOT,f).split(path.sep).join("/"));
    h.update("\n");
    h.update(fs.readFileSync(f));
    h.update("\n");
  }
  return h.digest("hex").toUpperCase();
}
function runScript(rel){
  const r=spawnSync(process.execPath,[path.join(ROOT,rel)],{cwd:ROOT,encoding:"utf8",timeout:600000});
  return {exit:r.status, stdout:r.stdout||"", stderr:r.stderr||""};
}
async function controls(){
  const sig=await import(pathToFileURL(path.join(ROOT,"src/evidence/proof-signature-v1_1.js")).href);
  const cp=await import(pathToFileURL(path.join(ROOT,"src/core/continuity-proof-v1_1.js")).href);
  const {createSigningIdentity,signProof,verifyProofSignature}=sig;
  const {createContinuityRoot,createProofCore,addContinuityHash,verifyProofChain,verifyProofCore}=cp;
  const id=createSigningIdentity({keyId:"proof-key"});
  const root=createContinuityRoot({session_id:"s",subject:"u",issuer:"i",auth_time:"2026-09-17T00:00:00.000Z",client_context:{}});
  const core=createProofCore({
    continuity_root:root.continuity_root,sequence:1,parent_hash:null,
    state_hash:"1".repeat(64),decision_hash:"2".repeat(64),
    issued_at:"2026-09-17T00:00:01.000Z",
    signer_key_id:id.keyId,policy_fingerprint_sha256:"3".repeat(64)
  });
  const signed=signProof(id,addContinuityHash(core));
  const r=[];
  const t=(n,c,d)=>r.push([n,c===true,String(d||"")]);
  const p1=verifyProofSignature(signed); t("PC1_VALID_SIGNATURE_ACCEPTED",p1.verified===true,p1.reason);
  const p2=verifyProofChain([signed],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature}); t("PC2_VALID_CHAIN_ACCEPTED",p2.verified===true,p2.reason);
  const n1=verifyProofSignature({...signed,decision_hash:"9".repeat(64)}); t("NC1_TAMPERED_DECISION_REJECTED",n1.verified===false,n1.reason);
  const n2=verifyProofSignature({...signed,continuity_hash:"f".repeat(64)}); t("NC2_TAMPERED_HASH_REJECTED",n2.verified===false,n2.reason);
  const n3=verifyProofCore({...signed,continuity_hash:"f".repeat(64)}); t("NC3_HASH_MISMATCH_REJECTED",n3.verified===false,n3.reason);
  const n4=verifyProofChain([],{verifySignature:verifyProofSignature}); t("NC4_EMPTY_CHAIN_REJECTED",n4.verified===false,n4.reason);
  const n5=verifyProofChain([signed],{}); t("NC5_MISSING_VERIFIER_REJECTED",n5.verified===false,n5.reason);
  const n6=verifyProofSignature({...signed,schema:"wrong"}); t("NC6_WRONG_SCHEMA_REJECTED",n6.verified===false,n6.reason);
  return r;
}
(async()=>{
  const L=[]; const put=s=>L.push(s);
  put("=== PROOF OF CORRECTNESS ===");
  put("PROOF_SCRIPT_SHA256="+sha256File(__filename));
  put("SRC_TREE_SHA256="+sha256Tree(path.join(ROOT,"src")));
  put("PACKAGE_JSON_SHA256="+sha256File(path.join(ROOT,"package.json")));
  put("");
  put("--- V1 REGRESSION ---");
  const v1=runScript("test/run-all-tests.mjs");
  const v1Res=(v1.stdout.match(/FINAL_REGRESSION=([A-Z]+)/)||[])[1]||"MISSING";
  const v1St=(v1.stdout.match(/PRODUCT_STATE=([A-Z_]+)/)||[])[1]||"MISSING";
  put("V1_RESULT="+v1Res); put("V1_STATE="+v1St); put("V1_EXIT="+v1.exit);
  put("");
  put("--- V1.1 REGRESSION ---");
  const v11=runScript("lab/v1_1-regression-gate.mjs");
  const v11Res=(v11.stdout.match(/V1_1_REGRESSION=([A-Z]+)/)||[])[1]||"MISSING";
  const v11P=(v11.stdout.match(/TOTAL_PASS=(\d+)/)||[])[1]||"0";
  const v11F=(v11.stdout.match(/TOTAL_FAIL=(\d+)/)||[])[1]||"0";
  put("V1_1_RESULT="+v11Res); put("V1_1_PASS="+v11P); put("V1_1_FAIL="+v11F); put("V1_1_EXIT="+v11.exit);
  put("");
  put("--- CONTROLS ---");
  const c=await controls();
  for(const [n,ok,d] of c) put(n+"="+(ok?"PASS":"FAIL")+"|"+d);
  put("");
  put("--- VERDICT ---");
  const allC=c.every(x=>x[1]);
  const ok=(v1Res==="PASS"&&v11Res==="PASS"&&v11F==="0"&&v1.exit===0&&v11.exit===0&&allC);
  put("OVERALL="+(ok?"PASS":"FAIL"));
  put("PROOF_DONE=1");
  const body=L.join("\n")+"\n";
  const runSha=crypto.createHash("sha256").update(Buffer.from(body,"utf8")).digest("hex").toUpperCase();
  L.push("PROOF_RUN_SHA256="+runSha);
  process.stdout.write(L.join("\n")+"\n");
})();