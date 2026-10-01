import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { execFileSync } from "node:child_process";
import { jcsCanonicalize,jcsSha256 } from "./continuity-proof-vnext/jcs-profile-v1_1.mjs";

const packageFile=path.join(String.raw`E:\SESSION-CONTINUITY\lab`,`phase4-5-10000-package.json`);
const sign=(k,v)=>crypto.sign(null,Buffer.from(jcsCanonicalize(v),"utf8"),k).toString("base64");
const verify=(k,v,s)=>crypto.verify(null,Buffer.from(jcsCanonicalize(v),"utf8"),k,Buffer.from(s,"base64"));
const der=k=>k.export({type:"spki",format:"der"}).toString("base64");
const fromDer=b=>crypto.createPublicKey({key:Buffer.from(b,"base64"),type:"spki",format:"der"});

if(process.argv[2]==="--verify"){
  const t0=performance.now();
  const pkg=JSON.parse(fs.readFileSync(process.argv[3],"utf8"));
  if(pkg.schema!=="session-continuity.package.v1.1"||pkg.version!=="1.1")throw new Error("PACKAGE_VERSION_MISMATCH");
  const sp=fromDer(pkg.trust_anchor.signer_public_key),wp=fromDer(pkg.trust_anchor.witness_public_key);
  const unsigned={schema:pkg.schema,version:pkg.version,created_at:pkg.created_at,continuity_root:pkg.continuity_root,proof_chain:pkg.proof_chain,witness_receipts:pkg.witness_receipts,trust_anchor:pkg.trust_anchor,policy_reference:pkg.policy_reference};
  if(!verify(sp,unsigned,pkg.package_signature.signature))throw new Error("PACKAGE_SIGNATURE_INVALID");
  const rootHash=pkg.continuity_root.root_hash;
  let previous=null;
  for(let i=0;i<pkg.proof_chain.length;i++){
    const p=pkg.proof_chain[i],b=p.body,r=pkg.witness_receipts[i];
    if(!verify(sp,p.body,p.signature))throw new Error("PROOF_SIGNATURE_INVALID");
    if(b.continuity_root!==rootHash)throw new Error("ROOT_MISMATCH");
    const core={schema:b.schema,continuity_root:b.continuity_root,sequence:b.sequence,parent_hash:b.parent_hash,state_hash:b.state_hash,decision_hash:b.decision_hash,issued_at:b.issued_at};
    if(jcsSha256(core)!==b.continuity_hash)throw new Error("CONTINUITY_HASH_MISMATCH");
    if(b.sequence!==i+1)throw new Error("SEQUENCE_INVALID");
    if(i===0){if(b.parent_hash!==null)throw new Error("PARENT_MISMATCH")}else if(b.parent_hash!==previous)throw new Error("PARENT_MISMATCH");
    if(r.body.continuity_root!==rootHash||r.body.sequence!==b.sequence||r.body.observed_proof_hash!==jcsSha256(b)||r.body.continuity_hash!==b.continuity_hash)throw new Error("RECEIPT_BINDING_MISMATCH");
    if(!verify(wp,r.body,r.signature))throw new Error("WITNESS_RECEIPT_INVALID");
    previous=b.continuity_hash;
  }
  console.log("ISOLATED_RECEIVER=PASS");
  console.log("PACKAGE_ALONE=PASS");
  console.log("SOURCE_APP_REQUIRED=NO");
  console.log("WITNESS_REQUIRED=NO");
  console.log("NETWORK_REQUIRED=NO");
  console.log("CHAIN_LENGTH="+pkg.proof_chain.length);
  console.log("OFFLINE_VERIFICATION_TIME_MS="+(performance.now()-t0).toFixed(3));
  process.exit(0);
}

fs.rmSync(packageFile,{force:true});
const signer=crypto.generateKeyPairSync("ed25519"),witness=crypto.generateKeyPairSync("ed25519");
const signerPublic=der(signer.publicKey),witnessPublic=der(witness.publicKey);
const rootBase={schema:"continuity-root.v1.1",session_id:"S1",subject:"U1",issuer:"I1",auth_time:"2026-09-15T03:00:00.000Z",client_context:{client_id:"C1",device_id:"D1"}};
const root={...rootBase,root_hash:jcsSha256(rootBase)};
const chain=[],receipts=[];let parent=null;
const buildStart=performance.now();
for(let i=1;i<=10000;i++){
  const core={schema:"continuity-proof.v1.1",continuity_root:root.root_hash,sequence:i,parent_hash:parent,state_hash:jcsSha256({sequence:i,state:"ACTIVE"}),decision_hash:jcsSha256("ALLOW"),issued_at:`2026-09-15T${String(Math.floor(i/3600)).padStart(2,"0")}:${String(Math.floor((i%3600)/60)).padStart(2,"0")}:${String(i%60).padStart(2,"0")}.000Z`};
  const body={...core,continuity_hash:jcsSha256(core)};
  const proof={body,signature:sign(signer.privateKey,body)};
  const rb={schema:"witness-receipt.v1.1",continuity_root:root.root_hash,sequence:i,observed_proof_hash:jcsSha256(body),continuity_hash:body.continuity_hash,witness_head_hash:body.continuity_hash,result:"ADVANCED"};
  chain.push(proof);receipts.push({body:rb,signature:sign(witness.privateKey,rb)});parent=body.continuity_hash;
}
const unsigned={schema:"session-continuity.package.v1.1",version:"1.1",created_at:"2026-09-15T04:00:00.000Z",continuity_root:root,proof_chain:chain,witness_receipts:receipts,trust_anchor:{signer_public_key:signerPublic,witness_public_key:witnessPublic},policy_reference:{policy_hash:jcsSha256({name:"phase4-5",max_chain_length:10000}),max_chain_length:10000}};
const pkg={...unsigned,package_signature:{signer_key_fingerprint:jcsSha256(signerPublic),signature:sign(signer.privateKey,unsigned)}};
fs.writeFileSync(packageFile,jcsCanonicalize(pkg),"utf8");
const buildMs=performance.now()-buildStart;
const size=fs.statSync(packageFile).size;
const childStart=performance.now();
let childOutput="";let childExit=0;
try{childOutput=execFileSync(process.execPath,[p,"--verify",packageFile],{encoding:"utf8",stdio:["ignore","pipe","pipe"]});}catch(e){childExit=e.status??1;childOutput=(e.stdout||"")+(e.stderr||"");}
const processMs=performance.now()-childStart;
console.log("=== CONTINUITY PROOF V1.1 :: PHASE 4.5 SCALE + PROCESS ISOLATION ===");
console.log("CHAIN_LENGTH_10000="+(chain.length===10000?"PASS":"FAIL"));
console.log("PACKAGE_SIZE_BYTES="+size);
console.log("PACKAGE_SIZE_MB="+(size/1048576).toFixed(3));
console.log("PACKAGE_BUILD_TIME_MS="+buildMs.toFixed(3));
console.log("ISOLATED_PROCESS_EXIT="+childExit);
console.log("ISOLATED_RECEIVER_RESULT="+(childExit===0&&childOutput.includes("ISOLATED_RECEIVER=PASS")?"PASS":"FAIL"));
const m=childOutput.match(/OFFLINE_VERIFICATION_TIME_MS=([0-9.]+)/);
console.log("ISOLATED_OFFLINE_VERIFICATION_TIME_MS="+(m?m[1]:"NA"));
console.log("END_TO_END_PROCESS_TIME_MS="+processMs.toFixed(3));
console.log("MERKLE_REQUIRED_BY_10K="+"UNDECIDED");
console.log("REFERENCE_PHASE4_5="+(chain.length===10000&&size>0&&childExit===0&&childOutput.includes("PACKAGE_ALONE=PASS")?"PASS":"FAIL"));
console.log(childOutput.trim());
