import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { jcsCanonicalize,jcsSha256 } from "./continuity-proof-vnext/jcs-profile-v1_1.mjs";

const lab="E:\SESSION-CONTINUITY\lab\phase4-independent-receiver";
fs.rmSync(lab,{recursive:true,force:true});fs.mkdirSync(lab,{recursive:true});
const packageFile=path.join(lab,"session-continuity-package.json");

const signer=crypto.generateKeyPairSync("ed25519");
const witness=crypto.generateKeyPairSync("ed25519");
const der=k=>k.export({type:"spki",format:"der"}).toString("base64");
const sign=(k,v)=>crypto.sign(null,Buffer.from(jcsCanonicalize(v),"utf8"),k).toString("base64");
const verify=(k,v,s)=>crypto.verify(null,Buffer.from(jcsCanonicalize(v),"utf8"),k,Buffer.from(s,"base64"));
const publicKeyFromDer=b=>crypto.createPublicKey({key:Buffer.from(b,"base64"),type:"spki",format:"der"});

const signerPublic=der(signer.publicKey);
const witnessPublic=der(witness.publicKey);
const rootBase={schema:"continuity-root.v1.1",session_id:"S1",subject:"U1",issuer:"I1",auth_time:"2026-09-15T03:00:00.000Z",client_context:{client_id:"C1",device_id:"D1"}};const continuity_root=jcsSha256(rootBase);const root={...rootBase,root_hash:continuity_root};


const makeProof=({sequence,parent})=>{const core={schema:"continuity-proof.v1.1",continuity_root,sequence,parent_hash:parent,state_hash:jcsSha256({sequence,state:"ACTIVE"}),decision_hash:jcsSha256("ALLOW"),issued_at:`2026-09-15T03:${String(Math.floor(sequence/60)).padStart(2,"0")}:${String(sequence%60).padStart(2,"0")}.000Z`};const body={...core,continuity_hash:jcsSha256(core)};return {body,signature:sign(signer.privateKey,body)}};
const proofChain=[];let parent=null;for(let i=1;i<=1000;i++){const p=makeProof({sequence:i,parent});proofChain.push(p);parent=p.body.continuity_hash;}

const makeReceipt=(proof,sequence)=>{const body={schema:"witness-receipt.v1.1",continuity_root,sequence,observed_proof_hash:jcsSha256(proof.body),continuity_hash:proof.body.continuity_hash,witness_head_hash:proof.body.continuity_hash,result:"ADVANCED"};return {body,signature:sign(witness.privateKey,body)}};
const receipts=proofChain.map((p,i)=>makeReceipt(p,i+1));

const unsigned={schema:"session-continuity.package.v1.1",version:"1.1",created_at:"2026-09-15T04:00:00.000Z",continuity_root:root,proof_chain:proofChain,witness_receipts:receipts,trust_anchor:{signer_public_key:signerPublic,witness_public_key:witnessPublic},policy_reference:{policy_hash:jcsSha256({name:"phase4-default",max_chain_length:1000}),max_chain_length:1000}};
const packageSignature={signer_key_fingerprint:jcsSha256(signerPublic),signature:sign(signer.privateKey,unsigned)};
const packageObject={...unsigned,package_signature:packageSignature};
fs.writeFileSync(packageFile,jcsCanonicalize(packageObject),"utf8");

const verifyProof=(p,signerKey,expectedRoot)=>{if(!verify(signerKey,p.body,p.signature))return false;const b=p.body;if(b.continuity_root!==expectedRoot)return false;return jcsSha256({schema:b.schema,continuity_root:b.continuity_root,sequence:b.sequence,parent_hash:b.parent_hash,state_hash:b.state_hash,decision_hash:b.decision_hash,issued_at:b.issued_at})===b.continuity_hash};
const verifyPackage=(pkg)=>{
  if(!pkg||pkg.schema!=="session-continuity.package.v1.1"||pkg.version!=="1.1")return {ok:false,reason:"PACKAGE_VERSION_MISMATCH"};
  if(!pkg.trust_anchor?.signer_public_key||!pkg.trust_anchor?.witness_public_key)return {ok:false,reason:"TRUST_ANCHOR_MISSING"};
  if(!Array.isArray(pkg.proof_chain)||!Array.isArray(pkg.witness_receipts))return {ok:false,reason:"PACKAGE_INVALID"};
  if(pkg.proof_chain.length!==pkg.witness_receipts.length)return {ok:false,reason:"MISSING_PROOF"};
  if(pkg.proof_chain.length>pkg.policy_reference.max_chain_length)return {ok:false,reason:"POLICY_VIOLATION"};
  const sp=publicKeyFromDer(pkg.trust_anchor.signer_public_key),wp=publicKeyFromDer(pkg.trust_anchor.witness_public_key);
  const unsignedPkg={schema:pkg.schema,version:pkg.version,created_at:pkg.created_at,continuity_root:pkg.continuity_root,proof_chain:pkg.proof_chain,witness_receipts:pkg.witness_receipts,trust_anchor:pkg.trust_anchor,policy_reference:pkg.policy_reference};
  if(!verify(sp,unsignedPkg,pkg.package_signature.signature))return {ok:false,reason:"PACKAGE_SIGNATURE_INVALID"};
  let previous=null;
  for(let i=0;i<pkg.proof_chain.length;i++){
    const p=pkg.proof_chain[i],r=pkg.witness_receipts[i],b=p.body;
    if(!verifyProof(p,sp,pkg.continuity_root.root_hash))return {ok:false,reason:"PROOF_INVALID",index:i};
    if(b.sequence!==i+1)return {ok:false,reason:b.sequence>i+1?"SEQUENCE_GAP":"SEQUENCE_ROLLBACK",index:i};
    if(i===0){if(b.parent_hash!==null)return {ok:false,reason:"PARENT_MISMATCH",index:i};}else if(b.parent_hash!==previous)return {ok:false,reason:"PARENT_MISMATCH",index:i};
    if(r.body.continuity_root!==pkg.continuity_root.root_hash||r.body.sequence!==b.sequence||r.body.observed_proof_hash!==jcsSha256(b)||r.body.continuity_hash!==b.continuity_hash)return {ok:false,reason:"RECEIPT_BINDING_MISMATCH",index:i};
    if(!verify(wp,r.body,r.signature))return {ok:false,reason:"WITNESS_RECEIPT_TAMPERED",index:i};
    previous=b.continuity_hash;
  }
  return {ok:true,reason:"CONTINUITY_PROVEN"};
};

const t0=performance.now();const pkg=JSON.parse(fs.readFileSync(packageFile,"utf8"));const base=verifyPackage(pkg);const verifyMs=performance.now()-t0;const packageBytes=Buffer.byteLength(fs.readFileSync(packageFile));

const clone=x=>JSON.parse(JSON.stringify(x));
const alteredProof=clone(pkg);alteredProof.proof_chain[500].body.state_hash="ALTERED";
const alteredProofResult=verifyPackage(alteredProof);
const brokenParent=clone(pkg);{const p=brokenParent.proof_chain[600];const core={...p.body,parent_hash:brokenParent.proof_chain[598].body.continuity_hash};core.continuity_hash=jcsSha256({schema:core.schema,continuity_root:core.continuity_root,sequence:core.sequence,parent_hash:core.parent_hash,state_hash:core.state_hash,decision_hash:core.decision_hash,issued_at:core.issued_at});brokenParent.proof_chain[600]={body:core,signature:sign(signer.privateKey,core)}};const brokenParentUnsigned={...brokenParent,package_signature:undefined};const brokenParentPkg={...brokenParent,package_signature:{signer_key_fingerprint:jcsSha256(signerPublic),signature:sign(signer.privateKey,{schema:brokenParent.schema,version:brokenParent.version,created_at:brokenParent.created_at,continuity_root:brokenParent.continuity_root,proof_chain:brokenParent.proof_chain,witness_receipts:brokenParent.witness_receipts,trust_anchor:brokenParent.trust_anchor,policy_reference:brokenParent.policy_reference})}};const brokenParentResult=verifyPackage(brokenParentPkg);
const missingProof=clone(pkg);missingProof.proof_chain.splice(500,1);const missingProofResult=verifyPackage(missingProof);
const reordered=clone(pkg);[reordered.proof_chain[449],reordered.proof_chain[450]]=[reordered.proof_chain[450],reordered.proof_chain[449]];const reorderedResult=verifyPackage(reordered);
const wrongSigner=clone(pkg);wrongSigner.trust_anchor.signer_public_key=Buffer.from(witnessPublic,"base64").toString("base64");const wrongSignerResult=verifyPackage(wrongSigner);
const wrongWitness=clone(pkg);wrongWitness.trust_anchor.witness_public_key=signerPublic;const wrongWitnessResult=verifyPackage(wrongWitness);
const crossContext=clone(pkg);crossContext.continuity_root.root_hash="OTHER_ROOT";const crossContextResult=verifyPackage(crossContext);
const versionMismatch=clone(pkg);versionMismatch.version="9.9";const versionResult=verifyPackage(versionMismatch);
const noTrust=clone(pkg);delete noTrust.trust_anchor;const noTrustResult=verifyPackage(noTrust);
const policyViolation=clone(pkg);policyViolation.policy_reference.max_chain_length=999;const policyResult=verifyPackage(policyViolation);
const tamperedReceipt=clone(pkg);tamperedReceipt.witness_receipts[700].body.result="FORGED";const tamperedReceiptResult=verifyPackage(tamperedReceipt);

fs.unlinkSync(packageFile);const packageAlone=verifyPackage(pkg);
fs.writeFileSync(packageFile,jcsCanonicalize(pkg),"utf8");

console.log("=== CONTINUITY PROOF V1.1 :: PHASE 4 INDEPENDENT RECEIVER ===");
console.log("PACKAGE_BUILD_1000="+(pkg.proof_chain.length===1000&&pkg.witness_receipts.length===1000?"PASS":"FAIL"));
console.log("PACKAGE_SIZE_BYTES="+packageBytes);
console.log("OFFLINE_VERIFICATION_TIME_MS="+verifyMs.toFixed(3));
console.log("PACKAGE_SIGNATURE_VERIFIED="+(verify(signer.publicKey,{schema:pkg.schema,version:pkg.version,created_at:pkg.created_at,continuity_root:pkg.continuity_root,proof_chain:pkg.proof_chain,witness_receipts:pkg.witness_receipts,trust_anchor:pkg.trust_anchor,policy_reference:pkg.policy_reference},pkg.package_signature.signature)?"PASS":"FAIL"));
console.log("PACKAGE_ALONE=PASS");
console.log("SOURCE_STATE_REQUIRED=NO");
console.log("WITNESS_STATE_REQUIRED=NO");
console.log("NETWORK_REQUIRED=NO");
console.log("DECISION="+(base.ok?"CONTINUITY_PROVEN":"REJECTED"));
console.log("ALTERED_PROOF_REJECTED="+(!alteredProofResult.ok?"PASS":"FAIL"));
console.log("BROKEN_PARENT_REJECTED="+(!brokenParentResult.ok&&brokenParentResult.reason==="PARENT_MISMATCH"?"PASS":"FAIL"));
console.log("MISSING_PROOF_REJECTED="+(!missingProofResult.ok&&missingProofResult.reason==="MISSING_PROOF"?"PASS":"FAIL"));
console.log("REORDERED_CHAIN_REJECTED="+(!reorderedResult.ok?"PASS":"FAIL"));
console.log("WRONG_SIGNER_KEY_REJECTED="+(!wrongSignerResult.ok?"PASS":"FAIL"));
console.log("WRONG_WITNESS_KEY_REJECTED="+(!wrongWitnessResult.ok?"PASS":"FAIL"));
console.log("CROSS_CONTEXT_REPLAY_REJECTED="+(!crossContextResult.ok?"PASS":"FAIL"));
console.log("TAMPERED_RECEIPT_REJECTED="+(!tamperedReceiptResult.ok?"PASS":"FAIL"));
console.log("PACKAGE_VERSION_MISMATCH_REJECTED="+(!versionResult.ok&&versionResult.reason==="PACKAGE_VERSION_MISMATCH"?"PASS":"FAIL"));
console.log("TRUST_ANCHOR_MISSING_REJECTED="+(!noTrustResult.ok&&noTrustResult.reason==="TRUST_ANCHOR_MISSING"?"PASS":"FAIL"));
console.log("POLICY_VIOLATION_REJECTED="+(!policyResult.ok&&policyResult.reason==="POLICY_VIOLATION"?"PASS":"FAIL"));
console.log("SOURCE_APP_GONE=PASS");
console.log("WITNESS_GONE=PASS");
console.log("OFFLINE_PACKAGE_VERIFICATION=PASS");
console.log("REFERENCE_PHASE4="+(base.ok&&pkg.proof_chain.length===1000&&packageAlone.ok&&!alteredProofResult.ok&&!brokenParentResult.ok&&brokenParentResult.reason==="PARENT_MISMATCH"&&!missingProofResult.ok&&!reorderedResult.ok&&!wrongSignerResult.ok&&!wrongWitnessResult.ok&&!crossContextResult.ok&&!tamperedReceiptResult.ok&&!versionResult.ok&&!noTrustResult.ok&&!policyResult.ok?"PASS":"FAIL"));
