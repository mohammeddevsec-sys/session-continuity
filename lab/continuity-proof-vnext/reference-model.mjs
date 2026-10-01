import crypto from "node:crypto";
const {privateKey,publicKey}=crypto.generateKeyPairSync("ed25519");
const canon=x=>JSON.stringify(x);
const H=x=>crypto.createHash("sha256").update(canon(x)).digest("hex");
const sign=x=>crypto.sign(null,Buffer.from(canon(x)),privateKey).toString("base64");
const verify=(x,s)=>crypto.verify(null,Buffer.from(canon(x)),publicKey,Buffer.from(s,"base64"));

function root(anchor){return H({type:"CONTINUITY_ROOT",anchor});}
function createProof(rootId,sequence,parent,state,decision="ALLOW"){
 const stateHash=H(state);
 const decisionHash=H({decision,policy:"P1"});
 const body={continuity_root:rootId,sequence,parent_hash:parent,state_hash:stateHash,decision_hash:decisionHash};
 body.continuity_hash=H(body);
 return {body,signature:sign(body)};
}

function Witness(){let head=null;return {submit(proof){
 if(!verify(proof.body,proof.signature))return {ok:false,reason:"INVALID_SIGNATURE"};
 if(!head){if(proof.body.sequence!==1)return {ok:false,reason:"FIRST_SEQUENCE_REQUIRED"}; head=proof;return {ok:true,reason:"REGISTERED"};}
 if(proof.body.continuity_root!==head.body.continuity_root)return {ok:false,reason:"ROOT_MISMATCH"};
 if(proof.body.sequence<head.body.sequence)return {ok:false,reason:"ROLLBACK"};
 if(proof.body.sequence===head.body.sequence)return proof.body.continuity_hash===head.body.continuity_hash?{ok:true,reason:"IDEMPOTENT_REPLAY"}:{ok:false,reason:"EQUIVOCATION_FORK"};
 if(proof.body.sequence!==head.body.sequence+1)return {ok:false,reason:"SEQUENCE_GAP"};
 if(proof.body.parent_hash!==head.body.continuity_hash)return {ok:false,reason:"PARENT_MISMATCH"};
 head=proof; return {ok:true,reason:"ADVANCED"};
},head:()=>head};}
const anchor={session_id:"V1",subject:"U1",issuer:"I1",client:"C1"};
const R=root(anchor);
const w=Witness();
const p1=createProof(R,1,"",{device:"D1",seq:1});
const p2=createProof(R,2,p1.body.continuity_hash,{device:"D1",seq:2});
const p2fork=createProof(R,2,p1.body.continuity_hash,{device:"D2",seq:2});
const p4=createProof(R,4,p2.body.continuity_hash,{device:"D1",seq:4});
const p3=createProof(R,3,p2.body.continuity_hash,{device:"D1",seq:3});
console.log("=== CONTINUITY PROOF V1 :: REFERENCE MODEL ===");
console.log("ROOT="+R);
console.log("P1="+w.submit(p1).reason);
console.log("P2="+w.submit(p2).reason);
console.log("FORK="+w.submit(p2fork).reason);
console.log("GAP="+w.submit(p4).reason);
console.log("P3="+w.submit(p3).reason);
console.log("REPLAY="+w.submit(p3).reason);
console.log("FORK_PROTECTION="+(w.submit(p2fork).reason==="ROLLBACK"?"PASS":"FAIL"));
console.log("GAP_PROTECTION="+(w.submit(p4).reason==="SEQUENCE_GAP"?"PASS":"FAIL"));
console.log("REPLAY_PROTECTION="+(w.submit(p3).reason==="IDEMPOTENT_REPLAY"?"PASS":"FAIL"));
console.log("REFERENCE_MODEL_READY=TRUE");
