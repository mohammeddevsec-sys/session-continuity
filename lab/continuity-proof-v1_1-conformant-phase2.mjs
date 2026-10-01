import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { jcsCanonicalize, jcsSha256 } from "./continuity-proof-vnext/jcs-profile-v1_1.mjs";

const base="E:\\SESSION-CONTINUITY\\lab\\continuity-proof-v1_1-phase2-state";
fs.rmSync(base,{recursive:true,force:true});
fs.mkdirSync(base,{recursive:true});
const stateFile=path.join(base,"witness-state.json");

const {privateKey:signingKey,publicKey:witnessKey}=crypto.generateKeyPairSync("ed25519");
const sign=v=>crypto.sign(null,Buffer.from(jcsCanonicalize(v),"utf8"),signingKey).toString("base64");
const verify=(v,s)=>crypto.verify(null,Buffer.from(jcsCanonicalize(v),"utf8"),witnessKey,Buffer.from(s,"base64"));

const root={schema:"continuity-root.v1.1",session_id:"S1",subject:"U1",issuer:"I1",auth_time:"2026-09-15T03:00:00.000Z",client_context:{client_id:"C1",device_id:"D1"}};
const continuity_root=jcsSha256(root);
const proofCore=({sequence,parent,state,issued_at})=>({schema:"continuity-proof.v1.1",continuity_root,sequence,parent_hash:parent,state_hash:jcsSha256(state),decision_hash:jcsSha256("ALLOW"),issued_at});
const makeProof=({sequence,parent,state,issued_at})=>{const core=proofCore({sequence,parent,state,issued_at});const body={...core,continuity_hash:jcsSha256(core)};return {body,signature:crypto.sign(null,Buffer.from(jcsCanonicalize(body),"utf8"),signingKey).toString("base64")};};
const verifyProof=proof=>crypto.verify(null,Buffer.from(jcsCanonicalize(proof.body),"utf8"),signingKey,Buffer.from(proof.signature,"base64"))?jcsSha256({schema:proof.body.schema,continuity_root:proof.body.continuity_root,sequence:proof.body.sequence,parent_hash:proof.body.parent_hash,state_hash:proof.body.state_hash,decision_hash:proof.body.decision_hash,issued_at:proof.body.issued_at})===proof.body.continuity_hash?"VALID":"CONTINUITY_HASH_MISMATCH":"SIGNATURE_INVALID";

class DurableWitness {
  constructor(file){this.file=file;this.state=this.load();}
  load(){if(!fs.existsSync(this.file))return {schema:"witness-state.v1.1",continuity_root,head_sequence:0,head_hash:null};const x=JSON.parse(fs.readFileSync(this.file,"utf8"));if(x.schema!=="witness-state.v1.1"||x.continuity_root!==continuity_root)throw new Error("WITNESS_STATE_CORRUPT");if(x.state_hash!==jcsSha256({schema:x.schema,continuity_root:x.continuity_root,head_sequence:x.head_sequence,head_hash:x.head_hash}))throw new Error("WITNESS_STATE_CORRUPT");return x;}
  save(next){const body={schema:next.schema,continuity_root:next.continuity_root,head_sequence:next.head_sequence,head_hash:next.head_hash};const out={...body,state_hash:jcsSha256(body)};const tmp=this.file+".tmp";fs.writeFileSync(tmp,jcsCanonicalize(out),"utf8");fs.renameSync(tmp,this.file);this.state=out;}
  observe(proof){const v=verifyProof(proof);if(v!=="VALID")return v;const b=proof.body;if(b.continuity_root!==continuity_root)return "ROOT_NOT_TRUSTED";if(b.sequence===this.state.head_sequence&&b.continuity_hash===this.state.head_hash)return "IDEMPOTENT_REPLAY";if(b.sequence===this.state.head_sequence)return "EQUIVOCATION_FORK";if(b.sequence<this.state.head_sequence)return "SEQUENCE_ROLLBACK";if(b.sequence>this.state.head_sequence+1)return "SEQUENCE_GAP";if(b.parent_hash!==this.state.head_hash)return "PARENT_MISMATCH";this.save({...this.state,head_sequence:b.sequence,head_hash:b.continuity_hash});return "ADVANCED";}
  receipt(proof,result){const body={schema:"witness-receipt.v1.1",continuity_root,sequence:proof.body.sequence,observed_proof_hash:jcsSha256(proof.body),continuity_hash:proof.body.continuity_hash,witness_head_hash:this.state.head_hash,result};return {...body,signature:sign(body)};}
}

const w1=new DurableWitness(stateFile);
const p1=makeProof({sequence:1,parent:null,state:{device:"D1",state:"ACTIVE"},issued_at:"2026-09-15T03:01:00.000Z"});
const p2=makeProof({sequence:2,parent:p1.body.continuity_hash,state:{device:"D1",state:"ACTIVE"},issued_at:"2026-09-15T03:02:00.000Z"});
const p2Alt=makeProof({sequence:2,parent:p1.body.continuity_hash,state:{device:"D1",state:"CHANGED"},issued_at:"2026-09-15T03:02:01.000Z"});
const p4=makeProof({sequence:4,parent:p2.body.continuity_hash,state:{device:"D1",state:"ACTIVE"},issued_at:"2026-09-15T03:04:00.000Z"});

const r1=w1.observe(p1);
const receipt1=w1.receipt(p1,r1);
const r2=w1.observe(p2);
const receipt2=w1.receipt(p2,r2);
const w2=new DurableWitness(stateFile);
const restartHead=w2.state.head_sequence===2&&w2.state.head_hash===p2.body.continuity_hash;
const rIdempotent=w2.observe(p2);
const rFork=w2.observe(p2Alt);
const rGap=w2.observe(p4);
const receiptValid=true;
const receiptBody={schema:receipt2.schema,continuity_root:receipt2.continuity_root,sequence:receipt2.sequence,observed_proof_hash:receipt2.observed_proof_hash,continuity_hash:receipt2.continuity_hash,witness_head_hash:receipt2.witness_head_hash,result:receipt2.result};
const receiptSignatureValid=verify(receiptBody,receipt2.signature);
const original=fs.readFileSync(stateFile,"utf8");
fs.writeFileSync(stateFile,original.replace(p2.body.continuity_hash,p1.body.continuity_hash),"utf8");
let corruption="NOT_DETECTED";try{new DurableWitness(stateFile);corruption="MISSED";}catch(e){corruption=e.message;}
fs.writeFileSync(stateFile,original,"utf8");

console.log("=== CONTINUITY PROOF V1.1 CONFORMANT :: PHASE 2 ===");
console.log("INITIAL_P1="+r1);
console.log("INITIAL_P2="+r2);
console.log("RESTART_STATE="+(restartHead?"PASS":"FAIL"));
console.log("IDEMPOTENT_REPLAY="+rIdempotent);
console.log("EQUIVOCATION_FORK="+rFork);
console.log("SEQUENCE_GAP="+rGap);
console.log("RECEIPT_SIGNATURE="+(receiptSignatureValid?"PASS":"FAIL"));
console.log("WITNESS_STATE_CORRUPTION="+corruption);
console.log("DURABLE_WITNESS="+(r1==="ADVANCED"&&r2==="ADVANCED"&&restartHead?"PASS":"FAIL"));
console.log("RECEIPT_BINDING="+(receiptBody.observed_proof_hash===jcsSha256(p2.body)&&receiptBody.continuity_hash===p2.body.continuity_hash&&receiptBody.witness_head_hash===p2.body.continuity_hash?"PASS":"FAIL"));
console.log("REFERENCE_PHASE2="+(rIdempotent==="IDEMPOTENT_REPLAY"&&rFork==="EQUIVOCATION_FORK"&&rGap==="SEQUENCE_GAP"&&receiptSignatureValid&&corruption==="WITNESS_STATE_CORRUPT"?"PASS":"FAIL"));
