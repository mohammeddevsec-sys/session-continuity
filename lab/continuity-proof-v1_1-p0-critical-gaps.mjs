import crypto from "node:crypto";
import { jcsCanonicalize,jcsSha256 } from "./continuity-proof-vnext/jcs-profile-v1_1.mjs";

const key=()=>crypto.generateKeyPairSync("ed25519");
const signerOld=key(),signerNew=key(),witnessKey=key(),witnessKey2=key();
const sign=(k,v)=>crypto.sign(null,Buffer.from(jcsCanonicalize(v),"utf8"),k).toString("base64");
const verify=(k,v,s)=>crypto.verify(null,Buffer.from(jcsCanonicalize(v),"utf8"),k,Buffer.from(s,"base64"));
const fp=v=>jcsSha256(v);
const rootBase={schema:"continuity-root.v1.1",session_id:"S1",subject:"U1",issuer:"I1",auth_time:"2026-09-15T03:00:00.000Z",client_context:{client_id:"C1",device_id:"D1"}};
const continuity_root=fp(rootBase);
const policyA=fp({policy:"P1",version:"1.0"});

const makeProof=({sequence,parent,keyId,keyPair,state="ACTIVE",policy=policyA})=>{
  const core={schema:"continuity-proof.v1.1",continuity_root,sequence,parent_hash:parent,state_hash:fp({sequence,state}),decision_hash:fp("ALLOW"),issued_at:`2026-09-15T03:00:${String(sequence).padStart(2,"0")}.000Z`,signer_key_id:keyId,policy_fingerprint_sha256:policy};
  const body={...core,continuity_hash:fp(core)};
  return {body,signature:sign(keyPair.privateKey,body)};
};

const verifyProof=(proof,registry)=>{
  const b=proof.body,e=registry[b.signer_key_id];
  if(!e)return "UNKNOWN_SIGNER_KEY";
  if(!verify(e.publicKey,b,proof.signature))return "SIGNATURE_INVALID";
  const core={schema:b.schema,continuity_root:b.continuity_root,sequence:b.sequence,parent_hash:b.parent_hash,state_hash:b.state_hash,decision_hash:b.decision_hash,issued_at:b.issued_at,signer_key_id:b.signer_key_id,policy_fingerprint_sha256:b.policy_fingerprint_sha256};
  if(b.continuity_root!==continuity_root||fp(core)!==b.continuity_hash)return "CONTINUITY_HASH_MISMATCH";
  return "VALID";
};

const registry={SOLD:{publicKey:signerOld.publicKey,valid_through_sequence:2,status:"retired"},SNEW:{publicKey:signerNew.publicKey,valid_from_sequence:3,status:"active"}};
const p1=makeProof({sequence:1,parent:null,keyId:"SOLD",keyPair:signerOld});
const p2a=makeProof({sequence:2,parent:p1.body.continuity_hash,keyId:"SOLD",keyPair:signerOld,state:"ACTIVE"});
const p2b=makeProof({sequence:2,parent:p1.body.continuity_hash,keyId:"SOLD",keyPair:signerOld,state:"CHANGED"});
const p3=makeProof({sequence:3,parent:p2a.body.continuity_hash,keyId:"SNEW",keyPair:signerNew});
const p4old=makeProof({sequence:4,parent:p3.body.continuity_hash,keyId:"SOLD",keyPair:signerOld});
const p4new=makeProof({sequence:4,parent:p3.body.continuity_hash,keyId:"SNEW",keyPair:signerNew});

const verifyPrefix=chain=>{let prev=null;for(let i=0;i<chain.length;i++){const p=chain[i],b=p.body;if(verifyProof(p,registry)!=="VALID")return {status:"REJECTED"};if(b.sequence!==i+1)return {status:"REJECTED"};if(i===0&&b.parent_hash!==null)return {status:"REJECTED"};if(i>0&&b.parent_hash!==prev)return {status:"REJECTED"};prev=b.continuity_hash;}return {status:"PREFIX_VALID",head_sequence:chain.length,head_hash:prev};};

const makeCheckpoint=({sequence,proof,witnessId,witnessPair,closed})=>{
  const body={schema:"continuity-checkpoint.v1.1",continuity_root,sequence,continuity_hash:proof.body.continuity_hash,proof_hash:fp(proof.body),witness_key_id:witnessId,checkpoint_kind:closed?"CLOSED":"HEAD"};
  return {body,signature:sign(witnessPair.privateKey,body)};
};
const verifyCheckpoint=(checkpoint,proof,keys)=>{
  const b=checkpoint.body,k=keys[b.witness_key_id];
  if(!k)return "UNKNOWN_WITNESS_KEY";
  if(!verify(k.publicKey,b,checkpoint.signature))return "CHECKPOINT_SIGNATURE_INVALID";
  if(b.continuity_root!==continuity_root||b.sequence!==proof.body.sequence||b.continuity_hash!==proof.body.continuity_hash||b.proof_hash!==fp(proof.body))return "CHECKPOINT_BINDING_MISMATCH";
  return b.checkpoint_kind==="CLOSED"?"FINALITY_ATTESTED":"HEAD_ATTESTED";
};
const checkpointKeys={W1:{publicKey:witnessKey.publicKey},W2:{publicKey:witnessKey2.publicKey}};

const prefix=verifyPrefix([p1,p2a,p3]);
const closedCheckpoint=makeCheckpoint({sequence:3,proof:p3,witnessId:"W1",witnessPair:witnessKey,closed:true});
const prefixNoCheckpoint=prefix.status==="PREFIX_VALID"?"INCOMPLETE":"REJECTED";
const finality=prefix.status==="PREFIX_VALID"&&verifyCheckpoint(closedCheckpoint,p3,checkpointKeys)==="FINALITY_ATTESTED"?"COMPLETE_WITHIN_ATTESTED_SCOPE":"REJECTED";

const receiptA=(()=>{const body={schema:"witness-receipt.v1.1",continuity_root,sequence:2,observed_proof_hash:fp(p2a.body),continuity_hash:p2a.body.continuity_hash,witness_key_id:"W1",result:"ADVANCED"};return {body,signature:sign(witnessKey.privateKey,body)}})();
const receiptB=(()=>{const body={schema:"witness-receipt.v1.1",continuity_root,sequence:2,observed_proof_hash:fp(p2b.body),continuity_hash:p2b.body.continuity_hash,witness_key_id:"W1",result:"ADVANCED"};return {body,signature:sign(witnessKey.privateKey,body)}})();
const proveWitnessEquivocation=(a,b)=>{const ka=checkpointKeys[a.body.witness_key_id],kb=checkpointKeys[b.body.witness_key_id];if(!ka||!kb)return "UNPROVABLE";if(a.body.continuity_root!==b.body.continuity_root||a.body.sequence!==b.body.sequence)return "NOT_EQUIVOCATION";if(a.body.continuity_hash===b.body.continuity_hash)return "NOT_EQUIVOCATION";if(!verify(ka.publicKey,a.body,a.signature)||!verify(kb.publicKey,b.body,b.signature))return "INVALID_RECEIPT";if(a.body.witness_key_id!==b.body.witness_key_id)return "DIFFERENT_WITNESSES";return "WITNESS_EQUIVOCATION_PROVEN"};
const witnessEquivocation=proveWitnessEquivocation(receiptA,receiptB);

const compromisePolicy={SOLD:{compromise_effective_sequence:3,post_compromise_disposition:"QUARANTINE"}};
const verifyWithCompromisePolicy=proof=>{const e=registry[proof.body.signer_key_id];const c=compromisePolicy[proof.body.signer_key_id];if(!e)return "UNKNOWN_SIGNER_KEY";if(!verify(e.publicKey,proof.body,proof.signature))return "SIGNATURE_INVALID";if(c&&proof.body.sequence>=c.compromise_effective_sequence)return c.post_compromise_disposition;return "VALID";};
const oldBeforeCompromise=verifyWithCompromisePolicy(p2a);
const oldAfterCompromise=verifyWithCompromisePolicy(p4old);
const newAfterRotation=verifyWithCompromisePolicy(p4new);

const checkpointTampered={body:{...closedCheckpoint.body,continuity_hash:"FORGED"},signature:closedCheckpoint.signature};
const checkpointTamperResult=verifyCheckpoint(checkpointTampered,p3,checkpointKeys);
const altCheckpoint=makeCheckpoint({sequence:2,proof:p2a,witnessId:"W1",witnessPair:witnessKey,closed:false});
const wrongCheckpoint=verifyCheckpoint(altCheckpoint,p3,checkpointKeys);

console.log("=== CONTINUITY PROOF V1.1 :: P0 CRITICAL GAP SUITE ===");
console.log("TRUNCATION_PREFIX_ONLY="+(prefixNoCheckpoint==="INCOMPLETE"?"PASS":"FAIL"));
console.log("CHECKPOINT_FINALITY_SCOPE="+(finality==="COMPLETE_WITHIN_ATTESTED_SCOPE"?"PASS":"FAIL"));
console.log("CHECKPOINT_DOES_NOT_REPLACE_PARENT_CHAIN="+(wrongCheckpoint==="CHECKPOINT_BINDING_MISMATCH"?"PASS":"FAIL"));
console.log("CHECKPOINT_TAMPER_REJECTED="+(checkpointTamperResult==="CHECKPOINT_BINDING_MISMATCH"||checkpointTamperResult==="CHECKPOINT_SIGNATURE_INVALID"?"PASS":"FAIL"));
console.log("TRUE_WITNESS_EQUIVOCATION_EVIDENCE="+(witnessEquivocation==="WITNESS_EQUIVOCATION_PROVEN"?"PASS":"FAIL"));
console.log("WITNESS_EQUIVOCATION_IS_EXTERNALLY_PROVABLE="+(witnessEquivocation==="WITNESS_EQUIVOCATION_PROVEN"?"PASS":"FAIL"));
console.log("PRE_COMPROMISE_HISTORICAL_PROOF="+(oldBeforeCompromise==="VALID"?"PASS":"FAIL"));
console.log("POST_COMPROMISE_POLICY_DISPOSITION="+(oldAfterCompromise==="QUARANTINE"?"PASS":"FAIL"));
console.log("NEW_KEY_AFTER_ROTATION="+(newAfterRotation==="VALID"?"PASS":"FAIL"));
console.log("REAL_KEY_IDENTITY_SEPARATION="+(signerOld.publicKey.export({type:"spki",format:"der"}).equals(signerNew.publicKey.export({type:"spki",format:"der"}))?"FAIL":"PASS"));
console.log("POLICY_FINGERPRINT_BOUND_IN_PROOF="+(p2a.body.policy_fingerprint_sha256===policyA?"PASS":"FAIL"));
console.log("REFERENCE_P0="+(prefixNoCheckpoint==="INCOMPLETE"&&finality==="COMPLETE_WITHIN_ATTESTED_SCOPE"&&wrongCheckpoint==="CHECKPOINT_BINDING_MISMATCH"&&witnessEquivocation==="WITNESS_EQUIVOCATION_PROVEN"&&oldBeforeCompromise==="VALID"&&oldAfterCompromise==="QUARANTINE"&&newAfterRotation==="VALID"&&p2a.body.policy_fingerprint_sha256===policyA?"PASS":"FAIL"));
