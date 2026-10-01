import { jcsCanonicalize,jcsSha256 } from "./canonical-v1_1.js";

function assertObject(value,name){
  if(value===null || typeof value!=="object" || Array.isArray(value)) throw new TypeError(name+"_OBJECT_REQUIRED");
}

function assertHex256(value,name){
  if(typeof value!=="string" || !/^[0-9a-f]{64}$/i.test(value)) throw new TypeError(name+"_SHA256_INVALID");
}

function assertUtcMillis(value){
  if(typeof value!=="string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(value)) throw new TypeError("ISSUED_AT_INVALID");
  const time=Date.parse(value);
  if(!Number.isFinite(time) || new Date(time).toISOString()!==value) throw new TypeError("ISSUED_AT_INVALID");
}

export function createContinuityRoot({session_id,subject,issuer,auth_time,client_context}){
  const root={schema:"continuity-root.v1.1",session_id,subject,issuer,auth_time,client_context};
  const continuity_root=jcsSha256(root);
  return Object.freeze({...root,continuity_root});
}

export function createProofCore({continuity_root,sequence,parent_hash,state_hash,decision_hash,issued_at,signer_key_id,policy_fingerprint_sha256}){
  assertHex256(continuity_root,"CONTINUITY_ROOT");
  if(!Number.isInteger(sequence) || sequence<1) throw new TypeError("SEQUENCE_INVALID");
  if(sequence===1){if(parent_hash!==null) throw new TypeError("FIRST_PARENT_MUST_BE_NULL");}else{assertHex256(parent_hash,"PARENT_HASH");}
  assertHex256(state_hash,"STATE");
  assertHex256(decision_hash,"DECISION");
  assertUtcMillis(issued_at);
  if(typeof signer_key_id!=="string" || signer_key_id.length===0) throw new TypeError("SIGNER_KEY_ID_INVALID");
  assertHex256(policy_fingerprint_sha256,"POLICY_FINGERPRINT");
  return Object.freeze({schema:"continuity-proof.v1.1",continuity_root,sequence,parent_hash,state_hash,decision_hash,issued_at,signer_key_id,policy_fingerprint_sha256});
}

export function addContinuityHash(core){
  assertObject(core,"CORE");
  if(core.continuity_hash!==undefined) throw new TypeError("CONTINUITY_HASH_ALREADY_PRESENT");
  return Object.freeze({...core,continuity_hash:jcsSha256(core)});
}

export function verifyProofCore(proof,{expectedContinuityRoot,expectedParentHash=null,expectedSequence=null}={}){
  assertObject(proof,"PROOF");
  const required=["schema","continuity_root","sequence","parent_hash","state_hash","decision_hash","issued_at","signer_key_id","policy_fingerprint_sha256","continuity_hash"];
  for(const key of required) if(!Object.prototype.hasOwnProperty.call(proof,key)) return {verified:false,reason:"PROOF_FIELD_MISSING:"+key};
  if(proof.schema!=="continuity-proof.v1.1") return {verified:false,reason:"PROOF_SCHEMA_INVALID"};
  try{createProofCore({continuity_root:proof.continuity_root,sequence:proof.sequence,parent_hash:proof.parent_hash,state_hash:proof.state_hash,decision_hash:proof.decision_hash,issued_at:proof.issued_at,signer_key_id:proof.signer_key_id,policy_fingerprint_sha256:proof.policy_fingerprint_sha256});}catch(error){return {verified:false,reason:error.message};}
  if(expectedContinuityRoot!==undefined && proof.continuity_root!==expectedContinuityRoot) return {verified:false,reason:"ROOT_NOT_TRUSTED"};
  if(expectedSequence!==null && expectedSequence!==undefined && proof.sequence!==expectedSequence) return {verified:false,reason:"SEQUENCE_MISMATCH"};
  if(proof.sequence===1 && proof.parent_hash!==null) return {verified:false,reason:"FIRST_PARENT_INVALID"};
  if(expectedParentHash!==null && expectedParentHash!==undefined && proof.parent_hash!==expectedParentHash) return {verified:false,reason:"PARENT_MISMATCH"};
  const core={schema:proof.schema,continuity_root:proof.continuity_root,sequence:proof.sequence,parent_hash:proof.parent_hash,state_hash:proof.state_hash,decision_hash:proof.decision_hash,issued_at:proof.issued_at,signer_key_id:proof.signer_key_id,policy_fingerprint_sha256:proof.policy_fingerprint_sha256};
  if(jcsSha256(core)!==proof.continuity_hash) return {verified:false,reason:"CONTINUITY_HASH_MISMATCH"};
  return {verified:true,reason:"VALID",core};
}

export function verifyProofChain(chain,{expectedContinuityRoot,verifySignature}={}){
  if(!Array.isArray(chain) || chain.length===0) return {verified:false,reason:"EMPTY_CHAIN"};
  if(typeof verifySignature!=="function") return {verified:false,reason:"SIGNATURE_VERIFIER_REQUIRED"};
  let parent=null;
  for(let i=0;i<chain.length;i++){
    const expectedSequence=i+1;
    const sig=verifySignature(chain[i]);
    if(!sig || sig.verified!==true) return {verified:false,reason:"SIGNATURE_INVALID",failedSequence:expectedSequence};
    const result=verifyProofCore(chain[i],{expectedContinuityRoot,expectedParentHash:parent,expectedSequence});
    if(!result.verified) return {verified:false,reason:result.reason,failedSequence:expectedSequence};
    parent=chain[i].continuity_hash;
  }
  return {verified:true,reason:"CONTINUITY_PROVEN",sequence:chain.length,head_hash:parent};
}