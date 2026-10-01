import crypto from "crypto";
import fs from "fs";
import path from "path";
import { jcsCanonicalize } from "../core/canonical-v1_1.js";
import { createSigningIdentity } from "./proof-signature-v1_1.js";

const STATE_SCHEMA_ID = "session-continuity.v1_1.witness.state";
const RECEIPT_SCHEMA_ID = "session-continuity.v1_1.witness.receipt";
const VERSION = 1;
const STATE_FILE = "WITNESS_STATE.json";
const LOCK_FILE = "WITNESS.lock";

function sha256(text){
  return crypto.createHash("sha256").update(Buffer.from(text,"utf8")).digest("hex").toLowerCase();
}

function ensureDir(dir){ fs.mkdirSync(dir,{recursive:true}); }

function atomicWrite(filePath,text){
  const temp=filePath+".tmp-"+process.pid+"-"+Date.now()+"-"+Math.random().toString(16).slice(2);
  const fd=fs.openSync(temp,"w");
  try{ fs.writeSync(fd,text,null,"utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temp,filePath);
}

function sleep(ms){ const end=Date.now()+ms; while(Date.now()<end){} }

function acquireLock(lockPath,timeoutMs){
  const started=Date.now();
  while(true){
    try{
      const fd=fs.openSync(lockPath,"wx");
      try{ fs.writeSync(fd,String(process.pid),null,"utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      return;
    } catch(err){
      if(err.code!=="EEXIST") throw err;
      if(Date.now()-started>=timeoutMs) throw new Error("WITNESS_LOCK_TIMEOUT");
      sleep(5);
    }
  }
}

function releaseLock(lockPath){
  try{ fs.unlinkSync(lockPath); } catch(err){ if(err.code!=="ENOENT") throw err; }
}

function emptyState(witnessDomainId){
  return {schema_id:STATE_SCHEMA_ID,version:VERSION,witness_domain_id:witnessDomainId,roots:{}};
}

function loadState(filePath,witnessDomainId){
  if(!fs.existsSync(filePath)) return emptyState(witnessDomainId);
  let raw;
  try{ raw=JSON.parse(fs.readFileSync(filePath,"utf8")); } catch { throw new Error("WITNESS_STATE_JSON_INVALID:FAIL_CLOSED"); }
  if(!raw||typeof raw!=="object") throw new Error("WITNESS_STATE_OBJECT_INVALID");
  if(raw.schema_id!==STATE_SCHEMA_ID) throw new Error("WITNESS_STATE_SCHEMA_INVALID");
  if(Number(raw.version)!==VERSION) throw new Error("WITNESS_STATE_VERSION_INVALID");
  if(raw.witness_domain_id!==witnessDomainId) throw new Error("WITNESS_STATE_DOMAIN_MISMATCH");
  if(!raw.roots||typeof raw.roots!=="object") throw new Error("WITNESS_STATE_ROOTS_INVALID");
  return raw;
}

function saveState(filePath,state){ atomicWrite(filePath,jcsCanonicalize(state)+"\n"); }

function makeReceiptPayload(witnessDomainId,continuityRoot,sequence,continuityHash,proofHash,witnessHeadSequence,witnessHeadHash,witnessKeyId,issuedAt){
  return {
    schema_id:RECEIPT_SCHEMA_ID,
    version:VERSION,
    witness_domain_id:witnessDomainId,
    continuity_root:continuityRoot,
    sequence,
    continuity_hash:continuityHash,
    proof_hash:proofHash,
    witness_head_sequence:witnessHeadSequence,
    witness_head_hash:witnessHeadHash,
    witness_key_id:witnessKeyId,
    issued_at:issuedAt
  };
}

function signPayload(identity,payload){
  const body=jcsCanonicalize(payload);
  const sig=crypto.sign(null,Buffer.from(body,"utf8"),identity.privateKey).toString("base64");
  return {
    body:payload,
    signature_base64:sig,
    witness_public_key_fingerprint_sha256:identity.publicKeyFingerprintSha256,
    witness_public_key_spki_base64:identity.publicKeySpkiBase64
  };
}

export function createWitnessIdentity({keyId=null}={}){
  const base=createSigningIdentity({keyId});
  return Object.freeze({keyId:base.keyId,privateKey:base.privateKey,publicKey:base.publicKey,publicKeySpkiBase64:base.publicKeySpkiBase64,publicKeyFingerprintSha256:base.publicKeyFingerprintSha256});
}

export function createDurableWitness({directory,witnessDomainId,identity,lockTimeoutMs=3000}){
  if(typeof directory!=="string"||!directory.length) throw new Error("WITNESS_DIRECTORY_INVALID");
  if(typeof witnessDomainId!=="string"||!witnessDomainId.length) throw new Error("WITNESS_DOMAIN_ID_INVALID");
  if(!identity||!identity.privateKey) throw new Error("WITNESS_IDENTITY_REQUIRED");
  ensureDir(directory);
  const statePath=path.join(directory,STATE_FILE);
  const lockPath=path.join(directory,LOCK_FILE);
  const state=loadState(statePath,witnessDomainId);
  saveState(statePath,state);
  return {version:VERSION,directory,witnessDomainId,identity,statePath,lockPath,state,lockTimeoutMs};
}

function readState(store){ return loadState(store.statePath,store.witnessDomainId); }

function recordObservation(store,continuityRoot,sequence,continuityHash,proofHash,issuedAt){
  const root=store.state.roots[continuityRoot]||{head_sequence:0,head_hash:"",history:{}};
  const key=String(sequence);
  const existing=root.history[key];
  if(existing){
    if(existing.continuity_hash===continuityHash) return {result:"IDEMPOTENT_REPLAY",head_sequence:root.head_sequence,head_hash:root.head_hash,existing};
    return {result:"EQUIVOCATION_FORK",head_sequence:root.head_sequence,head_hash:root.head_hash,existing,observed:{continuity_hash:continuityHash,proof_hash:proofHash}};
  }
  const expected=root.head_sequence+1;
  if(sequence>expected) return {result:"SEQUENCE_GAP",head_sequence:root.head_sequence,head_hash:root.head_hash,expected,observed:sequence};
  if(sequence<expected) return {result:"SEQUENCE_ROLLBACK",head_sequence:root.head_sequence,head_hash:root.head_hash,expected,observed:sequence};
  if(sequence>1){
    const prevKey=String(sequence-1);
    const prev=root.history[prevKey];
    if(!prev) return {result:"SEQUENCE_GAP",head_sequence:root.head_sequence,head_hash:root.head_hash,expected,observed:sequence};
    if(prev.continuity_hash!==root.head_hash) return {result:"PARENT_MISMATCH",head_sequence:root.head_sequence,head_hash:root.head_hash,expected,observed:sequence};
  }
  root.history[key]={continuity_hash:continuityHash,proof_hash:proofHash,issued_at:issuedAt};
  root.head_sequence=sequence;
  root.head_hash=continuityHash;
  store.state.roots[continuityRoot]=root;
  return {result:"ADVANCED",head_sequence:root.head_sequence,head_hash:root.head_hash};
}

export function witnessHealth(store){
  if(!store||store.version!==VERSION) return {status:"INVALID_STORE",reason:"WITNESS_STORE_INVALID"};
  if(!fs.existsSync(store.statePath)) return {status:"OK",reason:"FRESH_STATE"};
  try{ loadState(store.statePath,store.witnessDomainId); return {status:"OK",reason:"STATE_VALID"}; }
  catch(err){ return {status:"FAIL_CLOSED",reason:err.message}; }
}

export function witnessObserve(store,{continuityRoot,sequence,continuityHash,proofHash,issuedAt}){
  if(!store||store.version!==VERSION) throw new Error("WITNESS_STORE_INVALID");
  if(typeof continuityRoot!=="string"||!/^[0-9a-f]{64}$/i.test(continuityRoot)) throw new Error("WITNESS_ROOT_INVALID");
  if(!Number.isInteger(sequence)||sequence<1) throw new Error("WITNESS_SEQUENCE_INVALID");
  if(typeof continuityHash!=="string"||!/^[0-9a-f]{64}$/i.test(continuityHash)) throw new Error("WITNESS_CONTINUITY_HASH_INVALID");
  if(typeof proofHash!=="string"||!/^[0-9a-f]{64}$/i.test(proofHash)) throw new Error("WITNESS_PROOF_HASH_INVALID");
  if(typeof issuedAt!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(issuedAt)) throw new Error("WITNESS_ISSUED_AT_INVALID");
  acquireLock(store.lockPath,store.lockTimeoutMs);
  try{
    store.state=readState(store);
    const outcome=recordObservation(store,continuityRoot,sequence,continuityHash,proofHash,issuedAt);
    if(outcome.result==="ADVANCED"){
      const root=store.state.roots[continuityRoot];
      const payload=makeReceiptPayload(store.witnessDomainId,continuityRoot,sequence,continuityHash,proofHash,root.head_sequence,root.head_hash,store.identity.keyId,issuedAt);
      const receipt=signPayload(store.identity,payload);
      root.history[String(sequence)].receipt=receipt;
      saveState(store.statePath,store.state);
      return {result:outcome.result,receipt,head_sequence:root.head_sequence,head_hash:root.head_hash};
    }
    if(outcome.result==="IDEMPOTENT_REPLAY"){
      const root=store.state.roots[continuityRoot];
      if(outcome.existing?.receipt){
        return {result:outcome.result,receipt:outcome.existing.receipt,head_sequence:root.head_sequence,head_hash:root.head_hash};
      }
      const payload=makeReceiptPayload(store.witnessDomainId,continuityRoot,sequence,continuityHash,proofHash,root.head_sequence,root.head_hash,store.identity.keyId,issuedAt);
      const receipt=signPayload(store.identity,payload);
      outcome.existing.receipt=receipt;
      saveState(store.statePath,store.state);
      return {result:outcome.result,receipt,head_sequence:root.head_sequence,head_hash:root.head_hash};
    }
    if(outcome.result!=="EQUIVOCATION_FORK"){
      return {result:outcome.result,receipt:null,head_sequence:outcome.head_sequence,head_hash:outcome.head_hash,details:outcome};
    }
    const root=store.state.roots[continuityRoot];
    const payload=makeReceiptPayload(store.witnessDomainId,continuityRoot,sequence,continuityHash,proofHash,root.head_sequence,root.head_hash,store.identity.keyId,issuedAt);
    const receipt=signPayload(store.identity,payload);
    return {result:outcome.result,receipt,head_sequence:root.head_sequence,head_hash:root.head_hash};
  } finally { releaseLock(store.lockPath); }
}

export function witnessGetHead(store,continuityRoot){
  if(!store||store.version!==VERSION) throw new Error("WITNESS_STORE_INVALID");
  store.state=readState(store);
  const root=store.state.roots[continuityRoot];
  if(!root) return {head_sequence:0,head_hash:""};
  return {head_sequence:root.head_sequence,head_hash:root.head_hash};
}

export function verifyWitnessReceipt(receipt){
  if(!receipt||typeof receipt!=="object") return {verified:false,reason:"RECEIPT_MISSING"};
  const {body,signature_base64,witness_public_key_fingerprint_sha256,witness_public_key_spki_base64}=receipt;
  if(!body||typeof body!=="object") return {verified:false,reason:"RECEIPT_BODY_INVALID"};
  if(body.schema_id!==RECEIPT_SCHEMA_ID) return {verified:false,reason:"RECEIPT_SCHEMA_INVALID"};
  if(typeof signature_base64!=="string"||!signature_base64.length) return {verified:false,reason:"RECEIPT_SIGNATURE_MISSING"};
  if(typeof witness_public_key_spki_base64!=="string"||!witness_public_key_spki_base64.length) return {verified:false,reason:"RECEIPT_KEY_MISSING"};
  if(typeof witness_public_key_fingerprint_sha256!=="string"||!/^[0-9a-f]{64}$/i.test(witness_public_key_fingerprint_sha256)) return {verified:false,reason:"RECEIPT_FINGERPRINT_INVALID"};
  const der=Buffer.from(witness_public_key_spki_base64,"base64");
  const actual=crypto.createHash("sha256").update(der).digest("hex").toLowerCase();
  if(actual!==witness_public_key_fingerprint_sha256.toLowerCase()) return {verified:false,reason:"RECEIPT_FINGERPRINT_MISMATCH"};
  let publicKey;
  try{ publicKey=crypto.createPublicKey({key:der,type:"spki",format:"der"}); } catch { return {verified:false,reason:"RECEIPT_KEY_INVALID"}; }
  const payloadBytes=Buffer.from(jcsCanonicalize(body),"utf8");
  let ok=false;
  try{ ok=crypto.verify(null,payloadBytes,publicKey,Buffer.from(signature_base64,"base64")); } catch { return {verified:false,reason:"RECEIPT_SIGNATURE_INVALID"}; }
  return ok?{verified:true,reason:"RECEIPT_VALID",witness_public_key_fingerprint_sha256:actual}:{verified:false,reason:"RECEIPT_SIGNATURE_INVALID"};
}

export function detectWitnessEquivocation(receiptA,receiptB){
  if(!receiptA||!receiptB) return {equivocation:false,reason:"RECEIPTS_REQUIRED"};
  const a=receiptA.body,b=receiptB.body;
  if(!a||!b) return {equivocation:false,reason:"RECEIPT_BODY_INVALID"};
  const va=verifyWitnessReceipt(receiptA);
  const vb=verifyWitnessReceipt(receiptB);
  if(!va.verified||!vb.verified) return {equivocation:false,reason:"RECEIPT_SIGNATURE_INVALID"};
  if(a.witness_domain_id!==b.witness_domain_id) return {equivocation:false,reason:"DIFFERENT_DOMAIN"};
  if(a.witness_key_id!==b.witness_key_id) return {equivocation:false,reason:"DIFFERENT_WITNESS_KEY"};
  if(a.continuity_root!==b.continuity_root) return {equivocation:false,reason:"DIFFERENT_ROOT"};
  if(a.sequence!==b.sequence) return {equivocation:false,reason:"DIFFERENT_SEQUENCE"};
  if(a.continuity_hash===b.continuity_hash) return {equivocation:false,reason:"IDENTICAL"};
  return {equivocation:true,reason:"EQUIVOCATION_FORK",root:a.continuity_root,sequence:a.sequence,hash_a:a.continuity_hash,hash_b:b.continuity_hash};
}
