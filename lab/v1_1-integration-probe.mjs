import { createSigningIdentity, signProof, verifyProofSignature } from '../src/evidence/proof-signature-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

let identity;
try {
  identity=createSigningIdentity({keyId:'probe-key-1'});
  log('IDENTITY_CREATED','PASS');
} catch(e){
  log('IDENTITY_CREATED','FAIL');
  log('IDENTITY_ERROR',e.message);
}

let root;
try {
  root=createContinuityRoot({
    session_id:'sess-probe-1',
    subject:'user-probe-1',
    issuer:'issuer-probe',
    auth_time:'2026-09-16T05:00:00.000Z',
    client_context:{device_id:'dev-probe-1'}
  });
  log('ROOT_CREATED','PASS');
} catch(e){
  log('ROOT_CREATED','FAIL');
  log('ROOT_ERROR',e.message);
}

let core;
try {
  core=createProofCore({
    continuity_root:root.continuity_root,
    sequence:1,
    parent_hash:null,
    state_hash:'a'.repeat(64),
    decision_hash:'b'.repeat(64),
    issued_at:'2026-09-16T05:00:01.000Z',
    signer_key_id:identity.keyId,
    policy_fingerprint_sha256:'c'.repeat(64)
  });
  log('CORE_CREATED','PASS');
  log('CORE_SCHEMA',core.schema);
} catch(e){
  log('CORE_CREATED','FAIL');
  log('CORE_ERROR',e.message);
}

let withHash;
try {
  withHash=addContinuityHash(core);
  log('HASH_ADDED','PASS');
  log('HASH_SCHEMA',withHash.schema);
} catch(e){
  log('HASH_ADDED','FAIL');
  log('HASH_ERROR',e.message);
}

let signed;
try {
  signed=signProof(identity,withHash);
  log('SIGNED','PASS');
  log('SIGNED_SCHEMA',signed.schema);
} catch(e){
  log('SIGNED','FAIL');
  log('SIGNED_ERROR',e.message);
}

if(signed){
  try {
    const v=verifyProofSignature(signed);
    log('VERIFIED',v.verified?'PASS':'FAIL');
    log('VERIFY_REASON',v.reason);
  } catch(e){
    log('VERIFIED','FAIL');
    log('VERIFY_ERROR',e.message);
  }
}

console.log('PROBE_DONE');
