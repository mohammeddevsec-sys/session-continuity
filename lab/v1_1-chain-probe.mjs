import { createSigningIdentity, signProof, verifyProofSignature } from '../src/evidence/proof-signature-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash, verifyProofChain } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

const identity=createSigningIdentity({keyId:'chain-probe-key'});
const root=createContinuityRoot({
  session_id:'sess-chain-1',
  subject:'user-chain-1',
  issuer:'issuer-chain',
  auth_time:'2026-09-16T06:00:00.000Z',
  client_context:{device_id:'dev-chain-1'}
});

function buildSignedProof(sequence, parent_hash){
  const core=createProofCore({
    continuity_root:root.continuity_root,
    sequence,
    parent_hash,
    state_hash:'1'.repeat(64),
    decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T06:00:0'+sequence+'.000Z',
    signer_key_id:identity.keyId,
    policy_fingerprint_sha256:'3'.repeat(64)
  });
  return signProof(identity,addContinuityHash(core));
}

const p1=buildSignedProof(1,null);
const p2=buildSignedProof(2,p1.continuity_hash);
const p3=buildSignedProof(3,p2.continuity_hash);

const v=verifyProofChain([p1,p2,p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('CHAIN_VERIFY',v.verified?'PASS':'FAIL');
log('CHAIN_REASON',v.reason);
log('CHAIN_HEAD',v.head_hash===p3.continuity_hash?'PASS':'FAIL');

const t=verifyProofChain([p1,{...p2,decision_hash:'9'.repeat(64)},p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('TAMPER_REJECTED',!t.verified?'PASS':'FAIL');
log('TAMPER_REASON',t.reason);

const wp=verifyProofChain([p1,p2,{...p3,parent_hash:'f'.repeat(64)}],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('WRONG_PARENT_REJECTED',!wp.verified?'PASS':'FAIL');
log('WRONG_PARENT_REASON',wp.reason);

const g=verifyProofChain([p1,p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('SEQUENCE_GAP_REJECTED',!g.verified?'PASS':'FAIL');
log('SEQUENCE_GAP_REASON',g.reason);

const wr=verifyProofChain([p1,p2,p3],{expectedContinuityRoot:'0'.repeat(64),verifySignature:verifyProofSignature});
log('WRONG_ROOT_REJECTED',!wr.verified?'PASS':'FAIL');
log('WRONG_ROOT_REASON',wr.reason);

const single=verifyProofSignature(p1);
log('SINGLE_SIGNATURE',single.verified?'PASS':'FAIL');
log('SINGLE_REASON',single.reason);

console.log('CHAIN_PROBE_DONE');
