import { createSigningIdentity, signProof, verifyProofSignature } from '../src/evidence/proof-signature-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash, verifyProofChain } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const N=100;

const identity=createSigningIdentity({keyId:'scale-probe-key'});
const root=createContinuityRoot({
  session_id:'sess-scale-1',
  subject:'user-scale-1',
  issuer:'issuer-scale',
  auth_time:'2026-09-16T07:00:00.000Z',
  client_context:{device_id:'dev-scale-1'}
});

function utc(seq){
  return new Date(Date.UTC(2026,8,16,7,0,0,seq)).toISOString();
}

function build(sequence,parent_hash){
  const core=createProofCore({
    continuity_root:root.continuity_root,
    sequence,
    parent_hash,
    state_hash:'1'.repeat(64),
    decision_hash:'2'.repeat(64),
    issued_at:utc(sequence),
    signer_key_id:identity.keyId,
    policy_fingerprint_sha256:'3'.repeat(64)
  });
  return signProof(identity,addContinuityHash(core));
}

const t0=Date.now();
const chain=[];
let parent=null;
for(let i=1;i<=N;i++){
  const p=build(i,parent);
  chain.push(p);
  parent=p.continuity_hash;
}
const tBuild=Date.now()-t0;

const t1=Date.now();
const v=verifyProofChain(chain,{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
const tVerify=Date.now()-t1;

log('CHAIN_LENGTH',chain.length);
log('VERIFIED',v.verified?'PASS':'FAIL');
log('REASON',v.reason);
log('HEAD_MATCH',v.head_hash===chain[N-1].continuity_hash?'PASS':'FAIL');
log('BUILD_MS',tBuild);
log('VERIFY_MS',tVerify);
log('BUILD_MS_PER_PROOF',(tBuild/N).toFixed(3));
log('VERIFY_MS_PER_PROOF',(tVerify/N).toFixed(3));
log('SCALE_PROBE_DONE',1);
