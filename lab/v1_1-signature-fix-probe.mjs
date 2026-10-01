import { createSigningIdentity, signProof, verifyProofSignature } from '../src/evidence/proof-signature-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash, verifyProofChain } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

const legit=createSigningIdentity({keyId:'legit-key'});
const attacker=createSigningIdentity({keyId:'attacker-key'});
const root=createContinuityRoot({
  session_id:'sess-fix',
  subject:'user-fix',
  issuer:'issuer-fix',
  auth_time:'2026-09-16T09:00:00.000Z',
  client_context:{device_id:'dev-fix'}
});

function buildCore(seq,parent){
  return createProofCore({
    continuity_root:root.continuity_root,
    sequence:seq,
    parent_hash:parent,
    state_hash:'1'.repeat(64),
    decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T09:00:0'+seq+'.000Z',
    signer_key_id:legit.keyId,
    policy_fingerprint_sha256:'3'.repeat(64)
  });
}

const c1=addContinuityHash(buildCore(1,null));
const c2=addContinuityHash(buildCore(2,c1.continuity_hash));
const c3=addContinuityHash(buildCore(3,c2.continuity_hash));

const p1=signProof(legit,c1);
const p2=signProof(legit,c2);
const p3=signProof(legit,c3);
const p1Forged=signProof(attacker,c1);
const p1NoSig={...c1};

const noVerifier=verifyProofChain([p1,p2,p3],{expectedContinuityRoot:root.continuity_root});
log('NO_VERIFIER_REJECTED',!noVerifier.verified?'PASS':'FAIL');
log('NO_VERIFIER_REASON',noVerifier.reason);

const good=verifyProofChain([p1,p2,p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('LEGIT_CHAIN_VERIFY',good.verified?'PASS':'FAIL');
log('LEGIT_CHAIN_REASON',good.reason);

const forged=verifyProofChain([p1Forged,p2,p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('FORGED_P1_REJECTED',!forged.verified?'PASS':'FAIL');
log('FORGED_P1_REASON',forged.reason);

const noSig=verifyProofChain([p1NoSig,p2,p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('NO_SIG_P1_REJECTED',!noSig.verified?'PASS':'FAIL');
log('NO_SIG_P1_REASON',noSig.reason);

const tamperedP2={...p2,decision_hash:'9'.repeat(64)};
const tampered=verifyProofChain([p1,tamperedP2,p3],{expectedContinuityRoot:root.continuity_root,verifySignature:verifyProofSignature});
log('TAMPERED_P2_REJECTED',!tampered.verified?'PASS':'FAIL');
log('TAMPERED_P2_REASON',tampered.reason);

log('FIX_PROBE_DONE',1);
