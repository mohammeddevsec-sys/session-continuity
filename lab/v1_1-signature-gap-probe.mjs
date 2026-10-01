import { createSigningIdentity, signProof, verifyProofSignature } from '../src/evidence/proof-signature-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash, verifyProofChain } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

const legit=createSigningIdentity({keyId:'legit-key'});
const attacker=createSigningIdentity({keyId:'attacker-key'});
const root=createContinuityRoot({
  session_id:'sess-sig-gap',
  subject:'user-sig-gap',
  issuer:'issuer-sig-gap',
  auth_time:'2026-09-16T08:00:00.000Z',
  client_context:{device_id:'dev-sig-gap'}
});

function buildCore(seq,parent){
  return createProofCore({
    continuity_root:root.continuity_root,
    sequence:seq,
    parent_hash:parent,
    state_hash:'1'.repeat(64),
    decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T08:00:0'+seq+'.000Z',
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

const good=verifyProofChain([p1,p2,p3],{expectedContinuityRoot:root.continuity_root});
log('LEGIT_CHAIN_VERIFY',good.verified?'PASS':'FAIL');
log('LEGIT_CHAIN_REASON',good.reason);

const sig=verifyProofSignature(p1);
log('LEGIT_P1_SIG',sig.verified?'PASS':'FAIL');

// Attacker signs the SAME core with a different key
const p1Forged=signProof(attacker,c1);
log('FORGED_P1_SIG_VALID',verifyProofSignature(p1Forged).verified?'PASS':'FAIL');
log('FORGED_P1_FINGERPRINT_MATCH',p1Forged.signer_public_key_fingerprint_sha256===p1.signer_public_key_fingerprint_sha256?'SAME':'DIFFERENT');

// Build chain with forged p1 but same continuity_hash
const chainWithForged=verifyProofChain([p1Forged,p2,p3],{expectedContinuityRoot:root.continuity_root});
log('CHAIN_WITH_FORGED_P1_VERIFY',chainWithForged.verified?'PASS':'FAIL');
log('CHAIN_WITH_FORGED_P1_REASON',chainWithForged.reason);

// Build chain with proof missing signature field entirely
const p1NoSig={...c1};
log('P1_NO_SIG_HAS_SIGNATURE_FIELD','signature_base64' in p1NoSig?'YES':'NO');
const chainNoSig=verifyProofChain([p1NoSig,p2,p3],{expectedContinuityRoot:root.continuity_root});
log('CHAIN_NO_SIG_P1_VERIFY',chainNoSig.verified?'PASS':'FAIL');
log('CHAIN_NO_SIG_P1_REASON',chainNoSig.reason);

console.log('SIG_GAP_PROBE_DONE');
