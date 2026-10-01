import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor, revokeTrustAnchor } from '../src/evidence/trust-anchor.js';
import { verifyTrustedProofChainV1_1 } from '../src/evidence/trusted-proof-verifier-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

const legit=createSigningIdentity({keyId:'legit-trust-key'});
const attacker=createSigningIdentity({keyId:'attacker-trust-key'});

const store=createTrustAnchorStore();
registerTrustAnchor(store,legit.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T10:00:00Z',label:'legit-trust'});

const root=createContinuityRoot({
  session_id:'sess-trusted',
  subject:'user-trusted',
  issuer:'issuer-trusted',
  auth_time:'2026-09-16T10:00:00.000Z',
  client_context:{device_id:'dev-trusted'}
});

function buildCore(seq,parent,keyId){
  return createProofCore({
    continuity_root:root.continuity_root,
    sequence:seq,
    parent_hash:parent,
    state_hash:'1'.repeat(64),
    decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T10:00:0'+seq+'.000Z',
    signer_key_id:keyId,
    policy_fingerprint_sha256:'3'.repeat(64)
  });
}

function buildChain(identity){
  const c1=addContinuityHash(buildCore(1,null,identity.keyId));
  const c2=addContinuityHash(buildCore(2,c1.continuity_hash,identity.keyId));
  const c3=addContinuityHash(buildCore(3,c2.continuity_hash,identity.keyId));
  return [signProof(identity,c1),signProof(identity,c2),signProof(identity,c3)];
}

const legitChain=buildChain(legit);
const attackerChain=buildChain(attacker);

const legitResult=verifyTrustedProofChainV1_1(legitChain,{trustStore:store,expectedContinuityRoot:root.continuity_root});
log('LEGIT_TRUSTED_CHAIN',legitResult.verified?'PASS':'FAIL');
log('LEGIT_TRUSTED_REASON',legitResult.reason);
log('LEGIT_HEAD_MATCH',legitResult.head_hash===legitChain[2].continuity_hash?'PASS':'FAIL');

const attackerResult=verifyTrustedProofChainV1_1(attackerChain,{trustStore:store,expectedContinuityRoot:root.continuity_root});
log('ATTACKER_CHAIN_REJECTED',!attackerResult.verified?'PASS':'FAIL');
log('ATTACKER_REASON',attackerResult.reason);
log('ATTACKER_FAILED_SEQ',attackerResult.failedSequence);

const badStore=verifyTrustedProofChainV1_1(legitChain,{trustStore:null,expectedContinuityRoot:root.continuity_root});
log('NULL_STORE_REJECTED',!badStore.verified?'PASS':'FAIL');
log('NULL_STORE_REASON',badStore.reason);

const emptyChain=verifyTrustedProofChainV1_1([],{trustStore:store,expectedContinuityRoot:root.continuity_root});
log('EMPTY_CHAIN_REJECTED',!emptyChain.verified?'PASS':'FAIL');
log('EMPTY_CHAIN_REASON',emptyChain.reason);

const wrongRoot=verifyTrustedProofChainV1_1(legitChain,{trustStore:store,expectedContinuityRoot:'0'.repeat(64)});
log('WRONG_ROOT_REJECTED',!wrongRoot.verified?'PASS':'FAIL');
log('WRONG_ROOT_REASON',wrongRoot.reason);

revokeTrustAnchor(store,legit.publicKeyFingerprintSha256);
const revokedResult=verifyTrustedProofChainV1_1(legitChain,{trustStore:store,expectedContinuityRoot:root.continuity_root});
log('REVOKED_SIGNER_REJECTED',!revokedResult.verified?'PASS':'FAIL');
log('REVOKED_SIGNER_REASON',revokedResult.reason);

log('TRUSTED_PROBE_DONE',1);
