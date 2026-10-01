import fs from "fs";
import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor } from '../src/evidence/trust-anchor.js';
import { createKeyLifecycleStore, registerKey, retireKey, revokeKey } from '../src/evidence/key-lifecycle-v1_1.js';
import { verifyTrustedProofChainWithLifecycleV1_1 } from '../src/evidence/trusted-proof-verifier-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const dir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_lifecycle_integration";
fs.rmSync(dir,{recursive:true,force:true});

const signerA=createSigningIdentity({keyId:'signer-lifecycle-a'});
const signerB=createSigningIdentity({keyId:'signer-lifecycle-b'});

const trustStore=createTrustAnchorStore();
registerTrustAnchor(trustStore,signerA.publicKeySpkiBase64,{version:1,created_at:'2026-09-01T00:00:00Z'});
registerTrustAnchor(trustStore,signerB.publicKeySpkiBase64,{version:1,created_at:'2026-09-01T00:00:00Z'});

const lifecycle=createKeyLifecycleStore();
registerKey(lifecycle,signerA.publicKeyFingerprintSha256,{valid_from:'2026-09-01T00:00:00.000Z',valid_until:'2027-09-01T00:00:00.000Z',version:1});
registerKey(lifecycle,signerB.publicKeyFingerprintSha256,{valid_from:'2026-09-01T00:00:00.000Z',valid_until:'2027-09-01T00:00:00.000Z',version:1});

const root=createContinuityRoot({
  session_id:'sess-lifecycle',
  subject:'user-lifecycle',
  issuer:'issuer-lifecycle',
  auth_time:'2026-09-16T20:00:00.000Z',
  client_context:{device_id:'dev-lifecycle'}
});

function coreWith(seq,parent,identity,issuedAt){
  return createProofCore({
    continuity_root:root.continuity_root,sequence:seq,parent_hash:parent,
    state_hash:'1'.repeat(64),decision_hash:'2'.repeat(64),
    issued_at:issuedAt,
    signer_key_id:identity.keyId,policy_fingerprint_sha256:'3'.repeat(64)
  });
}

const c1=addContinuityHash(coreWith(1,null,signerA,'2026-09-16T20:00:01.000Z'));
const c2=addContinuityHash(coreWith(2,c1.continuity_hash,signerA,'2026-09-16T20:00:02.000Z'));
const c3=addContinuityHash(coreWith(3,c2.continuity_hash,signerA,'2026-09-16T20:00:03.000Z'));

const chainGood=[signProof(signerA,c1),signProof(signerA,c2),signProof(signerA,c3)];

const r1=verifyTrustedProofChainWithLifecycleV1_1(chainGood,{trustStore,keyLifecycleStore:lifecycle,expectedContinuityRoot:root.continuity_root});
log('GOOD_CHAIN_WITH_LIFECYCLE',r1.verified?'PASS':'FAIL');
log('GOOD_CHAIN_REASON',r1.reason);

const r2=verifyTrustedProofChainWithLifecycleV1_1(chainGood,{trustStore,expectedContinuityRoot:root.continuity_root});
log('NO_LIFECYCLE_STORE_REJECTED',!r2.verified?'PASS':'FAIL');
log('NO_LIFECYCLE_STORE_REASON',r2.reason);

const emptyStore=createKeyLifecycleStore();
const r3=verifyTrustedProofChainWithLifecycleV1_1(chainGood,{trustStore,keyLifecycleStore:emptyStore,expectedContinuityRoot:root.continuity_root});
log('UNREGISTERED_KEY_REJECTED',!r3.verified?'PASS':'FAIL');
log('UNREGISTERED_KEY_REASON',r3.reason);

retireKey(lifecycle,signerA.publicKeyFingerprintSha256,{retired_at:'2026-09-16T20:00:02.500Z'});
const r4=verifyTrustedProofChainWithLifecycleV1_1(chainGood,{trustStore,keyLifecycleStore:lifecycle,expectedContinuityRoot:root.continuity_root});
log('POST_RETIREMENT_PROOF_REJECTED',!r4.verified?'PASS':'FAIL');
log('POST_RETIREMENT_REASON',r4.reason);
log('POST_RETIREMENT_FAILED_SEQ',r4.failedSequence);

const r5=verifyTrustedProofChainWithLifecycleV1_1(chainGood,{trustStore,keyLifecycleStore:lifecycle,expectedContinuityRoot:root.continuity_root,requireActiveNow:true});
log('REQUIRE_ACTIVE_NOW_REJECTED',!r5.verified?'PASS':'FAIL');
log('REQUIRE_ACTIVE_NOW_REASON',r5.reason);

const cB1=addContinuityHash(coreWith(1,null,signerB,'2026-09-16T21:00:01.000Z'));
const cB2=addContinuityHash(coreWith(2,cB1.continuity_hash,signerB,'2026-09-16T21:00:02.000Z'));
const chainB=[signProof(signerB,cB1),signProof(signerB,cB2)];

revokeKey(lifecycle,signerB.publicKeyFingerprintSha256,{revoked_at:'2026-09-16T21:00:01.500Z',compromise_window:{start:'2026-09-16T21:00:00.000Z',end:'2026-09-16T21:00:03.000Z'}});

const r6=verifyTrustedProofChainWithLifecycleV1_1(chainB,{trustStore,keyLifecycleStore:lifecycle,expectedContinuityRoot:root.continuity_root});
log('COMPROMISE_WINDOW_PROOF_REJECTED',!r6.verified?'PASS':'FAIL');
log('COMPROMISE_WINDOW_REASON',r6.reason);
log('COMPROMISE_WINDOW_FAILED_SEQ',r6.failedSequence);

fs.rmSync(dir,{recursive:true,force:true});
log('CLEANUP','PASS');
log('LIFECYCLE_INTEGRATION_PROBE_DONE',1);
