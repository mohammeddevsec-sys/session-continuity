import fs from "fs";
import { createSigningIdentity, signProof, verifyProofSignature } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor } from '../src/evidence/trust-anchor.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve } from '../src/evidence/witness-v1_1.js';
import { buildPortablePackage, verifyPortablePackage } from '../src/evidence/portable-package-v1_1.js';
import { verifyTrustedProofChainV1_1 } from '../src/evidence/trusted-proof-verifier-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';
import { createDurableSequenceStore, verifyAndAdvanceDurableSequence, verifyDurableSequenceStore, getDurableSequence } from '../src/core/durable-sequence-guard-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const dir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_full_integration";
fs.rmSync(dir,{recursive:true,force:true});

const signer=createSigningIdentity({keyId:'signer-full'});
const witness=createWitnessIdentity({keyId:'witness-full'});
const packager=createSigningIdentity({keyId:'packager-full'});
const attacker=createSigningIdentity({keyId:'attacker-full'});
const fakePackager=createSigningIdentity({keyId:'fake-packager-full'});

const signerStore=createTrustAnchorStore();
registerTrustAnchor(signerStore,signer.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T18:00:00Z'});
const witnessStore=createTrustAnchorStore();
registerTrustAnchor(witnessStore,witness.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T18:00:00Z'});
const packagerStore=createTrustAnchorStore();
registerTrustAnchor(packagerStore,packager.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T18:00:00Z'});

const root=createContinuityRoot({
  session_id:'sess-full',subject:'user-full',issuer:'issuer-full',
  auth_time:'2026-09-16T18:00:00.000Z',client_context:{device_id:'dev-full'}
});

function core(seq,par){
  return createProofCore({
    continuity_root:root.continuity_root,sequence:seq,parent_hash:par,
    state_hash:'1'.repeat(64),decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T18:00:0'+seq+'.000Z',
    signer_key_id:signer.keyId,policy_fingerprint_sha256:'3'.repeat(64)
  });
}
const c1=addContinuityHash(core(1,null));
const c2=addContinuityHash(core(2,c1.continuity_hash));
const c3=addContinuityHash(core(3,c2.continuity_hash));
const p1=signProof(signer,c1);
const p2=signProof(signer,c2);
const p3=signProof(signer,c3);
const chain=[p1,p2,p3];

const seqStore=createDurableSequenceStore(dir+'\\seq');
let sr=verifyAndAdvanceDurableSequence(seqStore,'sess-full',1);
log('SEQ_1',sr.decision==='CONTINUOUS'?'PASS':'FAIL');
sr=verifyAndAdvanceDurableSequence(seqStore,'sess-full',2);
log('SEQ_2',sr.decision==='CONTINUOUS'?'PASS':'FAIL');
sr=verifyAndAdvanceDurableSequence(seqStore,'sess-full',3);
log('SEQ_3',sr.decision==='CONTINUOUS'?'PASS':'FAIL');
log('SEQ_VERIFY',verifyDurableSequenceStore(seqStore).verified?'PASS':'FAIL');
log('SEQ_HEAD',getDurableSequence(seqStore,'sess-full')===3?'PASS':'FAIL');

const dw=createDurableWitness({directory:dir+'\\witness',witnessDomainId:'domain-full',identity:witness});
const r1=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T18:00:01.000Z'});
const r2=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:2,continuityHash:p2.continuity_hash,proofHash:'b'.repeat(64),issuedAt:'2026-09-16T18:00:02.000Z'});
const r3=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:3,continuityHash:p3.continuity_hash,proofHash:'c'.repeat(64),issuedAt:'2026-09-16T18:00:03.000Z'});
log('WITNESS_R1',r1.result==='ADVANCED'?'PASS':'FAIL');
log('WITNESS_R2',r2.result==='ADVANCED'?'PASS':'FAIL');
log('WITNESS_R3',r3.result==='ADVANCED'?'PASS':'FAIL');
const receipts=[r1.receipt,r2.receipt,r3.receipt];

const trustedChain=verifyTrustedProofChainV1_1(chain,{trustStore:signerStore,expectedContinuityRoot:root.continuity_root});
log('TRUSTED_CHAIN',trustedChain.verified?'PASS':'FAIL');
log('TRUSTED_CHAIN_REASON',trustedChain.reason);

const pkgOpts={
  continuityRoot:root.continuity_root,
  proofChain:chain,
  witnessReceipts:receipts,
  signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
  policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
  packagerIdentity:packager,
  createdAt:'2026-09-16T18:01:00.000Z'
};
const pkg=buildPortablePackage(pkgOpts);
const verifyOpts={signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore,expectedContinuityRoot:root.continuity_root};
const vp=verifyPortablePackage(pkg,verifyOpts);
log('PACKAGE_VALID',vp.verified?'PASS':'FAIL');
log('PACKAGE_REASON',vp.reason);
log('PACKAGE_CHAIN_LEN',vp.chain_length===3?'PASS':'FAIL');
log('PACKAGE_RECEIPTS_LEN',vp.receipts===3?'PASS':'FAIL');

const t2={...p2,decision_hash:'9'.repeat(64)};
const tamperedPkg=buildPortablePackage({...pkgOpts,proofChain:[p1,t2,p3]});
const tp=verifyPortablePackage(tamperedPkg,verifyOpts);
log('TAMPER_PROOF_REJECTED',!tp.verified?'PASS':'FAIL');
log('TAMPER_PROOF_REASON',tp.reason);
log('TAMPER_PROOF_LAYER_CORRECT',tp.reason==='PACKAGE_CHAIN_SIGNATURE_INVALID'?'PASS':'FAIL');

const badReceipt={...receipts[1],body:{...receipts[1].body,continuity_hash:'9'.repeat(64)}};
const badReceiptPkg=buildPortablePackage({...pkgOpts,witnessReceipts:[receipts[0],badReceipt,receipts[2]]});
const br=verifyPortablePackage(badReceiptPkg,verifyOpts);
log('TAMPER_RECEIPT_REJECTED',!br.verified?'PASS':'FAIL');
log('TAMPER_RECEIPT_REASON',br.reason);
log('TAMPER_RECEIPT_LAYER_CORRECT',br.reason==='PACKAGE_WITNESS_RECEIPT_INVALID'?'PASS':'FAIL');

const fakePkg=buildPortablePackage({...pkgOpts,packagerIdentity:fakePackager});
const fp=verifyPortablePackage(fakePkg,verifyOpts);
log('FAKE_PACKAGER_REJECTED',!fp.verified?'PASS':'FAIL');
log('FAKE_PACKAGER_REASON',fp.reason);
log('FAKE_PACKAGER_LAYER_CORRECT',fp.reason==='PACKAGE_PACKAGER_NOT_TRUSTED'?'PASS':'FAIL');

const attackerP1=signProof(attacker,c1);
const undeclaredPkg=buildPortablePackage({...pkgOpts,proofChain:[attackerP1,p2,p3]});
const up=verifyPortablePackage(undeclaredPkg,verifyOpts);
log('UNDECLARED_SIGNER_REJECTED',!up.verified?'PASS':'FAIL');
log('UNDECLARED_SIGNER_REASON',up.reason);
log('UNDECLARED_SIGNER_LAYER_CORRECT',up.reason==='PACKAGE_CHAIN_SIGNATURE_INVALID'||up.reason==='PACKAGE_PROOF_SIGNER_NOT_DECLARED'?'PASS':'FAIL');

const witness2=createDurableWitness({directory:dir+'\\witness',witnessDomainId:'domain-full',identity:witness});
const postRestart=witnessObserve(witness2,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T18:00:01.000Z'});
log('WITNESS_RESTART_IDEMPOTENT',postRestart.result==='IDEMPOTENT_REPLAY'?'PASS':'FAIL');

const seqStore2=createDurableSequenceStore(dir+'\\seq');
log('SEQ_RESTART_VERIFY',verifyDurableSequenceStore(seqStore2).verified?'PASS':'FAIL');
log('SEQ_RESTART_HEAD',getDurableSequence(seqStore2,'sess-full')===3?'PASS':'FAIL');
sr=verifyAndAdvanceDurableSequence(seqStore2,'sess-full',4);
log('SEQ_POST_RESTART_4',sr.decision==='CONTINUOUS'?'PASS':'FAIL');

fs.rmSync(dir,{recursive:true,force:true});
log('CLEANUP','PASS');
log('FULL_INTEGRATION_DONE',1);
