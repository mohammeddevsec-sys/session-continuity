import fs from "fs";
import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor } from '../src/evidence/trust-anchor.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve } from '../src/evidence/witness-v1_1.js';
import { buildPortablePackage, verifyPortablePackage } from '../src/evidence/portable-package-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_portable_pkg_v2";
fs.rmSync(rootDir,{recursive:true,force:true});

const signer=createSigningIdentity({keyId:'signer-pkg'});
const witness=createWitnessIdentity({keyId:'witness-pkg'});
const packager=createSigningIdentity({keyId:'packager-pkg'});
const attackerSigner=createSigningIdentity({keyId:'attacker-signer'});
const fakePackager=createSigningIdentity({keyId:'fake-packager'});

const signerStore=createTrustAnchorStore();
registerTrustAnchor(signerStore,signer.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T14:00:00Z'});
const witnessStore=createTrustAnchorStore();
registerTrustAnchor(witnessStore,witness.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T14:00:00Z'});
const packagerStore=createTrustAnchorStore();
registerTrustAnchor(packagerStore,packager.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T14:00:00Z'});

const root=createContinuityRoot({
  session_id:'sess-pkg2',subject:'user-pkg2',issuer:'issuer-pkg2',
  auth_time:'2026-09-16T14:00:00.000Z',client_context:{device_id:'dev-pkg2'}
});

function buildCore(seq,parent){
  return createProofCore({
    continuity_root:root.continuity_root,sequence:seq,parent_hash:parent,
    state_hash:'1'.repeat(64),decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T14:00:0'+seq+'.000Z',
    signer_key_id:signer.keyId,policy_fingerprint_sha256:'3'.repeat(64)
  });
}

const c1=addContinuityHash(buildCore(1,null));
const c2=addContinuityHash(buildCore(2,c1.continuity_hash));
const c3=addContinuityHash(buildCore(3,c2.continuity_hash));

const p1=signProof(signer,c1);
const p2=signProof(signer,c2);
const p3=signProof(signer,c3);

const dw=createDurableWitness({directory:rootDir,witnessDomainId:'domain-pkg',identity:witness});
const r1=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T14:00:01.000Z'});
const r2=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:2,continuityHash:p2.continuity_hash,proofHash:'b'.repeat(64),issuedAt:'2026-09-16T14:00:02.000Z'});
const r3=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:3,continuityHash:p3.continuity_hash,proofHash:'c'.repeat(64),issuedAt:'2026-09-16T14:00:03.000Z'});
const receipts=[r1.receipt,r2.receipt,r3.receipt];

function buildPkg(overrides){
  const opts={
    continuityRoot:root.continuity_root,
    proofChain:[p1,p2,p3],
    witnessReceipts:receipts,
    signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
    witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
    policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
    packagerIdentity:packager,
    createdAt:'2026-09-16T14:01:00.000Z'
  };
  return buildPortablePackage(Object.assign(opts,overrides||{}));
}

const baseOpts={signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore};

const goodPkg=buildPkg({});
log('GOOD_PKG',verifyPortablePackage(goodPkg,baseOpts).verified?'PASS':'FAIL');

// Tampered proof, RE-SIGNED by legitimate packager
const tamperedProofPkg=buildPkg({proofChain:[p1,{...p2,decision_hash:'9'.repeat(64)},p3]});
const tp=verifyPortablePackage(tamperedProofPkg,baseOpts);
log('TAMPERED_PROOF_DEEP_REJECTED',!tp.verified?'PASS':'FAIL');
log('TAMPERED_PROOF_DEEP_REASON',tp.reason);

// Signer not declared, but package is validly signed
const attackerP1=signProof(attackerSigner,c1);
const undeclaredPkg=buildPkg({proofChain:[attackerP1,p2,p3]});
const ud=verifyPortablePackage(undeclaredPkg,baseOpts);
log('UNDECLARED_SIGNER_DEEP_REJECTED',!ud.verified?'PASS':'FAIL');
log('UNDECLARED_SIGNER_DEEP_REASON',ud.reason);

// Tampered receipt, re-signed package
const tamperedReceiptPkg=buildPkg({witnessReceipts:[receipts[0],{...receipts[1],body:{...receipts[1].body,continuity_hash:'9'.repeat(64)}},receipts[2]]});
const tr=verifyPortablePackage(tamperedReceiptPkg,baseOpts);
log('TAMPERED_RECEIPT_DEEP_REJECTED',!tr.verified?'PASS':'FAIL');
log('TAMPERED_RECEIPT_DEEP_REASON',tr.reason);

// Receipt binding mismatch: receipt reports hash of p1 but sequence=2, package validly signed
const badBindPkg=buildPkg({witnessReceipts:[receipts[0],{...receipts[1],body:{...receipts[1].body,continuity_hash:p1.continuity_hash}},receipts[2]]});
const bb=verifyPortablePackage(badBindPkg,baseOpts);
log('RECEIPT_BINDING_DEEP_REJECTED',!bb.verified?'PASS':'FAIL');
log('RECEIPT_BINDING_DEEP_REASON',bb.reason);

// Package signed by fake packager
const fakePkg=buildPkg({packagerIdentity:fakePackager});
const fp=verifyPortablePackage(fakePkg,baseOpts);
log('FAKE_PACKAGER_REJECTED',!fp.verified?'PASS':'FAIL');
log('FAKE_PACKAGER_REASON',fp.reason);

// No receipts, validly signed - should be accepted
const noReceiptsPkg=buildPkg({witnessReceipts:[]});
const nr=verifyPortablePackage(noReceiptsPkg,baseOpts);
log('NO_RECEIPTS_ACCEPTED',nr.verified?'PASS':'FAIL');
log('NO_RECEIPTS_REASON',nr.reason);

// Wrong root, re-signed
const wrongRootPkg=buildPkg({continuityRoot:'0'.repeat(64)});
const wr=verifyPortablePackage(wrongRootPkg,baseOpts);
log('WRONG_ROOT_DEEP_REJECTED',!wr.verified?'PASS':'FAIL');
log('WRONG_ROOT_DEEP_REASON',wr.reason);

fs.rmSync(rootDir,{recursive:true,force:true});
log('CLEANUP','PASS');
log('PORTABLE_PACKAGE_PROBE_V2_DONE',1);
