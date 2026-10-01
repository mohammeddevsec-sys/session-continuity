import fs from "fs";
import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor } from '../src/evidence/trust-anchor.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve } from '../src/evidence/witness-v1_1.js';
import { buildPortablePackage, verifyPortablePackage } from '../src/evidence/portable-package-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';
import { createSigningIdentity as createPackagerIdentity } from '../src/evidence/proof-signature-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_portable_pkg";
fs.rmSync(rootDir,{recursive:true,force:true});

const signer=createSigningIdentity({keyId:'signer-pkg'});
const witness=createWitnessIdentity({keyId:'witness-pkg'});
const packager=createPackagerIdentity({keyId:'packager-pkg'});
const untrustedPackager=createPackagerIdentity({keyId:'untrusted-packager'});
const attackerSigner=createSigningIdentity({keyId:'attacker-signer'});

const signerStore=createTrustAnchorStore();
registerTrustAnchor(signerStore,signer.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T14:00:00Z'});
const witnessStore=createTrustAnchorStore();
registerTrustAnchor(witnessStore,witness.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T14:00:00Z'});
const packagerStore=createTrustAnchorStore();
registerTrustAnchor(packagerStore,packager.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T14:00:00Z'});

const root=createContinuityRoot({
  session_id:'sess-pkg',
  subject:'user-pkg',
  issuer:'issuer-pkg',
  auth_time:'2026-09-16T14:00:00.000Z',
  client_context:{device_id:'dev-pkg'}
});

function buildCore(seq,parent){
  return createProofCore({
    continuity_root:root.continuity_root,
    sequence:seq,
    parent_hash:parent,
    state_hash:'1'.repeat(64),
    decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T14:00:0'+seq+'.000Z',
    signer_key_id:signer.keyId,
    policy_fingerprint_sha256:'3'.repeat(64)
  });
}

const c1=addContinuityHash(buildCore(1,null));
const c2=addContinuityHash(buildCore(2,c1.continuity_hash));
const c3=addContinuityHash(buildCore(3,c2.continuity_hash));

const p1=signProof(signer,c1);
const p2=signProof(signer,c2);
const p3=signProof(signer,c3);

const durableWitness=createDurableWitness({directory:rootDir,witnessDomainId:'domain-pkg',identity:witness});
const r1=witnessObserve(durableWitness,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T14:00:01.000Z'});
const r2=witnessObserve(durableWitness,{continuityRoot:root.continuity_root,sequence:2,continuityHash:p2.continuity_hash,proofHash:'b'.repeat(64),issuedAt:'2026-09-16T14:00:02.000Z'});
const r3=witnessObserve(durableWitness,{continuityRoot:root.continuity_root,sequence:3,continuityHash:p3.continuity_hash,proofHash:'c'.repeat(64),issuedAt:'2026-09-16T14:00:03.000Z'});

log('WITNESS_R1',r1.result==='ADVANCED'?'PASS':'FAIL');
log('WITNESS_R2',r2.result==='ADVANCED'?'PASS':'FAIL');
log('WITNESS_R3',r3.result==='ADVANCED'?'PASS':'FAIL');

const receipts=[r1.receipt,r2.receipt,r3.receipt];

const pkg=buildPortablePackage({
  continuityRoot:root.continuity_root,
  proofChain:[p1,p2,p3],
  witnessReceipts:receipts,
  signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
  policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
  packagerIdentity:packager,
  createdAt:'2026-09-16T14:01:00.000Z'
});

log('PKG_BUILT',pkg?'PASS':'FAIL');
log('PKG_PROOF_CHAIN_LEN',pkg.proof_chain.length===3?'PASS':'FAIL');
log('PKG_RECEIPTS_LEN',pkg.witness_receipts.length===3?'PASS':'FAIL');

const valid=verifyPortablePackage(pkg,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore,expectedContinuityRoot:root.continuity_root});
log('VALID_PACKAGE',valid.verified?'PASS':'FAIL');
log('VALID_PACKAGE_REASON',valid.reason);

const tamperedProof={...pkg,proof_chain:[p1,{...p2,decision_hash:'9'.repeat(64)},p3]};
const tamperedProofResult=verifyPortablePackage(tamperedProof,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('TAMPERED_PROOF_REJECTED',!tamperedProofResult.verified?'PASS':'FAIL');
log('TAMPERED_PROOF_REASON',tamperedProofResult.reason);

const tamperedReceipt={...pkg,witness_receipts:[receipts[0],{...receipts[1],body:{...receipts[1].body,continuity_hash:'9'.repeat(64)}},receipts[2]]};
const tamperedReceiptResult=verifyPortablePackage(tamperedReceipt,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('TAMPERED_RECEIPT_REJECTED',!tamperedReceiptResult.verified?'PASS':'FAIL');
log('TAMPERED_RECEIPT_REASON',tamperedReceiptResult.reason);

const wrongPackagerPkg={...pkg};
const wrongSig=buildPortablePackage({
  continuityRoot:root.continuity_root,
  proofChain:[p1,p2,p3],
  witnessReceipts:receipts,
  signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
  policyReferences:{},
  packagerIdentity:untrustedPackager,
  createdAt:'2026-09-16T14:01:00.000Z'
});
const untrustedPackagerResult=verifyPortablePackage(wrongSig,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('UNTRUSTED_PACKAGER_REJECTED',!untrustedPackagerResult.verified?'PASS':'FAIL');
log('UNTRUSTED_PACKAGER_REASON',untrustedPackagerResult.reason);

const attackerP1=signProof(attackerSigner,c1);
const attackerPkg={...pkg,proof_chain:[attackerP1,p2,p3]};
const attackerPkgResult=verifyPortablePackage(attackerPkg,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('UNDECLARED_SIGNER_REJECTED',!attackerPkgResult.verified?'PASS':'FAIL');
log('UNDECLARED_SIGNER_REASON',attackerPkgResult.reason);

const badBinding={...pkg,witness_receipts:[receipts[0],{...receipts[1],body:{...receipts[1].body,continuity_hash:p1.continuity_hash}},receipts[2]]};
const badBindingResult=verifyPortablePackage(badBinding,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('RECEIPT_BINDING_MISMATCH_REJECTED',!badBindingResult.verified?'PASS':'FAIL');
log('RECEIPT_BINDING_MISMATCH_REASON',badBindingResult.reason);

const wrongRoot={...pkg,continuity_root:'0'.repeat(64)};
const wrongRootResult=verifyPortablePackage(wrongRoot,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('WRONG_ROOT_REJECTED',!wrongRootResult.verified?'PASS':'FAIL');
log('WRONG_ROOT_REASON',wrongRootResult.reason);

const noReceipts={...pkg,witness_receipts:[]};
const noReceiptsResult=verifyPortablePackage(noReceipts,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('NO_RECEIPTS_ACCEPTED',noReceiptsResult.verified?'PASS':'FAIL');
log('NO_RECEIPTS_REASON',noReceiptsResult.reason);

const noPackagerStore=verifyPortablePackage(pkg,{signerTrustStore:signerStore,witnessTrustStore:witnessStore});
log('PACKAGE_WITHOUT_PACKAGER_TRUST',noPackagerStore.verified?'PASS':'FAIL');
log('PACKAGE_WITHOUT_PACKAGER_REASON',noPackagerStore.reason);

fs.rmSync(rootDir,{recursive:true,force:true});
log('CLEANUP','PASS');
log('PORTABLE_PACKAGE_PROBE_DONE',1);
