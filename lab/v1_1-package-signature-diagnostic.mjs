import fs from "fs";
import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor } from '../src/evidence/trust-anchor.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve } from '../src/evidence/witness-v1_1.js';
import { buildPortablePackage } from '../src/evidence/portable-package-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';
import { jcsCanonicalize } from '../src/core/canonical-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_diag_pkg_sig";
fs.rmSync(rootDir,{recursive:true,force:true});

const signer=createSigningIdentity({keyId:'sig-d'});
const witness=createWitnessIdentity({keyId:'wit-d'});
const packager=createSigningIdentity({keyId:'pkg-d'});

const root=createContinuityRoot({
  session_id:'s-sig-d',subject:'u-sig-d',issuer:'i-sig-d',
  auth_time:'2026-09-16T15:00:00.000Z',client_context:{d:'d1'}
});

function core(seq,par){
  return createProofCore({
    continuity_root:root.continuity_root,sequence:seq,parent_hash:par,
    state_hash:'1'.repeat(64),decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T15:00:0'+seq+'.000Z',
    signer_key_id:signer.keyId,policy_fingerprint_sha256:'3'.repeat(64)
  });
}
const c1=addContinuityHash(core(1,null));
const c2=addContinuityHash(core(2,c1.continuity_hash));
const c3=addContinuityHash(core(3,c2.continuity_hash));
const p1=signProof(signer,c1);
const p2=signProof(signer,c2);
const p3=signProof(signer,c3);

const dw=createDurableWitness({directory:rootDir,witnessDomainId:'dom-d',identity:witness});
const r1=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T15:00:01.000Z'});
const r2=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:2,continuityHash:p2.continuity_hash,proofHash:'b'.repeat(64),issuedAt:'2026-09-16T15:00:02.000Z'});
const r3=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:3,continuityHash:p3.continuity_hash,proofHash:'c'.repeat(64),issuedAt:'2026-09-16T15:00:03.000Z'});
const receipts=[r1.receipt,r2.receipt,r3.receipt];

const t2={...p2,decision_hash:'9'.repeat(64)};

function build(chain){
  return buildPortablePackage({
    continuityRoot:root.continuity_root,
    proofChain:chain,
    witnessReceipts:receipts,
    signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
    witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
    policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
    packagerIdentity:packager,
    createdAt:'2026-09-16T15:01:00.000Z'
  });
}

const pkgGood=build([p1,p2,p3]);
const pkgBad=build([p1,t2,p3]);

const SIG_FIELDS=["package_signature_base64","packager_public_key_spki_base64","packager_public_key_fingerprint_sha256"];

function payloadFromPkg(pkg){
  const body={};
  const keys=Object.keys(pkg).sort();
  for(const k of keys){ if(SIG_FIELDS.indexOf(k)===-1) body[k]=pkg[k]; }
  return jcsCanonicalize(body);
}

log('GOOD_BODY_LEN',payloadFromPkg(pkgGood).length);
log('BAD_BODY_LEN',payloadFromPkg(pkgBad).length);

log('GOOD_CHAIN0_HASH',jcsCanonicalize(pkgGood.proof_chain[0]).length);
log('BAD_CHAIN0_HASH',jcsCanonicalize(pkgBad.proof_chain[0]).length);

log('GOOD_CHAIN1_DECISION',pkgGood.proof_chain[1].decision_hash);
log('BAD_CHAIN1_DECISION',pkgBad.proof_chain[1].decision_hash);

log('GOOD_CHAIN1_SIG_LEN',pkgGood.proof_chain[1].signature_base64.length);
log('BAD_CHAIN1_SIG_LEN',pkgBad.proof_chain[1].signature_base64.length);

log('GOOD_CHAIN1_SIG_EQ',pkgGood.proof_chain[1].signature_base64===pkgBad.proof_chain[1].signature_base64?'SAME':'DIFFERENT');

const sigFieldsGood=Object.keys(pkgGood).filter(k=>SIG_FIELDS.indexOf(k)!==-1);
const sigFieldsBad=Object.keys(pkgBad).filter(k=>SIG_FIELDS.indexOf(k)!==-1);
log('SIG_FIELDS_GOOD_COUNT',sigFieldsGood.length);
log('SIG_FIELDS_BAD_COUNT',sigFieldsBad.length);

log('GOOD_SIG_LEN',pkgGood.package_signature_base64.length);
log('BAD_SIG_LEN',pkgBad.package_signature_base64.length);
log('SIGS_DIFFER',pkgGood.package_signature_base64!==pkgBad.package_signature_base64?'DIFFERENT':'SAME');

fs.rmSync(rootDir,{recursive:true,force:true});
log('DIAG_DONE',1);
