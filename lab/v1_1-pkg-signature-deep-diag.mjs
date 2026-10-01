import fs from "fs";
import crypto from "crypto";
import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve } from '../src/evidence/witness-v1_1.js';
import { buildPortablePackage } from '../src/evidence/portable-package-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';
import { jcsCanonicalize } from '../src/core/canonical-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_diag_deep";
fs.rmSync(rootDir,{recursive:true,force:true});

const signer=createSigningIdentity({keyId:'signer-d'});
const witness=createWitnessIdentity({keyId:'witness-d'});
const packager=createSigningIdentity({keyId:'packager-d'});

const root=createContinuityRoot({
  session_id:'sess-deep',subject:'user-deep',issuer:'issuer-deep',
  auth_time:'2026-09-16T16:00:00.000Z',client_context:{device_id:'dev-deep'}
});

function core(seq,par){
  return createProofCore({
    continuity_root:root.continuity_root,sequence:seq,parent_hash:par,
    state_hash:'1'.repeat(64),decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T16:00:0'+seq+'.000Z',
    signer_key_id:signer.keyId,policy_fingerprint_sha256:'3'.repeat(64)
  });
}
const c1=addContinuityHash(core(1,null));
const c2=addContinuityHash(core(2,c1.continuity_hash));
const c3=addContinuityHash(core(3,c2.continuity_hash));
const p1=signProof(signer,c1);
const p2=signProof(signer,c2);
const p3=signProof(signer,c3);
const t2={...p2,decision_hash:'9'.repeat(64)};

const dw=createDurableWitness({directory:rootDir,witnessDomainId:'dom-deep',identity:witness});
const r1=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T16:00:01.000Z'});
const r2=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:2,continuityHash:p2.continuity_hash,proofHash:'b'.repeat(64),issuedAt:'2026-09-16T16:00:02.000Z'});
const r3=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:3,continuityHash:p3.continuity_hash,proofHash:'c'.repeat(64),issuedAt:'2026-09-16T16:00:03.000Z'});
const receipts=[r1.receipt,r2.receipt,r3.receipt];

const SIG_FIELDS=["package_signature_base64","packager_public_key_spki_base64","packager_public_key_fingerprint_sha256"];

function buildDirect(chain){
  const body={
    schema_id:"session-continuity.v1_1.portable.package",
    version:1,
    created_at:'2026-09-16T16:01:00.000Z',
    continuity_root:root.continuity_root,
    proof_chain:chain,
    witness_receipts:receipts,
    signer_trust_fingerprints:[signer.publicKeyFingerprintSha256],
    witness_trust_fingerprints:[witness.publicKeyFingerprintSha256],
    policy_references:{policy_fingerprint_sha256:'3'.repeat(64)}
  };
  return body;
}

const bodyGood=buildDirect([p1,p2,p3]);
const bodyBad=buildDirect([p1,t2,p3]);

const payloadGood=jcsCanonicalize(bodyGood);
const payloadBad=jcsCanonicalize(bodyBad);

log('PAYLOAD_GOOD_LEN',payloadGood.length);
log('PAYLOAD_BAD_LEN',payloadBad.length);
log('PAYLOAD_EQ',payloadGood===payloadBad?'SAME':'DIFFERENT');

const pkgGood=buildPortablePackage({
  continuityRoot:root.continuity_root,
  proofChain:[p1,p2,p3],
  witnessReceipts:receipts,
  signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
  policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
  packagerIdentity:packager,
  createdAt:'2026-09-16T16:01:00.000Z'
});

const pkgBad=buildPortablePackage({
  continuityRoot:root.continuity_root,
  proofChain:[p1,t2,p3],
  witnessReceipts:receipts,
  signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
  policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
  packagerIdentity:packager,
  createdAt:'2026-09-16T16:01:00.000Z'
});

function packageSignedPayload(pkg){
  const b={};
  const ks=Object.keys(pkg).sort();
  for(const k of ks){ if(SIG_FIELDS.indexOf(k)===-1) b[k]=pkg[k]; }
  return jcsCanonicalize(b);
}

const recomputeGood=packageSignedPayload(pkgGood);
const recomputeBad=packageSignedPayload(pkgBad);

log('RECOMPUTE_GOOD_LEN',recomputeGood.length);
log('RECOMPUTE_BAD_LEN',recomputeBad.length);
log('RECOMPUTE_GOOD_EQ_BUILD',recomputeGood===payloadGood?'SAME':'DIFFERENT');
log('RECOMPUTE_BAD_EQ_BUILD',recomputeBad===payloadBad?'SAME':'DIFFERENT');

if(recomputeBad!==payloadBad){
  let i=0;
  const minLen=Math.min(recomputeBad.length,payloadBad.length);
  while(i<minLen && recomputeBad[i]===payloadBad[i]) i++;
  log('FIRST_DIFF_INDEX',i);
  log('BUILD_CTX',JSON.stringify(payloadBad.substring(Math.max(0,i-30),i+30)));
  log('VERIFY_CTX',JSON.stringify(recomputeBad.substring(Math.max(0,i-30),i+30)));
}

const der=Buffer.from(pkgBad.packager_public_key_spki_base64,"base64");
const publicKey=crypto.createPublicKey({key:der,type:"spki",format:"der"});
const payloadBuf=Buffer.from(recomputeBad,"utf8");
const sigBuf=Buffer.from(pkgBad.package_signature_base64,"base64");
let verifyResult=false;
try{ verifyResult=crypto.verify(null,payloadBuf,publicKey,sigBuf); }catch(e){ log('VERIFY_THROW',e.message); }
log('BAD_VERIFY_RAW',verifyResult?'TRUE':'FALSE');

const payloadBufBuild=Buffer.from(payloadBad,"utf8");
let verifyResultBuild=false;
try{ verifyResultBuild=crypto.verify(null,payloadBufBuild,publicKey,sigBuf); }catch(e){ log('VERIFY_BUILD_THROW',e.message); }
log('BAD_VERIFY_BUILD_PAYLOAD',verifyResultBuild?'TRUE':'FALSE');

log('GOOD_SIG_LEN',pkgGood.package_signature_base64.length);
log('BAD_SIG_LEN',pkgBad.package_signature_base64.length);
log('GOOD_KEY_EQ_BAD',pkgGood.packager_public_key_spki_base64===pkgBad.packager_public_key_spki_base64?'SAME':'DIFFERENT');

fs.rmSync(rootDir,{recursive:true,force:true});
log('DEEP_DIAG_DONE',1);
