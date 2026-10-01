import fs from "fs";
import crypto from "crypto";
import { createSigningIdentity, signProof } from '../src/evidence/proof-signature-v1_1.js';
import { createTrustAnchorStore, registerTrustAnchor } from '../src/evidence/trust-anchor.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve } from '../src/evidence/witness-v1_1.js';
import { buildPortablePackage, verifyPortablePackage } from '../src/evidence/portable-package-v1_1.js';
import { createContinuityRoot, createProofCore, addContinuityHash } from '../src/core/continuity-proof-v1_1.js';
import { jcsCanonicalize } from '../src/core/canonical-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_diag_targeted";
fs.rmSync(rootDir,{recursive:true,force:true});

const signer=createSigningIdentity({keyId:'sg-t'});
const witness=createWitnessIdentity({keyId:'wt-t'});
const packager=createSigningIdentity({keyId:'pg-t'});

const signerStore=createTrustAnchorStore();
registerTrustAnchor(signerStore,signer.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T17:00:00Z'});
const witnessStore=createTrustAnchorStore();
registerTrustAnchor(witnessStore,witness.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T17:00:00Z'});
const packagerStore=createTrustAnchorStore();
registerTrustAnchor(packagerStore,packager.publicKeySpkiBase64,{version:1,created_at:'2026-09-16T17:00:00Z'});

const root=createContinuityRoot({
  session_id:'s-t',subject:'u-t',issuer:'i-t',
  auth_time:'2026-09-16T17:00:00.000Z',client_context:{d:'d1'}
});

function core(seq,par){
  return createProofCore({
    continuity_root:root.continuity_root,sequence:seq,parent_hash:par,
    state_hash:'1'.repeat(64),decision_hash:'2'.repeat(64),
    issued_at:'2026-09-16T17:00:0'+seq+'.000Z',
    signer_key_id:signer.keyId,policy_fingerprint_sha256:'3'.repeat(64)
  });
}
const c1=addContinuityHash(core(1,null));
const c2=addContinuityHash(core(2,c1.continuity_hash));
const c3=addContinuityHash(core(3,c2.continuity_hash));
const p1=signProof(signer,c1);
const p2=signProof(signer,c2);
const p3=signProof(signer,c3);

const dw=createDurableWitness({directory:rootDir,witnessDomainId:'dom-t',identity:witness});
const r1=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:1,continuityHash:p1.continuity_hash,proofHash:'a'.repeat(64),issuedAt:'2026-09-16T17:00:01.000Z'});
const r2=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:2,continuityHash:p2.continuity_hash,proofHash:'b'.repeat(64),issuedAt:'2026-09-16T17:00:02.000Z'});
const r3=witnessObserve(dw,{continuityRoot:root.continuity_root,sequence:3,continuityHash:p3.continuity_hash,proofHash:'c'.repeat(64),issuedAt:'2026-09-16T17:00:03.000Z'});
const receipts=[r1.receipt,r2.receipt,r3.receipt];

const t2={...p2,decision_hash:'9'.repeat(64)};

const tamperedPkg=buildPortablePackage({
  continuityRoot:root.continuity_root,
  proofChain:[p1,t2,p3],
  witnessReceipts:receipts,
  signerTrustFingerprints:[signer.publicKeyFingerprintSha256],
  witnessTrustFingerprints:[witness.publicKeyFingerprintSha256],
  policyReferences:{policy_fingerprint_sha256:'3'.repeat(64)},
  packagerIdentity:packager,
  createdAt:'2026-09-16T17:01:00.000Z'
});

log('PKG_SIG_LEN',tamperedPkg.package_signature_base64.length);
log('PKG_CHAIN1_DECISION',tamperedPkg.proof_chain[1].decision_hash);

const SIG_FIELDS=["package_signature_base64","packager_public_key_spki_base64","packager_public_key_fingerprint_sha256"];
function rebuildBody(p){
  const b={};
  const ks=Object.keys(p).sort();
  for(const k of ks){ if(SIG_FIELDS.indexOf(k)===-1) b[k]=p[k]; }
  return b;
}
const rebuildPayload=jcsCanonicalize(rebuildBody(tamperedPkg));
log('REBUILD_PAYLOAD_LEN',rebuildPayload.length);

const der=Buffer.from(tamperedPkg.packager_public_key_spki_base64,"base64");
const pub=crypto.createPublicKey({key:der,type:"spki",format:"der"});
const sigBuf=Buffer.from(tamperedPkg.package_signature_base64,"base64");
const payloadBuf=Buffer.from(rebuildPayload,"utf8");
let rawVerify=false;
try{ rawVerify=crypto.verify(null,payloadBuf,pub,sigBuf); }catch(e){ log('RAW_THROW',e.message); }
log('RAW_VERIFY',rawVerify?'TRUE':'FALSE');

const vp=verifyPortablePackage(tamperedPkg,{signerTrustStore:signerStore,witnessTrustStore:witnessStore,packagerTrustStore:packagerStore});
log('VP_VERIFIED',vp.verified?'TRUE':'FALSE');
log('VP_REASON',vp.reason);
log('VP_FAILED_SEQ',vp.failedSequence);

fs.rmSync(rootDir,{recursive:true,force:true});
log('TARGETED_DIAG_DONE',1);
