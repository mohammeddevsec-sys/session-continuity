import fs from "fs";
import { createSigningIdentity } from '../src/evidence/proof-signature-v1_1.js';
import { createWitnessIdentity, createDurableWitness, witnessObserve, witnessGetHead, verifyWitnessReceipt, detectWitnessEquivocation } from '../src/evidence/witness-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_witness";
fs.rmSync(rootDir,{recursive:true,force:true});

const rootA='a'.repeat(64);
const rootB='b'.repeat(64);
const hash1A='1'.repeat(64);
const hash2A='2'.repeat(64);
const hash3A='3'.repeat(64);
const hash1B='4'.repeat(64);
const hash2B='5'.repeat(64);
const proofHash='f'.repeat(64);
const ts='2026-09-16T11:00:00.000Z';

const signer=createSigningIdentity({keyId:'signer-1'});
const witnessId=createWitnessIdentity({keyId:'witness-key-1'});

const witness=createDurableWitness({directory:rootDir,witnessDomainId:'domain-1',identity:witnessId});

let r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1A,proofHash,issuedAt:ts});
log('SEQ1_ADVANCED',r.result==='ADVANCED'?'PASS':'FAIL');
log('SEQ1_HAS_RECEIPT',r.receipt?'PASS':'FAIL');
const receipt1=r.receipt;
log('SEQ1_HEAD',r.head_sequence===1?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:2,continuityHash:hash2A,proofHash,issuedAt:ts});
log('SEQ2_ADVANCED',r.result==='ADVANCED'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:3,continuityHash:hash3A,proofHash,issuedAt:ts});
log('SEQ3_ADVANCED',r.result==='ADVANCED'?'PASS':'FAIL');
log('HEAD_AFTER_3',witnessGetHead(witness,rootA).head_sequence===3?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1A,proofHash,issuedAt:ts});
log('SEQ1_REPLAY_IDEMPOTENT',r.result==='IDEMPOTENT_REPLAY'?'PASS':'FAIL');
log('SEQ1_REPLAY_RECEIPT',r.receipt?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1B,proofHash,issuedAt:ts});
log('SEQ1_EQUIVOCATION',r.result==='EQUIVOCATION_FORK'?'PASS':'FAIL');
log('SEQ1_EQUIVOCATION_HAS_RECEIPT',r.receipt?'PASS':'FAIL');
const forkReceipt=r.receipt;

r=witnessObserve(witness,{continuityRoot:rootA,sequence:5,continuityHash:'5'.repeat(64),proofHash,issuedAt:ts});
log('SEQ5_GAP',r.result==='SEQUENCE_GAP'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:2,continuityHash:hash2A,proofHash,issuedAt:ts});
log('SEQ2_ROLLBACK',r.result==='SEQUENCE_ROLLBACK'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootB,sequence:1,continuityHash:'c'.repeat(64),proofHash,issuedAt:ts});
log('ROOTB_SEQ1',r.result==='ADVANCED'?'PASS':'FAIL');
log('ROOTA_HEAD_UNCHANGED',witnessGetHead(witness,rootA).head_sequence===3?'PASS':'FAIL');
log('ROOTB_HEAD',witnessGetHead(witness,rootB).head_sequence===1?'PASS':'FAIL');

const v1=verifyWitnessReceipt(receipt1);
log('RECEIPT1_VERIFY',v1.verified?'PASS':'FAIL');
log('RECEIPT1_REASON',v1.reason);

const tampered={...receipt1,body:{...receipt1.body,continuity_hash:'9'.repeat(64)}};
const vt=verifyWitnessReceipt(tampered);
log('TAMPERED_RECEIPT_REJECTED',!vt.verified?'PASS':'FAIL');
log('TAMPERED_RECEIPT_REASON',vt.reason);

const witnessId2=createWitnessIdentity({keyId:'witness-key-2'});
const witness2=createDurableWitness({directory:rootDir+'-2',witnessDomainId:'domain-2',identity:witnessId2});
const r2=witnessObserve(witness2,{continuityRoot:rootA,sequence:1,continuityHash:hash1B,proofHash,issuedAt:ts});
log('DOMAIN2_SEQ1_ADVANCED',r2.result==='ADVANCED'?'PASS':'FAIL');
const receipt2=r2.receipt;

const crossDomain=detectWitnessEquivocation(receipt1,receipt2);
log('CROSS_DOMAIN_NOT_EQUIVOCATION',!crossDomain.equivocation?'PASS':'FAIL');
log('CROSS_DOMAIN_REASON',crossDomain.reason);

if(forkReceipt){
  const sameDomain=detectWitnessEquivocation(receipt1,forkReceipt);
  log('SAME_DOMAIN_EQUIVOCATION_DETECTED',sameDomain.equivocation?'PASS':'FAIL');
  log('SAME_DOMAIN_REASON',sameDomain.reason);
} else {
  log('SAME_DOMAIN_EQUIVOCATION_DETECTED','FAIL');
  log('SAME_DOMAIN_REASON','FORK_RECEIPT_MISSING');
}

const witness3=createDurableWitness({directory:rootDir,witnessDomainId:'domain-1',identity:witnessId});
log('RESTART_HEAD',witnessGetHead(witness3,rootA).head_sequence===3?'PASS':'FAIL');
r=witnessObserve(witness3,{continuityRoot:rootA,sequence:1,continuityHash:hash1B,proofHash,issuedAt:ts});
log('POST_RESTART_EQUIVOCATION',r.result==='EQUIVOCATION_FORK'?'PASS':'FAIL');

fs.rmSync(rootDir,{recursive:true,force:true});
fs.rmSync(rootDir+'-2',{recursive:true,force:true});
log('PROBE_CLEANUP','PASS');
log('WITNESS_PROBE_DONE',1);
