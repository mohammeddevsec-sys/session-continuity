import fs from "fs";
import { createWitnessIdentity, createDurableWitness, witnessObserve, witnessGetHead, verifyWitnessReceipt, detectWitnessEquivocation } from '../src/evidence/witness-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_witness_v2";
fs.rmSync(rootDir,{recursive:true,force:true});

const rootA='a'.repeat(64);
const hash1A='1'.repeat(64);
const hash2A='2'.repeat(64);
const hash3A='3'.repeat(64);
const hash1B='4'.repeat(64);
const proofHash='f'.repeat(64);
const ts='2026-09-16T12:00:00.000Z';

const witnessId=createWitnessIdentity({keyId:'witness-v2'});
const witness=createDurableWitness({directory:rootDir,witnessDomainId:'domain-v2',identity:witnessId});

let r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1A,proofHash,issuedAt:ts});
log('SEQ1_ADVANCED',r.result==='ADVANCED'?'PASS':'FAIL');
const receipt1=r.receipt;

witnessObserve(witness,{continuityRoot:rootA,sequence:2,continuityHash:hash2A,proofHash,issuedAt:ts});
witnessObserve(witness,{continuityRoot:rootA,sequence:3,continuityHash:hash3A,proofHash,issuedAt:ts});
log('HEAD_AFTER_3',witnessGetHead(witness,rootA).head_sequence===3?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1A,proofHash,issuedAt:ts});
log('SEQ1_REPLAY',r.result==='IDEMPOTENT_REPLAY'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:2,continuityHash:hash2A,proofHash,issuedAt:ts});
log('SEQ2_REPLAY_AFTER_HEAD3',r.result==='IDEMPOTENT_REPLAY'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1B,proofHash,issuedAt:ts});
log('SEQ1_EQUIVOCATION',r.result==='EQUIVOCATION_FORK'?'PASS':'FAIL');
log('SEQ1_EQUIVOCATION_HAS_RECEIPT',r.receipt?'PASS':'FAIL');
const forkReceipt=r.receipt;

log('HEAD_UNCHANGED_AFTER_FORK',witnessGetHead(witness,rootA).head_sequence===3?'PASS':'FAIL');

if(forkReceipt){
  const vf=verifyWitnessReceipt(forkReceipt);
  log('FORK_RECEIPT_VERIFY',vf.verified?'PASS':'FAIL');
  log('FORK_RECEIPT_REASON',vf.reason);
  log('FORK_RECEIPT_SEQ',forkReceipt.body.sequence===1?'PASS':'FAIL');
  log('FORK_RECEIPT_HASH',forkReceipt.body.continuity_hash===hash1B?'PASS':'FAIL');
  log('FORK_RECEIPT_HEAD_SEQ',forkReceipt.body.witness_head_sequence===3?'PASS':'FAIL');
  const same=detectWitnessEquivocation(receipt1,forkReceipt);
  log('SAME_DOMAIN_EQUIVOCATION',same.equivocation?'PASS':'FAIL');
  log('SAME_DOMAIN_REASON',same.reason);
} else {
  log('FORK_RECEIPT_VERIFY','FAIL');
  log('SAME_DOMAIN_EQUIVOCATION','FAIL');
}

fs.rmSync(rootDir,{recursive:true,force:true});
log('CLEANUP','PASS');
log('WITNESS_PROBE_V2_DONE',1);
