import fs from "fs";
import path from "path";
import { createWitnessIdentity, createDurableWitness, witnessObserve, witnessHealth } from '../src/evidence/witness-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const rootDir="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_witness_failclosed";
fs.rmSync(rootDir,{recursive:true,force:true});

const rootA='a'.repeat(64);
const hash1='1'.repeat(64);
const hash2='2'.repeat(64);
const proofHash='f'.repeat(64);
const ts='2026-09-16T13:00:00.000Z';

const witnessId=createWitnessIdentity({keyId:'witness-fc'});
const witness=createDurableWitness({directory:rootDir,witnessDomainId:'domain-fc',identity:witnessId});

let r=witnessObserve(witness,{continuityRoot:rootA,sequence:1,continuityHash:hash1,proofHash,issuedAt:ts});
log('SEQ1',r.result==='ADVANCED'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:2,continuityHash:hash2,proofHash,issuedAt:ts});
log('SEQ2',r.result==='ADVANCED'?'PASS':'FAIL');

const healthBefore=witnessHealth(witness);
log('HEALTH_BEFORE_STATUS',healthBefore.status);
log('HEALTH_BEFORE_OK',healthBefore.status==='OK'?'PASS':'FAIL');

const statePath=path.join(rootDir,'WITNESS_STATE.json');
if(!fs.existsSync(statePath)){ log('STATE_FILE_MISSING','FAIL'); }
const validState=fs.readFileSync(statePath,'utf8');

fs.writeFileSync(statePath,'{"broken',"utf8");
const healthCorrupt=witnessHealth(witness);
log('HEALTH_CORRUPT_STATUS',healthCorrupt.status);
log('HEALTH_CORRUPT_FAIL_CLOSED',healthCorrupt.status==='FAIL_CLOSED'?'PASS':'FAIL');
log('HEALTH_CORRUPT_REASON_HAS_TAG',String(healthCorrupt.reason).includes('FAIL_CLOSED')?'PASS':'FAIL');

let observeRejected=false;
try {
  witnessObserve(witness,{continuityRoot:rootA,sequence:3,continuityHash:'3'.repeat(64),proofHash,issuedAt:ts});
} catch(e){
  observeRejected=true;
  log('OBSERVE_ERROR_MESSAGE',e.message);
}
log('OBSERVE_REJECTED_WHEN_CORRUPT',observeRejected?'PASS':'FAIL');

fs.writeFileSync(statePath,'{"schema_id":"wrong","version":1,"witness_domain_id":"domain-fc","roots":{}}',"utf8");
const healthWrongSchema=witnessHealth(witness);
log('HEALTH_WRONG_SCHEMA_STATUS',healthWrongSchema.status);
log('HEALTH_WRONG_SCHEMA_FAIL_CLOSED',healthWrongSchema.status==='FAIL_CLOSED'?'PASS':'FAIL');

fs.writeFileSync(statePath,validState,'utf8');
const healthRestored=witnessHealth(witness);
log('HEALTH_RESTORED_STATUS',healthRestored.status);
log('HEALTH_RESTORED_OK',healthRestored.status==='OK'?'PASS':'FAIL');

r=witnessObserve(witness,{continuityRoot:rootA,sequence:3,continuityHash:'3'.repeat(64),proofHash,issuedAt:ts});
log('RESUMED_AFTER_RESTORE',r.result==='ADVANCED'?'PASS':'FAIL');

fs.rmSync(rootDir,{recursive:true,force:true});
log('CLEANUP','PASS');
log('WITNESS_FAIL_CLOSED_PROBE_DONE',1);
