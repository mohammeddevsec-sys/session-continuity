import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {pathToFileURL,fileURLToPath} from "node:url";
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const WITNESS=path.join(ROOT,"src","evidence","witness-v1_1.js");
const stages=["AFTER_WRITE","AFTER_FSYNC","AFTER_CLOSE","AFTER_RENAME"];
const root="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ch="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ph="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const input={continuityRoot:root,sequence:1,continuityHash:ch,proofHash:ph,issuedAt:"2026-09-18T08:00:00.000Z"};
const mode=process.env.SC_CRASH_STAGE||"";
if(mode){
  const {syncBuiltinESMExports}=await import("node:module");
  const original={openSync:fs.openSync,writeSync:fs.writeSync,fsyncSync:fs.fsyncSync,closeSync:fs.closeSync,renameSync:fs.renameSync};
  const tracked=new Map(); let stateWriteCount=0;
  const target=p=>String(p).includes("WITNESS_STATE.json.tmp-");
  fs.openSync=function(p,...a){const fd=original.openSync.call(fs,p,...a);tracked.set(fd,String(p)); if(target(p)) stateWriteCount++; return fd};
  fs.writeSync=function(fd,...a){const r=original.writeSync.call(fs,fd,...a);if(mode==="AFTER_WRITE"&&stateWriteCount===2&&target(tracked.get(fd)))process.exit(73);return r};
  fs.fsyncSync=function(fd){const r=original.fsyncSync.call(fs,fd);if(mode==="AFTER_FSYNC"&&stateWriteCount===2&&target(tracked.get(fd)))process.exit(73);return r};
  fs.closeSync=function(fd){const p=tracked.get(fd);const r=original.closeSync.call(fs,fd);if(mode==="AFTER_CLOSE"&&stateWriteCount===2&&target(p))process.exit(73);return r};
  fs.renameSync=function(a,b){const r=original.renameSync.call(fs,a,b);if(mode==="AFTER_RENAME"&&stateWriteCount===2&&String(b).endsWith("WITNESS_STATE.json"))process.exit(73);return r};
  syncBuiltinESMExports();
  const M=await import(pathToFileURL(WITNESS).href);
  const d=process.env.SC_WITNESS_DIR;
  const s=M.createDurableWitness({directory:d,witnessDomainId:"DOMAIN-1",identity:M.createWitnessIdentity({keyId:"W1"})});
  M.witnessObserve(s,input);
  process.exit(70);
}
let all=true;
for(const stage of stages){
  const d=fs.mkdtempSync(path.join(os.tmpdir(),"sc-crash-boundary-"));
  const env={...process.env,SC_CRASH_STAGE:stage,SC_WITNESS_DIR:d};
  const child=spawnSync(process.execPath,[process.argv[1]],{cwd:ROOT,env,encoding:"utf8"});
  const crashOk=child.status===73;
  const lockPath=path.join(d,"WITNESS.lock"); if(fs.existsSync(lockPath)) fs.rmSync(lockPath,{force:true});
  const {createDurableWitness,createWitnessIdentity,witnessObserve,witnessGetHead}=await import(pathToFileURL(WITNESS).href);
  const s=createDurableWitness({directory:d,witnessDomainId:"DOMAIN-1",identity:createWitnessIdentity({keyId:"W1"})});
  const r=witnessObserve(s,input);
  const h=witnessGetHead(s,root);
  const statePath=path.join(d,"WITNESS_STATE.json");
  const state=JSON.parse(fs.readFileSync(statePath,"utf8"));
  const saved=!!state.roots?.[root]?.history?.["1"]?.receipt;
  const expected=stage==="AFTER_RENAME"?"IDEMPOTENT_REPLAY":"ADVANCED";
  const ok=crashOk&&r.result===expected&&h.head_sequence===1&&h.head_hash===ch&&saved&&!!r.receipt;
  console.log(stage+"="+(ok?"PASS":"FAIL"));
  if(!ok){console.log("DETAIL|EXIT="+child.status+"|RESULT="+r.result+"|HEAD="+h.head_sequence+"|SAVED="+saved)}
  if(!ok)all=false;
  fs.rmSync(d,{recursive:true,force:true});
}
console.log("CRASH_BOUNDARY_PROBE_DONE="+(all?"1":"0"));
if(!all)process.exit(2);
