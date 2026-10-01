import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const dir=fs.mkdtempSync(path.join(os.tmpdir(),"witness-corruption-"));
const file=path.join(dir,"WITNESS.json");
const {privateKey,publicKey}=crypto.generateKeyPairSync("ed25519");
const root="AUTH-ROOT-CORRUPTION";
const canon=x=>JSON.stringify(x);
const hash=x=>crypto.createHash("sha256").update(canon(x)).digest("hex");
const sign=b=>crypto.sign(null,Buffer.from(canon(b)),privateKey).toString("base64");
const verify=p=>crypto.verify(null,Buffer.from(canon(p.body)),publicKey,Buffer.from(p.sig,"base64"));
const make=(sequence,parent,state)=>{const body={root,sequence,parent,state};return {body,sig:sign(body),record_hash:hash(body)};};
const write=rows=>fs.writeFileSync(file,JSON.stringify(rows,null,2),"utf8");
const read=()=>JSON.parse(fs.readFileSync(file,"utf8"));
const validate=rows=>{if(!Array.isArray(rows)||rows.length===0)throw new Error("WITNESS_STATE_INVALID"); let prev=""; for(const r of rows){if(!r||typeof r.body!=="object"||!verify(r))throw new Error("WITNESS_RECORD_INVALID"); if(r.body.parent!==prev && r.body.sequence!==1)throw new Error("WITNESS_PARENT_INVALID"); if(r.record_hash!==hash(r.body))throw new Error("WITNESS_HASH_INVALID"); prev=hash(r.body);} return true;};
const p1=make(1,"","S1");
const p2=make(2,hash(p1.body),"S2");
const p3=make(3,hash(p2.body),"S3");
write([p1,p2,p3]);
const original=read();
const originalHead=hash(original[2].body);
console.log("=== WITNESS CORRUPTION / ROLLBACK LAB ===");
console.log("BASELINE_HEAD="+originalHead);
const tampered=JSON.parse(JSON.stringify(original));
tampered[1].body.state="ATTACKED";
write(tampered);
let tamperDetected="NO"; try{validate(read());}catch(e){tamperDetected="YES:"+e.message;}
console.log("FIELD_TAMPER="+tamperDetected);
write(original.slice(0,2));
let rollbackDetected="NO"; try{const rows=read(); if(hash(rows[rows.length-1].body)!==originalHead)throw new Error("WITNESS_HEAD_ROLLBACK");}catch(e){rollbackDetected="YES:"+e.message;}
console.log("TRUNCATION_ROLLBACK="+rollbackDetected);
write(original);
const forged=JSON.parse(JSON.stringify(original));
forged[2].body.state="FORGED";
write(forged);
let forgedDetected="NO"; try{validate(read());}catch(e){forgedDetected="YES:"+e.message;}
console.log("FORGED_RECORD="+forgedDetected);
write(original);
let restartValid="NO"; try{validate(read()); restartValid="YES";}catch{}
console.log("ORIGINAL_RESTART_VALID="+restartValid);
console.log("FIELD_TAMPER_BLOCKED="+(tamperDetected.startsWith("YES")?"PASS":"FAIL"));
console.log("ROLLBACK_BLOCKED="+(rollbackDetected.startsWith("YES")?"PASS":"FAIL"));
console.log("FORGED_BLOCKED="+(forgedDetected.startsWith("YES")?"PASS":"FAIL"));
console.log("RESTART_VALID="+(restartValid==="YES"?"PASS":"FAIL"));
console.log("WITNESS_CORRUPTION_RESULT="+([tamperDetected.startsWith("YES"),rollbackDetected.startsWith("YES"),forgedDetected.startsWith("YES"),restartValid==="YES"].every(Boolean)?"PASS":"FAIL"));
fs.rmSync(dir,{recursive:true,force:true});
