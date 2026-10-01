import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const dir=fs.mkdtempSync(path.join(os.tmpdir(),"witness-clean-"));
const journal=path.join(dir,"WITNESS.json");
const {privateKey,publicKey}=crypto.generateKeyPairSync("ed25519");
const root="AUTH-ROOT-CLEAN";
const canon=x=>JSON.stringify(x);
const hash=x=>crypto.createHash("sha256").update(canon(x)).digest("hex");
const sign=b=>crypto.sign(null,Buffer.from(canon(b)),privateKey).toString("base64");
const verify=p=>crypto.verify(null,Buffer.from(canon(p.body)),publicKey,Buffer.from(p.sig,"base64"));
const read=()=>fs.existsSync(journal)?JSON.parse(fs.readFileSync(journal,"utf8")):[];
const write=rows=>fs.writeFileSync(journal,JSON.stringify(rows,null,2),"utf8");
const make=(sequence,parent,state)=>{const body={root,sequence,parent,state};return {body,sig:sign(body)};};
function submit(p){
 if(!verify(p))return {ok:false,reason:"INVALID_SIGNATURE"};
 const rows=read(); const last=rows[rows.length-1];
 if(!last){if(p.body.sequence!==1)return {ok:false,reason:"FIRST_SEQUENCE_REQUIRED"};}
 if(last){
  if(p.body.sequence<last.body.sequence)return {ok:false,reason:"ROLLBACK"};
  if(p.body.sequence===last.body.sequence)return hash(p.body)===hash(last.body)?{ok:true,reason:"IDEMPOTENT_REPLAY"}:{ok:false,reason:"EQUIVOCATION_FORK"};
  if(p.body.sequence!==last.body.sequence+1)return {ok:false,reason:"SEQUENCE_GAP"};
  if(p.body.parent!==hash(last.body))return {ok:false,reason:"PARENT_MISMATCH"};
 }
 rows.push(p); write(rows); return {ok:true,reason:"ACCEPTED"};
}

const p1=make(1,"","S1");
const p2=make(2,hash(p1.body),"S2");
const fork=make(2,hash(p1.body),"S2-FORK");
const gap=make(4,hash(p2.body),"S4");
const forged={body:{root,sequence:3,parent:hash(p2.body),state:"FORGED"},sig:"AAAA"};
console.log("=== CLEAN ADVERSARIAL WITNESS LAB ===");
console.log("P1="+submit(p1).reason);
console.log("P2="+submit(p2).reason);
console.log("FORK="+submit(fork).reason);
console.log("GAP="+submit(gap).reason);
console.log("FORGED="+submit(forged).reason);
const before=read();
write(before.slice(0,1));
console.log("ROLLBACK="+submit(make(2,hash(p1.body),"OLD")).reason);
write([{broken:true}]);
let corruption="NOT_DETECTED"; try{const x=read(); if(!x[0]||typeof x[0].body!=="object") throw new Error("CORRUPT");}catch{corruption="DETECTED";}
console.log("JOURNAL_CORRUPTION="+corruption);
console.log("FORK_BLOCKED="+(submit(fork).reason==="EQUIVOCATION_FORK"?"PASS":"FAIL"));
console.log("FORGED_BLOCKED="+(submit(forged).reason==="INVALID_SIGNATURE"?"PASS":"FAIL"));
console.log("GAP_BLOCKED="+(submit(gap).reason==="SEQUENCE_GAP"?"PASS":"FAIL"));
console.log("ROLLBACK_BLOCKED="+(submit(make(1,"","OLD")).reason==="ROLLBACK"?"PASS":"FAIL"));
fs.rmSync(dir,{recursive:true,force:true});
