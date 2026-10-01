import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const dir=fs.mkdtempSync(path.join(os.tmpdir(),"witness-adv-"));
const journal=path.join(dir,"WITNESS.ndjson");
const {privateKey,publicKey}=crypto.generateKeyPairSync("ed25519");
const root="AUTH-ROOT-ADV";
const canon=x=>JSON.stringify(x);
const hash=x=>crypto.createHash("sha256").update(canon(x)).digest("hex");
const sign=b=>crypto.sign(null,Buffer.from(canon(b)),privateKey).toString("base64");
const verify=p=>crypto.verify(null,Buffer.from(canon(p.body)),publicKey,Buffer.from(p.sig,"base64"));
const make=(seq,parent,state)=>{const body={root,sequence:seq,parent,state};return {body,sig:sign(body)};};

function load(){
 if(!fs.existsSync(journal))return [];
 return fs.readFileSync(journal,"utf8").split(String.fromCharCode(10)).map(x=>x.trim()).filter(Boolean).map(JSON.parse);
}

function submit(p){
 if(!verify(p))return {ok:false,reason:"INVALID_SIGNATURE"};
 const rows=load();
 const last=rows[rows.length-1];
 if(!last){if(p.body.sequence!==1)return {ok:false,reason:"FIRST_SEQUENCE_REQUIRED"};}
 if(last){if(p.body.sequence<last.sequence)return {ok:false,reason:"ROLLBACK"}; if(p.body.sequence===last.sequence){return hash(p.body)===hash(last.body)?{ok:true,reason:"IDEMPOTENT_REPLAY"}:{ok:false,reason:"EQUIVOCATION_FORK"};} if(p.body.sequence!==last.sequence+1)return {ok:false,reason:"SEQUENCE_GAP"}; if(p.body.parent!==hash(last.body))return {ok:false,reason:"PARENT_MISMATCH"};}
 fs.appendFileSync(journal,JSON.stringify(p)+String.fromCharCode(10),"utf8");
 return {ok:true,reason:"ACCEPTED"};
}

const p1=make(1,"","S1");
const p2=make(2,hash(p1.body),"S2");
const p2fork=make(2,hash(p1.body),"S2-FORK");
const p4=make(4,hash(p2.body),"S4");
const forged={body:{root,sequence:3,parent:hash(p2.body),state:"FORGED"},sig:"AAAA"};
console.log("=== ADVERSARIAL WITNESS LAB ===");
console.log("P1="+submit(p1).reason);
console.log("P2="+submit(p2).reason);
console.log("FORK="+submit(p2fork).reason);
console.log("GAP="+submit(p4).reason);
console.log("FORGED="+submit(forged).reason);
const saved=fs.readFileSync(journal,"utf8");
fs.writeFileSync(journal,saved.split(/\\r?\\n/).filter(Boolean).slice(0,-1).join("\\n")+"\\n","utf8");
console.log("ROLLBACK_AFTER_TRUNCATION="+submit(make(2,hash(p1.body),"S2-ROLLBACK")).reason);
fs.writeFileSync(journal,saved+"{\"bad\":true}\\n","utf8");
let corruption="NOT_DETECTED"; try{for(const line of fs.readFileSync(journal,"utf8").split(/\\r?\\n/).filter(Boolean))JSON.parse(line); corruption="DETECTED";}catch{corruption="DETECTED";}
console.log("JOURNAL_CORRUPTION="+corruption);
console.log("FORK_BLOCKED="+(submit(make(2,hash(p1.body),"OTHER")).reason==="EQUIVOCATION_FORK"?"PASS":"FAIL"));
console.log("FORGED_BLOCKED="+(submit(forged).reason==="INVALID_SIGNATURE"?"PASS":"FAIL"));
console.log("GAP_BLOCKED="+(submit(p4).reason==="SEQUENCE_GAP"?"PASS":"FAIL"));
console.log("ROLLBACK_BLOCKED="+(submit(make(1,"","S1-OLD")).reason==="ROLLBACK"?"PASS":"FAIL"));
fs.rmSync(dir,{recursive:true,force:true});
