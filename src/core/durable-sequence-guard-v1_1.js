import fs from "fs";
import path from "path";
import crypto from "crypto";
import { jcsCanonicalize } from "./canonical-v1_1.js";

const JOURNAL_NAME = "REPLAY_JOURNAL.ndjson";
const HEAD_NAME = "HEAD.json";
const LOCK_NAME = "REPLAY.lock";
const EVENT_SCHEMA_ID = "session-continuity.v1_1.sequence.event";
const HEAD_SCHEMA_ID = "session-continuity.v1_1.sequence.head";
const VERSION = 1;

function sha256(text){
  return crypto.createHash("sha256").update(Buffer.from(text,"utf8")).digest("hex").toLowerCase();
}

function ensureDir(dir){ fs.mkdirSync(dir,{recursive:true}); }

function atomicWrite(filePath,text){
  const temp=filePath+".tmp-"+process.pid+"-"+Date.now()+"-"+Math.random().toString(16).slice(2);
  const fd=fs.openSync(temp,"w");
  try{ fs.writeSync(fd,text,null,"utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temp,filePath);
}

function appendJournal(filePath,text){
  const fd=fs.openSync(filePath,"a");
  try{ fs.writeSync(fd,text,null,"utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function sleep(ms){ const end=Date.now()+ms; while(Date.now()<end){} }

function acquireLock(lockPath,timeoutMs){
  const started=Date.now();
  while(true){
    try{
      const fd=fs.openSync(lockPath,"wx");
      try{ fs.writeSync(fd,String(process.pid),null,"utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      return;
    } catch(err){
      if(err.code!=="EEXIST") throw err;
      if(Date.now()-started>=timeoutMs) throw new Error("V1_1_SEQUENCE_LOCK_TIMEOUT");
      sleep(5);
    }
  }
}

function releaseLock(lockPath){
  try{ fs.unlinkSync(lockPath); } catch(err){ if(err.code!=="ENOENT") throw err; }
}

function parseJournal(filePath){
  if(!fs.existsSync(filePath)) return [];
  const raw=fs.readFileSync(filePath,"utf8");
  if(!raw.length) return [];
  const lines=raw.split(/\r?\n/).filter(Boolean);
  const records=[];
  let prevHash="";
  for(let i=0;i<lines.length;i++){
    let record;
    try{ record=JSON.parse(lines[i]); } catch { throw new Error("V1_1_SEQUENCE_JOURNAL_JSON_INVALID:"+i); }
    if(!record||typeof record!=="object") throw new Error("V1_1_SEQUENCE_JOURNAL_RECORD_INVALID:"+i);
    if(String(record.prev_hash||"")!==prevHash) throw new Error("V1_1_SEQUENCE_JOURNAL_CHAIN_BROKEN:"+i);
    const payload={schema_id:record.schema_id,version:record.version,event:record.event,session_id:record.session_id,sequence:record.sequence,prev_hash:record.prev_hash};
    const calculated=sha256(jcsCanonicalize(payload));
    if(String(record.record_hash||"").toLowerCase()!==calculated) throw new Error("V1_1_SEQUENCE_JOURNAL_HASH_MISMATCH:"+i);
    prevHash=calculated;
    records.push(record);
  }
  return records;
}

function buildSessions(records){
  const sessions=new Map();
  for(const record of records){
    const sid=record.session_id;
    if(typeof sid!=="string"||!sid.length) throw new Error("V1_1_SEQUENCE_SESSION_ID_INVALID");
    if(!Number.isInteger(record.sequence)||record.sequence<1) throw new Error("V1_1_SEQUENCE_VALUE_INVALID");
    const current=sessions.get(sid)??0;
    const expected=current+1;
    if(record.sequence!==expected) throw new Error("V1_1_SEQUENCE_JOURNAL_NON_CONTIGUOUS:"+sid);
    sessions.set(sid,record.sequence);
  }
  return sessions;
}

function buildHead(records){
  return {schema_id:HEAD_SCHEMA_ID,version:VERSION,height:records.length,last_record_hash:records.length?records[records.length-1].record_hash:""};
}

function writeHead(headPath,head){ atomicWrite(headPath,jcsCanonicalize(head)+"\n"); }

function verifyHead(records,headPath){
  if(!fs.existsSync(headPath)) throw new Error("V1_1_SEQUENCE_HEAD_MISSING");
  let head;
  try{ head=JSON.parse(fs.readFileSync(headPath,"utf8")); } catch { throw new Error("V1_1_SEQUENCE_HEAD_INVALID"); }
  if(head.schema_id!==HEAD_SCHEMA_ID) throw new Error("V1_1_SEQUENCE_HEAD_SCHEMA_INVALID");
  const expected=buildHead(records);
  if(Number(head.height)!==expected.height) throw new Error("V1_1_SEQUENCE_HEAD_HEIGHT_MISMATCH");
  if(String(head.last_record_hash||"")!==expected.last_record_hash) throw new Error("V1_1_SEQUENCE_HEAD_HASH_MISMATCH");
}

function refresh(store){
  const records=parseJournal(store.journalPath);
  verifyHead(records,store.headPath);
  store.records=records;
  store.sessions=buildSessions(records);
  return store.sessions;
}

export function createDurableSequenceStore(directory){
  if(typeof directory!=="string"||!directory.length) throw new Error("V1_1_SEQUENCE_DIRECTORY_INVALID");
  ensureDir(directory);
  const journalPath=path.join(directory,JOURNAL_NAME);
  const headPath=path.join(directory,HEAD_NAME);
  const lockPath=path.join(directory,LOCK_NAME);
  const records=parseJournal(journalPath);
  if(records.length>0||fs.existsSync(headPath)){ verifyHead(records,headPath); } else { writeHead(headPath,buildHead(records)); }
  return {version:VERSION,directory,journalPath,headPath,lockPath,records,sessions:buildSessions(records)};
}

export function verifyAndAdvanceDurableSequence(store,sessionId,presentedSequence){
  if(!store||store.version!==VERSION) return {decision:"REAUTH_REQUIRED",reason:"SEQUENCE_STORE_INVALID"};
  if(typeof sessionId!=="string"||!sessionId.length) return {decision:"REAUTH_REQUIRED",reason:"SEQUENCE_SESSION_INVALID"};
  if(!Number.isInteger(presentedSequence)||presentedSequence<1) return {decision:"REAUTH_REQUIRED",reason:"SEQUENCE_INVALID"};
  acquireLock(store.lockPath,3000);
  try{
    refresh(store);
    const last=store.sessions.get(sessionId)??0;
    const expected=last+1;
    if(presentedSequence<expected) return {decision:"REAUTH_REQUIRED",reason:"SEQUENCE_ROLLBACK",lastSequence:last,presentedSequence};
    if(presentedSequence>expected) return {decision:"REAUTH_REQUIRED",reason:"SEQUENCE_GAP",lastSequence:last,presentedSequence};
    const prevHash=store.records.length?store.records[store.records.length-1].record_hash:"";
    const payload={schema_id:EVENT_SCHEMA_ID,version:VERSION,event:"SEQUENCE_ACCEPTED",session_id:sessionId,sequence:presentedSequence,prev_hash:prevHash};
    const record={...payload,record_hash:sha256(jcsCanonicalize(payload))};
    appendJournal(store.journalPath,jcsCanonicalize(record)+"\n");
    const after=parseJournal(store.journalPath);
    writeHead(store.headPath,buildHead(after));
    refresh(store);
    if((store.sessions.get(sessionId)??0)!==presentedSequence) throw new Error("V1_1_SEQUENCE_PERSISTENCE_MISMATCH");
    return {decision:"CONTINUOUS",reason:"SEQUENCE_ACCEPTED",lastSequence:last,presentedSequence};
  } finally { releaseLock(store.lockPath); }
}

export function getDurableSequence(store,sessionId){
  refresh(store);
  return store.sessions.get(sessionId)??0;
}

export function verifyDurableSequenceStore(store){
  refresh(store);
  return {verified:true,journal_height:store.records.length,sessions:store.sessions.size,last_record_hash:store.records.length?store.records[store.records.length-1].record_hash:""};
}