import fs from "fs";
import path from "path";
import { createDurableSequenceStore, verifyAndAdvanceDurableSequence, getDurableSequence, verifyDurableSequenceStore } from '../src/core/durable-sequence-guard-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);
const root="E:\\SESSION-CONTINUITY - Copy\\lab\\_probe_durable_seq";
fs.rmSync(root,{recursive:true,force:true});

const session="sess-durable-1";

let store=createDurableSequenceStore(root);
log('INITIAL_VERIFY',verifyDurableSequenceStore(store).verified?'PASS':'FAIL');
log('INITIAL_LAST',getDurableSequence(store,session));

let r=verifyAndAdvanceDurableSequence(store,session,1);
log('SEQ1',r.decision==='CONTINUOUS'?'PASS':'FAIL');
log('SEQ1_REASON',r.reason);

r=verifyAndAdvanceDurableSequence(store,session,2);
log('SEQ2',r.decision==='CONTINUOUS'?'PASS':'FAIL');

r=verifyAndAdvanceDurableSequence(store,session,3);
log('SEQ3',r.decision==='CONTINUOUS'?'PASS':'FAIL');

r=verifyAndAdvanceDurableSequence(store,session,5);
log('SEQ_GAP_REJECTED',r.reason==='SEQUENCE_GAP'?'PASS':'FAIL');
log('SEQ_GAP_REASON',r.reason);

r=verifyAndAdvanceDurableSequence(store,session,2);
log('SEQ_ROLLBACK_REJECTED',r.reason==='SEQUENCE_ROLLBACK'?'PASS':'FAIL');

r=verifyAndAdvanceDurableSequence(store,session,3);
log('SEQ_REPLAY_REJECTED',r.reason==='SEQUENCE_ROLLBACK'?'PASS':'FAIL');

const stateAfterReject=getDurableSequence(store,session);
log('STATE_AFTER_REJECT',stateAfterReject===3?'PASS':'FAIL');

store=createDurableSequenceStore(root);
log('RESTART_VERIFY',verifyDurableSequenceStore(store).verified?'PASS':'FAIL');
log('RESTART_LAST',getDurableSequence(store,session)===3?'PASS':'FAIL');
log('RESTART_JOURNAL_HEIGHT',verifyDurableSequenceStore(store).journal_height===3?'PASS':'FAIL');

r=verifyAndAdvanceDurableSequence(store,session,4);
log('POST_RESTART_SEQ4',r.decision==='CONTINUOUS'?'PASS':'FAIL');

r=verifyAndAdvanceDurableSequence(store,session,4);
log('POST_RESTART_REPLAY',r.reason==='SEQUENCE_ROLLBACK'?'PASS':'FAIL');

const otherSession="sess-durable-2";
r=verifyAndAdvanceDurableSequence(store,otherSession,1);
log('SECOND_SESSION_SEQ1',r.decision==='CONTINUOUS'?'PASS':'FAIL');
r=verifyAndAdvanceDurableSequence(store,otherSession,2);
log('SECOND_SESSION_SEQ2',r.decision==='CONTINUOUS'?'PASS':'FAIL');
log('SESSION1_INDEPENDENT',getDurableSequence(store,session)===4?'PASS':'FAIL');
log('SESSION2_INDEPENDENT',getDurableSequence(store,otherSession)===2?'PASS':'FAIL');

const journalPath=path.join(root,'REPLAY_JOURNAL.ndjson');
const original=fs.readFileSync(journalPath,'utf8');
fs.writeFileSync(journalPath,original.split(/\r?\n/).filter(Boolean).slice(0,3).join('\n')+'\n','utf8');

let rollbackDetected=false;
try{ createDurableSequenceStore(root); } catch(e){ rollbackDetected=String(e.message).startsWith('V1_1_SEQUENCE_HEAD_HEIGHT_MISMATCH')||String(e.message).startsWith('V1_1_SEQUENCE_HEAD_HASH_MISMATCH'); }
log('ROLLBACK_DETECTED',rollbackDetected?'PASS':'FAIL');

fs.writeFileSync(journalPath,original,'utf8');
fs.appendFileSync(journalPath,'{"broken',"utf8");
let corruptionDetected=false;
try{ createDurableSequenceStore(root); } catch(e){ corruptionDetected=true; }
log('CORRUPTION_DETECTED',corruptionDetected?'PASS':'FAIL');

fs.writeFileSync(journalPath,original,'utf8');

const recovered=createDurableSequenceStore(root);
log('RECOVERY_AFTER_REPAIR',verifyDurableSequenceStore(recovered).verified?'PASS':'FAIL');
log('RECOVERED_LAST',getDurableSequence(recovered,session)===4?'PASS':'FAIL');

fs.rmSync(root,{recursive:true,force:true});
log('PROBE_CLEANUP','PASS');
log('DURABLE_SEQ_PROBE_DONE',1);
