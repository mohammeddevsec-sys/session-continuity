import { createSequenceState, verifyAndAdvanceSequence, getLastSequence } from '../src/core/sequence-guard-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

let s=createSequenceState();

let r=verifyAndAdvanceSequence(s,1);
log('FRESH_SEQ1',r.decision==='CONTINUOUS'?'PASS':'FAIL');
log('FRESH_SEQ1_REASON',r.reason);

r=verifyAndAdvanceSequence(s,2);
log('SEQ2_AFTER_1',r.decision==='CONTINUOUS'?'PASS':'FAIL');
log('STATE_AFTER_2',getLastSequence(s)===2?'PASS':'FAIL');

r=verifyAndAdvanceSequence(s,4);
log('SEQ_GAP_DECISION',r.decision==='REAUTH_REQUIRED'?'PASS':'FAIL');
log('SEQ_GAP_REASON',r.reason);
log('STATE_AFTER_GAP',getLastSequence(s)===2?'PASS':'FAIL');

r=verifyAndAdvanceSequence(s,2);
log('SEQ_REPLAY_REASON',r.reason);
log('SEQ_REPLAY_STATE',getLastSequence(s)===2?'PASS':'FAIL');

r=verifyAndAdvanceSequence(s,1);
log('SEQ_ROLLBACK_REASON',r.reason);

r=verifyAndAdvanceSequence(s,0);
log('SEQ_ZERO_REASON',r.reason);

r=verifyAndAdvanceSequence(s,-5);
log('SEQ_NEGATIVE_REASON',r.reason);

r=verifyAndAdvanceSequence(s,3.5);
log('SEQ_FLOAT_REASON',r.reason);

r=verifyAndAdvanceSequence(null,1);
log('SEQ_NULL_STATE_REASON',r.reason);

r=verifyAndAdvanceSequence(s,3);
log('SEQ3_AFTER_2',r.decision==='CONTINUOUS'?'PASS':'FAIL');
log('STATE_AFTER_3',getLastSequence(s)===3?'PASS':'FAIL');

r=verifyAndAdvanceSequence(s,4);
log('SEQ4_AFTER_3',r.decision==='CONTINUOUS'?'PASS':'FAIL');

log('SEQ_PROBE_DONE',1);
