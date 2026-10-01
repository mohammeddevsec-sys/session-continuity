import { createKeyLifecycleStore, registerKey, retireKey, revokeKey, getKey, canSignNow, verifyKeyForProof, KEY_STATUS } from '../src/evidence/key-lifecycle-v1_1.js';

const log=(k,v)=>console.log(k+'='+v);

const fpA='a'.repeat(64);
const fpB='b'.repeat(64);
const fpC='c'.repeat(64);

const store=createKeyLifecycleStore();

let rec=registerKey(store,fpA,{valid_from:'2026-09-01T00:00:00.000Z',valid_until:'2027-09-01T00:00:00.000Z',version:1});
log('REGISTER_A_STATUS',rec.status===KEY_STATUS.ACTIVE?'PASS':'FAIL');
log('REGISTER_A_FP',rec.fingerprint===fpA?'PASS':'FAIL');

rec=registerKey(store,fpB,{valid_from:'2026-09-01T00:00:00.000Z',version:1});
log('REGISTER_B',rec.status===KEY_STATUS.ACTIVE?'PASS':'FAIL');

rec=registerKey(store,fpC,{valid_from:'2026-09-01T00:00:00.000Z',valid_until:'2027-09-01T00:00:00.000Z',version:1});
log('REGISTER_C',rec.status===KEY_STATUS.ACTIVE?'PASS':'FAIL');

let dupRejected=false;
try{ registerKey(store,fpA,{}); }catch(e){ dupRejected=true; }
log('DUPLICATE_REJECTED',dupRejected?'PASS':'FAIL');

let s=canSignNow(store,fpA,'2026-09-16T12:00:00.000Z');
log('CAN_SIGN_A_NOW',s.allowed?'PASS':'FAIL');
log('CAN_SIGN_A_REASON',s.reason);

s=canSignNow(store,fpA,'2025-01-01T00:00:00.000Z');
log('CAN_SIGN_BEFORE_VALID',!s.allowed?'PASS':'FAIL');
log('CAN_SIGN_BEFORE_REASON',s.reason);

s=canSignNow(store,fpA,'2028-01-01T00:00:00.000Z');
log('CAN_SIGN_AFTER_VALID',!s.allowed?'PASS':'FAIL');
log('CAN_SIGN_AFTER_REASON',s.reason);

s=canSignNow(store,'f'.repeat(64),'2026-09-16T12:00:00.000Z');
log('CAN_SIGN_UNKNOWN',!s.allowed?'PASS':'FAIL');
log('CAN_SIGN_UNKNOWN_REASON',s.reason);

let v=verifyKeyForProof(store,fpA,'2026-09-15T12:00:00.000Z');
log('PROOF_A_VALID',v.valid?'PASS':'FAIL');
log('PROOF_A_REASON',v.reason);

v=verifyKeyForProof(store,fpA,'2024-01-01T00:00:00.000Z');
log('PROOF_BEFORE_VALID_REJECTED',!v.valid?'PASS':'FAIL');
log('PROOF_BEFORE_VALID_REASON',v.reason);

v=verifyKeyForProof(store,fpA,'2028-01-01T00:00:00.000Z');
log('PROOF_AFTER_VALID_REJECTED',!v.valid?'PASS':'FAIL');
log('PROOF_AFTER_VALID_REASON',v.reason);

const retired=retireKey(store,fpB,{retired_at:'2026-09-16T00:00:00.000Z'});
log('RETIRE_B_STATUS',retired.status===KEY_STATUS.RETIRED?'PASS':'FAIL');

s=canSignNow(store,fpB,'2026-09-17T12:00:00.000Z');
log('CAN_SIGN_RETIRED',!s.allowed?'PASS':'FAIL');
log('CAN_SIGN_RETIRED_REASON',s.reason);

v=verifyKeyForProof(store,fpB,'2026-09-10T12:00:00.000Z');
log('HISTORICAL_PROOF_BEFORE_RETIRE',v.valid?'PASS':'FAIL');
log('HISTORICAL_REASON',v.reason);

v=verifyKeyForProof(store,fpB,'2026-09-20T12:00:00.000Z');
log('PROOF_AFTER_RETIRE_REJECTED',!v.valid?'PASS':'FAIL');
log('PROOF_AFTER_RETIRE_REASON',v.reason);

let retireAgainRejected=false;
try{ retireKey(store,fpB,{retired_at:'2026-09-18T00:00:00.000Z'}); }catch(e){ retireAgainRejected=true; }
log('RETIRE_TWICE_REJECTED',retireAgainRejected?'PASS':'FAIL');

const revoked=revokeKey(store,fpC,{revoked_at:'2026-09-16T00:00:00.000Z',compromise_window:{start:'2026-09-10T00:00:00.000Z',end:'2026-09-16T00:00:00.000Z'}});
log('REVOKE_C_STATUS',revoked.status===KEY_STATUS.REVOKED?'PASS':'FAIL');
log('REVOKE_C_HAS_WINDOW',revoked.compromise_window?'PASS':'FAIL');

s=canSignNow(store,fpC,'2026-09-17T12:00:00.000Z');
log('CAN_SIGN_REVOKED',!s.allowed?'PASS':'FAIL');

v=verifyKeyForProof(store,fpC,'2026-09-05T12:00:00.000Z');
log('PROOF_BEFORE_COMPROMISE_VALID',v.valid?'PASS':'FAIL');
log('PROOF_BEFORE_COMPROMISE_REASON',v.reason);

v=verifyKeyForProof(store,fpC,'2026-09-12T12:00:00.000Z');
log('PROOF_WITHIN_COMPROMISE_REJECTED',!v.valid?'PASS':'FAIL');
log('PROOF_WITHIN_COMPROMISE_REASON',v.reason);

v=verifyKeyForProof(store,fpC,'2026-09-16T12:00:00.000Z');
log('PROOF_AT_COMPROMISE_END_REJECTED',!v.valid?'PASS':'FAIL');
log('PROOF_AT_COMPROMISE_END_REASON',v.reason);

let revokeAgainRejected=false;
try{ revokeKey(store,fpC,{revoked_at:'2026-09-17T00:00:00.000Z'}); }catch(e){ revokeAgainRejected=true; }
log('REVOKE_TWICE_REJECTED',revokeAgainRejected?'PASS':'FAIL');

let retireRevokedRejected=false;
try{ retireKey(store,fpC,{retired_at:'2026-09-17T00:00:00.000Z'}); }catch(e){ retireRevokedRejected=true; }
log('RETIRE_REVOKED_REJECTED',retireRevokedRejected?'PASS':'FAIL');

const recA=getKey(store,fpA);
log('GET_KEY_A',recA && recA.fingerprint===fpA?'PASS':'FAIL');
log('GET_KEY_UNKNOWN',getKey(store,'0'.repeat(64))===null?'PASS':'FAIL');

let badWindowRejected=false;
try{ revokeKey(store,'e'.repeat(64),{revoked_at:'2026-09-16T00:00:00.000Z'}); }catch(e){ badWindowRejected=true; }
log('UNKNOWN_REVOKE_REJECTED',badWindowRejected?'PASS':'FAIL');

log('KEY_LIFECYCLE_PROBE_DONE',1);
