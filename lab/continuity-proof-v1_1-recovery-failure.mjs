import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

const sourcePath="E:\\SESSION-CONTINUITY\\lab\\continuity-proof-v1_1-conformant-phase2-hardened.mjs";
const source=fs.readFileSync(sourcePath,"utf8");

if(!source.includes('const recover=()=>')) throw new Error("BASELINE_RECOVER_MISSING");
if(!source.includes('WITNESS_RECOVERY_FAILED')) throw new Error("BASELINE_RECOVERY_ERROR_MISSING");
if(!source.includes('WITNESS_NOT_READY')) throw new Error("BASELINE_NOT_READY_MISSING");

const target='const recovered=recover(),recoveryVerified=recovered.ready&&recovered.state.head_sequence===2&&recovered.state.head_hash===p2.body.continuity_hash;';
if(!source.includes(target)) throw new Error("BASELINE_TARGET_MISSING");

const replacement=[
'let recoveryFailureObserved=false;',
'let recoveryFailureMessage="";',
'const journalBackup=fs.readFileSync(journalFile,"utf8");',
'fs.writeFileSync(journalFile,journalBackup.replace(/"entry_hash":"[^"]+"/,\'"entry_hash":"CORRUPTED_RECOVERY_HASH"\'),"utf8");',
'try{recover();}catch(e){recoveryFailureObserved=e.message==="WITNESS_RECOVERY_FAILED";recoveryFailureMessage=e.message;}',
'const blockedAfterFailedRecovery=new Witness().observe(p4).result==="WITNESS_NOT_READY";',
'const failedObservation=new Witness().observe(p4); const noReceiptAfterFailedRecovery=failedObservation.result==="WITNESS_NOT_READY"&&!Object.prototype.hasOwnProperty.call(failedObservation,"receipt");',
'fs.writeFileSync(journalFile,journalBackup,"utf8");',
'const recovered=recover(),recoveryVerified=recovered.ready&&recovered.state.head_sequence===2&&recovered.state.head_hash===p2.body.continuity_hash;',
'console.log("RECOVERY_FAILURE_DETECTED="+(recoveryFailureObserved?"PASS":"FAIL"));',
'console.log("RECOVERY_FAILURE_ERROR="+(recoveryFailureMessage==="WITNESS_RECOVERY_FAILED"?"PASS":"FAIL"));',
'console.log("FAIL_CLOSED_AFTER_RECOVERY_FAILURE="+(blockedAfterFailedRecovery?"PASS":"FAIL"));',
'console.log("NO_RECEIPT_AFTER_RECOVERY_FAILURE="+(noReceiptAfterFailedRecovery?"PASS":"FAIL"));',
'console.log("RECOVERY_RESTORED_AFTER_JOURNAL_REPAIR="+(recoveryVerified?"PASS":"FAIL"));',
'console.log("REFERENCE_GAP7="+(recoveryFailureObserved&&blockedAfterFailedRecovery&&noReceiptAfterFailedRecovery&&recoveryVerified?"PASS":"FAIL"));'
].join("\n");

const patched=source.replace(target,replacement);
const tmp="E:\\SESSION-CONTINUITY\\lab\\nono-gap7-runtime.mjs";
fs.writeFileSync(tmp,patched,"utf8");
try{process.stdout.write(execFileSync(process.execPath,[tmp],{cwd:"E:\\SESSION-CONTINUITY\\lab",encoding:"utf8"}));}
finally{fs.rmSync(tmp,{force:true});}

console.log("HARNESS_SYNTAX=PASS");
console.log("SRC_NOT_TOUCHED=YES");
console.log("RELEASE_NOT_TOUCHED=YES");
console.log("SPEC_MODIFICATION=NONE");