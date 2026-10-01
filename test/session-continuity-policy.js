import { evaluateSessionContinuityPolicy, verifySessionContinuityPolicyDecision } from "../src/policy/session-continuity-policy.js";

function assert(condition,message){if(!condition) throw new Error(message)}

const allow=evaluateSessionContinuityPolicy({engineDecision:"CONTINUOUS",reason:"SECURE_CONTINUITY_COMMITTED",committed:true,certificatePresent:true,bindingValid:true,offlineVerified:true,trustedVerified:true});
assert(allow.decision==="ALLOW","ALLOW_DECISION_FAILED");
assert(verifySessionContinuityPolicyDecision(allow).verified===true,"ALLOW_VERIFICATION_FAILED");
console.log("POLICY_ALLOW=PASS");

const reauth=evaluateSessionContinuityPolicy({engineDecision:"REAUTH_REQUIRED",reason:"REPLAY_DETECTED",committed:false,certificatePresent:false,bindingValid:false,offlineVerified:false,trustedVerified:false});
assert(reauth.decision==="REAUTH","REAUTH_DECISION_FAILED");
assert(verifySessionContinuityPolicyDecision(reauth).verified===true,"REAUTH_VERIFICATION_FAILED");
console.log("POLICY_REAUTH=PASS");

const revoke=evaluateSessionContinuityPolicy({engineDecision:"CONTINUOUS",reason:"TRANSACTIONAL_TRUST_FAILED",committed:false,certificatePresent:true,bindingValid:true,offlineVerified:true,trustedVerified:false});
assert(revoke.decision==="REVOKE","REVOKE_DECISION_FAILED");
assert(verifySessionContinuityPolicyDecision(revoke).verified===true,"REVOKE_VERIFICATION_FAILED");
console.log("POLICY_REVOKE=PASS");

const insufficient=evaluateSessionContinuityPolicy({engineDecision:"CONTINUOUS",reason:"UNKNOWN_REASON",committed:false,certificatePresent:false,bindingValid:false,offlineVerified:false,trustedVerified:false});
assert(insufficient.decision==="REVOKE","INSUFFICIENT_EVIDENCE_NOT_REVOKED");
console.log("POLICY_INSUFFICIENT_EVIDENCE=PASS");

const tampered={...allow,decision:"REVOKE"};
const tamperedVerification=verifySessionContinuityPolicyDecision(tampered);
assert(tamperedVerification.verified===false,"POLICY_TAMPER_ACCEPTED");
assert(tamperedVerification.reason==="POLICY_FINGERPRINT_MISMATCH","POLICY_TAMPER_REASON_FAILED");
console.log("POLICY_TAMPER_REJECTED=PASS");

console.log("SESSION_CONTINUITY_POLICY=PASS");