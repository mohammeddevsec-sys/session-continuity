import fs from "fs";
import path from "path";
import os from "os";
import { provisionSigningAuthority } from "../../src/evidence/signing-authority.js";
import { createBindingKey, createSignedPresentation } from "../../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../../src/core/durable-secure-session-state.js";
import { createDurableTrustStore } from "../../src/evidence/durable-trust-store.js";
import { createOidcSessionAnchor } from "../../src/adapters/oidc-session-adapter.js";
import { executeSessionContinuityDecision } from "../../src/product/session-continuity-decision.js";
import { verifySessionProvenanceReceipt } from "../../src/evidence/session-provenance-receiver.js";

const root=fs.mkdtempSync(path.join(os.tmpdir(),"session-continuity-gap-lab-"));
const authority=provisionSigningAuthority(path.join(root,"authority"),{label:"comparative-gap-lab"});
const trust=createDurableTrustStore(authority.trustRoot);
const baseClaims={sub:"user-lab-001",iss:"https://issuer.example",sid:"sid-lab-001",auth_time:"2026-09-15T03:00:00.000Z",aud:"client-lab"};

function oidcBaseline(event){
  return {decision:"ALLOW",reason:event==="OIDC_INVALID"?"OIDC_REJECT":"OIDC_IDENTITY_VALID"};
}

function caeBaseline(tokenValid,event){
  if(!tokenValid) return {decision:"REJECT",reason:"TOKEN_INVALID"};
  const revocationEvents=new Set(["USER_DISABLED","PASSWORD_CHANGED","MFA_ENABLED","REFRESH_REVOKED","HIGH_RISK"]);
  const policyEvents=new Set(["IP_POLICY_VIOLATION"]);
  if(revocationEvents.has(event)||policyEvents.has(event)) return {decision:"REJECT",reason:"CAE_EVENT_ENFORCED"};
  return {decision:"ALLOW",reason:"NO_ENFORCEMENT_EVENT"};
}

function makeContext(deviceId){
  const nowMs=Date.now();
  const outputRoot=path.join(root,"scenario-"+deviceId+"-"+nowMs);
  fs.mkdirSync(outputRoot,{recursive:true});
  const state=createSecureSessionState(path.join(outputRoot,"state"),60000);
  const key=createBindingKey();
  const claims={...baseClaims};
  const anchorBase=createOidcSessionAnchor({verifiedClaims:claims,clientId:"client-lab",deviceId});
  const anchor={...anchorBase,publicKeySpkiBase64:key.publicKeySpkiBase64,publicKeyFingerprintSha256:key.publicKeyFingerprint};
  return {nowMs,outputRoot,state,key,anchor};
}

async function continuityOnce(ctx,deviceId,sequence=1){
  const nowMs=ctx.nowMs;
  const timestamp=new Date(nowMs).toISOString();
  const challenge=issueChallenge(ctx.state,ctx.anchor.sessionId,nowMs,60000);
  const signedPresentation=createSignedPresentation(ctx.key,{session_id:ctx.anchor.sessionId,subject:ctx.anchor.subject,issuer:ctx.anchor.issuer,client_id:ctx.anchor.clientId,device_id:deviceId,sequence,challenge:challenge.challenge,timestamp});
  const presented={sessionId:ctx.anchor.sessionId,subject:ctx.anchor.subject,issuer:ctx.anchor.issuer,clientId:ctx.anchor.clientId,deviceId,sequence};
  return executeSessionContinuityDecision({anchor:ctx.anchor,durableState:ctx.state,presented,signedPresentation,timestamp,nowMs,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(ctx.outputRoot,"proof-"+sequence)});
}

function row(name,oidc,cae,continuity,reason){
  return {scenario:name,oidc:oidc.decision,cae:cae.decision,continuity:continuity.decision,detail:reason};
}

const results=[];
const healthy=makeContext("device-A");
const healthyResult=await continuityOnce(healthy,"device-A",1);
results.push(row("01_HEALTHY",oidcBaseline("NONE"),caeBaseline(true,"NONE"),healthyResult,healthyResult.reason));

const revoke=makeContext("device-A");
const revokeResult=await continuityOnce(revoke,"device-A",1);
results.push(row("02_USER_REVOCATION_EVENT",oidcBaseline("NONE"),caeBaseline(true,"USER_DISABLED"),revokeResult,revokeResult.reason));

const ip=makeContext("device-A");
const ipResult=await continuityOnce(ip,"device-A",1);
results.push(row("03_IP_POLICY_EVENT",oidcBaseline("NONE"),caeBaseline(true,"IP_POLICY_VIOLATION"),ipResult,ipResult.reason));

const device=makeContext("device-A");
const challenge=issueChallenge(device.state,device.anchor.sessionId,device.nowMs,60000);
const timestamp=new Date(device.nowMs).toISOString();
const signedChangedDevice=createSignedPresentation(device.key,{session_id:device.anchor.sessionId,subject:device.anchor.subject,issuer:device.anchor.issuer,client_id:device.anchor.clientId,device_id:"device-B",sequence:1,challenge:challenge.challenge,timestamp});
const presentedChangedDevice={sessionId:device.anchor.sessionId,subject:device.anchor.subject,issuer:device.anchor.issuer,clientId:device.anchor.clientId,deviceId:"device-B",sequence:1};
const changedDeviceResult=await executeSessionContinuityDecision({anchor:device.anchor,durableState:device.state,presented:presentedChangedDevice,signedPresentation:signedChangedDevice,timestamp,nowMs:device.nowMs,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(device.outputRoot,"proof-device-change")});
results.push(row("04_DEVICE_CHANGED_WITHOUT_CAE_EVENT",oidcBaseline("NONE"),caeBaseline(true,"NONE"),changedDeviceResult,changedDeviceResult.reason));

const replay=makeContext("device-A");
const firstReplay=await continuityOnce(replay,"device-A",1);
const now2=replay.nowMs;
const challengeReplay=issueChallenge(replay.state,replay.anchor.sessionId,now2,60000);
const tsReplay=new Date(now2).toISOString();
const presReplay=createSignedPresentation(replay.key,{session_id:replay.anchor.sessionId,subject:replay.anchor.subject,issuer:replay.anchor.issuer,client_id:replay.anchor.clientId,device_id:"device-A",sequence:1,challenge:challengeReplay.challenge,timestamp:tsReplay});
const presentedReplay={sessionId:replay.anchor.sessionId,subject:replay.anchor.subject,issuer:replay.anchor.issuer,clientId:replay.anchor.clientId,deviceId:"device-A",sequence:1};
const firstProof={...firstReplay};
const replayResult=await executeSessionContinuityDecision({anchor:replay.anchor,durableState:replay.state,presented:presentedReplay,signedPresentation:presReplay,timestamp:tsReplay,nowMs:now2,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(replay.outputRoot,"proof-replay")});
results.push(row("05_SEQUENCE_REPLAY_ATTEMPT",oidcBaseline("NONE"),caeBaseline(true,"NONE"),replayResult,replayResult.reason));

const tamper=makeContext("device-A");
const tamperResult=await continuityOnce(tamper,"device-A",1);
const tamperProofRoot=path.join(tamper.outputRoot,"proof-1");
const cert=tamperResult.provenanceCertificate;
const policy=tamperResult.policy;
const evidenceFile=path.join(tamperProofRoot,"bundle","evidence.json");
fs.appendFileSync(evidenceFile,"X");
const verifyAfterTamper=verifySessionProvenanceReceipt({certificate:cert,durableTrustStore:trust,bundleDir:path.join(tamperProofRoot,"bundle"),lineageDir:path.join(tamperProofRoot,"lineage"),policyDecision:policy,expectedSessionId:cert.session_id,expectedSubject:cert.subject,expectedIssuer:cert.issuer});
results.push({scenario:"06_POST_DECISION_EVIDENCE_TAMPER",oidc:"NOT_APPLICABLE",cae:"NOT_APPLICABLE",continuity:verifyAfterTamper.verified?"ALLOW":"REJECT",detail:verifyAfterTamper.reason});

console.log("=== SESSION CONTINUITY :: ADVERSARIAL COMPARATIVE GAP LAB ===");
console.log("MODEL_SCOPE=OIDC_IDENTITY|CAE_EVENT_POLICY|SESSION_CONTINUITY_PRODUCT");
console.log("IMPORTANT=CAE_RESULTS_MODEL_PUBLISHED_SEMANTICS_NOT_VENDOR_UNIVERSAL");
console.log("");
for(const r of results){console.log(`${r.scenario}|OIDC=${r.oidc}|CAE=${r.cae}|CONTINUITY=${r.continuity}|DETAIL=${r.detail}`);}

const expected={
  "01_HEALTHY":["ALLOW","ALLOW","ALLOW"],
  "02_USER_REVOCATION_EVENT":["ALLOW","REJECT","ALLOW"],
  "03_IP_POLICY_EVENT":["ALLOW","REJECT","ALLOW"],
  "04_DEVICE_CHANGED_WITHOUT_CAE_EVENT":["ALLOW","ALLOW","REAUTH"],
  "05_SEQUENCE_REPLAY_ATTEMPT":["ALLOW","ALLOW","REAUTH"],
  "06_POST_DECISION_EVIDENCE_TAMPER":["NOT_APPLICABLE","NOT_APPLICABLE","REJECT"]
};
let failures=0;
for(const r of results){const e=expected[r.scenario]; if(r.oidc!==e[0]||r.cae!==e[1]||r.continuity!==e[2]){failures++;console.log("EXPECTATION_MISMATCH="+r.scenario);}}
console.log("");
console.log("SCENARIOS="+results.length);
console.log("EXPECTATION_CHECK="+(failures===0?"PASS":"FAIL"));
console.log("LAB_RESULT="+(failures===0?"PASS":"FAIL"));
fs.writeFileSync(path.join(process.cwd(),"lab-result.json"),JSON.stringify({results,expectations:expected,labResult:failures===0?"PASS":"FAIL"},null,2)+"\n","utf8");
fs.rmSync(root,{recursive:true,force:true});
if(failures!==0) process.exit(2);
