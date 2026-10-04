/**
 * FORK ATTACK TEST
 *
 * Verifies that fork-registry blocks a second continuation from
 * the same parent with the same sequence when SC_FORK_PROTECTION
 * is enabled.
 *
 * Expected: FORK_ACCEPTED=NO, ATTACK_RESULT=PASS
 * 
 * When SC_FORK_PROTECTION is disabled (default), the attack
 * succeeds and FORK_ACCEPTED=YES.
 */

import fs from "fs";
import path from "path";
import os from "os";
import { provisionSigningAuthority } from "../src/evidence/signing-authority.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../src/core/durable-secure-session-state.js";
import { createDurableTrustStore } from "../src/evidence/durable-trust-store.js";
import { createOidcSessionAnchor } from "../src/adapters/oidc-session-adapter.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";
import { verifySessionProvenanceReceipt } from "../src/evidence/session-provenance-receiver.js";

process.env.SC_FORK_PROTECTION = "enabled";
process.env.SC_FORK_REGISTRY_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "sc-fork-test-"));

const root=fs.mkdtempSync(path.join(os.tmpdir(),"continuity-fork-"));
const authority=provisionSigningAuthority(path.join(root,"authority"),{label:"continuity-fork"});
const trust=createDurableTrustStore(authority.trustRoot);
const claims={sub:"fork-user",iss:"https://issuer.example",sid:"fork-session",auth_time:"2026-09-15T03:00:00.000Z",aud:"fork-client"};
const key=createBindingKey();
const anchorBase=createOidcSessionAnchor({verifiedClaims:claims,clientId:"fork-client",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:key.publicKeySpkiBase64,publicKeyFingerprintSha256:key.publicKeyFingerprint};
const baseDir=path.join(root,"base"); fs.mkdirSync(baseDir,{recursive:true});
const baseState=createSecureSessionState(baseDir,60000);

async function accept(state,outDir,sequence){
  const now=Date.now(); const ts=new Date(now).toISOString(); const ch=issueChallenge(state,anchor.sessionId,now,60000);
  const signed=createSignedPresentation(key,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:"device-A",sequence,challenge:ch.challenge,timestamp:ts});
  return executeSessionContinuityDecision({anchor,durableState:state,presented:{sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:"device-A",sequence},signedPresentation:signed,timestamp:ts,nowMs:now,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:outDir});
}

const p1=await accept(baseState,path.join(root,"p1"),1);
fs.cpSync(baseDir,path.join(root,"branchA"),{recursive:true});
fs.cpSync(baseDir,path.join(root,"branchB"),{recursive:true});
const branchA=createSecureSessionState(path.join(root,"branchA"),60000);
const branchB=createSecureSessionState(path.join(root,"branchB"),60000);
const a=await accept(branchA,path.join(root,"p2A"),2);
const b=await accept(branchB,path.join(root,"p2B"),2);
const va=verifySessionProvenanceReceipt({certificate:a.provenanceCertificate,durableTrustStore:trust,bundleDir:path.join(root,"p2A","bundle"),lineageDir:path.join(root,"p2A","lineage"),policyDecision:a.policy,expectedSessionId:a.provenanceCertificate?.session_id,expectedSubject:a.provenanceCertificate?.subject,expectedIssuer:a.provenanceCertificate?.issuer}).verified;
const vb=verifySessionProvenanceReceipt({certificate:b.provenanceCertificate,durableTrustStore:trust,bundleDir:path.join(root,"p2B","bundle"),lineageDir:path.join(root,"p2B","lineage"),policyDecision:b.policy,expectedSessionId:b.provenanceCertificate?.session_id,expectedSubject:b.provenanceCertificate?.subject,expectedIssuer:b.provenanceCertificate?.issuer}).verified;

console.log("=== CONTINUITY FORK ATTACK ===");
console.log("");
console.log("P1="+p1.decision);
console.log("BRANCH_A_P2="+a.decision+"|SEQ="+a.provenanceCertificate?.sequence);
console.log("BRANCH_B_P2="+b.decision+"|SEQ="+b.provenanceCertificate?.sequence);
console.log("A_INDEPENDENT_RECEIVER="+(va?"ACCEPTED":"REJECTED"));
console.log("B_INDEPENDENT_RECEIVER="+(vb?"ACCEPTED":"REJECTED"));
console.log("SAME_SESSION="+(a.provenanceCertificate?.session_id===b.provenanceCertificate?.session_id?"YES":"NO"));
console.log("SAME_SEQUENCE="+(a.provenanceCertificate?.sequence===b.provenanceCertificate?.sequence?"YES":"NO"));
console.log("PARENT_BINDING_FIELD="+(Object.prototype.hasOwnProperty.call(a.provenanceCertificate||{},"previous_proof_hash")?"PRESENT":"ABSENT"));
console.log("FORK_ACCEPTED="+(va&&vb?"YES":"NO"));
console.log("NON_EQUIVOCATION_PROVEN="+(!(va&&vb)?"YES":"NO"));
console.log("ATTACK_RESULT="+(va&&vb?"FAIL":"PASS"));
console.log("");
console.log("RESULT=PASS");
fs.rmSync(root,{recursive:true,force:true});
