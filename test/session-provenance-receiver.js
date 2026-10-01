import fs from "fs";
import path from "path";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../src/core/durable-secure-session-state.js";
import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";
import { verifySessionProvenanceReceipt } from "../src/evidence/session-provenance-receiver.js";

const root="E:\\\\SESSION-CONTINUITY\\\\test\\\\fixtures\\\\session-provenance-receiver";
fs.rmSync(root,{recursive:true,force:true});
const sessionKey=createBindingKey();
const signer=createSigningIdentity();
const trustRoot=path.join(root,"trust");
const trust=createDurableTrustStore(trustRoot);
durableRegisterTrustAnchor(trust,signer.publicKeySpkiBase64,{version:1,created_at:"2026-09-13T19:30:00Z",label:"provenance-receiver-signer"});
const anchorBase=createSessionAnchor({sessionId:"sess-receiver-final-001",subject:"user-001",issuer:"issuer-A",authTime:"2026-09-13T09:00:00Z",clientId:"client-A",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};
const state=createSecureSessionState(path.join(root,"state"),60000);
const challenge=issueChallenge(state,anchor.sessionId,1100000,60000);
const signed=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:challenge.challenge,timestamp:"2026-09-13T19:30:00Z"});
const presented={sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:1};
const result=executeSessionContinuityDecision({anchor,durableState:state,presented,signedPresentation:signed,timestamp:"2026-09-13T19:30:00Z",nowMs:1100001,signingIdentity:signer,durableTrustStore:trust,outputRoot:path.join(root,"proof")});
if(result.decision!=="ALLOW") throw new Error("PROVENANCE_RECEIVER_PRODUCT_ALLOW_FAILED");
if(!result.provenanceCertificate) throw new Error("PROVENANCE_RECEIVER_CERTIFICATE_MISSING");
const receipt=verifySessionProvenanceReceipt({certificate:result.provenanceCertificate,durableTrustStore:createDurableTrustStore(trustRoot),bundleDir:path.join(root,"proof","bundle"),lineageDir:path.join(root,"proof","lineage"),policyDecision:result.policy,expectedSessionId:anchor.sessionId,expectedSubject:anchor.subject,expectedIssuer:anchor.issuer});
if(!receipt.verified) throw new Error("PROVENANCE_RECEIVER_VALIDATION_FAILED:"+receipt.reason);
console.log("PROVENANCE_RECEIVER_VALID=PASS");

const decisionTampered={...result.provenanceCertificate,decision:"REVOKE"};
const decisionCheck=verifySessionProvenanceReceipt({certificate:decisionTampered,durableTrustStore:createDurableTrustStore(trustRoot),bundleDir:path.join(root,"proof","bundle"),lineageDir:path.join(root,"proof","lineage"),policyDecision:result.policy,expectedSessionId:anchor.sessionId,expectedSubject:anchor.subject,expectedIssuer:anchor.issuer});
if(decisionCheck.verified) throw new Error("PROVENANCE_RECEIVER_DECISION_TAMPER_ACCEPTED");
console.log("PROVENANCE_RECEIVER_DECISION_TAMPER_REJECTED=PASS");

const policyTampered={...result.provenanceCertificate,policy_fingerprint_sha256:"f".repeat(64)};
const policyCheck=verifySessionProvenanceReceipt({certificate:policyTampered,durableTrustStore:createDurableTrustStore(trustRoot),bundleDir:path.join(root,"proof","bundle"),lineageDir:path.join(root,"proof","lineage"),policyDecision:result.policy,expectedSessionId:anchor.sessionId,expectedSubject:anchor.subject,expectedIssuer:anchor.issuer});
if(policyCheck.verified) throw new Error("PROVENANCE_RECEIVER_POLICY_TAMPER_ACCEPTED");
console.log("PROVENANCE_RECEIVER_POLICY_TAMPER_REJECTED=PASS");

fs.appendFileSync(path.join(root,"proof","bundle","evidence.json"),"X");
const evidenceCheck=verifySessionProvenanceReceipt({certificate:result.provenanceCertificate,durableTrustStore:createDurableTrustStore(trustRoot),bundleDir:path.join(root,"proof","bundle"),lineageDir:path.join(root,"proof","lineage"),policyDecision:result.policy,expectedSessionId:anchor.sessionId,expectedSubject:anchor.subject,expectedIssuer:anchor.issuer});
if(evidenceCheck.verified) throw new Error("PROVENANCE_RECEIVER_EVIDENCE_TAMPER_ACCEPTED");
console.log("PROVENANCE_RECEIVER_EVIDENCE_TAMPER_REJECTED=PASS");

console.log("SESSION_PROVENANCE_RECEIVER=PASS");
fs.rmSync(root,{recursive:true,force:true});