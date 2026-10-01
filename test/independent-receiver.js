import fs from "fs";
import path from "path";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../src/core/durable-secure-session-state.js";
import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";
import { verifyIndependentSessionProof } from "../src/evidence/independent-receiver.js";

const root="E:\\\\SESSION-CONTINUITY\\\\test\\\\fixtures\\\\independent-receiver";
fs.rmSync(root,{recursive:true,force:true});

const sessionKey=createBindingKey();
const signer=createSigningIdentity();
const trustRoot=path.join(root,"trust");
const trust=createDurableTrustStore(trustRoot);
durableRegisterTrustAnchor(trust,signer.publicKeySpkiBase64,{version:1,created_at:"2026-09-13T18:00:00Z",label:"receiver-signer"});

const anchorBase=createSessionAnchor({sessionId:"sess-receiver-001",subject:"user-001",issuer:"issuer-A",authTime:"2026-09-13T09:00:00Z",clientId:"client-A",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};
const state=createSecureSessionState(path.join(root,"state"),60000);
const challenge=issueChallenge(state,anchor.sessionId,900000,60000);
const signed=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:challenge.challenge,timestamp:"2026-09-13T18:00:00Z"});
const presented={sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:1};

const result=executeSessionContinuityDecision({anchor,durableState:state,presented,signedPresentation:signed,timestamp:"2026-09-13T18:00:00Z",nowMs:900001,signingIdentity:signer,durableTrustStore:trust,outputRoot:path.join(root,"proof")});
if(result.decision!=="ALLOW") throw new Error("RECEIVER_FIXTURE_ALLOW_FAILED");

const base={certificate:result.pipeline.certificate,durableTrustStore:createDurableTrustStore(trustRoot),bundleDir:path.join(root,"proof","bundle"),lineageDir:path.join(root,"proof","lineage"),policyDecision:result.policy};
const valid=verifyIndependentSessionProof(base);
if(!valid.verified) throw new Error("INDEPENDENT_RECEIVER_VALID_PROOF_FAILED");
console.log("RECEIVER_VALID_PROOF=PASS");

const certificateTampered={...base,certificate:{...base.certificate,merkle_root_sha256:"f".repeat(64)}};
const certificateResult=verifyIndependentSessionProof(certificateTampered);
if(certificateResult.verified) throw new Error("RECEIVER_CERTIFICATE_TAMPER_ACCEPTED");
console.log("RECEIVER_CERTIFICATE_TAMPER_REJECTED=PASS");

fs.appendFileSync(path.join(root,"proof","bundle","evidence.json"),"X");
const evidenceResult=verifyIndependentSessionProof(base);
if(evidenceResult.verified) throw new Error("RECEIVER_EVIDENCE_TAMPER_ACCEPTED");
console.log("RECEIVER_EVIDENCE_TAMPER_REJECTED=PASS");

const policyTampered={...base,policyDecision:{...base.policyDecision,decision:"REVOKE"}};
const policyResult=verifyIndependentSessionProof(policyTampered);
if(policyResult.verified) throw new Error("RECEIVER_POLICY_TAMPER_ACCEPTED");
console.log("RECEIVER_POLICY_TAMPER_REJECTED=PASS");

fs.rmSync(root,{recursive:true,force:true});
console.log("INDEPENDENT_RECEIVER=PASS");