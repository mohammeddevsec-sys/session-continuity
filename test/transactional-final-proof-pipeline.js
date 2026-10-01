import fs from "fs";
import path from "path";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge, verifySecureSessionState } from "../src/core/durable-secure-session-state.js";
import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { executeTransactionalFinalProofPipeline } from "../src/core/transactional-final-proof-pipeline.js";
import { verifyDurableTrustedProof } from "../src/evidence/durable-trusted-proof-verifier.js";

const root="E:\\\\SESSION-CONTINUITY\\\\test\\\\fixtures\\\\transactional-final-proof";
fs.rmSync(root,{recursive:true,force:true});

const sessionKey=createBindingKey();
const signingIdentity=createSigningIdentity();
const trustRoot=path.join(root,"trust");
const trustStore=createDurableTrustStore(trustRoot);
durableRegisterTrustAnchor(trustStore,signingIdentity.publicKeySpkiBase64,{version:1,created_at:"2026-09-13T16:00:00Z",label:"transactional-proof-signer"});

const anchorBase=createSessionAnchor({sessionId:"sess-transactional-001",subject:"user-001",issuer:"issuer-A",authTime:"2026-09-13T09:00:00Z",clientId:"client-A",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};
const state=createSecureSessionState(path.join(root,"state"),60000);
const challenge=issueChallenge(state,anchor.sessionId,700000,60000);

const signedPresentation=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:challenge.challenge,timestamp:"2026-09-13T16:00:00Z"});
const presented={sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:1};

const baseline=verifySecureSessionState(state);
if(baseline.journal_height!==1) throw new Error("INITIAL_JOURNAL_HEIGHT_FAILED");
if(state.challenges.get(challenge.challenge)?.consumed!==false) throw new Error("INITIAL_CHALLENGE_STATE_FAILED");

const badTrustStore=createDurableTrustStore(path.join(root,"bad-trust"));
let failed=false;
try { executeTransactionalFinalProofPipeline({anchor,durableState:state,presented,signedPresentation,timestamp:"2026-09-13T16:00:00Z",nowMs:700001,signingIdentity,durableTrustStore:badTrustStore,outputRoot:path.join(root,"failed-proof")}); } catch(error) { failed=true; console.log("PRECOMMIT_FAILURE_TRIGGERED=PASS|"+error.message); }
if(!failed) throw new Error("PRECOMMIT_FAILURE_NOT_TRIGGERED");
const afterFailure=verifySecureSessionState(state);
if(afterFailure.journal_height!==1) throw new Error("PRECOMMIT_STATE_CHANGED");
if(state.sessions.get(anchor.sessionId)!==undefined) throw new Error("PRECOMMIT_SEQUENCE_COMMITTED");
if(state.challenges.get(challenge.challenge)?.consumed!==false) throw new Error("PRECOMMIT_CHALLENGE_CONSUMED");
console.log("PRECOMMIT_STATE_UNCHANGED=PASS");
console.log("PRECOMMIT_CHALLENGE_PRESERVED=PASS");

const result=executeTransactionalFinalProofPipeline({anchor,durableState:state,presented,signedPresentation,timestamp:"2026-09-13T16:00:00Z",nowMs:700001,signingIdentity,durableTrustStore:trustStore,outputRoot:path.join(root,"proof")});
if(result.decision!=="CONTINUOUS") throw new Error("TRANSACTIONAL_DECISION_FAILED");
if(result.committed!==true) throw new Error("TRANSACTIONAL_COMMIT_MISSING");
if(!result.verification?.offline?.verified) throw new Error("TRANSACTIONAL_OFFLINE_VERIFY_FAILED");
if(!result.verification?.trusted?.verified) throw new Error("TRANSACTIONAL_TRUST_FAILED");
const afterSuccess=verifySecureSessionState(state);
if(state.sessions.get(anchor.sessionId)!==1) throw new Error("TRANSACTIONAL_SEQUENCE_NOT_COMMITTED");
if(state.challenges.get(challenge.challenge)?.consumed!==true) throw new Error("TRANSACTIONAL_CHALLENGE_NOT_CONSUMED");
if(afterSuccess.journal_height!==2) throw new Error("TRANSACTIONAL_JOURNAL_HEIGHT_INVALID");
const trustedAfterRestart=verifyDurableTrustedProof(result.certificate,createDurableTrustStore(trustRoot));
if(!trustedAfterRestart.verified) throw new Error("TRANSACTIONAL_TRUST_RESTART_FAILED");
console.log("TRANSACTIONAL_SUCCESS=PASS");
console.log("TRANSACTIONAL_COMMIT_LAST=PASS");
console.log("TRANSACTIONAL_TRUST_RESTART=PASS");
console.log("TRANSACTIONAL_FINAL_PROOF_PIPELINE=PASS");
fs.rmSync(root,{recursive:true,force:true});