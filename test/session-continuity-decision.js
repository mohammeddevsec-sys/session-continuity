import fs from "fs";
import path from "path";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge, verifySecureSessionState } from "../src/core/durable-secure-session-state.js";
import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";

const root="E:\\\\SESSION-CONTINUITY\\\\test\\\\fixtures\\\\product-decision";
fs.rmSync(root,{recursive:true,force:true});
const sessionKey=createBindingKey();
const signer=createSigningIdentity();
const trustRoot=path.join(root,"trust");
const trust=createDurableTrustStore(trustRoot);
durableRegisterTrustAnchor(trust,signer.publicKeySpkiBase64,{version:1,created_at:"2026-09-13T17:00:00Z",label:"product-signer"});
const anchorBase=createSessionAnchor({sessionId:"sess-product-001",subject:"user-001",issuer:"issuer-A",authTime:"2026-09-13T09:00:00Z",clientId:"client-A",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};
const state=createSecureSessionState(path.join(root,"state"),60000);
const challenge=issueChallenge(state,anchor.sessionId,800000,60000);
const signed=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:challenge.challenge,timestamp:"2026-09-13T17:00:00Z"});
const presented={sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:1};
const input={anchor,durableState:state,presented,signedPresentation:signed,timestamp:"2026-09-13T17:00:00Z",nowMs:800001,signingIdentity:signer,durableTrustStore:trust,outputRoot:path.join(root,"proof")};

const allowed=executeSessionContinuityDecision(input);
if(allowed.decision!=="ALLOW") throw new Error("PRODUCT_ALLOW_FAILED");
if(!allowed.pipeline?.committed) throw new Error("PRODUCT_ALLOW_NOT_COMMITTED");
console.log("PRODUCT_ALLOW=PASS");

const replay=executeSessionContinuityDecision(input);
if(replay.decision!=="REAUTH") throw new Error("PRODUCT_REAUTH_FAILED");
if(replay.reason!=="REPLAY_DETECTED") throw new Error("PRODUCT_REAUTH_REASON_FAILED");
console.log("PRODUCT_REAUTH_REPLAY=PASS");

const revokeState=createSecureSessionState(path.join(root,"revoke-state"),60000);
const revokeChallenge=issueChallenge(revokeState,anchor.sessionId,810000,60000);
const revokeSigned=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:revokeChallenge.challenge,timestamp:"2026-09-13T17:01:00Z"});
const revokePresented={...presented,sequence:1};
const untrusted=createDurableTrustStore(path.join(root,"empty-trust"));
const revoked=executeSessionContinuityDecision({anchor,durableState:revokeState,presented:revokePresented,signedPresentation:revokeSigned,timestamp:"2026-09-13T17:01:00Z",nowMs:810001,signingIdentity:signer,durableTrustStore:untrusted,outputRoot:path.join(root,"revoked-proof")});
if(revoked.decision!=="REVOKE") throw new Error("PRODUCT_REVOKE_FAILED");
if(revoked.reason!=="PROOF_INTEGRITY_OR_TRUST_FAILURE") throw new Error("PRODUCT_REVOKE_REASON_FAILED");
const revokeStateCheck=verifySecureSessionState(revokeState);
if(revokeStateCheck.journal_height!==1) throw new Error("PRODUCT_REVOKE_MUTATED_STATE");
if(revokeState.sessions.get(anchor.sessionId)!==undefined) throw new Error("PRODUCT_REVOKE_COMMITTED_STATE");
if(revokeState.challenges.get(revokeChallenge.challenge)?.consumed!==false) throw new Error("PRODUCT_REVOKE_CONSUMED_CHALLENGE");
console.log("PRODUCT_REVOKE_TRUST_FAILURE=PASS");
console.log("PRODUCT_REVOKE_NO_PRECOMMIT_MUTATION=PASS");

const recovered=executeSessionContinuityDecision({anchor,durableState:revokeState,presented:revokePresented,signedPresentation:revokeSigned,timestamp:"2026-09-13T17:01:00Z",nowMs:810001,signingIdentity:signer,durableTrustStore:trust,outputRoot:path.join(root,"recovered-proof")});
if(recovered.decision!=="ALLOW") throw new Error("PRODUCT_RECOVERY_ALLOW_FAILED");
console.log("PRODUCT_RECOVERY_AFTER_REVOKE=PASS");
console.log("SESSION_CONTINUITY_PRODUCT_BOUNDARY=PASS");
fs.rmSync(root,{recursive:true,force:true});