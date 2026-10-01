import fs from "fs";
import path from "path";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge, verifySecureSessionState } from "../src/core/durable-secure-session-state.js";
import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";

const root="E:\\\\SESSION-CONTINUITY\\\\test\\\\fixtures\\\\diagnostic-challenge-branches";
fs.rmSync(root,{recursive:true,force:true});

const sessionKey=createBindingKey();
const signer=createSigningIdentity();
const trustRoot=path.join(root,"trust");
const trust=createDurableTrustStore(trustRoot);
durableRegisterTrustAnchor(trust,signer.publicKeySpkiBase64,{version:1,created_at:"2026-09-20T10:00:00Z",label:"challenge-branch-signer"});

const anchorBase=createSessionAnchor({sessionId:"sess-challenge-001",subject:"user-001",issuer:"issuer-A",authTime:"2026-09-20T09:00:00Z",clientId:"client-A",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};

function buildSigned(challengeValue, sessionId, subject, sequence) {
  return createSignedPresentation(sessionKey, {
    session_id: sessionId,
    subject: subject,
    issuer: anchor.issuer,
    client_id: anchor.clientId,
    device_id: anchor.deviceId,
    sequence: sequence,
    challenge: challengeValue,
    timestamp: "2026-09-20T10:00:00Z"
  });
}

function presented(sequence) {
  return {sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:sequence};
}

// ===== CHALLENGE_UNKNOWN =====
{
  const state=createSecureSessionState(path.join(root,"unknown-state"),60000);
  const signed=buildSigned("nonexistent-challenge-value", anchor.sessionId, anchor.subject, 1);
  const result=executeSessionContinuityDecision({
    anchor, durableState: state,
    presented: presented(1),
    signedPresentation: signed,
    timestamp:"2026-09-20T10:00:00Z", nowMs:1000000,
    signingIdentity: signer, durableTrustStore: trust,
    outputRoot: path.join(root,"unknown-proof")
  });
  if(result.decision!=="REAUTH") throw new Error("CHALLENGE_UNKNOWN_DECISION_FAILED:"+result.decision);
  if(result.diagnostic?.reason_code!=="CHALLENGE_UNKNOWN") throw new Error("CHALLENGE_UNKNOWN_REASON_CODE_FAILED:"+result.diagnostic?.reason_code);
  if(result.diagnostic?.failure_stage!=="CHALLENGE") throw new Error("CHALLENGE_UNKNOWN_STAGE_FAILED:"+result.diagnostic?.failure_stage);
  if(result.diagnostic?.failure_location!=="challenge.lookup") throw new Error("CHALLENGE_UNKNOWN_LOCATION_FAILED:"+result.diagnostic?.failure_location);
  console.log("CHALLENGE_UNKNOWN=PASS");
}

// ===== CHALLENGE_SESSION_MISMATCH =====
{
  const state=createSecureSessionState(path.join(root,"mismatch-state"),60000);
  const challenge=issueChallenge(state, "sess-other-001", 2000000, 60000);
  const signed=buildSigned(challenge.challenge, anchor.sessionId, anchor.subject, 1);
  const result=executeSessionContinuityDecision({
    anchor, durableState: state,
    presented: presented(1),
    signedPresentation: signed,
    timestamp:"2026-09-20T10:00:00Z", nowMs:2000001,
    signingIdentity: signer, durableTrustStore: trust,
    outputRoot: path.join(root,"mismatch-proof")
  });
  if(result.decision!=="REAUTH") throw new Error("CHALLENGE_SESSION_MISMATCH_DECISION_FAILED:"+result.decision);
  if(result.diagnostic?.reason_code!=="CHALLENGE_SESSION_MISMATCH") throw new Error("CHALLENGE_SESSION_MISMATCH_REASON_CODE_FAILED:"+result.diagnostic?.reason_code);
  if(result.diagnostic?.failure_stage!=="CHALLENGE") throw new Error("CHALLENGE_SESSION_MISMATCH_STAGE_FAILED:"+result.diagnostic?.failure_stage);
  if(result.diagnostic?.failure_location!=="challenge.session_binding") throw new Error("CHALLENGE_SESSION_MISMATCH_LOCATION_FAILED:"+result.diagnostic?.failure_location);
  console.log("CHALLENGE_SESSION_MISMATCH=PASS");
}

// ===== CHALLENGE_EXPIRED =====
{
  const state=createSecureSessionState(path.join(root,"expired-state"),60000);
  const challenge=issueChallenge(state, anchor.sessionId, 3000000, 60000);
  const signed=buildSigned(challenge.challenge, anchor.sessionId, anchor.subject, 1);
  const result=executeSessionContinuityDecision({
    anchor, durableState: state,
    presented: presented(1),
    signedPresentation: signed,
    timestamp:"2026-09-20T10:00:00Z", nowMs:3060001,
    signingIdentity: signer, durableTrustStore: trust,
    outputRoot: path.join(root,"expired-proof")
  });
  if(result.decision!=="REAUTH") throw new Error("CHALLENGE_EXPIRED_DECISION_FAILED:"+result.decision);
  if(result.diagnostic?.reason_code!=="CHALLENGE_EXPIRED") throw new Error("CHALLENGE_EXPIRED_REASON_CODE_FAILED:"+result.diagnostic?.reason_code);
  if(result.diagnostic?.failure_stage!=="CHALLENGE") throw new Error("CHALLENGE_EXPIRED_STAGE_FAILED:"+result.diagnostic?.failure_stage);
  if(result.diagnostic?.failure_location!=="challenge.expiry") throw new Error("CHALLENGE_EXPIRED_LOCATION_FAILED:"+result.diagnostic?.failure_location);
  console.log("CHALLENGE_EXPIRED=PASS");
}

// ===== CHALLENGE_ALREADY_CONSUMED =====
// Sequence must advance (1 -> 2) so that the sequence check passes and the
// consumed-challenge check is reached before any sequence failure.
{
  const state=createSecureSessionState(path.join(root,"consumed-state"),60000);
  const challenge=issueChallenge(state, anchor.sessionId, 4000000, 60000);
  const signed1=buildSigned(challenge.challenge, anchor.sessionId, anchor.subject, 1);
  const first=executeSessionContinuityDecision({
    anchor, durableState: state,
    presented: presented(1),
    signedPresentation: signed1,
    timestamp:"2026-09-20T10:00:00Z", nowMs:4000001,
    signingIdentity: signer, durableTrustStore: trust,
    outputRoot: path.join(root,"consumed-proof-1")
  });
  if(first.decision!=="ALLOW") throw new Error("CHALLENGE_ALREADY_CONSUMED_FIRST_NOT_ALLOW:"+first.decision);
  const signed2=buildSigned(challenge.challenge, anchor.sessionId, anchor.subject, 2);
  const second=executeSessionContinuityDecision({
    anchor, durableState: state,
    presented: presented(2),
    signedPresentation: signed2,
    timestamp:"2026-09-20T10:00:01Z", nowMs:4000002,
    signingIdentity: signer, durableTrustStore: trust,
    outputRoot: path.join(root,"consumed-proof-2")
  });
  if(second.decision!=="REAUTH") throw new Error("CHALLENGE_ALREADY_CONSUMED_DECISION_FAILED:"+second.decision);
  if(second.diagnostic?.reason_code!=="CHALLENGE_ALREADY_CONSUMED") throw new Error("CHALLENGE_ALREADY_CONSUMED_REASON_CODE_FAILED:"+second.diagnostic?.reason_code);
  if(second.diagnostic?.failure_stage!=="CHALLENGE") throw new Error("CHALLENGE_ALREADY_CONSUMED_STAGE_FAILED:"+second.diagnostic?.failure_stage);
  if(second.diagnostic?.failure_location!=="challenge.consumed") throw new Error("CHALLENGE_ALREADY_CONSUMED_LOCATION_FAILED:"+second.diagnostic?.failure_location);
  console.log("CHALLENGE_ALREADY_CONSUMED=PASS");
}

console.log("DIAGNOSTIC_CHALLENGE_BRANCHES=PASS");
fs.rmSync(root,{recursive:true,force:true});