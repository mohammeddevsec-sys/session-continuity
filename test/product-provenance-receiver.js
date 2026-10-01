import fs from "fs";
import path from "path";
import { createSessionAnchor } from "../src/core/session-anchor.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../src/core/durable-secure-session-state.js";
import { createSigningIdentity } from "../src/evidence/proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";
import { verifySessionProvenanceCertificate } from "../src/evidence/session-provenance-certificate.js";

const root="E:\\\\SESSION-CONTINUITY\\\\test\\\\fixtures\\\\product-provenance-receiver";
fs.rmSync(root,{recursive:true,force:true});
const sessionKey=createBindingKey();
const signer=createSigningIdentity();
const trustRoot=path.join(root,"trust");
const trust=createDurableTrustStore(trustRoot);
durableRegisterTrustAnchor(trust,signer.publicKeySpkiBase64,{version:1,created_at:"2026-09-13T19:00:00Z",label:"product-provenance-signer"});
const anchorBase=createSessionAnchor({sessionId:"sess-provenance-001",subject:"user-001",issuer:"issuer-A",authTime:"2026-09-13T09:00:00Z",clientId:"client-A",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};
const state=createSecureSessionState(path.join(root,"state"),60000);
const challenge=issueChallenge(state,anchor.sessionId,1000000,60000);
const signed=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:challenge.challenge,timestamp:"2026-09-13T19:00:00Z"});
const presented={sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:1};
const result=executeSessionContinuityDecision({anchor,durableState:state,presented,signedPresentation:signed,timestamp:"2026-09-13T19:00:00Z",nowMs:1000001,signingIdentity:signer,durableTrustStore:trust,outputRoot:path.join(root,"proof")});
if(result.decision!=="ALLOW") throw new Error("PRODUCT_PROVENANCE_ALLOW_FAILED");
if(!result.provenanceCertificate) throw new Error("PROVENANCE_CERTIFICATE_MISSING");
const valid=verifySessionProvenanceCertificate(result.provenanceCertificate);
if(!valid.verified) throw new Error("PROVENANCE_CERTIFICATE_PRODUCT_VERIFY_FAILED");
console.log("PRODUCT_PROVENANCE_CERTIFICATE=PASS");
console.log("PRODUCT_PROVENANCE_CERTIFICATE_VERIFY=PASS");

const decisionTampered={...result.provenanceCertificate,decision:"REVOKE"};
if(verifySessionProvenanceCertificate(decisionTampered).verified) throw new Error("PRODUCT_PROVENANCE_DECISION_TAMPER_ACCEPTED");
console.log("PRODUCT_PROVENANCE_DECISION_TAMPER_REJECTED=PASS");

const policyTampered={...result.provenanceCertificate,policy_fingerprint_sha256:"f".repeat(64)};
if(verifySessionProvenanceCertificate(policyTampered).verified) throw new Error("PRODUCT_PROVENANCE_POLICY_TAMPER_ACCEPTED");
console.log("PRODUCT_PROVENANCE_POLICY_TAMPER_REJECTED=PASS");

const bundleTampered={...result.provenanceCertificate,bundle_root_sha256:"f".repeat(64)};
if(verifySessionProvenanceCertificate(bundleTampered).verified) throw new Error("PRODUCT_PROVENANCE_BUNDLE_TAMPER_ACCEPTED");
console.log("PRODUCT_PROVENANCE_BUNDLE_TAMPER_REJECTED=PASS");

console.log("PRODUCT_PROVENANCE_CHAIN=PASS");
fs.rmSync(root,{recursive:true,force:true});