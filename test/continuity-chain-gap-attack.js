import fs from "fs";
import path from "path";
import os from "os";
import { provisionSigningAuthority } from "../src/evidence/signing-authority.js";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../src/core/durable-secure-session-state.js";
import { createDurableTrustStore } from "../src/evidence/durable-trust-store.js";
import { createOidcSessionAnchor } from "../src/adapters/oidc-session-adapter.js";
import { executeTransactionalFinalProofPipeline } from "../src/core/transactional-final-proof-pipeline.js";
import { verifySessionProvenanceReceipt } from "../src/evidence/session-provenance-receiver.js";

const root=fs.mkdtempSync(path.join(os.tmpdir(),"continuity-gap-attack-"));
const authority=provisionSigningAuthority(path.join(root,"authority"),{label:"continuity-gap-attack"});
const trust=createDurableTrustStore(authority.trustRoot);
const claims={sub:"gap-user",iss:"https://issuer.example",sid:"gap-session",auth_time:"2026-09-15T03:00:00.000Z",aud:"gap-client"};
const dir=path.join(root,"session"); fs.mkdirSync(dir,{recursive:true});
const state=createSecureSessionState(path.join(dir,"state"),60000);
const key=createBindingKey();
const anchorBase=createOidcSessionAnchor({verifiedClaims:claims,clientId:"gap-client",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:key.publicKeySpkiBase64,publicKeyFingerprintSha256:key.publicKeyFingerprint};

async function prove(sequence,label){
  const now=Date.now(); const ts=new Date(now).toISOString(); const challenge=issueChallenge(state,anchor.sessionId,now,60000);
  const signed=createSignedPresentation(key,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:"device-A",sequence,challenge:challenge.challenge,timestamp:ts});
  return executeTransactionalFinalProofPipeline({anchor,durableState:state,presented:{sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:"device-A",sequence},signedPresentation:signed,timestamp:ts,nowMs:now,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(dir,label)});
}

const p1=await prove(1,"proof-1");
const p3=await prove(3,"proof-3");
const r3=verifySessionProvenanceReceipt({certificate:p3.certificate,durableTrustStore:trust,bundleDir:path.join(dir,"proof-3","bundle"),lineageDir:path.join(dir,"proof-3","lineage"),policyDecision:p3.policy,expectedSessionId:p3.certificate.session_id,expectedSubject:p3.certificate.subject,expectedIssuer:p3.certificate.issuer});
console.log("=== CONTINUITY CHAIN GAP ATTACK ===");
console.log("P1="+p1.decision+"|SEQ="+p1.certificate.sequence);
console.log("P2=ABSENT");
console.log("P3="+p3.decision+"|SEQ="+p3.certificate.sequence);
console.log("P3_INDEPENDENT_RECEIVER="+(r3.verified?"ACCEPTED":"REJECTED"));
console.log("P3_HAS_PARENT_LINK="+(Object.prototype.hasOwnProperty.call(p3.certificate,"previous_proof_hash")?"YES":"NO"));
console.log("P3_LINEAGE_LOCAL_ONLY="+(p3.certificate.sequence===3?"YES":"NO"));
console.log("HISTORICAL_CONTINUITY_GAP="+(r3.verified?"CONFIRMED":"NOT_CONFIRMED"));
console.log("ATTACK_RESULT="+(r3.verified?"FAIL":"PASS"));
fs.rmSync(root,{recursive:true,force:true});
