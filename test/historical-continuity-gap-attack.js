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

const root=fs.mkdtempSync(path.join(os.tmpdir(),"historical-continuity-gap-"));
const authority=provisionSigningAuthority(path.join(root,"authority"),{label:"historical-gap"});
const trust=createDurableTrustStore(authority.trustRoot);
const stateDir=path.join(root,"state");
const state=createSecureSessionState(stateDir,60000);
const key=createBindingKey();
const claims={sub:"gap-user",iss:"https://issuer.example",sid:"gap-session",auth_time:"2026-09-15T03:00:00.000Z",aud:"gap-client"};
const anchorBase=createOidcSessionAnchor({verifiedClaims:claims,clientId:"gap-client",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:key.publicKeySpkiBase64,publicKeyFingerprintSha256:key.publicKeyFingerprint};

async function accept(sequence,label){
  const now=Date.now();
  const ts=new Date(now).toISOString();
  const challenge=issueChallenge(state,anchor.sessionId,now,60000);
  const signed=createSignedPresentation(key,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:"device-A",sequence,challenge:challenge.challenge,timestamp:ts});
  return executeSessionContinuityDecision({anchor,durableState:state,presented:{sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:"device-A",sequence},signedPresentation:signed,timestamp:ts,nowMs:now,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(root,label)});
}

const p1=await accept(1,"proof-1");
const p3=await accept(3,"proof-3");
const c=p3.provenanceCertificate;
const v=verifySessionProvenanceReceipt({certificate:c,durableTrustStore:trust,bundleDir:path.join(root,"proof-3","bundle"),lineageDir:path.join(root,"proof-3","lineage"),policyDecision:p3.policy,expectedSessionId:c?.session_id,expectedSubject:c?.subject,expectedIssuer:c?.issuer});
console.log("=== HISTORICAL CONTINUITY GAP ATTACK ===");
console.log("P1_DECISION="+p1.decision+"|P1_SEQ="+p1.pipeline?.proof?.sequence);
console.log("P2=ABSENT");
console.log("P3_DECISION="+p3.decision+"|P3_SEQ="+p3.pipeline?.proof?.sequence);
console.log("P3_PROVENANCE="+(c?"PRESENT":"ABSENT"));
console.log("P3_PARENT_FIELD="+(c&&Object.prototype.hasOwnProperty.call(c,"previous_proof_hash")?"PRESENT":"ABSENT"));
console.log("P3_RECEIVER="+(v.verified?"ACCEPTED":"REJECTED"));
console.log("SEQUENCE_GAP=1->3");
console.log("HISTORICAL_CONTINUITY_PROVEN="+(!v.verified?"NO":"YES"));
console.log("ATTACK_RESULT="+(v.verified?"FAIL":"PASS"));
fs.rmSync(root,{recursive:true,force:true});
