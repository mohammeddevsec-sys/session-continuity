import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { provisionSigningAuthority } from "../../src/evidence/signing-authority.js";
import { createBindingKey, createSignedPresentation } from "../../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../../src/core/durable-secure-session-state.js";
import { createDurableTrustStore } from "../../src/evidence/durable-trust-store.js";
import { createOidcSessionAnchor } from "../../src/adapters/oidc-session-adapter.js";
import { executeSessionContinuityDecision } from "../../src/product/session-continuity-decision.js";

const root=fs.mkdtempSync(path.join(os.tmpdir(),"sc-witness-integration-"));
const authority=provisionSigningAuthority(path.join(root,"authority"),{label:"integration"});
const trust=createDurableTrustStore(authority.trustRoot);
const claims={sub:"integration-user",iss:"https://issuer.example",sid:"integration-session",auth_time:"2026-09-15T03:00:00.000Z",aud:"integration-client"};
const key=createBindingKey();
const anchorBase=createOidcSessionAnchor({verifiedClaims:claims,clientId:"integration-client",deviceId:"device-A"});
const anchor={...anchorBase,publicKeySpkiBase64:key.publicKeySpkiBase64,publicKeyFingerprintSha256:key.publicKeyFingerprint};
const baseDir=path.join(root,"base"); fs.mkdirSync(baseDir,{recursive:true});
const baseState=createSecureSessionState(baseDir,60000);
const hash=x=>crypto.createHash("sha256").update(JSON.stringify(x)).digest("hex");
let witnessHead=null;
function witnessSubmit(rootId,sequence,proofHash){
  if(!witnessHead){if(sequence!==1)return "FIRST_SEQUENCE_REQUIRED"; witnessHead={rootId,sequence,proofHash}; return "REGISTERED";}
  if(rootId!==witnessHead.rootId)return "ROOT_MISMATCH";
  if(sequence<witnessHead.sequence)return "ROLLBACK";
  if(sequence===witnessHead.sequence)return proofHash===witnessHead.proofHash?"IDEMPOTENT_REPLAY":"EQUIVOCATION_FORK";
  if(sequence!==witnessHead.sequence+1)return "SEQUENCE_GAP";
  witnessHead={rootId,sequence,proofHash}; return "ADVANCED";
}
async function accept(state,outDir,sequence){
  const now=Date.now(); const ts=new Date(now).toISOString(); const ch=issueChallenge(state,anchor.sessionId,now,60000);
  const signed=createSignedPresentation(key,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:"device-A",sequence,challenge:ch.challenge,timestamp:ts});
  return executeSessionContinuityDecision({anchor,durableState:state,presented:{sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:"device-A",sequence},signedPresentation:signed,timestamp:ts,nowMs:now,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:outDir});
}
const p1=await accept(baseState,path.join(root,"p1"),1);
const rootId=hash(anchor);
const p1Witness=witnessSubmit(rootId,1,hash(p1.provenanceCertificate));
fs.cpSync(baseDir,path.join(root,"branchA"),{recursive:true});
fs.cpSync(baseDir,path.join(root,"branchB"),{recursive:true});
const aState=createSecureSessionState(path.join(root,"branchA"),60000);
const bState=createSecureSessionState(path.join(root,"branchB"),60000);
const a=await accept(aState,path.join(root,"p2A"),2);
const b=await accept(bState,path.join(root,"p2B"),2);
const aHash=hash(a.provenanceCertificate);
const bHash=hash(b.provenanceCertificate);
const aWitness=witnessSubmit(rootId,2,aHash);
const bWitness=witnessSubmit(rootId,2,bHash);
console.log("=== SESSION CONTINUITY :: WITNESS INTEGRATION ===");
console.log("P1_PRODUCT="+p1.decision);
console.log("P1_WITNESS="+p1Witness);
console.log("BRANCH_A_PRODUCT="+a.decision+"|SEQ="+a.provenanceCertificate?.sequence);
console.log("BRANCH_B_PRODUCT="+b.decision+"|SEQ="+b.provenanceCertificate?.sequence);
console.log("CERT_A_HASH="+aHash);
console.log("CERT_B_HASH="+bHash);
console.log("CERTS_DIFFER="+(aHash!==bHash?"YES":"NO"));
console.log("BRANCH_A_WITNESS="+aWitness);
console.log("BRANCH_B_WITNESS="+bWitness);
console.log("PRODUCT_BOTH_ALLOW="+(a.decision==="ALLOW"&&b.decision==="ALLOW"?"YES":"NO"));
console.log("EXTERNAL_EQUIVOCATION_BLOCKED="+(bWitness==="EQUIVOCATION_FORK"?"PASS":"FAIL"));
console.log("INTEGRATION_RESULT="+(p1Witness==="REGISTERED"&&aWitness==="ADVANCED"&&bWitness==="EQUIVOCATION_FORK"?"PASS":"FAIL"));
fs.rmSync(root,{recursive:true,force:true});
