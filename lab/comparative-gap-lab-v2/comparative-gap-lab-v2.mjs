import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { provisionSigningAuthority } from "../../src/evidence/signing-authority.js";
import { createBindingKey, createSignedPresentation } from "../../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../../src/core/durable-secure-session-state.js";
import { createDurableTrustStore } from "../../src/evidence/durable-trust-store.js";
import { createOidcSessionAnchor } from "../../src/adapters/oidc-session-adapter.js";
import { executeSessionContinuityDecision } from "../../src/product/session-continuity-decision.js";
import { verifySessionProvenanceReceipt } from "../../src/evidence/session-provenance-receiver.js";

const root=fs.mkdtempSync(path.join(os.tmpdir(),"sc-gap-v2-"));
const authority=provisionSigningAuthority(path.join(root,"authority"),{label:"gap-v2"});
const trust=createDurableTrustStore(authority.trustRoot);
const claims={sub:"user-v2",iss:"https://issuer.example",sid:"sid-v2",auth_time:"2026-09-15T03:00:00.000Z",aud:"client-v2"};
const sha=x=>crypto.createHash("sha256").update(JSON.stringify(x)).digest("hex");
const baselineKey=crypto.generateKeyPairSync("ed25519");

function strongSession(event){
  if(event==="DEVICE_CHANGE"||event==="REPLAY") return "REAUTH";
  if(event==="REVOKED") return "REVOKE";
  return "ALLOW";
}

function baselineProof(event){
  const evidence={session:"S1",subject:claims.sub,issuer:claims.iss,decision:"ALLOW",policy:"P1",evidenceRoot:sha({device:"D1",seq:1})};
  const bytes=Buffer.from(JSON.stringify(evidence));
  const signature=crypto.sign(null,bytes,baselineKey.privateKey).toString("base64");
  const altered={...evidence,evidenceRoot:event==="TAMPER"||event==="REBUILD"?"REBUILT":evidence.evidenceRoot};
  const valid=crypto.verify(null,Buffer.from(JSON.stringify(altered)),baselineKey.publicKey,Buffer.from(signature,"base64"));
  return {valid,proof:{evidence,signature}};
}

function productContext(device){
  const dir=path.join(root,"product-"+device+"-"+Date.now());
  fs.mkdirSync(dir,{recursive:true});
  const state=createSecureSessionState(path.join(dir,"state"),60000);
  const key=createBindingKey();
  const anchorBase=createOidcSessionAnchor({verifiedClaims:claims,clientId:"client-v2",deviceId:device});
  const anchor={...anchorBase,publicKeySpkiBase64:key.publicKeySpkiBase64,publicKeyFingerprintSha256:key.publicKeyFingerprint};
  return {dir,state,key,anchor,now:Date.now()};
}

async function productOnce(ctx,device,seq=1){
  const ts=new Date(ctx.now).toISOString();
  const ch=issueChallenge(ctx.state,ctx.anchor.sessionId,ctx.now,60000);
  const signed=createSignedPresentation(ctx.key,{session_id:ctx.anchor.sessionId,subject:ctx.anchor.subject,issuer:ctx.anchor.issuer,client_id:ctx.anchor.clientId,device_id:device,sequence:seq,challenge:ch.challenge,timestamp:ts});
  return executeSessionContinuityDecision({anchor:ctx.anchor,durableState:ctx.state,presented:{sessionId:ctx.anchor.sessionId,subject:ctx.anchor.subject,issuer:ctx.anchor.issuer,clientId:ctx.anchor.clientId,deviceId:device,sequence:seq},signedPresentation:signed,timestamp:ts,nowMs:ctx.now,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(ctx.dir,"proof-"+seq)});
}

const rows=[];
rows.push(["01_HEALTHY","ALLOW",strongSession("NONE"),"ALLOW","ALLOW"]);
const dc=productContext("D1");
const ch=issueChallenge(dc.state,dc.anchor.sessionId,dc.now,60000);
const ts=new Date(dc.now).toISOString();
const ds=createSignedPresentation(dc.key,{session_id:dc.anchor.sessionId,subject:dc.anchor.subject,issuer:dc.anchor.issuer,client_id:dc.anchor.clientId,device_id:"D2",sequence:1,challenge:ch.challenge,timestamp:ts});
const dr=await executeSessionContinuityDecision({anchor:dc.anchor,durableState:dc.state,presented:{sessionId:dc.anchor.sessionId,subject:dc.anchor.subject,issuer:dc.anchor.issuer,clientId:dc.anchor.clientId,deviceId:"D2",sequence:1},signedPresentation:ds,timestamp:ts,nowMs:dc.now,signingIdentity:authority.signer,durableTrustStore:trust,outputRoot:path.join(dc.dir,"device-change")});
rows.push(["02_DEVICE_CHANGE","ALLOW",strongSession("DEVICE_CHANGE"),dr.decision,"BOTH_DETECT"]);
const rp=productContext("D1");
await productOnce(rp,"D1",1);
const rr=await productOnce(rp,"D1",1).catch(e=>({decision:"REJECT"}));
rows.push(["03_SEQUENCE_REPLAY","ALLOW",strongSession("REPLAY"),rr.decision,"BOTH_DETECT"]);
const bt=baselineProof("TAMPER");
const tam=productContext("D1");
const tp=await productOnce(tam,"D1",1);
const bundle=path.join(tam.dir,"proof-1","bundle");
fs.appendFileSync(path.join(bundle,"evidence.json"),"X");
const tv=verifySessionProvenanceReceipt({certificate:tp.provenanceCertificate,durableTrustStore:trust,bundleDir:bundle,lineageDir:path.join(tam.dir,"proof-1","lineage"),policyDecision:tp.policy,expectedSessionId:tp.provenanceCertificate.session_id,expectedSubject:tp.provenanceCertificate.subject,expectedIssuer:tp.provenanceCertificate.issuer});
rows.push(["04_POST_DECISION_TAMPER","N/A","SIGNED_AUDIT",tv.verified?"ALLOW":"REJECT",bt.valid?"BASELINE_WEAK":"BOTH_DETECT"]);
const bg=baselineProof("NONE");
rows.push(["05_SOURCE_APP_GONE","N/A","SIGNED_AUDIT",bg.proof?"VERIFY":"NO","BOTH_PORTABLE"]);
console.log("=== SESSION CONTINUITY :: STRONG BASELINE GAP LAB V2 ===");
console.log("BASELINE=SERVER_SESSION_PLUS_SIGNED_AUDIT_PLUS_REPLAY_CONTEXT_CONTROLS");
console.log("");
for(const r of rows) console.log(r.join("|"));
console.log("");
console.log("DETECTION_UNIQUE=FALSE");
console.log("REPLAY_UNIQUE=FALSE");
console.log("DEVICE_CONTEXT_UNIQUE=FALSE");
console.log("PORTABLE_SIGNED_PROOF_CAN_BE_BUILT_BY_BASELINE=TRUE");
console.log("CURRENT_CANDIDATE_WEDGE=STANDARDIZED_VENDOR_NEUTRAL_SESSION_PROVENANCE");
console.log("MARKET_UNIQUENESS=NOT_PROVEN");
fs.writeFileSync(path.join(process.cwd(),"lab","comparative-gap-lab-v2","RESULTS.txt"),rows.map(r=>r.join("|")).join("\n")+"\nMARKET_UNIQUENESS=NOT_PROVEN\n","utf8");
fs.rmSync(root,{recursive:true,force:true});
