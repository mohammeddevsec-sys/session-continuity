#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { createBindingKey, createSignedPresentation } from "../src/core/proof-of-possession.js";
import { createSecureSessionState, issueChallenge } from "../src/core/durable-secure-session-state.js";
import { createDurableTrustStore, durableRevokeTrustAnchor } from "../src/evidence/durable-trust-store.js";
import { provisionSigningAuthority, loadSigningAuthority, verifySigningAuthority } from "../src/evidence/signing-authority.js";
import { createOidcSessionAnchor, validateVerifiedOidcClaims } from "../src/adapters/oidc-session-adapter.js";
import { executeSessionContinuityDecision } from "../src/product/session-continuity-decision.js";
import { verifySessionProvenanceReceipt } from "../src/evidence/session-provenance-receiver.js";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PACKAGE_JSON_PATH = path.resolve(__dirname, "..", "package.json");
const PACKAGE_JSON = JSON.parse(fs.readFileSync(PACKAGE_JSON_PATH, "utf8"));
const VERSION = PACKAGE_JSON.version;

function help(){
  console.log("Session Continuity Engine");
  console.log("Commands:");
  console.log("  authority-init --output <directory>");
  console.log("  authority-status --authority <directory>");
  console.log("  authority-revoke --authority <directory>");
  console.log("  prove --claims <file> --output <directory> --authority <directory> [--client-id <id>] [--device-id <id>]");
  console.log("  verify --input <directory> --trust <directory>");
  console.log("  --version");
  console.log("  --help");
  console.log("");
  console.log("authority-init provisions the signing identity and external trust authority.");
  console.log("prove expects verified OIDC claims; JWT validation is outside this engine.");
  console.log("prove requires a pre-provisioned signing authority; it never creates or replaces trust.");
  console.log("verify requires an independently provisioned trust store outside the receipt.");
}

function valueOf(args,name){
  const index=args.indexOf(name);
  if(index<0 || index+1>=args.length) throw new Error("CLI_ARGUMENT_MISSING:"+name);
  return args[index+1];
}

function writeJson(file,value){
  fs.writeFileSync(file,JSON.stringify(value,null,2)+"\n","utf8");
}

function authorityInit(args){
  const outputRoot=path.resolve(valueOf(args,"--output"));
  const authority=provisionSigningAuthority(outputRoot,{label:"cli-session-provenance-authority"});
  const verification=verifySigningAuthority(outputRoot);
  if(verification.verified!==true) throw new Error("CLI_AUTHORITY_PROVISIONING_VERIFY_FAILED");
  console.log("AUTHORITY_OUTPUT="+outputRoot);
  console.log("TRUST_OUTPUT="+authority.trustRoot);
  console.log("SIGNER_FINGERPRINT="+authority.signer.publicKeyFingerprintSha256);
  console.log("AUTHORITY_VERIFIED=true");
}

function authorityStatus(args){
  const authorityRoot=path.resolve(valueOf(args,"--authority"));
  const authority=loadSigningAuthority(authorityRoot);
  const trust=createDurableTrustStore(authority.trustRoot);
  const fingerprint=authority.signer.publicKeyFingerprintSha256;
  const trusted=trust.state.accepted.has(fingerprint) && !trust.state.revoked.has(fingerprint);
  console.log("AUTHORITY="+authorityRoot);
  console.log("SIGNER_FINGERPRINT="+fingerprint);
  console.log("TRUST_OUTPUT="+authority.trustRoot);
  console.log("ACTIVE_FINGERPRINT="+String(trust.state.active ?? ""));
  console.log("TRUSTED="+trusted);
  console.log("STATUS="+(trusted ? "ACTIVE" : "REVOKED_OR_NOT_TRUSTED"));
}

function authorityRevoke(args){
  const authorityRoot=path.resolve(valueOf(args,"--authority"));
  const authority=loadSigningAuthority(authorityRoot);
  const trust=createDurableTrustStore(authority.trustRoot);
  const fingerprint=authority.signer.publicKeyFingerprintSha256;
  const result=durableRevokeTrustAnchor(trust,fingerprint);
  const verification=verifySigningAuthority(authorityRoot);
  if(verification.verified===true) throw new Error("CLI_AUTHORITY_REVOCATION_FAILED");
  console.log("AUTHORITY="+authorityRoot);
  console.log("REVOKED_FINGERPRINT="+result.revoked_fingerprint);
  console.log("ACTIVE_FINGERPRINT="+String(result.active_fingerprint ?? ""));
  console.log("STATUS=REVOKED");
}

function prove(args){
  const claimsFile=path.resolve(valueOf(args,"--claims"));
  const outputRoot=path.resolve(valueOf(args,"--output"));
  const authorityRoot=path.resolve(valueOf(args,"--authority"));
  const clientId=args.includes("--client-id") ? valueOf(args,"--client-id") : null;
  const deviceId=args.includes("--device-id") ? valueOf(args,"--device-id") : null;
  const authority=loadSigningAuthority(authorityRoot);
  const authorityVerification=verifySigningAuthority(authorityRoot);
  if(authorityVerification.verified!==true) throw new Error("CLI_AUTHORITY_NOT_TRUSTED");
  const rawText=fs.readFileSync(claimsFile,"utf8").replace(/^\uFEFF/,"");
  const raw=JSON.parse(rawText);
  if(raw?.verified!==true) throw new Error("OIDC_CLAIMS_NOT_MARKED_VERIFIED");
  const verifiedClaims={...raw};
  delete verifiedClaims.verified;
  validateVerifiedOidcClaims(verifiedClaims);
  const anchorBase=createOidcSessionAnchor({verifiedClaims,clientId,deviceId});
  fs.rmSync(outputRoot,{recursive:true,force:true});
  fs.mkdirSync(outputRoot,{recursive:true});
  const state=createSecureSessionState(path.join(outputRoot,"state"),60000);
  const proofRoot=path.join(outputRoot,"proof");
  const sessionKey=createBindingKey();
  const anchor={...anchorBase,publicKeySpkiBase64:sessionKey.publicKeySpkiBase64,publicKeyFingerprintSha256:sessionKey.publicKeyFingerprint};
  const nowMs=Date.now();
  const timestamp=new Date(nowMs).toISOString();
  const challenge=issueChallenge(state,anchor.sessionId,nowMs,60000);
  const signedPresentation=createSignedPresentation(sessionKey,{session_id:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,client_id:anchor.clientId,device_id:anchor.deviceId,sequence:1,challenge:challenge.challenge,timestamp});
  const presented={sessionId:anchor.sessionId,subject:anchor.subject,issuer:anchor.issuer,clientId:anchor.clientId,deviceId:anchor.deviceId,sequence:1};
  const result=executeSessionContinuityDecision({anchor,durableState:state,presented,signedPresentation,timestamp,nowMs,signingIdentity:authority.signer,durableTrustStore:createDurableTrustStore(authority.trustRoot),outputRoot:proofRoot});
  if(result.decision!=="ALLOW"){
    if(result.diagnostic){
      console.error("DIAGNOSTIC_REASON_CODE="+result.diagnostic.reason_code);
      console.error("DIAGNOSTIC_FAILURE_STAGE="+result.diagnostic.failure_stage);
      console.error("DIAGNOSTIC_FAILURE_LOCATION="+result.diagnostic.failure_location);
      console.error("DIAGNOSTIC_EVIDENCE_REF="+(result.diagnostic.evidence_ref===null?"null":result.diagnostic.evidence_ref));
    }
    throw new Error("CLI_PROVE_DECISION:"+result.decision+":"+result.reason);
  }
  if(!result.provenanceCertificate) throw new Error("CLI_PROVENANCE_CERTIFICATE_MISSING");
  writeJson(path.join(outputRoot,"verified-claims.json"),{verified:true,...verifiedClaims});
  writeJson(path.join(outputRoot,"policy.json"),result.policy);
  writeJson(path.join(outputRoot,"provenance-certificate.json"),result.provenanceCertificate);
  console.log("DECISION="+result.decision);
  console.log("REASON="+result.reason);
  console.log("OUTPUT="+outputRoot);
  console.log("AUTHORITY="+authorityRoot);
  console.log("SIGNER_FINGERPRINT="+authority.signer.publicKeyFingerprintSha256);
}

function verify(args){
  const inputRoot=path.resolve(valueOf(args,"--input"));
  const trustRoot=path.resolve(valueOf(args,"--trust"));
  const certificate=JSON.parse(fs.readFileSync(path.join(inputRoot,"provenance-certificate.json"),"utf8"));
  const policyDecision=JSON.parse(fs.readFileSync(path.join(inputRoot,"policy.json"),"utf8"));
  const trust=createDurableTrustStore(trustRoot);
  const receipt=verifySessionProvenanceReceipt({certificate,durableTrustStore:trust,bundleDir:path.join(inputRoot,"proof","bundle"),lineageDir:path.join(inputRoot,"proof","lineage"),policyDecision,expectedSessionId:certificate.session_id,expectedSubject:certificate.subject,expectedIssuer:certificate.issuer});
  console.log("VERIFIED="+receipt.verified);
  console.log("REASON="+receipt.reason);
  if(receipt.verified!==true) process.exit(1);
  console.log("DECISION="+receipt.decision);
  console.log("SESSION_ID="+receipt.session_id);
  console.log("BUNDLE_ROOT="+receipt.bundle_root_sha256);
  console.log("LINEAGE_ROOT="+receipt.lineage_root_sha256);
  console.log("MERKLE_ROOT="+receipt.merkle_root_sha256);
  console.log("EVIDENCE_FINGERPRINT="+receipt.evidence_fingerprint_sha256);
}

const args=process.argv.slice(2);
const command=args[0];
try {
  if(command==="--help" || command===undefined){ help(); process.exit(0); }
  if(command==="--version"){ console.log(VERSION); process.exit(0); }
  if(command==="authority-init"){ authorityInit(args.slice(1)); process.exit(0); }
  if(command==="authority-status"){ authorityStatus(args.slice(1)); process.exit(0); }
  if(command==="authority-revoke"){ authorityRevoke(args.slice(1)); process.exit(0); }
  if(command==="prove"){ prove(args.slice(1)); process.exit(0); }
  if(command==="verify"){ verify(args.slice(1)); process.exit(0); }
  throw new Error("CLI_COMMAND_UNKNOWN:"+command);
} catch(error) {
  console.error("ERROR="+(error instanceof Error ? error.message : String(error)));
  process.exit(1);
}