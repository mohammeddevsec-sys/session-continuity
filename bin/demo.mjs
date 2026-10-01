import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";

const projectRoot=process.cwd();
const demoRoot=fs.mkdtempSync(path.join(os.tmpdir(),"session-continuity-demo-"));
const claimsFile=path.join(demoRoot,"verified-oidc-claims.json");
const authorityRoot=path.join(demoRoot,"authority");
const receiptRoot=path.join(demoRoot,"receipt");
const cli=path.join(projectRoot,"bin","session-continuity.mjs");

fs.mkdirSync(demoRoot,{recursive:true});
fs.writeFileSync(claimsFile,JSON.stringify({
  verified:true,
  sub:"user-demo-001",
  iss:"https://issuer.example",
  sid:"sid-demo-001",
  auth_time:"2026-09-13T21:00:00.000Z",
  aud:"client-demo"
},null,2)+"\n","utf8");

function run(args){
  const result=spawnSync(process.execPath,[cli,...args],{stdio:"inherit"});
  if(result.error) throw result.error;
  return result.status;
}

try {
  console.log("=== SESSION CONTINUITY :: PRODUCT DEMO ===");
  console.log("");
  console.log("[1] PRE-PROVISION TRUST AUTHORITY");
  if(run(["authority-init","--output",authorityRoot])!==0) process.exit(1);
  console.log("DEMO_AUTHORITY_INIT=PASS");
  console.log("");
  console.log("[2] VERIFIED OIDC FIXTURE");
  console.log("CLAIMS="+claimsFile);
  if(run(["prove","--claims",claimsFile,"--output",receiptRoot,"--authority",authorityRoot,"--client-id","client-demo","--device-id","device-demo"])!==0) process.exit(1);
  console.log("DEMO_PROVE=PASS");
  console.log("");
  console.log("[3] INDEPENDENT VERIFICATION");
  if(run(["verify","--input",receiptRoot,"--trust",path.join(authorityRoot,"trust")])!==0) process.exit(1);
  console.log("DEMO_VERIFY=PASS");
  console.log("");
  console.log("[4] VERIFY WITHOUT TRUST");
  const noTrustStatus=run(["verify","--input",receiptRoot]);
  if(noTrustStatus===0) throw new Error("DEMO_VERIFY_WITHOUT_TRUST_ACCEPTED");
  console.log("DEMO_NO_TRUST_REJECTED=PASS");
  console.log("");
  console.log("[5] ADVERSARIAL EVIDENCE TAMPER");
  const evidenceFile=path.join(receiptRoot,"proof","bundle","evidence.json");
  fs.appendFileSync(evidenceFile,"X");
  const tamperStatus=run(["verify","--input",receiptRoot,"--trust",path.join(authorityRoot,"trust")]);
  if(tamperStatus===0) throw new Error("DEMO_TAMPER_ACCEPTED");
  console.log("DEMO_TAMPER_REJECTED=PASS");
  console.log("");
  console.log("SESSION_CONTINUITY_DEMO=PASS");
  console.log("NOTE=OIDC CLAIMS ARE A VERIFIED LOCAL FIXTURE; NO REAL IDP IS CONTACTED.");
  console.log("NOTE=TRUST AUTHORITY IS PRE-PROVISIONED OUTSIDE THE RECEIPT.");
  console.log("DEMO_WORKSPACE="+demoRoot);
} finally {
  fs.rmSync(demoRoot,{recursive:true,force:true});
}