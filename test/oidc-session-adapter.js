import { createOidcSessionAnchor, createOidcSessionBootstrap, validateVerifiedOidcClaims } from "../src/adapters/oidc-session-adapter.js";

const claims={sub:"user-001",iss:"https://issuer.example",sid:"sid-001",auth_time:"2026-09-13T18:00:00.000Z",aud:"client-A"};
const validated=validateVerifiedOidcClaims(claims);
if(validated.sub!=="user-001" || validated.iss!=="https://issuer.example" || validated.sid!=="sid-001") throw new Error("OIDC_VALIDATION_FAILED");
console.log("OIDC_CLAIMS_VALIDATION=PASS");

const anchor=createOidcSessionAnchor({verifiedClaims:claims,clientId:"client-A",deviceId:"device-A"});
if(anchor.sessionId!=="sid-001" || anchor.subject!=="user-001" || anchor.issuer!=="https://issuer.example") throw new Error("OIDC_ANCHOR_MAPPING_FAILED");
console.log("OIDC_ANCHOR_MAPPING=PASS");

const bootstrap=createOidcSessionBootstrap({verifiedClaims:claims,clientId:"client-A",deviceId:"device-A"});
if(bootstrap.protocol!=="OIDC" || bootstrap.anchor.sessionId!=="sid-001") throw new Error("OIDC_BOOTSTRAP_FAILED");
console.log("OIDC_BOOTSTRAP=PASS");

let missingRejected=false;
try { validateVerifiedOidcClaims({sub:"user-001",iss:"https://issuer.example",auth_time:"2026-09-13T18:00:00.000Z"}); } catch(error) { missingRejected=true; console.log("OIDC_MISSING_SID_REJECTED=PASS|"+error.message); }
if(!missingRejected) throw new Error("OIDC_MISSING_SID_ACCEPTED");

let missingSubjectRejected=false;
try { createOidcSessionAnchor({verifiedClaims:{iss:"https://issuer.example",sid:"sid-002",auth_time:"2026-09-13T18:00:00.000Z"}}); } catch(error) { missingSubjectRejected=true; console.log("OIDC_MISSING_SUB_REJECTED=PASS|"+error.message); }
if(!missingSubjectRejected) throw new Error("OIDC_MISSING_SUB_ACCEPTED");

let invalidClaimsRejected=false;
try { createOidcSessionBootstrap({verifiedClaims:null}); } catch(error) { invalidClaimsRejected=true; console.log("OIDC_UNVERIFIED_INPUT_REJECTED=PASS|"+error.message); }
if(!invalidClaimsRejected) throw new Error("OIDC_INVALID_INPUT_ACCEPTED");

console.log("OIDC_SESSION_ADAPTER=PASS");