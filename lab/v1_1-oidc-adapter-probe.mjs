import { createOidcSessionAnchor, createOidcSessionBootstrap } from "../src/adapters/oidc-session-adapter.js";
const claims={sub:"user-1",iss:"https://issuer.example",sid:"sid-1",auth_time:1700000000,aud:"client-1"};
const anchor=createOidcSessionAnchor({verifiedClaims:claims,clientId:"client-1"});
const bootstrap=createOidcSessionBootstrap({verifiedClaims:claims,clientId:"client-1"});
const expectedAuthTime=new Date(1700000000*1000).toISOString();
const failures=[];
if(anchor.sessionId!=="sid-1"||anchor.subject!=="user-1"||anchor.issuer!=="https://issuer.example"||anchor.authTime!==expectedAuthTime||anchor.clientId!=="client-1")failures.push("ANCHOR_BINDING");
if(bootstrap.protocol!=="OIDC"||bootstrap.anchor.sessionId!=="sid-1"||bootstrap.verifiedClaims.sub!=="user-1")failures.push("BOOTSTRAP_BINDING");
for(const [name,bad] of [["SUB",{iss:"i",sid:"s",auth_time:1}],["ISS",{sub:"u",sid:"s",auth_time:1}],["SID",{sub:"u",iss:"i",auth_time:1}],["AUTH_TIME",{sub:"u",iss:"i",sid:"s"}]]){let rejected=false;try{createOidcSessionAnchor({verifiedClaims:bad})}catch(e){rejected=String(e.message).startsWith("OIDC_")}if(!rejected)failures.push("REJECT_"+name)}
if(failures.length){console.error("OIDC_FAILURES="+failures.join(","));process.exit(2)}
console.log("OIDC_ANCHOR=PASS");
console.log("OIDC_BOOTSTRAP=PASS");
console.log("OIDC_INVALID_CLAIMS=PASS");
console.log("OIDC_ADAPTER_PROBE_DONE=1");
