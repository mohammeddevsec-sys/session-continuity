import fs from "fs";
import os from "os";
import path from "path";
import { provisionSigningAuthority, loadSigningAuthority, verifySigningAuthority } from "../src/evidence/signing-authority.js";
import { signProof, verifyProofSignature } from "../src/evidence/proof-signature.js";

const root=fs.mkdtempSync(path.join(os.tmpdir(),"sce-authority-"));
const authorityRoot=path.join(root,"authority");
const created=provisionSigningAuthority(authorityRoot,{label:"test-authority",created_at:"2026-09-13T22:00:00Z"});
if(!fs.existsSync(path.join(authorityRoot,"signer-private.pem"))) throw new Error("AUTHORITY_PRIVATE_KEY_NOT_CREATED");
if(!fs.existsSync(path.join(authorityRoot,"authority.json"))) throw new Error("AUTHORITY_METADATA_NOT_CREATED");
const first=verifySigningAuthority(authorityRoot);
if(!first.verified) throw new Error("AUTHORITY_INITIAL_VERIFY_FAILED");
console.log("AUTHORITY_INITIAL_VERIFY=PASS");

const proof={bundle_root_sha256:"1".repeat(64),lineage_root_sha256:"2".repeat(64),merkle_root_sha256:"3".repeat(64),evidence_fingerprint_sha256:"4".repeat(64)};
const certificate=signProof(created.signer,proof);
if(!verifyProofSignature(certificate).verified) throw new Error("AUTHORITY_SIGNING_FAILED");
console.log("AUTHORITY_SIGNING=PASS");

const recovered=loadSigningAuthority(authorityRoot);
if(recovered.signer.publicKeyFingerprintSha256!==created.signer.publicKeyFingerprintSha256) throw new Error("AUTHORITY_RESTART_FINGERPRINT_CHANGED");
if(!verifyProofSignature(signProof(recovered.signer,proof)).verified) throw new Error("AUTHORITY_RESTART_SIGNING_FAILED");
console.log("AUTHORITY_RESTART_RECOVERY=PASS");

const second=verifySigningAuthority(authorityRoot);
if(!second.verified) throw new Error("AUTHORITY_RESTART_VERIFY_FAILED");
console.log("AUTHORITY_RESTART_VERIFY=PASS");

fs.rmSync(root,{recursive:true,force:true});
console.log("SIGNING_AUTHORITY=PASS");