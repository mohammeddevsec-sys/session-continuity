import fs from "fs";
import path from "path";
import crypto from "crypto";
import { createSigningIdentity } from "./proof-signature.js";
import { createDurableTrustStore, durableRegisterTrustAnchor } from "./durable-trust-store.js";

const AUTHORITY_SCHEMA="session-continuity.signing-authority.v1";

function fingerprintPublicKey(publicKey) {
  const der=publicKey.export({type:"spki",format:"der"});
  return crypto.createHash("sha256").update(der).digest("hex").toLowerCase();
}

export function provisionSigningAuthority(directory,options={}) {
  if(typeof directory!=="string" || !directory.length) throw new TypeError("AUTHORITY_DIRECTORY_REQUIRED");
  const authorityRoot=path.resolve(directory);
  fs.mkdirSync(authorityRoot,{recursive:true});
  const privateKeyPath=path.join(authorityRoot,"signer-private.pem");
  const publicKeyPath=path.join(authorityRoot,"signer-public.pem");
  const metadataPath=path.join(authorityRoot,"authority.json");
  if(fs.existsSync(privateKeyPath) || fs.existsSync(metadataPath)) throw new Error("AUTHORITY_ALREADY_EXISTS");
  const identity=createSigningIdentity();
  fs.writeFileSync(privateKeyPath,identity.privateKey.export({type:"pkcs8",format:"pem"}),{encoding:"utf8",mode:0o600});
  fs.writeFileSync(publicKeyPath,identity.publicKey.export({type:"spki",format:"pem"}),{encoding:"utf8"});
  const metadata={schema_id:AUTHORITY_SCHEMA,version:1,signer_public_key_fingerprint_sha256:identity.publicKeyFingerprintSha256,created_at:options.created_at ?? new Date().toISOString(),label:options.label ?? "session-continuity-signer"};
  fs.writeFileSync(metadataPath,JSON.stringify(metadata,null,2)+"\n","utf8");
  const trustRoot=path.join(authorityRoot,"trust");
  const trust=createDurableTrustStore(trustRoot);
  durableRegisterTrustAnchor(trust,identity.publicKeySpkiBase64,{version:1,created_at:metadata.created_at,label:metadata.label});
  return Object.freeze({authorityRoot,trustRoot,signer:identity,metadata});
}

export function loadSigningAuthority(directory) {
  if(typeof directory!=="string" || !directory.length) throw new TypeError("AUTHORITY_DIRECTORY_REQUIRED");
  const authorityRoot=path.resolve(directory);
  const privateKeyPath=path.join(authorityRoot,"signer-private.pem");
  const metadataPath=path.join(authorityRoot,"authority.json");
  if(!fs.existsSync(privateKeyPath)) throw new Error("AUTHORITY_PRIVATE_KEY_MISSING");
  if(!fs.existsSync(metadataPath)) throw new Error("AUTHORITY_METADATA_MISSING");
  const metadata=JSON.parse(fs.readFileSync(metadataPath,"utf8").replace(/^\uFEFF/,""));
  if(metadata.schema_id!==AUTHORITY_SCHEMA || metadata.version!==1) throw new Error("AUTHORITY_SCHEMA_INVALID");
  const privateKey=crypto.createPrivateKey(fs.readFileSync(privateKeyPath,"utf8"));
  const publicKey=crypto.createPublicKey(privateKey);
  const publicKeyDer=publicKey.export({type:"spki",format:"der"});
  const publicKeySpkiBase64=publicKeyDer.toString("base64");
  const publicKeyFingerprintSha256=crypto.createHash("sha256").update(publicKeyDer).digest("hex").toLowerCase();
  if(publicKeyFingerprintSha256!==String(metadata.signer_public_key_fingerprint_sha256).toLowerCase()) throw new Error("AUTHORITY_KEY_FINGERPRINT_MISMATCH");
  return Object.freeze({
    authorityRoot,
    trustRoot:path.join(authorityRoot,"trust"),
    signer:Object.freeze({privateKey,publicKey,publicKeySpkiBase64,publicKeyFingerprintSha256}),
    metadata
  });
}

export function verifySigningAuthority(directory) {
  const authority=loadSigningAuthority(directory);
  const trust=createDurableTrustStore(authority.trustRoot);
  const fingerprint=authority.signer.publicKeyFingerprintSha256;
  const record=trust.state.accepted.get(fingerprint);
  const trusted=!!record && !trust.state.revoked.has(fingerprint);
  return Object.freeze({verified:trusted,reason:trusted ? "SIGNING_AUTHORITY_VALID" : "SIGNING_AUTHORITY_NOT_TRUSTED",signer_public_key_fingerprint_sha256:fingerprint,authorityRoot:authority.authorityRoot,trustRoot:authority.trustRoot});
}