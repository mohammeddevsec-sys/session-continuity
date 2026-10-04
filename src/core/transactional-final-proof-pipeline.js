import fs from "fs";
import path from "path";
import crypto from "crypto";
import { verifyContinuity } from "./continuity-verifier.js";
import { verifySignedPresentation } from "./proof-of-possession.js";
import { verifySecureSessionState, commitSessionAcceptance } from "./durable-secure-session-state.js";
import { createEvidenceContract } from "../evidence/evidence-contract.js";
import { writeEvidenceBundle } from "../evidence/evidence-bundle.js";
import { appendEvidenceLineage } from "../evidence/evidence-lineage.js";
import { verifyEvidenceProof } from "../evidence/offline-verifier.js";
import { signProof } from "../evidence/proof-signature.js";
import { verifyDurableTrustedProof } from "../evidence/durable-trusted-proof-verifier.js";
import { claimContinuationSlot, releaseContinuationSlot } from "./fork-registry.mjs";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text),"utf8")).digest("hex").toLowerCase();
}

function fingerprint(value) {
  return sha256Text(JSON.stringify(Object.keys(value).sort().reduce((out,key)=>{out[key]=value[key];return out;},{})));
}

function failure(decision,reason,failedChecks=[],evidence=null) {
  return Object.freeze({decision,reason,failedChecks,evidence,committed:false});
}

export function executeTransactionalFinalProofPipeline({
  anchor,
  durableState,
  presented,
  signedPresentation,
  timestamp,
  nowMs,
  signingIdentity,
  durableTrustStore,
  outputRoot
}) {
  const continuity=verifyContinuity(anchor,presented);
  if(continuity.decision!=="CONTINUOUS"){
    return failure("REAUTH_REQUIRED",continuity.reason,continuity.failedChecks||[]);
  }

  const proof=verifySignedPresentation(anchor,signedPresentation);
  if(!proof.verified){
    return failure("REAUTH_REQUIRED",proof.reason,["proofOfPossession"]);
  }

  verifySecureSessionState(durableState);
  const sequence=presented.sequence;
  const lastSequence=durableState.sessions.get(anchor.sessionId) ?? 0;
  if(!Number.isInteger(sequence) || sequence<1 || sequence<=lastSequence){
    return failure("REAUTH_REQUIRED","REPLAY_DETECTED",["sequence"]);
  }

  const challenge=signedPresentation?.payload?.challenge;
  const challengeState=durableState.challenges.get(challenge);
  if(!challengeState){
    return failure("REAUTH_REQUIRED","CHALLENGE_UNKNOWN",["challenge"]);
  }
  if(challengeState.sessionId!==anchor.sessionId){
    return failure("REAUTH_REQUIRED","CHALLENGE_SESSION_MISMATCH",["challenge"]);
  }
  if(challengeState.consumed){
    return failure("REAUTH_REQUIRED","CHALLENGE_ALREADY_CONSUMED",["challenge"]);
  }
  if(nowMs>challengeState.expiresAt){
    return failure("REAUTH_REQUIRED","CHALLENGE_EXPIRED",["challenge"]);
  }

  const evidence=createEvidenceContract({
    sessionId:anchor.sessionId,
    anchorFingerprint:fingerprint(anchor),
    presentationFingerprint:fingerprint(presented),
    sequence,
    timestamp,
    checks:{sessionId:true,subject:true,issuer:true,clientId:true,deviceId:true,sequence:true,proofOfPossession:true,challenge:true},
    failedChecks:[],
    decision:"CONTINUOUS",
    reason:"SECURE_CONTINUITY_COMMITTED",
    security:{
      popKeyFingerprintSha256:signedPresentation.public_key_fingerprint_sha256,
      challengeResult:"PRECOMMIT_VALIDATED",
      replayResult:"PRECOMMIT_VALIDATED",
      continuityResult:"ANCHOR_MATCH"
    }
  });

  const stagingRoot=outputRoot+".staging";
  fs.rmSync(stagingRoot,{recursive:true,force:true});
  fs.rmSync(outputRoot,{recursive:true,force:true});

  try {
    const bundleDir=path.join(stagingRoot,"bundle");
    const lineageDir=path.join(stagingRoot,"lineage");
    const bundle=writeEvidenceBundle(bundleDir,{
      "decision.json":{schema_id:"session-continuity.decision.v1",version:1,decision:"CONTINUOUS",reason:"SECURE_CONTINUITY_COMMITTED",sequence,timestamp},
      "evidence.json":evidence.evidence
    });
    const lineage=appendEvidenceLineage(lineageDir,{
      session_id:anchor.sessionId,
      decision:"CONTINUOUS",
      reason:"SECURE_CONTINUITY_COMMITTED",
      sequence,
      evidence_fingerprint_sha256:evidence.fingerprint,
      bundle_root_sha256:bundle.bundle_root_sha256,
      timestamp
    });
    const proofDocument={bundle_root_sha256:bundle.bundle_root_sha256,lineage_root_sha256:lineage.lineage_root_sha256,merkle_root_sha256:lineage.merkle_root_sha256,evidence_fingerprint_sha256:evidence.fingerprint};
    const certificate=signProof(signingIdentity,proofDocument);
    const offline=verifyEvidenceProof(bundleDir,lineageDir);
    const trusted=verifyDurableTrustedProof(certificate,durableTrustStore);
    const bindingValid=certificate.bundle_root_sha256===offline.bundle_root_sha256 && certificate.lineage_root_sha256===offline.lineage_root_sha256 && certificate.merkle_root_sha256===offline.merkle_root_sha256 && certificate.evidence_fingerprint_sha256===evidence.fingerprint;
    if(!bindingValid) throw new Error("TRANSACTIONAL_CERTIFICATE_BINDING_FAILED");
    if(!offline.verified) throw new Error("TRANSACTIONAL_OFFLINE_VERIFY_FAILED");
    if(!trusted.verified) throw new Error("TRANSACTIONAL_TRUST_FAILED");

    let forkAnchorFp = null;
    if (process.env.SC_FORK_PROTECTION === "enabled") {
      forkAnchorFp = fingerprint(anchor);
      const forkClaim = claimContinuationSlot({
        anchorFingerprint: forkAnchorFp,
        parentSequence: lastSequence,
        metadata: { sessionId: anchor.sessionId, presentedSequence: sequence, timestamp }
      });
      if (!forkClaim.claimed) {
        fs.rmSync(stagingRoot,{recursive:true,force:true});
        return failure("REAUTH_REQUIRED","FORK_DETECTED",["fork"]);
      }
    }

    const committed=commitSessionAcceptance(durableState,anchor.sessionId,sequence,challenge,nowMs);
    if(committed.decision!=="CONTINUOUS"){
      if (forkAnchorFp) releaseContinuationSlot({ anchorFingerprint: forkAnchorFp, parentSequence: lastSequence });
      fs.rmSync(stagingRoot,{recursive:true,force:true});
      return failure(committed.decision,committed.reason,["sequence"]);
    }

    fs.renameSync(stagingRoot,outputRoot);
    return Object.freeze({
      decision:"CONTINUOUS",
      reason:committed.reason,
      committed:true,
      session:{decision:"CONTINUOUS",reason:committed.reason,failedChecks:[]},
      bundle,lineage,proof:proofDocument,certificate,
      evidence,verification:{offline,trusted,binding_valid:bindingValid}
    });
  } catch(error) {
    fs.rmSync(stagingRoot,{recursive:true,force:true});
    throw error;
  }
}
