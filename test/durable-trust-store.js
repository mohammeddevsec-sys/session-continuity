import fs from "fs";
import path from "path";
import crypto from "crypto";
import {
  createDurableTrustStore,
  durableRegisterTrustAnchor,
  durableRotateTrustAnchor,
  durableRevokeTrustAnchor,
  verifyDurableTrust
} from "../src/evidence/durable-trust-store.js";

function keyBase64() {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  return publicKey.export({
    type: "spki",
    format: "der"
  }).toString("base64");
}

const root = "E:\\SESSION-CONTINUITY\\test\\fixtures\\durable-trust";
fs.rmSync(root, { recursive: true, force: true });
fs.mkdirSync(root, { recursive: true });

const journal = path.join(root, "TRUST_JOURNAL.ndjson");

const keyA = keyBase64();
const keyB = keyBase64();
const keyC = keyBase64();

const store1 = createDurableTrustStore(root);

const a = durableRegisterTrustAnchor(
  store1,
  keyA,
  {
    version: 1,
    created_at: "2026-09-13T12:00:00Z",
    label: "primary"
  }
);

if (!a.trusted) {
  throw new Error("DURABLE_REGISTER_FAILED");
}

const rotate = durableRotateTrustAnchor(
  store1,
  keyB,
  {
    version: 2,
    created_at: "2026-09-13T12:01:00Z",
    label: "rotated"
  }
);

if (rotate.active_fingerprint === rotate.previous_fingerprint) {
  throw new Error("ROTATION_DID_NOT_CHANGE_ACTIVE");
}

const trustedB = verifyDurableTrust(
  store1,
  rotate.active_fingerprint
);

if (!trustedB.trusted) {
  throw new Error("ACTIVE_ROTATED_KEY_NOT_TRUSTED");
}

const revokeA = durableRevokeTrustAnchor(
  store1,
  rotate.previous_fingerprint
);

if (revokeA.active_fingerprint !== rotate.active_fingerprint) {
  throw new Error("ACTIVE_KEY_CHANGED_BY_OLD_KEY_REVOKE");
}

const store2 = createDurableTrustStore(root);

const recoveredB = verifyDurableTrust(
  store2,
  rotate.active_fingerprint
);

if (!recoveredB.trusted) {
  throw new Error("TRUST_NOT_RECOVERED_AFTER_RESTART");
}

const recoveredA = verifyDurableTrust(
  store2,
  rotate.previous_fingerprint
);

if (recoveredA.trusted || recoveredA.reason !== "SIGNER_REVOKED") {
  throw new Error("REVOCATION_NOT_RECOVERED_AFTER_RESTART");
}

const unknownC = verifyDurableTrust(
  store2,
  crypto.createHash("sha256")
    .update(Buffer.from(keyC, "base64"))
    .digest("hex")
);

if (unknownC.trusted) {
  throw new Error("UNKNOWN_KEY_ACCEPTED_AFTER_RESTART");
}

const originalJournal = fs.readFileSync(journal, "utf8");

fs.appendFileSync(
  journal,
  '{"schema_id":"session-continuity.trust.event.v1"'
);

let corruptionDetected = false;

try {
  createDurableTrustStore(root);
} catch {
  corruptionDetected = true;
}

if (!corruptionDetected) {
  throw new Error("TRUST_JOURNAL_CORRUPTION_NOT_DETECTED");
}

fs.writeFileSync(journal, originalJournal, "utf8");

const recoveredAfterRestore = createDurableTrustStore(root);

if (
  !verifyDurableTrust(
    recoveredAfterRestore,
    rotate.active_fingerprint
  ).trusted
) {
  throw new Error("RESTORED_TRUST_STATE_INVALID");
}

console.log("DURABLE_TRUST_REGISTER=PASS");
console.log("DURABLE_KEY_ROTATION=PASS");
console.log("REVOCATION_PERSISTENCE=PASS");
console.log("RESTART_RECOVERY=PASS");
console.log("UNKNOWN_KEY_REJECTED=PASS");
console.log("JOURNAL_CORRUPTION_DETECTED=PASS");
console.log("DURABLE_TRUST_STORE=PASS");
