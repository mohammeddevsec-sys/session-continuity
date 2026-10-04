import fs from "fs";
import {
  createSigningIdentity,
  signProof
} from "../src/evidence/proof-signature.js";
import {
  createDurableTrustStore,
  durableRegisterTrustAnchor,
  durableRevokeTrustAnchor
} from "../src/evidence/durable-trust-store.js";
import {
  verifyDurableTrustedProof
} from "../src/evidence/durable-trusted-proof-verifier.js";

const root =
  "E:\\SESSION-CONTINUITY\\test\\fixtures\\durable-trusted-proof";

fs.rmSync(root, {
  recursive: true,
  force: true
});

const identity =
  createSigningIdentity();

const proof = {
  bundle_root_sha256: "1".repeat(64),
  lineage_root_sha256: "2".repeat(64),
  merkle_root_sha256: "3".repeat(64),
  evidence_fingerprint_sha256: "4".repeat(64)
};

const certificate =
  signProof(
    identity,
    proof
  );

const store1 =
  createDurableTrustStore(root);

durableRegisterTrustAnchor(
  store1,
  identity.publicKeySpkiBase64,
  {
    version: 1,
    created_at:
      "2026-09-13T15:00:00Z",
    label:
      "durable-proof-signer"
  }
);

const first =
  verifyDurableTrustedProof(
    certificate,
    store1
  );

if (!first.verified) {
  throw new Error(
    "DURABLE_TRUST_INITIAL_VERIFY_FAILED"
  );
}

const store2 =
  createDurableTrustStore(root);

const afterRestart =
  verifyDurableTrustedProof(
    certificate,
    store2
  );

if (!afterRestart.verified) {
  throw new Error(
    "DURABLE_TRUST_RESTART_VERIFY_FAILED"
  );
}

durableRevokeTrustAnchor(
  store2,
  identity.publicKeyFingerprintSha256
);

const revoked =
  verifyDurableTrustedProof(
    certificate,
    store2
  );

if (revoked.verified) {
  throw new Error(
    "DURABLE_REVOKED_SIGNER_ACCEPTED"
  );
}

if (revoked.reason !== "SIGNER_REVOKED") {
  throw new Error(
    "DURABLE_REVOKE_REASON_INVALID"
  );
}

const store3 =
  createDurableTrustStore(root);

const revokedAfterRestart =
  verifyDurableTrustedProof(
    certificate,
    store3
  );

if (revokedAfterRestart.verified) {
  throw new Error(
    "REVOCATION_NOT_PERSISTED"
  );
}

const unknownIdentity =
  createSigningIdentity();

const unknownCertificate =
  signProof(
    unknownIdentity,
    proof
  );

const unknown =
  verifyDurableTrustedProof(
    unknownCertificate,
    store3
  );

if (unknown.verified) {
  throw new Error(
    "UNKNOWN_DURABLE_SIGNER_ACCEPTED"
  );
}

console.log(
  "DURABLE_TRUST_INITIAL_VERIFY=PASS"
);
console.log(
  "DURABLE_TRUST_RESTART_VERIFY=PASS"
);
console.log(
  "DURABLE_REVOKED_SIGNER_REJECTED=PASS"
);
console.log(
  "REVOCATION_PERSISTED=PASS"
);
console.log(
  "UNKNOWN_DURABLE_SIGNER_REJECTED=PASS"
);
console.log(
  "DURABLE_TRUSTED_PROOF_VERIFIER=PASS"
);
console.log(
  "SIGNER_FINGERPRINT=" +
    identity.publicKeyFingerprintSha256
);
