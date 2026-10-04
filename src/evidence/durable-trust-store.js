import fs from "fs";
import path from "path";
import crypto from "crypto";
import { canonicalStringify } from "../core/canonical.js";

function sha256Text(text) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(String(text), "utf8"))
    .digest("hex")
    .toLowerCase();
}

function fingerprintPublicKey(publicKeySpkiBase64) {
  if (
    typeof publicKeySpkiBase64 !== "string" ||
    !publicKeySpkiBase64.length
  ) {
    throw new Error("TRUST_PUBLIC_KEY_INVALID");
  }

  const der = Buffer.from(
    publicKeySpkiBase64,
    "base64"
  );

  return crypto
    .createHash("sha256")
    .update(der)
    .digest("hex")
    .toLowerCase();
}

function writeRecordSync(filePath, record) {
  const line =
    canonicalStringify(record) + "\n";

  const fd = fs.openSync(
    filePath,
    "a"
  );

  try {
    fs.writeSync(
      fd,
      line,
      null,
      "utf8"
    );

    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function loadJournal(filePath) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const raw =
    fs.readFileSync(
      filePath,
      "utf8"
    );

  if (!raw.length) {
    return [];
  }

  const lines =
    raw
      .split(/\r?\n/)
      .filter(Boolean);

  const records = [];
  let previousHash = "";

  for (
    let i = 0;
    i < lines.length;
    i++
  ) {
    let record;

    try {
      record =
        JSON.parse(lines[i]);
    } catch {
      throw new Error(
        `TRUST_JOURNAL_JSON_INVALID:${i}`
      );
    }

    if (
      !record ||
      typeof record !== "object"
    ) {
      throw new Error(
        `TRUST_JOURNAL_RECORD_INVALID:${i}`
      );
    }

    if (
      String(record.prev_hash || "") !==
      previousHash
    ) {
      throw new Error(
        `TRUST_JOURNAL_CHAIN_BROKEN:${i}`
      );
    }

    const payload = {
      schema_id:
        record.schema_id,
      version:
        record.version,
      event:
        record.event,
      fingerprint:
        record.fingerprint,
      public_key_spki_base64:
        record.public_key_spki_base64 ??
        null,
      metadata:
        record.metadata ??
        null,
      prev_hash:
        record.prev_hash
    };

    const calculated =
      sha256Text(
        canonicalStringify(
          payload
        )
      );

    if (
      String(
        record.record_hash || ""
      ).toLowerCase() !==
      calculated
    ) {
      throw new Error(
        `TRUST_JOURNAL_HASH_MISMATCH:${i}`
      );
    }

    previousHash = calculated;
    records.push(record);
  }

  return records;
}

function buildState(records) {
  const accepted = new Map();
  const revoked = new Set();
  let active = null;

  for (const record of records) {
    const fingerprint =
      record.fingerprint;

    if (
      record.event ===
      "TRUST_ADD"
    ) {
      accepted.set(
        fingerprint,
        Object.freeze({
          fingerprint,
          public_key_spki_base64:
            record.public_key_spki_base64,
          status:
            "TRUSTED",
          version:
            Number(
              record.metadata?.version ??
              1
            ),
          created_at:
            String(
              record.metadata?.created_at ??
              ""
            ),
          label:
            record.metadata?.label ??
            null
        })
      );

      revoked.delete(
        fingerprint
      );

      if (
        active === null
      ) {
        active =
          fingerprint;
      }
    }

    if (
      record.event ===
      "TRUST_ACTIVATE"
    ) {
      if (
        !accepted.has(
          fingerprint
        ) ||
        revoked.has(
          fingerprint
        )
      ) {
        throw new Error(
          "TRUST_ACTIVATE_INVALID"
        );
      }

      active =
        fingerprint;
    }

    if (
      record.event ===
      "TRUST_REVOKE"
    ) {
      if (
        !accepted.has(
          fingerprint
        )
      ) {
        throw new Error(
          "TRUST_REVOKE_INVALID"
        );
      }

      accepted.delete(
        fingerprint
      );

      revoked.add(
        fingerprint
      );

      if (
        active ===
        fingerprint
      ) {
        active = null;
      }
    }
  }

  return {
    version: 1,
    active,
    accepted,
    revoked
  };
}

function appendEvent(
  journalPath,
  event,
  fingerprint,
  publicKeySpkiBase64 = null,
  metadata = null
) {
  const records =
    loadJournal(
      journalPath
    );

  const previousHash =
    records.length
      ? records[
          records.length - 1
        ].record_hash
      : "";

  const payload = {
    schema_id:
      "session-continuity.trust.event.v1",
    version:
      1,
    event,
    fingerprint,
    public_key_spki_base64:
      publicKeySpkiBase64,
    metadata,
    prev_hash:
      previousHash
  };

  const record = {
    ...payload,
    record_hash:
      sha256Text(
        canonicalStringify(
          payload
        )
      )
  };

  writeRecordSync(
    journalPath,
    record
  );

  return record;
}

export function createDurableTrustStore(
  directory
) {
  if (
    typeof directory !== "string" ||
    !directory.length
  ) {
    throw new Error(
      "TRUST_DIRECTORY_INVALID"
    );
  }

  fs.mkdirSync(
    directory,
    { recursive: true }
  );

  const journalPath =
    path.join(
      directory,
      "TRUST_JOURNAL.ndjson"
    );

  const records =
    loadJournal(
      journalPath
    );

  return {
    version: 1,
    directory,
    journalPath,
    records,
    state:
      buildState(records)
  };
}

function refresh(store) {
  const records =
    loadJournal(
      store.journalPath
    );

  store.records =
    records;

  store.state =
    buildState(records);

  return store.state;
}

export function durableRegisterTrustAnchor(
  store,
  publicKeySpkiBase64,
  metadata = {}
) {
  refresh(store);

  const fingerprint =
    fingerprintPublicKey(
      publicKeySpkiBase64
    );

  if (
    store.state.revoked.has(
      fingerprint
    )
  ) {
    throw new Error(
      "TRUST_KEY_REVOKED"
    );
  }

  if (
    !store.state.accepted.has(
      fingerprint
    )
  ) {
    appendEvent(
      store.journalPath,
      "TRUST_ADD",
      fingerprint,
      publicKeySpkiBase64,
      {
        version:
          Number(
            metadata.version ??
            1
          ),
        created_at:
          String(
            metadata.created_at ??
            ""
          ),
        label:
          metadata.label ??
          null
      }
    );
  }

  refresh(store);

  return Object.freeze({
    fingerprint,
    trusted:
      store.state.accepted.has(
        fingerprint
      )
  });
}

export function durableRotateTrustAnchor(
  store,
  publicKeySpkiBase64,
  metadata = {}
) {
  const added =
    durableRegisterTrustAnchor(
      store,
      publicKeySpkiBase64,
      metadata
    );

  refresh(store);

  const previous =
    store.state.active;

  if (
    previous !==
    added.fingerprint
  ) {
    appendEvent(
      store.journalPath,
      "TRUST_ACTIVATE",
      added.fingerprint
    );
  }

  refresh(store);

  return Object.freeze({
    previous_fingerprint:
      previous,
    active_fingerprint:
      store.state.active
  });
}

export function durableRevokeTrustAnchor(
  store,
  fingerprint
) {
  refresh(store);

  if (
    !store.state.accepted.has(
      fingerprint
    )
  ) {
    throw new Error(
      "TRUST_KEY_NOT_FOUND"
    );
  }

  appendEvent(
    store.journalPath,
    "TRUST_REVOKE",
    fingerprint
  );

  refresh(store);

  return Object.freeze({
    revoked_fingerprint:
      fingerprint,
    active_fingerprint:
      store.state.active
  });
}

export function verifyDurableTrust(
  store,
  fingerprint
) {
  refresh(store);

  const normalized =
    String(
      fingerprint || ""
    ).toLowerCase();

  if (
    store.state.revoked.has(
      normalized
    )
  ) {
    return {
      trusted: false,
      reason:
        "SIGNER_REVOKED"
    };
  }

  const record =
    store.state.accepted.get(
      normalized
    );

  if (!record) {
    return {
      trusted: false,
      reason:
        "SIGNER_NOT_TRUSTED"
    };
  }

  return {
    trusted: true,
    reason:
      "SIGNER_TRUSTED",
    record
  };
}
