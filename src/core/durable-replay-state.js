import fs from "fs";
import path from "path";
import crypto from "crypto";
import { canonicalStringify } from "./canonical.js";

function sha256Text(text) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(String(text), "utf8"))
    .digest("hex")
    .toLowerCase();
}

function sleepMs(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {}
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function fsyncFile(filePath) {
  const fd = fs.openSync(filePath, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function atomicWrite(filePath, text) {
  const tempPath =
    filePath +
    `.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  const fd = fs.openSync(tempPath, "w");

  try {
    fs.writeSync(fd, text, null, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  fs.renameSync(tempPath, filePath);
}

function loadJournal(journalPath) {
  if (!fs.existsSync(journalPath)) {
    return [];
  }

  const raw = fs.readFileSync(journalPath, "utf8");

  if (!raw.length) {
    return [];
  }

  const lines = raw.split(/\r?\n/).filter(Boolean);
  const records = [];
  let previousHash = "";

  for (let i = 0; i < lines.length; i++) {
    let record;

    try {
      record = JSON.parse(lines[i]);
    } catch {
      throw new Error(`REPLAY_JOURNAL_JSON_INVALID:${i}`);
    }

    if (!record || typeof record !== "object") {
      throw new Error(`REPLAY_JOURNAL_RECORD_INVALID:${i}`);
    }

    if (String(record.prev_hash || "") !== previousHash) {
      throw new Error(`REPLAY_JOURNAL_CHAIN_BROKEN:${i}`);
    }

    const payload = {
      schema_id: record.schema_id,
      version: record.version,
      event: record.event,
      session_id: record.session_id,
      sequence: record.sequence,
      prev_hash: record.prev_hash
    };

    const calculated = sha256Text(
      canonicalStringify(payload)
    );

    if (
      String(record.record_hash || "").toLowerCase() !==
      calculated
    ) {
      throw new Error(`REPLAY_JOURNAL_HASH_MISMATCH:${i}`);
    }

    previousHash = calculated;
    records.push(record);
  }

  return records;
}

function buildState(records) {
  const sessions = new Map();

  for (const record of records) {
    const sessionId = record.session_id;

    if (
      typeof sessionId !== "string" ||
      !sessionId.length
    ) {
      throw new Error("REPLAY_SESSION_ID_INVALID");
    }

    const current =
      sessions.get(sessionId) ?? 0;

    if (
      !Number.isInteger(record.sequence) ||
      record.sequence < 1
    ) {
      throw new Error("REPLAY_SEQUENCE_INVALID");
    }

    if (record.sequence <= current) {
      throw new Error(
        `REPLAY_SEQUENCE_ROLLBACK:${sessionId}`
      );
    }

    sessions.set(
      sessionId,
      record.sequence
    );
  }

  return sessions;
}

function buildHead(records) {
  return {
    schema_id: "session-continuity.replay.head.v1",
    version: 1,
    height: records.length,
    last_record_hash: records.length
      ? records[records.length - 1].record_hash
      : ""
  };
}

function writeHead(headPath, head) {
  atomicWrite(
    headPath,
    canonicalStringify(head) + "\n"
  );
}

function verifyHead(records, headPath) {
  if (!fs.existsSync(headPath)) {
    throw new Error("REPLAY_HEAD_MISSING");
  }

  let head;

  try {
    head = JSON.parse(
      fs.readFileSync(headPath, "utf8")
    );
  } catch {
    throw new Error("REPLAY_HEAD_INVALID");
  }

  const expected = buildHead(records);

  if (
    Number(head.height) !==
    expected.height
  ) {
    throw new Error("REPLAY_HEAD_HEIGHT_MISMATCH");
  }

  if (
    String(head.last_record_hash || "") !==
    expected.last_record_hash
  ) {
    throw new Error("REPLAY_HEAD_HASH_MISMATCH");
  }

  if (
    head.schema_id !==
    "session-continuity.replay.head.v1"
  ) {
    throw new Error("REPLAY_HEAD_SCHEMA_INVALID");
  }
}

function acquireLock(lockPath, timeoutMs = 3000) {
  const started = Date.now();

  while (true) {
    try {
      const fd = fs.openSync(
        lockPath,
        "wx"
      );

      fs.writeSync(
        fd,
        String(process.pid)
      );

      fs.fsyncSync(fd);
      fs.closeSync(fd);
      return;
    } catch (error) {
      if (error.code !== "EEXIST") {
        throw error;
      }

      if (
        Date.now() - started >=
        timeoutMs
      ) {
        throw new Error(
          "REPLAY_LOCK_TIMEOUT"
        );
      }

      sleepMs(5);
    }
  }
}

function releaseLock(lockPath) {
  try {
    fs.unlinkSync(lockPath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

function appendRecord(
  journalPath,
  record
) {
  const fd = fs.openSync(
    journalPath,
    "a"
  );

  try {
    fs.writeSync(
      fd,
      canonicalStringify(record) +
        "\n",
      null,
      "utf8"
    );

    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function createDurableReplayStore(
  directory
) {
  if (
    typeof directory !== "string" ||
    !directory.length
  ) {
    throw new Error(
      "REPLAY_DIRECTORY_INVALID"
    );
  }

  ensureDir(directory);

  const journalPath = path.join(
    directory,
    "REPLAY_JOURNAL.ndjson"
  );

  const headPath = path.join(
    directory,
    "HEAD.json"
  );

  const lockPath = path.join(
    directory,
    "REPLAY.lock"
  );

  const records =
    loadJournal(journalPath);

  if (
    records.length > 0 ||
    fs.existsSync(headPath)
  ) {
    verifyHead(
      records,
      headPath
    );
  } else {
    writeHead(
      headPath,
      buildHead(records)
    );
  }

  return {
    version: 1,
    directory,
    journalPath,
    headPath,
    lockPath,
    records,
    sessions: buildState(records)
  };
}

function refresh(store) {
  const records =
    loadJournal(store.journalPath);

  verifyHead(
    records,
    store.headPath
  );

  store.records = records;
  store.sessions =
    buildState(records);

  return store.sessions;
}

export function verifyAndAdvance(
  store,
  sessionId,
  presentedSequence
) {
  if (
    typeof sessionId !== "string" ||
    !sessionId.length
  ) {
    return {
      decision: "REAUTH_REQUIRED",
      reason: "REPLAY_SESSION_INVALID"
    };
  }

  if (
    !Number.isInteger(
      presentedSequence
    ) ||
    presentedSequence < 1
  ) {
    return {
      decision: "REAUTH_REQUIRED",
      reason: "INVALID_SEQUENCE"
    };
  }

  acquireLock(
    store.lockPath
  );

  try {
    refresh(store);

    const lastSequence =
      store.sessions.get(
        sessionId
      ) ?? 0;

    if (
      presentedSequence <=
      lastSequence
    ) {
      return {
        decision: "REAUTH_REQUIRED",
        reason: "REPLAY_DETECTED",
        lastSequence,
        presentedSequence
      };
    }

    const previousHash =
      store.records.length
        ? store.records[
            store.records.length - 1
          ].record_hash
        : "";

    const payload = {
      schema_id:
        "session-continuity.replay.event.v1",
      version: 1,
      event: "SEQUENCE_ACCEPTED",
      session_id: sessionId,
      sequence: presentedSequence,
      prev_hash: previousHash
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

    appendRecord(
      store.journalPath,
      record
    );

    const afterAppend =
      loadJournal(
        store.journalPath
      );

    const expectedHead =
      buildHead(afterAppend);

    writeHead(
      store.headPath,
      expectedHead
    );

    refresh(store);

    const persisted =
      store.sessions.get(
        sessionId
      );

    if (
      persisted !==
      presentedSequence
    ) {
      throw new Error(
        "REPLAY_PERSISTENCE_MISMATCH"
      );
    }

    return {
      decision: "CONTINUOUS",
      reason: "SEQUENCE_ACCEPTED",
      lastSequence,
      presentedSequence
    };
  } finally {
    releaseLock(
      store.lockPath
    );
  }
}

export function getLastSequence(
  store,
  sessionId
) {
  refresh(store);

  return (
    store.sessions.get(
      sessionId
    ) ?? 0
  );
}

export function verifyDurableReplayStore(
  store
) {
  refresh(store);

  return {
    verified: true,
    journal_height:
      store.records.length,
    sessions:
      store.sessions.size,
    last_record_hash:
      store.records.length
        ? store.records[
            store.records.length - 1
          ].record_hash
        : ""
  };
}
