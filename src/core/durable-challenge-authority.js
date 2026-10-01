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

function randomChallenge() {
  return crypto.randomBytes(32).toString("base64url");
}

function sleepMs(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {}
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
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

function acquireLock(lockPath, timeoutMs = 3000) {
  const started = Date.now();

  while (true) {
    try {
      const fd = fs.openSync(lockPath, "wx");
      fs.writeSync(fd, String(process.pid));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      return;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;

      if (Date.now() - started >= timeoutMs) {
        throw new Error("CHALLENGE_LOCK_TIMEOUT");
      }

      sleepMs(5);
    }
  }
}

function releaseLock(lockPath) {
  try {
    fs.unlinkSync(lockPath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function loadJournal(journalPath) {
  if (!fs.existsSync(journalPath)) return [];

  const raw = fs.readFileSync(journalPath, "utf8");
  if (!raw.length) return [];

  const lines = raw.split(/\r?\n/).filter(Boolean);
  const records = [];
  let previousHash = "";

  for (let i = 0; i < lines.length; i++) {
    let record;

    try {
      record = JSON.parse(lines[i]);
    } catch {
      throw new Error(`CHALLENGE_JOURNAL_JSON_INVALID:${i}`);
    }

    if (!record || typeof record !== "object") {
      throw new Error(`CHALLENGE_JOURNAL_RECORD_INVALID:${i}`);
    }

    if (String(record.prev_hash || "") !== previousHash) {
      throw new Error(`CHALLENGE_JOURNAL_CHAIN_BROKEN:${i}`);
    }

    const payload = {
      schema_id: record.schema_id,
      version: record.version,
      event: record.event,
      challenge: record.challenge,
      session_id: record.session_id,
      issued_at: record.issued_at ?? null,
      expires_at: record.expires_at ?? null,
      consumed_at: record.consumed_at ?? null,
      prev_hash: record.prev_hash
    };

    const calculated = sha256Text(canonicalStringify(payload));

    if (String(record.record_hash || "").toLowerCase() !== calculated) {
      throw new Error(`CHALLENGE_JOURNAL_HASH_MISMATCH:${i}`);
    }

    previousHash = calculated;
    records.push(record);
  }

  return records;
}

function buildState(records) {
  const challenges = new Map();

  for (const record of records) {
    const challenge = String(record.challenge || "");
    const sessionId = String(record.session_id || "");

    if (!challenge || !sessionId) {
      throw new Error("CHALLENGE_RECORD_INVALID");
    }

    if (
      !Number.isInteger(record.issued_at) ||
      !Number.isInteger(record.expires_at) ||
      record.expires_at < record.issued_at
    ) {
      throw new Error("CHALLENGE_TIME_INVALID");
    }

    if (record.event === "CHALLENGE_ISSUED") {
      if (challenges.has(challenge)) {
        throw new Error("CHALLENGE_DUPLICATE_ISSUE");
      }

      challenges.set(challenge, {
        sessionId,
        issuedAt: record.issued_at,
        expiresAt: record.expires_at,
        consumed: false,
        consumedAt: null
      });

      continue;
    }

    if (record.event === "CHALLENGE_CONSUMED") {
      const state = challenges.get(challenge);

      if (!state) {
        throw new Error("CHALLENGE_CONSUME_WITHOUT_ISSUE");
      }

      if (state.sessionId !== sessionId) {
        throw new Error("CHALLENGE_CONSUME_SESSION_MISMATCH");
      }

      if (state.consumed) {
        throw new Error("CHALLENGE_DOUBLE_CONSUME");
      }

      if (!Number.isInteger(record.consumed_at)) {
        throw new Error("CHALLENGE_CONSUMED_TIME_INVALID");
      }

      state.consumed = true;
      state.consumedAt = record.consumed_at;
      continue;
    }

    throw new Error(`CHALLENGE_EVENT_UNKNOWN:${record.event}`);
  }

  return challenges;
}

function buildHead(records) {
  return {
    schema_id: "session-continuity.challenge.head.v1",
    version: 1,
    height: records.length,
    last_record_hash: records.length
      ? records[records.length - 1].record_hash
      : ""
  };
}

function verifyHead(records, headPath) {
  if (!fs.existsSync(headPath)) {
    throw new Error("CHALLENGE_HEAD_MISSING");
  }

  let head;

  try {
    head = JSON.parse(fs.readFileSync(headPath, "utf8"));
  } catch {
    throw new Error("CHALLENGE_HEAD_INVALID");
  }

  const expected = buildHead(records);

  if (head.schema_id !== expected.schema_id) {
    throw new Error("CHALLENGE_HEAD_SCHEMA_INVALID");
  }

  if (Number(head.height) !== expected.height) {
    throw new Error("CHALLENGE_HEAD_HEIGHT_MISMATCH");
  }

  if (String(head.last_record_hash || "") !== expected.last_record_hash) {
    throw new Error("CHALLENGE_HEAD_HASH_MISMATCH");
  }
}

function appendRecord(journalPath, payload) {
  const records = loadJournal(journalPath);
  const prevHash = records.length
    ? records[records.length - 1].record_hash
    : "";

  const record = {
    ...payload,
    prev_hash: prevHash
  };

  record.record_hash = sha256Text(
    canonicalStringify(record)
  );

  const fd = fs.openSync(journalPath, "a");

  try {
    fs.writeSync(
      fd,
      canonicalStringify(record) + "\n",
      null,
      "utf8"
    );

    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  return record;
}

export function createDurableChallengeAuthority(
  directory,
  defaultTtlMs = 60000
) {
  if (
    typeof directory !== "string" ||
    !directory.length
  ) {
    throw new Error("CHALLENGE_DIRECTORY_INVALID");
  }

  if (
    !Number.isInteger(defaultTtlMs) ||
    defaultTtlMs < 1
  ) {
    throw new Error("CHALLENGE_TTL_INVALID");
  }

  ensureDir(directory);

  const journalPath =
    path.join(directory, "CHALLENGE_JOURNAL.ndjson");

  const headPath =
    path.join(directory, "HEAD.json");

  const lockPath =
    path.join(directory, "CHALLENGE.lock");

  const records = loadJournal(journalPath);

  if (
    records.length ||
    fs.existsSync(headPath)
  ) {
    verifyHead(records, headPath);
  } else {
    atomicWrite(
      headPath,
      canonicalStringify(buildHead(records)) + "\n"
    );
  }

  return {
    version: 1,
    directory,
    journalPath,
    headPath,
    lockPath,
    defaultTtlMs,
    records,
    challenges: buildState(records)
  };
}

function refresh(store) {
  const records = loadJournal(store.journalPath);

  verifyHead(
    records,
    store.headPath
  );

  store.records = records;
  store.challenges = buildState(records);

  return store.challenges;
}

function persistHead(store) {
  const records = loadJournal(store.journalPath);

  atomicWrite(
    store.headPath,
    canonicalStringify(buildHead(records)) + "\n"
  );
}

export function issueDurableChallenge(
  store,
  sessionId,
  nowMs = Date.now(),
  ttlMs = store.defaultTtlMs
) {
  if (
    typeof sessionId !== "string" ||
    !sessionId.length
  ) {
    throw new Error("CHALLENGE_SESSION_INVALID");
  }

  if (
    !Number.isInteger(nowMs) ||
    nowMs < 0
  ) {
    throw new Error("CHALLENGE_NOW_INVALID");
  }

  if (
    !Number.isInteger(ttlMs) ||
    ttlMs < 1
  ) {
    throw new Error("CHALLENGE_TTL_INVALID");
  }

  acquireLock(store.lockPath);

  try {
    refresh(store);

    let challenge;

    do {
      challenge = randomChallenge();
    } while (
      store.challenges.has(challenge)
    );

    const issuedAt = nowMs;
    const expiresAt = nowMs + ttlMs;

    appendRecord(
      store.journalPath,
      {
        schema_id:
          "session-continuity.challenge.event.v1",
        version: 1,
        event: "CHALLENGE_ISSUED",
        challenge,
        session_id: sessionId,
        issued_at: issuedAt,
        expires_at: expiresAt,
        consumed_at: null
      }
    );

    persistHead(store);
    refresh(store);

    const state =
      store.challenges.get(challenge);

    if (
      !state ||
      state.sessionId !== sessionId ||
      state.issuedAt !== issuedAt ||
      state.expiresAt !== expiresAt
    ) {
      throw new Error(
        "CHALLENGE_PERSISTENCE_MISMATCH"
      );
    }

    return Object.freeze({
      challenge,
      sessionId,
      issuedAt,
      expiresAt
    });
  } finally {
    releaseLock(store.lockPath);
  }
}

export function consumeDurableChallenge(
  store,
  challenge,
  sessionId,
  nowMs = Date.now()
) {
  if (
    typeof challenge !== "string" ||
    !challenge.length
  ) {
    return {
      accepted: false,
      reason: "CHALLENGE_INVALID"
    };
  }

  if (
    typeof sessionId !== "string" ||
    !sessionId.length
  ) {
    return {
      accepted: false,
      reason: "CHALLENGE_SESSION_INVALID"
    };
  }

  if (
    !Number.isInteger(nowMs) ||
    nowMs < 0
  ) {
    return {
      accepted: false,
      reason: "CHALLENGE_NOW_INVALID"
    };
  }

  acquireLock(store.lockPath);

  try {
    refresh(store);

    const state =
      store.challenges.get(challenge);

    if (!state) {
      return {
        accepted: false,
        reason: "CHALLENGE_UNKNOWN"
      };
    }

    if (state.sessionId !== sessionId) {
      return {
        accepted: false,
        reason: "CHALLENGE_SESSION_MISMATCH"
      };
    }

    if (state.consumed) {
      return {
        accepted: false,
        reason: "CHALLENGE_ALREADY_CONSUMED"
      };
    }

    if (nowMs > state.expiresAt) {
      return {
        accepted: false,
        reason: "CHALLENGE_EXPIRED"
      };
    }

    appendRecord(
      store.journalPath,
      {
        schema_id:
          "session-continuity.challenge.event.v1",
        version: 1,
        event: "CHALLENGE_CONSUMED",
        challenge,
        session_id: sessionId,
        issued_at: state.issuedAt,
        expires_at: state.expiresAt,
        consumed_at: nowMs
      }
    );

    persistHead(store);
    refresh(store);

    const persisted =
      store.challenges.get(challenge);

    if (
      !persisted ||
      !persisted.consumed ||
      persisted.consumedAt !== nowMs
    ) {
      throw new Error(
        "CHALLENGE_CONSUME_PERSISTENCE_MISMATCH"
      );
    }

    return {
      accepted: true,
      reason: "CHALLENGE_ACCEPTED",
      issuedAt: state.issuedAt,
      consumedAt: nowMs,
      expiresAt: state.expiresAt
    };
  } finally {
    releaseLock(store.lockPath);
  }
}

export function verifyDurableChallengeAuthority(
  store
) {
  refresh(store);

  return {
    verified: true,
    journal_height: store.records.length,
    active_challenges: [...store.challenges.values()]
      .filter(x => !x.consumed).length
  };
}
