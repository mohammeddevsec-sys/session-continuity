import fs from "fs";
import path from "path";
import crypto from "crypto";
import { canonicalStringify } from "./canonical.js";

function sha256Text(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex").toLowerCase();
}

function randomChallenge() {
  return crypto.randomBytes(32).toString("base64url");
}

function sleepMs(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {}
}

function atomicWrite(filePath, text) {
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, text, null, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
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
        throw new Error("SECURE_STATE_LOCK_TIMEOUT");
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
      throw new Error(`SECURE_STATE_JSON_INVALID:${i}`);
    }

    if (!record || typeof record !== "object") {
      throw new Error(`SECURE_STATE_RECORD_INVALID:${i}`);
    }

    if (String(record.prev_hash || "") !== previousHash) {
      throw new Error(`SECURE_STATE_CHAIN_BROKEN:${i}`);
    }

    const payload = {
      schema_id: record.schema_id,
      version: record.version,
      event: record.event,
      challenge: record.challenge ?? null,
      session_id: record.session_id ?? null,
      sequence: record.sequence ?? null,
      issued_at: record.issued_at ?? null,
      expires_at: record.expires_at ?? null,
      accepted_at: record.accepted_at ?? null,
      prev_hash: record.prev_hash
    };

    const calculated = sha256Text(canonicalStringify(payload));

    if (String(record.record_hash || "").toLowerCase() !== calculated) {
      throw new Error(`SECURE_STATE_HASH_MISMATCH:${i}`);
    }

    previousHash = calculated;
    records.push(record);
  }

  return records;
}

function buildState(records) {
  const challenges = new Map();
  const sessions = new Map();

  for (const record of records) {
    if (record.event === "CHALLENGE_ISSUED") {
      const challenge = String(record.challenge || "");
      const sessionId = String(record.session_id || "");

      if (!challenge || !sessionId) {
        throw new Error("SECURE_STATE_CHALLENGE_INVALID");
      }

      if (challenges.has(challenge)) {
        throw new Error("SECURE_STATE_DUPLICATE_CHALLENGE");
      }

      if (
        !Number.isInteger(record.issued_at) ||
        !Number.isInteger(record.expires_at) ||
        record.expires_at < record.issued_at
      ) {
        throw new Error("SECURE_STATE_CHALLENGE_TIME_INVALID");
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

    if (record.event === "SESSION_ACCEPTED") {
      const challenge = String(record.challenge || "");
      const sessionId = String(record.session_id || "");
      const sequence = Number(record.sequence);

      const state = challenges.get(challenge);

      if (!state) {
        throw new Error("SECURE_STATE_ACCEPT_WITHOUT_CHALLENGE");
      }

      if (state.sessionId !== sessionId) {
        throw new Error("SECURE_STATE_CHALLENGE_SESSION_MISMATCH");
      }

      if (state.consumed) {
        throw new Error("SECURE_STATE_DOUBLE_ACCEPT");
      }

      if (!Number.isInteger(sequence) || sequence < 1) {
        throw new Error("SECURE_STATE_SEQUENCE_INVALID");
      }

      const lastSequence = sessions.get(sessionId) ?? 0;

      if (sequence <= lastSequence) {
        throw new Error("SECURE_STATE_SEQUENCE_ROLLBACK");
      }

      if (!Number.isInteger(record.accepted_at)) {
        throw new Error("SECURE_STATE_ACCEPTED_TIME_INVALID");
      }

      state.consumed = true;
      state.consumedAt = record.accepted_at;
      sessions.set(sessionId, sequence);

      continue;
    }

    throw new Error(`SECURE_STATE_EVENT_UNKNOWN:${record.event}`);
  }

  return { challenges, sessions };
}

function buildHead(records) {
  return {
    schema_id: "session-continuity.secure-state.head.v1",
    version: 1,
    height: records.length,
    last_record_hash: records.length
      ? records[records.length - 1].record_hash
      : ""
  };
}

function verifyHead(records, headPath) {
  if (!fs.existsSync(headPath)) {
    throw new Error("SECURE_STATE_HEAD_MISSING");
  }

  let head;

  try {
    head = JSON.parse(fs.readFileSync(headPath, "utf8"));
  } catch {
    throw new Error("SECURE_STATE_HEAD_INVALID");
  }

  const expected = buildHead(records);

  if (head.schema_id !== expected.schema_id) {
    throw new Error("SECURE_STATE_HEAD_SCHEMA_INVALID");
  }

  if (Number(head.height) !== expected.height) {
    throw new Error("SECURE_STATE_HEAD_HEIGHT_MISMATCH");
  }

  if (String(head.last_record_hash || "") !== expected.last_record_hash) {
    throw new Error("SECURE_STATE_HEAD_HASH_MISMATCH");
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

  record.record_hash = sha256Text(canonicalStringify(record));

  const fd = fs.openSync(journalPath, "a");

  try {
    fs.writeSync(fd, canonicalStringify(record) + "\n", null, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  return record;
}

export function createSecureSessionState(directory, defaultTtlMs = 60000) {
  if (typeof directory !== "string" || !directory.length) {
    throw new Error("SECURE_STATE_DIRECTORY_INVALID");
  }

  if (!Number.isInteger(defaultTtlMs) || defaultTtlMs < 1) {
    throw new Error("SECURE_STATE_TTL_INVALID");
  }

  fs.mkdirSync(directory, { recursive: true });

  const journalPath = path.join(directory, "SESSION_SECURITY_JOURNAL.ndjson");
  const headPath = path.join(directory, "HEAD.json");
  const lockPath = path.join(directory, "SESSION_SECURITY.lock");

  const records = loadJournal(journalPath);

  if (records.length || fs.existsSync(headPath)) {
    verifyHead(records, headPath);
  } else {
    atomicWrite(headPath, canonicalStringify(buildHead(records)) + "\n");
  }

  return {
    version: 1,
    directory,
    journalPath,
    headPath,
    lockPath,
    defaultTtlMs,
    records,
    ...buildState(records)
  };
}

function refresh(store) {
  const records = loadJournal(store.journalPath);
  verifyHead(records, store.headPath);

  const state = buildState(records);

  store.records = records;
  store.challenges = state.challenges;
  store.sessions = state.sessions;

  return state;
}

function persistHead(store) {
  const records = loadJournal(store.journalPath);
  atomicWrite(store.headPath, canonicalStringify(buildHead(records)) + "\n");
}

export function issueChallenge(store, sessionId, nowMs = Date.now(), ttlMs = store.defaultTtlMs) {
  if (typeof sessionId !== "string" || !sessionId.length) {
    throw new Error("SECURE_STATE_SESSION_INVALID");
  }

  if (!Number.isInteger(nowMs) || nowMs < 0) {
    throw new Error("SECURE_STATE_NOW_INVALID");
  }

  if (!Number.isInteger(ttlMs) || ttlMs < 1) {
    throw new Error("SECURE_STATE_TTL_INVALID");
  }

  acquireLock(store.lockPath);

  try {
    refresh(store);

    let challenge;

    do {
      challenge = randomChallenge();
    } while (store.challenges.has(challenge));

    appendRecord(store.journalPath, {
      schema_id: "session-continuity.secure-state.event.v1",
      version: 1,
      event: "CHALLENGE_ISSUED",
      challenge,
      session_id: sessionId,
      sequence: null,
      issued_at: nowMs,
      expires_at: nowMs + ttlMs,
      accepted_at: null
    });

    persistHead(store);
    refresh(store);

    return Object.freeze({
      challenge,
      sessionId,
      issuedAt: nowMs,
      expiresAt: nowMs + ttlMs
    });
  } finally {
    releaseLock(store.lockPath);
  }
}

export function commitSessionAcceptance(store, sessionId, sequence, challenge, nowMs = Date.now()) {
  if (typeof sessionId !== "string" || !sessionId.length) {
    return { decision: "REAUTH_REQUIRED", reason: "SECURE_STATE_SESSION_INVALID" };
  }

  if (!Number.isInteger(sequence) || sequence < 1) {
    return { decision: "REAUTH_REQUIRED", reason: "INVALID_SEQUENCE" };
  }

  if (typeof challenge !== "string" || !challenge.length) {
    return { decision: "REAUTH_REQUIRED", reason: "CHALLENGE_INVALID" };
  }

  if (!Number.isInteger(nowMs) || nowMs < 0) {
    return { decision: "REAUTH_REQUIRED", reason: "NOW_INVALID" };
  }

  acquireLock(store.lockPath);

  try {
    refresh(store);

    const lastSequence = store.sessions.get(sessionId) ?? 0;

    if (sequence <= lastSequence) {
      return {
        decision: "REAUTH_REQUIRED",
        reason: "REPLAY_DETECTED",
        lastSequence,
        presentedSequence: sequence
      };
    }

    const challengeState = store.challenges.get(challenge);

    if (!challengeState) {
      return {
        decision: "REAUTH_REQUIRED",
        reason: "CHALLENGE_UNKNOWN"
      };
    }

    if (challengeState.sessionId !== sessionId) {
      return {
        decision: "REAUTH_REQUIRED",
        reason: "CHALLENGE_SESSION_MISMATCH"
      };
    }

    if (challengeState.consumed) {
      return {
        decision: "REAUTH_REQUIRED",
        reason: "CHALLENGE_ALREADY_CONSUMED"
      };
    }

    if (nowMs > challengeState.expiresAt) {
      return {
        decision: "REAUTH_REQUIRED",
        reason: "CHALLENGE_EXPIRED"
      };
    }

    appendRecord(store.journalPath, {
      schema_id: "session-continuity.secure-state.event.v1",
      version: 1,
      event: "SESSION_ACCEPTED",
      challenge,
      session_id: sessionId,
      sequence,
      issued_at: challengeState.issuedAt,
      expires_at: challengeState.expiresAt,
      accepted_at: nowMs
    });

    persistHead(store);
    refresh(store);

    if (store.sessions.get(sessionId) !== sequence) {
      throw new Error("SECURE_STATE_COMMIT_PERSISTENCE_MISMATCH");
    }

    const persistedChallenge = store.challenges.get(challenge);

    if (
      !persistedChallenge ||
      !persistedChallenge.consumed ||
      persistedChallenge.consumedAt !== nowMs
    ) {
      throw new Error("SECURE_STATE_CHALLENGE_PERSISTENCE_MISMATCH");
    }

    return {
      decision: "CONTINUOUS",
      reason: "SECURE_CONTINUITY_COMMITTED",
      lastSequence,
      presentedSequence: sequence
    };
  } finally {
    releaseLock(store.lockPath);
  }
}

export function verifySecureSessionState(store) {
  refresh(store);

  return {
    verified: true,
    journal_height: store.records.length,
    sessions: store.sessions.size,
    active_challenges: [...store.challenges.values()].filter(x => !x.consumed).length,
    last_record_hash: store.records.length
      ? store.records[store.records.length - 1].record_hash
      : ""
  };
}
