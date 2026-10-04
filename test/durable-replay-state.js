import fs from "fs";
import path from "path";
import {
  createDurableReplayStore,
  verifyAndAdvance,
  getLastSequence,
  verifyDurableReplayStore
} from "../src/core/durable-replay-state.js";

const root =
  "E:\\SESSION-CONTINUITY\\test\\fixtures\\durable-replay";

fs.rmSync(root, {
  recursive: true,
  force: true
});

fs.mkdirSync(root, {
  recursive: true
});

const store1 =
  createDurableReplayStore(root);

const first =
  verifyAndAdvance(
    store1,
    "sess-001",
    1
  );

if (
  first.decision !==
  "CONTINUOUS"
) {
  throw new Error(
    "FIRST_SEQUENCE_REJECTED"
  );
}

const replay =
  verifyAndAdvance(
    store1,
    "sess-001",
    1
  );

if (
  replay.decision !==
    "REAUTH_REQUIRED" ||
  replay.reason !==
    "REPLAY_DETECTED"
) {
  throw new Error(
    "REPLAY_ACCEPTED"
  );
}

const second =
  verifyAndAdvance(
    store1,
    "sess-001",
    2
  );

if (
  second.decision !==
  "CONTINUOUS"
) {
  throw new Error(
    "SECOND_SEQUENCE_REJECTED"
  );
}

const store2 =
  createDurableReplayStore(root);

if (
  getLastSequence(
    store2,
    "sess-001"
  ) !== 2
) {
  throw new Error(
    "RESTART_STATE_NOT_RECOVERED"
  );
}

const third =
  verifyAndAdvance(
    store2,
    "sess-001",
    3
  );

if (
  third.decision !==
  "CONTINUOUS"
) {
  throw new Error(
    "POST_RESTART_SEQUENCE_REJECTED"
  );
}

const otherSession =
  verifyAndAdvance(
    store2,
    "sess-002",
    1
  );

if (
  otherSession.decision !==
  "CONTINUOUS"
) {
  throw new Error(
    "SECOND_SESSION_BLOCKED"
  );
}

const state =
  verifyDurableReplayStore(
    store2
  );

if (
  !state.verified ||
  state.journal_height !== 4 ||
  state.sessions !== 2
) {
  throw new Error(
    "REPLAY_STATE_VERIFICATION_FAILED"
  );
}

const journal =
  path.join(
    root,
    "REPLAY_JOURNAL.ndjson"
  );

const head =
  path.join(
    root,
    "HEAD.json"
  );

const originalJournal =
  fs.readFileSync(
    journal,
    "utf8"
  );

const originalHead =
  fs.readFileSync(
    head,
    "utf8"
  );

const prefix =
  originalJournal
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(0, 2)
    .join("\n") + "\n";

fs.writeFileSync(
  journal,
  prefix,
  "utf8"
);

let rollbackDetected =
  false;

try {
  createDurableReplayStore(
    root
  );
} catch (error) {
  rollbackDetected =
    String(error.message) ===
      "REPLAY_HEAD_HEIGHT_MISMATCH" ||
    String(error.message) ===
      "REPLAY_HEAD_HASH_MISMATCH";
}

if (!rollbackDetected) {
  throw new Error(
    "ROLLBACK_NOT_DETECTED"
  );
}

fs.writeFileSync(
  journal,
  originalJournal,
  "utf8"
);

fs.writeFileSync(
  head,
  originalHead,
  "utf8"
);

const restored =
  createDurableReplayStore(
    root
  );

if (
  getLastSequence(
    restored,
    "sess-001"
  ) !== 3
) {
  throw new Error(
    "RESTORE_AFTER_ROLLBACK_TEST_FAILED"
  );
}

fs.appendFileSync(
  journal,
  '{"schema_id":"session-continuity.replay.event.v1"'
);

let corruptionDetected =
  false;

try {
  createDurableReplayStore(
    root
  );
} catch {
  corruptionDetected = true;
}

if (!corruptionDetected) {
  throw new Error(
    "JOURNAL_CORRUPTION_NOT_DETECTED"
  );
}

fs.writeFileSync(
  journal,
  originalJournal,
  "utf8"
);

fs.writeFileSync(
  head,
  originalHead,
  "utf8"
);

const lockPath =
  path.join(
    root,
    "REPLAY.lock"
  );

fs.writeFileSync(
  lockPath,
  String(process.pid),
  "utf8"
);

let lockTimeoutDetected =
  false;

try {
  verifyAndAdvance(
    createDurableReplayStore(
      root
    ),
    "sess-003",
    1
  );
} catch (error) {
  lockTimeoutDetected =
    String(error.message) ===
    "REPLAY_LOCK_TIMEOUT";
}

fs.unlinkSync(
  lockPath
);

if (!lockTimeoutDetected) {
  throw new Error(
    "LOCK_CONTENTION_NOT_DETECTED"
  );
}

const recovered =
  createDurableReplayStore(
    root
  );

if (
  getLastSequence(
    recovered,
    "sess-001"
  ) !== 3
) {
  throw new Error(
    "FINAL_RECOVERY_FAILED"
  );
}

console.log(
  "DURABLE_REPLAY_FIRST=PASS"
);
console.log(
  "DURABLE_REPLAY_DETECTION=PASS"
);
console.log(
  "DURABLE_RESTART_RECOVERY=PASS"
);
console.log(
  "DURABLE_MULTI_SESSION=PASS"
);
console.log(
  "ROLLBACK_DETECTION=PASS"
);
console.log(
  "JOURNAL_CORRUPTION_DETECTION=PASS"
);
console.log(
  "LOCK_CONTENTION_DETECTION=PASS"
);
console.log(
  "DURABLE_REPLAY_STATE=PASS"
);
