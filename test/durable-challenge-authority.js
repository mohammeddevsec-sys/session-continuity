import fs from "fs";
import path from "path";
import {
  createDurableChallengeAuthority,
  issueDurableChallenge,
  consumeDurableChallenge,
  verifyDurableChallengeAuthority
} from "../src/core/durable-challenge-authority.js";

const root =
  "E:\\SESSION-CONTINUITY\\test\\fixtures\\durable-challenge";

fs.rmSync(root, {
  recursive: true,
  force: true
});

fs.mkdirSync(root, {
  recursive: true
});

const authority1 =
  createDurableChallengeAuthority(
    root,
    60000
  );

const first =
  issueDurableChallenge(
    authority1,
    "sess-001",
    100000
  );

const accepted =
  consumeDurableChallenge(
    authority1,
    first.challenge,
    "sess-001",
    100001
  );

if (!accepted.accepted) {
  throw new Error(
    "FIRST_CHALLENGE_REJECTED"
  );
}

const replay =
  consumeDurableChallenge(
    authority1,
    first.challenge,
    "sess-001",
    100002
  );

if (
  replay.accepted ||
  replay.reason !==
    "CHALLENGE_ALREADY_CONSUMED"
) {
  throw new Error(
    "CHALLENGE_REPLAY_ACCEPTED"
  );
}

const second =
  issueDurableChallenge(
    authority1,
    "sess-001",
    200000
  );

const wrongSession =
  consumeDurableChallenge(
    authority1,
    second.challenge,
    "sess-002",
    200001
  );

if (
  wrongSession.accepted ||
  wrongSession.reason !==
    "CHALLENGE_SESSION_MISMATCH"
) {
  throw new Error(
    "CROSS_SESSION_CHALLENGE_ACCEPTED"
  );
}

const expired =
  issueDurableChallenge(
    authority1,
    "sess-001",
    300000,
    60000
  );

const expiredResult =
  consumeDurableChallenge(
    authority1,
    expired.challenge,
    "sess-001",
    360001
  );

if (
  expiredResult.accepted ||
  expiredResult.reason !==
    "CHALLENGE_EXPIRED"
) {
  throw new Error(
    "EXPIRED_CHALLENGE_ACCEPTED"
  );
}

const authority2 =
  createDurableChallengeAuthority(
    root,
    60000
  );

const recovered =
  verifyDurableChallengeAuthority(
    authority2
  );

if (
  !recovered.verified ||
  recovered.active_challenges !== 2
) {
  throw new Error(
    "CHALLENGE_RESTART_RECOVERY_FAILED"
  );
}

const recoveredConsumed =
  consumeDurableChallenge(
    authority2,
    first.challenge,
    "sess-001",
    100003
  );

if (
  recoveredConsumed.accepted ||
  recoveredConsumed.reason !==
    "CHALLENGE_ALREADY_CONSUMED"
) {
  throw new Error(
    "CONSUMED_CHALLENGE_REVIVED_AFTER_RESTART"
  );
}

const third =
  issueDurableChallenge(
    authority2,
    "sess-002",
    400000
  );

const thirdAccepted =
  consumeDurableChallenge(
    authority2,
    third.challenge,
    "sess-002",
    400001
  );

if (!thirdAccepted.accepted) {
  throw new Error(
    "POST_RESTART_CHALLENGE_FAILED"
  );
}

const journal =
  path.join(
    root,
    "CHALLENGE_JOURNAL.ndjson"
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
    .slice(0, 1)
    .join("\n") + "\n";

fs.writeFileSync(
  journal,
  prefix,
  "utf8"
);

let rollbackDetected =
  false;

try {
  createDurableChallengeAuthority(
    root,
    60000
  );
} catch (error) {
  rollbackDetected =
    String(error.message) ===
      "CHALLENGE_HEAD_HEIGHT_MISMATCH" ||
    String(error.message) ===
      "CHALLENGE_HEAD_HASH_MISMATCH";
}

if (!rollbackDetected) {
  throw new Error(
    "CHALLENGE_ROLLBACK_NOT_DETECTED"
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

fs.appendFileSync(
  journal,
  '{"schema_id":"session-continuity.challenge.event.v1"'
);

let corruptionDetected =
  false;

try {
  createDurableChallengeAuthority(
    root,
    60000
  );
} catch {
  corruptionDetected = true;
}

if (!corruptionDetected) {
  throw new Error(
    "CHALLENGE_CORRUPTION_NOT_DETECTED"
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
    "CHALLENGE.lock"
  );

fs.writeFileSync(
  lockPath,
  String(process.pid),
  "utf8"
);

let lockDetected =
  false;

try {
  consumeDurableChallenge(
    createDurableChallengeAuthority(
      root,
      60000
    ),
    third.challenge,
    "sess-002",
    400002
  );
} catch (error) {
  lockDetected =
    String(error.message) ===
    "CHALLENGE_LOCK_TIMEOUT";
}

fs.unlinkSync(lockPath);

if (!lockDetected) {
  throw new Error(
    "CHALLENGE_LOCK_CONTENTION_NOT_DETECTED"
  );
}

const finalAuthority =
  createDurableChallengeAuthority(
    root,
    60000
  );

const finalState =
  verifyDurableChallengeAuthority(
    finalAuthority
  );

if (!finalState.verified) {
  throw new Error(
    "FINAL_CHALLENGE_RECOVERY_FAILED"
  );
}

console.log(
  "DURABLE_CHALLENGE_FIRST=PASS"
);
console.log(
  "DURABLE_CHALLENGE_REPLAY_REJECTED=PASS"
);
console.log(
  "CROSS_SESSION_CHALLENGE_REJECTED=PASS"
);
console.log(
  "EXPIRED_CHALLENGE_REJECTED=PASS"
);
console.log(
  "DURABLE_CHALLENGE_RESTART_RECOVERY=PASS"
);
console.log(
  "CHALLENGE_ROLLBACK_DETECTION=PASS"
);
console.log(
  "CHALLENGE_CORRUPTION_DETECTION=PASS"
);
console.log(
  "CHALLENGE_LOCK_CONTENTION_DETECTION=PASS"
);
console.log(
  "DURABLE_CHALLENGE_AUTHORITY=PASS"
);
