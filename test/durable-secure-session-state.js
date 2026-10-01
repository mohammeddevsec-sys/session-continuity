import fs from "fs";
import path from "path";
import {
  createSecureSessionState,
  issueChallenge,
  commitSessionAcceptance,
  verifySecureSessionState
} from "../src/core/durable-secure-session-state.js";

const root = "E:\\SESSION-CONTINUITY\\test\\fixtures\\durable-secure-session";
fs.rmSync(root, { recursive: true, force: true });

const state1 = createSecureSessionState(root, 60000);

const first = issueChallenge(state1, "sess-001", 100000);

const accepted = commitSessionAcceptance(
  state1,
  "sess-001",
  1,
  first.challenge,
  100001
);

if (accepted.decision !== "CONTINUOUS") {
  throw new Error("ATOMIC_ACCEPT_FAILED");
}

const replay = commitSessionAcceptance(
  state1,
  "sess-001",
  1,
  first.challenge,
  100002
);

if (
  replay.decision !== "REAUTH_REQUIRED" ||
  replay.reason !== "REPLAY_DETECTED"
) {
  throw new Error("REPLAY_ACCEPTED");
}

const secondChallenge = issueChallenge(
  state1,
  "sess-001",
  200000
);

const wrongSession = commitSessionAcceptance(
  state1,
  "sess-002",
  2,
  secondChallenge.challenge,
  200001
);

if (
  wrongSession.decision !== "REAUTH_REQUIRED" ||
  wrongSession.reason !== "CHALLENGE_SESSION_MISMATCH"
) {
  throw new Error("CROSS_SESSION_ACCEPTED");
}

const sequenceBlockedChallenge = issueChallenge(
  state1,
  "sess-001",
  300000
);

const sequenceReplay = commitSessionAcceptance(
  state1,
  "sess-001",
  1,
  sequenceBlockedChallenge.challenge,
  300001
);

if (
  sequenceReplay.decision !== "REAUTH_REQUIRED" ||
  sequenceReplay.reason !== "REPLAY_DETECTED"
) {
  throw new Error("SEQUENCE_REPLAY_NOT_BLOCKED");
}

const reuseAfterSequenceReject = commitSessionAcceptance(
  state1,
  "sess-001",
  2,
  sequenceBlockedChallenge.challenge,
  300002
);

if (reuseAfterSequenceReject.decision !== "CONTINUOUS") {
  throw new Error("CHALLENGE_CONSUMED_BY_REJECTED_SEQUENCE");
}

const expiredChallenge = issueChallenge(
  state1,
  "sess-001",
  400000,
  60000
);

const expired = commitSessionAcceptance(
  state1,
  "sess-001",
  3,
  expiredChallenge.challenge,
  460001
);

if (
  expired.decision !== "REAUTH_REQUIRED" ||
  expired.reason !== "CHALLENGE_EXPIRED"
) {
  throw new Error("EXPIRED_CHALLENGE_ACCEPTED");
}

const restarted = createSecureSessionState(root, 60000);

if (!verifySecureSessionState(restarted).verified) {
  throw new Error("RESTART_STATE_INVALID");
}

const recoveredSequenceReplay = commitSessionAcceptance(
  restarted,
  "sess-001",
  2,
  secondChallenge.challenge,
  200003
);

if (
  recoveredSequenceReplay.decision !== "REAUTH_REQUIRED" ||
  recoveredSequenceReplay.reason !== "REPLAY_DETECTED"
) {
  throw new Error("STATE_RECOVERY_INCONSISTENT");
}

const freshAfterRestart = issueChallenge(
  restarted,
  "sess-001",
  500000
);

const acceptedAfterRestart = commitSessionAcceptance(
  restarted,
  "sess-001",
  3,
  freshAfterRestart.challenge,
  500001
);

if (acceptedAfterRestart.decision !== "CONTINUOUS") {
  throw new Error("POST_RESTART_ACCEPT_FAILED");
}

const journal = path.join(root, "SESSION_SECURITY_JOURNAL.ndjson");
const head = path.join(root, "HEAD.json");

const originalJournal = fs.readFileSync(journal, "utf8");
const originalHead = fs.readFileSync(head, "utf8");

fs.writeFileSync(
  journal,
  originalJournal
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(0, 1)
    .join("\n") + "\n",
  "utf8"
);

let rollbackDetected = false;

try {
  createSecureSessionState(root, 60000);
} catch (error) {
  rollbackDetected =
    String(error.message) === "SECURE_STATE_HEAD_HEIGHT_MISMATCH" ||
    String(error.message) === "SECURE_STATE_HEAD_HASH_MISMATCH";
}

if (!rollbackDetected) {
  throw new Error("ROLLBACK_NOT_DETECTED");
}

fs.writeFileSync(journal, originalJournal, "utf8");
fs.writeFileSync(head, originalHead, "utf8");

fs.appendFileSync(
  journal,
  '{"schema_id":"session-continuity.secure-state.event.v1"'
);

let corruptionDetected = false;

try {
  createSecureSessionState(root, 60000);
} catch {
  corruptionDetected = true;
}

if (!corruptionDetected) {
  throw new Error("CORRUPTION_NOT_DETECTED");
}

fs.writeFileSync(journal, originalJournal, "utf8");
fs.writeFileSync(head, originalHead, "utf8");

const lockPath = path.join(root, "SESSION_SECURITY.lock");
fs.writeFileSync(lockPath, String(process.pid), "utf8");

let lockDetected = false;

try {
  issueChallenge(
    createSecureSessionState(root, 60000),
    "sess-003",
    600000
  );
} catch (error) {
  lockDetected =
    String(error.message) === "SECURE_STATE_LOCK_TIMEOUT";
}

fs.unlinkSync(lockPath);

if (!lockDetected) {
  throw new Error("LOCK_CONTENTION_NOT_DETECTED");
}

const finalState = createSecureSessionState(root, 60000);

if (!verifySecureSessionState(finalState).verified) {
  throw new Error("FINAL_STATE_RECOVERY_FAILED");
}

console.log("ATOMIC_SESSION_ACCEPT=PASS");
console.log("REPLAY_REJECTED=PASS");
console.log("CROSS_SESSION_REJECTED=PASS");
console.log("SEQUENCE_REPLAY_REJECTED=PASS");
console.log("CHALLENGE_NOT_CONSUMED_ON_SEQUENCE_FAILURE=PASS");
console.log("EXPIRED_CHALLENGE_REJECTED=PASS");
console.log("RESTART_RECOVERY=PASS");
console.log("STATE_REPLAY_RECOVERY=PASS");
console.log("POST_RESTART_ACCEPT=PASS");
console.log("ROLLBACK_DETECTION=PASS");
console.log("CORRUPTION_DETECTION=PASS");
console.log("LOCK_CONTENTION_DETECTION=PASS");
console.log("DURABLE_SECURE_SESSION_STATE=PASS");
