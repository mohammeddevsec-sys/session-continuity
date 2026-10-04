import { createReplayState, verifySequence, advanceReplayState } from "../src/core/replay-guard.js";

let state = createReplayState();

const first = advanceReplayState(state, 1);
state = first.state;

const replay = verifySequence(state, 1);

const next = advanceReplayState(state, 2);
state = next.state;

const old = verifySequence(state, 1);

console.log("FIRST_SEQUENCE=", JSON.stringify(first.result));
console.log("REPLAY_SEQUENCE=", JSON.stringify(replay));
console.log("NEXT_SEQUENCE=", JSON.stringify(next.result));
console.log("OLD_SEQUENCE=", JSON.stringify(old));

if (
  first.result.decision !== "CONTINUOUS" ||
  replay.decision !== "REAUTH_REQUIRED" ||
  replay.reason !== "REPLAY_DETECTED" ||
  next.result.decision !== "CONTINUOUS" ||
  old.decision !== "REAUTH_REQUIRED"
) process.exit(1);

console.log("REPLAY_GUARD_RESULT=PASS");
