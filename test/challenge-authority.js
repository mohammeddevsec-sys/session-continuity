import {
  createChallengeAuthority,
  issueChallenge,
  consumeChallenge
} from "../src/core/challenge-authority.js";

const authority = createChallengeAuthority();

const first = issueChallenge(
  authority,
  "sess-001",
  100000
);

const accepted = consumeChallenge(
  authority,
  first.challenge,
  "sess-001",
  100001,
  60000
);

if (!accepted.accepted) {
  throw new Error("LEGITIMATE_CHALLENGE_REJECTED");
}

const replay = consumeChallenge(
  authority,
  first.challenge,
  "sess-001",
  100002,
  60000
);

if (replay.accepted || replay.reason !== "CHALLENGE_ALREADY_CONSUMED") {
  throw new Error("CHALLENGE_REPLAY_ACCEPTED");
}

const otherSession = consumeChallenge(
  authority,
  first.challenge,
  "sess-002",
  100003,
  60000
);

if (otherSession.accepted || otherSession.reason !== "CHALLENGE_SESSION_MISMATCH") {
  throw new Error("CROSS_SESSION_CHALLENGE_ACCEPTED");
}

const expiredChallenge = issueChallenge(
  authority,
  "sess-001",
  200000
);

const expired = consumeChallenge(
  authority,
  expiredChallenge.challenge,
  "sess-001",
  260001,
  60000
);

if (expired.accepted || expired.reason !== "CHALLENGE_EXPIRED") {
  throw new Error("EXPIRED_CHALLENGE_ACCEPTED");
}

const unknown = consumeChallenge(
  authority,
  "unknown-challenge",
  "sess-001",
  100000,
  60000
);

if (unknown.accepted || unknown.reason !== "CHALLENGE_UNKNOWN") {
  throw new Error("UNKNOWN_CHALLENGE_ACCEPTED");
}

console.log("CHALLENGE_LEGITIMATE=PASS");
console.log("CHALLENGE_REPLAY_REJECTED=PASS");
console.log("CROSS_SESSION_REJECTED=PASS");
console.log("EXPIRED_CHALLENGE_REJECTED=PASS");
console.log("UNKNOWN_CHALLENGE_REJECTED=PASS");
console.log("CHALLENGE_AUTHORITY=PASS");
