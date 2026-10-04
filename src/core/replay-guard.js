export function createReplayState() {
  return Object.freeze({ lastSequence: 0 });
}

export function verifySequence(state, presentedSequence) {
  if (!state || !Number.isInteger(state.lastSequence) || state.lastSequence < 0)
    return { decision: "REAUTH_REQUIRED", reason: "INVALID_REPLAY_STATE" };

  if (!Number.isInteger(presentedSequence) || presentedSequence < 1)
    return { decision: "REAUTH_REQUIRED", reason: "INVALID_SEQUENCE" };

  if (presentedSequence <= state.lastSequence)
    return {
      decision: "REAUTH_REQUIRED",
      reason: "REPLAY_DETECTED",
      lastSequence: state.lastSequence,
      presentedSequence
    };

  return {
    decision: "CONTINUOUS",
    reason: "SEQUENCE_ACCEPTED",
    lastSequence: state.lastSequence,
    presentedSequence
  };
}

export function advanceReplayState(state, presentedSequence) {
  const result = verifySequence(state, presentedSequence);
  if (result.decision !== "CONTINUOUS") return { state, result };

  return {
    state: Object.freeze({ lastSequence: presentedSequence }),
    result
  };
}
