export function createSequenceState() {
  return { version: 1, lastSequence: 0 };
}

export function verifyAndAdvanceSequence(state, presentedSequence) {
  if (!state || state.version !== 1 || !Number.isInteger(state.lastSequence) || state.lastSequence < 0) {
    return { decision: "REAUTH_REQUIRED", reason: "SEQUENCE_STATE_INVALID" };
  }
  if (!Number.isInteger(presentedSequence) || presentedSequence < 1) {
    return { decision: "REAUTH_REQUIRED", reason: "SEQUENCE_INVALID" };
  }
  const expected = state.lastSequence + 1;
  if (presentedSequence < expected) {
    return { decision: "REAUTH_REQUIRED", reason: "SEQUENCE_ROLLBACK", lastSequence: state.lastSequence, presentedSequence };
  }
  if (presentedSequence > expected) {
    return { decision: "REAUTH_REQUIRED", reason: "SEQUENCE_GAP", lastSequence: state.lastSequence, presentedSequence };
  }
  state.lastSequence = presentedSequence;
  return { decision: "CONTINUOUS", reason: "SEQUENCE_ACCEPTED", lastSequence: state.lastSequence, presentedSequence };
}

export function getLastSequence(state) {
  if (!state || state.version !== 1) return 0;
  return state.lastSequence;
}