import crypto from "node:crypto";

const BINDING_VERSION = "1.0.0";
const BINDING_TTL_MS = 60000;

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(Buffer.from(input, "utf8")).digest("hex");
}

export function createParentBinding({
  parentSessionId,
  parentSequence,
  nextChallenge,
  privateKeyPem,
  issuedAt = Date.now()
}) {
  if (!parentSessionId || typeof parentSequence !== "number" || !nextChallenge) {
    throw new Error("createParentBinding: missing required fields");
  }

  const nextChallengeHash = sha256Hex(nextChallenge);

  const binding = {
    version: BINDING_VERSION,
    parent_session_id: parentSessionId,
    parent_sequence: parentSequence,
    next_sequence: parentSequence + 1,
    next_challenge_hash: nextChallengeHash,
    issued_at: issuedAt,
    expires_at: issuedAt + BINDING_TTL_MS,
    nonce: crypto.randomBytes(16).toString("hex")
  };

  const signingPayload = canonicalize(binding);
  const signature = crypto.sign(null, Buffer.from(signingPayload, "utf8"), privateKeyPem);

  return {
    ...binding,
    signature: signature.toString("base64")
  };
}

export function verifyParentBinding({ binding, parentPublicKeyPem, presentedChallenge, nowMs = Date.now() }) {
  try {
    if (!binding || typeof binding !== "object") {
      return { valid: false, reason: "MISSING_BINDING" };
    }
    if (binding.version !== BINDING_VERSION) {
      return { valid: false, reason: "UNSUPPORTED_BINDING_VERSION" };
    }

    const { signature, ...payload } = binding;
    const signingPayload = canonicalize(payload);
    const publicKey = crypto.createPublicKey(parentPublicKeyPem);

    const sigOk = crypto.verify(
      null,
      Buffer.from(signingPayload, "utf8"),
      publicKey,
      Buffer.from(signature, "base64")
    );
    if (!sigOk) return { valid: false, reason: "BINDING_SIGNATURE_INVALID" };

    if (typeof binding.expires_at !== "number" || nowMs > binding.expires_at) {
      return { valid: false, reason: "BINDING_EXPIRED" };
    }

    const expectedHash = sha256Hex(presentedChallenge);
    if (binding.next_challenge_hash !== expectedHash) {
      return { valid: false, reason: "BINDING_CHALLENGE_MISMATCH" };
    }

    if (binding.next_sequence !== binding.parent_sequence + 1) {
      return { valid: false, reason: "BINDING_SEQUENCE_INVALID" };
    }

    return {
      valid: true,
      reason: "BINDING_VALID",
      binding_id: binding.nonce,
      parent_sequence: binding.parent_sequence,
      next_sequence: binding.next_sequence
    };
  } catch (e) {
    return { valid: false, reason: "BINDING_VERIFY_ERROR: " + (e && e.message ? e.message : String(e)) };
  }
}

export function bindingId(binding) {
  if (!binding || typeof binding !== "object") return null;
  return binding.nonce || null;
}
