export function canonicalize(value) {
  if (value === null) return null;

  const type = typeof value;

  if (type === "string" || type === "number" || type === "boolean") {
    if (type === "number" && (!Number.isFinite(value) || Number.isNaN(value))) {
      throw new TypeError("CANONICAL_NUMBER_INVALID");
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (type === "object") {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      result[key] = canonicalize(value[key]);
    }
    return result;
  }

  throw new TypeError(`CANONICAL_UNSUPPORTED_TYPE:${type}`);
}

export function canonicalStringify(value) {
  return JSON.stringify(canonicalize(value));
}
