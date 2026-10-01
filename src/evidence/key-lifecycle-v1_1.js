const STATE_SCHEMA_ID = "session-continuity.v1_1.key.lifecycle";
const VERSION = 1;

export const KEY_STATUS = Object.freeze({
  ACTIVE: "ACTIVE",
  RETIRED: "RETIRED",
  REVOKED: "REVOKED"
});

function assertHex64(value, name){
  if(typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) throw new TypeError(name + "_INVALID");
}

function assertUtcMillis(value, name){
  if(typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) throw new TypeError(name + "_INVALID");
}

function storeCheck(store){
  if(!store || store.version !== VERSION) throw new Error("KEY_STORE_INVALID");
}

export function createKeyLifecycleStore(){
  return {version: VERSION, schema_id: STATE_SCHEMA_ID, keys: new Map()};
}

export function registerKey(store, fingerprint, options){
  const opts = options || {};
  storeCheck(store);
  assertHex64(fingerprint, "KEY_FINGERPRINT");
  const normalized = fingerprint.toLowerCase();
  if(store.keys.has(normalized)) throw new Error("KEY_ALREADY_REGISTERED");
  const validFrom = opts.valid_from || null;
  const validUntil = opts.valid_until || null;
  if(validFrom !== null) assertUtcMillis(validFrom, "KEY_VALID_FROM");
  if(validUntil !== null) assertUtcMillis(validUntil, "KEY_VALID_UNTIL");
  if(validFrom !== null && validUntil !== null && validFrom > validUntil) throw new Error("KEY_INTERVAL_INVALID");
  const record = Object.freeze({
    fingerprint: normalized,
    status: KEY_STATUS.ACTIVE,
    valid_from: validFrom,
    valid_until: validUntil,
    retired_at: null,
    revoked_at: null,
    compromise_window: null,
    version: Number(opts.version == null ? 1 : opts.version)
  });
  store.keys.set(normalized, record);
  return record;
}

export function retireKey(store, fingerprint, options){
  const opts = options || {};
  storeCheck(store);
  assertHex64(fingerprint, "KEY_FINGERPRINT");
  const normalized = fingerprint.toLowerCase();
  const record = store.keys.get(normalized);
  if(!record) throw new Error("KEY_NOT_FOUND");
  if(record.status === KEY_STATUS.REVOKED) throw new Error("KEY_ALREADY_REVOKED");
  if(record.status === KEY_STATUS.RETIRED) throw new Error("KEY_ALREADY_RETIRED");
  const retiredAt = opts.retired_at;
  if(!retiredAt) throw new Error("KEY_RETIRED_AT_REQUIRED");
  assertUtcMillis(retiredAt, "KEY_RETIRED_AT");
  const updated = Object.freeze(Object.assign({}, record, {
    status: KEY_STATUS.RETIRED,
    retired_at: retiredAt
  }));
  store.keys.set(normalized, updated);
  return updated;
}

export function revokeKey(store, fingerprint, options){
  const opts = options || {};
  storeCheck(store);
  assertHex64(fingerprint, "KEY_FINGERPRINT");
  const normalized = fingerprint.toLowerCase();
  const record = store.keys.get(normalized);
  if(!record) throw new Error("KEY_NOT_FOUND");
  if(record.status === KEY_STATUS.REVOKED) throw new Error("KEY_ALREADY_REVOKED");
  const revokedAt = opts.revoked_at;
  if(!revokedAt) throw new Error("KEY_REVOKED_AT_REQUIRED");
  assertUtcMillis(revokedAt, "KEY_REVOKED_AT");
  let compromiseWindow = null;
  if(opts.compromise_window){
    assertUtcMillis(opts.compromise_window.start, "COMPROMISE_START");
    assertUtcMillis(opts.compromise_window.end, "COMPROMISE_END");
    if(opts.compromise_window.start > opts.compromise_window.end) throw new Error("COMPROMISE_WINDOW_INVALID");
    compromiseWindow = Object.freeze({start: opts.compromise_window.start, end: opts.compromise_window.end});
  }
  const updated = Object.freeze(Object.assign({}, record, {
    status: KEY_STATUS.REVOKED,
    revoked_at: revokedAt,
    compromise_window: compromiseWindow
  }));
  store.keys.set(normalized, updated);
  return updated;
}

export function getKey(store, fingerprint){
  storeCheck(store);
  assertHex64(fingerprint, "KEY_FINGERPRINT");
  return store.keys.get(fingerprint.toLowerCase()) || null;
}

export function canSignNow(store, fingerprint, now){
  const rec = getKey(store, fingerprint);
  if(!rec) return {allowed: false, reason: "KEY_NOT_FOUND"};
  if(rec.status !== KEY_STATUS.ACTIVE) return {allowed: false, reason: "KEY_NOT_ACTIVE", status: rec.status};
  assertUtcMillis(now, "NOW");
  if(rec.valid_from !== null && now < rec.valid_from) return {allowed: false, reason: "KEY_NOT_YET_VALID"};
  if(rec.valid_until !== null && now > rec.valid_until) return {allowed: false, reason: "KEY_VALIDITY_EXPIRED"};
  return {allowed: true, reason: "KEY_ACTIVE_AND_VALID", record: rec};
}

export function verifyKeyForProof(store, fingerprint, issued_at){
  const rec = getKey(store, fingerprint);
  if(!rec) return {valid: false, reason: "KEY_NOT_FOUND"};
  assertUtcMillis(issued_at, "ISSUED_AT");
  if(rec.valid_from !== null && issued_at < rec.valid_from) return {valid: false, reason: "PROOF_BEFORE_KEY_VALID"};
  if(rec.valid_until !== null && issued_at > rec.valid_until) return {valid: false, reason: "PROOF_AFTER_KEY_VALID"};
  if(rec.status === KEY_STATUS.ACTIVE) return {valid: true, reason: "KEY_ACTIVE_AT_ISSUE", record: rec};
  if(rec.status === KEY_STATUS.RETIRED){
    if(rec.retired_at !== null && issued_at > rec.retired_at) return {valid: false, reason: "PROOF_AFTER_RETIREMENT"};
    return {valid: true, reason: "KEY_RETIRED_BUT_HISTORICALLY_VALID", record: rec};
  }
  if(rec.status === KEY_STATUS.REVOKED){
    if(rec.compromise_window){
      if(issued_at >= rec.compromise_window.start && issued_at <= rec.compromise_window.end){
        return {valid: false, reason: "PROOF_WITHIN_COMPROMISE_WINDOW", record: rec};
      }
    }
    if(rec.revoked_at !== null && issued_at > rec.revoked_at) return {valid: false, reason: "PROOF_AFTER_REVOCATION"};
    return {valid: true, reason: "KEY_REVOKED_BUT_HISTORICALLY_VALID", record: rec};
  }
  return {valid: false, reason: "KEY_STATUS_UNKNOWN"};
}