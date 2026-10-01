import { createSessionAnchor } from "../core/session-anchor.js";

function requireString(value,name) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`OIDC_${name}_REQUIRED`);
  return value;
}

export function validateVerifiedOidcClaims(claims) {
  if (!claims || typeof claims !== "object") throw new TypeError("OIDC_VERIFIED_CLAIMS_REQUIRED");
  requireString(claims.sub,"SUB");
  requireString(claims.iss,"ISS");
  if (typeof claims.sid !== "string" || claims.sid.length === 0) throw new TypeError("OIDC_SID_REQUIRED");
  if (typeof claims.auth_time !== "string" && !Number.isInteger(claims.auth_time)) throw new TypeError("OIDC_AUTH_TIME_REQUIRED");
  return Object.freeze({
    sub:claims.sub,
    iss:claims.iss,
    sid:claims.sid,
    auth_time:typeof claims.auth_time==="number" ? new Date(claims.auth_time*1000).toISOString() : claims.auth_time,
    aud:claims.aud ?? null
  });
}

export function createOidcSessionAnchor({ verifiedClaims, clientId=null, deviceId=null, networkContext=null }) {
  const claims=validateVerifiedOidcClaims(verifiedClaims);
  return createSessionAnchor({
    sessionId:claims.sid,
    subject:claims.sub,
    issuer:claims.iss,
    authTime:claims.auth_time,
    clientId,
    deviceId,
    networkContext
  });
}

export function createOidcSessionBootstrap({ verifiedClaims, clientId=null, deviceId=null, networkContext=null }) {
  const claims=validateVerifiedOidcClaims(verifiedClaims);
  const anchor=createSessionAnchor({
    sessionId:claims.sid,
    subject:claims.sub,
    issuer:claims.iss,
    authTime:claims.auth_time,
    clientId,
    deviceId,
    networkContext
  });
  return Object.freeze({
    protocol:"OIDC",
    verifiedClaims:claims,
    anchor
  });
}