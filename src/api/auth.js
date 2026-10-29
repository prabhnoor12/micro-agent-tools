/**
 * Opt-in bearer-key auth for hosted deploys.
 * Local use stays free-and-open: when no keys are configured every route is
 * public. When API_KEYS is set, all POST routes (tool execution + MCP) and
 * /metrics require `Authorization: Bearer <key>`. GET discovery routes stay
 * open so agents can still find the catalog.
 *
 * Comparison is timing-safe. Keys live only in env, never in code or logs.
 */

'use strict';

function parseApiKeys() {
  const raw = typeof process !== 'undefined' && process.env ? process.env.API_KEYS : undefined;
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length >= 16);
}

function parseApiKeysFromEnv(env) {
  if (!env || typeof env.API_KEYS !== 'string' || !env.API_KEYS) return [];
  return env.API_KEYS.split(',')
    .map((s) => s.trim())
    .filter((s) => s.length >= 16);
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  try {
    // eslint-disable-next-line global-require
    const crypto = require('node:crypto');
    const ab = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
  } catch (_) {
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
  }
}

function extractBearer(authorization) {
  if (typeof authorization !== 'string') return null;
  const m = authorization.match(/^Bearer\s+(\S+)$/i);
  return m ? m[1] : null;
}

/** True when the request presents one of the configured keys. */
function isAuthorized(headers, keys) {
  if (!keys || keys.length === 0) return true; // open mode
  const presented = extractBearer(
    (headers && (headers.authorization || headers.Authorization)) || null
  );
  if (!presented) return false;
  return keys.some((k) => timingSafeEqualStr(presented, k));
}

/** True when this method+path needs auth (in keyed mode). */
function routeNeedsAuth(method, pathname) {
  if (pathname === '/metrics') return true;
  if (method !== 'POST') return false;
  return pathname === '/v1/mcp' || pathname.startsWith('/v1/tools/');
}

module.exports = {
  parseApiKeys,
  parseApiKeysFromEnv,
  isAuthorized,
  routeNeedsAuth,
  timingSafeEqualStr,
};
