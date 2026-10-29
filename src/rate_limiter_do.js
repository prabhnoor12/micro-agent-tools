/**
 * Persistent sliding-window rate limiter as a Cloudflare Durable Object.
 * Unlike the in-memory buckets in src/api/limits.js (per-isolate), one DO
 * instance per key-space serializes all checks globally and survives
 * restarts via state.storage.
 *
 * Protocol: POST { key, limit, windowMs, now? } →
 *   { allowed, remaining, resetMs, retryAfterSec, limit }
 * GET /health → { ok, keys } (no key material, counts only).
 *
 * Plain ESM with no platform imports, so the logic is unit-testable in Node
 * with a stubbed state object.
 */

const MAX_KEYS_PER_INSTANCE = 20000;

function prune(hits, now, windowMs) {
  let i = 0;
  while (i < hits.length && now - hits[i] >= windowMs) i += 1;
  return i === 0 ? hits : hits.slice(i);
}

export class RateLimitDO {
  constructor(state) {
    this.state = state;
  }

  storageKey(key) {
    return `rl:${key}`;
  }

  async check(key, limit, windowMs, now) {
    const sk = this.storageKey(key);
    let hits = (await this.state.storage.get(sk)) || [];
    if (!Array.isArray(hits)) hits = [];
    hits = prune(hits, now, windowMs);
    if (hits.length >= limit) {
      const resetMs = hits[0] + windowMs - now;
      return {
        allowed: false,
        remaining: 0,
        resetMs: Math.max(0, resetMs),
        retryAfterSec: Math.max(1, Math.ceil(Math.max(0, resetMs) / 1000)),
        limit,
      };
    }
    hits.push(now);
    // Best-effort persistence; a lost write only loosens one window.
    try {
      await this.state.storage.put(sk, hits);
    } catch (_) {
      // ignore — memory copy still enforced below within this instance
    }
    return { allowed: true, remaining: limit - hits.length, resetMs: windowMs, retryAfterSec: 0, limit };
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname.endsWith('/health')) {
      let keys = 0;
      try {
        const listed = await this.state.storage.list({ prefix: 'rl:' });
        keys = listed.size;
      } catch (_) {
        keys = -1;
      }
      return Response.json({ ok: true, keys });
    }
    if (request.method !== 'POST') {
      return Response.json({ error: 'Method not allowed' }, { status: 405 });
    }
    let body;
    try {
      body = await request.json();
    } catch (_) {
      return Response.json({ error: 'Invalid JSON' }, { status: 400 });
    }
    const key = typeof body.key === 'string' ? body.key.slice(0, 256) : '';
    const limit = Number(body.limit);
    const windowMs = Number(body.windowMs);
    const now = Number(body.now) > 0 ? Number(body.now) : Date.now();
    if (!key || !Number.isFinite(limit) || limit <= 0 || limit > 100000) {
      return Response.json({ error: 'Bad key/limit' }, { status: 400 });
    }
    if (!Number.isFinite(windowMs) || windowMs <= 0 || windowMs > 3600000) {
      return Response.json({ error: 'Bad windowMs' }, { status: 400 });
    }
    try {
      const listed = await this.state.storage.list({ prefix: 'rl:' });
      if (listed.size >= MAX_KEYS_PER_INSTANCE && !(await this.state.storage.get(this.storageKey(key)))) {
        return Response.json({ error: 'Keyspace full' }, { status: 429 });
      }
    } catch (_) {
      // storage listing unavailable — proceed with check anyway
    }
    const result = await this.check(key, Math.floor(limit), Math.floor(windowMs), now);
    const status = result.allowed ? 200 : 429;
    return Response.json(result, {
      status,
      headers: result.allowed ? {} : { 'Retry-After': String(result.retryAfterSec) },
    });
  }
}
