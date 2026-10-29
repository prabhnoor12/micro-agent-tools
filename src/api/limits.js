/**
 * Shared Rate Limiting + Usage Limiting module.
 * Zero dependencies. Works in Node.js (require) and Cloudflare Workers
 * (import default interop via nodejs_compat).
 *
 * Rate limiting: in-memory sliding-window per key. On Workers this is
 * per-isolate best-effort (isolates don't share memory). For distributed
 * enforcement, configure Cloudflare Rate Limiting rules in front of the
 * Worker (see README section) — this module remains as defense-in-depth.
 *
 * Usage limiting: cheap pre-execution guards (string/array lengths,
 * decoded byte sizes) so heavy tools (pdf, csv, logs) can't OOM the process.
 */

'use strict';

const DEFAULTS = {
  globalPerMin: 120,
  mcpPerMin: 30,
  cheapPerMin: 60,
  mediumPerMin: 20,
  heavyPerMin: 5,
  windowMs: 60 * 1000,
  maxKeys: 10000,
  maxBodyBytes: 1 * 1024 * 1024, // 1MB default
  maxPdfBodyBytes: 6 * 1024 * 1024, // PDFs are base64-heavy
  maxConcurrentHeavy: 4,
  toolTimeoutMs: 15000,
  heavyTimeoutMs: 25000,
};

// Heavy tools cost real CPU/memory. Everything else is cheap/medium.
const HEAVY_TOOLS = new Set(['pdf_processor', 'website_health_auditor', 'duck_log']);
const MEDIUM_TOOLS = new Set([
  'sheet_diff',
  'json_diff',
  'text_cleaner',
  'terms_risk_scanner',
  'receipt_parser',
  'og_card_generator',
  'code_card_generator',
  'sourcemap_demapper',
  'env_matrix',
]);

function numFromEnv(name, fallback) {
  const raw = typeof process !== 'undefined' && process.env ? process.env[name] : undefined;
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function parseAllowedOrigins() {
  const raw =
    typeof process !== 'undefined' && process.env ? process.env.ALLOWED_ORIGINS : undefined;
  if (raw === undefined || raw === '') return ['*'];
  return raw
    .split(',')
    .map((s) => s.trim().replace(/\/$/, ''))
    .filter(Boolean);
}

function getConfig() {
  return {
    globalPerMin: numFromEnv('RATE_LIMIT_GLOBAL_PER_MIN', DEFAULTS.globalPerMin),
    mcpPerMin: numFromEnv('RATE_LIMIT_MCP_PER_MIN', DEFAULTS.mcpPerMin),
    cheapPerMin: numFromEnv('RATE_LIMIT_CHEAP_PER_MIN', DEFAULTS.cheapPerMin),
    mediumPerMin: numFromEnv('RATE_LIMIT_MEDIUM_PER_MIN', DEFAULTS.mediumPerMin),
    heavyPerMin: numFromEnv('RATE_LIMIT_HEAVY_PER_MIN', DEFAULTS.heavyPerMin),
    windowMs: DEFAULTS.windowMs,
    maxKeys: DEFAULTS.maxKeys,
    maxBodyBytes: numFromEnv('MAX_BODY_BYTES', DEFAULTS.maxBodyBytes),
    maxPdfBodyBytes: numFromEnv('MAX_PDF_BODY_BYTES', DEFAULTS.maxPdfBodyBytes),
    maxConcurrentHeavy: numFromEnv('MAX_CONCURRENT_HEAVY', DEFAULTS.maxConcurrentHeavy),
    toolTimeoutMs: numFromEnv('TOOL_TIMEOUT_MS', DEFAULTS.toolTimeoutMs),
    heavyTimeoutMs: numFromEnv('HEAVY_TOOL_TIMEOUT_MS', DEFAULTS.heavyTimeoutMs),
    trustProxyHeaders:
      (typeof process !== 'undefined' &&
        process.env &&
        process.env.TRUST_PROXY_HEADERS === '1') ||
      false,
    allowedOrigins: parseAllowedOrigins(),
    disabled:
      (typeof process !== 'undefined' &&
        process.env &&
        process.env.RATE_LIMIT_DISABLED === '1') ||
      false,
  };
}

function getToolTier(toolName) {
  if (HEAVY_TOOLS.has(toolName)) return 'heavy';
  if (MEDIUM_TOOLS.has(toolName)) return 'medium';
  return 'cheap';
}

function limitForTier(toolName, config) {
  const tier = getToolTier(toolName);
  if (tier === 'heavy') return config.heavyPerMin;
  if (tier === 'medium') return config.mediumPerMin;
  return config.cheapPerMin;
}

// ---------------------------------------------------------------------------
// Sliding-window store
// ---------------------------------------------------------------------------
// key -> array of epoch-ms timestamps (ascending). Old entries are evicted
// on each check, so memory stays proportional to request rate.
const buckets = new Map();
let lastSweep = Date.now();

function sweepIfNeeded(config) {
  const now = Date.now();
  if (now - lastSweep < 5 * 60 * 1000) return;
  lastSweep = now;
  for (const [key, hits] of buckets) {
    const fresh = hits.filter((t) => now - t < config.windowMs);
    if (fresh.length === 0) buckets.delete(key);
    else buckets.set(key, fresh);
  }
  // LRU-ish eviction if something pathological created many keys.
  if (buckets.size > config.maxKeys) {
    const excess = buckets.size - config.maxKeys;
    let i = 0;
    for (const key of buckets.keys()) {
      buckets.delete(key);
      if (++i >= excess) break;
    }
  }
}

/**
 * Sliding-window check.
 * @returns {{allowed:boolean, remaining:number, resetMs:number, retryAfterSec:number, limit:number}}
 */
function checkLimit(key, limit, windowMs, config) {
  if (config.disabled) {
    return { allowed: true, remaining: limit, resetMs: 0, retryAfterSec: 0, limit };
  }
  sweepIfNeeded(config);
  const now = Date.now();
  let hits = buckets.get(key);
  if (!hits) {
    hits = [];
    buckets.set(key, hits);
  }
  // Evict expired hits from the front (array is ascending).
  while (hits.length > 0 && now - hits[0] >= windowMs) hits.shift();
  if (hits.length >= limit) {
    const oldest = hits[0];
    const resetMs = oldest + windowMs - now;
    return {
      allowed: false,
      remaining: 0,
      resetMs,
      retryAfterSec: Math.max(1, Math.ceil(resetMs / 1000)),
      limit,
    };
  }
  hits.push(now);
  return {
    allowed: true,
    remaining: limit - hits.length,
    resetMs: windowMs,
    retryAfterSec: 0,
    limit,
  };
}

function rateLimitHeaders(result) {
  return {
    'X-RateLimit-Limit': String(result.limit),
    'X-RateLimit-Remaining': String(result.remaining),
  };
}

/**
 * Distributed check via the RateLimitDO binding when present, with
 * synchronous in-memory fallback. Never rejects: on any binding error it
 * falls back to the local bucket so a storage outage degrades to
 * per-isolate limiting instead of failing open or closed.
 *
 * @returns {Promise<{allowed:boolean,remaining:number,resetMs:number,retryAfterSec:number,limit:number,distributed:boolean,fallback:boolean}>}
 */
async function checkLimitDistributed(env, key, limit, windowMs, config, now) {
  const binding = env && (env.RATE_LIMITER || env.RATE_LIMIT_DO);
  if (!binding || typeof binding.getByName !== 'function') {
    return { ...checkLimit(key, limit, windowMs, config), distributed: false, fallback: false };
  }
  const idName = `rl-${String(key).split(':')[0] || 'default'}`;
  const attempt = (async () => {
    const stub = binding.getByName(idName);
    const res = await stub.fetch('https://rl/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, limit, windowMs, now: now || Date.now() }),
    });
    if (!res.ok && res.status !== 429) throw new Error(`limiter DO HTTP ${res.status}`);
    const data = await res.json();
    return { ...data, distributed: true, fallback: false };
  })();
  const guard = new Promise((resolve) => {
    const t = setTimeout(() => {
      resolve({ ...checkLimit(key, limit, windowMs, config), distributed: false, fallback: true });
    }, 500);
    if (t.unref) t.unref();
  });
  return Promise.race([attempt.catch(() => ({ ...checkLimit(key, limit, windowMs, config), distributed: false, fallback: true })), guard]);
}

// ---------------------------------------------------------------------------
// Client IP helpers — spoof-resistant by default.
// CF-Connecting-IP (set by Cloudflare) is authoritative. X-Forwarded-For is
// attacker-controlled unless the process runs behind a trusted proxy that
// overwrites it, so it is ignored unless TRUST_PROXY_HEADERS=1.
// ---------------------------------------------------------------------------
function getNodeClientIp(req, config) {
  const cf = req.headers && (req.headers['cf-connecting-ip'] || req.headers['CF-Connecting-IP']);
  if (cf) return String(cf).split(',')[0].trim().slice(0, 64);
  const trustProxy = Boolean(config && config.trustProxyHeaders);
  if (trustProxy) {
    const fwd = req.headers && req.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim().slice(0, 64);
  }
  if (req.socket && req.socket.remoteAddress) return String(req.socket.remoteAddress).slice(0, 64);
  return 'unknown';
}

function getWorkerClientIp(request, config) {
  try {
    const cf = request.headers.get('CF-Connecting-IP');
    if (cf) return cf.slice(0, 64);
    if (config && config.trustProxyHeaders) {
      const fwd = request.headers.get('X-Forwarded-For');
      if (fwd) return fwd.split(',')[0].trim().slice(0, 64);
    }
  } catch (_) {
    // ignore
  }
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Security headers + strict CORS
// ---------------------------------------------------------------------------
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-DNS-Prefetch-Control': 'off',
};

/** Resolve the ACAO value for a request, or null when no CORS grant applies. */
function corsAllowOrigin(reqHeaders, config) {
  const origins = (config && config.allowedOrigins) || ['*'];
  if (origins.includes('*')) return '*';
  const origin =
    reqHeaders &&
    (reqHeaders.origin || reqHeaders.Origin || reqHeaders['origin'] || reqHeaders['Origin']);
  if (typeof origin === 'string' && origins.includes(origin.replace(/\/$/, ''))) return origin;
  return null;
}

/**
 * Strip internals from tool error messages before reflecting them in 400s:
 * first line only (drop stacks), no control chars, no absolute paths,
 * capped at 500 chars. Generic 500s never use the raw message at all.
 */
function safeToolMessage(err, fallback = 'Bad request') {
  const raw = err && typeof err.message === 'string' ? err.message : '';
  const firstLine = raw.split('\n')[0];
  // eslint-disable-next-line no-control-regex
  const clean = firstLine.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  const noPaths = clean
    .replace(/[A-Za-z]:\\[^\s"']*/g, '[path]')
    .replace(/(^|[\s"'(])(?:\/[\w.\-]+)+\/?/g, '$1[path]');
  // Scrub secret-shaped material so a secret embedded in a failure (bad key
  // format, echo in a parser message) can never reflect to the client.
  const noSecrets = noPaths
    .replace(/\b(sk_live|sk_test|rk_live|rk_test|whsec_|xox[baprs]-|ghp_|gho_|github_pat_|AKIA|ASIA|AIza|pk_live|pk_test)[A-Za-z0-9+/=_-]{8,}/g, '[redacted]')
    .replace(/\bBearer\s+[A-Za-z0-9\-._~+/=]{8,}/g, 'Bearer [redacted]');
  if (!noSecrets) return fallback;
  return noSecrets.length > 500 ? `${noSecrets.slice(0, 500)}…` : noSecrets;
}

function corsHeaders(reqHeaders, config, { allowMethods = false } = {}) {
  const allowOrigin = corsAllowOrigin(reqHeaders, config);
  const headers = { ...SECURITY_HEADERS };
  if (allowOrigin) {
    headers['Access-Control-Allow-Origin'] = allowOrigin;
    if (allowOrigin !== '*') headers.Vary = 'Origin';
  }
  if (allowMethods) {
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Agent-ID';
    headers['Access-Control-Max-Age'] = '86400';
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Usage limits (cheap pre-execution guards)
// ---------------------------------------------------------------------------
const TOOL_USAGE_LIMITS = {
  pdf_processor: { maxBodyChars: 8 * 1024 * 1024, maxFiles: 5, maxFields: 50 },
  sheet_diff: { maxCsvChars: 500 * 1024, maxRows: 10000 },
  duck_log: { maxLogChars: 1024 * 1024, maxSqlChars: 5000, maxResultRows: 1000 },
  text_cleaner: { maxChars: 200 * 1024 },
  pii_redactor: { maxChars: 500 * 1024, maxMaskChars: 64 },
  terms_risk_scanner: { maxChars: 200 * 1024 },
  receipt_parser: { maxChars: 100 * 1024 },
  json_diff: { maxJsonChars: 500 * 1024 },
  og_card_generator: { maxTitle: 200, maxDesc: 1000, maxBadge: 40, maxBrand: 60, maxUrlChars: 2048 },
  code_card_generator: { maxCodeChars: 20 * 1024, maxLines: 200, maxTitle: 80 },
  webhook_verifier: { maxPayloadChars: 200 * 1024 },
  env_matrix: { maxEnvChars: 100 * 1024 },
  jwt_verifier: { maxTokenChars: 20 * 1024 },
  sourcemap_demapper: { maxTraceChars: 100 * 1024, maxMapChars: 500 * 1024 },
  invoice_builder: { maxItems: 200 },
  website_health_auditor: { maxUrlChars: 2048 },
};

function strLen(v) {
  return typeof v === 'string' ? v.length : 0;
}

function base64ByteSize(s) {
  if (typeof s !== 'string' || s.length === 0) return 0;
  const clean = s.replace(/^data:[^,]+,/, '').replace(/\s/g, '');
  // 4 base64 chars ~= 3 bytes. Cheap estimate, no decode.
  return Math.floor(clean.length * 0.75);
}

/**
 * Throws an Error with .statusCode = 413/422 when args exceed safe bounds.
 * Runs BEFORE executeTool so we never decode giant PDFs or parse giant CSVs.
 */
function enforceToolUsage(toolName, args) {
  const a = args || {};
  const fail = (message) => {
    const err = new Error(message);
    err.statusCode = 413;
    throw err;
  };

  switch (toolName) {
    case 'pdf_processor': {
      const lim = TOOL_USAGE_LIMITS.pdf_processor;
      if (Array.isArray(a.pdf_list) && a.pdf_list.length > lim.maxFiles) {
        fail(`"pdf_list" exceeds max of ${lim.maxFiles} files.`);
      }
      if (Array.isArray(a.fields) && a.fields.length > lim.maxFields) {
        fail(`"fields" exceeds max of ${lim.maxFields} annotations.`);
      }
      const biggest =
        Math.max(base64ByteSize(a.pdf_base64), 0) ||
        (Array.isArray(a.pdf_list)
          ? Math.max(0, ...a.pdf_list.map((s) => base64ByteSize(typeof s === 'string' ? s : '')))
          : 0);
      if (biggest > 8 * 1024 * 1024) fail('PDF payload exceeds max decoded size of 8MB.');
      const totalChars = strLen(a.pdf_base64) + (Array.isArray(a.pdf_list) ? a.pdf_list.reduce((n, s) => n + strLen(typeof s === 'string' ? s : ''), 0) : 0);
      if (totalChars > lim.maxBodyChars) fail('PDF payload exceeds max request size.');
      break;
    }
    case 'sheet_diff': {
      const lim = TOOL_USAGE_LIMITS.sheet_diff;
      if (strLen(a.baseline_csv) > lim.maxCsvChars || strLen(a.updated_csv) > lim.maxCsvChars) {
        fail('CSV exceeds max size of 500KB per sheet.');
      }
      break;
    }
    case 'duck_log': {
      const lim = TOOL_USAGE_LIMITS.duck_log;
      const rawLen = Array.isArray(a.raw_logs) ? a.raw_logs.length : strLen(a.raw_logs);
      // Array items could still be huge; check serialized length cheaply for arrays under 500 items.
      if (strLen(a.raw_logs) > lim.maxLogChars) fail('raw_logs exceeds max size of 1MB.');
      if (Array.isArray(a.raw_logs) && rawLen > 20000) fail('raw_logs exceeds max of 20000 entries.');
      if (strLen(a.sql_query) > lim.maxSqlChars) fail('sql_query exceeds max length of 5000 chars.');
      break;
    }
    case 'text_cleaner':
      if (strLen(a.text) > TOOL_USAGE_LIMITS.text_cleaner.maxChars) fail('text exceeds max size of 200KB.');
      break;
    case 'pii_redactor': {
      const lim = TOOL_USAGE_LIMITS.pii_redactor;
      if (typeof a.text !== 'string') {
        const err = new Error('"text" parameter must be a string.');
        err.statusCode = 400;
        throw err;
      }
      if (a.text.length > lim.maxChars) fail('text exceeds max size of 500KB.');
      if (typeof a.replacement_mask === 'string' && a.replacement_mask.length > lim.maxMaskChars) {
        fail('replacement_mask exceeds max length of 64 chars.');
      }
      break;
    }
    case 'terms_risk_scanner':
      if (strLen(a.terms_text) > TOOL_USAGE_LIMITS.terms_risk_scanner.maxChars) fail('terms_text exceeds max size of 200KB.');
      break;
    case 'receipt_parser':
      if (strLen(a.document_text) > TOOL_USAGE_LIMITS.receipt_parser.maxChars) fail('document_text exceeds max size of 100KB.');
      break;
    case 'og_card_generator': {
      const lim = TOOL_USAGE_LIMITS.og_card_generator;
      if (strLen(a.title) > lim.maxTitle) fail('title exceeds max length of 200 chars.');
      if (strLen(a.description) > lim.maxDesc) fail('description exceeds max length of 1000 chars.');
      if (strLen(a.badge) > lim.maxBadge) fail('badge exceeds max length of 40 chars.');
      if (strLen(a.brand) > lim.maxBrand) fail('brand exceeds max length of 60 chars.');
      if (strLen(a.url) > lim.maxUrlChars) fail('url exceeds max length of 2048 chars.');
      break;
    }
    case 'json_diff':
      if (strLen(typeof a.original_json === 'string' ? a.original_json : JSON.stringify(a.original_json || '')) > TOOL_USAGE_LIMITS.json_diff.maxJsonChars) {
        fail('original_json exceeds max size of 500KB.');
      }
      if (strLen(typeof a.updated_json === 'string' ? a.updated_json : JSON.stringify(a.updated_json || '')) > TOOL_USAGE_LIMITS.json_diff.maxJsonChars) {
        fail('updated_json exceeds max size of 500KB.');
      }
      break;
    case 'code_card_generator': {
      const lim = TOOL_USAGE_LIMITS.code_card_generator;
      if (strLen(a.code) > lim.maxCodeChars) fail('code exceeds max size of 20KB.');
      if (typeof a.code === 'string' && a.code.split(/\r?\n/).length > lim.maxLines) {
        fail('code exceeds max of 200 lines.');
      }
      if (strLen(a.title) > lim.maxTitle) fail('title exceeds max length of 80 chars.');
      break;
    }
    case 'webhook_verifier': {
      const payloadLen = typeof a.payload === 'string' ? a.payload.length : strLen(JSON.stringify(a.payload || ''));
      if (payloadLen > TOOL_USAGE_LIMITS.webhook_verifier.maxPayloadChars) fail('payload exceeds max size of 200KB.');
      break;
    }
    case 'invoice_builder':
      if (Array.isArray(a.items) && a.items.length > TOOL_USAGE_LIMITS.invoice_builder.maxItems) {
        fail('items exceeds max of 200 line items.');
      }
      break;
    case 'website_health_auditor': {
      const lim = TOOL_USAGE_LIMITS.website_health_auditor;
      if (typeof a.url !== 'string' || a.url.length === 0) {
        const err = new Error('"url" parameter is required.');
        err.statusCode = 400;
        throw err;
      }
      if (a.url.length > lim.maxUrlChars) {
        fail(`"url" exceeds max length of ${lim.maxUrlChars} chars.`);
      }
      break;
    }
    case 'jwt_verifier':
      if (strLen(a.jwt_token) > TOOL_USAGE_LIMITS.jwt_verifier.maxTokenChars) fail('jwt_token exceeds max length.');
      break;
    case 'sourcemap_demapper': {
      const lim = TOOL_USAGE_LIMITS.sourcemap_demapper;
      if (strLen(a.stack_trace) > lim.maxTraceChars) fail('stack_trace exceeds max size of 100KB.');
      const mapLen = typeof a.source_map === 'string' ? a.source_map.length : strLen(JSON.stringify(a.source_map || ''));
      if (mapLen > lim.maxMapChars) fail('source_map exceeds max size of 500KB.');
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// Concurrency guard for heavy tools (Node only; Workers isolate per-request)
// ---------------------------------------------------------------------------
let heavyInFlight = 0;

function tryAcquireHeavy(config) {
  if (heavyInFlight >= config.maxConcurrentHeavy) return false;
  heavyInFlight += 1;
  return true;
}

function releaseHeavy() {
  heavyInFlight = Math.max(0, heavyInFlight - 1);
}

function heavyInFlightCount() {
  return heavyInFlight;
}

function throwIfAborted(signal, toolName) {
  if (signal && signal.aborted) {
    const err = new Error(`Tool "${toolName}" aborted.`);
    err.statusCode = 504;
    throw err;
  }
}

/**
 * Cooperative timeout: the builder fn receives an AbortSignal that fires
 * when the deadline hits. Tools that accept opts.signal stop early;
 * tools that ignore it still lose the race, and the abort tells queued
 * pre-start checks to fail fast. Replaces bare withTimeout for tool runs.
 */
function withToolTimeout(ms, toolName, fn) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try {
        controller.abort();
      } catch (_) {
        // ignore
      }
      const err = new Error(`Tool "${toolName}" timed out after ${ms}ms.`);
      err.statusCode = 504;
      reject(err);
    }, ms);
    // Deliberately NOT unref'd: the caller awaits this race, and an unref'd
    // timer would let the process exit before the deadline fires, stranding
    // the waiter with no settlement. The timer is always cleared on settle.
  });
  return Promise.race([fn(controller.signal), timeout]).then(
    (v) => {
      clearTimeout(timer);
      return v;
    },
    (e) => {
      clearTimeout(timer);
      throw e;
    }
  );
}

function withTimeout(promise, ms, toolName) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(`Tool "${toolName}" timed out after ${ms}ms.`);
      err.statusCode = 504;
      reject(err);
    }, ms);
    if (timer.unref) timer.unref();
  });
  return Promise.race([promise, timeout]).then(
    (v) => {
      clearTimeout(timer);
      return v;
    },
    (e) => {
      clearTimeout(timer);
      throw e;
    }
  );
}

function resetForTests() {
  buckets.clear();
  heavyInFlight = 0;
}

module.exports = {
  DEFAULTS,
  HEAVY_TOOLS,
  MEDIUM_TOOLS,
  TOOL_USAGE_LIMITS,
  SECURITY_HEADERS,
  getConfig,
  getToolTier,
  limitForTier,
  checkLimit,
  checkLimitDistributed,
  rateLimitHeaders,
  corsAllowOrigin,
  corsHeaders,
  safeToolMessage,
  getNodeClientIp,
  getWorkerClientIp,
  enforceToolUsage,
  base64ByteSize,
  tryAcquireHeavy,
  releaseHeavy,
  heavyInFlightCount,
  throwIfAborted,
  withToolTimeout,
  withTimeout,
  resetForTests,
};
