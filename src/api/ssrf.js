/**
 * Shared SSRF guard for outbound audit fetches.
 * Zero dependencies. Works in Node.js and Cloudflare Workers.
 *
 * Threat model: an unauthenticated caller supplies `url` to
 * `website_health_auditor`. Without validation the server becomes an
 * open proxy into internal networks (localhost, RFC1918, cloud metadata
 * 169.254.169.254) and a memory-exhaustion oracle via unbounded bodies.
 *
 * Guarantees:
 * - http/https only, no credentials in URL, no control chars.
 * - IP literals must be public (incl. decimal/octal/hex obfuscation).
 * - Suspicious hostnames (localhost, .internal, metadata, …) rejected
 *   before any DNS or fetch happens.
 * - Only ports 80/443 (+ explicit allowlist) permitted.
 * - Redirects are followed manually and re-validated every hop.
 * - Response bodies are read through a capped reader (never .text()).
 * - DNS names are resolved and every A/AAAA result must be public
 *   when a resolver is available (Node). Workers have no socket DNS API,
 *   so the literal + hostname checks are the enforcement there — pair
 *   with Cloudflare egress / Zero Trust policy (see docs/rate-limiting.md).
 */

'use strict';

const MAX_URL_CHARS = 2048;
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1MB cap on audited bodies
const MAX_REDIRECTS = 3;
const DEFAULT_PORTS = new Set([80, 443]);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.google.com',
  'instance-data',
]);

const BLOCKED_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.invalid',
  '.example',
  '.test',
  '.lan',
];

/** Operator denylist: AUDIT_DENYLIST="corp,secret.internal,.dyn" (exact or .suffix). */
function getAuditDenylist() {
  try {
    const raw = typeof process !== 'undefined' && process.env ? process.env.AUDIT_DENYLIST : '';
    if (!raw) return [];
    return raw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
      .slice(0, 100);
  } catch (_) {
    return [];
  }
}

function isDeniedByOperator(hostname) {
  const h = String(hostname || '').toLowerCase();
  for (const entry of getAuditDenylist()) {
    if (entry.startsWith('.')) {
      if (h.endsWith(entry)) return true;
    } else if (h === entry) {
      return true;
    }
  }
  return false;
}

function fail(message) {
  const err = new Error(message);
  err.statusCode = 400;
  throw err;
}

/** Parse an IPv4 address, accepting decimal/octal/hex per-part obfuscation. */
function parseIPv4Obfuscated(host) {
  let h = host;
  // Strip trailing dot (DNS root) — "127.0.0.1." is still loopback.
  if (h.endsWith('.')) h = h.slice(0, -1);
  // Pure 32-bit integer form: http://2130706433/ == 127.0.0.1
  if (/^\d+$/.test(h)) {
    try {
      const n = BigInt(h);
      if (n < 0n || n > 4294967295n) return null;
      const v = Number(n);
      return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
    } catch (_) {
      return null;
    }
  }
  const parts = h.split('.');
  if (parts.length !== 4) return null;
  const out = [];
  for (const p of parts) {
    if (p.length === 0) return null;
    let base = 10;
    let digits = p;
    if (/^0x[0-9a-fA-F]+$/.test(p)) {
      base = 16;
      digits = p.slice(2);
    } else if (/^0[0-7]+$/.test(p) && p.length > 1) {
      base = 8;
    } else if (!/^\d+$/.test(p)) {
      return null;
    }
    const n = parseInt(digits, base);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out.push(n);
  }
  return out;
}

function isIPv4Literal(host) {
  return parseIPv4Obfuscated(host) !== null;
}

function isPrivateIPv4(octets) {
  const [a, b] = octets;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local + cloud metadata
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && octets[2] === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && octets[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
  if (a === 198 && b === 51 && octets[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && octets[2] === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (a >= 224) return true; // 224.0.0.0/4 multicast + 255.255.255.255
  return false;
}

/** True when an IP string (v4 incl. obfuscated, or v6) is globally routable. */
function isPublicIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  let v = ip.trim();
  // Strip brackets / zone id.
  if (v.startsWith('[') && v.endsWith(']')) v = v.slice(1, -1);
  const pct = v.indexOf('%');
  if (pct !== -1) v = v.slice(0, pct);
  const v4 = parseIPv4Obfuscated(v);
  if (v4) return !isPrivateIPv4(v4);
  if (v.includes(':')) {
    const low = v.toLowerCase();
    if (low === '::1' || low === '::') return false;
    if (low.startsWith('fe80:')) return false; // link-local
    if (low.startsWith('fc') || low.startsWith('fd')) return false; // unique local fc00::/7
    if (low.startsWith('ff')) return false; // multicast
    if (low.startsWith('::ffff:')) {
      // IPv4-mapped: check the embedded v4.
      const tail = low.slice('::ffff:'.length);
      const dotted = tail.includes('.') ? tail : null;
      if (dotted && !isPublicIp(dotted)) return false;
      if (!dotted) return false; // hex mapped form — reject, can't prove public
    }
    // Anything else with a colon we treat as global unicast.
    return true;
  }
  return false;
}

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase();
  if (h.length === 0) return true;
  if (BLOCKED_HOSTNAMES.has(h)) return true;
  // Bare IP forms handled by literal checks, but 169.254.169.254 arrives
  // here too when written plainly — the literal check below catches it.
  for (const suffix of BLOCKED_SUFFIXES) {
    if (h === suffix.slice(1) || h.endsWith(suffix)) return true;
  }
  return false;
}

/**
 * Validate a caller-supplied audit URL. Returns the normalized href.
 * Throws 400 on anything that is not a public http(s) target.
 */
function validateAuditUrl(input, opts = {}) {
  const maxUrlChars = opts.maxUrlChars || MAX_URL_CHARS;
  const allowedPorts = opts.allowedPorts || DEFAULT_PORTS;
  if (typeof input !== 'string' || input.length === 0) {
    fail('"url" parameter is required.');
  }
  if (input.length > maxUrlChars) {
    fail(`"url" exceeds max length of ${maxUrlChars} chars.`);
  }
  // Reject control characters / spaces (header + parser-differential tricks).
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x20\x7f]/.test(input.trim().replace(/^https?:\/\/[^\s]*/i, '')) || /[\x00-\x1f\x7f]/.test(input)) {
    fail('"url" contains invalid characters.');
  }
  const trimmed = input.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    fail('"url" must start with http:// or https://.');
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_) {
    fail('"url" is not a valid URL.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    fail('"url" must use http or https.');
  }
  if (parsed.username || parsed.password) {
    fail('"url" must not contain credentials.');
  }
  const hostname = parsed.hostname;
  if (!hostname || isBlockedHostname(hostname)) {
    fail(`Audit target "${hostname || '(empty)'}" is not allowed.`);
  }
  if (isDeniedByOperator(hostname)) {
    fail(`Audit target "${hostname}" is denied by operator policy.`);
  }
  // IP literals (incl. obfuscated) must be public — no DNS needed to decide.
  if (isIPv4Literal(hostname) || hostname.includes(':')) {
    if (!isPublicIp(hostname)) {
      fail(`Audit target "${hostname}" resolves to a non-public address.`);
    }
  }
  const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
  if (!allowedPorts.has(port)) {
    fail(`Port ${port} is not allowed for audits (allowed: ${[...allowedPorts].join(', ')}).`);
  }
  return parsed.href;
}

/**
 * Resolve a hostname and require every address to be public.
 * `lookup` is injectable for tests; defaults to Node dns.promises.
 * Returns true when a check ran, false when no resolver exists (Workers).
 */
async function assertPublicDns(hostname, lookup) {
  if (isIPv4Literal(hostname) || hostname.includes(':')) return true; // already checked
  let resolver = lookup;
  if (!resolver) {
    try {
      // eslint-disable-next-line global-require
      resolver = require('dns').promises.lookup;
    } catch (_) {
      return false; // Workers: no socket DNS API — literal checks stand.
    }
  }
  let results;
  try {
    results = await resolver(hostname, { all: true });
  } catch (_) {
    fail(`Audit target "${hostname}" could not be resolved.`);
  }
  const addrs = Array.isArray(results) ? results : [results];
  if (addrs.length === 0) fail(`Audit target "${hostname}" could not be resolved.`);
  for (const r of addrs) {
    const addr = typeof r === 'string' ? r : r.address;
    if (!isPublicIp(addr)) {
      fail(`Audit target "${hostname}" resolves to a non-public address.`);
    }
  }
  return true;
}

/** Read a fetch Response body through a hard byte cap. */
async function readCappedBody(response, maxBytes) {
  const capped = maxBytes || MAX_BODY_BYTES;
  const lengthHeader =
    typeof response.headers?.get === 'function' ? response.headers.get('Content-Length') : null;
  if (lengthHeader && Number(lengthHeader) > capped) {
    const err = new Error(`Response body exceeds max size of ${capped} bytes.`);
    err.statusCode = 413;
    throw err;
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (text.length > capped) {
      const err = new Error(`Response body exceeds max size of ${capped} bytes.`);
      err.statusCode = 413;
      throw err;
    }
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > capped) {
      try {
        await reader.cancel();
      } catch (_) {
        // ignore
      }
      const err = new Error(`Response body exceeds max size of ${capped} bytes.`);
      err.statusCode = 413;
      throw err;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

function nodeHttpModules() {
  try {
    // eslint-disable-next-line global-require
    const http = require('node:http');
    // eslint-disable-next-line global-require
    const https = require('node:https');
    // eslint-disable-next-line global-require
    const dns = require('node:dns');
    return { http, https, dns };
  } catch (_) {
    return null; // Workers / browser: no socket stack
  }
}

/**
 * Pinned GET (Node only): resolve the hostname, require every address
 * public, then connect to a pinned IP with SNI/Host pinned to the original
 * hostname. Closes the check-then-connect TOCTOU where DNS flips between
 * validation and connect. Returns { status, getHeader, bodyText }.
 */
async function pinnedGet(urlHref, { timeoutMs, maxBodyBytes, headers, dnsLookup }) {
  const mods = nodeHttpModules();
  if (!mods) throw new Error('Pinned transport requires Node.js.');
  const parsed = new URL(urlHref);
  const lookup = dnsLookup || mods.dns.promises.lookup;
  let addrs;
  try {
    const results = await lookup(parsed.hostname, { all: true });
    addrs = Array.isArray(results) ? results : [results];
  } catch (_) {
    fail(`Audit target "${parsed.hostname}" could not be resolved.`);
  }
  if (!addrs || addrs.length === 0) fail(`Audit target "${parsed.hostname}" could not be resolved.`);
  for (const r of addrs) {
    const ip = typeof r === 'string' ? r : r.address;
    if (!isPublicIp(ip)) fail(`Audit target "${parsed.hostname}" resolves to a non-public address.`);
  }
  const pinnedIp = typeof addrs[0] === 'string' ? addrs[0] : addrs[0].address;
  const isTls = parsed.protocol === 'https:';
  const port = parsed.port ? Number(parsed.port) : isTls ? 443 : 80;
  const hostHeader = parsed.hostname + ((parsed.port && !((isTls && port === 443) || (!isTls && port === 80))) ? `:${port}` : '');

  return new Promise((resolve, reject) => {
    const req = (isTls ? mods.https : mods.http).request(
      {
        hostname: pinnedIp,
        port,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: { ...headers, Host: hostHeader },
        servername: parsed.hostname,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        let total = 0;
        let settled = false;
        const failWith = (err) => {
          if (settled) return;
          settled = true;
          try {
            res.destroy();
          } catch (_) {
            // ignore
          }
          reject(err);
        };
        res.on('data', (chunk) => {
          total += chunk.length;
          if (total > maxBodyBytes) {
            const err = new Error(`Response body exceeds max size of ${maxBodyBytes} bytes.`);
            err.statusCode = 413;
            failWith(err);
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({
            status: res.statusCode,
            getHeader: (name) => {
              const v = res.headers[String(name).toLowerCase()];
              return Array.isArray(v) ? v[0] : v == null ? null : String(v);
            },
            bodyText: Buffer.concat(chunks).toString('utf8'),
          });
        });
        res.on('error', failWith);
      }
    );
    req.on('timeout', () => {
      const err = new Error('Request timed out.');
      err.name = 'AbortError';
      try {
        req.destroy(err);
      } catch (_) {
        // ignore
      }
      reject(err);
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch an audit target with per-hop SSRF validation.
 * Never follows redirects automatically — each Location is re-validated.
 * Transport: explicit fetchFn wins (tests/injection); otherwise pinned
 * sockets on Node, plain fetch elsewhere.
 */
async function fetchAuditTarget(startUrl, opts = {}) {
  const {
    timeoutMs = 8000,
    maxBodyBytes = MAX_BODY_BYTES,
    maxRedirects = MAX_REDIRECTS,
    fetchFn = null,
    transport = 'auto',
    dnsLookup = null,
    allowedPorts = DEFAULT_PORTS,
    headers = { 'User-Agent': 'AgentToolBot/1.0 (+https://freetools.dev)' },
  } = opts;

  let current = validateAuditUrl(startUrl, { allowedPorts });
  const usePinned =
    transport === 'pinned' || (transport === 'auto' && !fetchFn && nodeHttpModules() !== null);
  const activeFetch = fetchFn || fetch;

  // Redirect trail for audit reporting (hop URLs + statuses only).
  const redirectChain = [];

  if (usePinned) {
    // Pinned-socket loop: resolve + public-check + connect-to-pinned-IP
    // per hop. No separate assert step needed — pinnedGet resolves itself.
    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      const got = await pinnedGet(current, { timeoutMs, maxBodyBytes, headers, dnsLookup });
      redirectChain.push({ url: current, status: got.status });
      if (got.status >= 300 && got.status < 400) {
        if (hop === maxRedirects) fail('Too many redirects.');
        const location = got.getHeader('location');
        if (!location) return { response: null, bodyText: got.bodyText, finalUrl: current, redirectHops: hop, redirectChain };
        let next;
        try {
          next = new URL(location, current).href;
        } catch (_) {
          fail('Redirect Location is not a valid URL.');
        }
        current = validateAuditUrl(next, { allowedPorts });
        continue;
      }
      return { response: null, bodyText: got.bodyText, finalUrl: current, redirectHops: hop, redirectChain, status: got.status, getHeader: got.getHeader };
    }
    fail('Too many redirects.');
  }

  let response = null;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const parsed = new URL(current);
    await assertPublicDns(parsed.hostname, dnsLookup);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      response = await activeFetch(current, {
        signal: controller.signal,
        headers,
        redirect: 'manual',
      });
    } finally {
      clearTimeout(timer);
    }
    const status = response.status;
    redirectChain.push({ url: current, status });
    if (status >= 300 && status < 400) {
      if (hop === maxRedirects) {
        fail('Too many redirects.');
      }
      const location =
        typeof response.headers?.get === 'function' ? response.headers.get('Location') : null;
      if (!location) return { response, bodyText: await readCappedBody(response, maxBodyBytes), finalUrl: current, redirectHops: hop, redirectChain };
      // Resolve relative redirects against the current URL, then re-validate.
      let next;
      try {
        next = new URL(location, current).href;
      } catch (_) {
        fail('Redirect Location is not a valid URL.');
      }
      current = validateAuditUrl(next, { allowedPorts });
      // Drain the redirect body so sockets are reused, then continue.
      try {
        if (response.body && typeof response.body.cancel === 'function') await response.body.cancel();
      } catch (_) {
        // ignore
      }
      continue;
    }
    const bodyText = await readCappedBody(response, maxBodyBytes);
    return { response, bodyText, finalUrl: current, redirectHops: hop, redirectChain };
  }
  fail('Too many redirects.');
}

module.exports = {
  MAX_URL_CHARS,
  MAX_BODY_BYTES,
  MAX_REDIRECTS,
  validateAuditUrl,
  assertPublicDns,
  readCappedBody,
  fetchAuditTarget,
  pinnedGet,
  nodeHttpModules,
  isPublicIp,
  isDeniedByOperator,
  getAuditDenylist,
};
