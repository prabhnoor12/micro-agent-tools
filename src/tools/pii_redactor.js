/**
 * PIIRedactor Agent Tool
 * High-precision redaction for sensitive personal and financial identifiers.
 *
 * Security properties (P1):
 * - Credit cards require Luhn checksum (no more bare 16-digit matches).
 * - Phone matcher requires separators / leading + / parentheses, so plain
 *   digit runs (years, IDs, quantities) are left alone.
 * - API-key coverage extended: sk_live/test, rk_live, xox*, ghp/gho,
 *   github_pat, AKIA/ASIA, AIza, Stripe publishable, PEM blocks, Bearer,
 *   and generic key:=assignment with high-entropy values.
 * - detections_summary NEVER echoes raw secrets: type + length + last4 only.
 * - Every detection carries source start/end offsets (no raw text).
 * - replacement_mask is length-capped and control-char stripped.
 * - allow_test_data lets reserved fictional values (555-01xx, RFC 2606
 *   domains) pass; custom_patterns adds caller regexes (capped + budgeted).
 */

function luhnValid(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function sanitizeMask(mask) {
  if (typeof mask !== 'string' || mask.length === 0) return '[REDACTED]';
  // Strip control chars (log-injection) and cap length.
  // eslint-disable-next-line no-control-regex
  return mask.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 64) || '[REDACTED]';
}

function execute(args) {
  const {
    text,
    redact_credit_cards = true,
    redact_emails = true,
    redact_phones = true,
    redact_ssn = true,
    redact_api_keys = true,
    replacement_mask = '[REDACTED]',
    allow_test_data = false,
    custom_patterns = []
  } = args;

  if (typeof text !== 'string') {
    throw new Error('"text" parameter must be a string.');
  }

  const mask = sanitizeMask(replacement_mask);

  // Reserved fictional ranges (RFC 2606 documentation domains, NANP 555-01xx)
  // that `allow_test_data: true` lets through unredacted. Everything else —
  // including documentation test card numbers — is always redacted.
  const TEST_DOMAINS = ['example.com', 'example.net', 'example.org'];
  function isTestData(type, match) {
    if (type === 'phone') {
      return /55501\d\d/.test(String(match).replace(/\D/g, ''));
    }
    if (type === 'email') {
      const domain = (String(match).split('@')[1] || '').toLowerCase();
      return TEST_DOMAINS.includes(domain) || domain === 'localhost' ||
        domain.endsWith('.test') || domain.endsWith('.localhost');
    }
    return false;
  }

  // Single-pass collection over the ORIGINAL text in priority order (cards,
  // emails, SSNs, phones, keys, custom). Earlier passes claim their spans so
  // later passes can never match inside a redacted region — the precedence
  // sequential replacement provided — while every hit keeps true source
  // offsets for highlight / audit / selective-restore flows.
  const claimed = [];
  const hits = [];
  const overlapsClaimed = (s, e) => claimed.some(c => s < c.end && e > c.start);
  const pushHit = (type, raw, start, end, recordLast4) => {
    const digits = String(raw).replace(/\D/g, '');
    hits.push({
      type,
      length: String(raw).length,
      // Last-4 only, and only for digit-bearing finds. Never a prefix:
      // prefixes identify issuers / key types and aid phishing.
      last4: recordLast4 !== false && digits.length >= 4 ? digits.slice(-4) : undefined,
      start,
      end,
    });
  };

  const collect = (re, type, opts = {}) => {
    const { valueGroup = 0, accept = null, rawOf = null, recordLast4 = true, deadlineMs = 0 } = opts;
    re.lastIndex = 0;
    let m;
    let guard = 0;
    while ((m = re.exec(text)) !== null) {
      if (++guard > 200000) {
        const err = new Error('Pattern matching exceeded max of 200000 matches.');
        err.statusCode = 413;
        throw err;
      }
      if (deadlineMs && Date.now() > deadlineMs) {
        const err = new Error('Custom pattern matching exceeded time budget.');
        err.statusCode = 413;
        throw err;
      }
      if (!m[0]) { re.lastIndex = m.index + 1; continue; }
      if (accept && !accept(m)) continue;
      let start = m.index;
      let end = m.index + m[0].length;
      let prefix = '';
      // Generic-assignment patterns keep the key name, redact only the value.
      if (valueGroup > 0 && m[valueGroup] && m[0].includes(m[valueGroup])) {
        const vs = m[0].indexOf(m[valueGroup]);
        prefix = m[0].slice(0, vs);
        start = m.index + vs;
        end = start + m[valueGroup].length;
      }
      if (overlapsClaimed(start, end)) continue;
      if (allow_test_data === true && isTestData(type, m[0])) continue;
      claimed.push({ start, end });
      const spanText = text.slice(start, end);
      pushHit(type, rawOf ? rawOf(m, spanText) : spanText, start, end, recordLast4);
      hits[hits.length - 1].prefix = prefix;
    }
  };

  // 1. Credit cards: 13–19 digits (spaced/dashed/plain) + Luhn check.
  if (redact_credit_cards) {
    collect(/\b(?:\d[ -]?){13,19}\b/g, 'credit_card', {
      rawOf: (m) => m[0].replace(/\D/g, ''),
      accept: (m) => {
        const digits = m[0].replace(/\D/g, '');
        return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
      },
    });
  }

  // 2. Email addresses (unchanged semantics, no raw preview).
  if (redact_emails) {
    collect(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, 'email');
  }

  // 3. US SSNs (unchanged pattern, no raw preview).
  if (redact_ssn) {
    collect(/\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g, 'ssn');
  }

  // 4. Phone numbers — require a separator, parens, or leading +.
  // Plain 10-digit runs (order IDs, years, counts) are NOT redacted.
  if (redact_phones) {
    collect(/(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g, 'phone', {
      accept: (m) => {
        const hasSeparator = /[-.\s()]/.test(m[0]) || m[0].trim().startsWith('+');
        if (!hasSeparator) return false;
        // Skip when embedded in a longer digit run (e.g. card fragments).
        const before = m.index > 0 ? text[m.index - 1] : '';
        return !/\d/.test(before);
      },
    });
  }

  // 5. API keys & tokens — extended provider coverage + generic assignment.
  if (redact_api_keys) {
    const patterns = [
      /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      /\brk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
      /\bghp_[A-Za-z0-9]{30,}\b/g,
      /\bgho_[A-Za-z0-9]{30,}\b/g,
      /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
      /\bAKIA[0-9A-Z]{16}\b/g,
      /\bASIA[0-9A-Z]{16}\b/g,
      /\bAIza[0-9A-Za-z\-_]{30,}\b/g,
      /\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      /\bwhsec_[A-Za-z0-9+/=]{16,}\b/g,
      /\bBearer\s+[A-Za-z0-9\-._~+/=]{20,}\b/g,
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    ];
    for (const re of patterns) collect(re, 'api_key');
    // Generic `key = value` / `"secret": "value"` high-entropy assignment.
    collect(/(?:"?(?:api[_-]?key|secret|token|password|passwd|pwd)"?\s*[:=]\s*["']?)([A-Za-z0-9\-._~+/=]{16,})(["']?)/gi, 'api_key', { valueGroup: 1 });
  }

  // 6. Caller-supplied patterns for domain-specific secret shapes. Whole
  // match is redacted as `custom`; summaries carry type + length + offsets
  // only (never last4 — the shape is caller-defined). Guards live here, not
  // just in usage limits, because direct/MCP calls bypass the HTTP guard layer.
  if (Array.isArray(custom_patterns) && custom_patterns.length > 0) {
    if (custom_patterns.length > 20) {
      const err = new Error('"custom_patterns" exceeds max of 20 patterns.');
      err.statusCode = 413;
      throw err;
    }
    const deadlineMs = Date.now() + 500;
    custom_patterns.forEach((src, i) => {
      if (typeof src !== 'string' || src.length === 0 || src.length > 200) {
        const err = new Error(`Custom pattern at index ${i} exceeds max length of 200 chars.`);
        err.statusCode = 413;
        throw err;
      }
      let re;
      try {
        re = new RegExp(src, 'g');
      } catch (_) {
        const err = new Error(`Custom pattern at index ${i} is not a valid regular expression.`);
        err.statusCode = 400;
        throw err;
      }
      collect(re, 'custom', { recordLast4: false, deadlineMs });
    });
  }

  // Splice back-to-front so original offsets stay valid throughout.
  let sanitized = text;
  for (const h of [...hits].sort((a, b) => b.start - a.start)) {
    sanitized = sanitized.slice(0, h.start) + (h.prefix || '') + mask + sanitized.slice(h.end);
  }

  return {
    success: true,
    redacted_text: sanitized,
    redactions_count: hits.length,
    detections_summary: hits.map(h => ({
      type: h.type,
      length: h.length,
      last4: h.last4,
      start: h.start,
      end: h.end,
    })),
  };
}

module.exports = {
  name: 'pii_redactor',
  description: 'Detects and redacts sensitive PII (Luhn-verified credit cards, SSNs, emails, phone numbers, and API tokens) from text before sending to LLMs. Summaries never echo raw secrets.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      text: { type: 'string', description: 'Raw text containing potentially sensitive data' },
      redact_credit_cards: { type: 'boolean', description: 'Redact Luhn-verified credit cards. Default true.' },
      redact_emails: { type: 'boolean', description: 'Redact email addresses. Default true.' },
      redact_phones: { type: 'boolean', description: 'Redact phone numbers. Default true.' },
      redact_ssn: { type: 'boolean', description: 'Redact Social Security Numbers. Default true.' },
      redact_api_keys: { type: 'boolean', description: 'Redact API tokens and secret keys. Default true.' },
      replacement_mask: { type: 'string', description: 'Replacement string, max 64 chars. Default "[REDACTED]".' },
      allow_test_data: { type: 'boolean', description: 'Let reserved fictional values (555-01xx numbers, example.com/.test addresses) pass unredacted. Default false.' },
      custom_patterns: { type: 'array', description: 'Extra regex sources for domain-specific secret shapes (max 20 patterns, 200 chars each). Matched text is redacted as type "custom".', items: { type: 'string' } }
    },
    required: ['text']
  },
  execute
};
