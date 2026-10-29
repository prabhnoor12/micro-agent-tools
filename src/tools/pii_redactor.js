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
 * - replacement_mask is length-capped and control-char stripped.
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
    replacement_mask = '[REDACTED]'
  } = args;

  if (typeof text !== 'string') {
    throw new Error('"text" parameter must be a string.');
  }

  const mask = sanitizeMask(replacement_mask);
  let sanitized = text;
  const detections = [];
  const push = (type, raw) => {
    const digits = String(raw).replace(/\D/g, '');
    detections.push({
      type,
      length: String(raw).length,
      // Last-4 only, and only for digit-bearing finds. Never a prefix:
      // prefixes identify issuers / key types and aid phishing.
      last4: digits.length >= 4 ? digits.slice(-4) : undefined,
    });
  };

  // 1. Credit cards: 13–19 digits (spaced/dashed/plain) + Luhn check.
  if (redact_credit_cards) {
    const ccRegex = /\b(?:\d[ -]?){13,19}\b/g;
    sanitized = sanitized.replace(ccRegex, (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length < 13 || digits.length > 19) return match;
      if (!luhnValid(digits)) return match;
      push('credit_card', digits);
      return mask;
    });
  }

  // 2. Email addresses (unchanged semantics, no raw preview).
  if (redact_emails) {
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    sanitized = sanitized.replace(emailRegex, (match) => {
      push('email', match);
      return mask;
    });
  }

  // 3. US SSNs (unchanged pattern, no raw preview).
  if (redact_ssn) {
    const ssnRegex = /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g;
    sanitized = sanitized.replace(ssnRegex, (match) => {
      push('ssn', match);
      return mask;
    });
  }

  // 4. Phone numbers — require a separator, parens, or leading +.
  // Plain 10-digit runs (order IDs, years, counts) are NOT redacted.
  if (redact_phones) {
    const phoneRegex = /(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
    sanitized = sanitized.replace(phoneRegex, (match, offset, full) => {
      const hasSeparator = /[-.\s()]/.test(match) || match.trim().startsWith('+');
      if (!hasSeparator) return match;
      // Skip when embedded in a longer digit run (e.g. card fragments).
      const before = offset > 0 ? full[offset - 1] : '';
      if (/\d/.test(before)) return match;
      push('phone', match);
      return mask;
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
      // Generic `key = value` / `"secret": "value"` high-entropy assignment.
      /(?:"?(?:api[_-]?key|secret|token|password|passwd|pwd)"?\s*[:=]\s*["']?)([A-Za-z0-9\-._~+/=]{16,})(["']?)/gi,
    ];
    for (const re of patterns) {
      sanitized = sanitized.replace(re, (...m) => {
        const match = m[0];
        // Generic-assignment pattern keeps the key name, redacts only the value.
        if (m.length > 3 && m[1] && match.includes(m[1])) {
          push('api_key', m[1]);
          return match.replace(m[1], mask);
        }
        push('api_key', match);
        return mask;
      });
    }
  }

  return {
    success: true,
    redacted_text: sanitized,
    redactions_count: detections.length,
    detections_summary: detections
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
      replacement_mask: { type: 'string', description: 'Replacement string, max 64 chars. Default "[REDACTED]".' }
    },
    required: ['text']
  },
  execute
};
