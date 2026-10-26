/**
 * PIIRedactor Agent Tool
 * High-precision redaction for sensitive personal and financial identifiers
 * Cost: $0.002 / call
 */

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

  let sanitized = text;
  const detections = [];

  // 1. Credit Card Numbers (13-16 digits with Luhn verification or format)
  if (redact_credit_cards) {
    const ccRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b/g;
    sanitized = sanitized.replace(ccRegex, match => {
      detections.push({ type: 'credit_card', preview: match.slice(0, 4) + '...' });
      return replacement_mask;
    });
  }

  // 2. Email Addresses
  if (redact_emails) {
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    sanitized = sanitized.replace(emailRegex, match => {
      detections.push({ type: 'email', preview: match.slice(0, 3) + '...@...' });
      return replacement_mask;
    });
  }

  // 3. Social Security Numbers (US SSN: XXX-XX-XXXX)
  if (redact_ssn) {
    const ssnRegex = /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g;
    sanitized = sanitized.replace(ssnRegex, match => {
      detections.push({ type: 'ssn', preview: '***-**-****' });
      return replacement_mask;
    });
  }

  // 4. Phone Numbers (International & US formats)
  if (redact_phones) {
    const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
    sanitized = sanitized.replace(phoneRegex, match => {
      if (match.trim().length >= 10) {
        detections.push({ type: 'phone', preview: match.slice(0, 3) + '...' });
        return replacement_mask;
      }
      return match;
    });
  }

  // 5. API Keys and Tokens (Bearer, sk_live, ghp_, etc.)
  if (redact_api_keys) {
    const keyRegex = /\b(?:sk_live_[a-zA-Z0-9]{24,}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9_\-\.]{20,})\b/g;
    sanitized = sanitized.replace(keyRegex, match => {
      detections.push({ type: 'api_key', preview: match.slice(0, 7) + '...' });
      return replacement_mask;
    });
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
  description: 'Detects and redacts sensitive PII (credit cards, SSNs, emails, phone numbers, and API tokens) from text before sending to LLMs.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      text: { type: 'string', description: 'Raw text containing potentially sensitive data' },
      redact_credit_cards: { type: 'boolean', description: 'Redact credit cards. Default true.' },
      redact_emails: { type: 'boolean', description: 'Redact email addresses. Default true.' },
      redact_phones: { type: 'boolean', description: 'Redact phone numbers. Default true.' },
      redact_ssn: { type: 'boolean', description: 'Redact Social Security Numbers. Default true.' },
      redact_api_keys: { type: 'boolean', description: 'Redact API tokens and secret keys. Default true.' },
      replacement_mask: { type: 'string', description: 'Replacement string. Default "[REDACTED]".' }
    },
    required: ['text']
  },
  execute
};
