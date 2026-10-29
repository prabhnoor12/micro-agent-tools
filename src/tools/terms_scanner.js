/**
 * TermsScanner Agent Tool
 * Contract & Terms of Service Risk Analyzer
 * Cost: $0.003 / call
 */

const RISK_RULES = [
  {
    id: 'forced_arbitration',
    category: 'Legal Rights',
    severity: 'HIGH',
    title: 'Forced Binding Arbitration & Class Action Waiver',
    regex: /(binding\s+arbitration|waive\s+(any\s+)?right\s+to\s+(participate\s+in\s+)?(a\s+)?class\s+action|dispute\s+resolution\s+by\s+arbitration|american\s+arbitration\s+association)/i,
    explanation: 'Strips your legal right to file a lawsuit or participate in a class-action suit in court, forcing private arbitration.'
  },
  {
    id: 'ai_data_harvesting',
    category: 'Privacy & AI',
    severity: 'HIGH',
    title: 'AI Model Training on Customer Data',
    regex: /(train(ing)?\s+(our\s+)?(machine\s+learning|ai|artificial\s+intelligence|models)|improve\s+(our\s+)?algorithms\s+using\s+(your\s+)?(content|data|inputs)|grant\s+.*\s+license\s+to\s+train)/i,
    explanation: 'Permits the vendor to ingest and train internal generative AI models on your private documents and data.'
  },
  {
    id: 'auto_renewal_trap',
    category: 'Billing',
    severity: 'MEDIUM',
    title: 'Hidden Auto-Renewal & Strict Cancellation Window',
    regex: /(automatically\s+renew(s)?|recurring\s+subscription\s+fee|cancel(lation)?\s+(at\s+least\s+)?\d+\s+days\s+prior\s+to\s+renewal)/i,
    explanation: 'Subscription auto-renews automatically unless cancelled strictly within a narrow advance notice window.'
  },
  {
    id: 'unilateral_modification',
    category: 'Governance',
    severity: 'HIGH',
    title: 'Unilateral Terms Modification Without Notice',
    regex: /(modify\s+(these\s+)?terms\s+at\s+any\s+time\s+without\s+prior\s+notice|continued\s+use\s+constitutes\s+acceptance\s+of\s+(any\s+)?changes)/i,
    explanation: 'The service can alter pricing, privacy terms, or service obligations at will without notifying you directly.'
  },
  {
    id: 'broad_ip_license',
    category: 'Intellectual Property',
    severity: 'HIGH',
    title: 'Broad Royalty-Free Perpetual IP License',
    regex: /(perpetual(ly)?,\s*irrevocable,\s*royalty-free,\s*worldwide\s+license|reproduce,\s*modify,\s*adapt,\s*publish,\s*translate,\s*create\s+derivative\s+works)/i,
    explanation: 'Grants the provider sweeping, irrevocable commercial rights to copy, modify, and repurpose your uploaded content.'
  },
  {
    id: 'liability_cap_zero',
    category: 'Liability',
    severity: 'MEDIUM',
    title: 'Total Disclaimers of Consequential Damages',
    regex: /(aggregate\s+liability\s+shall\s+(not\s+exceed|be\s+limited\s+to)\s+(\$?\d+|amount\s+paid)|in\s+no\s+event\s+shall\s+.*be\s+liable\s+for\s+any\s+indirect,\s*incidental,\s*special)/i,
    explanation: 'Limits vendor liability strictly to small subscription fees, even in events of severe data loss or outages.'
  }
];

// Negation window: "we will NOT train AI on your data" is protective
// language, not a risk. A negation cue in the ~60 chars before the match
// moves the hit to negated_flags (still visible, never counted). Documented
// heuristic: double negations ("does not limit our right to…") can misread —
// review negated_flags when they appear.
const NEGATION_RE = /\b(not|never|no|without|except|prohibit|forbid|against|opt[\s-]?out|decline|refuse)\b/i;
function isNegated(text, index) {
  return NEGATION_RE.test(text.slice(Math.max(0, index - 60), index));
}

function excerptAround(text, index, length) {
  const snippetStart = Math.max(0, index - 50);
  const snippetEnd = Math.min(text.length, index + length + 120);
  return `"...${text.slice(snippetStart, snippetEnd).trim().replace(/\s+/g, ' ')}..."`;
}

function scanRules(text, rules) {
  const red_flags = [];
  const negated_flags = [];
  let high = 0;
  let medium = 0;
  let low = 0;
  for (const rule of rules) {
    const re = rule.regex instanceof RegExp ? rule.regex : new RegExp(rule.pattern, 'i');
    const match = text.match(re);
    if (!match) continue;
    const index = match.index || 0;
    const hit = {
      id: rule.id,
      category: rule.category || 'Custom',
      severity: rule.severity || 'MEDIUM',
      title: rule.title || rule.id,
      matched_phrase: match[0],
      clause_excerpt: excerptAround(text, index, match[0].length),
      explanation: rule.explanation || ''
    };
    if (isNegated(text, index)) {
      negated_flags.push({ ...hit, note: 'Protective/negated language precedes the match; excluded from risk counts.' });
      continue;
    }
    if (hit.severity === 'HIGH') high++;
    else if (hit.severity === 'LOW') low++;
    else medium++;
    red_flags.push(hit);
  }
  return { red_flags, negated_flags, high, medium, low };
}

function execute(args) {
  const { terms_text, custom_rules = [] } = args;

  if (typeof terms_text !== 'string' || !terms_text.trim()) {
    throw new Error('"terms_text" parameter must be a non-empty string.');
  }
  const rules_in = Array.isArray(custom_rules) ? custom_rules : [];
  if (rules_in.length > 20) {
    const err = new Error('"custom_rules" exceeds max of 20 rules.');
    err.statusCode = 413;
    throw err;
  }
  const customs = rules_in.map((r, i) => {
    if (!r || typeof r !== 'object' || Array.isArray(r)) {
      const err = new Error(`Custom rule at index ${i} must be an object.`);
      err.statusCode = 400;
      throw err;
    }
    if (typeof r.id !== 'string' || !r.id) {
      const err = new Error(`Custom rule at index ${i} requires a string "id".`);
      err.statusCode = 400;
      throw err;
    }
    if (typeof r.pattern !== 'string' || !r.pattern) {
      const err = new Error(`Custom rule at index ${i} requires a string "pattern".`);
      err.statusCode = 400;
      throw err;
    }
    if (r.pattern.length > 500) {
      const err = new Error(`Custom rule at index ${i} exceeds max pattern length of 500 chars.`);
      err.statusCode = 413;
      throw err;
    }
    try {
      // eslint-disable-next-line no-new
      new RegExp(r.pattern, 'i');
    } catch (_) {
      const err = new Error(`Custom rule at index ${i} is not a valid regular expression.`);
      err.statusCode = 400;
      throw err;
    }
    return { id: r.id, category: r.category, severity: r.severity, title: r.title, explanation: r.explanation, pattern: r.pattern };
  });

  const base = scanRules(terms_text, RISK_RULES);
  const custom = scanRules(terms_text, customs);
  const red_flags = [...base.red_flags, ...custom.red_flags];
  const negated_flags = [...base.negated_flags, ...custom.negated_flags];
  const highCount = base.high + custom.high;
  const mediumCount = base.medium + custom.medium;
  const lowCount = base.low + custom.low;

  let overall_risk = 'LOW';
  if (highCount >= 2) overall_risk = 'CRITICAL';
  else if (highCount === 1) overall_risk = 'HIGH';
  else if (mediumCount > 0) overall_risk = 'MEDIUM';

  return {
    success: true,
    overall_risk,
    risk_score: Math.min(100, highCount * 30 + mediumCount * 10 + lowCount * 5),
    total_flags_detected: red_flags.length,
    high_severity_count: highCount,
    medium_severity_count: mediumCount,
    low_severity_count: lowCount,
    red_flags,
    negated_flags
  };
}

module.exports = {
  name: 'terms_risk_scanner',
  description: 'Scans contract and Terms of Service text for hidden legal traps: forced arbitration, AI training clauses, unilateral changes, and auto-renewals.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      terms_text: { type: 'string', description: 'Legal agreement or terms of service text to analyze' },
      custom_rules: {
        type: 'array',
        description: 'Extra caller-defined risk rules (max 20). Each needs id + pattern; severity/category/title/explanation optional.',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Stable rule identifier' },
            pattern: { type: 'string', description: 'Regular expression source (case-insensitive), max 500 chars' },
            severity: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'], description: 'Default "MEDIUM".' },
            category: { type: 'string' },
            title: { type: 'string' },
            explanation: { type: 'string' }
          }
        }
      }
    },
    required: ['terms_text']
  },
  execute
};
