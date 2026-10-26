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

function execute(args) {
  const { terms_text } = args;

  if (typeof terms_text !== 'string' || !terms_text.trim()) {
    throw new Error('"terms_text" parameter must be a non-empty string.');
  }

  const red_flags = [];
  let highCount = 0;
  let mediumCount = 0;

  RISK_RULES.forEach(rule => {
    const match = terms_text.match(rule.regex);
    if (match) {
      if (rule.severity === 'HIGH') highCount++;
      else mediumCount++;

      // Extract context snippet
      const index = match.index || 0;
      const snippetStart = Math.max(0, index - 50);
      const snippetEnd = Math.min(terms_text.length, index + match[0].length + 120);
      const excerpt = terms_text.slice(snippetStart, snippetEnd).trim().replace(/\s+/g, ' ');

      red_flags.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        matched_phrase: match[0],
        clause_excerpt: `"...${excerpt}..."`,
        explanation: rule.explanation
      });
    }
  });

  let overall_risk = 'LOW';
  if (highCount >= 2) overall_risk = 'CRITICAL';
  else if (highCount === 1) overall_risk = 'HIGH';
  else if (mediumCount > 0) overall_risk = 'MEDIUM';

  return {
    success: true,
    overall_risk,
    total_flags_detected: red_flags.length,
    high_severity_count: highCount,
    medium_severity_count: mediumCount,
    red_flags
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
      terms_text: { type: 'string', description: 'Legal agreement or terms of service text to analyze' }
    },
    required: ['terms_text']
  },
  execute
};
