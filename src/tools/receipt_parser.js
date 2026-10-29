/**
 * ReceiptParser Agent Tool
 * Extracts structured financial fields (vendor, date, invoice #, tax, total, category) from raw invoice text
 * Cost: $0.005 / call
 */

const SOFTWARE = 'Software & Cloud Infrastructure';
const FOOD = 'Food & Delivery';
const TRAVEL = 'Travel & Lodging';
const RETAIL = 'Retail & Shopping';
const MEDIA = 'Media & Entertainment';
// Priority order: specific before general (AWS before Amazon, Uber Eats before Uber).
const VENDOR_PATTERNS = [
  [/amazon\s+web\s+services|aws/i, SOFTWARE],
  [/google(\s+cloud|\s+workspace)?/i, SOFTWARE],
  [/digitalocean/i, SOFTWARE],
  [/github/i, SOFTWARE],
  [/stripe/i, SOFTWARE],
  [/slack/i, SOFTWARE],
  [/openai/i, SOFTWARE],
  [/anthropic/i, SOFTWARE],
  [/vercel/i, SOFTWARE],
  [/cloudflare/i, SOFTWARE],
  [/figma/i, SOFTWARE],
  [/notion/i, SOFTWARE],
  [/zoom/i, SOFTWARE],
  [/microsoft/i, SOFTWARE],
  [/adobe/i, SOFTWARE],
  [/salesforce/i, SOFTWARE],
  [/atlassian|jira|confluence/i, SOFTWARE],
  [/hubspot|zendesk|asana|trello|monday/i, SOFTWARE],
  [/twilio|sendgrid|datadog/i, SOFTWARE],
  [/mongodb|heroku|netlify|shopify/i, SOFTWARE],
  [/godaddy|namecheap|hetzner/i, SOFTWARE],
  [/jetbrains|elastic|1password/i, SOFTWARE],
  [/uber\s+eats/i, FOOD],
  [/doordash|grubhub|instacart/i, FOOD],
  [/mcdonald|chipotle|dominos|panera|subway|starbucks|kfc|pizza\s*hut/i, FOOD],
  [/united|delta|southwest|jetblue|alaska\s+air/i, TRAVEL],
  [/british\s+airways|lufthansa|emirates|american\s+airlines/i, TRAVEL],
  [/airbnb|marriott|hilton|hyatt|ihg|expedia|booking\.com/i, TRAVEL],
  [/uber(?!(\s+eats))/i, TRAVEL],
  [/lyft/i, TRAVEL],
  [/amazon/i, RETAIL],
  [/walmart|target|costco|ikea|best\s+buy|ebay|etsy/i, RETAIL],
  [/netflix|spotify|hulu|disney/i, MEDIA],
];

const MONTHS = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6,
  jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12
};
// Normalize to YYYY-MM-DD; null when components don't form a real date.
function toISODate(y, m, d) {
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  const p = n => String(n).padStart(2, '0');
  return `${y}-${p(m)}-${p(d)}`;
}

function execute(args) {
  const { document_text } = args;

  if (typeof document_text !== 'string' || !document_text.trim()) {
    throw new Error('"document_text" parameter must be a non-empty string.');
  }

  const text = document_text;
  let vendor = 'Unknown Vendor';
  let date = null;
  let date_raw = null;
  let invoice_number = null;
  let tax = 0;
  let total = null;
  let currency = null;
  let category = 'General Expense';
  // Per-field confidence so agents know when to ask the user. Null mirrors
  // a null field: no claim is made about undetected values.
  const confidence = { vendor: null, date: null, invoice_number: null, tax_amount: null, total_amount: null };

  // 1. Detect Vendor
  for (const [pat, cat] of VENDOR_PATTERNS) {
    const match = text.match(pat);
    if (match) {
      vendor = match[0].toUpperCase();
      category = cat;
      confidence.vendor = 0.85;
      break;
    }
  }

  if (vendor === 'Unknown Vendor') {
    // Fallback: Check top lines
    const topLines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 5);
    for (const line of topLines) {
      if (line.length > 2 && !line.match(/invoice|receipt|bill\s+to|date|order/i)) {
        vendor = line;
        confidence.vendor = 0.5;
        break;
      }
    }
    if (confidence.vendor === null) confidence.vendor = 0.2;
  }

  // 2. Detect Date, normalized to YYYY-MM-DD (raw kept for traceability).
  const datePatterns = [
    { re: /\b((20\d{2})[-\/.](0?[1-9]|1[0-2])[-\/.](0?[1-9]|[12]\d|3[01]))\b/, parts: m => [Number(m[2]), Number(m[3]), Number(m[4])] },
    { re: /\b((0?[1-9]|1[0-2])[-\/.](0?[1-9]|[12]\d|3[01])[-\/.]((?:20)?\d{2}))\b/, parts: m => [m[4].length === 2 ? 2000 + Number(m[4]) : Number(m[4]), Number(m[2]), Number(m[3])] },
    { re: /\b((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{1,2}),?\s+(20\d{2}))\b/i, parts: m => [Number(m[4]), MONTHS[m[2].toLowerCase().slice(0, 3)], Number(m[3])] },
  ];
  for (const dp of datePatterns) {
    const match = text.match(dp.re);
    if (match) {
      date_raw = match[1];
      const [y, mo, d] = dp.parts(match);
      date = toISODate(y, mo, d);
      confidence.date = date ? 0.9 : 0.4;
      break;
    }
  }

  // 3. Detect Invoice #
  const invMatch = text.match(/(?:invoice|inv|receipt|order|bill)\s*(?:#|no\.?|num)?\s*[:\s]?\s*([A-Z0-9_\-]{4,25})/i);
  if (invMatch) {
    invoice_number = invMatch[1];
    confidence.invoice_number = 0.85;
  }

  // 4. Detect Totals and Tax. Decimal amounts first; whole amounts only with
  // an explicit currency symbol on a total keyword line (bare integers are
  // dates, quantities, or order numbers — never totals).
  const parseMoney = s => parseFloat(String(s).replace(/,/g, ''));
  const moneyRegex = /(?:total(?:\s+due)?|amount\s+due|grand\s+total|balance\s+due)\s*[:\s]?\s*[\$€£]?\s*([0-9,]+\.[0-9]{2})/i;
  const totalMatch = text.match(moneyRegex);
  if (totalMatch) {
    total = parseMoney(totalMatch[1]);
    confidence.total_amount = 0.95;
  } else {
    const wholeMatch = text.match(/(?:total(?:\s+due)?|amount\s+due|grand\s+total|balance\s+due)[^\n]*?[\$€£]\s*([0-9,]+)(?![0-9.])/i);
    if (wholeMatch) {
      total = parseMoney(wholeMatch[1]);
      confidence.total_amount = 0.7;
    }
  }

  const taxRegex = /(?:tax|vat|gst|sales\s+tax)\s*[:\s]?\s*[\$€£]?\s*([0-9,]+\.[0-9]{2})/i;
  const taxMatch = text.match(taxRegex);
  if (taxMatch) {
    tax = parseMoney(taxMatch[1]);
    confidence.tax_amount = 0.9;
  }

  const curSym = text.match(/[\$€£]/);
  const curCode = text.match(/\b(USD|EUR|GBP|CAD|AUD|JPY|INR)\b/i);
  currency = curSym ? curSym[0] : (curCode ? curCode[1].toUpperCase() : null);

  // Extract possible line items (whole amounts require a currency symbol).
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const possible_items = [];
  lines.forEach(l => {
    const m = l.match(/(.+?)\s+([\$€£]?[0-9,]+(?:\.[0-9]{2})?)$/);
    if (m && !l.match(/total|tax|subtotal|balance/i)) {
      const hasCents = /\.\d{2}$/.test(m[2]);
      const hasSym = /[\$€£]/.test(m[2]);
      if (hasCents || hasSym) {
        possible_items.push({
          description: m[1].trim(),
          amount: parseMoney(m[2].replace(/[\$€£]/g, ''))
        });
      }
    }
  });

  return {
    success: true,
    data: {
      vendor,
      date,
      date_raw,
      invoice_number,
      tax_amount: tax,
      total_amount: total,
      currency,
      category,
      confidence,
      detected_line_items: possible_items.slice(0, 10)
    }
  };
}

module.exports = {
  name: 'receipt_parser',
  description: 'Parses unstructured invoice, receipt, or billing text into structured financial JSON: vendor, date, invoice number, tax, total, and line items.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      document_text: { type: 'string', description: 'Raw text of the receipt or invoice' }
    },
    required: ['document_text']
  },
  execute
};
