/**
 * ReceiptParser Agent Tool
 * Extracts structured financial fields (vendor, date, invoice #, tax, total, category) from raw invoice text
 * Cost: $0.005 / call
 */

const VENDOR_PATTERNS = [
  /amazon(\.com|\s+web\s+services|aws)?/i,
  /google(\s+cloud|\s+workspace)?/i,
  /digitalocean/i,
  /github/i,
  /stripe/i,
  /slack/i,
  /openai/i,
  /anthropic/i,
  /vercel/i,
  /cloudflare/i,
  /figma/i,
  /notion/i,
  /zoom/i,
  /microsoft/i,
  /uber(\s+eats)?/i,
  /starbucks/i
];

function execute(args) {
  const { document_text } = args;

  if (typeof document_text !== 'string' || !document_text.trim()) {
    throw new Error('"document_text" parameter must be a non-empty string.');
  }

  const text = document_text;
  let vendor = 'Unknown Vendor';
  let date = null;
  let invoice_number = null;
  let tax = 0;
  let total = null;
  let category = 'General Expense';

  // 1. Detect Vendor
  for (const pat of VENDOR_PATTERNS) {
    const match = text.match(pat);
    if (match) {
      vendor = match[0].toUpperCase();
      category = 'Software & Cloud Infrastructure';
      break;
    }
  }

  if (vendor === 'Unknown Vendor') {
    // Fallback: Check top lines
    const topLines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 5);
    for (const line of topLines) {
      if (line.length > 2 && !line.match(/invoice|receipt|bill\s+to|date|order/i)) {
        vendor = line;
        break;
      }
    }
  }

  // 2. Detect Date (YYYY-MM-DD or MM/DD/YYYY or Mon DD, YYYY)
  const datePatterns = [
    /\b(20\d{2}[-\/.](?:0?[1-9]|1[0-2])[-\/.](?:0?[1-9]|[12]\d|3[01]))\b/,
    /\b((?:0?[1-9]|1[0-2])[-\/.](?:0?[1-9]|[12]\d|3[01])[-\/.](?:20\d{2}|\d{2}))\b/,
    /\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+20\d{2})\b/i
  ];
  for (const dp of datePatterns) {
    const match = text.match(dp);
    if (match) {
      date = match[1];
      break;
    }
  }

  // 3. Detect Invoice #
  const invMatch = text.match(/(?:invoice|inv|receipt|order|bill)\s*(?:#|no\.?|num)?\s*[:\s]?\s*([A-Z0-9_\-]{4,25})/i);
  if (invMatch) {
    invoice_number = invMatch[1];
  }

  // 4. Detect Totals and Tax
  const moneyRegex = /(?:total(?:\s+due)?|amount\s+due|grand\s+total|balance\s+due)\s*[:\s]?\s*[\$€£]?\s*([0-9,]+\.[0-9]{2})/i;
  const totalMatch = text.match(moneyRegex);
  if (totalMatch) {
    total = parseFloat(totalMatch[1].replace(/,/g, ''));
  }

  const taxRegex = /(?:tax|vat|gst|sales\s+tax)\s*[:\s]?\s*[\$€£]?\s*([0-9,]+\.[0-9]{2})/i;
  const taxMatch = text.match(taxRegex);
  if (taxMatch) {
    tax = parseFloat(taxMatch[1].replace(/,/g, ''));
  }

  // Extract possible line items
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const possible_items = [];
  lines.forEach(l => {
    const m = l.match(/(.+?)\s+[\$€£]?([0-9,]+\.[0-9]{2})$/);
    if (m && !l.match(/total|tax|subtotal|balance/i)) {
      possible_items.push({
        description: m[1].trim(),
        amount: parseFloat(m[2].replace(/,/g, ''))
      });
    }
  });

  return {
    success: true,
    data: {
      vendor,
      date,
      invoice_number,
      tax_amount: tax,
      total_amount: total,
      category,
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
