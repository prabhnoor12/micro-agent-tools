/**
 * InvoiceBuilder Agent Tool
 * Generates structured financial calculations & formatted invoice summaries
 * Cost: $0.002 / call
 */

function execute(args) {
  const {
    doc_type = 'INVOICE',
    number = 'INV-001',
    date = new Date().toISOString().split('T')[0],
    due_date,
    currency = '$',
    from,
    to,
    items = [],
    tax_percent = 0,
    discount_percent = 0,
    shipping = 0,
    payment_instructions = ''
  } = args;

  // Cent-accurate money math: round every ledger step so binary float
  // artifacts (0.1 + 0.2 = 0.30000000000000004) never reach the totals.
  const round2 = n => Math.round((Number(n) || 0) * 100) / 100;
  let subtotal = 0;
  const computedItems = items.map(it => {
    const qty = parseFloat(it.quantity) || 1;
    const rate = parseFloat(it.rate) || 0;
    const amount = round2(qty * rate);
    subtotal = round2(subtotal + amount);
    return {
      description: it.description || 'Service',
      quantity: qty,
      rate,
      amount
    };
  });

  const discountAmount = round2(subtotal * ((parseFloat(discount_percent) || 0) / 100));
  const taxableBase = Math.max(0, round2(subtotal - discountAmount));
  const taxAmount = round2(taxableBase * ((parseFloat(tax_percent) || 0) / 100));
  const grandTotal = round2(taxableBase + taxAmount + (parseFloat(shipping) || 0));

  const format = val => `${currency}${val.toFixed(2)}`;

  const summaryLines = [
    `🧾 ${doc_type}: ${number}`,
    `Date: ${date} | Due: ${due_date || 'Upon Receipt'}`,
    `From: ${from ? (from.name || from) : 'Service Provider'}`,
    `To: ${to ? (to.name || to) : 'Client'}`,
    `----------------------------------------`,
    `Items:`
  ];

  computedItems.forEach(it => {
    summaryLines.push(`• ${it.description} (${it.quantity} @ ${format(it.rate)}) = ${format(it.amount)}`);
  });

  summaryLines.push(`----------------------------------------`);
  summaryLines.push(`Subtotal: ${format(subtotal)}`);
  if (discountAmount > 0) summaryLines.push(`Discount (-${discount_percent}%): -${format(discountAmount)}`);
  if (taxAmount > 0) summaryLines.push(`Tax (+${tax_percent}%): +${format(taxAmount)}`);
  summaryLines.push(`GRAND TOTAL: ${format(grandTotal)}`);
  if (payment_instructions) summaryLines.push(`\nPayment Info:\n${payment_instructions}`);

  return {
    success: true,
    doc_type,
    number,
    totals: {
      subtotal,
      discount_amount: discountAmount,
      tax_amount: taxAmount,
      shipping: round2(shipping),
      grand_total: grandTotal,
      currency
    },
    items: computedItems,
    formatted_text: summaryLines.join('\n')
  };
}

module.exports = {
  name: 'invoice_builder',
  description: 'Calculates line-item totals, taxes, discounts, and generates formatted invoice/estimate breakdowns for client billing.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      doc_type: { type: 'string', enum: ['INVOICE', 'ESTIMATE'], description: 'Document type. Default "INVOICE".' },
      number: { type: 'string', description: 'Invoice number (e.g. "INV-2026-101")' },
      date: { type: 'string', description: 'Issue date (YYYY-MM-DD)' },
      due_date: { type: 'string', description: 'Due date (YYYY-MM-DD)' },
      currency: { type: 'string', description: 'Currency symbol ($, €, £, etc.). Default "$".' },
      from: { type: 'object', description: 'Sender details (name, email, address)' },
      to: { type: 'object', description: 'Client details (name, email, address)' },
      items: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            description: { type: 'string' },
            quantity: { type: 'number' },
            rate: { type: 'number' }
          },
          required: ['description', 'rate']
        },
        description: 'Line items list'
      },
      tax_percent: { type: 'number', description: 'Tax or VAT percentage (e.g. 10 for 10%)' },
      discount_percent: { type: 'number', description: 'Discount percentage' },
      shipping: { type: 'number', description: 'Flat shipping or extra fee' },
      payment_instructions: { type: 'string', description: 'Payment wire/PayPal/Stripe details' }
    },
    required: ['items']
  },
  execute
};
