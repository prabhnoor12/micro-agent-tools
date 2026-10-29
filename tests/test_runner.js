/**
 * Comprehensive Micro-Agent Tools Test Suite
 * Validates all 16 converted tools and MCP JSON-RPC protocol
 */

const { executeTool, listTools } = require('../src/tools/index');
const { handleRpcRequest } = require('../src/mcp/server');

async function runTests() {
  console.log('🧪 Starting Micro-Agent Comprehensive Test Suite (16 Tools)...\n');
  let passed = 0;
  let failed = 0;

  function assert(condition, name) {
    if (condition) {
      console.log(`  ✅ ${name}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${name}`);
      failed++;
    }
  }

  // 1. Tool Catalog
  console.log('--- 1. Tool Catalog ---');
  const catalog = listTools();
  assert(catalog.length === 16, `Catalog has 16 registered tools (found ${catalog.length})`);

  // 2. SheetDiff Test
  console.log('\n--- 2. Tool: sheet_diff ---');
  const diffRes = await executeTool('sheet_diff', {
    baseline_csv: 'sku,name,price\n101,Widget,10.00\n102,Gizmo,20.00',
    updated_csv: 'sku,name,price\n101,Widget,12.50\n103,Doodad,30.00',
    primary_key: 'sku'
  });
  assert(diffRes.stats.added_count === 1, 'SheetDiff detects 1 added row (SKU 103)');
  assert(diffRes.stats.deleted_count === 1, 'SheetDiff detects 1 deleted row (SKU 102)');
  assert(diffRes.stats.modified_count === 1, 'SheetDiff detects 1 modified row (SKU 101)');

  // 2b. SheetDiff capability: numeric-aware compare, duplicates, schema, moves
  const numRes = await executeTool('sheet_diff', {
    baseline_csv: 'sku,price\nA,10\nB,20.00',
    updated_csv: 'sku,price\nA,10.00\nB,20',
    primary_key: 'sku'
  });
  assert(numRes.stats.modified_count === 0, 'SheetDiff numeric compare: 10 vs 10.00 unchanged');
  const tolRes = await executeTool('sheet_diff', {
    baseline_csv: 'sku,price\nA,10.00',
    updated_csv: 'sku,price\nA,10.05',
    primary_key: 'sku',
    numeric_tolerance: 0.1
  });
  assert(tolRes.stats.modified_count === 0, 'SheetDiff tolerance 0.1 absorbs 10.00 vs 10.05');
  const dupRes = await executeTool('sheet_diff', {
    baseline_csv: 'sku,price\nA,1\nA,2',
    updated_csv: 'sku,price\nA,1',
    primary_key: 'sku'
  });
  assert(dupRes.stats.duplicate_key_count === 1, 'SheetDiff reports duplicate primary key');
  assert(dupRes.duplicate_keys.baseline.length === 1 && dupRes.duplicate_keys.baseline[0].key === 'A', 'SheetDiff names the duplicated key');
  const schRes = await executeTool('sheet_diff', {
    baseline_csv: 'sku,cost\nA,1',
    updated_csv: 'sku,price\nA,1',
    primary_key: 'sku'
  });
  assert(schRes.schema_changes.renamed_columns.length === 1 && schRes.schema_changes.renamed_columns[0].from === 'cost' && schRes.schema_changes.renamed_columns[0].to === 'price', 'SheetDiff detects column rename cost->price');
  const movRes = await executeTool('sheet_diff', {
    baseline_csv: 'sku,price\nA,1\nB,2',
    updated_csv: 'sku,price\nB,2\nA,1',
    primary_key: 'sku'
  });
  assert(movRes.stats.moved_count === 2 && movRes.stats.added_count === 0 && movRes.stats.deleted_count === 0, 'SheetDiff reports reorder as moves, not add/delete');

  // 2c. SheetDiff follow-ups: composite keys, delimiter override, header case
  const compRes = await executeTool('sheet_diff', {
    baseline_csv: 'wh,sku,price\nA,1,10\nB,2,20',
    updated_csv: 'wh,sku,price\nA,1,12\nB,3,20',
    primary_key: ['wh', 'sku']
  });
  assert(compRes.stats.modified_count === 1 && compRes.stats.added_count === 1 && compRes.stats.deleted_count === 1, 'SheetDiff composite key matches on wh+sku');
  assert(compRes.primary_key_used === 'wh+sku', 'SheetDiff reports composite key in use');
  const pipeRes = await executeTool('sheet_diff', {
    baseline_csv: 'a|b\n1|2',
    updated_csv: 'a|b\n1|3',
    delimiter: '|'
  });
  assert(pipeRes.stats.modified_count === 1 && pipeRes.primary_key_used === 'a', 'SheetDiff delimiter override parses pipe-separated sheets');
  const hcaseRes = await executeTool('sheet_diff', {
    baseline_csv: 'SKU,Price\nA,10',
    updated_csv: 'sku,price\nA,10'
  });
  assert(hcaseRes.stats.modified_count === 0 && hcaseRes.stats.unchanged_count === 1, 'SheetDiff matches headers case-insensitively by default');
  const hcaseStrict = await executeTool('sheet_diff', {
    baseline_csv: 'sku,Price\nA,10',
    updated_csv: 'sku,price\nA,10',
    headers_case_sensitive: true
  });
  assert(hcaseStrict.stats.modified_count === 1, 'SheetDiff headers_case_sensitive restores strict columns');

  // 3. TextCleaner Test
  console.log('\n--- 3. Tool: text_cleaner ---');
  const cleanRes = await executeTool('text_cleaner', {
    text: 'Check: https://example.com/blog?utm_source=twitter&fbclid=123 \u201CHello\u201D\nworld'
  });
  assert(!cleanRes.cleaned_text.includes('utm_source'), 'TextCleaner stripped UTM tracking');

  // 3b. TextCleaner follow-ups: wrap counts, new tracking keys, HTML stripping
  const wrapRes = await executeTool('text_cleaner', { text: 'line one\ncontinued here and\nmore text\n\nNew para' });
  assert(wrapRes.stats.line_wraps_fixed === 2 && wrapRes.cleaned_text.includes('line one continued here and more text'), 'TextCleaner counts every fixed line wrap');
  const keyRes = await executeTool('text_cleaner', { text: 'See https://example.com/a?gbraid=abc&dclid=x&ttclid=y&q=keep' });
  assert(!keyRes.cleaned_text.includes('gbraid') && !keyRes.cleaned_text.includes('dclid') && !keyRes.cleaned_text.includes('ttclid') && keyRes.cleaned_text.includes('q=keep'), 'TextCleaner strips newer ad click IDs, keeps real params');
  const htmlRes = await executeTool('text_cleaner', { text: '<p>Hello <b>World</b></p><script>var x = 1;</script>' });
  assert(!htmlRes.cleaned_text.includes('<') && htmlRes.cleaned_text.includes('Hello') && htmlRes.cleaned_text.includes('World') && !htmlRes.cleaned_text.includes('var x'), 'TextCleaner strips HTML tags and script content');
  assert(htmlRes.stats.html_tags_removed > 0, 'TextCleaner reports stripped tag count');

  // 4. PIIRedactor Test
  console.log('\n--- 4. Tool: pii_redactor ---');
  const redactRes = await executeTool('pii_redactor', {
    // 4111-1111-1111-1111 is the standard Luhn-valid Visa test number
    // (the old 4111-2222-3333-4444 fails Luhn and must NOT match).
    text: 'Call alex@example.com at 555-123-4567. Card: 4111-1111-1111-1111'
  });
  assert(redactRes.redactions_count === 3, 'PIIRedactor detected 3 PII entities');

  // 4b. PIIRedactor capability: offsets, test-data allowlist, custom patterns
  const spanText = 'Call alex@example.com now';
  const spanRes = await executeTool('pii_redactor', { text: spanText });
  const emailHit = spanRes.detections_summary.find(d => d.type === 'email');
  assert(emailHit && emailHit.start === spanText.indexOf('alex@example.com') && emailHit.end === spanText.indexOf('alex@example.com') + 16, 'PIIRedactor reports source offsets per detection');
  assert(spanText.slice(emailHit.start, emailHit.end) === 'alex@example.com', 'PIIRedactor offsets slice the exact match');
  const ficRes = await executeTool('pii_redactor', { text: 'Call 555-014-0199, mail ops@example.com', allow_test_data: true });
  assert(ficRes.redactions_count === 0, 'PIIRedactor allow_test_data lets fictional values through');
  const ficDefault = await executeTool('pii_redactor', { text: 'Call 555-014-0199, mail ops@example.com' });
  assert(ficDefault.redactions_count === 2, 'PIIRedactor still redacts fictional-looking values by default');
  const custRes = await executeTool('pii_redactor', { text: 'deploy INTERNAL-1234 now', custom_patterns: ['INTERNAL-[0-9]{4}'] });
  assert(custRes.redactions_count === 1 && custRes.detections_summary[0].type === 'custom' && !custRes.redacted_text.includes('INTERNAL-1234'), 'PIIRedactor custom pattern redacts domain secret');
  assert(custRes.detections_summary[0].last4 === undefined, 'PIIRedactor custom detections carry no last4');

  // 4c. PIIRedactor follow-ups: pseudonyms, IBAN, confidence
  const pseudoRes = await executeTool('pii_redactor', { text: 'mail a@x.com and a@x.com, call 555-123-4567', pseudonymize: true });
  const pseudoMails = pseudoRes.detections_summary.filter(d => d.type === 'email');
  assert(pseudoRes.redactions_count === 3, 'PIIRedactor pseudonymize still redacts all hits');
  assert(pseudoMails.length === 2 && pseudoMails[0].surrogate === pseudoMails[1].surrogate && /^\[EMAIL-\d+\]$/.test(pseudoMails[0].surrogate), 'PIIRedactor same value reuses the same surrogate');
  assert(!pseudoRes.redacted_text.includes('a@x.com') && pseudoRes.redacted_text.includes(pseudoMails[0].surrogate), 'PIIRedactor surrogates appear in redacted text');
  const seedA = await executeTool('pii_redactor', { text: 'key a@x.com', pseudonymize: true, pseudonym_seed: 's1' });
  const seedB = await executeTool('pii_redactor', { text: 'key a@x.com', pseudonymize: true, pseudonym_seed: 's1' });
  const seedC = await executeTool('pii_redactor', { text: 'key a@x.com', pseudonymize: true, pseudonym_seed: 's2' });
  assert(seedA.detections_summary[0].surrogate === seedB.detections_summary[0].surrogate, 'PIIRedactor seeded surrogates are deterministic');
  assert(seedA.detections_summary[0].surrogate !== seedC.detections_summary[0].surrogate, 'PIIRedactor surrogates differ across seeds');
  assert(!JSON.stringify(seedA).includes('s1'), 'PIIRedactor never echoes the pseudonym seed');
  const ibanRes = await executeTool('pii_redactor', { text: 'pay GB29NWBK60161331926819 or GB29NWBK60161331926818' });
  assert(ibanRes.redactions_count === 1 && ibanRes.detections_summary[0].type === 'iban' && !ibanRes.redacted_text.includes('GB29NWBK60161331926819') && ibanRes.redacted_text.includes('GB29NWBK60161331926818'), 'PIIRedactor redacts mod-97-valid IBAN only');
  assert(typeof ibanRes.detections_summary[0].confidence === 'number' && ibanRes.detections_summary[0].confidence > 0 && ibanRes.detections_summary[0].confidence <= 1, 'PIIRedactor reports confidence per detection');

  // 5. TermsScanner Test
  console.log('\n--- 5. Tool: terms_risk_scanner ---');
  const termsRes = await executeTool('terms_risk_scanner', {
    terms_text: 'All disputes must be resolved by binding arbitration. We may train artificial intelligence algorithms using your content.'
  });
  assert(termsRes.total_flags_detected >= 2, 'TermsScanner detected arbitration & AI training');

  // 5b. TermsScanner follow-ups: negation guard, custom rules, risk score
  const negRes = await executeTool('terms_risk_scanner', {
    terms_text: 'We will never train AI models on your data. All disputes must be resolved by binding arbitration.'
  });
  assert(negRes.total_flags_detected === 1 && negRes.negated_flags.length === 1 && negRes.negated_flags[0].id === 'ai_data_harvesting', 'TermsScanner moves negated AI-training language out of risk counts');
  const custRuleRes = await executeTool('terms_risk_scanner', {
    terms_text: 'A $500 early termination fee applies. All disputes must be resolved by binding arbitration.',
    custom_rules: [{ id: 'early_fee', pattern: 'early termination fee', severity: 'MEDIUM', title: 'Early Termination Fee' }]
  });
  assert(custRuleRes.total_flags_detected === 2 && custRuleRes.red_flags.some(f => f.id === 'early_fee'), 'TermsScanner fires caller-defined custom rules');
  assert(typeof custRuleRes.risk_score === 'number' && custRuleRes.risk_score === 40, 'TermsScanner risk score weights HIGH=30 + MEDIUM=10');

  // 6. ReceiptParser Test
  console.log('\n--- 6. Tool: receipt_parser ---');
  const receiptRes = await executeTool('receipt_parser', {
    document_text: 'AMAZON WEB SERVICES\nInvoice #: AWS-1234\nDate: 2026-10-15\nTotal Due: $150.00'
  });
  assert(receiptRes.data.vendor === 'AMAZON WEB SERVICES', 'ReceiptParser detected AWS');
  assert(receiptRes.data.total_amount === 150.00, 'ReceiptParser parsed total $150.00');

  // 6b. ReceiptParser follow-ups: whole amounts, vendors, ISO dates, confidence
  const wholeRes = await executeTool('receipt_parser', {
    document_text: 'DOORDASH\nDate: Oct 5, 2026\nTotal Due: $42'
  });
  assert(wholeRes.data.total_amount === 42, 'ReceiptParser parses whole-dollar totals with a currency symbol');
  assert(wholeRes.data.vendor === 'DOORDASH' && wholeRes.data.category === 'Food & Delivery', 'ReceiptParser classifies food vendors');
  assert(wholeRes.data.date === '2026-10-05' && wholeRes.data.date_raw === 'Oct 5, 2026', 'ReceiptParser normalizes dates to ISO with raw kept');
  assert(wholeRes.data.confidence && wholeRes.data.confidence.vendor === 0.85 && wholeRes.data.confidence.total_amount === 0.7, 'ReceiptParser reports per-field confidence');
  const noFalseTotal = await executeTool('receipt_parser', {
    document_text: 'ACME\nOrder 150\nDate: 2026-10-15'
  });
  assert(noFalseTotal.data.total_amount === null, 'ReceiptParser never mistakes bare integers for totals');

  // 7. InvoiceBuilder Test
  console.log('\n--- 7. Tool: invoice_builder ---');
  const invRes = await executeTool('invoice_builder', {
    items: [{ description: 'Dev Work', quantity: 10, rate: 100 }],
    tax_percent: 10
  });
  assert(invRes.totals.grand_total === 1100, 'InvoiceBuilder computed grand total with tax $1100');
  const floatRes = await executeTool('invoice_builder', {
    items: [{ description: 'A', quantity: 1, rate: 0.1 }, { description: 'B', quantity: 1, rate: 0.2 }]
  });
  assert(floatRes.totals.subtotal === 0.3 && floatRes.totals.grand_total === 0.3, 'InvoiceBuilder rounds ledger math to exact cents');

  // 8. OGCardGenerator Test
  console.log('\n--- 8. Tool: og_card_generator ---');
  const ogRes = await executeTool('og_card_generator', {
    title: 'Autonomous Agents',
    description: 'The future of software'
  });
  assert(ogRes.svg_card.includes('<svg'), 'OGCardGenerator produced valid SVG');

  // 8b. OGCard follow-ups: word-wrap, strict theme
  const wrapOg = await executeTool('og_card_generator', {
    title: 'Alpha Beta Gamma Delta Epsilon Zeta Eta Theta Iota Kappa Lambda Mu',
    description: 'one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen'
  });
  const words = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Zeta', 'Eta', 'Theta', 'Iota', 'Kappa', 'Lambda', 'Mu'];
  assert(words.every(w => wrapOg.svg_card.includes(w)), 'OGCardGenerator wraps the full title without clipping words');
  assert(!wrapOg.svg_card.includes('Alph</text>') && !wrapOg.svg_card.includes('Gam</text>'), 'OGCardGenerator never truncates mid-word');
  await executeTool('og_card_generator', { title: 'x' }).then(
    () => assert(true, 'OGCardGenerator default theme renders'),
    () => assert(false, 'OGCardGenerator default theme renders')
  );
  let themeRejected = false;
  try {
    await executeTool('og_card_generator', { title: 'x', theme: 'hacker' });
  } catch (e) {
    themeRejected = e && e.statusCode === 400;
  }
  assert(themeRejected, 'OGCardGenerator rejects unknown theme with 400');

  // 9. CodeCardGenerator Test (QuickShot)
  console.log('\n--- 9. Tool: code_card_generator ---');
  const codeRes = await executeTool('code_card_generator', {
    code: 'const greeting = "Hello Autonomous World";\nconsole.log(greeting);',
    language: 'javascript',
    title: 'agent.js'
  });
  assert(codeRes.svg_code_card.includes('<svg') && codeRes.total_lines === 2, 'CodeCardGenerator rendered 2-line code card SVG');

  // 9b. CodeCard follow-up: tokens actually highlighted
  const hlRes = await executeTool('code_card_generator', {
    code: 'const greeting = "hi"; // say hi',
    language: 'javascript',
    title: 'agent.js'
  });
  assert(hlRes.svg_code_card.includes('<tspan fill="#a78bfa">const</tspan>'), 'CodeCardGenerator tints keywords');
  assert(hlRes.svg_code_card.includes('<tspan fill="#34d399">&quot;hi&quot;</tspan>'), 'CodeCardGenerator tints strings without splitting them');
  assert(hlRes.svg_code_card.includes('<tspan fill="#64748b">// say hi</tspan>'), 'CodeCardGenerator tints full-line comments over inner quotes');

  // 10. PDFProcessor Test (DocuMerge, DocuFiller, SignEasy)
  console.log('\n--- 10. Tool: pdf_processor ---');
  const samplePdfRes = await executeTool('pdf_processor', { mode: 'sample' });
  assert(samplePdfRes.success && samplePdfRes.pdf_base64, 'PDFProcessor generated in-memory sample PDF');

  const fillPdfRes = await executeTool('pdf_processor', {
    mode: 'fill',
    pdf_base64: samplePdfRes.pdf_base64,
    fields: [
      { page: 1, type: 'text', text: 'Autonomous Agent Corp', x_percent: 0.35, y_percent: 0.17 },
      { page: 1, type: 'check', x_percent: 0.1, y_percent: 0.25 }
    ]
  });
  assert(fillPdfRes.annotations_count === 2, 'PDFProcessor applied 2 vector annotations');

  // 10b. PDFProcessor follow-ups: split + watermark (README parity)
  const merge2 = await executeTool('pdf_processor', { mode: 'merge', pdf_list: [samplePdfRes.pdf_base64, samplePdfRes.pdf_base64] });
  assert(merge2.total_pages === 2, 'PDFProcessor merged 2 samples into 2 pages');
  const splitRes = await executeTool('pdf_processor', { mode: 'split', pdf_base64: merge2.pdf_base64, pages: '2' });
  assert(splitRes.success && splitRes.total_pages === 1 && splitRes.pages[0] === 2, 'PDFProcessor split extracts page 2');
  const wmRes = await executeTool('pdf_processor', { mode: 'watermark', pdf_base64: samplePdfRes.pdf_base64, watermark_text: 'DRAFT' });
  const wmInspect = await executeTool('pdf_processor', { mode: 'inspect', pdf_base64: wmRes.pdf_base64 });
  assert(wmRes.success && wmInspect.page_count === 1 && wmRes.size_bytes > samplePdfRes.size_bytes, 'PDFProcessor watermark stamps a still-valid PDF');
  let splitRejected = false;
  try {
    await executeTool('pdf_processor', { mode: 'split', pdf_base64: samplePdfRes.pdf_base64, pages: '9' });
  } catch (e) {
    splitRejected = e && e.statusCode === 400;
  }
  assert(splitRejected, 'PDFProcessor split rejects out-of-range pages with 400');

  // 11. JSONDiff Test (JSON Diff Studio)
  console.log('\n--- 11. Tool: json_diff ---');
  const jsonDiffRes = await executeTool('json_diff', {
    original_json: { id: 1, user: 'alice', role: 'admin' },
    updated_json: { id: 1, user: 'alice' } // role deleted (breaking change!)
  });
  assert(jsonDiffRes.hasBreakingChanges === true, 'JSONDiff detected breaking schema change (role removed)');

  // 12. WebhookVerifier Test (WebhookForge)
  console.log('\n--- 12. Tool: webhook_verifier ---');
  const whRes = await executeTool('webhook_verifier', {
    provider: 'stripe',
    payload: JSON.stringify({ event: 'payment_intent.succeeded', amount: 5000 }),
    secret: 'whsec_test_secret_key_12345'
  });
  assert(whRes.signatureHeaderValue.includes('t='), 'WebhookVerifier generated valid Stripe timestamped signature');

  // 12b. WebhookVerifier follow-ups: auto-detect + replay tolerance
  const autoRes = await executeTool('webhook_verifier', {
    payload: JSON.stringify({ event: 'payment_intent.succeeded', amount: 5000 }),
    secret: 'whsec_test_secret_key_12345',
    received_signature: whRes.signatureHeaderValue
  });
  assert(autoRes.provider === 'stripe' && autoRes.providerDetected === true && autoRes.verification && autoRes.verification.isValid === true, 'WebhookVerifier auto-detects Stripe and verifies');
  const staleTs = Math.floor(Date.now() / 1000) - 3600;
  const staleMint = await executeTool('webhook_verifier', {
    provider: 'stripe',
    payload: JSON.stringify({ event: 'x' }),
    secret: 'whsec_test_secret_key_12345',
    timestamp: staleTs
  });
  const staleDefault = await executeTool('webhook_verifier', {
    payload: JSON.stringify({ event: 'x' }),
    secret: 'whsec_test_secret_key_12345',
    received_signature: staleMint.signatureHeaderValue
  });
  assert(staleDefault.verification.isReplayRisk === true, 'WebhookVerifier flags hour-old signatures by default');
  const staleWide = await executeTool('webhook_verifier', {
    payload: JSON.stringify({ event: 'x' }),
    secret: 'whsec_test_secret_key_12345',
    received_signature: staleMint.signatureHeaderValue,
    timestamp_tolerance_sec: 7200
  });
  assert(staleWide.verification.timestampOk === true && staleWide.verification.isReplayRisk === false, 'WebhookVerifier honors custom replay tolerance');

  // 13. EnvMatrix Test (EnvMatrix)
  console.log('\n--- 13. Tool: env_matrix ---');
  const envRes = await executeTool('env_matrix', {
    dev_env: 'DB_HOST=localhost\nSTRIPE_SECRET=sk_test_123',
    staging_env: 'DB_HOST=staging.db\nSTRIPE_SECRET=sk_test_123',
    prod_env: 'DB_HOST=prod.db' // missing STRIPE_SECRET!
  });
  assert(envRes.criticalRisksDetected > 0, 'EnvMatrix flagged missing secret in production');

  // 14. DuckLog Test (DuckLog)
  console.log('\n--- 14. Tool: duck_log ---');
  const logData = '{"status": 200, "path": "/api/users"}\n{"status": 500, "path": "/api/checkout"}\n{"status": 200, "path": "/api/items"}';
  const duckRes = await executeTool('duck_log', {
    raw_logs: logData,
    sql_query: 'SELECT status, count(*) AS count FROM logs GROUP BY status'
  });
  assert(duckRes.rowCount === 2, 'DuckLog executed SQL aggregate over raw JSON logs');
  assert(duckRes.schema && duckRes.schema.logs.columns.some(c => c.name === 'status' && c.type === 'number'), 'DuckLog returns schema discovery with column types');

  // 14b. DuckLog capability: JOINs, DATE_TRUNC bucketing, LEFT JOIN nulls
  const accessLogs = '{"trace":"t1","path":"/pay","status":500}\n{"trace":"t2","path":"/ok","status":200}';
  const errorLogs = '{"trace":"t1","error":"charge_failed"}';
  const joinRes = await executeTool('duck_log', {
    raw_logs: accessLogs,
    extra_tables: { errors: errorLogs },
    sql_query: 'SELECT logs.path AS path, errors.error AS error FROM logs JOIN errors ON logs.trace = errors.trace'
  });
  assert(joinRes.ok === true && joinRes.rowCount === 1 && joinRes.rows[0].path === '/pay' && joinRes.rows[0].error === 'charge_failed', 'DuckLog INNER JOIN correlates two log sources');
  const leftRes = await executeTool('duck_log', {
    raw_logs: accessLogs,
    extra_tables: { errors: errorLogs },
    sql_query: 'SELECT logs.path AS path, errors.error AS error FROM logs LEFT JOIN errors ON logs.trace = errors.trace ORDER BY path'
  });
  assert(leftRes.ok === true && leftRes.rowCount === 2 && leftRes.rows[0].path === '/ok' && leftRes.rows[0].error === null, 'DuckLog LEFT JOIN keeps unmatched rows with nulls');
  const timeLogs = '{"ts":"2026-10-29T13:15:00Z","status":500}\n{"ts":"2026-10-29T13:45:00Z","status":500}\n{"ts":"2026-10-29T14:05:00Z","status":200}';
  const truncRes = await executeTool('duck_log', {
    raw_logs: timeLogs,
    sql_query: "SELECT DATE_TRUNC('hour', ts) AS hour, COUNT(*) AS n FROM logs GROUP BY DATE_TRUNC('hour', ts) ORDER BY hour"
  });
  assert(truncRes.ok === true && truncRes.rowCount === 2 && truncRes.rows[0].hour === '2026-10-29T13:00:00.000Z' && truncRes.rows[0].n === 2, 'DuckLog DATE_TRUNC buckets timestamps by hour');

  // 14c. DuckLog follow-ups: percentiles, whole-set aggregates, HAVING, UNION, chained JOINs
  const latLines = [];
  for (let i = 1; i <= 10; i++) latLines.push(JSON.stringify({ latency_ms: i * 10, status: 200 }));
  const pRes = await executeTool('duck_log', {
    raw_logs: latLines.join('\n'),
    sql_query: 'SELECT P50(latency_ms) AS p50, P95(latency_ms) AS p95 FROM logs'
  });
  assert(pRes.ok === true && pRes.rowCount === 1 && pRes.rows[0].p50 === 50 && pRes.rows[0].p95 === 100, 'DuckLog P50/P95 percentiles over the whole set');
  const haveRes = await executeTool('duck_log', {
    raw_logs: '{"status":200}\n{"status":200}\n{"status":500}',
    sql_query: 'SELECT status, COUNT(*) AS n FROM logs GROUP BY status HAVING COUNT(*) > 1'
  });
  assert(haveRes.ok === true && haveRes.rowCount === 1 && Number(haveRes.rows[0].status) === 200, 'DuckLog HAVING filters grouped rows');
  const unionRes = await executeTool('duck_log', {
    raw_logs: '{"status":200}\n{"status":500}',
    extra_tables: { old: '{"status":200}\n{"status":503}' },
    sql_query: 'SELECT status FROM logs UNION SELECT status FROM old ORDER BY status'
  });
  assert(unionRes.ok === true && unionRes.rowCount === 3, 'DuckLog UNION dedupes combined arms');
  const unionAllRes = await executeTool('duck_log', {
    raw_logs: '{"status":200}',
    extra_tables: { old: '{"status":200}' },
    sql_query: 'SELECT status FROM logs UNION ALL SELECT status FROM old'
  });
  assert(unionAllRes.ok === true && unionAllRes.rowCount === 2, 'DuckLog UNION ALL keeps duplicates');
  const chainRes = await executeTool('duck_log', {
    raw_logs: '{"trace":"t1","path":"/pay"}',
    extra_tables: {
      errors: '{"trace":"t1","code":"E1"}',
      owners: '{"code":"E1","team":"billing"}'
    },
    sql_query: 'SELECT logs.path AS path, owners.team AS team FROM logs JOIN errors ON logs.trace = errors.trace JOIN owners ON errors.code = owners.code'
  });
  assert(chainRes.ok === true && chainRes.rowCount === 1 && chainRes.rows[0].team === 'billing', 'DuckLog chains two JOINs across three tables');

  // 15. JwtVerifier Test (JWT Studio Pro)
  console.log('\n--- 15. Tool: jwt_verifier ---');
  const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o';
  const jwtRes = await executeTool('jwt_verifier', {
    jwt_token: testJwt,
    secret_key: 'your-256-bit-secret'
  });
  assert(jwtRes.payload.name === 'John Doe', 'JwtVerifier decoded JWT payload');

  // 16. SourceMapDemapper Test (SourceMap Hero)
  console.log('\n--- 16. Tool: sourcemap_demapper ---');
  const sampleMap = {
    version: 3,
    sources: ["src/app.ts"],
    names: ["calculateTotal"],
    mappings: "AAAA,QAASA",
    sourcesContent: ["function calculateTotal() {\n  return 42;\n}"]
  };
  const smRes = await executeTool('sourcemap_demapper', {
    stack_trace: 'Error: Failed\n    at bundle.js:1:1',
    source_map: sampleMap
  });
  assert(smRes.ok === true, 'SourceMapDemapper decoded stack trace against V3 sourcemap');

  // 17. MCP Protocol Handshake
  console.log('\n--- 17. MCP Protocol Handshake ---');
  const toolsListResp = await handleRpcRequest({
    jsonrpc: '2.0',
    id: 99,
    method: 'tools/list'
  });
  assert(toolsListResp.result.tools.length === 16, `MCP tools/list exposes all 16 agent tools (found ${toolsListResp.result.tools.length})`);

  console.log(`\n========================================`);
  console.log(`Summary: ${passed} passed, ${failed} failed.`);
  console.log(`========================================\n`);

  if (failed > 0) process.exit(1);
}

runTests().catch(err => {
  console.error('Test runner fatal error:', err);
  process.exit(1);
});
