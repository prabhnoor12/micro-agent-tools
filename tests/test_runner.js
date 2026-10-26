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

  // 3. TextCleaner Test
  console.log('\n--- 3. Tool: text_cleaner ---');
  const cleanRes = await executeTool('text_cleaner', {
    text: 'Check: https://example.com/blog?utm_source=twitter&fbclid=123 \u201CHello\u201D\nworld'
  });
  assert(!cleanRes.cleaned_text.includes('utm_source'), 'TextCleaner stripped UTM tracking');

  // 4. PIIRedactor Test
  console.log('\n--- 4. Tool: pii_redactor ---');
  const redactRes = await executeTool('pii_redactor', {
    text: 'Call alex@example.com at 555-123-4567. Card: 4111-2222-3333-4444'
  });
  assert(redactRes.redactions_count === 3, 'PIIRedactor detected 3 PII entities');

  // 5. TermsScanner Test
  console.log('\n--- 5. Tool: terms_risk_scanner ---');
  const termsRes = await executeTool('terms_risk_scanner', {
    terms_text: 'All disputes must be resolved by binding arbitration. We may train artificial intelligence algorithms using your content.'
  });
  assert(termsRes.total_flags_detected >= 2, 'TermsScanner detected arbitration & AI training');

  // 6. ReceiptParser Test
  console.log('\n--- 6. Tool: receipt_parser ---');
  const receiptRes = await executeTool('receipt_parser', {
    document_text: 'AMAZON WEB SERVICES\nInvoice #: AWS-1234\nDate: 2026-10-15\nTotal Due: $150.00'
  });
  assert(receiptRes.data.vendor === 'AMAZON WEB SERVICES', 'ReceiptParser detected AWS');
  assert(receiptRes.data.total_amount === 150.00, 'ReceiptParser parsed total $150.00');

  // 7. InvoiceBuilder Test
  console.log('\n--- 7. Tool: invoice_builder ---');
  const invRes = await executeTool('invoice_builder', {
    items: [{ description: 'Dev Work', quantity: 10, rate: 100 }],
    tax_percent: 10
  });
  assert(invRes.totals.grand_total === 1100, 'InvoiceBuilder computed grand total with tax $1100');

  // 8. OGCardGenerator Test
  console.log('\n--- 8. Tool: og_card_generator ---');
  const ogRes = await executeTool('og_card_generator', {
    title: 'Autonomous Agents',
    description: 'The future of software'
  });
  assert(ogRes.svg_card.includes('<svg'), 'OGCardGenerator produced valid SVG');

  // 9. CodeCardGenerator Test (QuickShot)
  console.log('\n--- 9. Tool: code_card_generator ---');
  const codeRes = await executeTool('code_card_generator', {
    code: 'const greeting = "Hello Autonomous World";\nconsole.log(greeting);',
    language: 'javascript',
    title: 'agent.js'
  });
  assert(codeRes.svg_code_card.includes('<svg') && codeRes.total_lines === 2, 'CodeCardGenerator rendered 2-line code card SVG');

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
