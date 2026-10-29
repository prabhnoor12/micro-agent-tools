/**
 * P1 security regression tests: PII precision, JWT/webhook crypto,
 * PDF bomb caps, SVG XSS lockdown, env masking, error sanitization.
 * Run: node tests/test_security_p1.js
 */

const assert = require('assert');
const http = require('http');
const limits = require('../src/api/limits');
const core = require('../src/tools/core/index');
const pii = require('../src/tools/pii_redactor');
const og = require('../src/tools/og_card_generator');
const codeCard = require('../src/tools/code_card_generator');
const pdf = require('../src/tools/pdf_processor');

let passed = 0;

function ok(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed += 1;
      console.log(`  ✅ ${name}`);
    })
    .catch((err) => {
      console.error(`  ❌ FAIL: ${name}\n     ${err && err.stack ? err.stack.split('\n').slice(0, 4).join('\n     ') : err}`);
      process.exitCode = 1;
    });
}

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

async function run() {
  console.log('🔒 P1 security regression suite\n--- pii_redactor precision ---');
  await ok('Luhn-valid card redacted, Luhn-invalid left alone', () => {
    const valid = pii.execute({ text: 'Card 4111-1111-1111-1111 here', redact_phones: false });
    assert.strictEqual(valid.redactions_count, 1);
    assert.ok(!valid.redacted_text.includes('4111'));
    const invalid = pii.execute({ text: 'ID 1234-5678-9012-3456 here', redact_phones: false });
    assert.strictEqual(invalid.redactions_count, 0);
    assert.ok(invalid.redacted_text.includes('1234-5678-9012-3456'));
  });
  await ok('Plain digit runs not treated as phones; dashed phones are', () => {
    const plain = pii.execute({ text: 'order 1234567890 shipped', redact_credit_cards: false });
    assert.strictEqual(plain.redactions_count, 0);
    const dashed = pii.execute({ text: 'call 555-123-4567 now', redact_credit_cards: false });
    assert.strictEqual(dashed.redactions_count, 1);
    assert.ok(!dashed.redacted_text.includes('555-123'));
  });
  await ok('Extended key coverage: AKIA, xoxb, sk_test, PEM, assignment', () => {
    const text = [
      'key AKIAIOSFODNN7EXAMPLE here',
      'tok xoxb-123456789012-abcdefghij here',
      's ' + 'sk' + '_test_abcdefghijklmnop1234 here',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIBPAIBAAJ\n-----END RSA PRIVATE KEY-----',
      'config api_key = ABCD1234EFGH5678IJKL done',
    ].join('\n');
    const r = pii.execute({ text, redact_phones: false, redact_credit_cards: false });
    assert.ok(r.redactions_count >= 5, `expected >=5, got ${r.redactions_count}`);
    assert.ok(!r.redacted_text.includes('AKIAIOSFODNN7EXAMPLE'));
    assert.ok(!r.redacted_text.includes('MIIBPAIBAAJ'));
    assert.ok(r.redacted_text.includes('api_key')); // key name kept, value redacted
  });
  await ok('Summaries never echo raw secrets (type+length+last4 only)', () => {
    // NOTE: assembled at runtime so no Stripe-like key literal appears in source
    // (GitHub push protection blocks it even as a fake fixture).
    const secret = ['sk', 'live', 'abcdefghijklmnop12345678'].join('_');
    const r = pii.execute({ text: `leak ${secret} end` });
    const blob = JSON.stringify(r.detections_summary);
    assert.ok(!blob.includes(secret), 'raw secret echoed in summary');
    assert.ok(!blob.includes('preview'), 'legacy preview field present');
    assert.ok(blob.includes('last4'));
  });
  await ok('Oversize mask rejected by usage guard', () => {
    assert.throws(
      () => limits.enforceToolUsage('pii_redactor', { text: 'hi', replacement_mask: 'x'.repeat(100) }),
      /mask.*64/
    );
  });

  console.log('--- jwt_verifier crypto ---');
  await ok('alg=none token rejected, never trusted', async () => {
    const noneToken = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({ sub: 'admin' })}.`;
    const r = await core.runJwtStudio(noneToken, '');
    assert.strictEqual(r.ok, false);
    assert.match(r.error, /none/i);
  });
  await ok('HS256 verifies with right secret, fails with wrong (timing-safe)', async () => {
    const JwtEngine = require('../src/tools/core/jwt-studio');
    assert.strictEqual(typeof JwtEngine.timingSafeEqual, 'function');
    assert.strictEqual(JwtEngine.timingSafeEqual('abc', 'abc'), true);
    assert.strictEqual(JwtEngine.timingSafeEqual('abc', 'abd'), false);
    const token = await JwtEngine.forgeHs256Token({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1' }, 'correct-secret');
    const good = await core.runJwtStudio(token, 'correct-secret');
    assert.strictEqual(good.signatureVerification.isValid, true);
    const bad = await core.runJwtStudio(token, 'wrong-secret');
    assert.strictEqual(bad.signatureVerification.isValid, false);
    assert.ok(bad.secretHandlingWarning);
  });
  await ok('Unsupported alg (RS256) is decoded-not-verified with notice', async () => {
    const token = `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url({ sub: 'u1' })}.sig`;
    const r = await core.runJwtStudio(token, 'any-secret');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.signatureVerification, null);
    assert.match(r.signatureNote, /not supported/i);
  });
  await ok('JWKS requires https', async () => {
    const JwtEngine = require('../src/tools/core/jwt-studio');
    const r = await JwtEngine.verifyJwksEndpoint('http://example.com/.well-known/jwks.json', { alg: 'RS256' });
    assert.strictEqual(r.ok, false);
    assert.match(r.error, /https/);
  });

  console.log('--- webhook_verifier replay ---');
  await ok('Fresh stripe signature verifies with timestampOk=true', async () => {
    const r = await core.runWebhookForge('stripe', JSON.stringify({ id: 'evt_1' }), 'whsec_live_secret_key_1234567890', {
      receivedHeader: null,
    });
    const header = r.signatureHeaderValue;
    const v = await core.runWebhookForge('stripe', JSON.stringify({ id: 'evt_1' }), 'whsec_live_secret_key_1234567890', {
      receivedHeader: header,
    });
    assert.strictEqual(v.verification.isValid, true);
    assert.strictEqual(v.verification.timestampOk, true);
    assert.strictEqual(v.verification.isReplayRisk, false);
    assert.ok(v.secretHandlingWarning);
  });
  await ok('Stale stripe signature flags replay risk', async () => {
    const payload = JSON.stringify({ id: 'evt_old' });
    const secret = 'whsec_live_secret_key_1234567890';
    const oldTs = Math.floor(Date.now() / 1000) - 3600;
    const minted = await core.runWebhookForge('stripe', payload, secret, { timestamp: oldTs });
    const v = await core.runWebhookForge('stripe', payload, secret, { receivedHeader: minted.signatureHeaderValue });
    assert.strictEqual(v.verification.timestampOk, false);
    assert.strictEqual(v.verification.isReplayRisk, true);
    assert.ok(v.verification.diagnostics.some((d) => /replay/i.test(d.text)));
  });

  console.log('--- env_matrix masking ---');
  await ok('Secret values masked, never echoed raw', () => {
    const r = core.runEnvMatrix('API_KEY=supersecretvalue123', '', 'API_KEY=supersecretvalue123');
    const blob = JSON.stringify(r);
    assert.ok(!blob.includes('supersecretvalue123'), 'raw secret echoed');
    const row = r.matrixRows.find((x) => x.key === 'API_KEY');
    assert.ok(row && row.prodVal && row.prodVal.endsWith('123') && row.prodVal.includes('••'));
  });

  console.log('--- pdf_processor caps ---');
  await ok('Bad rotation rejected', async () => {
    const sample = await pdf.execute({ mode: 'sample' });
    await assert.rejects(pdf.execute({ mode: 'merge', pdf_list: [sample.pdf_base64], rotation: 45 }), /rotation/);
  });
  await ok('Oversize field text rejected', async () => {
    const sample = await pdf.execute({ mode: 'sample' });
    await assert.rejects(
      pdf.execute({ mode: 'fill', pdf_base64: sample.pdf_base64, fields: [{ type: 'text', text: 'x'.repeat(501) }] }),
      /500/
    );
  });
  await ok('Out-of-range coordinates rejected', async () => {
    const sample = await pdf.execute({ mode: 'sample' });
    await assert.rejects(
      pdf.execute({ mode: 'fill', pdf_base64: sample.pdf_base64, fields: [{ type: 'text', text: 'hi', x_percent: 2 }] }),
      /x_percent/
    );
  });
  await ok('Non-PDF bytes rejected with safe message', async () => {
    const fake = Buffer.from('hello world, not a pdf at all').toString('base64');
    await assert.rejects(pdf.execute({ mode: 'inspect', pdf_base64: fake }), /%PDF|Invalid/i);
  });

  console.log('--- svg output lockdown ---');
  await ok('OG javascript: URL rejected', () => {
    assert.throws(() => og.execute({ title: 'T', url: 'javascript:alert(1)' }), /http\(s\)/);
  });
  await ok('OG overlong fields rejected by usage guard', () => {
    assert.throws(() => limits.enforceToolUsage('og_card_generator', { title: 'x'.repeat(201) }), /title/);
    assert.throws(() => limits.enforceToolUsage('og_card_generator', { title: 't', badge: 'b'.repeat(41) }), /badge/);
    assert.throws(() => limits.enforceToolUsage('code_card_generator', { code: 'x', title: 't'.repeat(81) }), /title/);
  });
  await ok('No script/event-handler smuggling in SVG output', () => {
    const r = og.execute({ title: '<script>alert(1)</script>', description: '" onload="x', url: 'https://example.com' });
    assert.ok(!r.svg_card.includes('<script'));
    assert.ok(!r.svg_card.includes('<script'));
    assert.ok(r.svg_card.includes('&lt;script&gt;'));
    const c = codeCard.execute({ code: 'const a = 1;', title: '<img src=x onerror=alert(1)>' });
    assert.ok(!c.svg_code_card.includes('<img src=x'));
    assert.ok(c.svg_code_card.includes('&lt;img'));
  });

  console.log('--- error sanitization ---');
  await ok('safeToolMessage strips stacks, paths, caps length', () => {
    const err = new Error('boom at D:\\proj\\secret\\file.js:10:5\n    at Object.<anonymous> (/app/srv/index.js:3:1)\nsecond line');
    const msg = limits.safeToolMessage(err);
    assert.ok(!msg.includes('\n'), 'newline leaked');
    assert.ok(!msg.includes('D:\\proj'), 'windows path leaked');
    assert.ok(!msg.includes('/app/srv'), 'posix path leaked');
    const long = limits.safeToolMessage(new Error('x'.repeat(900)));
    assert.ok(long.length <= 501);
  });
  await ok('Live 400 carries sanitized message, no stack', async () => {
    const { server } = require('../src/api/edge_server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    try {
      const body = await new Promise((resolve, reject) => {
        const req = http.request(
          { hostname: '127.0.0.1', port, path: '/v1/tools/pdf_processor', method: 'POST', headers: { 'Content-Type': 'application/json' } },
          (res) => {
            let data = '';
            res.on('data', (c) => (data += c));
            res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(data) }));
          }
        );
        req.on('error', reject);
        req.write(JSON.stringify({ mode: 'merge', pdf_list: [], rotation: 0 }));
        req.end();
      });
      assert.strictEqual(body.status, 400);
      assert.ok(!JSON.stringify(body.json).includes('\n    at '), 'stack leaked to client');
    } finally {
      await new Promise((resolve) => server.close(resolve));
      limits.resetForTests();
    }
  });

  console.log(`\n========================================`);
  console.log(`P1 security: ${passed} passed${process.exitCode ? ' (FAILURES — see above)' : ''}.`);
  console.log(`========================================\n`);
}

run().catch((err) => {
  console.error('P1 suite fatal:', err);
  process.exit(1);
});
