/**
 * Secret-canary gate: canary credentials flow through every secret-handling
 * path, and NO response, summary, diagnostic, or error message may contain
 * them. If a future change echoes a secret, this suite fails first.
 * Run: node tests/test_secret_canary.js
 */

const assert = require('assert');
const { executeTool } = require('../src/tools/index');
const core = require('../src/tools/core/index');
const limits = require('../src/api/limits');

const CANARIES = {
  // Assembled at runtime: same value, but no Stripe-like key literal in source (push protection).
  apiKey: ['sk', 'live', 'C4N4RY88X7Q2Z9ABCD'].join('_'),
  webhookSecret: 'whsec_C4N4RYhookSecret5519MM',
  jwtSecret: 'C4N4RYjwtSecret7712QWERTYY',
  envValue: 'C4N4RYenvValue9917ZXCVBNM',
  bearer: 'Bearer C4N4RYbearerToken6621QWERTYUIOP',
};

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

function assertNoCanary(name, obj) {
  const blob = JSON.stringify(obj);
  for (const [kind, value] of Object.entries(CANARIES)) {
    // Bearer canary: the scheme word may legitimately survive scrubbed.
    const needle = kind === 'bearer' ? 'C4N4RYbearerToken6621QWERTYUIOP' : value;
    assert.ok(!blob.includes(needle), `${name} leaks ${kind} canary`);
  }
}

async function run() {
  console.log('🐤 Secret-canary gate\n--- canary containment ---');

  await ok('pii_redactor output + summary hold no canary', async () => {
    const r = await executeTool('pii_redactor', {
      text: `token ${CANARIES.apiKey} and ${CANARIES.bearer} leaked`,
    });
    assertNoCanary('pii_redactor', r);
    assert.ok(r.redactions_count >= 2);
  });

  await ok('env_matrix masks canary values', async () => {
    const r = await executeTool('env_matrix', {
      dev_env: `API_KEY=${CANARIES.envValue}`,
      prod_env: `API_KEY=${CANARIES.envValue}`,
    });
    assertNoCanary('env_matrix', r);
  });

  await ok('jwt_verifier holds no signing secret', async () => {
    const JwtEngine = require('../src/tools/core/jwt-studio');
    const token = await JwtEngine.forgeHs256Token({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1' }, CANARIES.jwtSecret);
    const r = await executeTool('jwt_verifier', { jwt_token: token, secret_key: CANARIES.jwtSecret });
    assertNoCanary('jwt_verifier', r);
    assert.strictEqual(r.signatureVerification.isValid, true);
  });

  await ok('webhook_verifier holds no secret (valid + invalid)', async () => {
    const payload = JSON.stringify({ id: 'evt_canary' });
    const minted = await core.runWebhookForge('stripe', payload, CANARIES.webhookSecret, {});
    const good = await core.runWebhookForge('stripe', payload, CANARIES.webhookSecret, {
      receivedHeader: minted.signatureHeaderValue,
    });
    assertNoCanary('webhook good-path', good);
    const bad = await core.runWebhookForge('stripe', payload, CANARIES.webhookSecret, {
      receivedHeader: 't=123,v1=deadbeef',
    });
    assertNoCanary('webhook bad-path', bad);
  });

  await ok('error sanitizer scrubs secret-shaped text', () => {
    const msg = limits.safeToolMessage(new Error(`bad key ${CANARIES.apiKey} rejected at D:\\svc\\x.js:1`));
    assert.ok(!msg.includes(CANARIES.apiKey), 'secret survived sanitizer');
    assert.ok(!msg.includes('D:\\svc'), 'path survived sanitizer');
    const bearerMsg = limits.safeToolMessage(new Error(`auth ${CANARIES.bearer} failed`));
    assert.ok(!bearerMsg.includes('C4N4RYbearerToken'), 'bearer survived sanitizer');
  });

  console.log(`\n========================================`);
  console.log(`Canary gate: ${passed} passed${process.exitCode ? ' (FAILURES — see above)' : ''}.`);
  console.log(`========================================\n`);
}

run().catch((err) => {
  console.error('Canary suite fatal:', err);
  process.exit(1);
});
