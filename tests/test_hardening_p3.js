/**
 * P3 hardening regression tests: auth, schema validation, DO limiter,
 * heavy threads, SSRF phase 2, metrics, socket defenses.
 * Run: node tests/test_hardening_p3.js
 */

const assert = require('assert');
const http = require('http');
const path = require('path');
const limits = require('../src/api/limits');
const auth = require('../src/api/auth');
const metrics = require('../src/api/metrics');
const { executeTool } = require('../src/tools/index');
const ssrf = require('../src/api/ssrf');
const heavyRunner = require('../src/api/heavy_runner');

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

function withServer(fn) {
  return (async () => {
    const { server } = require('../src/api/edge_server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    try {
      await fn(port);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      limits.resetForTests();
      metrics.resetForTests();
    }
  })();
}

function request(port, pathName, method = 'GET', body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path: pathName, method, headers: { 'Content-Type': 'application/json', ...headers } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      }
    );
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

function fakeDOState() {
  const map = new Map();
  return {
    storage: {
      async get(k) {
        return map.has(k) ? map.get(k) : undefined;
      },
      async put(k, v) {
        map.set(k, v);
      },
      async list({ prefix }) {
        const out = new Map();
        for (const [k, v] of map) if (!prefix || k.startsWith(prefix)) out.set(k, v);
        return out;
      },
    },
  };
}

async function run() {
  console.log('🛡️ P3 hardening regression suite\n--- auth unit ---');
  await ok('routeNeedsAuth covers POST tools/mcp + metrics only', () => {
    assert.strictEqual(auth.routeNeedsAuth('POST', '/v1/tools/sheet_diff'), true);
    assert.strictEqual(auth.routeNeedsAuth('POST', '/v1/mcp'), true);
    assert.strictEqual(auth.routeNeedsAuth('GET', '/metrics'), true);
    assert.strictEqual(auth.routeNeedsAuth('GET', '/v1/tools'), false);
    assert.strictEqual(auth.routeNeedsAuth('GET', '/status'), false);
  });
  await ok('open mode authorizes; keyed mode needs exact bearer', () => {
    assert.strictEqual(auth.isAuthorized({}, []), true);
    const keys = ['test-key-0123456789abcdef'];
    assert.strictEqual(auth.isAuthorized({ authorization: 'Bearer test-key-0123456789abcdef' }, keys), true);
    assert.strictEqual(auth.isAuthorized({}, keys), false);
    assert.strictEqual(auth.isAuthorized({ authorization: 'Bearer wrong' }, keys), false);
    assert.strictEqual(auth.isAuthorized({ authorization: 'Basic abc' }, keys), false);
  });

  console.log('--- schema validation ---');
  await ok('Unknown properties rejected (strict)', async () => {
    await assert.rejects(
      executeTool('text_cleaner', { text: 'hi', bogus_field: 1 }),
      (e) => e.statusCode === 400 && /Unknown property/.test(e.message)
    );
  });
  await ok('New capability params type-checked; usage guards cap custom patterns + extra tables', async () => {
    await assert.rejects(
      executeTool('sheet_diff', { baseline_csv: 'a,b\n1,2', updated_csv: 'a,b\n1,2', numeric_tolerance: 'wide' }),
      (e) => e.statusCode === 400 && /must be of type/.test(e.message)
    );
    await assert.rejects(
      executeTool('pii_redactor', { text: 'hi', custom_patterns: ['('] }),
      (e) => e.statusCode === 400 && /valid regular expression/.test(e.message)
    );
    assert.throws(
      () => limits.enforceToolUsage('pii_redactor', { text: 'hi', custom_patterns: new Array(21).fill('x+') }),
      (e) => e.statusCode === 413
    );
    assert.throws(
      () => limits.enforceToolUsage('duck_log', { raw_logs: 'x', extra_tables: { 'bad-name': 'y' } }),
      (e) => e.statusCode === 413
    );
    assert.throws(
      () => limits.enforceToolUsage('duck_log', { raw_logs: 'x', extra_tables: { logs: 'y' } }),
      (e) => e.statusCode === 413
    );
  });
  await ok('Wrong types + enum violations rejected without echoing values', async () => {
    await assert.rejects(
      executeTool('text_cleaner', { text: 12345 }),
      (e) => e.statusCode === 400 && !e.message.includes('12345')
    );
    await assert.rejects(
      executeTool('og_card_generator', { title: 't', theme: 'hacker' }),
      (e) => e.statusCode === 400 && /must be one of/.test(e.message)
    );
    await assert.rejects(executeTool('sheet_diff', { baseline_csv: 'a' }), (e) => e.statusCode === 400 && /required/.test(e.message));
  });

  console.log('--- durable object limiter ---');
  await ok('DO sliding window allows then 429s then resets', async () => {
    const { RateLimitDO } = await import('../src/rate_limiter_do.js');
    const doInst = new RateLimitDO(fakeDOState());
    const send = (body) => doInst.fetch(new Request('https://rl/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
    const t = 1000000;
    assert.strictEqual((await (await send({ key: 'k', limit: 2, windowMs: 60000, now: t })).json()).allowed, true);
    assert.strictEqual((await (await send({ key: 'k', limit: 2, windowMs: 60000, now: t + 1 })).json()).allowed, true);
    const third = await (await send({ key: 'k', limit: 2, windowMs: 60000, now: t + 2 })).json();
    assert.strictEqual(third.allowed, false);
    assert.ok(third.retryAfterSec >= 1);
    const reset = await (await send({ key: 'k', limit: 2, windowMs: 60000, now: t + 61000 })).json();
    assert.strictEqual(reset.allowed, true);
    const bad = await doInst.fetch(new Request('https://rl/check', { method: 'POST', body: '{}' }));
    assert.strictEqual(bad.status, 400);
  });
  await ok('checkLimitDistributed falls back without binding / on error', async () => {
    const cfg = limits.getConfig();
    const mem = await limits.checkLimitDistributed({}, 'fk', 1000, 60000, cfg);
    assert.strictEqual(mem.distributed, false);
    assert.strictEqual(mem.allowed, true);
    const broken = await limits.checkLimitDistributed(
      { RATE_LIMITER: { getByName() { throw new Error('down'); } } },
      'fk', 1000, 60000, cfg
    );
    assert.strictEqual(broken.fallback, true);
    assert.strictEqual(broken.allowed, true);
    const fake = await limits.checkLimitDistributed(
      {
        RATE_LIMITER: {
          getByName: () => ({
            fetch: async () => Response.json({ allowed: true, remaining: 9, resetMs: 1000, retryAfterSec: 0, limit: 10 }),
          }),
        },
      },
      'fk', 10, 60000, cfg
    );
    assert.strictEqual(fake.distributed, true);
    assert.strictEqual(fake.remaining, 9);
  });

  console.log('--- heavy threads ---');
  await ok('pdf_processor runs isolated; thread count returns to 0', async () => {
    const r = await heavyRunner.runHeavy('pdf_processor', { mode: 'sample' }, { timeoutMs: 20000 });
    assert.strictEqual(r.success, true);
    assert.strictEqual(heavyRunner.activeThreadCount(), 0);
  });
  await ok('Hung worker thread is terminated with 504', async () => {
    await assert.rejects(
      heavyRunner.runInThread(path.join(__dirname, 'fixtures', 'sleep_worker.js'), {}, { timeoutMs: 200 }),
      (e) => e.statusCode === 504
    );
    assert.strictEqual(heavyRunner.activeThreadCount(), 0);
  });

  console.log('--- SSRF phase 2 ---');
  await ok('Operator denylist blocks exact + suffix', () => {
    // NOTE: denied.example would trip the built-in .example reserve first,
    // so the exact-match case uses a non-reserved name on purpose.
    process.env.AUDIT_DENYLIST = 'deniedhost,.evilcorp';
    try {
      assert.throws(() => ssrf.validateAuditUrl('https://deniedhost/'), /denied by operator/);
      assert.throws(() => ssrf.validateAuditUrl('https://sub.evilcorp/'), /denied by operator/);
      assert.doesNotThrow(() => ssrf.validateAuditUrl('https://example.com/'));
    } finally {
      delete process.env.AUDIT_DENYLIST;
    }
  });
  await ok('Pinned transport rejects private-resolved hosts pre-connect', async () => {
    await assert.rejects(
      ssrf.pinnedGet('https://example.com/', {
        timeoutMs: 2000,
        maxBodyBytes: 1024,
        headers: {},
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }],
      }),
      /non-public/
    );
  });
  await ok('Explicit fetchFn wins over pinned auto-transport', async () => {
    let calls = 0;
    const stubRes = {
      status: 200,
      headers: { get: () => null, has: () => false },
      body: { getReader: () => ({ read: async () => ({ done: true, value: undefined }) }) },
    };
    const out = await ssrf.fetchAuditTarget('https://example.com/', {
      fetchFn: async () => {
        calls += 1;
        return stubRes;
      },
      dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }],
    });
    assert.strictEqual(calls, 1);
    assert.strictEqual(out.finalUrl, 'https://example.com/');
  });

  console.log('--- auth + metrics + sockets (live) ---');
  await ok('Socket timeouts exceed heaviest tool deadline', async () => {
    const { server, startServer } = require('../src/api/edge_server');
    startServer(0);
    const cfg = limits.getConfig();
    try {
      assert.ok(server.requestTimeout >= cfg.heavyTimeoutMs + 15000, `requestTimeout=${server.requestTimeout}`);
      assert.strictEqual(server.headersTimeout, 15000);
      assert.strictEqual(server.keepAliveTimeout, 5000);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  await ok('Keyed mode: 401s, open discovery, gated metrics', async () => {
    await withServer(async (port) => {
      const toolBody = { baseline_csv: 'id\n1', updated_csv: 'id\n1', primary_key: 'id' };
      const open = await request(port, '/v1/tools/sheet_diff', 'POST', toolBody);
      assert.strictEqual(open.status, 200);

      process.env.API_KEYS = 'test-key-0123456789abcdef,second-key-uvwxyz0123456789';
      try {
        const noKey = await request(port, '/v1/tools/sheet_diff', 'POST', toolBody);
        assert.strictEqual(noKey.status, 401);
        assert.ok(noKey.headers['www-authenticate']);
        const badKey = await request(port, '/v1/tools/sheet_diff', 'POST', toolBody, { Authorization: 'Bearer nope' });
        assert.strictEqual(badKey.status, 401);
        const goodKey = await request(port, '/v1/tools/sheet_diff', 'POST', toolBody, { Authorization: 'Bearer test-key-0123456789abcdef' });
        assert.strictEqual(goodKey.status, 200);
        const catalog = await request(port, '/v1/tools');
        assert.strictEqual(catalog.status, 200);
        const metricsClosed = await request(port, '/metrics');
        assert.strictEqual(metricsClosed.status, 401);
        const metricsOpen = await request(port, '/metrics', 'GET', null, { Authorization: 'Bearer second-key-uvwxyz0123456789' });
        assert.strictEqual(metricsOpen.status, 200);
        assert.ok(metricsOpen.headers['content-type'].includes('text/plain'));
        assert.ok(metricsOpen.body.includes('microagent_requests_total'));
        assert.ok(metricsOpen.body.includes('microagent_tool_runs_total'));
      } finally {
        delete process.env.API_KEYS;
      }
    });
  });

  console.log(`\n========================================`);
  console.log(`P3 hardening: ${passed} passed${process.exitCode ? ' (FAILURES — see above)' : ''}.`);
  console.log(`========================================\n`);
}

run().catch((err) => {
  console.error('P3 suite fatal:', err);
  process.exit(1);
});
