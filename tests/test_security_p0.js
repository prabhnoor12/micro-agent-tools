/**
 * P0 security regression tests: SSRF guard, spoof-resistant IP,
 * security headers + strict CORS, auditor usage limits.
 * Run: node tests/test_security_p0.js
 */

const assert = require('assert');
const http = require('http');
const limits = require('../src/api/limits');
const ssrf = require('../src/api/ssrf');
const auditor = require('../src/tools/web_auditor');

let passed = 0;

function ok(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed += 1;
      console.log(`  ✅ ${name}`);
    })
    .catch((err) => {
      console.error(`  ❌ FAIL: ${name}\n     ${err && err.stack ? err.stack.split('\n').slice(0, 3).join('\n     ') : err}`);
      process.exitCode = 1;
    });
}

function expectBlock(name, url) {
  return ok(`SSRF blocks ${name}`, () => {
    assert.throws(() => ssrf.validateAuditUrl(url), /not allowed|must use|must start|Port|non-public|credentials|invalid|length/i);
  });
}

function stubHeaders(map = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(map)) lower[k.toLowerCase()] = v;
  return {
    get: (k) => (k.toLowerCase() in lower ? lower[k.toLowerCase()] : null),
    has: (k) => k.toLowerCase() in lower,
  };
}

function stubResponse({ status = 200, headers = {}, bodyText = 'ok' } = {}) {
  const bytes = new TextEncoder().encode(bodyText);
  return {
    status,
    headers: stubHeaders(headers),
    body: {
      getReader() {
        let sent = false;
        return {
          async read() {
            if (sent) return { done: true, value: undefined };
            sent = true;
            return { done: false, value: bytes };
          },
          async cancel() {},
        };
      },
      async cancel() {},
    },
  };
}

async function run() {
  console.log('🔒 P0 security regression suite\n--- SSRF URL validation ---');
  await expectBlock('localhost', 'https://localhost/admin');
  await expectBlock('127.0.0.1', 'http://127.0.0.1/');
  await expectBlock('10/8', 'http://10.0.0.5/');
  await expectBlock('192.168/16', 'http://192.168.1.1/');
  await expectBlock('172.16/12', 'http://172.20.3.4/');
  await expectBlock('0.0.0.0', 'http://0.0.0.0/');
  await expectBlock('cloud metadata', 'http://169.254.169.254/latest/meta-data/');
  await expectBlock('decimal-IP obfuscation', 'http://2130706433/');
  await expectBlock('hex-IP obfuscation', 'http://0x7f.0.0.1/');
  await expectBlock('octal-IP obfuscation', 'http://0177.0.0.1/');
  await expectBlock('metadata hostname', 'https://metadata.google.internal/');
  await expectBlock('.internal suffix', 'https://db.internal/');
  await expectBlock('.local suffix', 'https://printer.local/');
  await expectBlock('file: scheme', 'file:///etc/passwd');
  await expectBlock('ftp: scheme', 'ftp://example.com/x');
  await expectBlock('userinfo', 'https://user:pass@example.com/');
  await expectBlock('blocked port', 'http://example.com:6379/');
  await expectBlock('ipv6 loopback', 'http://[::1]/');

  await ok('SSRF allows public https URL', () => {
    const href = ssrf.validateAuditUrl('https://example.com/blog');
    assert.ok(href.startsWith('https://example.com/'));
  });

  console.log('--- DNS + redirect + body caps ---');
  await ok('DNS resolving to private IP is rejected', async () => {
    const lookup = async () => [{ address: '10.1.2.3', family: 4 }];
    await assert.rejects(ssrf.assertPublicDns('evil.example.com', lookup), /non-public/);
  });
  await ok('DNS resolving to public IP passes', async () => {
    const lookup = async () => [{ address: '93.184.216.34', family: 4 }];
    assert.strictEqual(await ssrf.assertPublicDns('example.com', lookup), true);
  });
  await ok('Redirect to internal target is rejected', async () => {
    const calls = [];
    const fetchFn = async (u) => {
      calls.push(u);
      if (calls.length === 1) return stubResponse({ status: 302, headers: { Location: 'http://169.254.169.254/x' } });
      return stubResponse({ status: 200 });
    };
    await assert.rejects(
      ssrf.fetchAuditTarget('https://example.com/go', { fetchFn, dnsLookup: async () => [{ address: '93.184.216.34' }] }),
      /non-public|not allowed/i
    );
  });
  await ok('Redirect to public target is followed once', async () => {
    const fetchFn = async (u) => {
      if (u.startsWith('https://example.com/go')) return stubResponse({ status: 302, headers: { Location: 'https://example.com/ok' } });
      return stubResponse({ status: 200, bodyText: '<html></html>' });
    };
    const r = await ssrf.fetchAuditTarget('https://example.com/go', {
      fetchFn,
      dnsLookup: async () => [{ address: '93.184.216.34' }],
    });
    assert.strictEqual(r.finalUrl, 'https://example.com/ok');
    assert.strictEqual(r.redirectHops, 1);
  });
  await ok('Oversize Content-Length is rejected before read', async () => {
    const res = stubResponse({ status: 200, headers: { 'Content-Length': String(2 * 1024 * 1024) } });
    await assert.rejects(ssrf.readCappedBody(res, 1024 * 1024), /exceeds max size/);
  });

  console.log('--- Client IP trust ---');
  await ok('X-Forwarded-For ignored by default (uses socket)', () => {
    const ip = limits.getNodeClientIp(
      { headers: { 'x-forwarded-for': '9.9.9.9, 8.8.8.8' }, socket: { remoteAddress: '10.9.9.9' } },
      limits.getConfig()
    );
    assert.strictEqual(ip, '10.9.9.9');
  });
  await ok('CF-Connecting-IP wins when present', () => {
    const ip = limits.getNodeClientIp(
      { headers: { 'cf-connecting-ip': '1.2.3.4', 'x-forwarded-for': '9.9.9.9' }, socket: { remoteAddress: '10.9.9.9' } },
      limits.getConfig()
    );
    assert.strictEqual(ip, '1.2.3.4');
  });
  await ok('XFF honored only with TRUST_PROXY_HEADERS', () => {
    const ip = limits.getNodeClientIp(
      { headers: { 'x-forwarded-for': '9.9.9.9, 8.8.8.8' }, socket: { remoteAddress: '10.9.9.9' } },
      { trustProxyHeaders: true }
    );
    assert.strictEqual(ip, '9.9.9.9');
  });
  await ok('Worker ignores XFF by default', () => {
    const req = { headers: { get: (k) => (k === 'X-Forwarded-For' ? '9.9.9.9' : null) } };
    assert.strictEqual(limits.getWorkerClientIp(req, { trustProxyHeaders: false }), 'unknown');
  });

  console.log('--- Security headers + CORS ---');
  await ok('Default security header set is complete', () => {
    for (const h of ['X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Content-Security-Policy', 'Strict-Transport-Security']) {
      assert.ok(limits.SECURITY_HEADERS[h], `missing ${h}`);
    }
    assert.strictEqual(limits.SECURITY_HEADERS['X-Frame-Options'], 'DENY');
  });
  await ok('Wildcard config grants ACAO *', () => {
    assert.strictEqual(limits.corsAllowOrigin({}, { allowedOrigins: ['*'] }), '*');
  });
  await ok('Allowlist echoes match + drops others', () => {
    const cfg = { allowedOrigins: ['https://app.example'] };
    assert.strictEqual(limits.corsAllowOrigin({ origin: 'https://app.example' }, cfg), 'https://app.example');
    assert.strictEqual(limits.corsAllowOrigin({ origin: 'https://evil.example' }, cfg), null);
    const h = limits.corsHeaders({ origin: 'https://app.example' }, cfg);
    assert.strictEqual(h.Vary, 'Origin');
    assert.ok(h['Content-Security-Policy']);
  });

  console.log('--- Auditor tool boundary ---');
  await ok('Auditor rejects localhost without network', async () => {
    await assert.rejects(auditor.execute({ url: 'http://localhost:3000/' }), /not allowed|non-public/i);
  });
  await ok('Auditor rejects metadata IP without network', async () => {
    await assert.rejects(auditor.execute({ url: 'http://169.254.169.254/' }), /non-public|not allowed/i);
  });
  await ok('Auditor usage guard requires url + caps length', () => {
    assert.throws(() => limits.enforceToolUsage('website_health_auditor', {}), /"url" parameter is required/);
    assert.throws(
      () => limits.enforceToolUsage('website_health_auditor', { url: 'https://example.com/' + 'a'.repeat(3000) }),
      /exceeds max length/
    );
  });

  console.log('--- Live edge headers ---');
  await ok('GET /status emits security + CORS headers', async () => {
    const { server } = require('../src/api/edge_server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    try {
      const res = await new Promise((resolve, reject) => {
        http
          .get({ hostname: '127.0.0.1', port, path: '/status' }, resolve)
          .on('error', reject);
      });
      assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
      assert.strictEqual(res.headers['x-frame-options'], 'DENY');
      assert.ok(res.headers['content-security-policy']);
      assert.ok(res.headers['strict-transport-security']);
      assert.strictEqual(res.headers['access-control-allow-origin'], '*');
      await new Promise((resolve) => res.resume().on('end', resolve));
    } finally {
      await new Promise((resolve) => server.close(resolve));
      limits.resetForTests();
    }
  });

  console.log(`\n========================================`);
  console.log(`P0 security: ${passed} passed${process.exitCode ? ' (FAILURES — see above)' : ''}.`);
  console.log(`========================================\n`);
}

run().catch((err) => {
  console.error('P0 suite fatal:', err);
  process.exit(1);
});
