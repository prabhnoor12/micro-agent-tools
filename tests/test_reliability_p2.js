/**
 * P2 reliability regression tests: cooperative timeouts, arg shape guard,
 * duck_log caps, stdio line cap, request IDs, health fields.
 * Run: node tests/test_reliability_p2.js
 */

const assert = require('assert');
const http = require('http');
const limits = require('../src/api/limits');
const { executeTool } = require('../src/tools/index');
const core = require('../src/tools/core/index');
const mcp = require('../src/mcp/server');

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

async function run() {
  console.log('🔧 P2 reliability regression suite\n--- cooperative timeouts ---');
  await ok('withToolTimeout rejects 504 on deadline', async () => {
    await assert.rejects(
      limits.withToolTimeout(50, 'test_tool', () => new Promise(() => {})),
      (e) => e.statusCode === 504 && /timed out after 50ms/.test(e.message)
    );
  });
  await ok('withToolTimeout aborts the signal for cooperative work', async () => {
    let sawAborted = false;
    await assert.rejects(
      limits.withToolTimeout(50, 'test_tool', (signal) => new Promise((resolve) => {
        const t = setInterval(() => {
          if (signal.aborted) {
            sawAborted = true;
            clearInterval(t);
          }
        }, 5);
      })),
      (e) => e.statusCode === 504
    );
    // The reject lands on a microtask right at the deadline; give the
    // cooperative poller one macrotask turn to observe the abort.
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(sawAborted, true);
  });
  await ok('withToolTimeout passes fast results through', async () => {
    const v = await limits.withToolTimeout(1000, 'test_tool', async () => 42);
    assert.strictEqual(v, 42);
  });
  await ok('executeTool with pre-aborted signal fails fast (504)', async () => {
    const c = new AbortController();
    c.abort();
    await assert.rejects(
      executeTool('text_cleaner', { text: 'hi' }, { signal: c.signal }),
      (e) => e.statusCode === 504
    );
  });

  console.log('--- argument shape guard ---');
  await ok('Deep nesting rejected (shape guard 413 + end-to-end 4xx)', async () => {
    const { checkArgShape } = require('../src/tools/index');
    let nested = 'leaf';
    for (let i = 0; i < 30; i++) nested = { wrap: nested };
    // Shape guard itself: depth error with 413.
    assert.throws(() => checkArgShape({ extra: nested }), (e) => e.statusCode === 413 && /depth/.test(e.message));
    // End-to-end: strict schema validation now fires first (400 unknown
    // property) — either layer rejecting is the required property.
    await assert.rejects(
      executeTool('text_cleaner', { text: 'hi', extra: nested }),
      (e) => (e.statusCode === 400 || e.statusCode === 413)
    );
  });
  await ok('Key fan-out rejected (shape guard 413 + end-to-end 4xx)', async () => {
    const { checkArgShape } = require('../src/tools/index');
    const args = { text: 'hi' };
    for (let i = 0; i < 6000; i++) args[`k${i}`] = 1;
    assert.throws(() => checkArgShape(args), (e) => e.statusCode === 413 && /keys/.test(e.message));
    await assert.rejects(executeTool('text_cleaner', args), (e) => (e.statusCode === 400 || e.statusCode === 413));
  });

  console.log('--- duck_log caps ---');
  await ok('Results hard-capped at 1000 rows with truncated flag', () => {
    const lines = [];
    for (let i = 0; i < 1500; i++) lines.push(JSON.stringify({ status: 1000 + i, path: '/x' }));
    const r = core.runDuckLog(lines.join('\n'), 'SELECT status FROM logs');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.rowCount, 1000);
    assert.strictEqual(r.truncated, true);
    assert.strictEqual(r.maxRows, 1000);
  });
  await ok('Multi-statement SQL rejected', () => {
    const r = core.runDuckLog('{"status":200}', 'SELECT status FROM logs; SELECT status FROM logs');
    assert.strictEqual(r.ok, false);
    assert.match(r.error, /single SELECT/i);
  });
  await ok('Aborted duck_log throws 504 instead of 200-shaped failure', () => {
    const c = new AbortController();
    c.abort();
    assert.throws(
      () => core.runDuckLog('{"status":200}', 'SELECT status FROM logs', { signal: c.signal }),
      (e) => e.statusCode === 504
    );
  });

  console.log('--- MCP stdio line cap ---');
  await ok('Oversize line rejected without parsing, counted', async () => {
    const before = mcp.oversizeLineCountTotal();
    const out = await mcp.handleStdioLine(`{"jsonrpc":"2.0","id":1,"method":"ping","pad":"${'x'.repeat(2 * 1024 * 1024)}"}`);
    const parsed = JSON.parse(out);
    assert.strictEqual(parsed.error.code, -32700);
    assert.match(parsed.error.message, /exceeds max/);
    assert.strictEqual(mcp.oversizeLineCountTotal(), before + 1);
  });
  await ok('Normal + empty lines still handled', async () => {
    const out = await mcp.handleStdioLine('{"jsonrpc":"2.0","id":7,"method":"ping"}');
    assert.strictEqual(JSON.parse(out).id, 7);
    assert.strictEqual(await mcp.handleStdioLine('   '), null);
  });

  console.log('--- request IDs + health (live) ---');
  await ok('X-Request-Id minted, unique, and echoable; health fields present', async () => {
    const { server } = require('../src/api/edge_server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const get = (headers = {}) => new Promise((resolve, reject) => {
      http.get({ hostname: '127.0.0.1', port, path: '/status', headers }, (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ headers: res.headers, json: JSON.parse(data) }));
      }).on('error', reject);
    });
    try {
      const a = await get();
      const b = await get();
      assert.ok(a.headers['x-request-id'], 'missing request id');
      assert.ok(b.headers['x-request-id'], 'missing request id');
      assert.notStrictEqual(a.headers['x-request-id'], b.headers['x-request-id']);
      const echo = await get({ 'X-Request-Id': 'trace-abc.123' });
      assert.strictEqual(echo.headers['x-request-id'], 'trace-abc.123');
      // Transmittable-but-invalid IDs (spaces, symbols) must NOT echo:
      // the server mints its own instead of reflecting attacker bytes.
      // (Raw CR/LF can't even leave a compliant client — Node rejects them.)
      const odd = await get({ 'X-Request-Id': 'not a valid id !@#' });
      assert.notStrictEqual(odd.headers['x-request-id'], 'not a valid id !@#');
      assert.match(odd.headers['x-request-id'], /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/);
      assert.strictEqual(typeof a.json.uptime_s, 'number');
      assert.strictEqual(typeof a.json.in_flight_requests, 'number');
      assert.strictEqual(a.json.heavy_in_flight, 0);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      limits.resetForTests();
    }
  });
  await ok('Heavy concurrency budget fully released', () => {
    assert.strictEqual(limits.heavyInFlightCount(), 0);
  });

  console.log(`\n========================================`);
  console.log(`P2 reliability: ${passed} passed${process.exitCode ? ' (FAILURES — see above)' : ''}.`);
  console.log(`========================================\n`);
}

run().catch((err) => {
  console.error('P2 suite fatal:', err);
  process.exit(1);
});
