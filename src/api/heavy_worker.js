/**
 * Worker-thread entry for heavy tool isolation (Node only; Cloudflare
 * Workers have no worker threads — the Worker path stays in-isolate).
 * Receives { toolName, args }, runs the tool, posts back the result.
 * Timeouts and memory caps are enforced by the parent (heavy_runner.js).
 */

'use strict';

const { parentPort, workerData } = require('node:worker_threads');

async function main() {
  const { executeTool } = require('../tools/index');
  const { toolName, args } = workerData || {};
  try {
    const result = await executeTool(toolName, args || {});
    parentPort.postMessage({ ok: true, result });
  } catch (err) {
    parentPort.postMessage({
      ok: false,
      message: err && err.message ? String(err.message).split('\n')[0].slice(0, 500) : 'Tool failed',
      statusCode: (err && err.statusCode) || 400,
    });
  }
}

main().catch((err) => {
  try {
    parentPort.postMessage({
      ok: false,
      message: err && err.message ? String(err.message).split('\n')[0].slice(0, 500) : 'Tool failed',
      statusCode: 500,
    });
  } catch (_) {
    process.exit(1);
  }
});
