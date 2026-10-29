/**
 * Heavy-tool isolation runner (Node only).
 * Spawns one worker thread per heavy job with a V8 heap cap; a deadline
 * timer terminates the thread so a runaway job can't wedge the event loop.
 * The in-process semaphore (tryAcquireHeavy) stays as admission control.
 */

'use strict';

const path = require('node:path');
const { Worker } = require('node:worker_threads');

const DEFAULT_TIMEOUT_MS = 25000;
const DEFAULT_MEMORY_MB = 256;

let activeThreads = 0;

function activeThreadCount() {
  return activeThreads;
}

function runInThread(workerPath, data, { timeoutMs = DEFAULT_TIMEOUT_MS, memoryMb = DEFAULT_MEMORY_MB } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let worker;
    try {
      worker = new Worker(workerPath, {
        workerData: data,
        resourceLimits: {
          maxOldGenerationSizeMb: memoryMb,
          maxYoungGenerationSizeMb: Math.max(16, Math.floor(memoryMb / 8)),
        },
      });
    } catch (err) {
      reject(err);
      return;
    }
    activeThreads += 1;
    const done = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      activeThreads = Math.max(0, activeThreads - 1);
      try {
        worker.terminate();
      } catch (_) {
        // ignore
      }
      fn(value);
    };
    const timer = setTimeout(() => {
      const err = new Error('Heavy tool timed out and its worker thread was terminated.');
      err.statusCode = 504;
      done(reject, err);
    }, timeoutMs);
    worker.once('message', (msg) => {
      if (msg && msg.ok) {
        done(resolve, msg.result);
      } else {
        const err = new Error((msg && msg.message) || 'Heavy tool failed.');
        err.statusCode = (msg && msg.statusCode) || 400;
        done(reject, err);
      }
    });
    worker.once('error', (err) => {
      const e = new Error(err && err.message ? String(err.message).split('\n')[0].slice(0, 500) : 'Heavy worker error.');
      e.statusCode = 500;
      done(reject, e);
    });
    worker.once('exit', (code) => {
      if (!settled && code !== 0) {
        const err = new Error(`Heavy worker exited with code ${code}.`);
        err.statusCode = 500;
        done(reject, err);
      }
    });
  });
}

function runHeavy(toolName, args, opts = {}) {
  return runInThread(path.join(__dirname, 'heavy_worker.js'), { toolName, args: args || {} }, opts);
}

module.exports = {
  runHeavy,
  runInThread,
  activeThreadCount,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MEMORY_MB,
};
