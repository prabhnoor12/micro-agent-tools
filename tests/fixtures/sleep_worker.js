/**
 * Never posts back. The parent (heavy_runner.js) terminates it on deadline.
 * Test fixture for the timeout-kill path.
 */
'use strict';

const { parentPort } = require('node:worker_threads');

void parentPort;
setInterval(() => {}, 1000);
