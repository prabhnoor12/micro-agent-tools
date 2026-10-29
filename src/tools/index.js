/**
 * Central Agent Tool Registry
 * Aggregates all 16 deterministic headless agent tools, schemas and configurations.
 * 100% Free Forever for all AI Agents, LLMs & Developers.
 */

// Core Utilities
const sheetDiff = require('./sheet_diff');
const textCleaner = require('./text_cleaner');
const piiRedactor = require('./pii_redactor');
const termsScanner = require('./terms_scanner');
const receiptParser = require('./receipt_parser');
const invoiceBuilder = require('./invoice_builder');
const ogCardGenerator = require('./og_card_generator');
const webAuditor = require('./web_auditor');
const codeCardGenerator = require('./code_card_generator');
const pdfProcessor = require('./pdf_processor');

// Developer & Infrastructure Utilities
const jsonDiff = require('./json_diff');
const webhookVerifier = require('./webhook_verifier');
const envMatrix = require('./env_matrix');
const duckLog = require('./duck_log');
const jwtVerifier = require('./jwt_verifier');
const sourcemapDemapper = require('./sourcemap_demapper');

const TOOLS = [
  sheetDiff,
  textCleaner,
  piiRedactor,
  termsScanner,
  receiptParser,
  invoiceBuilder,
  ogCardGenerator,
  webAuditor,
  codeCardGenerator,
  pdfProcessor,
  jsonDiff,
  webhookVerifier,
  envMatrix,
  duckLog,
  jwtVerifier,
  sourcemapDemapper
];

const { validateArgs } = require('./validate');

const TOOLS_MAP = new Map(TOOLS.map(t => [t.name, t]));

// Generic pre-execution shape guard: per-tool usage limits check sizes,
// this checks nesting depth + key fan-out so a tiny-but-hostile payload
// (deep nesting, 100k-key object) can't blow the stack or event loop.
const MAX_ARG_DEPTH = 20;
const MAX_ARG_KEYS = 5000;

function checkArgShape(value, depth = 0, budget = { keys: MAX_ARG_KEYS }) {
  if (budget.keys < 0) {
    const err = new Error(`Tool arguments exceed max of ${MAX_ARG_KEYS} total keys.`);
    err.statusCode = 413;
    throw err;
  }
  if (Array.isArray(value)) {
    if (depth > MAX_ARG_DEPTH) {
      const err = new Error(`Tool arguments exceed max nesting depth of ${MAX_ARG_DEPTH}.`);
      err.statusCode = 413;
      throw err;
    }
    for (const item of value) checkArgShape(item, depth + 1, budget);
    return;
  }
  if (value && typeof value === 'object') {
    if (depth > MAX_ARG_DEPTH) {
      const err = new Error(`Tool arguments exceed max nesting depth of ${MAX_ARG_DEPTH}.`);
      err.statusCode = 413;
      throw err;
    }
    const keys = Object.keys(value);
    budget.keys -= keys.length;
    for (const k of keys) checkArgShape(value[k], depth + 1, budget);
  }
}

function listTools() {
  return TOOLS.map(t => ({
    name: t.name,
    description: t.description,
    free: true,
    cost_usd: 0.00,
    parameters: t.parameters
  }));
}

async function executeTool(name, args, opts = {}) {
  const tool = TOOLS_MAP.get(name);
  if (!tool) {
    throw new Error(`Tool "${name}" not found. Available tools: ${Array.from(TOOLS_MAP.keys()).join(', ')}`);
  }
  const safeArgs = validateArgs(tool, args || {});
  checkArgShape(safeArgs);
  // Cooperative cancellation: aborted before start → fail fast instead of
  // burning CPU on work nobody waits for anymore.
  if (opts.signal && opts.signal.aborted) {
    const err = new Error(`Tool "${name}" aborted before start.`);
    err.statusCode = 504;
    throw err;
  }
  return await tool.execute(safeArgs, opts);
}

function getTool(name) {
  return TOOLS_MAP.get(name);
}

module.exports = {
  TOOLS,
  listTools,
  executeTool,
  getTool,
  checkArgShape,
  MAX_ARG_DEPTH,
  MAX_ARG_KEYS,
};
