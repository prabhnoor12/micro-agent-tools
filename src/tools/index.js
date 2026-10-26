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

const TOOLS_MAP = new Map(TOOLS.map(t => [t.name, t]));

function listTools() {
  return TOOLS.map(t => ({
    name: t.name,
    description: t.description,
    free: true,
    cost_usd: 0.00,
    parameters: t.parameters
  }));
}

async function executeTool(name, args) {
  const tool = TOOLS_MAP.get(name);
  if (!tool) {
    throw new Error(`Tool "${name}" not found. Available tools: ${Array.from(TOOLS_MAP.keys()).join(', ')}`);
  }
  return await tool.execute(args || {});
}

function getTool(name) {
  return TOOLS_MAP.get(name);
}

module.exports = {
  TOOLS,
  listTools,
  executeTool,
  getTool
};
