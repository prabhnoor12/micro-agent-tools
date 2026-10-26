/**
 * JSONDiff Agent Tool
 * Semantic JSON API diffing, smart array reconciliation by primary key & schema breaking change sentinel
 * Cost: $0.003 / call
 */

const { runJsonDiff } = require('./core/index');

function execute(args) {
  const { original_json, updated_json, primary_key = 'auto', ignore_timestamps = true, ignore_uuids = true } = args;

  if (original_json === undefined || updated_json === undefined) {
    throw new Error('Both "original_json" and "updated_json" are required.');
  }

  return runJsonDiff(original_json, updated_json, {
    primaryKey: primary_key,
    ignoreTimestamps: ignore_timestamps,
    ignoreUuids: ignore_uuids
  });
}

module.exports = {
  name: 'json_diff',
  description: 'Semantic JSON diffing with primary-key array reconciliation and breaking schema change detection (RFC 6902 patch export).',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      original_json: { description: 'Baseline JSON object or JSON string' },
      updated_json: { description: 'Modified JSON object or JSON string' },
      primary_key: { type: 'string', description: 'Primary key for array object matching (e.g. "id", "sku", or "auto"). Default "auto".' },
      ignore_timestamps: { type: 'boolean', description: 'Suppress timestamp noise. Default true.' },
      ignore_uuids: { type: 'boolean', description: 'Suppress random UUID churn. Default true.' }
    },
    required: ['original_json', 'updated_json']
  },
  execute
};
