/**
 * Schema-first argument validation. Every tool call is checked against the
 * tool's own JSON Schema (the same object advertised via MCP tools/list)
 * BEFORE execution: required keys, value types, enums, and unknown-key
 * rejection at every level that declares properties.
 *
 * Error messages name paths and expectations only — never caller values,
 * which may be secrets.
 */

'use strict';

function fail(message) {
  const err = new Error(message);
  err.statusCode = 400;
  throw err;
}

function checkType(value, type, path) {
  if (!type) return;
  const types = Array.isArray(type) ? type : [type];
  const ok = types.some((t) => {
    if (t === 'string') return typeof value === 'string';
    if (t === 'number') return typeof value === 'number' && Number.isFinite(value);
    if (t === 'integer') return Number.isInteger(value);
    if (t === 'boolean') return typeof value === 'boolean';
    if (t === 'array') return Array.isArray(value);
    if (t === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
    if (t === 'null') return value === null;
    return true;
  });
  if (!ok) fail(`"${path}" must be of type ${types.join('/')}.`);
}

function checkEnum(value, schema, path) {
  if (!schema || !Array.isArray(schema.enum)) return;
  if (!schema.enum.includes(value)) {
    fail(`"${path}" must be one of: ${schema.enum.map((v) => JSON.stringify(v)).join(', ')}.`);
  }
}

function validateValue(value, schema, path) {
  if (!schema || typeof schema !== 'object') return;
  checkType(value, schema.type, path);
  checkEnum(value, schema, path);
  if (schema.properties && value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of Object.keys(value)) {
      if (!Object.prototype.hasOwnProperty.call(schema.properties, key)) {
        fail(`Unknown property "${path ? `${path}.` : ''}${key}".`);
      }
    }
    for (const [key, sub] of Object.entries(schema.properties)) {
      if (value[key] !== undefined) validateValue(value[key], sub, path ? `${path}.${key}` : key);
    }
  }
  if (schema.items && Array.isArray(value)) {
    const limit = 5000;
    if (value.length > limit) fail(`"${path}" exceeds max of ${limit} items.`);
    value.forEach((item, i) => validateValue(item, schema.items, `${path}[${i}]`));
  }
}

function validateArgs(tool, args) {
  const schema = tool && tool.parameters;
  if (!schema) return args || {};
  const value = args || {};
  if (schema.type === 'object' && (value === null || typeof value !== 'object' || Array.isArray(value))) {
    fail('Tool arguments must be an object.');
  }
  if (Array.isArray(schema.required)) {
    for (const key of schema.required) {
      if (value[key] === undefined || value[key] === null) {
        fail(`"${key}" is required.`);
      }
    }
  }
  validateValue(value, schema, '');
  return value;
}

module.exports = {
  validateArgs,
  validateValue,
};
