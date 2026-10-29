/**
 * DuckLog Agent Tool
 * In-Memory SQL Query Engine for high-volume server & application logs
 * Cost: $0.005 / call
 */

const { runDuckLog } = require('./core/index');

function execute(args, opts = {}) {
  const { raw_logs, sql_query = 'SELECT status, COUNT(*) AS count FROM logs GROUP BY status ORDER BY count DESC', extra_tables } = args;

  if (!raw_logs) {
    throw new Error('"raw_logs" parameter is required (JSON logs, Apache, Nginx, or Docker).');
  }

  return runDuckLog(raw_logs, sql_query, { signal: opts.signal, tables: extra_tables });
}

module.exports = {
  name: 'duck_log',
  description: 'Parses raw application, Docker, Nginx, or JSON logs into virtual tables and executes SQL (WHERE/GROUP BY/ORDER BY/LIMIT, single INNER/LEFT JOIN, DATE_TRUNC bucketing) with automated post-mortem metrics and schema discovery.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      raw_logs: { description: 'Log text dump or array of log entries for the primary "logs" table' },
      sql_query: { type: 'string', description: 'SQL query to execute. Default "SELECT status, COUNT(*) AS count FROM logs GROUP BY status ORDER BY count DESC". Supports one JOIN (e.g. FROM logs JOIN errors ON logs.trace = errors.trace) and DATE_TRUNC(\'hour\'|\'day\'|\'minute\', col).' },
      extra_tables: { type: 'object', description: 'Optional named extra log sources for JOINs: { errors: "<ndjson>" }. Max 8 tables; names must be letters/digits/underscores and differ from "logs".' }
    },
    required: ['raw_logs']
  },
  execute
};
