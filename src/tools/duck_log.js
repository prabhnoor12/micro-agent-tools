/**
 * DuckLog Agent Tool
 * In-Memory SQL Query Engine for high-volume server & application logs
 * Cost: $0.005 / call
 */

const { runDuckLog } = require('./core/index');

function execute(args) {
  const { raw_logs, sql_query = 'SELECT status, COUNT(*) AS count FROM logs GROUP BY status ORDER BY count DESC' } = args;

  if (!raw_logs) {
    throw new Error('"raw_logs" parameter is required (JSON logs, Apache, Nginx, or Docker).');
  }

  return runDuckLog(raw_logs, sql_query);
}

module.exports = {
  name: 'duck_log',
  description: 'Parses raw application, Docker, Nginx, or JSON logs into a virtual table and executes standard SQL queries with automated post-mortem metrics.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      raw_logs: { description: 'Log text dump or array of log entries' },
      sql_query: { type: 'string', description: 'SQL query to execute against the virtual "logs" table. Default "SELECT status, COUNT(*) AS count FROM logs GROUP BY status ORDER BY count DESC".' }
    },
    required: ['raw_logs']
  },
  execute
};
