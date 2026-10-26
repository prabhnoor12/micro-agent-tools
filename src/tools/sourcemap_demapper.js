/**
 * SourceMapDemapper Agent Tool
 * Demaps minified production stack traces back to original TypeScript/JavaScript source files and line numbers
 * Cost: $0.003 / call
 */

const { runSourceMapHero } = require('./core/index');

function execute(args) {
  const { stack_trace, source_map, repo_url } = args;

  if (!stack_trace || !source_map) {
    throw new Error('Both "stack_trace" and "source_map" are required.');
  }

  return runSourceMapHero(stack_trace, source_map, { repoUrl: repo_url });
}

module.exports = {
  name: 'sourcemap_demapper',
  description: 'Demaps minified production JavaScript/Node error stack traces back to original source files, lines, columns, and symbols using V3 SourceMaps.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      stack_trace: { type: 'string', description: 'Minified production error stack trace string' },
      source_map: { description: 'V3 SourceMap JSON object or JSON string' },
      repo_url: { type: 'string', description: 'GitHub / GitLab repository URL for deep linking to original source lines' }
    },
    required: ['stack_trace', 'source_map']
  },
  execute
};
