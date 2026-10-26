/**
 * EnvMatrix Agent Tool
 * 3-Way Environment Variable Matrix & Secret Leak Validator
 * Cost: $0.002 / call
 */

const { runEnvMatrix } = require('./core/index');

function execute(args) {
  const { dev_env, staging_env, prod_env } = args;

  if (!dev_env && !prod_env) {
    throw new Error('At least "dev_env" and "prod_env" are required.');
  }

  return runEnvMatrix(dev_env || '', staging_env || '', prod_env || '');
}

module.exports = {
  name: 'env_matrix',
  description: 'Audits .env configurations across dev, staging, and prod. Detects missing production secrets, test keys in prod, and generates sanitized .env.example templates.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      dev_env: { description: 'Development .env string or key-value object' },
      staging_env: { description: 'Staging .env string or key-value object' },
      prod_env: { description: 'Production .env string or key-value object' }
    },
    required: ['dev_env', 'prod_env']
  },
  execute
};
