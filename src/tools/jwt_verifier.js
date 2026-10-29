/**
 * JwtVerifier Agent Tool
 * Cryptographic JWT claims debugger, expiration check & weak secret auditing
 * Cost: $0.002 / call
 */

const { runJwtStudio } = require('./core/index');

async function execute(args) {
  const { jwt_token, secret_key = '', algorithm = 'HS256' } = args;

  if (!jwt_token) {
    throw new Error('"jwt_token" string is required.');
  }

  return await runJwtStudio(jwt_token, secret_key, { algorithm });
}

module.exports = {
  name: 'jwt_verifier',
  description: 'Decodes JWT header/payload claims, audits signature integrity, checks expiration timestamps, and tests for weak shared HMAC secrets. Prefer local-only use for live production secrets.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      jwt_token: { type: 'string', description: 'Raw JWT token string (header.payload.signature)' },
      secret_key: { type: 'string', description: 'Secret key to verify signature' },
      algorithm: { type: 'string', enum: ['HS256', 'HS384', 'HS512', 'RS256'], description: 'Signing algorithm. Default "HS256".' }
    },
    required: ['jwt_token']
  },
  execute
};
