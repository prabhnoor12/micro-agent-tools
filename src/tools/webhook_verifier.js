/**
 * WebhookVerifier Agent Tool
 * Multi-provider HMAC webhook signature verification & test signature generator
 * Supports Stripe, GitHub, Shopify, Slack, Svix, Paddle
 * Cost: $0.002 / call
 */

const { runWebhookForge } = require('./core/index');

async function execute(args) {
  const { provider = 'stripe', payload, secret, received_signature, timestamp } = args;

  if (!payload || !secret) {
    throw new Error('Both "payload" and "secret" are required.');
  }

  return await runWebhookForge(provider, payload, secret, {
    receivedHeader: received_signature,
    timestamp
  });
}

module.exports = {
  name: 'webhook_verifier',
  description: 'Verifies and computes HMAC webhook signatures for Stripe, GitHub, Shopify, Slack, Svix, and Paddle with weak secret auditing.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      provider: { type: 'string', enum: ['stripe', 'github', 'shopify', 'slack', 'svix', 'paddle'], description: 'Webhook provider. Default "stripe".' },
      payload: { description: 'Raw webhook payload string or JSON object' },
      secret: { type: 'string', description: 'Webhook signing secret key (e.g. whsec_...)' },
      received_signature: { type: 'string', description: 'Incoming signature header value from request to verify' },
      timestamp: { type: 'number', description: 'Optional Unix timestamp for signature calculation' }
    },
    required: ['payload', 'secret']
  },
  execute
};
