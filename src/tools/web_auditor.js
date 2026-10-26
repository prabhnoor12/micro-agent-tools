/**
 * WebAuditor Agent Tool
 * Audits websites for HTTP security headers, Open Graph tags & latency
 * Cost: $0.005 / call
 */

const https = require('https');
const http = require('http');

async function execute(args) {
  const { url } = args;

  if (!url || typeof url !== 'string') {
    throw new Error('"url" parameter is required.');
  }

  const targetUrl = url.startsWith('http') ? url : `https://${url}`;

  return new Promise((resolve) => {
    const startTime = Date.now();
    const reqModule = targetUrl.startsWith('https') ? https : http;

    const req = reqModule.get(targetUrl, { timeout: 8000, headers: { 'User-Agent': 'AgentToolBot/1.0 (+https://freetools.dev)' } }, res => {
      const latencyMs = Date.now() - startTime;
      const headers = res.headers;

      let body = '';
      res.on('data', chunk => {
        if (body.length < 50000) body += chunk.toString();
      });

      res.on('end', () => {
        // Analyze Security Headers
        const secHeaders = {
          'strict-transport-security': !!headers['strict-transport-security'],
          'content-security-policy': !!headers['content-security-policy'],
          'x-frame-options': !!headers['x-frame-options'],
          'x-content-type-options': !!headers['x-content-type-options'],
          'referrer-policy': !!headers['referrer-policy']
        };

        let secScore = 0;
        Object.values(secHeaders).forEach(val => { if (val) secScore += 20; });

        // Analyze Open Graph tags
        const hasOgTitle = /property=["']og:title["']/i.test(body);
        const hasOgImage = /property=["']og:image["']/i.test(body);
        const hasOgDesc = /property=["']og:description["']/i.test(body);
        const hasMetaDesc = /name=["']description["']/i.test(body);

        const recommendations = [];
        if (!secHeaders['strict-transport-security']) recommendations.push('Add Strict-Transport-Security (HSTS) header.');
        if (!secHeaders['content-security-policy']) recommendations.push('Configure Content-Security-Policy (CSP) to prevent XSS attacks.');
        if (!hasOgImage) recommendations.push('Missing og:image tag. Links shared on social media will look blank.');
        if (!hasMetaDesc) recommendations.push('Missing meta description tag. Crucial for Google search ranking.');

        resolve({
          success: true,
          url: targetUrl,
          status_code: res.statusCode,
          latency_ms: latencyMs,
          security_score: secScore,
          security_headers: secHeaders,
          social_metadata: {
            has_og_title: hasOgTitle,
            has_og_image: hasOgImage,
            has_og_description: hasOgDesc,
            has_meta_description: hasMetaDesc
          },
          recommendations
        });
      });
    });

    req.on('error', err => {
      resolve({
        success: false,
        url: targetUrl,
        error: err.message
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        success: false,
        url: targetUrl,
        error: 'Request timed out after 8000ms'
      });
    });
  });
}

module.exports = {
  name: 'website_health_auditor',
  description: 'Inspects a target URL for HTTP security headers (HSTS, CSP, X-Frame-Options), Open Graph social tags, and TTFB response latency.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Website URL to audit (e.g. "https://stripe.com")' }
    },
    required: ['url']
  },
  execute
};
