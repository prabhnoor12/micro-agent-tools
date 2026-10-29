/**
 * WebAuditor Agent Tool
 * Audits websites for HTTP security headers, Open Graph tags & latency
 * SSRF-hardened: public http(s) only, manual re-validated redirects,
 * DNS re-check, DNS-pinned sockets on Node, capped bodies, bounded timeouts.
 */

const { fetchAuditTarget } = require('../api/ssrf');

async function execute(args) {
  const { url } = args;

  if (!url || typeof url !== 'string') {
    throw new Error('"url" parameter is required.');
  }

  const startTime = Date.now();

  try {
    const { response, bodyText, finalUrl, status, getHeader } = await fetchAuditTarget(url, { timeoutMs: 8000 });
    const statusCode = typeof status === 'number' ? status : response.status;
    const hasHeader = (name) => {
      if (typeof getHeader === 'function') return getHeader(name) != null;
      return response.headers.has(name);
    };

    const latencyMs = Date.now() - startTime;

    // Analyze Security Headers
    const secHeaders = {
      'strict-transport-security': hasHeader('strict-transport-security'),
      'content-security-policy': hasHeader('content-security-policy'),
      'x-frame-options': hasHeader('x-frame-options'),
      'x-content-type-options': hasHeader('x-content-type-options'),
      'referrer-policy': hasHeader('referrer-policy')
    };

    let secScore = 0;
    Object.values(secHeaders).forEach(val => { if (val) secScore += 20; });

    // Analyze Open Graph tags
    const hasOgTitle = /property=["']og:title["']/i.test(bodyText);
    const hasOgImage = /property=["']og:image["']/i.test(bodyText);
    const hasOgDesc = /property=["']og:description["']/i.test(bodyText);
    const hasMetaDesc = /name=["']description["']/i.test(bodyText);

    const recommendations = [];
    if (!secHeaders['strict-transport-security']) recommendations.push('Add Strict-Transport-Security (HSTS) header.');
    if (!secHeaders['content-security-policy']) recommendations.push('Configure Content-Security-Policy (CSP) to prevent XSS attacks.');
    if (!hasOgImage) recommendations.push('Missing og:image tag. Links shared on social media will look blank.');
    if (!hasMetaDesc) recommendations.push('Missing meta description tag. Crucial for Google search ranking.');

    return {
      success: true,
      url: finalUrl,
      status_code: statusCode,
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
    };
  } catch (err) {
    if (err && (err.statusCode === 400 || err.statusCode === 413)) throw err;
    const isTimeout = err.name === 'AbortError' || err.message?.includes('timeout') || err.message?.includes('abort');
    return {
      success: false,
      url: typeof url === 'string' ? url.slice(0, 2048) : '',
      error: isTimeout ? 'Request timed out after 8000ms' : err.message
    };
  }
}

module.exports = {
  name: 'website_health_auditor',
  description: 'Inspects a target URL for HTTP security headers (HSTS, CSP, X-Frame-Options), Open Graph social tags, and TTFB response latency.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Public http(s) website URL to audit (e.g. "https://stripe.com"). Private/internal hosts are rejected.' }
    },
    required: ['url']
  },
  execute
};
