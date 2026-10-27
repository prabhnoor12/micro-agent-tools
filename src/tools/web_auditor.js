/**
 * WebAuditor Agent Tool
 * Audits websites for HTTP security headers, Open Graph tags & latency
 * Cost: $0.005 / call
 */

async function execute(args) {
  const { url } = args;

  if (!url || typeof url !== 'string') {
    throw new Error('"url" parameter is required.');
  }

  const targetUrl = url.startsWith('http') ? url : `https://${url}`;
  const startTime = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(targetUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'AgentToolBot/1.0 (+https://freetools.dev)'
      },
      redirect: 'follow'
    });

    clearTimeout(timeoutId);
    const latencyMs = Date.now() - startTime;
    const body = await response.text();

    // Analyze Security Headers
    const secHeaders = {
      'strict-transport-security': response.headers.has('strict-transport-security'),
      'content-security-policy': response.headers.has('content-security-policy'),
      'x-frame-options': response.headers.has('x-frame-options'),
      'x-content-type-options': response.headers.has('x-content-type-options'),
      'referrer-policy': response.headers.has('referrer-policy')
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

    return {
      success: true,
      url: targetUrl,
      status_code: response.status,
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
    const isTimeout = err.name === 'AbortError' || err.message?.includes('timeout') || err.message?.includes('abort');
    return {
      success: false,
      url: targetUrl,
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
      url: { type: 'string', description: 'Website URL to audit (e.g. "https://stripe.com")' }
    },
    required: ['url']
  },
  execute
};
