/**
 * WebAuditor Agent Tool
 * Audits websites for HTTP security headers, Open Graph tags & latency
 * SSRF-hardened: public http(s) only, manual re-validated redirects,
 * DNS re-check, DNS-pinned sockets on Node, capped bodies, bounded timeouts.
 */

const { fetchAuditTarget } = require('../api/ssrf');

// Pure value-aware scoring, exported for unit tests (the live path can't be
// tested against localhost — SSRF guards reject non-public hosts by design).
// headers: lowercase name -> value|null. Weights sum to 100.
function scoreSecurityHeaders(headers, finalUrl) {
  const h = headers || {};
  const hsts = h['strict-transport-security'] != null ? String(h['strict-transport-security']) : null;
  const csp = h['content-security-policy'] != null ? String(h['content-security-policy']) : null;
  const xfo = h['x-frame-options'] != null ? String(h['x-frame-options']) : null;
  const xcto = h['x-content-type-options'] != null ? String(h['x-content-type-options']) : null;
  const rp = h['referrer-policy'] != null ? String(h['referrer-policy']) : null;

  const hstsAgeMatch = hsts ? hsts.match(/max-age\s*=\s*"?(\d+)/i) : null;
  const hstsMaxAge = hstsAgeMatch ? parseInt(hstsAgeMatch[1], 10) : null;
  const hstsSubdomains = hsts ? /includeSubDomains/i.test(hsts) : false;
  const hstsPts = !hsts ? 0 : 15 + (hstsMaxAge !== null && hstsMaxAge >= 31536000 ? 10 : 0);

  const cspUnsafe = csp ? /unsafe-inline|unsafe-eval/i.test(csp) : false;
  const cspScoped = csp ? /(default-src|script-src)/i.test(csp) : false;
  const cspPts = !csp ? 0 : 10 + (!cspUnsafe && cspScoped ? 15 : 0);

  const xfoNorm = (xfo || '').trim().toUpperCase();
  const xfoPts = xfoNorm === 'DENY' || xfoNorm === 'SAMEORIGIN' ? 15 : 0;

  const xctoPts = (xcto || '').trim().toLowerCase() === 'nosniff' ? 15 : 0;

  const rpUnsafe = rp ? /^unsafe-url$/i.test(rp.trim()) : false;
  const rpPts = !rp ? 0 : rpUnsafe ? 6 : 10;

  const httpsFinal = /^https:/i.test(finalUrl || '');
  const httpsPts = httpsFinal ? 10 : 0;

  return {
    score: hstsPts + cspPts + xfoPts + xctoPts + rpPts + httpsPts,
    booleans: {
      'strict-transport-security': hsts !== null,
      'content-security-policy': csp !== null,
      'x-frame-options': xfo !== null,
      'x-content-type-options': xcto !== null,
      'referrer-policy': rp !== null
    },
    details: {
      hsts: { present: hsts !== null, max_age: hstsMaxAge, include_subdomains: hstsSubdomains, points: hstsPts, max: 25 },
      csp: { present: csp !== null, has_unsafe_directive: cspUnsafe, has_source_scope: cspScoped, points: cspPts, max: 25 },
      x_frame_options: { present: xfo !== null, value: xfo, points: xfoPts, max: 15 },
      x_content_type_options: { present: xcto !== null, nosniff: xctoPts === 15, points: xctoPts, max: 15 },
      referrer_policy: { present: rp !== null, value: rp, points: rpPts, max: 10 },
      https_final: { value: httpsFinal, points: httpsPts, max: 10 }
    }
  };
}

async function execute(args) {
  const { url } = args;

  if (!url || typeof url !== 'string') {
    throw new Error('"url" parameter is required.');
  }

  const startTime = Date.now();

  try {
    const { response, bodyText, finalUrl, status, getHeader, redirectChain } = await fetchAuditTarget(url, { timeoutMs: 8000 });
    const statusCode = typeof status === 'number' ? status : response.status;
    const getVal = (name) => {
      let v;
      if (typeof getHeader === 'function') v = getHeader(name);
      else v = response.headers.get(name);
      return v == null ? null : String(v);
    };

    const latencyMs = Date.now() - startTime;

    const headers = {
      'strict-transport-security': getVal('strict-transport-security'),
      'content-security-policy': getVal('content-security-policy'),
      'x-frame-options': getVal('x-frame-options'),
      'x-content-type-options': getVal('x-content-type-options'),
      'referrer-policy': getVal('referrer-policy')
    };
    // Value-aware header analysis: presence is table stakes, values earn the rest.
    const hsts = headers['strict-transport-security'];
    const csp = headers['content-security-policy'];
    const xfo = headers['x-frame-options'];
    const xcto = headers['x-content-type-options'];
    const rp = headers['referrer-policy'];

    // Weights: HSTS 25 + CSP 25 + X-Frame-Options 15 + nosniff 15 + RP 10 + HTTPS 10 = 100.
    const { score: secScore, booleans: secHeaders, details: header_details } = scoreSecurityHeaders(headers, finalUrl);
    const hstsMaxAge = header_details.hsts.max_age;
    const cspUnsafe = header_details.csp.has_unsafe_directive;
    const httpsFinal = header_details.https_final.value;

    // Analyze Open Graph tags
    const hasOgTitle = /property=["']og:title["']/i.test(bodyText);
    const hasOgImage = /property=["']og:image["']/i.test(bodyText);
    const hasOgDesc = /property=["']og:description["']/i.test(bodyText);
    const hasMetaDesc = /name=["']description["']/i.test(bodyText);

    const chain = Array.isArray(redirectChain) ? redirectChain : [];
    const recommendations = [];
    if (!secHeaders['strict-transport-security']) recommendations.push('Add Strict-Transport-Security (HSTS) header.');
    else if (hstsMaxAge === null || hstsMaxAge < 31536000) recommendations.push('Raise HSTS max-age to at least 31536000 (1 year); consider includeSubDomains.');
    if (!secHeaders['content-security-policy']) recommendations.push('Configure Content-Security-Policy (CSP) to prevent XSS attacks.');
    else if (cspUnsafe) recommendations.push('CSP allows unsafe-inline/unsafe-eval — tighten script-src to nonces or hashes.');
    if (!secHeaders['x-frame-options']) recommendations.push('Add X-Frame-Options (DENY or SAMEORIGIN) to block clickjacking.');
    if (!secHeaders['x-content-type-options']) recommendations.push('Add X-Content-Type-Options: nosniff to block MIME sniffing.');
    if (!httpsFinal) recommendations.push('Final URL uses plain HTTP — serve the site over HTTPS.');
    if (chain.length > 3) recommendations.push(`Long redirect chain (${chain.length} hops) — flatten it for speed and crawler budget.`);
    if (!hasOgImage) recommendations.push('Missing og:image tag. Links shared on social media will look blank.');
    if (!hasMetaDesc) recommendations.push('Missing meta description tag. Crucial for Google search ranking.');

    return {
      success: true,
      url: finalUrl,
      requested_url: typeof url === 'string' ? url.slice(0, 2048) : '',
      status_code: statusCode,
      latency_ms: latencyMs,
      security_score: secScore,
      security_headers: secHeaders,
      header_details,
      redirect_count: chain.length > 0 ? chain.length - 1 : 0,
      redirect_chain: chain,
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
  description: 'Inspects a target URL for HTTP security headers with value-aware scoring (HSTS max-age, CSP strength), redirect-chain reporting, Open Graph social tags, and TTFB response latency.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Public http(s) website URL to audit (e.g. "https://stripe.com"). Private/internal hosts are rejected.' }
    },
    required: ['url']
  },
  execute,
  scoreSecurityHeaders
};
