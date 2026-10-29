/**
 * OGCardGenerator Agent Tool
 * Generates Open Graph SVG graphics, HTML meta tags & Next.js metadata objects
 * Cost: $0.003 / call
 */

function execute(args) {
  const {
    title,
    description = '',
    badge = 'Release',
    brand = 'AgentApp',
    url = 'https://example.com',
    theme = 'emerald'
  } = args;

  if (!title || typeof title !== 'string') {
    throw new Error('"title" parameter is required.');
  }
  if (title.length > 200) {
    const err = new Error('"title" exceeds max length of 200 chars.');
    err.statusCode = 413;
    throw err;
  }
  for (const [key, max] of [['description', 1000], ['badge', 40], ['brand', 60]]) {
    if (typeof args[key] === 'string' && args[key].length > max) {
      const err = new Error(`"${key}" exceeds max length of ${max} chars.`);
      err.statusCode = 413;
      throw err;
    }
  }
  if (typeof url !== 'string' || url.length > 2048) {
    const err = new Error('"url" must be a string of max 2048 chars.');
    err.statusCode = url && url.length > 2048 ? 413 : 400;
    throw err;
  }

  const themes = {
    emerald: { bg1: '#090d16', bg2: '#064e3b', accent: '#10b981', text: '#ffffff', sub: '#94a3b8' },
    purple: { bg1: '#0b0a1a', bg2: '#31104b', accent: '#a855f7', text: '#ffffff', sub: '#cbd5e1' },
    sunset: { bg1: '#18070d', bg2: '#4a1525', accent: '#f43f5e', text: '#ffffff', sub: '#fecdd3' },
    ocean: { bg1: '#030d1a', bg2: '#0c2d48', accent: '#0ea5e9', text: '#ffffff', sub: '#93c5fd' },
    light: { bg1: '#ffffff', bg2: '#f1f5f9', accent: '#0f172a', text: '#0f172a', sub: '#475569' }
  };

  const t = themes[theme] || themes.emerald;
  const withScheme = url.startsWith('http://') || url.startsWith('https://') ? url : `https://${url}`;
  let cleanUrl;
  try {
    const parsed = new URL(withScheme);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('bad protocol');
    if (parsed.username || parsed.password) throw new Error('credentials');
    cleanUrl = parsed.href;
  } catch (_) {
    throw new Error('"url" must be a valid http(s) URL.');
  }

  // Generate crisp 1200x630 vector SVG
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${t.bg1}"/>
      <stop offset="100%" stop-color="${t.bg2}"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <rect x="50" y="50" width="1100" height="530" rx="24" fill="none" stroke="${t.accent}" stroke-opacity="0.25" stroke-width="2"/>
  
  <!-- Badge -->
  <rect x="100" y="110" width="${badge.length * 12 + 36}" height="38" rx="19" fill="${t.accent}" fill-opacity="0.2" stroke="${t.accent}" stroke-opacity="0.5" stroke-width="1.5"/>
  <circle cx="120" cy="129" r="5" fill="${t.accent}"/>
  <text x="134" y="135" font-family="-apple-system, sans-serif" font-size="18" font-weight="600" fill="${t.text}">${escapeXml(badge)}</text>
  
  <!-- Title -->
  <text x="100" y="230" font-family="-apple-system, sans-serif" font-size="52" font-weight="800" fill="${t.text}">
    ${escapeXml(title.slice(0, 75))}
  </text>
  
  <!-- Description -->
  <text x="100" y="320" font-family="-apple-system, sans-serif" font-size="24" font-weight="400" fill="${t.sub}">
    ${escapeXml(description.slice(0, 110))}
  </text>
  
  <!-- Footer Brand -->
  <rect x="100" y="470" width="46" height="46" rx="12" fill="${t.accent}"/>
  <text x="123" y="500" font-family="-apple-system, sans-serif" font-size="20" font-weight="700" fill="#ffffff" text-anchor="middle">${escapeXml(brand.slice(0, 2).toUpperCase())}</text>
  <text x="160" y="495" font-family="-apple-system, sans-serif" font-size="24" font-weight="700" fill="${t.text}">${escapeXml(brand)}</text>
  <text x="160" y="520" font-family="-apple-system, sans-serif" font-size="16" fill="${t.sub}">${escapeXml(cleanUrl)}</text>
</svg>`;

  const htmlMetaTags = `<!-- Open Graph / Meta Tags -->
<title>${escapeXml(title)}</title>
<meta name="description" content="${escapeXml(description)}" />
<meta property="og:type" content="website" />
<meta property="og:url" content="${cleanUrl}" />
<meta property="og:title" content="${escapeXml(title)}" />
<meta property="og:description" content="${escapeXml(description)}" />
<meta property="og:image" content="${cleanUrl}/og-image.png" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${escapeXml(title)}" />
<meta name="twitter:description" content="${escapeXml(description)}" />`;

  return {
    success: true,
    svg_card: svg,
    svg_data_uri: `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`,
    html_meta_tags: htmlMetaTags,
    nextjs_metadata: {
      title,
      description,
      openGraph: {
        title,
        description,
        url: cleanUrl,
        siteName: brand,
        images: [{ url: `${cleanUrl}/og-image.png`, width: 1200, height: 630 }]
      },
      twitter: {
        card: 'summary_large_image',
        title,
        description
      }
    }
  };
}

function escapeXml(str) {
  return String(str || '').replace(/[<>&'"]/g, c => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
    }
  });
}

module.exports = {
  name: 'og_card_generator',
  description: 'Generates 1200x630 Open Graph vector social card graphics, HTML meta tags, and Next.js metadata configurations for articles or releases.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      title: { type: 'string', description: 'Social card headline' },
      description: { type: 'string', description: 'Social card description snippet' },
      badge: { type: 'string', description: 'Pill tag (e.g. "Release v2.0", "New Guide"). Default "Release".' },
      brand: { type: 'string', description: 'Brand or site name. Default "AgentApp".' },
      url: { type: 'string', description: 'Target destination URL' },
      theme: { type: 'string', enum: ['emerald', 'purple', 'sunset', 'ocean', 'light'], description: 'Card color theme. Default "emerald".' }
    },
    required: ['title']
  },
  execute
};
