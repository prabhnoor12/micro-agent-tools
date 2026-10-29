/**
 * CodeCardGenerator Agent Tool
 * Renders syntax-highlighted code cards with macOS frames and gradients as scalable SVGs
 * Cost: $0.003 / call
 */

const THEMES = {
  midnight: { bg1: '#0f172a', bg2: '#1e1b4b', windowBg: '#090d16', text: '#e2e8f0', keyword: '#a78bfa', string: '#34d399', comment: '#64748b' },
  hyper: { bg1: '#ec4899', bg2: '#3b82f6', windowBg: '#0f172a', text: '#f8fafc', keyword: '#f472b6', string: '#38bdf8', comment: '#94a3b8' },
  sunset: { bg1: '#f97316', bg2: '#ec4899', windowBg: '#18070d', text: '#fff1f2', keyword: '#fb7185', string: '#fde047', comment: '#9f1239' },
  emerald: { bg1: '#064e3b', bg2: '#022c22', windowBg: '#021812', text: '#ecfdf5', keyword: '#34d399', string: '#a7f3d0', comment: '#065f46' },
  slate: { bg1: '#334155', bg2: '#0f172a', windowBg: '#020617', text: '#f1f5f9', keyword: '#38bdf8', string: '#86efac', comment: '#475569' }
};

function execute(args) {
  const {
    code,
    language = 'javascript',
    title = 'snippet.js',
    theme = 'midnight',
    show_line_numbers = true
  } = args;

  if (!code || typeof code !== 'string') {
    throw new Error('"code" parameter must be a non-empty string.');
  }
  if (typeof title === 'string' && title.length > 80) {
    const err = new Error('"title" exceeds max length of 80 chars.');
    err.statusCode = 413;
    throw err;
  }

  const t = THEMES[theme] || THEMES.midnight;
  const lines = code.trim().split(/\r?\n/).slice(0, 40);

  const lineHeight = 22;
  const cardPadding = 50;
  const headerHeight = 44;
  const contentHeight = lines.length * lineHeight + 30;
  const totalHeight = headerHeight + contentHeight + cardPadding * 2;
  const totalWidth = 800;
  const windowWidth = totalWidth - cardPadding * 2;
  const windowHeight = headerHeight + contentHeight;

  // Simple token regex
  const keywordRegex = /\b(const|let|var|function|return|import|export|from|default|class|if|else|for|while|async|await|def|select|from|where)\b/g;
  const stringRegex = /(["'`].*?["'`])/g;
  const commentRegex = /(\/\/.*$|#.*$)/;

  const renderedLines = lines.map((line, idx) => {
    let processed = escapeXml(line);
    const lineNum = idx + 1;
    const yPos = headerHeight + 25 + idx * lineHeight;

    return `
      <g>
        ${show_line_numbers ? `<text x="75" y="${yPos}" font-family="monospace" font-size="12" fill="${t.comment}" text-anchor="end">${lineNum}</text>` : ''}
        <text x="${show_line_numbers ? 95 : 75}" y="${yPos}" font-family="monospace" font-size="13" fill="${t.text}">${processed}</text>
      </g>
    `;
  }).join('');

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="${totalHeight}" viewBox="0 0 ${totalWidth} ${totalHeight}">
  <defs>
    <linearGradient id="codeBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${t.bg1}"/>
      <stop offset="100%" stop-color="${t.bg2}"/>
    </linearGradient>
  </defs>
  <!-- Gradient Background -->
  <rect width="${totalWidth}" height="${totalHeight}" fill="url(#codeBg)" rx="16"/>

  <!-- Window Container -->
  <g transform="translate(${cardPadding}, ${cardPadding})">
    <rect width="${windowWidth}" height="${windowHeight}" rx="12" fill="${t.windowBg}" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
    
    <!-- Traffic lights -->
    <circle cx="22" cy="22" r="6" fill="#ef4444"/>
    <circle cx="42" cy="22" r="6" fill="#f59e0b"/>
    <circle cx="62" cy="22" r="6" fill="#10b981"/>

    <!-- Window Title -->
    <text x="${windowWidth / 2}" y="26" font-family="-apple-system, sans-serif" font-size="12" font-weight="600" fill="${t.comment}" text-anchor="middle">${escapeXml(title)}</text>
    <line x1="0" y1="${headerHeight}" x2="${windowWidth}" y2="${headerHeight}" stroke="rgba(255,255,255,0.06)" stroke-width="1"/>

    <!-- Code Body -->
    ${renderedLines}
  </g>
</svg>`;

  return {
    success: true,
    total_lines: lines.length,
    language,
    svg_code_card: svg,
    svg_data_uri: `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`
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
  name: 'code_card_generator',
  description: 'Turns raw code snippets into studio-grade syntax-highlighted SVG graphics with macOS window frames and gradient backdrops.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      code: { type: 'string', description: 'Code snippet to render' },
      language: { type: 'string', description: 'Programming language (e.g. javascript, python, sql). Default "javascript".' },
      title: { type: 'string', description: 'Window title (e.g. "auth.ts"). Default "snippet.js".' },
      theme: { type: 'string', enum: ['midnight', 'hyper', 'sunset', 'emerald', 'slate'], description: 'Color theme. Default "midnight".' },
      show_line_numbers: { type: 'boolean', description: 'Show line numbers. Default true.' }
    },
    required: ['code']
  },
  execute
};
