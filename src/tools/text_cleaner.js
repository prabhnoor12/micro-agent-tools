/**
 * TextCleaner Agent Tool
 * Sanitizes messy scraped text, repairs broken PDF line wraps & strips URL tracking params
 * Cost: $0.001 / call
 */

function execute(args) {
  const {
    text,
    strip_tracking_urls = true,
    fix_line_wraps = true,
    straighten_quotes = true,
    remove_invisible_chars = true
  } = args;

  if (typeof text !== 'string') {
    throw new Error('"text" parameter must be a string.');
  }

  let cleaned = text;
  let stats = {
    urls_cleaned: 0,
    line_wraps_fixed: 0,
    invisible_chars_removed: 0
  };

  // 1. Remove invisible zero-width characters
  if (remove_invisible_chars) {
    const origLen = cleaned.length;
    cleaned = cleaned.replace(/[\u200B-\u200D\uFEFF\u00A0\u2060]/g, ' ');
    stats.invisible_chars_removed = origLen - cleaned.length;
  }

  // 2. Straighten curly quotes
  if (straighten_quotes) {
    cleaned = cleaned
      .replace(/[\u2018\u2019]/g, "'")
      .replace(/[\u201C\u201D]/g, '"')
      .replace(/\u2014/g, '--')
      .replace(/\u2013/g, '-');
  }

  // 3. Fix broken PDF line wraps
  if (fix_line_wraps) {
    // Join lines that end without a period or colon followed by lowercase or continuation
    const beforeWrap = cleaned;
    cleaned = cleaned.replace(/([^\.\:\!\?\n])\r?\n([a-z0-9])/gi, '$1 $2');
    if (beforeWrap !== cleaned) stats.line_wraps_fixed++;
  }

  // 4. Strip UTM and tracking parameters
  if (strip_tracking_urls) {
    const urlPattern = /(https?:\/\/[^\s\)\"\'>]+)/gi;
    cleaned = cleaned.replace(urlPattern, match => {
      try {
        const u = new URL(match);
        const trackingKeys = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', 'msclkid', 'mc_eid', 'ref', 'source'];
        let stripped = false;
        trackingKeys.forEach(k => {
          if (u.searchParams.has(k)) {
            u.searchParams.delete(k);
            stripped = true;
          }
        });
        if (stripped) stats.urls_cleaned++;
        return u.toString();
      } catch (_) {
        return match;
      }
    });
  }

  return {
    success: true,
    cleaned_text: cleaned,
    stats
  };
}

module.exports = {
  name: 'text_cleaner',
  description: 'Sanitizes messy text: repairs broken PDF line wraps, straightens quotes, removes zero-width characters & strips UTM tracking parameters from URLs.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      text: { type: 'string', description: 'Raw text to clean and sanitize' },
      strip_tracking_urls: { type: 'boolean', description: 'Remove UTM and click IDs from URLs. Default true.' },
      fix_line_wraps: { type: 'boolean', description: 'Merge sentences broken by PDF column margins. Default true.' },
      straighten_quotes: { type: 'boolean', description: 'Convert smart quotes to standard ASCII. Default true.' },
      remove_invisible_chars: { type: 'boolean', description: 'Remove zero-width spaces and non-breaking spaces. Default true.' }
    },
    required: ['text']
  },
  execute
};
