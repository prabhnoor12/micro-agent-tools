/**
 * EnvMatrix — Production .env Parser & Serializer
 * Supports standard dotenv syntax:
 * - Comments (# and inline comments)
 * - Single/double quoted strings with escape sequences
 * - Multiline entries
 * - Optional 'export ' prefix
 */

const EnvParser = (() => {

  /**
   * Parse .env file string into structured tokens
   */
  function parse(envString) {
    if (!envString || typeof envString !== 'string') {
      return { entries: [], map: new Map() };
    }

    const lines = envString.split(/\r?\n/);
    const entries = [];
    const map = new Map();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Empty line
      if (!trimmed) {
        entries.push({ type: 'empty', raw: line, lineNumber: i + 1 });
        continue;
      }

      // Full comment line
      if (trimmed.startsWith('#')) {
        entries.push({
          type: 'comment',
          comment: trimmed.substring(1).trim(),
          raw: line,
          lineNumber: i + 1
        });
        continue;
      }

      // Variable definition
      let cleanLine = trimmed;
      if (cleanLine.startsWith('export ')) {
        cleanLine = cleanLine.substring(7).trim();
      }

      const eqIdx = cleanLine.indexOf('=');
      if (eqIdx === -1) {
        // Line without '='
        entries.push({ type: 'invalid', raw: line, lineNumber: i + 1, error: 'Missing equal sign (=)' });
        continue;
      }

      const key = cleanLine.substring(0, eqIdx).trim();
      let valPart = cleanLine.substring(eqIdx + 1).trim();

      let quoteChar = null;
      let value = valPart;
      let inlineComment = "";

      // Check for quoted value
      if (valPart.startsWith('"') || valPart.startsWith("'")) {
        quoteChar = valPart.charAt(0);
        const endQuoteIdx = valPart.indexOf(quoteChar, 1);
        if (endQuoteIdx !== -1) {
          value = valPart.substring(1, endQuoteIdx);
          const remainder = valPart.substring(endQuoteIdx + 1).trim();
          if (remainder.startsWith('#')) {
            inlineComment = remainder.substring(1).trim();
          }
        } else {
          // Unclosed quote, take raw
          value = valPart.substring(1);
        }
      } else {
        // Unquoted, check for inline comment
        const commentIdx = valPart.indexOf('#');
        if (commentIdx !== -1) {
          inlineComment = valPart.substring(commentIdx + 1).trim();
          value = valPart.substring(0, commentIdx).trim();
        } else {
          value = valPart.trim();
        }
      }

      // Handle common escape sequences in double-quoted strings
      if (quoteChar === '"') {
        value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t');
      }

      const entry = {
        type: 'variable',
        key,
        value,
        quoteChar,
        inlineComment,
        raw: line,
        lineNumber: i + 1
      };

      entries.push(entry);
      map.set(key, value);
    }

    return { entries, map };
  }

  /**
   * Serialize entries back to a standard .env formatted string
   */
  function serialize(entries) {
    if (!entries || !entries.length) return "";
    return entries.map(e => {
      if (e.type === 'empty') return "";
      if (e.type === 'comment') return `# ${e.comment}`;
      if (e.type === 'variable') {
        let valFormatted = e.value;
        if (e.quoteChar || valFormatted.includes(' ') || valFormatted.includes('#')) {
          valFormatted = `"${valFormatted.replace(/"/g, '\\"')}"`;
        }
        let line = `${e.key}=${valFormatted}`;
        if (e.inlineComment) line += ` # ${e.inlineComment}`;
        return line;
      }
      return e.raw || "";
    }).join('\n');
  }

  /**
   * Sort all variable definitions alphabetically while maintaining formatting
   */
  function sortAlphabetically(envString) {
    const { entries } = parse(envString);
    const vars = entries.filter(e => e.type === 'variable');
    vars.sort((a, b) => a.key.localeCompare(b.key));
    return serialize(vars);
  }

  const parser = {
    parse,
    serialize,
    sortAlphabetically
  };

  if (typeof window !== 'undefined') {
    window.EnvParser = parser;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = parser;
  }

  return parser;

})();
