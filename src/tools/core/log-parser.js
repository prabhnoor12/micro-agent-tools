/**
 * DuckLog — Universal In-Browser Log Parser
 * Parses:
 * - JSON Lines (NDJSON / Docker / CloudWatch / Winston)
 * - Nginx / Apache Combined Access Logs
 * - Syslog Standard Format
 */

const LogParser = (() => {

  // Nginx Combined Regex: IP - User [Time] "Method Path Proto" Status Bytes "Referer" "UserAgent" ResponseTime
  const NGINX_REGEX = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)(?: (\S+))?" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?(?: (\d+(?:\.\d+)?))?/;

  /**
   * Auto-detect format from raw text sample
   */
  function detectFormat(text) {
    if (!text || !text.trim()) return 'empty';
    const lines = text.trim().split(/\r?\n/).slice(0, 10);

    let jsonMatches = 0;
    let nginxMatches = 0;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        try {
          JSON.parse(trimmed);
          jsonMatches++;
        } catch (e) {}
      } else if (NGINX_REGEX.test(trimmed)) {
        nginxMatches++;
      }
    }

    if (jsonMatches >= lines.length * 0.6) return 'json';
    if (nginxMatches >= lines.length * 0.5) return 'nginx';
    return 'generic';
  }

  /**
   * Parse log text into structured rows
   */
  function parseLogs(rawText) {
    if (!rawText || !rawText.trim()) return [];
    const lines = rawText.split(/\r?\n/);
    const format = detectFormat(rawText);
    const rows = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      if (format === 'json') {
        try {
          const obj = JSON.parse(line);
          rows.push({
            _line: i + 1,
            timestamp: obj.timestamp || obj.time || obj.date || obj['@timestamp'] || new Date().toISOString(),
            level: (obj.level || obj.severity || (obj.status >= 500 ? 'ERROR' : obj.status >= 400 ? 'WARN' : 'INFO')).toUpperCase(),
            message: obj.message || obj.msg || line,
            status: obj.status ? Number(obj.status) : null,
            latency_ms: obj.latency_ms || obj.response_time_ms || obj.duration_ms ? Number(obj.latency_ms || obj.response_time_ms || obj.duration_ms) : null,
            service: obj.service || obj.app || 'app',
            ...obj
          });
        } catch (e) {
          rows.push({ _line: i + 1, level: 'INFO', message: line, raw: line });
        }
      } else if (format === 'nginx') {
        const match = line.match(NGINX_REGEX);
        if (match) {
          const statusNum = Number(match[6]);
          rows.push({
            _line: i + 1,
            ip: match[1],
            timestamp: match[2],
            method: match[3],
            path: match[4],
            protocol: match[5] || 'HTTP/1.1',
            status: statusNum,
            bytes: match[7] !== '-' ? Number(match[7]) : 0,
            referer: match[8] || '',
            user_agent: match[9] || '',
            latency_ms: match[10] ? Math.round(parseFloat(match[10]) * 1000) : null,
            level: statusNum >= 500 ? 'ERROR' : statusNum >= 400 ? 'WARN' : 'INFO',
            message: `${match[3]} ${match[4]} ${statusNum}`
          });
        } else {
          rows.push({ _line: i + 1, level: 'INFO', message: line, raw: line });
        }
      } else {
        // Generic log line
        let level = 'INFO';
        if (/error|fatal|fail/i.test(line)) level = 'ERROR';
        else if (/warn/i.test(line)) level = 'WARN';
        else if (/debug/i.test(line)) level = 'DEBUG';

        rows.push({
          _line: i + 1,
          timestamp: new Date().toISOString(),
          level,
          message: line,
          raw: line
        });
      }
    }

    return rows;
  }

  const parser = {
    detectFormat,
    parseLogs
  };

  if (typeof window !== 'undefined') {
    window.LogParser = parser;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = parser;
  }

  return parser;

})();
