/**
 * DuckLog — In-Memory High Performance SQL Query Engine
 * Executes SQL queries directly over parsed in-memory log records.
 */

const SqlEngine = (() => {

  /**
   * Execute a SQL query over array of log objects
   */
  // Throw a 504-style abort when the caller's deadline fired. Sync engine,
  // so this is checked cooperatively every 1024 rows, not per row.
  function checkAborted(signal) {
    if (signal && signal.aborted) {
      const err = new Error('SQL execution aborted (timeout).');
      err.statusCode = 504;
      throw err;
    }
  }

  // Qualified reference resolution for JOINed rows. Joined rows carry a `__q`
  // map of `table.column` -> value plus bare columns (left table wins
  // collisions). Plain single-table rows resolve bare names as before.
  function getRef(row, ref) {
    if (!row || typeof ref !== 'string') return undefined;
    if (Object.prototype.hasOwnProperty.call(row, ref)) return row[ref];
    if (row.__q && Object.prototype.hasOwnProperty.call(row.__q, ref)) return row.__q[ref];
    return undefined;
  }

  // DATE_TRUNC('hour'|'day'|'minute', col): bucket timestamps for time-series
  // GROUP BY. Accepts ISO strings, nginx-style dates, and epoch (s or ms).
  const TRUNC_RE = /^DATE_TRUNC\s*\(\s*'(hour|day|minute)'\s*,\s*([\w.]+)\s*\)$/i;
  function parseLogDate(v) {
    if (v === undefined || v === null || v === '') return null;
    let ms;
    if (typeof v === 'number' && Number.isFinite(v)) {
      ms = v < 1e12 ? v * 1000 : v;
    } else {
      ms = Date.parse(String(v));
      if (Number.isNaN(ms)) {
        const asNum = Number(String(v).trim());
        if (!Number.isFinite(asNum)) return null;
        ms = asNum < 1e12 ? asNum * 1000 : asNum;
      }
    }
    return Number.isFinite(ms) ? ms : null;
  }
  function truncValue(unit, ms) {
    const d = new Date(ms);
    const p = (n) => String(n).padStart(2, '0');
    const day = `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
    if (unit === 'day') return `${day}T00:00:00.000Z`;
    if (unit === 'hour') return `${day}T${p(d.getUTCHours())}:00:00.000Z`;
    return `${day}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:00.000Z`;
  }
  function parseTruncExpr(expr) {
    const m = typeof expr === 'string' ? expr.trim().match(TRUNC_RE) : null;
    return m ? { unit: m[1].toLowerCase(), col: m[2] } : null;
  }
  function resolveValue(row, expr) {
    const t = parseTruncExpr(expr);
    if (t) {
      const ms = parseLogDate(getRef(row, t.col));
      return ms === null ? null : truncValue(t.unit, ms);
    }
    return getRef(row, typeof expr === 'string' ? expr.trim() : expr);
  }

  const MAX_JOIN_ROWS = 100000;
  function mergeRows(l, r, leftTable, rightTable, rightCols) {
    const merged = { ...l };
    delete merged.__q;
    const q = { ...(l.__q || {}) };
    for (const k of Object.keys(l)) {
      if (k === '__q') continue;
      q[`${leftTable}.${k}`] = l[k];
    }
    if (r) {
      const rq = r.__q || null;
      for (const k of Object.keys(r)) {
        if (k === '__q') continue;
        q[`${rightTable}.${k}`] = r[k];
        if (!Object.prototype.hasOwnProperty.call(merged, k)) merged[k] = r[k];
      }
      if (rq) for (const k of Object.keys(rq)) {
        if (!Object.prototype.hasOwnProperty.call(q, k)) q[k] = rq[k];
      }
    } else {
      for (const k of rightCols) {
        q[`${rightTable}.${k}`] = null;
        if (!Object.prototype.hasOwnProperty.call(merged, k)) merged[k] = null;
      }
    }
    merged.__q = q;
    return merged;
  }

  // Hash join on a single equality predicate. Bare ON refs resolve left-first.
  function buildJoin(leftRows, rightRows, leftTable, rightTable, leftRef, rightRef, kind, signal) {
    const norm = (ref, side) => {
      const parts = String(ref).split('.');
      if (parts.length > 1) {
        if (parts[0].toLowerCase() !== side) {
          // Thrown inside execute(): surfaces as an { error } result, like
          // every other query-shape error (only aborts propagate as throws).
          throw new Error(`JOIN predicate references table "${parts[0]}" on the "${side}" side.`);
        }
        return parts.slice(1).join('.');
      }
      return parts[0];
    };
    const lcol = norm(leftRef, leftTable);
    const rcol = norm(rightRef, rightTable);
    const rightCols = [];
    const seen = new Set();
    for (const r of rightRows) {
      for (const k of Object.keys(r)) {
        if (k === '__q' || seen.has(k)) continue;
        seen.add(k);
        rightCols.push(k);
      }
      if (rightCols.length > 500) break;
    }
    const index = new Map();
    rightRows.forEach((r, i) => {
      if (i % 1024 === 0) checkAborted(signal);
      const key = String(getRef(r, rcol) === undefined || getRef(r, rcol) === null ? '__null__' : getRef(r, rcol));
      if (!index.has(key)) index.set(key, []);
      index.get(key).push(r);
    });
    const out = [];
    leftRows.forEach((l, i) => {
      if (i % 1024 === 0) checkAborted(signal);
      const lv = getRef(l, lcol);
      const key = String(lv === undefined || lv === null ? '__null__' : lv);
      const matches = index.get(key) || [];
      if (matches.length === 0) {
        if (kind === 'left') out.push(mergeRows(l, null, leftTable, rightTable, rightCols));
      } else {
        for (const r of matches) {
          out.push(mergeRows(l, r, leftTable, rightTable, rightCols));
          if (out.length > MAX_JOIN_ROWS) {
            throw new Error(`JOIN exceeded max of ${MAX_JOIN_ROWS} combined rows. Narrow with WHERE first.`);
          }
        }
      }
    });
    return out;
  }

  function execute(sqlQuery, tablesOrDataset, opts = {}) {
    const startTime = performance.now();
    const signal = opts.signal || null;
    const maxRows = Number(opts.maxRows) > 0 ? Number(opts.maxRows) : 1000;
    if (!sqlQuery || !sqlQuery.trim()) {
      return { columns: [], rows: [], executionTimeMs: 0, error: 'Empty SQL query' };
    }

    // Tables: array (legacy single `logs` table) or { name: rows } map.
    let tables;
    if (Array.isArray(tablesOrDataset)) {
      tables = { logs: tablesOrDataset };
    } else if (tablesOrDataset && typeof tablesOrDataset === 'object') {
      tables = {};
      for (const [name, rows] of Object.entries(tablesOrDataset)) {
        tables[String(name).toLowerCase()] = Array.isArray(rows) ? rows : [];
      }
    } else {
      tables = { logs: [] };
    }

    try {
      const cleanSql = sqlQuery.trim().replace(/;$/, '');
      if (cleanSql.includes(';')) {
        throw new Error('Multiple statements are not allowed. Send a single SELECT query.');
      }

      // Match basic components
      // SELECT ... FROM logs [[INNER|LEFT] JOIN other ON a.x = b.y]
      //   [WHERE ...] [GROUP BY ...] [ORDER BY ...] [LIMIT ...]
      const selectMatch = cleanSql.match(/^SELECT\s+([\s\S]+?)\s+FROM\s+(\w+)((?:\s+(?:INNER|LEFT)\s+)?\s*JOIN\s+(\w+)\s+ON\s+([\w.]+)\s*=\s*([\w.]+))?/i);
      if (!selectMatch) {
        throw new Error("Invalid SQL syntax. Expected: SELECT ... FROM logs [WHERE ...] [GROUP BY ...] [ORDER BY ...] [LIMIT ...]");
      }

      const selectClause = selectMatch[1].trim();
      const fromTable = (selectMatch[2] || 'logs').toLowerCase();
      if (!tables[fromTable]) {
        throw new Error(`Unknown table "${selectMatch[2]}". Available: ${Object.keys(tables).join(', ')}.`);
      }
      let dataset = tables[fromTable];
      if (selectMatch[3]) {
        const afterJoin = cleanSql.slice(cleanSql.indexOf(selectMatch[3]) + selectMatch[3].length);
        if (/\bJOIN\b/i.test(afterJoin)) {
          throw new Error('Only a single JOIN is supported. Query each pair separately.');
        }
        const rightTable = selectMatch[4].toLowerCase();
        if (!tables[rightTable]) {
          throw new Error(`Unknown table "${selectMatch[4]}". Available: ${Object.keys(tables).join(', ')}.`);
        }
        if (rightTable === fromTable) {
          throw new Error('Cannot JOIN a table to itself.');
        }
        const kind = /LEFT/i.test(selectMatch[3]) ? 'left' : 'inner';
        dataset = buildJoin(dataset, tables[rightTable], fromTable, rightTable, selectMatch[5], selectMatch[6], kind, signal);
      }

      // Extract optional clauses
      let whereClause = null;
      let groupByClause = null;
      let orderByClause = null;
      let limitClause = null;

      const whereMatch = cleanSql.match(/\s+WHERE\s+([\s\S]+?)(?=\s+GROUP\s+BY|\s+ORDER\s+BY|\s+LIMIT|$)/i);
      if (whereMatch) whereClause = whereMatch[1].trim();

      const groupMatch = cleanSql.match(/\s+GROUP\s+BY\s+([\s\S]+?)(?=\s+ORDER\s+BY|\s+LIMIT|$)/i);
      if (groupMatch) groupByClause = groupMatch[1].trim();

      const orderMatch = cleanSql.match(/\s+ORDER\s+BY\s+([\s\S]+?)(?=\s+LIMIT|$)/i);
      if (orderMatch) orderByClause = orderMatch[1].trim();

      const limitMatch = cleanSql.match(/\s+LIMIT\s+(\d+)/i);
      if (limitMatch) limitClause = parseInt(limitMatch[1], 10);

      // 1. FILTER (WHERE) — cooperative abort every 1024 rows.
      let filtered = dataset;
      if (whereClause) {
        filtered = dataset.filter((row, i) => {
          if (i % 1024 === 0) checkAborted(signal);
          return evaluateWhere(whereClause, row);
        });
      }
      checkAborted(signal);

      // 2. GROUP BY & AGGREGATE
      let resultRows = [];
      if (groupByClause) {
        resultRows = executeGroupBy(filtered, groupByClause, selectClause, signal);
      } else {
        resultRows = executeSelect(filtered, selectClause, signal);
      }
      checkAborted(signal);

      // 3. ORDER BY
      if (orderByClause) {
        resultRows = executeOrderBy(resultRows, orderByClause);
      }

      // 4. LIMIT
      if (limitClause !== null && limitClause >= 0) {
        resultRows = resultRows.slice(0, limitClause);
      }

      // 5. Hard result cap: never hand a 100k-row array to JSON.stringify.
      let truncated = false;
      if (resultRows.length > maxRows) {
        resultRows = resultRows.slice(0, maxRows);
        truncated = true;
      }

      const columns = resultRows.length > 0 ? Object.keys(resultRows[0]) : [];
      const executionTimeMs = Math.round((performance.now() - startTime) * 100) / 100;

      return {
        columns,
        rows: resultRows,
        rowCount: resultRows.length,
        truncated,
        maxRows,
        executionTimeMs
      };

    } catch (err) {
      // Cooperative abort must propagate to the caller (→ HTTP 504),
      // not collapse into a 200-shaped {error} result.
      if (err && err.statusCode === 504) throw err;
      return {
        columns: [],
        rows: [],
        rowCount: 0,
        executionTimeMs: Math.round(performance.now() - startTime),
        error: err.message
      };
    }
  }

  /**
   * Evaluate simple SQL WHERE expressions
   */
  function evaluateWhere(whereStr, row) {
    // Handle AND / OR
    const andParts = whereStr.split(/\s+AND\s+/i);
    for (const part of andParts) {
      if (!evaluateCondition(part.trim(), row)) return false;
    }
    return true;
  }

  function evaluateCondition(cond, row) {
    // LIKE (column refs may be table-qualified: access.path)
    const likeMatch = cond.match(/^([\w.]+)\s+LIKE\s+'%([^']+?)%'/i);
    if (likeMatch) {
      const val = String(getRef(row, likeMatch[1]) || '');
      return val.toLowerCase().includes(likeMatch[2].toLowerCase());
    }

    // Comparison operators (>=, <=, !=, <>, >, <, =)
    const compMatch = cond.match(/^([\w.]+)\s*(=|!=|<>|>=|<=|>|<)\s*(.+)$/);
    if (compMatch) {
      const field = compMatch[1];
      const op = compMatch[2];
      let expected = compMatch[3].trim();

      if ((expected.startsWith("'") && expected.endsWith("'")) || (expected.startsWith('"') && expected.endsWith('"'))) {
        expected = expected.substring(1, expected.length - 1);
      } else if (!isNaN(Number(expected))) {
        expected = Number(expected);
      }

      const actual = getRef(row, field);
      if (actual === undefined || actual === null) return false;

      switch (op) {
        case '=': return String(actual).toLowerCase() === String(expected).toLowerCase();
        case '!=':
        case '<>': return String(actual).toLowerCase() !== String(expected).toLowerCase();
        case '>=': return Number(actual) >= Number(expected);
        case '<=': return Number(actual) <= Number(expected);
        case '>': return Number(actual) > Number(expected);
        case '<': return Number(actual) < Number(expected);
      }
    }

    return true;
  }

  /**
   * Standard SELECT without GROUP BY
   */
  // Split a select list on top-level commas: DATE_TRUNC('hour', ts) carries
  // a comma inside parens that a naive split would tear apart.
  function splitTopLevel(s) {
    const parts = [];
    let depth = 0;
    let cur = '';
    for (const ch of String(s)) {
      if (ch === '(') depth++;
      else if (ch === ')') depth = Math.max(0, depth - 1);
      if (ch === ',' && depth === 0) {
        if (cur.trim() !== '') parts.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    if (cur.trim() !== '') parts.push(cur.trim());
    return parts;
  }

  // Split a trailing `AS alias` off a select item, if present.
  function splitAlias(f) {
    const m = f.match(/^(.*?)\s+AS\s+(\w+)$/i);
    return m ? { expr: m[1].trim(), alias: m[2] } : { expr: f, alias: null };
  }
  function truncDefaultName(col) {
    return `trunc_${col.replace(/\./g, '_')}`;
  }

  function executeSelect(dataset, selectClause, signal) {
    if (selectClause === '*') {
      return dataset.map((row, i) => {
        if (i % 1024 === 0) checkAborted(signal);
        const { __q, ...rest } = row;
        return { ...rest };
      });
    }

    const fields = splitTopLevel(selectClause);
    return dataset.map((row, i) => {
      if (i % 1024 === 0) checkAborted(signal);
      const out = {};
      fields.forEach(f => {
        const { expr, alias } = splitAlias(f);
        const trunc = parseTruncExpr(expr);
        if (trunc) {
          out[alias || truncDefaultName(trunc.col)] = resolveValue(row, expr);
        } else if (alias) {
          const v = getRef(row, expr);
          out[alias] = v !== undefined ? v : null;
        } else {
          const v = getRef(row, f);
          out[f] = v !== undefined ? v : null;
        }
      });
      return out;
    });
  }

  /**
   * GROUP BY execution with COUNT, SUM, AVG
   */
  function executeGroupBy(dataset, groupField, selectClause, signal) {
    const groups = new Map();

    dataset.forEach((row, i) => {
      if (i % 1024 === 0) checkAborted(signal);
      const gv = resolveValue(row, groupField);
      const key = gv !== undefined && gv !== null ? String(gv) : '(empty)';
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key).push(row);
    });
    checkAborted(signal);

    const groupTrunc = parseTruncExpr(groupField);
    const fields = splitTopLevel(selectClause);
    const result = [];

    groups.forEach((rowsInGroup, groupKey) => {
      const item = {};
      fields.forEach(f => {
        // e.g. COUNT(*) AS count
        const countMatch = f.match(/COUNT\((.*?)\)(?:\s+AS\s+(\w+))?/i);
        const avgMatch = f.match(/AVG\(([\w.]+)\)(?:\s+AS\s+(\w+))?/i);
        const sumMatch = f.match(/SUM\(([\w.]+)\)(?:\s+AS\s+(\w+))?/i);

        if (countMatch) {
          const colName = countMatch[2] || 'count';
          item[colName] = rowsInGroup.length;
        } else if (avgMatch) {
          const colName = avgMatch[2] || `avg_${avgMatch[1]}`;
          const total = rowsInGroup.reduce((acc, r) => acc + (Number(getRef(r, avgMatch[1])) || 0), 0);
          item[colName] = rowsInGroup.length ? Math.round((total / rowsInGroup.length) * 10) / 10 : 0;
        } else if (sumMatch) {
          const colName = sumMatch[2] || `sum_${sumMatch[1]}`;
          item[colName] = rowsInGroup.reduce((acc, r) => acc + (Number(getRef(r, sumMatch[1])) || 0), 0);
        } else {
          const { expr: rawCol, alias } = splitAlias(f);
          const rawTrunc = parseTruncExpr(rawCol);
          const outCol = alias || (rawTrunc ? truncDefaultName(rawTrunc.col) : rawCol);
          if (rawCol === groupField || (rawTrunc && groupTrunc && rawTrunc.unit === groupTrunc.unit && rawTrunc.col.toLowerCase() === groupTrunc.col.toLowerCase())) {
            item[outCol] = groupKey;
          } else if (rawTrunc) {
            item[outCol] = rowsInGroup[0] ? resolveValue(rowsInGroup[0], rawCol) : null;
          } else {
            const v = rowsInGroup[0] ? getRef(rowsInGroup[0], rawCol) : undefined;
            item[outCol] = v !== undefined ? v : null;
          }
        }
      });
      result.push(item);
    });

    return result;
  }

  /**
   * ORDER BY execution
   */
  function executeOrderBy(rows, orderClause) {
    const parts = orderClause.split(/\s+/);
    const col = parts[0];
    const isDesc = parts[1] && parts[1].toUpperCase() === 'DESC';

    return [...rows].sort((a, b) => {
      const valA = getRef(a, col);
      const valB = getRef(b, col);
      if (valA === valB) return 0;
      if (valA === undefined || valA === null) return 1;
      if (valB === undefined || valB === null) return -1;

      if (typeof valA === 'number' && typeof valB === 'number') {
        return isDesc ? valB - valA : valA - valB;
      }
      return isDesc ? String(valB).localeCompare(String(valA)) : String(valA).localeCompare(String(valB));
    });
  }

  const engine = {
    execute
  };

  if (typeof window !== 'undefined') {
    window.SqlEngine = engine;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = engine;
  }

  return engine;

})();
