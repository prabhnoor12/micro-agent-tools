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
  function mergeRows(l, r, leftLabel, rightTable, rightCols) {
    const merged = { ...l };
    delete merged.__q;
    const q = { ...(l.__q || {}) };
    for (const k of Object.keys(l)) {
      if (k === '__q') continue;
      // Stamp-if-absent: chained joins keep earlier tables' qualifications.
      if (!Object.prototype.hasOwnProperty.call(q, `${leftLabel}.${k}`)) q[`${leftLabel}.${k}`] = l[k];
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
  // leftNames lists every table already on the left (chained joins); the ON
  // left side may qualify with any of them.
  function buildJoin(leftRows, rightRows, leftNames, rightTable, leftRef, rightRef, kind, signal) {
    const norm = (ref, sides) => {
      const parts = String(ref).split('.');
      if (parts.length > 1) {
        if (!sides.includes(parts[0].toLowerCase())) {
          // Thrown inside execute(): surfaces as an { error } result, like
          // every other query-shape error (only aborts propagate as throws).
          throw new Error(`JOIN predicate references unknown table "${parts[0]}".`);
        }
        return parts.slice(1).join('.');
      }
      return parts[0];
    };
    const lcol = norm(leftRef, leftNames);
    const rcol = norm(rightRef, [rightTable]);
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
        if (kind === 'left') out.push(mergeRows(l, null, leftNames[0], rightTable, rightCols));
      } else {
        for (const r of matches) {
          out.push(mergeRows(l, r, leftNames[0], rightTable, rightCols));
          if (out.length > MAX_JOIN_ROWS) {
            throw new Error(`JOIN exceeded max of ${MAX_JOIN_ROWS} combined rows. Narrow with WHERE first.`);
          }
        }
      }
    });
    return out;
  }

  // Nearest-rank percentile over finite numbers. Null when empty.
  function percentile(nums, p) {
    if (!nums.length) return null;
    const s = [...nums].sort((a, b) => a - b);
    const rank = Math.max(1, Math.ceil((p / 100) * s.length));
    const v = s[Math.min(rank, s.length) - 1];
    return Math.round(v * 100) / 100;
  }

  // Shared aggregate computer for GROUP BY, HAVING, and whole-set SELECTs.
  function aggNumber(fn, arg, members) {
    if (fn === 'count') {
      if (arg === '*') return members.length;
      return members.filter(r => {
        const v = getRef(r, arg);
        return v !== undefined && v !== null;
      }).length;
    }
    const nums = [];
    for (const r of members) {
      const n = Number(getRef(r, arg));
      if (Number.isFinite(n)) nums.push(n);
    }
    if (fn === 'avg') return nums.length ? Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 10) / 10 : 0;
    if (fn === 'sum') return nums.reduce((a, b) => a + b, 0);
    if (fn === 'p50' || fn === 'p95' || fn === 'p99') return percentile(nums, Number(fn.slice(1)));
    return NaN;
  }

  function evalHavingOperand(expr, item, members) {
    const t = String(expr).trim();
    let m = t.match(/^COUNT\(\*\)$/i);
    if (m) return members.length;
    m = t.match(/^COUNT\(([\w.]+)\)$/i);
    if (m) return aggNumber('count', m[1], members);
    m = t.match(/^(AVG|SUM|P50|P95|P99)\(([\w.]+)\)$/i);
    if (m) return aggNumber(m[1].toLowerCase(), m[2], members);
    const v = getRef(item, t);
    return v === undefined || v === null ? NaN : Number(v);
  }

  // HAVING: `AGG(...) OP number [AND ...]`. Strict by design — unparseable
  // conditions and non-numeric literals are query errors, not silent drops.
  function evalHaving(havingStr, item, members) {
    const andParts = String(havingStr).split(/\s+AND\s+/i);
    for (const part of andParts) {
      const m = part.trim().match(/^(.+?)\s*(=|!=|<>|>=|<=|>|<)\s*(.+)$/);
      if (!m) throw new Error('Invalid HAVING condition. Expected: AGG(col) <op> number [AND ...].');
      const left = evalHavingOperand(m[1], item, members);
      const right = Number(m[3].trim());
      if (!Number.isFinite(right)) throw new Error('HAVING comparisons require a numeric literal.');
      if (typeof left !== 'number' || Number.isNaN(left)) return false;
      const ok = m[2] === '=' ? left === right
        : m[2] === '!=' || m[2] === '<>' ? left !== right
        : m[2] === '>=' ? left >= right
        : m[2] === '<=' ? left <= right
        : m[2] === '>' ? left > right : left < right;
      if (!ok) return false;
    }
    return true;
  }

  // Split `SELECT ... UNION [ALL] SELECT ...` on the UNION keyword only, then
  // require every arm to start with SELECT. A string literal containing the
  // lone word UNION therefore fails loudly instead of corrupting silently.
  function splitUnion(cleanSql) {
    const re = /\bUNION\s+ALL\b|\bUNION\b/gi;
    const hits = [];
    let m;
    while ((m = re.exec(cleanSql)) !== null) {
      hits.push({ index: m.index, len: m[0].length, all: /ALL/i.test(m[0]) });
    }
    if (!hits.length) return null;
    const parts = [];
    let prev = 0;
    for (const h of hits) {
      parts.push({ sql: cleanSql.slice(prev, h.index).trim(), distinct: !h.all });
      prev = h.index + h.len;
    }
    parts.push({ sql: cleanSql.slice(prev).trim(), distinct: false });
    for (let i = 1; i < parts.length; i++) {
      if (!/^SELECT\b/i.test(parts[i].sql)) {
        throw new Error('UNION must be followed by SELECT.');
      }
    }
    return parts;
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

      const union = splitUnion(cleanSql);
      let resultRows;
      if (union && union.length > 1) {
        // Every arm runs without ORDER/LIMIT except the last, whose trailing
        // clauses apply to the combined result (standard SQL semantics).
        const sides = [];
        for (let i = 0; i < union.length; i++) {
          sides.push(runSingleSelect(union[i].sql, tables, signal, { deferOrderLimit: true }));
          if (i < union.length - 1 && (sides[i].orderClause || sides[i].limitClause !== null)) {
            throw new Error('ORDER BY and LIMIT are only allowed after the final SELECT of a UNION.');
          }
        }
        // Positional column alignment on the first non-empty arm's names.
        let keys = [];
        for (const s of sides) {
          if (s.rows.length) { keys = Object.keys(s.rows[0]); break; }
        }
        resultRows = [];
        for (const s of sides) {
          for (const r of s.rows) {
            const vals = Object.keys(r).map(k => r[k]);
            if (keys.length && vals.length !== keys.length) {
              throw new Error(`UNION arms return different column counts (${vals.length} vs ${keys.length}).`);
            }
            const o = {};
            keys.forEach((k, idx) => { o[k] = vals[idx] !== undefined ? vals[idx] : null; });
            resultRows.push(o);
          }
        }
        if (union.some(u => u.distinct)) {
          const seen = new Set();
          resultRows = resultRows.filter(r => {
            const j = JSON.stringify(r);
            if (seen.has(j)) return false;
            seen.add(j);
            return true;
          });
        }
        const tail = sides[sides.length - 1];
        if (tail.orderClause) resultRows = executeOrderBy(resultRows, tail.orderClause);
        if (tail.limitClause !== null && tail.limitClause >= 0) resultRows = resultRows.slice(0, tail.limitClause);
      } else {
        resultRows = runSingleSelect(cleanSql, tables, signal, { deferOrderLimit: false }).rows;
      }
      checkAborted(signal);

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

  // One SELECT arm: FROM + chained JOINs, WHERE, GROUP BY + HAVING, SELECT
  // (or whole-set aggregates), ORDER BY, LIMIT. With deferOrderLimit the
  // trailing clauses are parsed and returned for the caller (UNION tail)
  // instead of applied.
  function runSingleSelect(cleanSql, tables, signal, opts = {}) {
    const deferOrderLimit = !!opts.deferOrderLimit;
    // Match basic components
    // SELECT ... FROM logs [JOIN ...] [WHERE ...] [GROUP BY ... [HAVING ...]]
    //   [ORDER BY ...] [LIMIT ...]
    const fromMatch = cleanSql.match(/^SELECT\s+([\s\S]+?)\s+FROM\s+(\w+)/i);
    if (!fromMatch) {
      throw new Error("Invalid SQL syntax. Expected: SELECT ... FROM logs [WHERE ...] [GROUP BY ...] [ORDER BY ...] [LIMIT ...]");
    }
    const selectClause = fromMatch[1].trim();
    const fromTable = (fromMatch[2] || 'logs').toLowerCase();
    if (!tables[fromTable]) {
      throw new Error(`Unknown table "${fromMatch[2]}". Available: ${Object.keys(tables).join(', ')}.`);
    }
    const afterFrom = cleanSql.slice(fromMatch[0].length);
    const cut = afterFrom.search(/\bWHERE\b|\bGROUP\s+BY\b|\bHAVING\b|\bORDER\s+BY\b|\bLIMIT\b/i);
    const joinSeg = (cut === -1 ? afterFrom : afterFrom.slice(0, cut)).trim();
    let dataset = tables[fromTable];
    const joinedTables = [fromTable];
    if (joinSeg) {
      const oneJoinSrc = '(?:(INNER|LEFT)\\s+)?JOIN\\s+(\\w+)\\s+ON\\s+([\\w.]+)\\s*=\\s*([\\w.]+)';
      const joins = [];
      let jm;
      const joinRe = new RegExp(oneJoinSrc, 'gi');
      while ((jm = joinRe.exec(joinSeg)) !== null) {
        joins.push({ kind: (jm[1] || 'inner').toLowerCase(), table: jm[2], lref: jm[3], rref: jm[4] });
      }
      const leftover = joinSeg.replace(new RegExp(oneJoinSrc, 'gi'), '').trim();
      if (joins.length === 0 || leftover) {
        throw new Error('Invalid JOIN syntax. Expected [INNER|LEFT] JOIN <table> ON <a.col> = <b.col>.');
      }
      for (const j of joins) {
        const rightTable = j.table.toLowerCase();
        if (!tables[rightTable]) {
          throw new Error(`Unknown table "${j.table}". Available: ${Object.keys(tables).join(', ')}.`);
        }
        if (joinedTables.includes(rightTable)) {
          throw new Error('Cannot JOIN a table to itself.');
        }
        dataset = buildJoin(dataset, tables[rightTable], joinedTables, rightTable, j.lref, j.rref, j.kind, signal);
        joinedTables.push(rightTable);
      }
    }

    // Extract optional clauses
    let whereClause = null;
    let groupByClause = null;
    let havingClause = null;
    let orderByClause = null;
    let limitClause = null;

    const whereMatch = cleanSql.match(/\s+WHERE\s+([\s\S]+?)(?=\s+GROUP\s+BY|\s+HAVING|\s+ORDER\s+BY|\s+LIMIT|$)/i);
    if (whereMatch) whereClause = whereMatch[1].trim();

    const groupMatch = cleanSql.match(/\s+GROUP\s+BY\s+([\s\S]+?)(?=\s+HAVING|\s+ORDER\s+BY|\s+LIMIT|$)/i);
    if (groupMatch) groupByClause = groupMatch[1].trim();

    const havingMatch = cleanSql.match(/\s+HAVING\s+([\s\S]+?)(?=\s+ORDER\s+BY|\s+LIMIT|$)/i);
    if (havingMatch) havingClause = havingMatch[1].trim();

    const orderMatch = cleanSql.match(/\s+ORDER\s+BY\s+([\s\S]+?)(?=\s+LIMIT|$)/i);
    if (orderMatch) orderByClause = orderMatch[1].trim();

    const limitMatch = cleanSql.match(/\s+LIMIT\s+(\d+)/i);
    if (limitMatch) limitClause = parseInt(limitMatch[1], 10);

    if (havingClause && !groupByClause) {
      throw new Error('HAVING requires GROUP BY.');
    }

    // 1. FILTER (WHERE) — cooperative abort every 1024 rows.
    let filtered = dataset;
    if (whereClause) {
      filtered = dataset.filter((row, i) => {
        if (i % 1024 === 0) checkAborted(signal);
        return evaluateWhere(whereClause, row);
      });
    }
    checkAborted(signal);

    // 2. GROUP BY & AGGREGATE (+ HAVING)
    let resultRows = [];
    if (groupByClause) {
      resultRows = executeGroupBy(filtered, groupByClause, selectClause, signal, havingClause);
    } else {
      resultRows = executeSelectOrAggregate(filtered, selectClause, signal);
    }
    checkAborted(signal);

    if (deferOrderLimit) return { rows: resultRows, orderClause: orderByClause, limitClause };

    // 3. ORDER BY
    if (orderByClause) {
      resultRows = executeOrderBy(resultRows, orderByClause);
    }

    // 4. LIMIT
    if (limitClause !== null && limitClause >= 0) {
      resultRows = resultRows.slice(0, limitClause);
    }
    return { rows: resultRows, orderClause: orderByClause, limitClause };
  }

  // SELECT without GROUP BY: when every selected item is an aggregate
  // (COUNT/AVG/SUM/P50/P95/P99, optional AS), compute one summary row over
  // the whole filtered set instead of per-row nulls.
  function executeSelectOrAggregate(dataset, selectClause, signal) {
    const fields = splitTopLevel(selectClause);
    const aggs = fields.map(f => {
      const { expr, alias } = splitAlias(f);
      const t = expr.trim();
      let m = t.match(/^COUNT\(\*\)$/i);
      if (m) return { out: alias || 'count', fn: 'count', arg: '*' };
      m = t.match(/^COUNT\(([\w.]+)\)$/i);
      if (m) return { out: alias || `count_${m[1]}`, fn: 'count', arg: m[1] };
      m = t.match(/^(AVG|SUM|P50|P95|P99)\(([\w.]+)\)$/i);
      if (m) return { out: alias || `${m[1].toLowerCase()}_${m[2]}`, fn: m[1].toLowerCase(), arg: m[2] };
      return null;
    });
    if (aggs.some(a => !a)) return executeSelect(dataset, selectClause, signal);
    checkAborted(signal);
    const row = {};
    for (const a of aggs) row[a.out] = aggNumber(a.fn, a.arg, dataset);
    return [row];
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
  function executeGroupBy(dataset, groupField, selectClause, signal, havingClause) {
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
        // e.g. COUNT(*) AS count, P95(latency_ms) AS p95
        const countMatch = f.match(/COUNT\((.*?)\)(?:\s+AS\s+(\w+))?/i);
        const avgMatch = f.match(/AVG\(([\w.]+)\)(?:\s+AS\s+(\w+))?/i);
        const sumMatch = f.match(/SUM\(([\w.]+)\)(?:\s+AS\s+(\w+))?/i);
        const pMatch = f.match(/P(50|95|99)\(([\w.]+)\)(?:\s+AS\s+(\w+))?/i);

        if (countMatch) {
          const colName = countMatch[2] || 'count';
          const arg = (countMatch[1] || '').trim();
          item[colName] = aggNumber('count', arg === '' ? '*' : arg, rowsInGroup);
        } else if (avgMatch) {
          const colName = avgMatch[2] || `avg_${avgMatch[1]}`;
          item[colName] = aggNumber('avg', avgMatch[1], rowsInGroup);
        } else if (sumMatch) {
          const colName = sumMatch[2] || `sum_${sumMatch[1]}`;
          item[colName] = aggNumber('sum', sumMatch[1], rowsInGroup);
        } else if (pMatch) {
          const colName = pMatch[3] || `p${pMatch[1]}_${pMatch[2]}`;
          item[colName] = aggNumber(`p${pMatch[1]}`, pMatch[2], rowsInGroup);
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
      if (!havingClause || evalHaving(havingClause, item, rowsInGroup)) {
        result.push(item);
      }
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
