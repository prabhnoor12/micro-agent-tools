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

  function execute(sqlQuery, dataset, opts = {}) {
    const startTime = performance.now();
    const signal = opts.signal || null;
    const maxRows = Number(opts.maxRows) > 0 ? Number(opts.maxRows) : 1000;
    if (!sqlQuery || !sqlQuery.trim()) {
      return { columns: [], rows: [], executionTimeMs: 0, error: 'Empty SQL query' };
    }

    try {
      const cleanSql = sqlQuery.trim().replace(/;$/, '');
      if (cleanSql.includes(';')) {
        throw new Error('Multiple statements are not allowed. Send a single SELECT query.');
      }
      
      // Match basic components
      // SELECT ... FROM logs [WHERE ...] [GROUP BY ...] [ORDER BY ...] [LIMIT ...]
      const selectMatch = cleanSql.match(/^SELECT\s+([\s\S]+?)\s+FROM\s+\w+/i);
      if (!selectMatch) {
        throw new Error("Invalid SQL syntax. Expected: SELECT ... FROM logs [WHERE ...] [GROUP BY ...] [ORDER BY ...] [LIMIT ...]");
      }

      const selectClause = selectMatch[1].trim();

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
    // LIKE
    const likeMatch = cond.match(/^(\w+)\s+LIKE\s+'%([^']+?)%'/i);
    if (likeMatch) {
      const val = String(row[likeMatch[1]] || '');
      return val.toLowerCase().includes(likeMatch[2].toLowerCase());
    }

    // Comparison operators (>=, <=, !=, <>, >, <, =)
    const compMatch = cond.match(/^(\w+)\s*(=|!=|<>|>=|<=|>|<)\s*(.+)$/);
    if (compMatch) {
      const field = compMatch[1];
      const op = compMatch[2];
      let expected = compMatch[3].trim();

      if ((expected.startsWith("'") && expected.endsWith("'")) || (expected.startsWith('"') && expected.endsWith('"'))) {
        expected = expected.substring(1, expected.length - 1);
      } else if (!isNaN(Number(expected))) {
        expected = Number(expected);
      }

      const actual = row[field];
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
  function executeSelect(dataset, selectClause, signal) {
    if (selectClause === '*') {
      return dataset.map((row, i) => {
        if (i % 1024 === 0) checkAborted(signal);
        return { ...row };
      });
    }

    const fields = selectClause.split(',').map(s => s.trim());
    return dataset.map((row, i) => {
      if (i % 1024 === 0) checkAborted(signal);
      const out = {};
      fields.forEach(f => {
        const asMatch = f.match(/^(\w+)\s+AS\s+(\w+)$/i);
        if (asMatch) {
          out[asMatch[2]] = row[asMatch[1]];
        } else {
          out[f] = row[f] !== undefined ? row[f] : null;
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
      const key = row[groupField] !== undefined ? String(row[groupField]) : '(empty)';
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key).push(row);
    });
    checkAborted(signal);

    const fields = selectClause.split(',').map(s => s.trim());
    const result = [];

    groups.forEach((rowsInGroup, groupKey) => {
      const item = {};
      fields.forEach(f => {
        // e.g. COUNT(*) AS count
        const countMatch = f.match(/COUNT\((.*?)\)(?:\s+AS\s+(\w+))?/i);
        const avgMatch = f.match(/AVG\((\w+)\)(?:\s+AS\s+(\w+))?/i);
        const sumMatch = f.match(/SUM\((\w+)\)(?:\s+AS\s+(\w+))?/i);

        if (countMatch) {
          const colName = countMatch[2] || 'count';
          item[colName] = rowsInGroup.length;
        } else if (avgMatch) {
          const colName = avgMatch[2] || `avg_${avgMatch[1]}`;
          const total = rowsInGroup.reduce((acc, r) => acc + (Number(r[avgMatch[1]]) || 0), 0);
          item[colName] = rowsInGroup.length ? Math.round((total / rowsInGroup.length) * 10) / 10 : 0;
        } else if (sumMatch) {
          const colName = sumMatch[2] || `sum_${sumMatch[1]}`;
          item[colName] = rowsInGroup.reduce((acc, r) => acc + (Number(r[sumMatch[1]]) || 0), 0);
        } else {
          const asMatch = f.match(/^(\w+)\s+AS\s+(\w+)$/i);
          const rawCol = asMatch ? asMatch[1] : f;
          const outCol = asMatch ? asMatch[2] : f;
          if (rawCol === groupField) {
            item[outCol] = groupKey;
          } else {
            item[outCol] = rowsInGroup[0] ? rowsInGroup[0][rawCol] : null;
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
      const valA = a[col];
      const valB = b[col];
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
