/**
 * SheetDiff Agent Tool
 * Headless Tabular CSV & Spreadsheet Reconciler
 * Cost: $0.002 / call
 */

function parseCsv(text) {
  if (!text || typeof text !== 'string') return { headers: [], rows: [] };
  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length === 0) return { headers: [], rows: [] };

  const firstLine = lines[0];
  const tabCount = (firstLine.match(/\t/g) || []).length;
  const commaCount = (firstLine.match(/,/g) || []).length;
  const semiCount = (firstLine.match(/;/g) || []).length;
  let delimiter = ',';
  if (tabCount > commaCount && tabCount >= semiCount) delimiter = '\t';
  else if (semiCount > commaCount && semiCount > tabCount) delimiter = ';';

  const parseLine = line => {
    const res = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === delimiter && !inQuotes) {
        res.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    res.push(cur.trim());
    return res;
  };

  const headers = parseLine(lines[0]).map((h, i) => h.trim() || `col_${i + 1}`);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const parts = parseLine(lines[i]);
    const row = {};
    headers.forEach((h, idx) => {
      row[h] = parts[idx] !== undefined ? parts[idx] : '';
    });
    rows.push(row);
  }
  return { headers, rows };
}

function detectPrimaryKey(headers, rows) {
  const patterns = [/^id$/i, /^sku$/i, /^email$/i, /^code$/i, /^uuid$/i, /^key$/i, /_id$/i, /sku/i, /code/i];
  for (const pat of patterns) {
    const found = headers.find(h => pat.test(h));
    if (found) return found;
  }
  return headers[0] || 'row_index';
}

function tryParseNumber(val) {
  if (val === undefined || val === null) return null;
  const s = String(val).trim();
  if (s === '') return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

// Numeric-aware equality: "10" vs "10.00" is the same value, subject to an
// absolute tolerance. Non-numeric values fall back to trimmed string compare.
function valuesEqual(valA, valB, caseSensitive, numericTolerance) {
  const numA = tryParseNumber(valA);
  const numB = tryParseNumber(valB);
  if (numA !== null && numB !== null) {
    return Math.abs(numA - numB) <= numericTolerance;
  }
  const sA = String(valA !== undefined && valA !== null ? valA : '').trim();
  const sB = String(valB !== undefined && valB !== null ? valB : '').trim();
  return caseSensitive ? sA === sB : sA.toLowerCase() === sB.toLowerCase();
}

function keyLabel(row, keyCol, idx) {
  const raw = row[keyCol];
  return raw !== undefined && raw !== null && String(raw) !== '' ? String(raw) : `row_${idx + 1}`;
}

// Rename heuristic: a removed column and an added column carrying identical
// value vectors (row order included) are reported as one rename, not churn.
function detectRenames(sheetA, sheetB, removed, added) {
  const renamed = [];
  const stillRemoved = [...removed];
  const stillAdded = [...added];
  for (const r of [...stillRemoved]) {
    const vecR = sheetA.rows.map(row => String(row[r] !== undefined ? row[r] : ''));
    const j = stillAdded.findIndex(a => {
      const vecA = sheetB.rows.map(row => String(row[a] !== undefined ? row[a] : ''));
      return vecA.length === vecR.length && vecA.every((v, i) => v === vecR[i]);
    });
    if (j >= 0) {
      renamed.push({ from: r, to: stillAdded[j] });
      stillRemoved.splice(stillRemoved.indexOf(r), 1);
      stillAdded.splice(j, 1);
    }
  }
  return { renamed_columns: renamed, added_columns: stillAdded, removed_columns: stillRemoved };
}

function execute(args) {
  const { baseline_csv, updated_csv, primary_key, case_sensitive, numeric_tolerance, detect_moves } = args;

  if (!baseline_csv || !updated_csv) {
    throw new Error('Both "baseline_csv" and "updated_csv" strings are required.');
  }

  const tolerance = typeof numeric_tolerance === 'number' && numeric_tolerance > 0 ? numeric_tolerance : 0;
  const movesOn = detect_moves !== false;

  const sheetA = parseCsv(baseline_csv);
  const sheetB = parseCsv(updated_csv);

  const allHeaders = [...sheetB.headers];
  sheetA.headers.forEach(h => {
    if (!allHeaders.includes(h)) allHeaders.push(h);
  });

  const keyCol = primary_key || detectPrimaryKey(allHeaders, sheetB.rows);
  const normalize = val => {
    let s = String(val !== undefined && val !== null ? val : '').trim();
    return case_sensitive ? s : s.toLowerCase();
  };

  // Duplicate primary keys used to last-win silently. Still last-win (stable
  // contract), but every surplus occurrence is now reported.
  const mapA = new Map();
  const dupCountA = new Map();
  const firstRawA = new Map();
  sheetA.rows.forEach((row, idx) => {
    const k = normalize(row[keyCol] !== undefined ? row[keyCol] : idx);
    dupCountA.set(k, (dupCountA.get(k) || 0) + 1);
    if (!firstRawA.has(k)) firstRawA.set(k, keyLabel(row, keyCol, idx));
    mapA.set(k, { row, index: idx });
  });

  const added_rows = [];
  const modified_rows = [];
  const moved_rows = [];
  let unchanged_count = 0;
  let total_cell_changes = 0;
  const processedKeys = new Set();
  const dupCountB = new Map();
  const firstRawB = new Map();

  sheetB.rows.forEach((rowB, idx) => {
    const k = normalize(rowB[keyCol] !== undefined ? rowB[keyCol] : idx);
    dupCountB.set(k, (dupCountB.get(k) || 0) + 1);
    if (!firstRawB.has(k)) firstRawB.set(k, keyLabel(rowB, keyCol, idx));
    processedKeys.add(k);

    if (mapA.has(k)) {
      const itemA = mapA.get(k);
      const rowA = itemA.row;
      const cellDiffs = {};
      let isMod = false;

      allHeaders.forEach(col => {
        const rawA = rowA[col] !== undefined ? rowA[col] : '';
        const rawB = rowB[col] !== undefined ? rowB[col] : '';
        if (!valuesEqual(rawA, rawB, !!case_sensitive, tolerance)) {
          isMod = true;
          cellDiffs[col] = { old_value: String(rawA), new_value: String(rawB) };
          total_cell_changes++;
        }
      });

      if (movesOn && itemA.index !== idx) {
        moved_rows.push({
          key: keyLabel(rowB, keyCol, idx),
          from_index: itemA.index,
          to_index: idx,
          row_data: rowB
        });
      }

      if (isMod) {
        modified_rows.push({
          key: keyLabel(rowB, keyCol, idx),
          cell_changes: cellDiffs,
          row_data: rowB
        });
      } else {
        unchanged_count++;
      }
    } else {
      added_rows.push({
        key: keyLabel(rowB, keyCol, idx),
        row_data: rowB
      });
    }
  });

  const deleted_rows = [];
  sheetA.rows.forEach((rowA, idx) => {
    const k = normalize(rowA[keyCol] !== undefined ? rowA[keyCol] : idx);
    if (!processedKeys.has(k)) {
      deleted_rows.push({
        key: keyLabel(rowA, keyCol, idx),
        row_data: rowA
      });
    }
  });

  const dupList = (counts, firstRaw) => {
    const out = [];
    for (const [k, n] of counts) {
      if (n > 1) out.push({ key: firstRaw.get(k), occurrences: n });
    }
    return out;
  };
  const dupBaseline = dupList(dupCountA, firstRawA);
  const dupUpdated = dupList(dupCountB, firstRawB);
  const duplicate_key_count =
    dupBaseline.reduce((n, d) => n + d.occurrences - 1, 0) +
    dupUpdated.reduce((n, d) => n + d.occurrences - 1, 0);

  const schema_changes = detectRenames(
    sheetA,
    sheetB,
    sheetA.headers.filter(h => !sheetB.headers.includes(h)),
    sheetB.headers.filter(h => !sheetA.headers.includes(h))
  );

  return {
    success: true,
    primary_key_used: keyCol,
    stats: {
      baseline_total_rows: sheetA.rows.length,
      updated_total_rows: sheetB.rows.length,
      added_count: added_rows.length,
      deleted_count: deleted_rows.length,
      modified_count: modified_rows.length,
      unchanged_count,
      total_cell_changes,
      moved_count: moved_rows.length,
      duplicate_key_count
    },
    added_rows,
    deleted_rows,
    modified_rows,
    moved_rows,
    duplicate_keys: { baseline: dupBaseline, updated: dupUpdated },
    schema_changes
  };
}

module.exports = {
  name: 'sheet_diff',
  description: 'Reconciles two CSV/TSV spreadsheets by Primary Key (SKU, Email, ID). Returns structured row and cell deltas.',
  free: true,
  cost_usd: 0.00,
  parameters: {
    type: 'object',
    properties: {
      baseline_csv: { type: 'string', description: 'Original CSV or TSV string' },
      updated_csv: { type: 'string', description: 'Updated/modified CSV or TSV string' },
      primary_key: { type: 'string', description: 'Column name to match rows (e.g. "sku", "id", "email"). Auto-detected if omitted.' },
      case_sensitive: { type: 'boolean', description: 'Whether string comparisons are case-sensitive. Default false.' },
      numeric_tolerance: { type: 'number', description: 'Absolute tolerance for numeric cell comparison ("10" vs "10.00" always equal; 10.00 vs 10.05 equal when tolerance >= 0.05). Default 0.' },
      detect_moves: { type: 'boolean', description: 'Report rows present in both sheets at different positions as moved_rows. Default true.' }
    },
    required: ['baseline_csv', 'updated_csv']
  },
  execute
};
