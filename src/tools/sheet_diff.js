/**
 * SheetDiff Agent Tool
 * Headless Tabular CSV & Spreadsheet Reconciler
 * Cost: $0.002 / call
 */

function parseCsv(text, delimiterOverride) {
  if (!text || typeof text !== 'string') return { headers: [], rows: [] };
  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length === 0) return { headers: [], rows: [] };

  let delimiter = ',';
  if (typeof delimiterOverride === 'string' && delimiterOverride.length === 1) {
    delimiter = delimiterOverride;
  } else {
    const firstLine = lines[0];
    const tabCount = (firstLine.match(/\t/g) || []).length;
    const commaCount = (firstLine.match(/,/g) || []).length;
    const semiCount = (firstLine.match(/;/g) || []).length;
    if (tabCount > commaCount && tabCount >= semiCount) delimiter = '\t';
    else if (semiCount > commaCount && semiCount > tabCount) delimiter = ';';
  }

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

// Rename heuristic: a removed column and an added column carrying identical
// value vectors (row order included) are reported as one rename, not churn.
// Works on canonical names; value vectors come from caller-supplied getters
// so header-case aliasing stays outside this function.
function detectRenames(vecA, vecB, removed, added) {
  const renamed = [];
  const stillRemoved = [...removed];
  const stillAdded = [...added];
  for (const r of [...stillRemoved]) {
    const colR = vecA(r);
    const j = stillAdded.findIndex(a => {
      const colA = vecB(a);
      return colA.length === colR.length && colA.every((v, i) => v === colR[i]);
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
  const { baseline_csv, updated_csv, primary_key, case_sensitive, numeric_tolerance, detect_moves, delimiter, headers_case_sensitive } = args;

  if (!baseline_csv || !updated_csv) {
    throw new Error('Both "baseline_csv" and "updated_csv" strings are required.');
  }

  const tolerance = typeof numeric_tolerance === 'number' && numeric_tolerance > 0 ? numeric_tolerance : 0;
  const movesOn = detect_moves !== false;
  const headersCaseSensitive = headers_case_sensitive === true;

  const sheetA = parseCsv(baseline_csv, delimiter);
  const sheetB = parseCsv(updated_csv, delimiter);

  // Header canonicalization: `SKU` vs `sku` is the same column unless the
  // caller opts into case-sensitive headers. First spelling wins on
  // within-sheet collisions after lowering.
  const normH = h => headersCaseSensitive ? String(h) : String(h).toLowerCase();
  const canonA = new Map();
  sheetA.headers.forEach(h => { const n = normH(h); if (!canonA.has(n)) canonA.set(n, h); });
  const canonB = new Map();
  sheetB.headers.forEach(h => { const n = normH(h); if (!canonB.has(n)) canonB.set(n, h); });
  const canonHeaders = [...canonB.keys()];
  canonA.forEach((orig, n) => { if (!canonB.has(n)) canonHeaders.push(n); });
  const displayOf = n => canonB.get(n) !== undefined ? canonB.get(n) : canonA.get(n);
  const cellOf = (row, alias, n) => {
    const o = alias.get(n);
    return o !== undefined && row[o] !== undefined ? row[o] : '';
  };

  // Primary key: single column or composite list, resolved through the same
  // canonicalization so `primary_key: 'SKU'` matches a `sku` column.
  const resolveKeyCol = name => normH(name);
  let keyCols;
  if (Array.isArray(primary_key) && primary_key.length > 0) keyCols = primary_key.map(resolveKeyCol);
  else if (typeof primary_key === 'string' && primary_key) keyCols = [resolveKeyCol(primary_key)];
  else keyCols = [normH(detectPrimaryKey(canonHeaders, sheetB.rows))];

  const normalize = val => {
    let s = String(val !== undefined && val !== null ? val : '').trim();
    return case_sensitive ? s : s.toLowerCase();
  };
  const compKey = (row, alias, idx) => keyCols.map(c => {
    const o = alias.get(c);
    return normalize(o !== undefined && row[o] !== undefined ? row[o] : idx);
  }).join('\x00');
  const keyDisplay = (row, alias, idx) => {
    const parts = keyCols.map(c => {
      const o = alias.get(c);
      return o !== undefined && row[o] !== undefined ? String(row[o]) : '';
    }).filter(s => s !== '');
    return parts.length > 0 ? parts.join('|') : `row_${idx + 1}`;
  };

  // Duplicate primary keys used to last-win silently. Still last-win (stable
  // contract), but every surplus occurrence is now reported.
  const mapA = new Map();
  const dupCountA = new Map();
  const firstRawA = new Map();
  sheetA.rows.forEach((row, idx) => {
    const k = compKey(row, canonA, idx);
    dupCountA.set(k, (dupCountA.get(k) || 0) + 1);
    if (!firstRawA.has(k)) firstRawA.set(k, keyDisplay(row, canonA, idx));
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
    const k = compKey(rowB, canonB, idx);
    dupCountB.set(k, (dupCountB.get(k) || 0) + 1);
    if (!firstRawB.has(k)) firstRawB.set(k, keyDisplay(rowB, canonB, idx));
    processedKeys.add(k);

    if (mapA.has(k)) {
      const itemA = mapA.get(k);
      const rowA = itemA.row;
      const cellDiffs = {};
      let isMod = false;

      canonHeaders.forEach(canon => {
        const rawA = cellOf(rowA, canonA, canon);
        const rawB = cellOf(rowB, canonB, canon);
        if (!valuesEqual(rawA, rawB, !!case_sensitive, tolerance)) {
          isMod = true;
          cellDiffs[displayOf(canon)] = { old_value: String(rawA), new_value: String(rawB) };
          total_cell_changes++;
        }
      });

      if (movesOn && itemA.index !== idx) {
        moved_rows.push({
          key: keyDisplay(rowB, canonB, idx),
          from_index: itemA.index,
          to_index: idx,
          row_data: rowB
        });
      }

      if (isMod) {
        modified_rows.push({
          key: keyDisplay(rowB, canonB, idx),
          cell_changes: cellDiffs,
          row_data: rowB
        });
      } else {
        unchanged_count++;
      }
    } else {
      added_rows.push({
        key: keyDisplay(rowB, canonB, idx),
        row_data: rowB
      });
    }
  });

  const deleted_rows = [];
  sheetA.rows.forEach((rowA, idx) => {
    const k = compKey(rowA, canonA, idx);
    if (!processedKeys.has(k)) {
      deleted_rows.push({
        key: keyDisplay(rowA, canonA, idx),
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

  const removedCanon = [...canonA.keys()].filter(n => !canonB.has(n));
  const addedCanon = [...canonB.keys()].filter(n => !canonA.has(n));
  const renames = detectRenames(
    c => sheetA.rows.map(row => String(cellOf(row, canonA, c))),
    c => sheetB.rows.map(row => String(cellOf(row, canonB, c))),
    removedCanon,
    addedCanon
  );
  const schema_changes = {
    added_columns: renames.added_columns.map(displayOf),
    removed_columns: renames.removed_columns.map(displayOf),
    renamed_columns: renames.renamed_columns.map(p => ({
      from: canonA.get(p.from) !== undefined ? canonA.get(p.from) : p.from,
      to: canonB.get(p.to) !== undefined ? canonB.get(p.to) : p.to,
    })),
  };

  return {
    success: true,
    primary_key_used: keyCols.map(displayOf).join('+'),
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
      primary_key: { type: ['string', 'array'], description: 'Column name or list of columns to match rows (e.g. "sku" or ["warehouse", "sku"] for composite keys). Auto-detected if omitted.', items: { type: 'string' } },
      case_sensitive: { type: 'boolean', description: 'Whether string comparisons are case-sensitive. Default false.' },
      delimiter: { type: 'string', enum: [',', '\t', ';', '|', ':'], description: 'Field delimiter override. Auto-detected (comma/tab/semicolon) if omitted.' },
      headers_case_sensitive: { type: 'boolean', description: 'Treat "SKU" and "sku" as different columns. Default false (case-insensitive header matching).' },
      numeric_tolerance: { type: 'number', description: 'Absolute tolerance for numeric cell comparison ("10" vs "10.00" always equal; 10.00 vs 10.05 equal when tolerance >= 0.05). Default 0.' },
      detect_moves: { type: 'boolean', description: 'Report rows present in both sheets at different positions as moved_rows. Default true.' }
    },
    required: ['baseline_csv', 'updated_csv']
  },
  execute
};
