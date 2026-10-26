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

function execute(args) {
  const { baseline_csv, updated_csv, primary_key, case_sensitive } = args;

  if (!baseline_csv || !updated_csv) {
    throw new Error('Both "baseline_csv" and "updated_csv" strings are required.');
  }

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

  const mapA = new Map();
  sheetA.rows.forEach((row, idx) => {
    const k = normalize(row[keyCol] !== undefined ? row[keyCol] : idx);
    mapA.set(k, { row, index: idx });
  });

  const added_rows = [];
  const modified_rows = [];
  let unchanged_count = 0;
  let total_cell_changes = 0;
  const processedKeys = new Set();

  sheetB.rows.forEach((rowB, idx) => {
    const k = normalize(rowB[keyCol] !== undefined ? rowB[keyCol] : idx);
    processedKeys.add(k);

    if (mapA.has(k)) {
      const itemA = mapA.get(k);
      const rowA = itemA.row;
      const cellDiffs = {};
      let isMod = false;

      allHeaders.forEach(col => {
        const valA = String(rowA[col] !== undefined ? rowA[col] : '');
        const valB = String(rowB[col] !== undefined ? rowB[col] : '');
        if (normalize(valA) !== normalize(valB)) {
          isMod = true;
          cellDiffs[col] = { old_value: valA, new_value: valB };
          total_cell_changes++;
        }
      });

      if (isMod) {
        modified_rows.push({
          key: rowB[keyCol] || `row_${idx + 1}`,
          cell_changes: cellDiffs,
          row_data: rowB
        });
      } else {
        unchanged_count++;
      }
    } else {
      added_rows.push({
        key: rowB[keyCol] || `row_${idx + 1}`,
        row_data: rowB
      });
    }
  });

  const deleted_rows = [];
  sheetA.rows.forEach((rowA, idx) => {
    const k = normalize(rowA[keyCol] !== undefined ? rowA[keyCol] : idx);
    if (!processedKeys.has(k)) {
      deleted_rows.push({
        key: rowA[keyCol] || `row_${idx + 1}`,
        row_data: rowA
      });
    }
  });

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
      total_cell_changes
    },
    added_rows,
    deleted_rows,
    modified_rows
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
      case_sensitive: { type: 'boolean', description: 'Whether string comparisons are case-sensitive. Default false.' }
    },
    required: ['baseline_csv', 'updated_csv']
  },
  execute
};
