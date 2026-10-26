/**
 * JSON Diff Studio — Core Comparison Engine
 * Supports:
 * - Semantic Deep Comparison
 * - Smart Primary-Key Array Reconciliation
 * - Noise Suppression (Timestamps, UUIDs, Hashes, Custom Paths)
 * - Breaking Change & Schema Drift Sentinel
 * - RFC 6902 JSON Patch & Database Migration Exports
 * - Inferred TypeScript Interface Generator
 */

const DiffEngine = (() => {

  // Common UUID regex
  const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  // Common Hex / Hash regex (MD5, SHA1, SHA256)
  const HASH_REGEX = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
  // ISO Date regex
  const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$/;
  // Key names commonly associated with timestamps
  const TIMESTAMP_KEYS = /^(created_?at|updated_?at|timestamp|date|last_?modified|expires_?at|published_?at|time)$/i;
  // Key names commonly associated with volatile tokens / trace IDs
  const TRACE_KEYS = /^(trace_?id|request_?id|correlation_?id|etag|_?rev|session_?token|token|nonce)$/i;

  /**
   * Safely parse JSON with friendly error positioning
   */
  function parseJSON(str) {
    if (!str || typeof str !== 'string' || !str.trim()) {
      return { ok: false, error: 'Input is empty' };
    }
    try {
      const data = JSON.parse(str);
      return { ok: true, data };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /**
   * Determine exact type of JSON value
   */
  function getType(val) {
    if (val === null) return 'null';
    if (Array.isArray(val)) return 'array';
    return typeof val;
  }

  /**
   * Recursively sort object keys alphabetically
   */
  function sortKeys(obj) {
    if (Array.isArray(obj)) {
      return obj.map(sortKeys);
    } else if (obj !== null && typeof obj === 'object') {
      const sorted = {};
      Object.keys(obj).sort().forEach(k => {
        sorted[k] = sortKeys(obj[k]);
      });
      return sorted;
    }
    return obj;
  }

  /**
   * Checks if a value/key represents dynamic timestamp noise
   */
  function isTimestampNoise(key, val) {
    if (TIMESTAMP_KEYS.test(key)) return true;
    if (typeof val === 'string' && ISO_DATE_REGEX.test(val)) return true;
    if (typeof val === 'number') {
      // Milliseconds between 2010 and 2040
      if (val > 1262304000000 && val < 2208988800000) return true;
      // Seconds between 2010 and 2040
      if (val > 1262304000 && val < 2208988800) return true;
    }
    return false;
  }

  /**
   * Checks if a value/key represents UUID, hash or trace noise
   */
  function isUuidNoise(key, val) {
    if (TRACE_KEYS.test(key)) return true;
    if (typeof val === 'string') {
      if (UUID_REGEX.test(val)) return true;
      if (HASH_REGEX.test(val)) return true;
    }
    return false;
  }

  /**
   * Checks if path matches user-defined custom ignore patterns
   */
  function isCustomIgnored(pathStr, patterns) {
    if (!patterns || !patterns.length) return false;
    for (const pat of patterns) {
      const clean = pat.trim();
      if (!clean) continue;
      // Convert simple glob (*.id) to regex
      const regexStr = '^' + clean.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$';
      try {
        if (new RegExp(regexStr, 'i').test(pathStr)) return true;
      } catch (e) {
        if (pathStr.toLowerCase().includes(clean.toLowerCase())) return true;
      }
    }
    return false;
  }

  /**
   * Auto-detect the primary key for an array of objects
   */
  function detectPrimaryKey(arrA, arrB, preferredKey) {
    if (preferredKey && preferredKey !== 'auto') {
      return preferredKey;
    }

    const candidates = ['id', '_id', 'uuid', 'key', 'sku', 'code', 'email', 'userId', 'orderId', 'slug', 'name'];
    const sample = [...(arrA || []), ...(arrB || [])].filter(x => x && typeof x === 'object' && !Array.isArray(x));
    if (sample.length === 0) return null;

    for (const cand of candidates) {
      const matchCount = sample.filter(item => item[cand] !== undefined && item[cand] !== null).length;
      if (matchCount / sample.length >= 0.7) {
        return cand;
      }
    }
    return null;
  }

  /**
   * Main Diff function
   */
  function diff(jsonA, jsonB, options = {}) {
    const opts = {
      smartArrays: options.smartArrays !== false,       // Primary Key array matching
      primaryKey: options.primaryKey || 'auto',
      ignoreTimestamps: !!options.ignoreTimestamps,     // Ignore date/timestamp noise
      ignoreUuids: !!options.ignoreUuids,               // Ignore trace/UUID/hashes
      ignoreKeyOrder: options.ignoreKeyOrder !== false, // Always sort keys
      customIgnore: options.customIgnore || [],         // Array of pattern strings
      proActive: !!options.proActive                    // Pro status toggle
    };

    // If Pro is inactive, disable advanced Pro features in free mode
    if (!opts.proActive) {
      opts.smartArrays = false;
      opts.ignoreTimestamps = false;
      opts.ignoreUuids = false;
      opts.customIgnore = [];
    }

    let a = jsonA;
    let b = jsonB;

    if (opts.ignoreKeyOrder) {
      a = sortKeys(a);
      b = sortKeys(b);
    }

    const stats = {
      totalNodes: 0,
      added: 0,
      removed: 0,
      modified: 0,
      breaking: 0,
      ignored: 0,
      unchanged: 0
    };

    const breakingChanges = [];
    const patchOperations = [];

    // Recursive diff core
    function compare(valA, valB, key, path, depth) {
      stats.totalNodes++;
      const currentPath = path ? `${path}.${key}` : key;
      const typeA = getType(valA);
      const typeB = getType(valB);

      // Check noise filters
      const isNoise = (opts.ignoreTimestamps && isTimestampNoise(key, valA) && isTimestampNoise(key, valB)) ||
                      (opts.ignoreUuids && isUuidNoise(key, valA) && isUuidNoise(key, valB)) ||
                      isCustomIgnored(currentPath, opts.customIgnore);

      if (isNoise) {
        stats.ignored++;
        return {
          key,
          path: currentPath,
          status: 'IGNORED',
          typeA,
          typeB,
          valA,
          valB,
          depth,
          noiseReason: 'Filter matched'
        };
      }

      // 1. ADDED in B
      if (valA === undefined && valB !== undefined) {
        stats.added++;
        patchOperations.push({ op: 'add', path: '/' + currentPath.replace(/\./g, '/'), value: valB });
        return {
          key,
          path: currentPath,
          status: 'ADDED',
          typeB,
          valB,
          depth
        };
      }

      // 2. REMOVED in B (Potential Breaking Change!)
      if (valA !== undefined && valB === undefined) {
        stats.removed++;
        stats.breaking++;
        breakingChanges.push({
          path: currentPath,
          type: 'FIELD_DELETED',
          severity: 'CRITICAL',
          message: `Mandatory field '${currentPath}' removed in target payload.`
        });
        patchOperations.push({ op: 'remove', path: '/' + currentPath.replace(/\./g, '/') });
        return {
          key,
          path: currentPath,
          status: 'REMOVED',
          typeA,
          valA,
          depth
        };
      }

      // 3. TYPE MUTATION (Critical Breaking Change!)
      if (typeA !== typeB) {
        // Nullable transitions
        const isNullTransition = (typeA === 'null' || typeB === 'null');
        stats.modified++;
        stats.breaking++;
        breakingChanges.push({
          path: currentPath,
          type: 'TYPE_MUTATION',
          severity: isNullTransition ? 'WARNING' : 'CRITICAL',
          message: `Type changed from '${typeA}' to '${typeB}'. Potential client crash.`
        });
        patchOperations.push({ op: 'replace', path: '/' + currentPath.replace(/\./g, '/'), value: valB });
        return {
          key,
          path: currentPath,
          status: 'BREAKING',
          typeA,
          typeB,
          valA,
          valB,
          depth,
          breakingDetails: `Type changed from ${typeA} to ${typeB}`
        };
      }

      // 4. BOTH ARE OBJECTS
      if (typeA === 'object') {
        const keysA = Object.keys(valA);
        const keysB = Object.keys(valB);
        const allKeys = Array.from(new Set([...keysA, ...keysB])).sort();

        const children = [];
        let hasChildDiff = false;

        for (const childKey of allKeys) {
          const childNode = compare(valA[childKey], valB[childKey], childKey, currentPath, depth + 1);
          children.push(childNode);
          if (childNode.status !== 'UNCHANGED' && childNode.status !== 'IGNORED') {
            hasChildDiff = true;
          }
        }

        return {
          key,
          path: currentPath,
          status: hasChildDiff ? 'MODIFIED' : 'UNCHANGED',
          type: 'object',
          children,
          depth
        };
      }

      // 5. BOTH ARE ARRAYS
      if (typeA === 'array') {
        const children = [];
        let hasChildDiff = false;

        // Check if Smart Array Reconciliation applies (arrays of objects with primary key)
        const detectedKey = opts.smartArrays ? detectPrimaryKey(valA, valB, opts.primaryKey) : null;

        if (opts.smartArrays && detectedKey) {
          // Smart Array Reconciliation by Primary Key
          const mapA = new Map();
          const mapB = new Map();

          valA.forEach((item, idx) => {
            if (item && typeof item === 'object') {
              const id = item[detectedKey];
              if (id !== undefined) mapA.set(String(id), { item, idx });
            }
          });

          valB.forEach((item, idx) => {
            if (item && typeof item === 'object') {
              const id = item[detectedKey];
              if (id !== undefined) mapB.set(String(id), { item, idx });
            }
          });

          const processedKeys = new Set();

          // Compare existing & matched items
          mapA.forEach(({ item: itemA, idx: idxA }, idStr) => {
            processedKeys.add(idStr);
            if (mapB.has(idStr)) {
              const { item: itemB, idx: idxB } = mapB.get(idStr);
              const node = compare(itemA, itemB, `[${detectedKey}:${idStr}]`, currentPath, depth + 1);
              if (idxA !== idxB) {
                node.indexShift = { from: idxA, to: idxB };
              }
              children.push(node);
              if (node.status !== 'UNCHANGED' && node.status !== 'IGNORED') {
                hasChildDiff = true;
              }
            } else {
              // Item in A but deleted in B
              stats.removed++;
              patchOperations.push({ op: 'remove', path: `${currentPath}[${idxA}]` });
              children.push({
                key: `[${detectedKey}:${idStr}]`,
                path: `${currentPath}[${idxA}]`,
                status: 'REMOVED',
                typeA: 'object',
                valA: itemA,
                depth: depth + 1
              });
              hasChildDiff = true;
            }
          });

          // Items added in B
          mapB.forEach(({ item: itemB, idx: idxB }, idStr) => {
            if (!processedKeys.has(idStr)) {
              stats.added++;
              patchOperations.push({ op: 'add', path: `${currentPath}[${idxB}]`, value: itemB });
              children.push({
                key: `[${detectedKey}:${idStr}]`,
                path: `${currentPath}[${idxB}]`,
                status: 'ADDED',
                typeB: 'object',
                valB: itemB,
                depth: depth + 1
              });
              hasChildDiff = true;
            }
          });

        } else {
          // Standard Index-based comparison
          const maxLen = Math.max(valA.length, valB.length);
          for (let i = 0; i < maxLen; i++) {
            const childNode = compare(valA[i], valB[i], `[${i}]`, currentPath, depth + 1);
            children.push(childNode);
            if (childNode.status !== 'UNCHANGED' && childNode.status !== 'IGNORED') {
              hasChildDiff = true;
            }
          }
        }

        return {
          key,
          path: currentPath,
          status: hasChildDiff ? 'MODIFIED' : 'UNCHANGED',
          type: 'array',
          children,
          depth,
          arrayReconciledKey: detectedKey || null
        };
      }

      // 6. PRIMITIVE VALUES (string, number, boolean)
      if (valA === valB) {
        stats.unchanged++;
        return {
          key,
          path: currentPath,
          status: 'UNCHANGED',
          type: typeA,
          valA,
          valB,
          depth
        };
      } else {
        stats.modified++;
        patchOperations.push({ op: 'replace', path: '/' + currentPath.replace(/\./g, '/'), value: valB });
        return {
          key,
          path: currentPath,
          status: 'MODIFIED',
          typeA,
          typeB,
          valA,
          valB,
          depth
        };
      }
    }

    const tree = compare(a, b, 'root', '', 0);

    return {
      tree,
      stats,
      breakingChanges,
      patchOperations,
      options: opts
    };
  }

  /**
   * Export RFC 6902 JSON Patch formatted string
   */
  function exportJsonPatch(patchOps) {
    return JSON.stringify(patchOps, null, 2);
  }

  /**
   * Generate MongoDB Update Query ($set, $unset)
   */
  function exportMongoQuery(patchOps) {
    const $set = {};
    const $unset = {};

    for (const op of patchOps) {
      const dotPath = op.path.replace(/^\//, '').replace(/\//g, '.');
      if (op.op === 'add' || op.op === 'replace') {
        $set[dotPath] = op.value;
      } else if (op.op === 'remove') {
        $unset[dotPath] = "";
      }
    }

    const query = {};
    if (Object.keys($set).length) query.$set = $set;
    if (Object.keys($unset).length) query.$unset = $unset;

    return `db.collection.updateOne(\n  { /* filter */ },\n  ${JSON.stringify(query, null, 2)}\n);`;
  }

  /**
   * Generate PostgreSQL JSONB updates
   */
  function exportPostgresQuery(patchOps, tableName = "api_payloads", jsonColumn = "payload") {
    let sql = `-- PostgreSQL JSONB Reconcile Script\n`;
    patchOps.forEach(op => {
      const cleanPath = op.path.replace(/^\//, '').split('/');
      const pathArraySql = cleanPath.map(p => `'${p}'`).join(', ');

      if (op.op === 'add' || op.op === 'replace') {
        const valJson = JSON.stringify(op.value).replace(/'/g, "''");
        sql += `UPDATE ${tableName}\nSET ${jsonColumn} = jsonb_set(${jsonColumn}, '{${cleanPath.join(',')}}', '${valJson}'::jsonb, true)\nWHERE id = 1;\n\n`;
      } else if (op.op === 'remove') {
        sql += `UPDATE ${tableName}\nSET ${jsonColumn} = ${jsonColumn} #- '{${cleanPath.join(',')}}'\nWHERE id = 1;\n\n`;
      }
    });
    return sql;
  }

  /**
   * Generate TypeScript Interface from JSON object
   */
  function generateTypeScript(obj, interfaceName = "ApiResponse") {
    if (obj === null || typeof obj !== 'object') {
      return `export type ${interfaceName} = ${typeof obj};`;
    }

    const interfaces = [];
    const createdNames = new Set();

    function formatInterface(name, target) {
      if (Array.isArray(target)) {
        if (target.length === 0) return `export type ${name} = any[];`;
        const innerType = typeof target[0] === 'object' && target[0] !== null ? `${name}Item` : typeof target[0];
        if (typeof target[0] === 'object' && target[0] !== null) {
          formatInterface(innerType, target[0]);
        }
        return `export type ${name} = ${innerType}[];`;
      }

      let lines = [`export interface ${name} {`];
      for (const [k, v] of Object.entries(target)) {
        const keyName = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(k) ? k : `"${k}"`;
        if (v === null) {
          lines.push(`  ${keyName}: any | null;`);
        } else if (Array.isArray(v)) {
          if (v.length > 0 && typeof v[0] === 'object' && v[0] !== null) {
            const subName = `${name}_${k.charAt(0).toUpperCase() + k.slice(1)}Item`;
            if (!createdNames.has(subName)) {
              createdNames.add(subName);
              formatInterface(subName, v[0]);
            }
            lines.push(`  ${keyName}: ${subName}[];`);
          } else {
            lines.push(`  ${keyName}: ${v.length ? typeof v[0] : 'any'}[];`);
          }
        } else if (typeof v === 'object') {
          const subName = `${name}_${k.charAt(0).toUpperCase() + k.slice(1)}`;
          if (!createdNames.has(subName)) {
            createdNames.add(subName);
            formatInterface(subName, v);
          }
          lines.push(`  ${keyName}: ${subName};`);
        } else {
          lines.push(`  ${keyName}: ${typeof v};`);
        }
      }
      lines.push('}');
      interfaces.unshift(lines.join('\n'));
    }

    formatInterface(interfaceName, obj);
    return interfaces.join('\n\n');
  }

  const engine = {
    parseJSON,
    diff,
    exportJsonPatch,
    exportMongoQuery,
    exportPostgresQuery,
    generateTypeScript
  };

  if (typeof window !== 'undefined') {
    window.DiffEngine = engine;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = engine;
  }

  return engine;
})();
