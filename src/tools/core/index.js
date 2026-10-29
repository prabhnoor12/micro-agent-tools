/**
 * Agentic Micro-SaaS Suite — Unified Core Engines
 * Zero DOM dependencies. 100% Web Standards (Web Crypto, TextEncoder).
 * Optimized for LLM Agents & Edge Compute.
 */

const DiffEngine = require('./json-diff.js');
const HmacEngine = require('./webhook-forge.js');
const JwtEngine = require('./jwt-studio.js');
const SourceMapParser = require('./sourcemap-hero.js');
const EnvParser = require('./env-parser.js');
const EnvValidator = require('./env-validator.js');
const EnvExporters = require('./env-exporters.js');
const LogParser = require('./log-parser.js');
const SqlEngine = require('./sql-engine.js');

/**
 * 1. JSON Diff & Schema Breaking Change Detector
 */
function runJsonDiff(payloadA, payloadB, options = {}) {
  const jsonA = typeof payloadA === 'string' ? JSON.parse(payloadA) : payloadA;
  const jsonB = typeof payloadB === 'string' ? JSON.parse(payloadB) : payloadB;

  const diffOpts = {
    smartArrays: options.smartArrays !== false,
    primaryKey: options.primaryKey || 'auto',
    ignoreTimestamps: options.ignoreTimestamps !== false,
    ignoreUuids: options.ignoreUuids !== false,
    ignoreKeyOrder: options.ignoreKeyOrder !== false,
    customIgnore: options.customIgnore || [],
    proActive: true
  };

  const result = DiffEngine.diff(jsonA, jsonB, diffOpts);

  return {
    ok: true,
    breakingChanges: result.breakingChanges,
    hasBreakingChanges: result.breakingChanges.length > 0,
    stats: result.stats,
    patchOperations: result.patchOperations,
    jsonPatch: DiffEngine.exportJsonPatch(result.patchOperations),
    diffSummary: `Diff Analysis: +${result.stats.added} added, -${result.stats.removed} removed, ~${result.stats.modified} modified, ${result.stats.breaking} breaking schema changes, ${result.stats.ignored} noise filtered.`
  };
}

/**
 * 2. Webhook Signature Verifier, Signer & Insecure Secret Sentinel
 */
async function runWebhookForge(provider, rawPayload, secret, options = {}) {
  const provKey = (provider || 'stripe').toLowerCase();
  const payloadStr = typeof rawPayload === 'object' ? JSON.stringify(rawPayload) : String(rawPayload || '');
  const secretKey = String(secret || '');

  // 1. Audit weak secret
  const weakCheck = HmacEngine.checkWeakSecret(secretKey);

  // 2. Generate or re-sign signature
  const timestamp = options.timestamp || (Math.floor(Date.now() / 1000) + (options.timestampOffsetSeconds || 0));
  const computed = await HmacEngine.generateProviderSignature(provKey, payloadStr, secretKey, { timestamp });

  // 3. Verify incoming signature if provided
  let verification = null;
  if (options.receivedHeader) {
    verification = await HmacEngine.verifySignature(provKey, payloadStr, secretKey, options.receivedHeader);
  }

  // Replay protection: timestamped providers (stripe/slack/svix/paddle)
  // are fresh only within the tolerance window (default 300s).
  const tolerance = Number(options.timestampToleranceSec) || 300;
  let timestampOk = null;
  let isReplayRisk = false;
  if (verification && ['stripe', 'slack', 'svix', 'paddle'].includes(provKey)) {
    const age = Math.floor(Date.now() / 1000) - Number(verification.timestamp || 0);
    timestampOk = Number.isFinite(age) && Math.abs(age) <= tolerance;
    isReplayRisk = timestampOk === false;
    if (isReplayRisk) {
      verification.diagnostics.push({
        level: 'error',
        text: `Replay risk: signature timestamp is ${age}s old (tolerance ${tolerance}s). Reject this webhook even though the HMAC may verify.`,
      });
    }
  }

  return {
    ok: true,
    provider: provKey,
    signatureHeaderName: computed.headerName,
    signatureHeaderValue: computed.fullHeader,
    timestamp,
    signedString: computed.signedString,
    weakSecretAudit: weakCheck,
    secretHandlingWarning: SECRET_HANDLING_WARNING,
    verification: verification ? {
      isValid: verification.isValid,
      expectedSignature: verification.expectedSignature,
      receivedSignature: verification.receivedSignature,
      timestamp: verification.timestamp,
      timestampOk,
      isReplayRisk,
      diagnostics: verification.diagnostics
    } : null
  };
}

/**
 * 3. 3-Way .env Matrix Sentinel & Secret Leak Detector
 */
function runEnvMatrix(devEnv, stagingEnv, prodEnv, options = {}) {
  const devStr = typeof devEnv === 'object' ? Object.entries(devEnv).map(([k, v]) => `${k}=${v}`).join('\n') : String(devEnv || '');
  const stagingStr = typeof stagingEnv === 'object' ? Object.entries(stagingEnv).map(([k, v]) => `${k}=${v}`).join('\n') : String(stagingEnv || '');
  const prodStr = typeof prodEnv === 'object' ? Object.entries(prodEnv).map(([k, v]) => `${k}=${v}`).join('\n') : String(prodEnv || '');

  const parsedDev = EnvParser.parse(devStr);
  const parsedStaging = EnvParser.parse(stagingStr);
  const parsedProd = EnvParser.parse(prodStr);

  // Never echo raw secret values back: existence + masked tail only.
  const maskVal = (v) => {
    if (v === null || v === undefined || v === '') return null;
    const s = String(v);
    return s.length <= 4 ? '••••' : `••••${s.slice(-4)}`;
  };

  const matrix = EnvValidator.buildMatrix(parsedDev.map, parsedStaging.map, parsedProd.map);

  return {
    ok: true,
    stats: matrix.stats,
    criticalRisksDetected: matrix.stats.missingInProd + matrix.stats.testKeyInProd + matrix.stats.liveKeyInDev,
    isFullySynced: (matrix.stats.missingInProd + matrix.stats.testKeyInProd + matrix.stats.liveKeyInDev) === 0,
    auditReport: matrix.auditReport,
    matrixRows: matrix.matrixRows.map(r => ({
      key: r.key,
      status: r.status,
      devVal: r.dev.exists ? maskVal(r.dev.value) : null,
      stagingVal: r.staging.exists ? maskVal(r.staging.value) : null,
      prodVal: r.prod.exists ? maskVal(r.prod.value) : null,
      issues: r.issues
    })),
    sanitizedExample: EnvExporters.toExample(parsedProd.entries.length ? parsedProd.entries : parsedDev.entries)
  };
}

/**
 * 4. In-Memory SQL Query Engine for High-Volume Logs
 */
const MAX_DUCK_DATASET_ROWS = 50000;
const MAX_DUCK_TABLES = 9; // `logs` + up to 8 extra tables

function parseDuckTable(raw) {
  const logStr = Array.isArray(raw) ? raw.map(l => typeof l === 'object' ? JSON.stringify(l) : String(l)).join('\n') : String(raw || '');
  const format = LogParser.detectFormat(logStr);
  let rows = LogParser.parseLogs(logStr);
  // Dataset cap: a 1MB log of tiny lines still parses to tens of thousands
  // of rows. Slice (newest assumption: file order) and say so.
  let truncated = false;
  if (rows.length > MAX_DUCK_DATASET_ROWS) {
    rows = rows.slice(0, MAX_DUCK_DATASET_ROWS);
    truncated = true;
  }
  return { rows, truncated, format };
}

// Column inventory so agents discover table shape instead of guessing names.
function inferDuckColumns(rows) {
  const seen = new Map();
  const limit = Math.min(rows.length, 2000);
  for (let i = 0; i < limit; i++) {
    const row = rows[i];
    if (!row || typeof row !== 'object') continue;
    for (const k of Object.keys(row)) {
      if (k === '__q' || seen.has(k)) continue;
      if (seen.size >= 200) break;
      seen.set(k, null);
    }
  }
  const columns = [];
  for (const name of seen.keys()) {
    let type = 'string';
    for (let i = 0; i < limit; i++) {
      const v = rows[i] ? rows[i][name] : undefined;
      if (v === undefined || v === null) continue;
      type = typeof v === 'number' ? 'number' : typeof v === 'boolean' ? 'boolean' : 'string';
      break;
    }
    columns.push({ name, type });
  }
  return columns;
}

function runDuckLog(rawLogs, sqlQuery = "SELECT status, COUNT(*) AS count FROM logs GROUP BY status ORDER BY count DESC", opts = {}) {
  const signal = opts.signal || null;
  const maxRows = Number(opts.maxRows) > 0 ? Number(opts.maxRows) : 1000;
  const extra = (opts.tables && typeof opts.tables === 'object' && !Array.isArray(opts.tables)) ? opts.tables : {};
  const tableSpecs = { logs: rawLogs };
  for (const [name, raw] of Object.entries(extra)) tableSpecs[name] = raw;
  if (Object.keys(tableSpecs).length > MAX_DUCK_TABLES) {
    return { ok: false, error: `Too many tables (max ${MAX_DUCK_TABLES}).`, detectedFormat: 'empty', totalLogsParsed: 0 };
  }

  const datasets = {};
  const schema = {};
  let detectedFormat = 'empty';
  for (const [name, raw] of Object.entries(tableSpecs)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      return { ok: false, error: `Invalid table name "${name}". Use letters, digits, underscores.`, detectedFormat: 'empty', totalLogsParsed: 0 };
    }
    const parsed = parseDuckTable(raw);
    const key = name.toLowerCase();
    datasets[key] = parsed.rows;
    schema[key] = { rows: parsed.rows.length, truncated: parsed.truncated, format: parsed.format, columns: inferDuckColumns(parsed.rows) };
    if (key === 'logs') detectedFormat = parsed.format;
  }
  const dataset = datasets.logs;
  const datasetTruncated = schema.logs.truncated;
  let queryResult;
  try {
    queryResult = SqlEngine.execute(sqlQuery, datasets, { signal, maxRows });
  } catch (err) {
    // Cooperative abort must propagate as a throw (→ HTTP 504), not a
    // 200-shaped {ok:false} result nobody waits for.
    if (err && err.statusCode === 504) throw err;
    return {
      ok: false,
      error: err && err.message ? String(err.message).split('\n')[0].slice(0, 500) : 'SQL execution failed',
      detectedFormat,
      totalLogsParsed: dataset.length
    };
  }

  if (queryResult.error) {
    return {
      ok: false,
      error: queryResult.error,
      detectedFormat,
      totalLogsParsed: dataset.length,
      schema
    };
  }

  // Generate automated post-mortem summary
  const total = dataset.length;
  const errors5xx = dataset.filter(r => Number(r.status) >= 500 || r.level === 'ERROR');
  const errorRate = total > 0 ? ((errors5xx.length / total) * 100).toFixed(2) : '0.00';

  return {
    ok: true,
    detectedFormat,
    totalLogsParsed: total,
    datasetTruncated,
    schema,
    query: sqlQuery,
    executionTimeMs: queryResult.executionTimeMs,
    rowCount: queryResult.rowCount,
    truncated: queryResult.truncated || false,
    maxRows: queryResult.maxRows,
    columns: queryResult.columns,
    rows: queryResult.rows,
    metricsSummary: {
      totalEvents: total,
      errorCount5xx: errors5xx.length,
      errorRatePercent: parseFloat(errorRate)
    }
  };
}

/**
 * 5. Production V3 SourceMap Demapper & Original Symbol Reconstructor
 */
function runSourceMapHero(stackTraceStr, sourceMapData, options = {}) {
  const traceStr = String(stackTraceStr || '');
  const mapJson = typeof sourceMapData === 'string' ? JSON.parse(sourceMapData) : sourceMapData;

  const consumer = new SourceMapParser.SourceMapConsumer(mapJson);
  const frames = SourceMapParser.demapStackTrace(traceStr, consumer);

  const mappedFrames = frames.filter(f => f.isMapped);
  const repoUrl = options.repoUrl ? options.repoUrl.replace(/\/+$/, '') : null;

  const formattedFrames = mappedFrames.map(f => {
    let deepLink = null;
    if (repoUrl && f.mapped && f.mapped.sourceFile) {
      const cleanPath = f.mapped.sourceFile.replace(/^(\.\/|webpack:\/\/[^/]*\/|\/)+/, '');
      deepLink = `${repoUrl}/blob/main/${cleanPath}#L${f.mapped.originalLine}`;
    }

    return {
      sourceFile: f.mapped.sourceFile,
      originalLine: f.mapped.originalLine,
      originalColumn: f.mapped.originalColumn,
      originalSymbol: f.mapped.originalName || f.functionName,
      minifiedLocation: `${f.filename}:${f.genLine}:${f.genCol}`,
      deepLink,
      contextCode: f.mapped.surroundingContext || []
    };
  });

  return {
    ok: true,
    mappedFramesCount: mappedFrames.length,
    totalFramesCount: frames.filter(f => !f.isHeader).length,
    frames: formattedFrames
  };
}

/**
 * 6. Cryptographic JWT Claims Debugger & Weak Secret Cracker
 */
const SECRET_HANDLING_WARNING =
  'Do not send production secrets to hosted gateways. Prefer local-only verification for live keys.';

async function runJwtStudio(jwtString, secretKey, options = {}) {
  const token = String(jwtString || '').trim();
  const parsed = JwtEngine.parseToken(token);

  if (!parsed.ok) {
    return { ok: false, error: parsed.error };
  }

  // alg=none / empty alg: unsigned token — never treat the payload as trusted.
  const alg = parsed.header && typeof parsed.header.alg === 'string' ? parsed.header.alg : '';
  if (alg.toLowerCase() === 'none' || alg === '') {
    return {
      ok: false,
      error: 'Unsigned token rejected (alg=none). A payload without a signature is not verified.',
    };
  }

  const skew = Number(options.clockSkewSeconds) || 0;
  const expInfo = JwtEngine.evaluateExpiration(parsed.payload, skew);

  // Signature check — engine verifies HS256; other algs get an explicit
  // unsupported notice instead of a silent pass.
  let signatureCheck = null;
  let signatureNote = null;
  if (secretKey && alg === 'HS256') {
    signatureCheck = await JwtEngine.verifyHs256Signature(parsed.signedData, parsed.rawSignature, secretKey);
  } else if (secretKey && /^HS(384|512)$/.test(alg)) {
    signatureNote = `Signature verification for "${alg}" is not supported by this engine (HS256 only). Token was decoded, not verified.`;
  } else if (secretKey) {
    signatureNote = `Signature verification for algorithm "${String(alg).slice(0, 16)}" is not supported. Token was decoded, not verified.`;
  }

  // Weak secret dictionary audit
  let weakSecretAudit = null;
  if (options.auditWeakSecrets !== false && parsed.header.alg === 'HS256') {
    weakSecretAudit = await JwtEngine.crackWeakSecret(parsed.signedData, parsed.rawSignature);
  }

  // Remote JWKS verification
  let jwksResult = null;
  if (options.jwksUrl) {
    jwksResult = await JwtEngine.verifyJwksEndpoint(options.jwksUrl, parsed.header);
  }

  return {
    ok: true,
    header: parsed.header,
    payload: parsed.payload,
    algorithm: parsed.header.alg,
    expiration: {
      status: expInfo.status,
      isExpired: expInfo.isExpired,
      message: expInfo.expMessage,
      expDate: expInfo.expDate,
      clockSkewSeconds: skew
    },
    signatureVerification: signatureCheck ? {
      isValid: signatureCheck.isValid,
      expected: signatureCheck.expectedSignature,
      received: signatureCheck.receivedSignature
    } : null,
    signatureNote,
    secretHandlingWarning: secretKey ? SECRET_HANDLING_WARNING : null,
    weakSecretAudit: weakSecretAudit ? {
      isVulnerableToDictionaryAttack: weakSecretAudit.cracked,
      crackedSecret: weakSecretAudit.secret || null
    } : null,
    jwksVerification: jwksResult
  };
}

module.exports = {
  runJsonDiff,
  runWebhookForge,
  runEnvMatrix,
  runDuckLog,
  runSourceMapHero,
  runJwtStudio
};
