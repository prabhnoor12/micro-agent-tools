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

  return {
    ok: true,
    provider: provKey,
    signatureHeaderName: computed.headerName,
    signatureHeaderValue: computed.fullHeader,
    timestamp,
    signedString: computed.signedString,
    weakSecretAudit: weakCheck,
    verification: verification ? {
      isValid: verification.isValid,
      expectedSignature: verification.expectedSignature,
      receivedSignature: verification.receivedSignature,
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
      devVal: r.dev.exists ? r.dev.value : null,
      stagingVal: r.staging.exists ? r.staging.value : null,
      prodVal: r.prod.exists ? r.prod.value : null,
      issues: r.issues
    })),
    sanitizedExample: EnvExporters.toExample(parsedProd.entries.length ? parsedProd.entries : parsedDev.entries)
  };
}

/**
 * 4. In-Memory SQL Query Engine for High-Volume Logs
 */
function runDuckLog(rawLogs, sqlQuery = "SELECT status, COUNT(*) AS count FROM logs GROUP BY status ORDER BY count DESC") {
  const logStr = Array.isArray(rawLogs) ? rawLogs.map(l => typeof l === 'object' ? JSON.stringify(l) : String(l)).join('\n') : String(rawLogs || '');

  const detectedFormat = LogParser.detectFormat(logStr);
  const dataset = LogParser.parseLogs(logStr);
  const queryResult = SqlEngine.execute(sqlQuery, dataset);

  if (queryResult.error) {
    return {
      ok: false,
      error: queryResult.error,
      detectedFormat,
      totalLogsParsed: dataset.length
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
    query: sqlQuery,
    executionTimeMs: queryResult.executionTimeMs,
    rowCount: queryResult.rowCount,
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
async function runJwtStudio(jwtString, secretKey, options = {}) {
  const token = String(jwtString || '').trim();
  const parsed = JwtEngine.parseToken(token);

  if (!parsed.ok) {
    return { ok: false, error: parsed.error };
  }

  const skew = Number(options.clockSkewSeconds) || 0;
  const expInfo = JwtEngine.evaluateExpiration(parsed.payload, skew);

  // Signature check
  let signatureCheck = null;
  if (secretKey && parsed.header.alg === 'HS256') {
    signatureCheck = await JwtEngine.verifyHs256Signature(parsed.signedData, parsed.rawSignature, secretKey);
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
