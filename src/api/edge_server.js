/**
 * Edge API Server — 100% Free & Open Access
 * Deterministic headless tool execution & MCP JSON-RPC Gateway for AI Agents
 * Compatible with Node.js, Cloudflare Workers & Docker
 *
 * P0 hardening: spoof-resistant client IP, security headers + strict CORS,
 * SSRF-guarded auditor, capped bodies, tiered limits with Retry-After.
 * In-memory limits are per-process defense-in-depth — pair with Cloudflare
 * Rate Limiting rules for distributed enforcement (see docs/rate-limiting.md).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { listTools, executeTool, getTool } = require('../tools/index');
const { handleRpcRequest } = require('../mcp/server');
const limits = require('./limits');
const auth = require('./auth');
const metrics = require('./metrics');
const heavyRunner = require('./heavy_runner');

const PORT = process.env.PORT || 3000;
const BOOT_TIME = Date.now();

let requestCounter = 0;
let inFlightRequests = 0;

function getRequestId(req) {
  const incoming = req.headers && req.headers['x-request-id'];
  if (typeof incoming === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(incoming)) {
    return incoming;
  }
  requestCounter += 1;
  const rand = Math.random().toString(36).slice(2, 8);
  return `${Date.now().toString(36)}-${requestCounter.toString(36)}-${rand}`;
}

function logLine(level, fields) {
  const order = { debug: 10, info: 20, warn: 30, error: 40 };
  const configured = String(process.env.LOG_LEVEL || 'warn').toLowerCase();
  const threshold = order[configured] === undefined ? 30 : order[configured];
  if ((order[level] || 30) < threshold) return;
  try {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), level, ...fields })}\n`);
  } catch (_) {
    // ignore — logging must never break responses
  }
}

function parseBody(req, maxBytes) {
  const cfg = limits.getConfig();
  const cap = maxBytes || cfg.maxBodyBytes;
  return new Promise((resolve, reject) => {
    let bytes = 0;
    const chunks = [];
    let rejected = false;
    req.on('data', chunk => {
      if (rejected) return;
      bytes += chunk.length;
      if (bytes > cap) {
        rejected = true;
        const err = new Error(`Payload too large (limit ${cap} bytes).`);
        err.statusCode = 413;
        try { req.destroy(); } catch (_) { /* ignore */ }
        reject(err);
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (rejected) return;
      try {
        const data = Buffer.concat(chunks).toString('utf8');
        resolve(data ? JSON.parse(data) : {});
      } catch (err) {
        const e = new Error('Invalid JSON payload');
        e.statusCode = 400;
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function sendRateLimited(req, res, result, info = {}) {
  logLine('warn', { event: 'rate_limited', reqId: info.reqId || null, path: info.path || null });
  metrics.observeRateLimited();
  return sendJson(req, res, 429, {
    error: 'Rate limit exceeded',
    message: `Too many requests. Retry in ${result.retryAfterSec}s.`,
    retry_after_sec: result.retryAfterSec,
  }, {
    'Retry-After': String(result.retryAfterSec),
    ...limits.rateLimitHeaders(result),
  });
}

function sendJson(req, res, statusCode, data, headers = {}) {
  const cfg = limits.getConfig();
  const extra = { ...headers };
  if (req && req.requestId && !extra['X-Request-Id']) extra['X-Request-Id'] = req.requestId;
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    ...limits.corsHeaders(req ? req.headers : {}, cfg),
    'X-Access': 'free-unlimited',
    'X-Cost': '$0.00',
    ...extra
  });
  res.end(JSON.stringify(data, null, 2));
}

function sendText(req, res, statusCode, text, headers = {}) {
  const cfg = limits.getConfig();
  const extra = { ...headers };
  if (req && req.requestId && !extra['X-Request-Id']) extra['X-Request-Id'] = req.requestId;
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
    ...limits.corsHeaders(req ? req.headers : {}, cfg),
    'X-Access': 'free-unlimited',
    'X-Cost': '$0.00',
    ...extra
  });
  res.end(text);
}

const server = http.createServer(async (req, res) => {
  req.requestId = getRequestId(req);
  inFlightRequests += 1;
  const startedAt = Date.now();
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const cfg = limits.getConfig();
  const clientIp = limits.getNodeClientIp(req, cfg);

  // Handle CORS Preflight (still emits security headers; ACAO only for allowlisted origins)
  if (req.method === 'OPTIONS') {
    const preflight = limits.corsHeaders(req.headers, cfg, { allowMethods: true });
    preflight['X-Request-Id'] = req.requestId;
    res.writeHead(204, preflight);
    res.end();
    metrics.observeRequest(req.method, pathname, 204, Date.now() - startedAt);
    inFlightRequests -= 1;
    return;
  }

  // Global per-IP sliding-window guard (all routes).
  const globalCheck = limits.checkLimit(`global:${clientIp}`, cfg.globalPerMin, cfg.windowMs, cfg);
  if (!globalCheck.allowed) {
    try {
      return sendRateLimited(req, res, globalCheck, { reqId: req.requestId, path: pathname });
    } finally {
      metrics.observeRequest(req.method, pathname, 429, Date.now() - startedAt);
      inFlightRequests -= 1;
    }
  }

  // Opt-in bearer auth for hosted deploys (open mode when unconfigured).
  const apiKeys = auth.parseApiKeys();
  if (apiKeys.length > 0 && auth.routeNeedsAuth(req.method, pathname) && !auth.isAuthorized(req.headers, apiKeys)) {
    metrics.observeRequest(req.method, pathname, 401, Date.now() - startedAt);
    inFlightRequests -= 1;
    return sendJson(req, res, 401, {
      error: 'Unauthorized',
      message: 'This gateway requires a valid Bearer API key.'
    }, { 'WWW-Authenticate': 'Bearer' });
  }

  let metricTool = null;

  try {
    // 1. llms.txt (Agent Sitemap)
    if (pathname === '/llms.txt' && req.method === 'GET') {
      const llmsPath = path.join(__dirname, '../../llms.txt');
      if (fs.existsSync(llmsPath)) {
        return sendText(req, res, 200, fs.readFileSync(llmsPath, 'utf8'));
      }
      return sendText(req, res, 404, 'llms.txt not found');
    }

    // 2. llms-full.txt (Full documentation)
    if (pathname === '/llms-full.txt' && req.method === 'GET') {
      const llmsFullPath = path.join(__dirname, '../../llms-full.txt');
      if (fs.existsSync(llmsFullPath)) {
        return sendText(req, res, 200, fs.readFileSync(llmsFullPath, 'utf8'));
      }
      return sendText(req, res, 404, 'llms-full.txt not found');
    }

    // 3. Tool Catalog (GET /v1/tools)
    if (pathname === '/v1/tools' && req.method === 'GET') {
      return sendJson(req, res, 200, {
        protocol: 'micro-agent-tools-v2',
        total_tools: listTools().length,
        pricing: '100% Free Forever (Zero paywalls, zero rate limits)',
        tools: listTools()
      });
    }

    // 4. HTTP MCP JSON-RPC Gateway (POST /v1/mcp)
    if (pathname === '/v1/mcp' && req.method === 'POST') {
      const mcpCheck = limits.checkLimit(`mcp:${clientIp}`, cfg.mcpPerMin, cfg.windowMs, cfg);
      if (!mcpCheck.allowed) {
        return sendRateLimited(req, res, mcpCheck);
      }
      const rpcBody = await parseBody(req);
      // If the RPC call targets a heavy tool, apply that tool's bucket too.
      const rpcTool = rpcBody && rpcBody.method === 'tools/call' && rpcBody.params ? rpcBody.params.name : null;
      if (rpcTool && getTool(rpcTool)) {
        const tierLimit = limits.limitForTier(rpcTool, cfg);
        const toolCheck = limits.checkLimit(`tool:${clientIp}:${rpcTool}`, tierLimit, cfg.windowMs, cfg);
        if (!toolCheck.allowed) {
          return sendRateLimited(req, res, toolCheck);
        }
        try {
          limits.enforceToolUsage(rpcTool, rpcBody.params.arguments || {});
        } catch (usageErr) {
          return sendJson(req, res, usageErr.statusCode || 413, { error: 'Usage limit exceeded', message: usageErr.message });
        }
      }
      const rpcResponse = await limits.withTimeout(handleRpcRequest(rpcBody), cfg.toolTimeoutMs, 'mcp');
      if (rpcTool && getTool(rpcTool)) metricTool = rpcTool;
      return sendJson(req, res, 200, rpcResponse || {}, limits.rateLimitHeaders(mcpCheck));
    }

    // 5. Direct Tool Execution (POST /v1/tools/:toolName)
    const matchTool = pathname.match(/^\/v1\/tools\/([a-zA-Z0-9_\-]+)$/);
    if (matchTool && req.method === 'POST') {
      const toolName = matchTool[1];
      const tool = getTool(toolName);

      if (!tool) {
        return sendJson(req, res, 404, {
          error: 'Tool not found',
          requested: String(toolName).slice(0, 64),
          available_tools: listTools().map(t => t.name)
        });
      }

      const tierLimit = limits.limitForTier(toolName, cfg);
      const toolCheck = limits.checkLimit(`tool:${clientIp}:${toolName}`, tierLimit, cfg.windowMs, cfg);
      if (!toolCheck.allowed) {
        metrics.observeTool(toolName, 'limited');
        return sendRateLimited(req, res, toolCheck, { reqId: req.requestId, path: pathname });
      }
      metricTool = toolName;

      const isPdf = toolName === 'pdf_processor';
      const body = await parseBody(req, isPdf ? cfg.maxPdfBodyBytes : cfg.maxBodyBytes);
      try {
        limits.enforceToolUsage(toolName, body);
      } catch (usageErr) {
        return sendJson(req, res, usageErr.statusCode || 413, {
          error: 'Usage limit exceeded',
          tool: toolName,
          message: usageErr.message,
        }, limits.rateLimitHeaders(toolCheck));
      }

      const tier = limits.getToolTier(toolName);
      const timeoutMs = tier === 'heavy' ? cfg.heavyTimeoutMs : cfg.toolTimeoutMs;
      let acquiredHeavy = false;
      if (tier === 'heavy') {
        if (!limits.tryAcquireHeavy(cfg)) {
          metrics.observeTool(toolName, 'busy');
          return sendJson(req, res, 429, {
            error: 'Server busy',
            message: `Too many concurrent "${toolName}" executions. Retry shortly.`,
          }, { 'Retry-After': '5', ...limits.rateLimitHeaders(toolCheck) });
        }
        acquiredHeavy = true;
      }
      try {
        // Heavy tier runs in a worker thread with its own heap cap; the
        // thread is terminated on deadline (fail-closed). Light tiers run
        // in-process with cooperative abort.
        const result = tier === 'heavy'
          ? await heavyRunner.runHeavy(toolName, body, { timeoutMs })
          : await limits.withToolTimeout(timeoutMs, toolName, (signal) =>
            executeTool(toolName, body, { signal })
          );
        metrics.observeTool(toolName, 'ok');
        logLine('debug', { event: 'tool_executed', reqId: req.requestId, tool: toolName, ms: Date.now() - startedAt });
        return sendJson(req, res, 200, {
          success: true,
          tool: toolName,
          result,
          access: 'free_unlimited',
          cost_usd: 0.00
        }, limits.rateLimitHeaders(toolCheck));
      } finally {
        if (acquiredHeavy) limits.releaseHeavy();
      }
    }

    // 6. Root Gateway Status & Health
    if (pathname === '/' || pathname === '/status') {
      return sendJson(req, res, 200, {
        status: 'online',
        server: 'MicroAgent Edge Gateway',
        description: '100% Free, deterministic headless tool microservices for autonomous AI agents & developers.',
        pricing: '100% Free Forever',
        uptime_s: Math.floor((Date.now() - BOOT_TIME) / 1000),
        in_flight_requests: inFlightRequests,
        heavy_in_flight: limits.heavyInFlightCount(),
        mcp_endpoint: '/v1/mcp',
        tools_catalog: '/v1/tools',
        discovery: {
          sitemap: '/llms.txt',
          full_documentation: '/llms-full.txt'
        },
        tools_available: listTools().map(t => ({ name: t.name, cost: 'Free ($0.00)' }))
      });
    }

    // 7. Prometheus-style metrics (auth-gated when API_KEYS is set)
    if (pathname === '/metrics' && req.method === 'GET') {
      return sendText(req, res, 200, metrics.render(), { 'Content-Type': 'text/plain; version=0.0.4' });
    }

    // 404 Not Found (echo capped to avoid giant-path reflection)
    return sendJson(req, res, 404, { error: 'Route not found', path: String(pathname).slice(0, 256) });

  } catch (err) {
    let status = err && (err.statusCode === 413 || err.statusCode === 400 || err.statusCode === 504)
      ? err.statusCode
      : 500;
    // Tool validation errors carry no statusCode — surface them as 400 with
    // the tool's message (safe, no internals). Only truly unexpected errors
    // become generic 500s.
    const isToolRoute = pathname.startsWith('/v1/tools/') || pathname === '/v1/mcp';
    if (status === 500 && isToolRoute && err && err.message) {
      status = 400;
    }
    const title = status === 413 ? 'Usage limit exceeded'
      : status === 400 ? 'Bad request'
      : status === 504 ? 'Tool timeout'
      : 'Internal Server Error';
    const headers = status === 504 ? { 'Retry-After': '5' } : {};
    if (status === 500) {
      logLine('error', { event: 'internal_error', reqId: req.requestId, path: String(pathname).slice(0, 256) });
    } else if (status === 504) {
      logLine('warn', { event: 'tool_timeout', reqId: req.requestId, path: String(pathname).slice(0, 256) });
    }
    if (metricTool) metrics.observeTool(metricTool, status === 504 ? 'timeout' : 'error');
    return sendJson(req, res, status, {
      error: title,
      message: status === 500 ? 'Internal Server Error' : limits.safeToolMessage(err, title)
    }, headers);
  } finally {
    metrics.observeRequest(req.method, pathname, res.statusCode || 500, Date.now() - startedAt);
    inFlightRequests -= 1;
  }
});

function startServer(port = PORT) {
  // Slow-client defenses: kill headers/body drips before they accumulate.
  // requestTimeout comfortably exceeds the heaviest tool deadline.
  const cfg = limits.getConfig();
  server.requestTimeout = Math.max(cfg.heavyTimeoutMs, cfg.toolTimeoutMs) + 15000;
  server.headersTimeout = 15000;
  server.keepAliveTimeout = 5000;

  const keys = auth.parseApiKeys();
  if (keys.length === 0) {
    logLine('warn', { event: 'open_mode', message: 'No API_KEYS configured — POST routes are public. Bind to localhost or set API_KEYS on hostile networks.' });
    console.log('⚠️  Open mode: no API_KEYS set. POST /v1/* is public. Set API_KEYS or bind to localhost on hostile networks.');
  } else {
    console.log(`🔑 Keyed mode: ${keys.length} API key(s) guard POST /v1/* and /metrics.`);
  }

  server.listen(port, () => {
    console.log(`⚡ MicroAgent Edge API (100% Free) listening on http://localhost:${port}`);
    console.log(`📖 Agent Discovery: http://localhost:${port}/llms.txt`);
    console.log(`🛠️ Tool Catalog:    http://localhost:${port}/v1/tools`);
    console.log(`🔌 MCP JSON-RPC:    http://localhost:${port}/v1/mcp`);
  });

  // Graceful shutdown: stop accepting, drain in-flight, then exit.
  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logLine('warn', { event: 'shutdown', signal, inFlightRequests });
    console.log(`\n${signal} received — draining ${inFlightRequests} in-flight request(s)...`);
    server.close(() => process.exit(0));
    setTimeout(() => {
      logLine('error', { event: 'shutdown_forced', inFlightRequests });
      process.exit(1);
    }, 10000).unref();
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  server,
  startServer
};
