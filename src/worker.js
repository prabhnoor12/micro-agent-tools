/**
 * Cloudflare Worker Gateway for MicroAgent Tools & MCP
 * Native V8 Edge runtime with sub-millisecond execution & Static Asset Serving
 *
 * P0 hardening: spoof-resistant IP, security headers + strict CORS,
 * SSRF-guarded auditor, capped bodies, heavy-tool concurrency guard.
 * In-memory limits are per-isolate best-effort — pair with Cloudflare
 * Rate Limiting rules for distributed enforcement (see docs/rate-limiting.md).
 */

import toolsRegistry from './tools/index.js';
import mcpServer from './mcp/server.js';
import limitsModule from './api/limits.js';

export { RateLimitDO } from './rate_limiter_do.js';

const { listTools, executeTool, getTool } = toolsRegistry;
const { handleRpcRequest } = mcpServer;
const limits = limitsModule && limitsModule.default ? limitsModule.default : limitsModule;
import authModule from './api/auth.js';
import metricsModule from './api/metrics.js';

const auth = authModule && authModule.default ? authModule.default : authModule;
const metrics = metricsModule && metricsModule.default ? metricsModule.default : metricsModule;

function workerKeys(env) {
  try {
    return auth.parseApiKeysFromEnv(env);
  } catch (_) {
    return [];
  }
}

function workerHeaders(request) {
  const plain = {};
  try {
    request.headers.forEach((v, k) => {
      plain[k.toLowerCase()] = v;
    });
  } catch (_) {
    // ignore
  }
  return plain;
}

function rateLimitedResponse(request, result, cfg) {
  try {
    metrics.observeRateLimited();
  } catch (_) {
    // ignore — metrics must never break responses
  }
  return sendJson(request, cfg, {
    error: 'Rate limit exceeded',
    message: `Too many requests. Retry in ${result.retryAfterSec}s.`,
    retry_after_sec: result.retryAfterSec,
  }, 429, {
    'Retry-After': String(result.retryAfterSec),
    ...limits.rateLimitHeaders(result),
  });
}

function unauthorizedResponse(request, cfg) {
  return sendJson(request, cfg, {
    error: 'Unauthorized',
    message: 'This gateway requires a valid Bearer API key.'
  }, 401, { 'WWW-Authenticate': 'Bearer' });
}

async function readJsonBody(request, maxBytes) {
  const lengthHeader = request.headers.get('Content-Length');
  if (lengthHeader && Number(lengthHeader) > maxBytes) {
    const err = new Error(`Payload too large (limit ${maxBytes} bytes).`);
    err.statusCode = 413;
    throw err;
  }
  const text = await request.text();
  if (text.length > maxBytes) {
    const err = new Error(`Payload too large (limit ${maxBytes} bytes).`);
    err.statusCode = 413;
    throw err;
  }
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (e) {
    const err = new Error('Invalid JSON payload');
    err.statusCode = 400;
    throw err;
  }
}

const WORKER_BOOT = Date.now();

function getRequestId(request) {
  try {
    const incoming = request.headers.get('X-Request-Id');
    if (typeof incoming === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(incoming)) {
      return incoming;
    }
  } catch (_) {
    // ignore
  }
  try {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
      return globalThis.crypto.randomUUID();
    }
  } catch (_) {
    // ignore
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function baseHeaders(request, cfg, reqId) {
  const plain = {};
  try {
    request.headers.forEach((v, k) => {
      plain[k] = v;
    });
  } catch (_) {
    // ignore
  }
  const headers = {
    ...limits.corsHeaders(plain, cfg),
    'X-Access': 'free-unlimited',
    'X-Cost': '$0.00'
  };
  if (reqId) headers['X-Request-Id'] = reqId;
  return headers;
}

function sendJson(request, cfg, data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...baseHeaders(request, cfg, getRequestId(request)),
      ...extraHeaders
    }
  });
}

function sendText(request, cfg, text, status = 200, extraHeaders = {}) {
  return new Response(text, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...baseHeaders(request, cfg, getRequestId(request)),
      ...extraHeaders
    }
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const cfg = limits.getConfig();
    // Env-overridable CORS allowlist (Workers have no process.env).
    if (env && typeof env.ALLOWED_ORIGINS === 'string' && env.ALLOWED_ORIGINS) {
      cfg.allowedOrigins = env.ALLOWED_ORIGINS.split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean);
    }
    if (env && env.TRUST_PROXY_HEADERS === '1') cfg.trustProxyHeaders = true;
    const clientIp = limits.getWorkerClientIp(request, cfg);

    // 1. CORS Preflight (security headers included; ACAO only for allowlisted origins)
    if (request.method === 'OPTIONS') {
      const plain = {};
      try {
        request.headers.forEach((v, k) => {
          plain[k] = v;
        });
      } catch (_) {
        // ignore
      }
      return new Response(null, {
        status: 204,
        headers: {
          ...limits.corsHeaders(plain, cfg, { allowMethods: true }),
          'X-Access': 'free-unlimited',
          'X-Cost': '$0.00',
          'X-Request-Id': getRequestId(request)
        }
      });
    }

    // Global per-IP guard. Distributed via the RateLimitDO binding when
    // configured (see wrangler.jsonc); otherwise per-isolate memory with
    // Cloudflare Rate Limiting rules as the outer ring.
    const globalCheck = await limits.checkLimitDistributed(env, `global:${clientIp}`, cfg.globalPerMin, cfg.windowMs, cfg);
    if (!globalCheck.allowed) {
      return rateLimitedResponse(request, globalCheck, cfg);
    }

    // Opt-in bearer auth (open mode when unconfigured).
    const apiKeys = workerKeys(env);
    if (apiKeys.length > 0 && auth.routeNeedsAuth(request.method, pathname) && !auth.isAuthorized(workerHeaders(request), apiKeys)) {
      return unauthorizedResponse(request, cfg);
    }

    try {
      // 2. Tool Catalog (GET /v1/tools)
      if (pathname === '/v1/tools' && request.method === 'GET') {
        return sendJson(request, cfg, {
          protocol: 'micro-agent-tools-v2',
          runtime: 'Cloudflare Workers (Edge V8)',
          total_tools: listTools().length,
          pricing_model: '100% Free Forever for AI Agents & Developers',
          tools: listTools()
        });
      }

      // 3. MCP JSON-RPC Gateway (POST /v1/mcp)
      if (pathname === '/v1/mcp' && request.method === 'POST') {
        const mcpCheck = await limits.checkLimitDistributed(env, `mcp:${clientIp}`, cfg.mcpPerMin, cfg.windowMs, cfg);
        if (!mcpCheck.allowed) {
          return rateLimitedResponse(request, mcpCheck, cfg);
        }
        let rpcBody;
        try {
          rpcBody = await readJsonBody(request, cfg.maxBodyBytes);
        } catch (e) {
          if (e.statusCode === 413) {
            return sendJson(request, cfg, { error: 'Usage limit exceeded', message: e.message }, 413);
          }
          return sendJson(request, cfg, { jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null }, 400);
        }
        const rpcTool = rpcBody && rpcBody.method === 'tools/call' && rpcBody.params ? rpcBody.params.name : null;
        if (rpcTool && getTool(rpcTool)) {
          const tierLimit = limits.limitForTier(rpcTool, cfg);
          const toolCheck = await limits.checkLimitDistributed(env, `tool:${clientIp}:${rpcTool}`, tierLimit, cfg.windowMs, cfg);
          if (!toolCheck.allowed) {
            return rateLimitedResponse(request, toolCheck, cfg);
          }
          try {
            limits.enforceToolUsage(rpcTool, rpcBody.params.arguments || {});
          } catch (usageErr) {
            return sendJson(request, cfg, { error: 'Usage limit exceeded', message: usageErr.message }, usageErr.statusCode || 413);
          }
        }
        const rpcResponse = await limits.withTimeout(handleRpcRequest(rpcBody), cfg.toolTimeoutMs, 'mcp');
        return sendJson(request, cfg, rpcResponse || {}, 200, limits.rateLimitHeaders(mcpCheck));
      }

      // 4. Direct Tool Execution (POST /v1/tools/:toolName)
      const matchTool = pathname.match(/^\/v1\/tools\/([a-zA-Z0-9_\-]+)$/);
      if (matchTool && request.method === 'POST') {
        const toolName = matchTool[1];
        const tool = getTool(toolName);

        if (!tool) {
          return sendJson(request, cfg, {
            error: 'Tool not found',
            requested: String(toolName).slice(0, 64),
            available_tools: listTools().map(t => t.name)
          }, 404);
        }

        const tierLimit = limits.limitForTier(toolName, cfg);
        const toolCheck = await limits.checkLimitDistributed(env, `tool:${clientIp}:${toolName}`, tierLimit, cfg.windowMs, cfg);
        if (!toolCheck.allowed) {
          return rateLimitedResponse(request, toolCheck, cfg);
        }

        const isPdf = toolName === 'pdf_processor';
        let body = {};
        try {
          body = await readJsonBody(request, isPdf ? cfg.maxPdfBodyBytes : cfg.maxBodyBytes);
        } catch (bodyErr) {
          const status = bodyErr.statusCode || 400;
          const title = status === 413 ? 'Usage limit exceeded' : 'Bad request';
          return sendJson(request, cfg, { error: title, message: bodyErr.message }, status);
        }
        try {
          limits.enforceToolUsage(toolName, body);
        } catch (usageErr) {
          return sendJson(request, cfg, {
            error: 'Usage limit exceeded',
            tool: toolName,
            message: usageErr.message,
          }, usageErr.statusCode || 413, limits.rateLimitHeaders(toolCheck));
        }

        const tier = limits.getToolTier(toolName);
        const timeoutMs = tier === 'heavy' ? cfg.heavyTimeoutMs : cfg.toolTimeoutMs;
        let acquiredHeavy = false;
        if (tier === 'heavy') {
          if (!limits.tryAcquireHeavy(cfg)) {
            try {
              metrics.observeTool(toolName, 'busy');
            } catch (_) {
              // ignore
            }
            return sendJson(request, cfg, {
              error: 'Server busy',
              message: `Too many concurrent "${toolName}" executions. Retry shortly.`,
            }, 429, { 'Retry-After': '5', ...limits.rateLimitHeaders(toolCheck) });
          }
          acquiredHeavy = true;
        }
        try {
          const result = await limits.withToolTimeout(timeoutMs, toolName, (signal) =>
            executeTool(toolName, body, { signal })
          );
          try {
            metrics.observeTool(toolName, 'ok');
          } catch (_) {
            // ignore
          }
          return sendJson(request, cfg, {
            success: true,
            tool: toolName,
            result,
            access: 'free_unlimited',
            cost_usd: 0.00
          }, 200, {
            'X-Access': 'free-unlimited',
            'X-Cost': '$0.00',
            ...limits.rateLimitHeaders(toolCheck),
          });
        } finally {
          if (acquiredHeavy) limits.releaseHeavy();
        }
      }

      // 5. Gateway Status & Health (GET /status)
      if (pathname === '/status') {
        return sendJson(request, cfg, {
          status: 'online',
          server: 'Micro-Agent Edge Gateway',
          runtime: 'Cloudflare Workers (Edge V8)',
          uptime_s: Math.floor((Date.now() - WORKER_BOOT) / 1000),
          heavy_in_flight: limits.heavyInFlightCount(),
          discovery: {
            landing_page: '/',
            sitemap: '/llms.txt',
            full_documentation: '/llms-full.txt',
            tools_catalog: '/v1/tools',
            mcp_endpoint: '/v1/mcp'
          },
          tools_available: listTools().map(t => ({ name: t.name, free: true }))
        });
      }

      // 6. Prometheus-style metrics (auth-gated when API keys are set)
      if (pathname === '/metrics' && request.method === 'GET') {
        return sendText(request, cfg, metrics.render(), 200, { 'Content-Type': 'text/plain; version=0.0.4' });
      }

      // 7. Static Asset Fallback (Cloudflare Workers Static Assets binding)
      if (env && env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      // 404 Route Not Found
      return sendJson(request, cfg, { error: 'Route not found', path: String(pathname).slice(0, 256) }, 404);

    } catch (err) {
      let status = err && (err.statusCode === 413 || err.statusCode === 400 || err.statusCode === 504)
        ? err.statusCode
        : 500;
      const isToolRoute = pathname.startsWith('/v1/tools/') || pathname === '/v1/mcp';
      if (status === 500 && isToolRoute && err && err.message) {
        status = 400;
      }
      if (status !== 500) {
        const title = status === 413 ? 'Usage limit exceeded' : status === 504 ? 'Tool timeout' : 'Bad request';
        return sendJson(request, cfg, { error: title, message: limits.safeToolMessage(err, title) }, status);
      }
      return sendJson(request, cfg, {
        error: 'Edge Execution Error',
        message: 'Internal Server Error'
      }, 500);
    }
  }
};
