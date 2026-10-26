/**
 * Cloudflare Worker Gateway for MicroAgent Tools & MCP
 * Native V8 Edge runtime with sub-millisecond execution & Static Asset Serving
 */

import toolsRegistry from './tools/index.js';
import mcpServer from './mcp/server.js';

const { listTools, executeTool, getTool } = toolsRegistry;
const { handleRpcRequest } = mcpServer;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Agent-ID',
  'X-Access': 'free-unlimited',
  'X-Cost': '$0.00'
};

function sendJson(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
      ...extraHeaders
    }
  });
}

function sendText(text, status = 200, extraHeaders = {}) {
  return new Response(text, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...CORS_HEADERS,
      ...extraHeaders
    }
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 1. CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      // 2. Tool Catalog (GET /v1/tools)
      if (pathname === '/v1/tools' && request.method === 'GET') {
        return sendJson({
          protocol: 'micro-agent-tools-v2',
          runtime: 'Cloudflare Workers (Edge V8)',
          total_tools: listTools().length,
          pricing_model: '100% Free Forever for AI Agents & Developers',
          tools: listTools()
        });
      }

      // 3. MCP JSON-RPC Gateway (POST /v1/mcp)
      if (pathname === '/v1/mcp' && request.method === 'POST') {
        let rpcBody;
        try {
          rpcBody = await request.json();
        } catch (e) {
          return sendJson({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null }, 400);
        }
        const rpcResponse = await handleRpcRequest(rpcBody);
        return sendJson(rpcResponse || {});
      }

      // 4. Direct Tool Execution (POST /v1/tools/:toolName)
      const matchTool = pathname.match(/^\/v1\/tools\/([a-zA-Z0-9_\-]+)$/);
      if (matchTool && request.method === 'POST') {
        const toolName = matchTool[1];
        const tool = getTool(toolName);

        if (!tool) {
          return sendJson({
            error: 'Tool not found',
            requested: toolName,
            available_tools: listTools().map(t => t.name)
          }, 404);
        }

        let body = {};
        try {
          body = await request.json();
        } catch (err) {
          // Empty or invalid body defaults to empty object
        }

        const result = await executeTool(toolName, body);

        return sendJson({
          success: true,
          tool: toolName,
          result,
          access: 'free_unlimited',
          cost_usd: 0.00
        }, 200, {
          'X-Access': 'free-unlimited',
          'X-Cost': '$0.00'
        });
      }

      // 5. Gateway Status & Health (GET /status)
      if (pathname === '/status') {
        return sendJson({
          status: 'online',
          server: 'Micro-Agent Edge Gateway',
          runtime: 'Cloudflare Workers (Edge V8)',
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

      // 6. Static Asset Fallback (Cloudflare Workers Static Assets binding)
      if (env && env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      // 404 Route Not Found
      return sendJson({ error: 'Route not found', path: pathname }, 404);

    } catch (err) {
      return sendJson({
        error: 'Edge Execution Error',
        message: err.message
      }, 500);
    }
  }
};
