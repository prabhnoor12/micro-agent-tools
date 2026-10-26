/**
 * Edge API Server — 100% Free & Open Access
 * Deterministic headless tool execution & MCP JSON-RPC Gateway for AI Agents
 * Compatible with Node.js, Cloudflare Workers & Docker
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { listTools, executeTool, getTool } = require('../tools/index');
const { handleRpcRequest } = require('../mcp/server');

const PORT = process.env.PORT || 3000;

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 10 * 1024 * 1024) { // 10MB limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (err) {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Agent-ID',
    'X-Access': 'free-unlimited',
    'X-Cost': '$0.00',
    ...headers
  });
  res.end(JSON.stringify(data, null, 2));
}

function sendText(res, statusCode, text, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'X-Access': 'free-unlimited',
    'X-Cost': '$0.00',
    ...headers
  });
  res.end(text);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Agent-ID'
    });
    res.end();
    return;
  }

  try {
    // 1. llms.txt (Agent Sitemap)
    if (pathname === '/llms.txt' && req.method === 'GET') {
      const llmsPath = path.join(__dirname, '../../llms.txt');
      if (fs.existsSync(llmsPath)) {
        return sendText(res, 200, fs.readFileSync(llmsPath, 'utf8'));
      }
      return sendText(res, 404, 'llms.txt not found');
    }

    // 2. llms-full.txt (Full documentation)
    if (pathname === '/llms-full.txt' && req.method === 'GET') {
      const llmsFullPath = path.join(__dirname, '../../llms-full.txt');
      if (fs.existsSync(llmsFullPath)) {
        return sendText(res, 200, fs.readFileSync(llmsFullPath, 'utf8'));
      }
      return sendText(res, 404, 'llms-full.txt not found');
    }

    // 3. Tool Catalog (GET /v1/tools)
    if (pathname === '/v1/tools' && req.method === 'GET') {
      return sendJson(res, 200, {
        protocol: 'micro-agent-tools-v2',
        total_tools: listTools().length,
        pricing: '100% Free Forever (Zero paywalls, zero rate limits)',
        tools: listTools()
      });
    }

    // 4. HTTP MCP JSON-RPC Gateway (POST /v1/mcp)
    if (pathname === '/v1/mcp' && req.method === 'POST') {
      const rpcBody = await parseBody(req);
      const rpcResponse = await handleRpcRequest(rpcBody);
      return sendJson(res, 200, rpcResponse || {});
    }

    // 5. Direct Tool Execution (POST /v1/tools/:toolName)
    const matchTool = pathname.match(/^\/v1\/tools\/([a-zA-Z0-9_\-]+)$/);
    if (matchTool && req.method === 'POST') {
      const toolName = matchTool[1];
      const tool = getTool(toolName);

      if (!tool) {
        return sendJson(res, 404, {
          error: 'Tool not found',
          requested: toolName,
          available_tools: listTools().map(t => t.name)
        });
      }

      const body = await parseBody(req);
      const result = await executeTool(toolName, body);

      return sendJson(res, 200, {
        success: true,
        tool: toolName,
        result,
        access: 'free_unlimited',
        cost_usd: 0.00
      });
    }

    // 6. Root Gateway Status & Health
    if (pathname === '/' || pathname === '/status') {
      return sendJson(res, 200, {
        status: 'online',
        server: 'MicroAgent Edge Gateway',
        description: '100% Free, deterministic headless tool microservices for autonomous AI agents & developers.',
        pricing: '100% Free Forever',
        mcp_endpoint: '/v1/mcp',
        tools_catalog: '/v1/tools',
        discovery: {
          sitemap: '/llms.txt',
          full_documentation: '/llms-full.txt'
        },
        tools_available: listTools().map(t => ({ name: t.name, cost: 'Free ($0.00)' }))
      });
    }

    // 404 Not Found
    return sendJson(res, 404, { error: 'Route not found', path: pathname });

  } catch (err) {
    return sendJson(res, 500, {
      error: 'Internal Server Error',
      message: err.message
    });
  }
});

function startServer(port = PORT) {
  server.listen(port, () => {
    console.log(`⚡ MicroAgent Edge API (100% Free) listening on http://localhost:${port}`);
    console.log(`📖 Agent Discovery: http://localhost:${port}/llms.txt`);
    console.log(`🛠️ Tool Catalog:    http://localhost:${port}/v1/tools`);
    console.log(`🔌 MCP JSON-RPC:    http://localhost:${port}/v1/mcp`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = {
  server,
  startServer
};
