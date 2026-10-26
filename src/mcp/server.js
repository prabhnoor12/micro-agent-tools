#!/usr/bin/env node
/**
 * Model Context Protocol (MCP) Server
 * Compatible with Claude Desktop, Cursor, OpenAI Agents, LangChain & CrewAI
 * Exposes all 8 deterministic agent tools via standard MCP JSON-RPC 2.0 (stdio & SSE)
 */

const readline = require('readline');
const { listTools, executeTool, getTool } = require('../tools/index');

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_INFO = {
  name: 'micro-agent-tools',
  version: '2.0.0'
};

/**
 * Handle individual JSON-RPC requests
 */
async function handleRpcRequest(request) {
  const { id, method, params } = request;

  // 1. Initialize Handshake
  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        serverInfo: SERVER_INFO,
        instructions: 'MicroAgent Tools: 100% Free & Open headless utilities for spreadsheet diffing, PII sanitization, contract risk analysis, and developer workflows.'
      }
    };
  }

  // 2. Initialized Notification
  if (method === 'notifications/initialized') {
    return null; // No response needed for notifications
  }

  // 3. Ping
  if (method === 'ping') {
    return { jsonrpc: '2.0', id, result: {} };
  }

  // 4. Tools List
  if (method === 'tools/list') {
    const rawTools = listTools();
    const mcpTools = rawTools.map(t => ({
      name: t.name,
      description: `[Free] ${t.description}`,
      inputSchema: t.parameters
    }));

    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: mcpTools
      }
    };
  }

  // 5. Tools Call
  if (method === 'tools/call') {
    const { name, arguments: toolArgs } = params || {};
    const tool = getTool(name);

    if (!tool) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32601,
          message: `Unknown tool: "${name}"`
        }
      };
    }

    try {
      const output = await executeTool(name, toolArgs || {});
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2)
            }
          ]
        }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Error executing tool "${name}": ${err.message}`
            }
          ]
        }
      };
    }
  }

  // Unknown method
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: `Method not found: "${method}"`
    }
  };
}

/**
 * Start stdio transport (Used by Claude Desktop & Cursor)
 */
function startStdio() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on('line', async line => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const request = JSON.parse(trimmed);
      const response = await handleRpcRequest(request);
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    } catch (err) {
      const errorResp = {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error: ' + err.message }
      };
      process.stdout.write(JSON.stringify(errorResp) + '\n');
    }
  });

  process.stderr.write(`[MCP] Micro-Agent Tools Server running on stdio (PID: ${process.pid})\n`);
}

// Run stdio if directly invoked
if (require.main === module) {
  startStdio();
}

module.exports = {
  handleRpcRequest,
  startStdio
};
