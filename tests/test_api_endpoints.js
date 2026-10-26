/**
 * Edge API Endpoint Test
 */

const { server } = require('../src/api/edge_server');
const http = require('http');

async function testApi() {
  server.listen(4199, async () => {
    console.log('🚀 Test server running on port 4199...');

    const request = (path, method = 'GET', body = null, headers = {}) => {
      return new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: 4199,
          path,
          method,
          headers: {
            'Content-Type': 'application/json',
            ...headers
          }
        }, res => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
        req.end();
      });
    };

    try {
      // 1. Check /llms.txt
      const r1 = await request('/llms.txt');
      const hasTitle = r1.body.includes('MicroAgent Tools');
      console.log('GET /llms.txt -> status:', r1.status, 'contains title:', hasTitle);
      if (!hasTitle) {
        throw new Error('llms.txt did not contain "MicroAgent Tools"');
      }

      // 2. Check /v1/tools
      const r2 = await request('/v1/tools');
      const toolsJson = JSON.parse(r2.body);
      console.log('GET /v1/tools -> status:', r2.status, 'total_tools:', toolsJson.total_tools);
      if (toolsJson.total_tools !== 16) {
        throw new Error(`Expected 16 registered tools, got ${toolsJson.total_tools}`);
      }

      // 3. Execute tool via POST /v1/tools/sheet_diff
      const r3 = await request('/v1/tools/sheet_diff', 'POST', {
        baseline_csv: 'id,price\n1,10\n2,20',
        updated_csv: 'id,price\n1,15\n3,30',
        primary_key: 'id'
      }, { 'Authorization': 'Bearer sk_agent_demo' });

      console.log('POST /v1/tools/sheet_diff -> status:', r3.status);
      console.log('Headers access:', r3.headers['x-access'], 'cost:', r3.headers['x-cost']);
      const resJson = JSON.parse(r3.body);
      if (r3.headers['x-access'] !== 'free-unlimited' || r3.headers['x-cost'] !== '$0.00') {
        throw new Error(`Unexpected payment headers: ${JSON.stringify(r3.headers)}`);
      }
      if (resJson.cost_usd !== 0 || resJson.access !== 'free_unlimited') {
        throw new Error(`Expected free access in response payload: ${JSON.stringify(resJson)}`);
      }
      console.log('Diff result added:', resJson.result.stats.added_count, 'modified:', resJson.result.stats.modified_count);

      // 4. Test MCP Gateway over HTTP POST /v1/mcp
      const r4 = await request('/v1/mcp', 'POST', {
        jsonrpc: '2.0',
        id: 99,
        method: 'tools/list'
      });
      const mcpJson = JSON.parse(r4.body);
      console.log('POST /v1/mcp -> status:', r4.status, 'mcp tools:', mcpJson.result.tools.length);
      if (mcpJson.result.tools.length !== 16) {
        throw new Error(`Expected 16 MCP tools, got ${mcpJson.result.tools.length}`);
      }

      console.log('\n🎉 ALL EDGE API ENDPOINTS FUNCTIONING PERFECTLY (100% FREE FOREVER)!\n');
    } catch (err) {
      console.error('API Test Error:', err);
      process.exitCode = 1;
    } finally {
      server.close();
      process.exit(process.exitCode || 0);
    }
  });
}

testApi();
