# MicroAgent Tools 🤖
> **Deterministic Headless Tool Suite & Model Context Protocol (MCP) Server for Autonomous AI Agents — 100% Free Forever**

MicroAgent Tools is built strictly for the **Agentic Future**. Human graphical interfaces (buttons, CSS animations, popups) add latency and friction. This repository strips away human UI bloat to expose **deterministic, high-precision tools** directly to AI agents via **MCP (Model Context Protocol)**, **Edge JSON APIs**, and **`llms.txt`** discovery.

**Zero Paywalls. Zero Token Metering. Zero Rate Limits. 100% Free Forever.**

---

## ⚡ Quickstart

### 1. Connect Directly to Claude Desktop, Cursor, or Antigravity (MCP)
Add this to your `claude_desktop_config.json` or Cursor settings:

```json
{
  "mcpServers": {
    "micro-agent-tools": {
      "command": "node",
      "args": ["d:/Free-Micro-SaaS-Tools/src/mcp/server.js"]
    }
  }
}
```

### 2. Run Edge API Server Locally
```bash
npm start
# Server starts on http://localhost:3000
```
- **Discovery Sitemap:** `http://localhost:3000/llms.txt`
- **Full Schema Spec:** `http://localhost:3000/llms-full.txt`
- **Tool Catalog (JSON):** `http://localhost:3000/v1/tools`
- **MCP HTTP Gateway:** `http://localhost:3000/v1/mcp`
- **Interactive Console:** `http://localhost:3000/`

### 3. Run Automated Test Suite
```bash
npm test
# Verifies all 16 headless tools + MCP JSON-RPC protocol (21 unit tests)
node tests/test_api_endpoints.js
# Verifies live Edge REST and MCP endpoints
```

---

## 🛠️ Registered Agent Capabilities (All 16 Tools Free Forever)

| Tool Name | Agent Problem Solved | Pricing |
| :--- | :--- | :--- |
| **`sheet_diff`** | Reconciles two CSV/TSV spreadsheets by primary key (SKU, Email, ID). Returns structured row and cell deltas without LLM hallucination. | **Free ($0.00)** |
| **`text_cleaner`** | Sanitizes scraped web text, repairs broken PDF line wraps, straightens quotes & strips UTM click tracking IDs. | **Free ($0.00)** |
| **`pii_redactor`** | Scrubs credit card numbers, SSNs, emails, phone numbers & API tokens from text before forwarding to LLMs. | **Free ($0.00)** |
| **`terms_risk_scanner`** | Scans contracts for forced arbitration, AI model data training clauses, auto-renewals, and IP grabs. | **Free ($0.00)** |
| **`receipt_parser`** | Extracts vendor, date, invoice number, tax, and line items from unstructured billing text. | **Free ($0.00)** |
| **`invoice_builder`** | Computes line-item totals, taxes, discounts, and formats client billing breakdowns. | **Free ($0.00)** |
| **`og_card_generator`** | Generates 1200x630 vector SVG social preview cards and HTML / Next.js meta tags. | **Free ($0.00)** |
| **`website_health_auditor`**| Inspects a target URL for HSTS, CSP, X-Frame-Options security headers, and Open Graph tags. | **Free ($0.00)** |
| **`code_card_generator`** | Renders beautiful syntax-highlighted code snippet cards into vector SVG / PNG ready for documentation. | **Free ($0.00)** |
| **`pdf_processor`** | Merges, splits, extracts pages, and applies watermarks or stamp approvals to PDF documents. | **Free ($0.00)** |
| **`json_diff`** | Deep semantic JSON comparer calculating structural added, deleted, and modified paths. | **Free ($0.00)** |
| **`webhook_verifier`** | Cryptographic HMAC signature validator for Stripe, GitHub, Shopify, and standard webhooks. | **Free ($0.00)** |
| **`env_matrix`** | Validates `.env` and `.env.example` configurations, detects missing keys and unmasked secrets. | **Free ($0.00)** |
| **`duck_log`** | In-memory SQL engine for agent logs, JSON arrays, and CSV event streams. | **Free ($0.00)** |
| **`jwt_verifier`** | Decodes JWT headers and payloads, validates expiration, and checks cryptographic signatures. | **Free ($0.00)** |
| **`sourcemap_demapper`** | Translates minified production stack traces back to original source files and line numbers. | **Free ($0.00)** |

---

## 📡 Edge REST API Example

Execute tools via standard HTTP POST (no authentication required; any API key or token accepted):

```bash
curl -X POST http://localhost:3000/v1/tools/sheet_diff \
  -H "Content-Type: application/json" \
  -d '{
    "baseline_csv": "sku,price\nSKU-1,10.00\nSKU-2,20.00",
    "updated_csv": "sku,price\nSKU-1,15.00\nSKU-3,30.00",
    "primary_key": "sku"
  }'
```

**Response Headers:**
```http
HTTP/1.1 200 OK
X-Access: free-unlimited
X-Cost: $0.00
Content-Type: application/json
```

**Response Body:**
```json
{
  "success": true,
  "tool": "sheet_diff",
  "result": {
    "stats": {
      "added_count": 1,
      "deleted_count": 1,
      "modified_count": 1,
      "total_cell_changes": 1
    },
    "added_rows": [{ "key": "SKU-3", "row_data": { "sku": "SKU-3", "price": "30.00" } }],
    "deleted_rows": [{ "key": "SKU-2", "row_data": { "sku": "SKU-2", "price": "20.00" } }],
    "modified_rows": [{
      "key": "SKU-1",
      "cell_changes": { "price": { "old_value": "10.00", "new_value": "15.00" } }
    }]
  },
  "access": "free_unlimited",
  "cost_usd": 0.00
}
```

---

## 📁 Repository Structure

```
.
├── llms.txt               # Machine-readable agent discovery sitemap
├── llms-full.txt          # Detailed schemas, examples & MCP specs
├── package.json           # Agent package definition & zero-dep runner
├── index.html             # Developer & Agent Testing Portal
├── README.md              # Project documentation
├── src/
│   ├── tools/             # Headless deterministic tool engines (16 tools)
│   │   ├── index.js       # Central tool registry
│   │   ├── sheet_diff.js
│   │   ├── text_cleaner.js
│   │   ├── pii_redactor.js
│   │   ├── terms_scanner.js
│   │   ├── receipt_parser.js
│   │   ├── invoice_builder.js
│   │   ├── og_card_generator.js
│   │   ├── web_auditor.js
│   │   ├── code_card_generator.js
│   │   ├── pdf_processor.js
│   │   ├── json_diff.js
│   │   ├── webhook_verifier.js
│   │   ├── env_matrix.js
│   │   ├── duck_log.js
│   │   ├── jwt_verifier.js
│   │   ├── sourcemap_demapper.js
│   │   └── core/          # Zero-dependency algorithmic engines
│   ├── mcp/
│   │   └── server.js      # Model Context Protocol (stdio & SSE)
│   └── api/
│       └── edge_server.js # Edge HTTP API with free unlimited access
└── tests/
    ├── test_runner.js     # Verification suite (21 unit tests)
    └── test_api_endpoints.js # Live HTTP endpoint tests
```

---

## 🔒 100% In-Browser / On-Device Privacy
Everything runs in local memory or on local microservices. Zero telemetry, zero tracking, zero vendor lock-in.
