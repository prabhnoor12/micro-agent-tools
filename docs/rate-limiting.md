# Rate limiting & abuse protection

In-memory limits in `src/api/limits.js` are **per-process / per-isolate
defense-in-depth**. On Cloudflare Workers isolates do not share memory, so a
global attacker spread across N isolates gets ~N× budget. For production you
MUST pair the code with Cloudflare Rate Limiting rules (distributed
enforcement at the edge).

## What the code does

- Global per-IP sliding window (`RATE_LIMIT_GLOBAL_PER_MIN`, default 120/min).
- Per-tier tool buckets: cheap 60/min, medium 20/min, heavy 5/min.
- MCP gateway bucket (`RATE_LIMIT_MCP_PER_MIN`, default 30/min).
- `Retry-After` + `X-RateLimit-Limit/Remaining` on every tool response.
- Client IP is **spoof-resistant by default**: `CF-Connecting-IP` wins,
  `X-Forwarded-For` is ignored unless `TRUST_PROXY_HEADERS=1` (only set this
  behind a proxy you control that overwrites XFF).
- `ALLOWED_ORIGINS` (comma-separated, default `*`) restricts which `Origin`
  values receive `Access-Control-Allow-Origin` on API responses.

## Recommended Cloudflare rules (dashboard)

Create three rules on the Worker route (`POST /v1/tools/*`, `POST /v1/mcp`):

| Rule | Characteristics | Period | Requests | Action |
| --- | --- | --- | --- | --- |
| Global abuse | IP, path contains `/v1/` | 1 min | 120 | Block 60s |
| MCP gateway | IP, path = `/v1/mcp` | 1 min | 30 | Challenge / block 60s |
| Heavy tools | IP, path in `/v1/tools/pdf_processor`, `/v1/tools/website_health_auditor`, `/v1/tools/duck_log` | 1 min | 5 | Block 300s |

Dashboard: Security → WAF → Rate limiting rules → Create rule → set the
above → enable logging. Verify with:

```bash
for i in $(seq 1 40); do curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://<your-worker>/v1/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'; done
# expect 200s then 429s with Retry-After
```

## Equivalent API call (automation)

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets" \
  -H "Authorization: Bearer <API_TOKEN>" -H 'Content-Type: application/json' \
  -d @rate-limiting.example.json
```

See `rate-limiting.example.json` (draft template — adjust zone/route IDs).

## Self-hosted Node

- Run behind one trusted reverse proxy; set `TRUST_PROXY_HEADERS=1` ONLY if
  that proxy overwrites `X-Forwarded-For`. Otherwise leave it `0` so XFF is
  ignored and `socket.remoteAddress` is used.
- Set `ALLOWED_ORIGINS=https://your-app.example` to stop arbitrary websites
  from calling the API from browsers. `curl` / server-side agents are
  unaffected (no Origin header).
- Tune via env: `RATE_LIMIT_GLOBAL_PER_MIN`, `RATE_LIMIT_MCP_PER_MIN`,
  `RATE_LIMIT_CHEAP_PER_MIN`, `RATE_LIMIT_MEDIUM_PER_MIN`,
  `RATE_LIMIT_HEAVY_PER_MIN`, `MAX_BODY_BYTES`, `MAX_PDF_BODY_BYTES`,
  `MAX_CONCURRENT_HEAVY`, `TOOL_TIMEOUT_MS`, `HEAVY_TOOL_TIMEOUT_MS`.

## Auditor egress

`website_health_auditor` additionally enforces SSRF guards in code
(`src/api/ssrf.js`): public http(s) only, ports 80/443, per-hop redirect
re-validation, DNS re-resolution to public addresses (Node), 1MB body cap.
On Workers there is no socket DNS API — add a Cloudflare Zero Trust egress
policy denying `10/8, 172.16/12, 192.168/16, 127/8, 169.254/16` for
defense-in-depth.
