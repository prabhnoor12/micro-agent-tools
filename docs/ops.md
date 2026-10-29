# Ops: requests, logs, health, shutdown, containers

## Request IDs

Every HTTP response carries `X-Request-Id`. Send your own (`[A-Za-z0-9_.:-]`,
max 128 chars) to trace a call end-to-end; otherwise the server mints one.
Include it in bug reports. The Worker mints UUIDs via `crypto.randomUUID`.

## Logging

Structured JSON lines on stderr. Default `LOG_LEVEL=warn` (rate limits,
timeouts, shutdown, 500s). Levels: `debug < info < warn < error`.

- `debug`: every tool execution `{reqId, tool, ms}` — enable with
  `LOG_LEVEL=debug` when profiling.
- `warn`: `rate_limited`, `tool_timeout`, `shutdown`.
- `error`: `internal_error`, `shutdown_forced`.

Bodies, secrets, and raw error internals are never logged. 500 responses are
always generic; the detail stays in the server log line keyed by `reqId`.

## Health

`GET /` and `GET /status` return:

```json
{
  "status": "online",
  "uptime_s": 1234,
  "in_flight_requests": 3,
  "heavy_in_flight": 1
}
```

(`/status` on Workers omits `in_flight_requests` — isolates are per-request —
but includes `heavy_in_flight` and `uptime_s` of the isolate.)

Docker `HEALTHCHECK` polls `/status`. Kubernetes example:

```yaml
livenessProbe:
  httpGet: { path: /status, port: 3000 }
  periodSeconds: 30
readinessProbe:
  httpGet: { path: /status, port: 3000 }
  periodSeconds: 5
```

## Shutdown

`SIGTERM`/`SIGINT` stops accepting new connections, drains in-flight
requests, then exits. After 10s the process force-exits (exit 1) so a stuck
tool can't hang a deploy forever. In-flight heavy-tool slots are released via
`finally`, so a restart never leaks the concurrency budget.

## Containers

```bash
docker build -t micro-agent-tools .
docker run -p 3000:3000 \
  -e ALLOWED_ORIGINS=https://your-app.example \
  -e RATE_LIMIT_GLOBAL_PER_MIN=120 \
  micro-agent-tools
```

`--max-old-space-size=512` caps V8 heap inside the container; per-tool usage
guards (`src/api/limits.js`) cap individual payloads well below that. Raise
the heap flag before raising payload limits, never the reverse.

## Authentication (hosted deploys)

Local use stays open. Set `API_KEYS` (comma-separated, each ≥16 chars) and
all `POST /v1/*` routes plus `GET /metrics` require
`Authorization: Bearer <key>` (timing-safe compare). Discovery GETs stay
open. Without keys the server logs an `open_mode` warning on boot — bind to
localhost or set keys on hostile networks. Same contract on the Worker via
`API_KEYS` env (`vars` in wrangler.jsonc).

## Metrics

`GET /metrics` returns Prometheus text (`microagent_requests_total`,
`microagent_request_ms_sum/count`, `microagent_tool_runs_total{outcome}`,
`microagent_rate_limited_total`, `microagent_uptime_s`). Node aggregates
per-process; Workers per-isolate — aggregate at scrape time. Popular
Prometheus scrape config works unchanged. `/metrics` is auth-gated when keys
are set; otherwise restrict it at the proxy.

## Sockets

Node sets `requestTimeout` (heaviest tool deadline + 15s), `headersTimeout`
15s, `keepAliveTimeout` 5s — slow drips die before they accumulate.

## Persistent rate limiting

`src/rate_limiter_do.js` (`RateLimitDO`) is a Durable Object sliding-window
limiter. Bind it as `RATE_LIMITER` (see wrangler.jsonc + migration `v1`);
the Worker prefers it and falls back to memory on any error (never fails
open/closed on a storage outage). Without the binding, memory + WAF rules
remain the enforcement (see rate-limiting.md).

## Heavy isolation

On Node, heavy-tier tools run in a worker thread (`src/api/heavy_runner.js`)
with a 256MB heap cap; the thread is terminated on deadline. Light tiers run
in-process with cooperative abort. The `heavy_in_flight` gauge and
`microagent_tool_runs_total{outcome="busy"}` show saturation.

## Schema validation

Every call is validated against the tool's own JSON Schema before execution
(required, types, enums, unknown-key rejection at every level). Error
messages name paths only, never caller values.

## Auditor egress (phase 2)

`AUDIT_DENYLIST="corp,secret.internal,.dyn"` adds exact/suffix denies on top
of the built-in reserves. On Node the auditor uses DNS-pinned sockets
(resolve → require-public → connect-to-IP with SNI/Host of the hostname),
closing the check-then-connect TOCTOU. Elsewhere it resolves + checks per
redirect hop; keep the Zero Trust egress policy as the outer ring.

## Reliability notes

- Timeouts are cooperative: the HTTP response always resolves by the deadline,
  and tools that accept the abort signal (`pdf_processor`, `duck_log`/SQL)
  stop early. Sync-only tools still resolve via the race; their slot is freed.
- Tool arguments are shape-checked before execution (max depth 20, max 5000
  keys) on top of per-tool size limits.
- `duck_log` results are hard-capped at 1000 rows (`truncated: true` when hit);
  multi-statement SQL is rejected; the engine is SELECT-only by construction.
- MCP stdio lines are capped at 1MB; oversize lines get a `-32700` error and
  are counted (`oversizeLineCountTotal`) instead of parsed.
