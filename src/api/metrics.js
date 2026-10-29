/**
 * Minimal Prometheus-style metrics. Zero dependencies, works in Node and
 * Workers (per-process / per-isolate counters — aggregate at scrape time).
 *
 * Series stay low-cardinality on purpose: routes are archetypes
 * (/v1/tools/:tool), never raw paths or user input.
 */

'use strict';

function createStore() {
  return {
    requestsTotal: new Map(), // `${method} ${route} ${status}` -> count
    requestMsTotal: new Map(), // `${method} ${route}` -> { count, sumMs }
    toolsTotal: new Map(), // `${tool} ${outcome}` -> count (outcome: ok|error|timeout|limited)
    rateLimitedTotal: 0,
    startedAt: Date.now(),
  };
}

let store = createStore();

function resetForTests() {
  store = createStore();
}

/** Collapse a pathname to a bounded route label. */
function routeLabel(method, pathname) {
  if (pathname === '/v1/mcp' && method === 'POST') return 'POST /v1/mcp';
  const m = pathname.match(/^\/v1\/tools\/([a-zA-Z0-9_-]+)$/);
  if (m && method === 'POST') return 'POST /v1/tools/:tool';
  if (pathname === '/v1/tools' && method === 'GET') return 'GET /v1/tools';
  if (pathname === '/metrics') return 'GET /metrics';
  if ((pathname === '/' || pathname === '/status') && method === 'GET') return 'GET /status';
  if (method === 'OPTIONS') return 'OPTIONS *';
  return `${method} other`;
}

function observeRequest(method, pathname, status, ms) {
  const route = routeLabel(method, pathname);
  const key = `${method} ${route.split(' ').slice(1).join(' ') || route} ${status}`;
  store.requestsTotal.set(key, (store.requestsTotal.get(key) || 0) + 1);
  const agg = store.requestMsTotal.get(route) || { count: 0, sumMs: 0 };
  agg.count += 1;
  agg.sumMs += ms;
  store.requestMsTotal.set(route, agg);
}

function observeTool(tool, outcome) {
  const key = `${tool} ${outcome}`;
  store.toolsTotal.set(key, (store.toolsTotal.get(key) || 0) + 1);
}

function observeRateLimited() {
  store.rateLimitedTotal += 1;
}

function esc(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function render() {
  const lines = [];
  lines.push('# HELP microagent_requests_total HTTP responses by route and status.');
  lines.push('# TYPE microagent_requests_total counter');
  for (const [key, count] of store.requestsTotal) {
    const [method, ...rest] = key.split(' ');
    const status = rest.pop();
    const route = rest.join(' ');
    lines.push(`microagent_requests_total{method="${esc(method)}",route="${esc(route)}",status="${esc(status)}"} ${count}`);
  }
  lines.push('# HELP microagent_request_ms_sum Total latency ms by route.');
  lines.push('# TYPE microagent_request_ms_sum counter');
  lines.push('# HELP microagent_request_count Requests by route.');
  lines.push('# TYPE microagent_request_count counter');
  for (const [route, agg] of store.requestMsTotal) {
    lines.push(`microagent_request_ms_sum{route="${esc(route)}"} ${Math.round(agg.sumMs)}`);
    lines.push(`microagent_request_count{route="${esc(route)}"} ${agg.count}`);
  }
  lines.push('# HELP microagent_tool_runs_total Tool executions by outcome (ok|error|timeout|limited|busy|denied).');
  lines.push('# TYPE microagent_tool_runs_total counter');
  for (const [key, count] of store.toolsTotal) {
    const [tool, outcome] = key.split(' ');
    lines.push(`microagent_tool_runs_total{tool="${esc(tool)}",outcome="${esc(outcome)}"} ${count}`);
  }
  lines.push('# HELP microagent_rate_limited_total Rate-limit denials.');
  lines.push('# TYPE microagent_rate_limited_total counter');
  lines.push(`microagent_rate_limited_total ${store.rateLimitedTotal}`);
  lines.push('# HELP microagent_uptime_s Process/isolate uptime.');
  lines.push('# TYPE microagent_uptime_s gauge');
  lines.push(`microagent_uptime_s ${Math.floor((Date.now() - store.startedAt) / 1000)}`);
  return `${lines.join('\n')}\n`;
}

module.exports = {
  observeRequest,
  observeTool,
  observeRateLimited,
  routeLabel,
  render,
  resetForTests,
};
