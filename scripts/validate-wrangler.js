/**
 * Validate wrangler.jsonc: JSONC syntax, required keys, sane values.
 * Run: node scripts/validate-wrangler.js (also in CI).
 */
const fs = require('fs');
const path = require('path');

function fail(msg) {
  console.error(`wrangler validation FAIL: ${msg}`);
  process.exit(1);
}

const file = path.join(__dirname, '..', 'wrangler.jsonc');
let raw;
try {
  raw = fs.readFileSync(file, 'utf8');
} catch (_) {
  fail('wrangler.jsonc not found');
}
const stripped = raw.replace(/^[ \t]*\/\/.*$/gm, '');
let cfg;
try {
  cfg = JSON.parse(stripped);
} catch (e) {
  fail(`invalid JSONC: ${e.message}`);
}

for (const key of ['name', 'main', 'compatibility_date', 'assets']) {
  if (cfg[key] === undefined) fail(`missing required key "${key}"`);
}
if (!/^\d{4}-\d{2}-\d{2}$/.test(cfg.compatibility_date || '')) fail('compatibility_date must be YYYY-MM-DD');
const date = new Date(`${cfg.compatibility_date}T00:00:00Z`);
if (Number.isNaN(date.getTime())) fail('compatibility_date is not a real date');
if (date > new Date()) fail('compatibility_date is in the future');
if (date < new Date('2023-01-01T00:00:00Z')) fail('compatibility_date is stale; bump it deliberately');

if (!fs.existsSync(path.join(__dirname, '..', cfg.main))) fail(`main entry "${cfg.main}" does not exist`);
if (!fs.existsSync(path.join(__dirname, '..', cfg.assets.directory))) {
  fail(`assets directory "${cfg.assets.directory}" does not exist (run npm run build)`);
}

// Every Durable Object binding must resolve to an exported class.
if (cfg.durable_objects && Array.isArray(cfg.durable_objects.bindings)) {
  for (const b of cfg.durable_objects.bindings) {
    if (!b.name || !b.class_name) fail(`durable_objects binding missing name/class_name: ${JSON.stringify(b)}`);
  }
  const hasMigration = (cfg.migrations || []).some((m) =>
    (m.new_sqlite_classes || m.new_classes || []).includes(
      cfg.durable_objects.bindings[0].class_name
    )
  );
  if (!hasMigration) fail('durable_objects binding has no matching migration entry');
}

// Declared vars must be consumed somewhere (dead config rots).
const src = ['src/worker.js', 'src/api/limits.js'];
const workerSrc = src.map((f) => {
  try {
    return fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  } catch (_) {
    return '';
  }
}).join('\n');
for (const key of Object.keys(cfg.vars || {})) {
  if (!workerSrc.includes(key)) fail(`vars.${key} is declared but never read`);
}

console.log('✅ wrangler.jsonc valid:', JSON.stringify({
  name: cfg.name,
  compatibility_date: cfg.compatibility_date,
  bindings: (cfg.durable_objects?.bindings || []).map((b) => b.name),
  vars: Object.keys(cfg.vars || {}),
}));
