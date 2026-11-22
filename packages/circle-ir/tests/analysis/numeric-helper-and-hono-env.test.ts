/**
 * a value proven numeric is clean for SQL and command sinks, and Hono
 * bindings (`c.env`) are not request data.
 *
 * `const hours = parseHours(raw)`, where `parseHours` checks a digit regex and
 * a range and returns a number on every path, then `INTERVAL '${hours}' HOUR`
 * was reported as SQL injection. Inline `Number(x)` was already credited; a
 * same-file helper that only returns numbers now is too. A handler that reads
 * the request also tainted `c`, and `c.env.TABLE` inherited that taint.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { jsHelperReturnsNumber } from '../../src/analysis/js-helper-return.js';
import { honoEnvDefIds } from '../../src/analysis/hono-env.js';

const flows = async (code: string, type = 'sql_injection') =>
  (await analyze(code, 'src/r.ts', 'typescript')).taint.flows.filter(f => f.sink_type === type);

const PARSE_HOURS = `function parseHours(raw: string | undefined): number {
  if (!raw || !/^[0-9]{1,3}$/.test(raw)) return 24;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 720) return 24;
  return n;
}`;

const pgRoute = (helper: string, value: string) => `import { Hono } from 'hono';
import { Pool } from 'pg';
const pool = new Pool();
const app = new Hono();
${helper}
app.get('/stats', async (c) => {
  const hours = ${value};
  const r = await pool.query(\`SELECT count(*) FROM events WHERE ts > now() - INTERVAL '\${hours}' HOUR\`);
  return c.json(r.rows);
});
`;

describe('numeric helper return is a sanitizer', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the parseHours shape gives no flow', async () => {
    expect(await flows(pgRoute(PARSE_HOURS, `parseHours(c.req.query('h'))`))).toHaveLength(0);
  });

  it('raw c.req.query interpolated still flows', async () => {
    expect((await flows(pgRoute('', `c.req.query('h')`))).length).toBeGreaterThan(0);
  });

  it('a helper that can hand back its input still flows', async () => {
    const helper = `function parseHours(raw: string | undefined): number {
  if (!raw || !/^[0-9]{1,3}$/.test(raw)) return 24;
  return raw as unknown as number;
}`;
    expect((await flows(pgRoute(helper, `parseHours(c.req.query('h'))`))).length).toBeGreaterThan(0);
  });

  it('an arrow helper with a ternary of numbers gives no flow', async () => {
    const helper = `const toHours = (raw?: string): number => {
  const n = parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 && n <= 720 ? n : 24;
};`;
    expect(await flows(pgRoute(helper, `toHours(c.req.query('h'))`))).toHaveLength(0);
  });

  it('a numeric helper feeding a shell command gives no flow; the raw value does', async () => {
    const cmd = (value: string) => `import { Hono } from 'hono';
import { exec } from 'child_process';
const app = new Hono();
${PARSE_HOURS}
app.get('/wait', (c) => {
  const hours = ${value};
  exec(\`sleep \${hours}\`);
  return c.text('ok');
});
`;
    expect(await flows(cmd(`parseHours(c.req.query('h'))`), 'command_injection')).toHaveLength(0);
    expect((await flows(cmd(`c.req.query('h')`), 'command_injection')).length).toBeGreaterThan(0);
  });
});

describe('jsHelperReturnsNumber', () => {
  const yes = (code: string, name = 'f') => expect(jsHelperReturnsNumber(code, name)).toBe(true);
  const no = (code: string, name = 'f') => expect(jsHelperReturnsNumber(code, name)).toBe(false);

  it('accepts literals, numeric coercions, unary plus and numeric locals', () => {
    yes(PARSE_HOURS, 'parseHours');
    yes('function f(x) { return Number(x); }');
    yes('function f(x) { return Math.min(Math.max(parseInt(x, 10), 1), 99); }');
    yes('function f(x) { return +x; }');
    yes('function f(x) { let n = 0; if (x) n = parseFloat(x); n++; return n; }');
    yes('const f = async function (x) { return x ? 1 : (2); };');
    yes('function f(x) { /* a */ return Number(x) as  number; /* b */ }');
  });

  it('rejects anything that may return a non-number', () => {
    no('function f(x) { return x; }');
    no('function f(x) { return x as number; }');
    no('function f(x) { return Number(x)asnumber; }');
    no('function f(x) { /* 1 */ return x; /* 2 */ }');
    no('function f(x) { return Number(x) + x; }');
    no('function f(x) { if (x) return; return 1; }');
    no('function f(x) { const n = Number(x); return n\n    + x; }');
    no('function f(x) { let n = 1; n += x; return n; }');
    no('function f(x) { let n = 1; n = x; return n; }');
    no('function f(x) { const { n } = x; return n; }');
    no('function f(x) { return x.map(v => 1).length; }');
    no('function f(x) { return 1; }\nfunction f(x) { return x; }');
    no('function f(x) { return 1; }\nf = (x) => x;');
    no('function f(x) { return n; }');
    no('function f() {}');
    no('function g(x) { return 1; }');
    no('function f(x) { return 1; }', 'a.b');
  });
});

describe('Hono c.env is not request-tainted', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const route = (body: string) => `import { Hono } from 'hono';
import { Pool } from 'pg';
const pool = new Pool();
const app = new Hono();
app.get('/stats', async (c) => {
${body}
});
`;

  it('a binding read beside a request read does not flow', async () => {
    expect(await flows(route(`  const table = c.env.TABLE;
  const q = c.req.query('q');
  const r = await pool.query(\`SELECT count(*) FROM \${table}\`);
  return c.json({ q, rows: r.rows });`))).toHaveLength(0);
  });

  it('an alias of c.env and a destructuring of it do not flow', async () => {
    expect(await flows(route(`  const q = c.req.query('q');
  const env = c.env;
  const days = env.RETENTION_DAYS;
  const { SCHEMA } = c.env;
  const r = await pool.query(\`SELECT count(*) FROM \${SCHEMA}.t WHERE age < \${days}\`);
  return c.json({ q, rows: r.rows });`))).toHaveLength(0);
  });

  it('a binding indexed by a request value still flows', async () => {
    expect((await flows(route(`  const q = c.req.query('q');
  const table = c.env[q];
  const r = await pool.query(\`SELECT count(*) FROM \${table}\`);
  return c.json(r.rows);`))).length).toBeGreaterThan(0);
  });

  it('a request value next to a binding read still flows', async () => {
    expect((await flows(route(`  const table = c.env.TABLE;
  const q = c.req.query('q');
  const r = await pool.query(\`SELECT * FROM \${table} WHERE name = '\${q}'\`);
  return c.json(r.rows);`))).length).toBeGreaterThan(0);
  });

  const cmdRoute = (path: string, body: string) => `import { Hono } from 'hono';
import { exec } from 'child_process';
const app = new Hono();
app.get('${path}', (c) => {
${body}
  return c.text('ok');
});
`;

  it('an env field of the query object still flows', async () => {
    expect((await flows(cmdRoute('/run', `  const q = c.req.query();
  const target = q.env;
  exec(\`deploy \${target}\`);`), 'command_injection')).length).toBeGreaterThan(0);
  });

  it('an env field of the path params still flows', async () => {
    expect((await flows(cmdRoute('/run/:env', `  const tag = c.req.query('tag');
  const p = c.req.param();
  const name = p.env;
  exec(\`deploy \${name}\`);`), 'command_injection')).length).toBeGreaterThan(0);
  });

  it('only an env read on the context parameter is a barrier', async () => {
    const code = `import { Hono } from 'hono';
const app = new Hono();
app.post('/run', async (c) => {
  const body = await c.req.json();
  const bin = c.env.TOOL;
  body.jobs.forEach((job) => {
    const target = job.env;
  });
  const q = c.req.query();
  const mode = q.env;
  return c.text(bin);
});
function helper(c) {
  const dir = c.env;
}
`;
    const { dfg } = await analyze(code, 'src/r.ts', 'typescript');
    const barrier = honoEnvDefIds(dfg.defs, dfg.uses, code, 'typescript');
    const names = dfg.defs.filter(d => barrier.has(d.id)).map(d => d.variable);
    expect(names).toEqual(['bin']);
  });

  it('the context parameter keeps the barrier under any name, in middleware too', async () => {
    const code = `import { Hono } from 'hono';
import type { Context, Next } from 'hono';
import { exec } from 'child_process';
const app = new Hono();
app.use('*', async (ctx, next) => {
  const q = ctx.req.query('q');
  const dir = ctx.env.WORK_DIR;
  exec(\`ls \${dir}\`);
  await next();
});
async function handler(c: Context) {
  const q = c.req.query('q');
  const bin = c.env.TOOL;
  exec(\`\${bin} --version\`);
  return c.text(q ?? '');
}
app.get('/v', handler);
`;
    expect(await flows(code, 'command_injection')).toHaveLength(0);
  });
});
