/**
 * Sprint 77b — #216 Pattern X (mixed in-corpus FPs): 2 TS FPs
 *
 * Closes the last 2 scorecard FPs from #216:
 *   - typescript safe_interop_shell_in_string.ts: argv-form
 *     `execFile('echo', ['--', arg], () => {})` — fixed program
 *     literal, no shell parsing of subsequent argv slots.
 *   - typescript safe_interop_sql_in_string.ts: parameterized pg
 *     query `pool.query('SELECT * FROM users WHERE name = $1', [name])`
 *     — `$1` placeholder binds the tainted value at the driver layer
 *     rather than splicing it into SQL text.
 *
 * Each TN reproduces the verbatim corpus FP shape. Each TP-control
 * pairs with the TN to prove the new sanitizer does NOT over-suppress
 * a similar but actually-unsafe variant (shell-via-argv, tainted
 * program slot, concat'd SQL, interpolated template SQL).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#216 Sprint 77b — TS interop sanitizer recognition', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — safe_interop_shell_in_string.ts: execFile(literal, [argv]) sanitizes command_injection + ETE', async () => {
    const code = [
      "/** SAFE mirror — execFile with argv, no shell. */",
      "import express from 'express';",
      "import { execFile } from 'child_process';",
      '',
      'const app = express();',
      '',
      "app.get('/run', (req, res) => {",
      "  const arg = String(req.query.arg ?? '');",
      "  execFile('echo', ['--', arg], () => {});",
      "  res.end('ok');",
      '});',
      'export default app;',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'safe_interop_shell_in_string.ts',
      'typescript',
    );
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(ci.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-1 — exec("cmd " + taint) shell-string form still fires command_injection', async () => {
    const code = [
      "import express from 'express';",
      "import { exec } from 'child_process';",
      '',
      'const app = express();',
      "app.get('/run', (req, res) => {",
      "  const arg = String(req.query.arg ?? '');",
      "  exec('echo ' + arg, () => {});",
      "  res.end('ok');",
      '});',
      'export default app;',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'unsafe_shell_concat.ts',
      'typescript',
    );
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    // Shell concat path must still fire (sanitizer must not over-suppress).
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-2 — execFile("sh", ["-c", taint]) shell-via-argv still fires command_injection', async () => {
    const code = [
      "import express from 'express';",
      "import { execFile } from 'child_process';",
      '',
      'const app = express();',
      "app.get('/run', (req, res) => {",
      "  const arg = String(req.query.arg ?? '');",
      "  execFile('sh', ['-c', 'echo ' + arg], () => {});",
      "  res.end('ok');",
      '});',
      'export default app;',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'unsafe_sh_dashc.ts',
      'typescript',
    );
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    // sh -c re-enables shell parsing — must still fire.
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('TN-2 — safe_interop_sql_in_string.ts: pool.query("...$1", [name]) sanitizes sql_injection + ETE', async () => {
    const code = [
      "/** SAFE mirror — parameterized query. */",
      "import express from 'express';",
      "import { Pool } from 'pg';",
      '',
      'const app = express();',
      'const pool = new Pool();',
      '',
      "app.get('/user', async (req, res) => {",
      "  const name = String(req.query.name ?? '');",
      "  await pool.query('SELECT * FROM users WHERE name = $1', [name]);",
      "  res.end('ok');",
      '});',
      'export default app;',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'safe_interop_sql_in_string.ts',
      'typescript',
    );
    const sqli = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'sql_injection',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(sqli.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-3 — pool.query("... = \'" + taint + "\'") concat SQL still fires sql_injection', async () => {
    const code = [
      "import express from 'express';",
      "import { Pool } from 'pg';",
      '',
      'const app = express();',
      'const pool = new Pool();',
      "app.get('/user', async (req, res) => {",
      "  const name = String(req.query.name ?? '');",
      "  await pool.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");",
      "  res.end('ok');",
      '});',
      'export default app;',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'unsafe_sql_concat.ts',
      'typescript',
    );
    const sqli = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'sql_injection',
    );
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });

  it('TP-4 — pool.query(`... ${taint}`) interpolated template SQL still fires sql_injection', async () => {
    const code = [
      "import express from 'express';",
      "import { Pool } from 'pg';",
      '',
      'const app = express();',
      'const pool = new Pool();',
      "app.get('/user', async (req, res) => {",
      "  const name = String(req.query.name ?? '');",
      '  await pool.query(`SELECT * FROM users WHERE name = \'${name}\'`);',
      "  res.end('ok');",
      '});',
      'export default app;',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'unsafe_sql_template.ts',
      'typescript',
    );
    const sqli = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'sql_injection',
    );
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });
});
