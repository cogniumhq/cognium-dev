/**
 * `log_injection` (CWE-117) on JavaScript / TypeScript: a request value written
 * unchanged to a log call is a flow; CR/LF stripped with `.replace` or the value
 * passed through `JSON.stringify` (which escapes CR/LF) is not.
 *
 * Fixtures in `tests/fixtures/log-injection/`:
 *   - vulnerable.ts / vulnerable.js — every `// FLAG` line gives one flow
 *   - fixed-replace.ts              — CR/LF stripped: zero
 *   - fixed-json.ts                 — JSON.stringify: zero
 *   - near-miss.ts                  — a `.replace` that strips no CR/LF: still flagged
 *
 * `JSON.stringify` is credited for `log_injection` only: its output still carries
 * `<`, quotes and SQL metacharacters, so an xss or sql flow through it stays.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/log-injection');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const sinkLines = (r: R, type: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line).sort((a, b) => a - b);
const flagLines = (code: string) =>
  code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));

describe('log_injection (CWE-117) on JS/TS: JSON.stringify and CR/LF replace are fixes', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['vulnerable.ts', 'typescript'],
    ['vulnerable.js', 'javascript'],
    ['near-miss.ts', 'typescript'],
  ] as const)('%s: one log_injection flow per FLAG line', async (name, language) => {
    const code = fixture(name);
    const r = await analyze(code, name, language);
    const flags = flagLines(code);
    expect(flags.length).toBeGreaterThan(0);
    expect(sinkLines(r, 'log_injection')).toEqual(flags);
  });

  it.each(['fixed-replace.ts', 'fixed-json.ts'])('%s: no log_injection flow', async (name) => {
    const r = await analyze(fixture(name), name, 'typescript');
    expect(sinkLines(r, 'log_injection')).toEqual([]);
  });

  it('JSON.stringify is credited for log_injection only', async () => {
    const r = await analyze(fixture('fixed-json.ts'), 'fixed-json.ts', 'typescript');
    const credited = (r.taint.sanitizers ?? []).filter(s => s.method.startsWith('JSON.stringify'));
    expect(credited.length).toBeGreaterThan(0);
    for (const s of credited) expect(s.sanitizes).toEqual(['log_injection']);
  });

  it('an xss or sql flow through JSON.stringify stays', async () => {
    const code = [
      "import express from 'express';",
      "import mysql from 'mysql';",
      'const db = mysql.createConnection({});',
      'const app = express();',
      'export function show(req, res) {',
      '  const name = req.query.name;',
      "  res.send('<p>' + JSON.stringify(name) + '</p>');",
      '}',
      'export function find(req, res) {',
      '  const id = req.query.id;',
      "  db.query('SELECT * FROM users WHERE name = ' + JSON.stringify(id), (e, rows) => res.json(rows));",
      '}',
      "app.get('/show', show);",
      "app.get('/find', find);",
    ].join('\n');
    const r = await analyze(code, 'stringify-not-xss-sql.ts', 'typescript');
    expect(sinkLines(r, 'xss')).toEqual([7]);
    expect(sinkLines(r, 'sql_injection')).toEqual([11]);
  });
});
