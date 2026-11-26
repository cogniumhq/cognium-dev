/**
 * cognium-dev #1372 — taint-coverage propagation axis: a value that goes
 * through `JSON.stringify` / `JSON.parse` and is assigned to a variable keeps
 * its taint for every sink type the JSON call does not clean.
 *
 * Two defects dropped the flow:
 *   - the class-less `parse` row (Rust `str.parse::<i32>()` coercion) matched
 *     `JSON.parse`, crediting it for sql_injection / command_injection;
 *   - the definition-to-definition hop treated any sanitizer as a full stop,
 *     so `const t = JSON.stringify(s)` (log_injection only) ended the taint.
 *
 * Fixtures are hand-written handler shapes.
 */
import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

type R = Awaited<ReturnType<typeof analyze>>;
const sinkTypes = (r: R) => new Set((r.taint.flows ?? []).map(f => f.sink_type));

const handler = (transform: string, sink: string) => `const { execSync } = require('child_process');
function lookup(req, res, db) {
  const raw = req.query.name;
  const value = ${transform};
  ${sink};
}
module.exports = { lookup };
`;

const SQL = `db.query("SELECT * FROM users WHERE name='" + value + "'")`;
const CMD = `execSync('finger ' + value)`;

describe('#1372 JSON round-trip keeps taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it.each([
    ['JSON.stringify(raw)'],
    ['JSON.stringify({ name: raw })'],
    ['JSON.parse(raw)'],
    ['JSON.parse(raw).name'],
    ['JSON.parse(JSON.stringify({ name: raw })).name'],
  ])('%s assigned, then concatenated into SQL', async (transform) => {
    const r = await analyze(handler(transform, SQL), 'json_sql.js', 'javascript');
    expect(sinkTypes(r).has('sql_injection')).toBe(true);
  });

  it.each([
    ['JSON.parse(raw)'],
    ['JSON.parse(JSON.stringify({ name: raw })).name'],
  ])('%s assigned, then concatenated into a shell command', async (transform) => {
    const r = await analyze(handler(transform, CMD), 'json_cmd.js', 'javascript');
    expect(sinkTypes(r).has('command_injection')).toBe(true);
  });

  it('JSON.parse credits are scoped to the JSON rows', async () => {
    const r = await analyze(handler('JSON.parse(raw)', SQL), 'json_scope.js', 'javascript');
    const credited = (r.taint.sanitizers ?? []).filter(s => s.method.startsWith('JSON.parse('));
    expect(credited.length).toBeGreaterThan(0);
    for (const s of credited) expect(s.sanitizes).not.toContain('sql_injection');
  });

  it('a JSON.stringify value assigned before a log call is still credited for log_injection', async () => {
    const code = `import express from 'express';
const app = express();
export function audit(req, res) {
  const who = JSON.stringify(req.query.user);
  console.log('audit ' + who);
  res.send('ok');
}
app.get('/audit', audit);
`;
    const r = await analyze(code, 'json_log.ts', 'typescript');
    expect(sinkTypes(r).has('log_injection')).toBe(false);
  });

  it('Rust str.parse coercion still cleans a command', async () => {
    const code = `use std::process::Command;
fn run(input: String) {
    let n: i32 = input.parse().unwrap();
    Command::new("sleep").arg(n.to_string()).output().unwrap();
}
`;
    const r = await analyze(code, 'parse_cmd.rs', 'rust');
    const credited = (r.taint.sanitizers ?? []).filter(s => s.method.includes('parse'));
    expect(credited.some(s => s.sanitizes.includes('command_injection'))).toBe(true);
  });
});
