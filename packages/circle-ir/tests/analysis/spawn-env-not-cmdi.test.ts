/**
 * E2 / E6: the spawn family with an argument array and no shell.
 *
 * E2: a program with `{ env: { ...process.env, X: v } }` in the options
 *     object is not command injection: the environment is not the command line.
 * E6: a program read from an operator environment variable, run with an
 *     argument array and no shell, is argument injection at most: tagged and
 *     reported at medium, not critical shell command injection.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { ARGV_NO_SHELL_TAG, classifyJsSpawnTaint, jsCallArgs } from '../../src/analysis/js-spawn-argv.js';

const cmdFlows = async (code: string) =>
  ((await analyze(code, 'r.ts', 'typescript')).taint.flows ?? []).filter(f => f.sink_type === 'command_injection');

const cmdFindings = async (code: string) => {
  const ir = await analyze(code, 'r.ts', 'typescript');
  return generateFindings(ir.taint.sources, ir.taint.sinks, ir.dfg, 'r.ts', code, 'typescript',
    ir.taint.sanitizers ?? [], ir.types, ir.taint.flows).filter(f => f.type === 'command_injection');
};

const route = (body: string) =>
  `import { spawn, spawnSync, execFile, exec } from 'child_process';\n` +
  `import express from 'express';\nconst GIT = 'git';\nconst app = express();\n` +
  `app.get('/r', (req, res) => {\n  const v = req.query.v;\n  ${body}\n  res.send('ok');\n});\n`;

describe('spawn family: env in options is not command injection (E2)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a named program with process.env spread into env is not flagged', async () => {
    const code =
      `import { spawn } from 'child_process';\n` +
      `const GIT = '/usr/bin/git';\n` +
      `export function run(key: string) {\n` +
      `  return spawn(GIT, ['status'], { env: { ...process.env, API_KEY: key } });\n` +
      `}\n`;
    expect(await cmdFlows(code)).toHaveLength(0);
  });

  it('request data in env next to a named program is not flagged', async () => {
    expect(await cmdFlows(route(`spawn(GIT, ['status'], { env: { ...process.env, TOKEN: v } });`))).toHaveLength(0);
  });

  it('spawnSync / execFile with env in a multi-line options object are not flagged', async () => {
    expect(await cmdFlows(route(
      `spawnSync(GIT, ['fetch'], {\n    cwd: '/tmp',\n    env: { ...process.env, MODE: v },\n  });`))).toHaveLength(0);
    expect(await cmdFlows(route(`execFile(GIT, ['fetch'], { env: { ...process.env, X: v } }, () => {});`))).toHaveLength(0);
  });

  it('an env object built first and passed by name is not flagged', async () => {
    expect(await cmdFlows(route(`const env = { ...process.env, X: v };\n  spawn(GIT, ['status'], { env });`))).toHaveLength(0);
  });
});

describe('spawn family: program from an operator env var, argv, no shell (E6)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const e6 =
    `import { spawn } from 'child_process';\n` +
    `const bin = process.env.EDITOR_BIN;\n` +
    `export function open(file: string) {\n` +
    `  return spawn(bin, [file], { stdio: 'inherit' });\n` +
    `}\n`;

  it('the flow is tagged argument injection', async () => {
    const flows = await cmdFlows(e6);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(f => f.tags?.includes(ARGV_NO_SHELL_TAG))).toBe(true);
  });

  it('the finding is medium, not critical', async () => {
    const findings = await cmdFindings(e6);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every(f => f.severity === 'medium')).toBe(true);
  });

  it('inline env program and a `??` default with a callback are tagged too', async () => {
    const inline =
      `import { spawnSync } from 'child_process';\n` +
      `export function fmt(file: string) {\n  return spawnSync(process.env.FORMATTER, ['--write', file]);\n}\n`;
    const withDefault =
      `import { execFile } from 'child_process';\n` +
      `export function fmt(file: string) {\n  const tool = process.env.TOOL ?? 'prettier';\n` +
      `  execFile(tool, ['--write', file], () => {});\n}\n`;
    for (const code of [inline, withDefault]) {
      const flows = await cmdFlows(code);
      expect(flows.length).toBeGreaterThan(0);
      expect(flows.every(f => f.tags?.includes(ARGV_NO_SHELL_TAG))).toBe(true);
    }
  });

  it('request data in argv of a named non-shell program is argument injection', async () => {
    const flows = await cmdFlows(route(`spawn(GIT, ['clone', v]);`));
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(f => f.tags?.includes(ARGV_NO_SHELL_TAG))).toBe(true);
  });
});

describe('spawn family: true positives kept', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const untagged = async (code: string) => {
    const flows = await cmdFlows(code);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => !f.tags?.includes(ARGV_NO_SHELL_TAG))).toBe(true);
  };

  it('exec with a tainted template string', async () => {
    await untagged(route('exec(`ls ${v}`);'));
  });

  it('spawn with a tainted command and shell: true', async () => {
    await untagged(route('spawn(v, { shell: true });'));
  });

  it('a request-tainted program stays command injection', async () => {
    await untagged(route(`spawn(v, ['x']);`));
  });

  it('shell: true with a literal program and tainted argv', async () => {
    await untagged(route(`spawn('ls', [v], { shell: true });`));
  });

  it('an interpolated template program under shell: true, with tainted env too', async () => {
    await untagged(route('spawn(`ls ${v}`, [], { shell: true, env: { ...process.env, X: v } });'));
  });

  it('a named shell program with -c keeps critical', async () => {
    const findings = await cmdFindings(route(`const SH = 'sh';\n  spawn(SH, ['-c', v]);`));
    expect(findings.some(f => f.severity === 'critical' || f.severity === 'high')).toBe(true);
  });
});

describe('classifyJsSpawnTaint', () => {
  const at = (stmt: string, carriers: string[], env = false) =>
    classifyJsSpawnTaint(`const GIT = 'git';\nconst SH = 'bash';\n${stmt}`, 3, /\b(\w+)\(/.exec(stmt)![1]!, carriers, env);

  it('reads arguments across lines and nesting', () => {
    expect(jsCallArgs(['spawn(a, [b, `c,${d}`], {', '  env: { x: f(1, 2) },', '});'], 1, 'spawn'))
      .toEqual(['a', '[b, `c,${d}`]', '{\n  env: { x: f(1, 2) },\n}']);
  });

  it('options-only taint', () => {
    expect(at(`spawn(GIT, ['x'], { cwd: v });`, ['v'])).toBe('options-only');
    expect(at(`spawn(GIT, { env: { ...process.env } });`, ['process.env'])).toBe('options-only');
  });

  it('a tainted shell option value picks the program', () => {
    expect(at(`spawn(GIT, ['x'], { shell: v });`, ['v'])).toBe('command');
  });

  it('argv-no-shell needs a visible non-shell program and no shell', () => {
    expect(at(`spawn(GIT, ['x', v]);`, ['v'])).toBe('argv-no-shell');
    expect(at(`spawn(process.execPath, ['x.js', v]);`, ['v'])).toBe('argv-no-shell');
    expect(at(`spawn(SH, ['x', v]);`, ['v'])).toBe('command');
    expect(at(`spawn(other, ['x', v]);`, ['v'])).toBe('command');
    expect(at(`spawn(GIT, ['x', v], opts);`, ['v'])).toBe('command');
    expect(at(`spawn(GIT, args);`, ['args'])).toBe('command');
    expect(at(`spawn(GIT, ['-c', v]);`, ['v'])).toBe('command');
    expect(at(`spawn(GIT, ['x', v], { shell: true });`, ['v'])).toBe('command');
  });

  it('a tainted program is argument injection only when it comes from the environment', () => {
    expect(at(`spawn(bin, ['x']);`, ['bin'], true)).toBe('argv-no-shell');
    expect(at(`spawn(bin, ['x']);`, ['bin'], false)).toBe('command');
    expect(at(`spawn(bin, ['x'], { shell: false });`, ['bin'], true)).toBe('argv-no-shell');
  });

  it('other methods are left alone', () => {
    expect(at(`exec(v, { env: {} });`, ['v'])).toBe('command');
  });
});
