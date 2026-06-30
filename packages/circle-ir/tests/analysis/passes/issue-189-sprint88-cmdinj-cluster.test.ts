/**
 * Sprint 88 — #189 variant-regression: command_injection JS (4) cluster.
 *
 * Baseline against 3.137.0 corpus showed **0 of 4 FN** — all four
 * variants were already TP via the existing configured nodejs.json
 * sinks (Sprint 54 added execa.command/commandSync; child_process
 * exec/execFile/spawn have always been sinks). No new pattern detectors
 * are needed in this sprint.
 *
 * This test file pins the coverage as a regression guard:
 *   - js__cmdinj_v01_execa_command.js       — execa.command(taintedString)
 *   - js__cmdinj_v02_execfile_shc.js        — execFile('sh', ['-c', tainted])
 *   - js__cmdinj_v03_promisified_exec.js    — util.promisify(exec)(tainted)
 *   - js__cmdinj_v04_spawn_shc.js           — spawn('sh', ['-c', tainted])
 *
 * Paired TN controls verify the engine does NOT fire on literal-only
 * commands (no tainted argument).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasFlowOfType = (r: any, sinkType: string) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === sinkType);

const hasCmdInjSignal = (r: any) =>
  hasFlowOfType(r, 'command_injection') || hasFlowOfType(r, 'command_execution');

describe('#189 Sprint 88 — JS command_injection cluster (regression lockdown)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // V01 — execa.command(taintedString)

  it('V01-TP: execa.command(`ls ` + req.query.cmd) fires command_injection', async () => {
    const code = [
      "const express = require('express');",
      "const { execa } = require('execa');",
      'const app = express();',
      "app.get('/run', async (req, res) => {",
      '  const cmd = req.query.cmd;',
      "  const { stdout } = await execa.command('ls ' + cmd);",
      '  res.send(stdout);',
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(true);
  });

  it('V01-TN: execa.command(literal) does NOT fire', async () => {
    const code = [
      "const { execa } = require('execa');",
      "async function h() { return await execa.command('ls -la'); }",
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(false);
  });

  // V02 — execFile('sh', ['-c', tainted])

  it("V02-TP: execFile('sh', ['-c', `ls ` + tainted]) fires command_injection", async () => {
    const code = [
      "const express = require('express');",
      "const { execFile } = require('child_process');",
      'const app = express();',
      "app.get('/run', (req, res) => {",
      '  const cmd = req.query.cmd;',
      "  execFile('sh', ['-c', 'ls ' + cmd], (err, stdout) => {",
      "    if (err) return res.status(500).send('err');",
      '    res.send(stdout);',
      '  });',
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(true);
  });

  it('V02-TN: execFile with literal args does NOT fire', async () => {
    const code = [
      "const { execFile } = require('child_process');",
      "function h() { execFile('sh', ['-c', 'ls -la'], () => {}); }",
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(false);
  });

  // V03 — util.promisify(exec)(tainted)

  it('V03-TP: util.promisify(exec)(`ls ` + tainted) fires command_injection', async () => {
    const code = [
      "const express = require('express');",
      "const { exec } = require('child_process');",
      "const { promisify } = require('util');",
      'const execP = promisify(exec);',
      'const app = express();',
      "app.get('/run', async (req, res) => {",
      '  const cmd = req.query.cmd;',
      "  const { stdout } = await execP('ls ' + cmd);",
      '  res.send(stdout);',
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(true);
  });

  it('V03-TN: promisified exec with literal command does NOT fire', async () => {
    const code = [
      "const { exec } = require('child_process');",
      "const { promisify } = require('util');",
      'const execP = promisify(exec);',
      "async function h() { return await execP('ls -la'); }",
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(false);
  });

  // V04 — spawn('sh', ['-c', tainted])

  it("V04-TP: spawn('sh', ['-c', `ls ` + tainted]) fires command_injection", async () => {
    const code = [
      "const express = require('express');",
      "const { spawn } = require('child_process');",
      'const app = express();',
      "app.get('/run', (req, res) => {",
      '  const cmd = req.query.cmd;',
      "  const child = spawn('sh', ['-c', 'ls ' + cmd]);",
      "  let out = '';",
      "  child.stdout.on('data', (d) => (out += d.toString()));",
      "  child.on('close', () => res.send(out));",
      '});',
      'app.listen(3000);',
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(true);
  });

  it('V04-TN: spawn with literal args does NOT fire', async () => {
    const code = [
      "const { spawn } = require('child_process');",
      "function h() { spawn('sh', ['-c', 'ls -la']); }",
    ].join('\n');
    const r = await analyze(code, '/x/a.js', 'javascript');
    expect(hasCmdInjSignal(r)).toBe(false);
  });
});
