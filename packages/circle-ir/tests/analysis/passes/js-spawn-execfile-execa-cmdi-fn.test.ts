/**
 * Sprint 54 — cognium-dev #187: JS command_injection FNs across four
 * variants from variant-regression/command_injection probe.
 *
 *   v04 — spawn('sh', ['-c', 'echo '+taint])   — argv array taint, sh -c
 *   v05 — execFile('/bin/sh', ['-c', taint])   — argv array taint, /bin/sh
 *   v06 — execa.command(taint)                 — library wrapper sink not modeled
 *   v08 — util.promisify(exec)(taint)          — promisified alias not propagated
 *
 * Current sink configs at `configs/sinks/nodejs.json:38-86`:
 *   - spawn / spawnSync     arg_positions: [0, 1]  (Collection + classless)
 *   - execFile              arg_positions: [0, 1]
 *   - exec / execSync       arg_positions: [0]
 *
 * Hypothesis for v04/v05: arg[1] is an array literal containing tainted
 * expressions — the engine's regex scan likely does not walk array-element
 * positions for variable extraction. Symmetric to #194/#195 nested
 * collection-value gap.
 *
 * v06: `execa.command` is not registered anywhere in the codebase.
 * v08: `util.promisify` is not tracked as a sink-preserving alias.
 *
 * Recall locks: non-shell programs (`spawn('git', ['clone', taint])`)
 * MUST NOT fire (false-positive guard for argv-of-non-shell case).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countCmdiFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'command_injection').length;

describe('cognium-dev #187 — JS command_injection FNs (spawn/execFile/execa/promisify)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('v04 FN — spawn("sh", ["-c", "echo "+taint]) fires command_injection', async () => {
    const code = `const express = require('express');
const { spawn } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  const taint = req.query.cmd || '';
  spawn('sh', ['-c', 'echo ' + taint]);
  res.end('ok');
});
`;
    const r = await analyze(code, 'v04.js', 'javascript');
    expect(countCmdiFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('v05 FN — execFile("/bin/sh", ["-c", taint]) fires command_injection', async () => {
    const code = `const express = require('express');
const { execFile } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  const taint = req.query.cmd || '';
  execFile('/bin/sh', ['-c', taint]);
  res.end('ok');
});
`;
    const r = await analyze(code, 'v05.js', 'javascript');
    expect(countCmdiFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('v06 FN — execa.command(taint) fires command_injection', async () => {
    const code = `const express = require('express');
const execa = require('execa');
const app = express();

app.get('/run', (req, res) => {
  const taint = req.query.cmd || '';
  execa.command(taint);
  res.end('ok');
});
`;
    const r = await analyze(code, 'v06.js', 'javascript');
    expect(countCmdiFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('v08 FN — util.promisify(exec)(taint) fires command_injection', async () => {
    const code = `const express = require('express');
const util = require('util');
const { exec } = require('child_process');
const app = express();
const execAsync = util.promisify(exec);

app.get('/run', async (req, res) => {
  const taint = req.query.cmd || '';
  await execAsync(taint);
  res.end('ok');
});
`;
    const r = await analyze(code, 'v08.js', 'javascript');
    expect(countCmdiFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — spawn("git", ["clone", taint]) non-shell does NOT fire (FP guard)', async () => {
    const code = `const express = require('express');
const { spawn } = require('child_process');
const app = express();

app.get('/clone', (req, res) => {
  const taint = req.query.repo || '';
  spawn('git', ['clone', taint]);
  res.end('ok');
});
`;
    const r = await analyze(code, 'git.js', 'javascript');
    expect(countCmdiFlows(r.taint?.flows)).toBe(0);
  });

  it('recall — exec(taint) baseline still fires (control)', async () => {
    const code = `const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  const taint = req.query.cmd || '';
  exec('echo ' + taint);
  res.end('ok');
});
`;
    const r = await analyze(code, 'baseline.js', 'javascript');
    expect(countCmdiFlows(r.taint?.flows)).toBeGreaterThan(0);
  });
});
