/**
 * cognium-dev#682 — `require('child_process').exec(tainted)` with the module
 * required inline at the call was not a command_injection sink, while the
 * bound forms (`cp.exec`, destructured `exec`) were.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const handler = (body: string) => `
const express = require('express');
const app = express();
app.get('/run', (req, res) => { ${body} res.end(); });
`;

async function cmdi(code: string) {
  const r = await analyze(code, 'runner.js', 'javascript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
}

describe('cognium-dev#682 — inline require receiver', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it("require('child_process').exec(tainted) is command_injection", async () => {
    expect((await cmdi(handler("require('child_process').exec('ls ' + req.query.dir);"))).length).toBeGreaterThanOrEqual(1);
  });

  it("require('node:child_process').execSync(tainted) is command_injection", async () => {
    expect((await cmdi(handler("require('node:child_process').execSync('ls ' + req.query.dir);"))).length).toBeGreaterThanOrEqual(1);
  });

  it('bound module control still fires', async () => {
    const code = `const cp = require('child_process');\n${handler("cp.exec('ls ' + req.query.dir);")}`;
    expect((await cmdi(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('safe: constant command through the inline receiver stays clean', async () => {
    expect(await cmdi(handler("require('child_process').exec('ls -la');"))).toHaveLength(0);
  });

  it('safe: a different module with an exec method is not child_process', async () => {
    expect(await cmdi(handler("require('./child_process_helper').exec('ls ' + req.query.dir);"))).toHaveLength(0);
  });
});
