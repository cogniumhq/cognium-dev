/**
 * cognium-dev#1332 slice S2 — anchored allowlist + early-return reject guard
 * credits safe BenchProctor express_ts shapes (cmdi / xpathi / sqli).
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

describe('cognium-dev #1332 anchored allowlist reject guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsOf = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint.flows ?? []).filter(f => f.sink_type === type);

  it('safe cmdi: allowlist regex + return before execSync (negative)', async () => {
    const code = `
import childProcess from 'child_process';
export function BenchmarkTest00087Safe(req, res) {
  const userInput = req.query.data;
  const data = Buffer.from(userInput, 'base64').toString();
  const processed = data;
  if (!/^(asc|desc|name|created)$/.test(String(data))) {
    res.status(400).json({ error: 'invalid' });
    return;
  }
  childProcess.execSync('echo ' + processed);
}`;
    const r = await analyze(code, 'cmdi-allowlist-safe.ts', 'typescript');
    expect(flowsOf(r, 'command_injection')).toHaveLength(0);
  });

  it('bad cmdi: no allowlist guard still fires (positive control)', async () => {
    const code = `
import childProcess from 'child_process';
export function BenchmarkTest00087Bad(req) {
  const userInput = req.query.data;
  const data = Buffer.from(userInput, 'base64').toString();
  childProcess.execSync('echo ' + data);
}`;
    const r = await analyze(code, 'cmdi-allowlist-bad.ts', 'typescript');
    expect(flowsOf(r, 'command_injection').length).toBeGreaterThan(0);
  });

  it('safe xpathi: allowlist regex + return before xpath.select (negative)', async () => {
    const code = `
import xpath from 'xpath';
export function BenchmarkTest00047Safe(req, res, xmlDoc) {
  const userInput = req.query.data;
  const data = Buffer.from(userInput, 'base64').toString();
  const processed = data;
  if (!/^(user|admin)$/.test(processed)) {
    res.status(400).json({ error: 'invalid' });
    return;
  }
  xpath.select("//user[name='" + processed + "']", xmlDoc);
}`;
    const r = await analyze(code, 'xpath-allowlist-safe.ts', 'typescript');
    expect(flowsOf(r, 'xpath_injection')).toHaveLength(0);
  });

  it('bad xpathi: missing guard still fires (positive control)', async () => {
    const code = `
import xpath from 'xpath';
export function BenchmarkTest00047Bad(req, xmlDoc) {
  const data = Buffer.from(req.query.data, 'base64').toString();
  xpath.select("//user[name='" + data + "']", xmlDoc);
}`;
    const r = await analyze(code, 'xpath-allowlist-bad.ts', 'typescript');
    expect(flowsOf(r, 'xpath_injection').length).toBeGreaterThan(0);
  });
});