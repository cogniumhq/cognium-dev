/**
 * cognium-dev#629 — `res.status(400).end()` with no arguments is not an XSS
 * sink. The tainted name on that line is only the subject of a validation
 * test. A response writer still fires when the tainted value is an argument.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const xssFindings = async (code: string) => {
  const r = await analyze(code, 'guard-end.js', 'javascript');
  const fromFlows = generateFindings(
    r.taint.sources,
    r.taint.sinks,
    r.dfg,
    'guard-end.js',
    code,
    'javascript',
    r.taint.sanitizers,
    r.types,
    r.taint.flows,
  );
  const fromProximity = generateFindings(
    r.taint.sources,
    r.taint.sinks,
    r.dfg,
    'guard-end.js',
    code,
    'javascript',
  );
  return {
    sinks: r.taint.sinks.filter(s => s.type === 'xss').map(s => s.method),
    flows: r.taint.flows.filter(f => f.sink_type === 'xss'),
    findings: fromFlows.filter(f => f.type === 'xss'),
    proximity: fromProximity.filter(f => f.type === 'xss'),
  };
};

describe('#629 argument-less response writers are not XSS sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not report res.status(400).end() when the tainted value is only tested', async () => {
    const got = await xssFindings(`const express = require('express');
const app = express();
app.get('/f', (req, res) => {
  const label = req.query.label;
  if (!/^[a-z]+$/.test(label)) { return res.status(400).end(); }
  res.send('ok');
});
`);
    expect(got.sinks).not.toContain('end');
    expect(got.flows).toEqual([]);
    expect(got.findings).toEqual([]);
    expect(got.proximity).toEqual([]);
  });

  it('still reports res.send when the tainted value is written', async () => {
    const got = await xssFindings(`const express = require('express');
const app = express();
app.get('/f', (req, res) => {
  const label = req.query.label;
  res.send('<b>' + label + '</b>');
});
`);
    expect(got.sinks).toContain('send');
    expect(got.findings.length).toBeGreaterThan(0);
  });

  it('still reports res.end when the tainted value is the argument', async () => {
    const got = await xssFindings(`const express = require('express');
const app = express();
app.get('/f', (req, res) => {
  const label = req.query.label;
  res.end(label);
});
`);
    expect(got.sinks).toContain('end');
    expect(got.findings.length).toBeGreaterThan(0);
  });
});
