/**
 * Tests for cognium-dev #216 sanitizer-wrapped FP cluster — JavaScript
 * `log_injection` (CWE-117) FP suppression on CRLF-stripping sanitizers
 * (Stage 16 in `sink-filter-pass.ts`, Sprint 52).
 *
 * Recognised patterns:
 *   - inline `stripCrlf(...)` / `sanitizeLogValue(...)` etc.
 *   - inline `.replace(/[\r\n]/g, '')` regex literal
 *   - variable on sink line assigned within 30 lines above from a
 *     sanitizer-pattern RHS
 *
 * Recall locks:
 *   - non-CRLF `.replace(/x/g, '')` does NOT suppress
 *   - missing sanitizer still fires
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countLogSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'log_injection').length;
const countLogFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'log_injection').length;

describe('cognium-dev #216 — JS log_injection sanitizer FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ---------------------------------------------------------------------------
  // FP suppression — sanitizer on sink line
  // ---------------------------------------------------------------------------

  it('FP — inline stripCrlf call on sink line', async () => {
    const code = `const express = require('express');
const app = express();
function stripCrlf(s) { return String(s).replace(/[\\r\\n]/g, ''); }
app.get('/wrapped', (req, res) => { console.log('a ' + stripCrlf(req.query.user || '')); res.end(); });
module.exports = app;
`;
    const r = await analyze(code, 'sanitizer_combos_loginj.js', 'javascript');
    expect(countLogSinks(r.taint?.sinks)).toBe(0);
    expect(countLogFlows(r.taint?.flows)).toBe(0);
  });

  it('FP — variable assigned from stripCrlf above the sink', async () => {
    const code = `const express = require('express');
const app = express();
function stripCrlf(s) { return String(s).replace(/[\\r\\n]/g, ''); }
app.get('/multiline', (req, res) => {
  const cleaned = stripCrlf(req.query.user || '');
  console.log('user=' + cleaned);
  res.end();
});
module.exports = app;
`;
    const r = await analyze(code, 'multiline_loginj.js', 'javascript');
    expect(countLogFlows(r.taint?.flows)).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Recall locks
  // ---------------------------------------------------------------------------

  it('recall — non-CRLF .replace(/x/g, "") does NOT suppress', async () => {
    const code = `const express = require('express');
const app = express();
function stripX(s) { return String(s).replace(/x/g, ''); }
app.get('/fake', (req, res) => { console.log('a ' + stripX(req.query.user || '')); res.end(); });
module.exports = app;
`;
    const r = await analyze(code, 'wrong_strip.js', 'javascript');
    expect(countLogFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — missing sanitizer still fires', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/raw', (req, res) => { console.log('a ' + (req.query.user || '')); res.end(); });
module.exports = app;
`;
    const r = await analyze(code, 'raw_loginj.js', 'javascript');
    expect(countLogFlows(r.taint?.flows)).toBeGreaterThan(0);
  });
});
