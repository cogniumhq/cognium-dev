import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 55 — #184 XSS: Angular `DomSanitizer.bypassSecurityTrust*` family
 * must be recognised as `xss` sinks. These methods explicitly bypass
 * Angular's built-in sanitization and re-introduce DOM-injection risk
 * when tainted input flows in.
 *
 * Recall lock: React.createElement with dangerouslySetInnerHTML
 * (already-shipped shape) must keep firing.
 */
describe('Sprint 55 — #184 Angular DomSanitizer XSS', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — bypassSecurityTrustHtml(taint) must fire xss', async () => {
    // Use Express + DomSanitizer to provide an HTTP-derived taint source
    // (Angular's own ActivatedRoute source-recognition is independent and
    // out of Sprint 55 scope; sink presence is what we're testing).
    const code = `import { DomSanitizer } from '@angular/platform-browser';
const express = require('express');
const app = express();
const sanitizer = {} as DomSanitizer;
app.get('/p', (req, res) => {
  const out = sanitizer.bypassSecurityTrustHtml(req.query.q);
  res.send(out);
});`;
    const r = await analyze(code, 'angular-html.ts', 'typescript');
    expect(countFlows(r, 'xss')).toBeGreaterThanOrEqual(1);
  });

  it('FN — bypassSecurityTrustScript(taint) must fire xss', async () => {
    const code = `import { DomSanitizer } from '@angular/platform-browser';
const express = require('express');
const app = express();
const sanitizer = {} as DomSanitizer;
app.get('/p', (req, res) => {
  const out = sanitizer.bypassSecurityTrustScript(req.query.q);
  res.send(out);
});`;
    const r = await analyze(code, 'angular-script.ts', 'typescript');
    expect(countFlows(r, 'xss')).toBeGreaterThanOrEqual(1);
  });

  it('FN — bypassSecurityTrustResourceUrl(taint) must fire xss', async () => {
    const code = `import { DomSanitizer } from '@angular/platform-browser';
const express = require('express');
const app = express();
const sanitizer = {} as DomSanitizer;
app.get('/p', (req, res) => {
  const out = sanitizer.bypassSecurityTrustResourceUrl(req.query.q);
  res.send(out);
});`;
    const r = await analyze(code, 'angular-resurl.ts', 'typescript');
    expect(countFlows(r, 'xss')).toBeGreaterThanOrEqual(1);
  });

  it('recall — React.createElement dSIH still fires', async () => {
    const code = `const express = require('express');
const React = require('react');
const app = express();
app.get('/p', (req, res) => {
  const el = React.createElement('div', { dangerouslySetInnerHTML: { __html: req.query.q } });
  res.send(el);
});`;
    const r = await analyze(code, 'react.js', 'javascript');
    expect(countFlows(r, 'xss')).toBeGreaterThanOrEqual(1);
  });
});
