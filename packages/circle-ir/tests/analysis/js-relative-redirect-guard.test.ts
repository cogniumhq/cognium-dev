/**
 * CWE-601: the same-site relative-path guard in JS/TS, ternary form on the redirect line:
 *   res.redirect(next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/');
 * A target that starts with a single `/` and is neither `//…` (protocol-relative) nor `/\…` (read by browsers
 * as `//…`) cannot leave the site, so a guard that rejects both is credited for `open_redirect` (not for
 * crlf: a same-site path can still carry CR/LF). A guard that rejects only `//` is bypassable with
 * `/\evil.example` and is NOT credited. (The if-block forms are already dropped by the sink filter's stage 8a.)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const has = (flows: Array<{ sink_type?: string }> | undefined, t: string) => (flows ?? []).some((f) => f.sink_type === t);
const app = (line: string) => `const express = require('express');
const app = express();
app.get('/login', (req, res) => {
  const next = req.query.next;
  const other = req.query.other;
${line}
});
`;

describe('JS/TS relative redirect guard, ternary form (CWE-601)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  for (const [lang, ext] of [['javascript', 'js'], ['typescript', 'ts']] as const) {
    const flows = async (name: string, line: string) => (await analyze(app(line), `${name}.${ext}`, lang)).taint.flows;

    it(`${lang}: no guard — open_redirect`, async () => {
      expect(has(await flows('none', '  res.redirect(next);'), 'open_redirect')).toBe(true);
    });

    it(`${lang}: '/' and not '//' and not '/\\\\' ? next : '/' — open_redirect credited, crlf kept`, async () => {
      const f = await flows('full', "  res.redirect(next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\\\') ? next : '/');");
      expect(has(f, 'open_redirect')).toBe(false);
      expect(has(f, 'crlf')).toBe(true);
    });

    it(`${lang}: strict regex /^\\/(?![\\/\\\\])/.test(next) ? next : '/' — credited`, async () => {
      expect(has(await flows('regex', "  res.redirect(/^\\/(?![\\/\\\\])/.test(next) ? next : '/');"), 'open_redirect')).toBe(false);
    });

    it(`${lang}: only '//' rejected (bypassable with '/\\\\evil') — still open_redirect`, async () => {
      expect(has(await flows('only-double', "  res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');"), 'open_redirect')).toBe(true);
    });

    it(`${lang}: a complete guard on another value redirecting next — still open_redirect`, async () => {
      expect(has(await flows('other-var', "  res.redirect(other.startsWith('/') && !other.startsWith('//') && !other.startsWith('/\\\\') ? next : '/');"), 'open_redirect')).toBe(true);
    });

    it(`${lang}: the guarded value is the fallback, not the consequent — still open_redirect`, async () => {
      expect(has(await flows('inverted', "  res.redirect(next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\\\') ? '/' : next);"), 'open_redirect')).toBe(true);
    });
  }
});
