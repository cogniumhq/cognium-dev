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

  // #1257 review B1: a guard credits only its own handler, and only until the variable is reassigned. The sinks
  // sit more than 6 lines below any `if (…startsWith…)` so the sink filter's stage 8a (any such `if` within 6
  // lines drops a JS open_redirect sink) does not decide these cases.
  describe('guard credit stays in its own handler', () => {
    const guard = "  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\\\')) return res.redirect('/');";
    const pad = Array.from({ length: 7 }, (_, k) => `  res.locals.k${k} = ${k};`).join('\n');
    for (const [lang, ext] of [['javascript', 'js'], ['typescript', 'ts']] as const) {
      it(`${lang}: the guarded handler is credited; a second handler using next is not`, async () => {
        const code = `const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  const next = req.query.next;
${guard}
${pad}
  res.redirect(next);
});
app.get('/b', (req, res) => {
  const next = req.query.next;
${pad}
  res.redirect(next);
});
`;
        const lines = code.split('\n');
        const sinkA = lines.findIndex((l, k) => k > 4 && l.includes('res.redirect(next);')) + 1;
        const sinkB = lines.findIndex((l, k) => k >= sinkA && l.includes('res.redirect(next);')) + 1;
        const r = await analyze(code, `two.${ext}`, lang);
        const got = (r.taint.flows ?? []).filter((f: any) => f.sink_type === 'open_redirect').map((f: any) => f.sink_line);
        expect(got).toContain(sinkB);
        expect(got).not.toContain(sinkA);
      });

      it(`${lang}: the variable reassigned after the guard is not credited`, async () => {
        const code = `const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  let next = req.query.next;
${guard}
${pad}
  next = req.query.other;
  res.redirect(next);
});
`;
        const r = await analyze(code, `reassign.${ext}`, lang);
        expect(has(r.taint.flows, 'open_redirect')).toBe(true);
      });

      it(`${lang}: a block-form reject guard credits the rest of its handler`, async () => {
        const code = `const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  const next = req.query.next;
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\\\')) {
    return res.redirect('/');
  }
${pad}
  res.redirect(next);
});
`;
        const r = await analyze(code, `block.${ext}`, lang);
        expect(has(r.taint.flows, 'open_redirect')).toBe(false);
      });
    }
  });

  describe('path guard credit stays in its own handler (same helper)', () => {
    for (const [lang, ext] of [['javascript', 'js'], ['typescript', 'ts']] as const) {
      it(`${lang}: a path.resolve + startsWith guard in one handler does not sanitize another handler's \`full\``, async () => {
        const code = `const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const ROOT = '/srv/files';
app.get('/a', (req, res) => {
  const full = path.resolve(ROOT, req.query.name);
  if (!full.startsWith(ROOT)) return res.status(400).end();
  res.send(fs.readFileSync(full));
});
app.get('/b', (req, res) => {
  const full = req.query.name;
  res.send(fs.readFileSync(full));
});
`;
        const r = await analyze(code, `paths.${ext}`, lang);
        const lines = (r.taint.flows ?? []).filter((f: any) => f.sink_type === 'path_traversal').map((f: any) => f.sink_line);
        expect(lines).toContain(13);
        expect(lines).not.toContain(9);
      });
    }
  });
});

