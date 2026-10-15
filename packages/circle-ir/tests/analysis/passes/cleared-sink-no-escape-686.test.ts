/**
 * cognium-dev #686 — a redirect whose sink SinkFilterPass cleared (an
 * allowlist / prefix guard above it) came back as `external_taint_escape`.
 *
 * Once the argument-less `res.status(403).end()` stopped counting as an XSS
 * sink (#629) the file had no sink left, so the no-sink fallback treated
 * `res.redirect(dest)` as an unknown external method and re-reported it.
 * A call the sink registry matched is not unknown: if the filter cleared it,
 * the fallback must not report it again.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

async function types(code: string, file: string): Promise<string[]> {
  const ir = await analyze(code, file, 'javascript');
  return (ir.taint.flows ?? []).map(f => f.sink_type);
}

beforeAll(async () => {
  await initAnalyzer();
});

describe('#686 guarded redirect is not re-reported as an escape', () => {
  const guarded = `const express = require('express');
const app = express();
app.get('/continue', (req, res) => {
  const dest = String(req.query.to || '');
  if (!dest.startsWith('/account/')) return res.status(400).end();
  res.redirect(dest);
});
`;

  it('guarded redirect: no flow at all', async () => {
    expect(await types(guarded, 'continue_route.js')).toEqual([]);
  });

  it('guard via allowlist Set: no flow', async () => {
    const code = `const express = require('express');
const app = express();
const PAGES = new Set(['/home', '/settings']);
app.get('/continue', (req, res) => {
  const dest = String(req.query.to || '');
  if (!PAGES.has(dest)) return res.status(400).end();
  res.redirect(dest);
});
`;
    expect(await types(code, 'continue_allowlist.js')).toEqual([]);
  });

  it('unguarded redirect still reports open_redirect', async () => {
    const code = guarded.replace("  if (!dest.startsWith('/account/')) return res.status(400).end();\n", '');
    expect(await types(code, 'continue_open.js')).toContain('open_redirect');
  });

  it('an unrelated external call with the same request value still escapes', async () => {
    const code = `const express = require('express');
const audit = require('./audit');
const app = express();
app.get('/continue', (req, res) => {
  const dest = String(req.query.to || '');
  audit.record(dest);
  res.end();
});
`;
    expect(await types(code, 'continue_audit.js')).toContain('external_taint_escape');
  });
});
