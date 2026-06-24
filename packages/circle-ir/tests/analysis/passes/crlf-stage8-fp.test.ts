/**
 * Tests for cognium-dev #132 — JS/TS CRLF / open_redirect Stage 8 FP
 * suppression (CWE-113 / CWE-601).
 *
 * The fix extends the existing Stage 8 filter in
 * `sink-filter-pass.ts:241-283` along two axes:
 *
 *   1. `guardPatterns` regex extension — adds the `has` method to the
 *      allowlist primitive set, recognising Set / Map allowlist guards:
 *
 *        if (ALLOWED.has(url)) res.redirect(url);
 *
 *      This mirrors the existing `.includes/.startsWith/.endsWith/
 *      .indexOf/.test/.match` window-of-6 guard logic.
 *
 *   2. New sub-stage 8d — Express/Koa `res.cookie(name, value, [opts])`
 *      is CRLF-safe by construction because the cookie helper
 *      serialises via `cookie.serialize()` which URL-encodes CR (%0D)
 *      and LF (%0A). Only `sink.method === 'cookie'` AND
 *      `sink.type === 'crlf'` are suppressed; the raw-header path
 *      `setHeader('Set-Cookie', tainted)` is unaffected and keeps
 *      firing.
 *
 * Recall lock: bare `res.redirect(req.query.url)` and bare
 * `res.setHeader('Location', req.query.url)` (no allowlist, no cookie
 * helper) continue to emit a `crlf`-type sink.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countCrlfSinks = (
  sinks: Array<{ type?: string }> | undefined,
) => (sinks ?? []).filter((s) => s.type === 'crlf').length;

describe('cognium-dev #132 — JS/TS CRLF Stage 8 FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP-suppression: `.has` Set/Map allowlist guard
  // -------------------------------------------------------------------------

  it('JS — if (ALLOWED.has(url)) res.redirect(url): no crlf sink', async () => {
    const code = `const express = require('express');
const app = express();
const ALLOWED_REDIRECTS = new Set(['/home', '/profile', '/settings']);

app.get('/go', (req, res) => {
  const target = req.query.url;
  if (ALLOWED_REDIRECTS.has(target)) {
    res.redirect(target);
  } else {
    res.status(400).send('Invalid redirect target');
  }
});
`;
    const r = await analyze(code, 'safe_routes.js', 'javascript');
    expect(countCrlfSinks(r.taint?.sinks)).toBe(0);
  });

  it('TS — Set<string> allowlist + res.redirect(url): no crlf sink', async () => {
    const code = `import express from 'express';
const app = express();
const ALLOWED: Set<string> = new Set(['/cb1', '/cb2']);

app.get('/auth/callback', (req, res) => {
  const next = String(req.query.next ?? '');
  if (ALLOWED.has(next)) {
    res.redirect(next);
  } else {
    res.status(400).send('bad next');
  }
});
`;
    const r = await analyze(code, 'safe_server.ts', 'typescript');
    expect(countCrlfSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // FP-suppression: `res.cookie(...)` helper (sub-stage 8d)
  // -------------------------------------------------------------------------

  it('JS — res.cookie(name, value, {secure,httpOnly,sameSite}): no crlf sink', async () => {
    const code = `const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  const session = req.query.sid;
  res.cookie('session', session, { secure: true, httpOnly: true, sameSite: 'lax' });
  res.send('ok');
});
`;
    const r = await analyze(code, 'safe_routes.js', 'javascript');
    expect(countCrlfSinks(r.taint?.sinks)).toBe(0);
  });

  it('JS — res.cookie(name, value) 2-arg form: no crlf sink', async () => {
    const code = `const express = require('express');
const app = express();

app.get('/track', (req, res) => {
  const id = req.query.id;
  res.cookie('tracking_id', id);
  res.send('ok');
});
`;
    const r = await analyze(code, 'safe_routes.js', 'javascript');
    expect(countCrlfSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall: bare unguarded shapes still fire
  // -------------------------------------------------------------------------

  it('Recall — bare res.redirect(req.query.url): emits crlf sink', async () => {
    const code = `const express = require('express');
const app = express();

app.get('/r', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});
`;
    const r = await analyze(code, 'unsafe.js', 'javascript');
    expect(countCrlfSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — raw setHeader Location with tainted value: emits crlf sink', async () => {
    const code = `const express = require('express');
const app = express();

app.get('/rh', (req, res) => {
  const loc = req.query.dest;
  res.setHeader('Location', loc);
  res.status(302).end();
});
`;
    const r = await analyze(code, 'unsafe.js', 'javascript');
    expect(countCrlfSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Regression: existing `.includes` guard (cognium-dev #99) still suppresses
  // -------------------------------------------------------------------------

  it('Regression — if (ALLOWED.includes(url)) res.redirect(url): no crlf sink', async () => {
    const code = `const express = require('express');
const app = express();
const ALLOWED = ['/a', '/b', '/c'];

app.get('/legacy', (req, res) => {
  const target = req.query.url;
  if (ALLOWED.includes(target)) {
    res.redirect(target);
  } else {
    res.status(400).send('bad');
  }
});
`;
    const r = await analyze(code, 'legacy.js', 'javascript');
    expect(countCrlfSinks(r.taint?.sinks)).toBe(0);
  });
});
