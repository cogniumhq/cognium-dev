/**
 * CWE-502 from a cookie: `serialize.unserialize(req.cookies.x)` is the classic Node.js RCE (the
 * node-serialize advisory's exploit arrives in a cookie). The source-to-sink reach map allowed
 * deserialization from request params, query and body but not from cookies, so the cookie form was
 * dropped while the `req.body` form fired. `req.signedCookies` stays out of scope: a signed cookie's
 * value is integrity-protected by the server's secret, so it is not attacker-chosen.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { canSourceReachSink } from '../../src/analysis/findings.js';

const hasFlow = (flows: Array<{ sink_type?: string; source_type?: string }> | undefined, sink: string, source?: string) =>
  (flows ?? []).some((f) => f.sink_type === sink && (!source || f.source_type === source));

describe('deserialization from a cookie (CWE-502)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('the reach map lets a cookie reach a deserialization sink', () => {
    expect(canSourceReachSink('http_cookie', 'deserialization')).toBe(true);
  });

  for (const [lang, ext] of [['javascript', 'js'], ['typescript', 'ts']] as const) {
    it(`${lang}: serialize.unserialize(req.cookies.profile) fires deserialization`, async () => {
      const code = `const express = require('express');
const serialize = require('node-serialize');
const app = express();
app.get('/profile', (req, res) => {
  const profile = serialize.unserialize(req.cookies.profile);
  res.send(profile.name);
});
`;
      const r = await analyze(code, `cookie-unser.${ext}`, lang);
      expect(hasFlow(r.taint.flows, 'deserialization')).toBe(true);
    });

    it(`${lang}: a local copy of req.cookies.session into unserialize fires deserialization`, async () => {
      const code = `const express = require('express');
const { unserialize } = require('node-serialize');
const app = express();
app.get('/me', (req, res) => {
  const raw = req.cookies.session;
  const s = unserialize(raw);
  res.json(s);
});
`;
      const r = await analyze(code, `cookie-unser2.${ext}`, lang);
      expect(hasFlow(r.taint.flows, 'deserialization')).toBe(true);
    });

    it(`${lang}: JSON.parse of a cookie and unserialize of a literal do not fire deserialization`, async () => {
      const code = `const express = require('express');
const serialize = require('node-serialize');
const app = express();
app.get('/safe', (req, res) => {
  const prefs = JSON.parse(req.cookies.prefs || '{}');
  const fixed = serialize.unserialize('{"a":1}');
  res.json({ prefs, fixed });
});
`;
      const r = await analyze(code, `cookie-safe.${ext}`, lang);
      expect(hasFlow(r.taint.flows, 'deserialization')).toBe(false);
    });
  }
});
