/**
 * #670 — a login relay that forwards credentials with node http.request.
 *
 * 1. `JSON.stringify(...)` of request data is a pure serializer call, not an
 *    external_taint_escape: the string comes straight back to the caller.
 * 2. `const up = http.request('http://…'); up.write(payload)` where `payload`
 *    carries a credential is CWE-523 cleartext credential transport. Before,
 *    only the inline-argument form was recognised, so the relay reported
 *    nothing but the stringify escape, and its https twin looked the same.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const relay = (mod: 'http' | 'https', ...body: string[]) =>
  [
    "'use strict';",
    "const express = require('express');",
    `const ${mod} = require('${mod}');`,
    'const app = express();',
    '',
    "app.post('/signin', express.urlencoded({ extended: false }), (req, res) => {",
    ...body.map((l) => '  ' + l),
    "  res.end('done');",
    '});',
    'module.exports = app;',
  ].join('\n');

const scan = async (code: string) => {
  const r = await analyze(code, 'relay.js', 'javascript');
  return {
    flows: (r.taint.flows ?? []).map((f) => f.sink_type),
    cwe523: r.findings.filter((f) => f.cwe === 'CWE-523').map((f) => f.line),
  };
};

const PAYLOAD = 'const payload = JSON.stringify({ name: req.body.login, p: req.body.password });';

describe('#670 — credential relay over node http.request', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the https relay is clean', async () => {
    const r = await scan(relay('https', PAYLOAD,
      "const up = https.request('https://idp.example.test/signin', { method: 'POST' });",
      'up.write(payload); up.end();'));
    expect(r.flows).toEqual([]);
    expect(r.cwe523).toEqual([]);
  });

  it('the http relay reports CWE-523 on the request', async () => {
    const r = await scan(relay('http', PAYLOAD,
      "const up = http.request('http://idp.example.test/signin', { method: 'POST' });",
      'up.write(payload); up.end();'));
    expect(r.cwe523).toEqual([8]);
    expect(r.flows).not.toContain('external_taint_escape');
  });

  it('an inline credential body passed to end() reports CWE-523', async () => {
    const r = await scan(relay('http',
      "const up = http.request('http://idp.example.test/signin', { method: 'POST' });",
      'up.end(JSON.stringify({ password: req.body.password }));'));
    expect(r.cwe523).toEqual([7]);
  });

  it.each([
    ['a body without a credential', 'const payload = JSON.stringify({ term: req.body.term });',
      "const up = http.request('http://search.example.test/q', { method: 'POST' });", 'up.write(payload); up.end();'],
    ['a credential sent to localhost', PAYLOAD,
      "const up = http.request('http://localhost:8080/signin', { method: 'POST' });", 'up.write(payload); up.end();'],
    ['a credential written to a different request', PAYLOAD,
      "const up = http.request('http://idp.example.test/signin', { method: 'POST' });",
      "const other = http.request('https://idp.example.test/signin');", 'up.end();', 'other.write(payload);'],
  ])('%s is not CWE-523', async (_n, ...body) => {
    expect((await scan(relay('http', ...body))).cwe523).toEqual([]);
  });

  it('a stringified request echoed into HTML is still xss', async () => {
    const r = await scan(relay('http', 'res.send(JSON.stringify(req.query));'));
    expect(r.flows).toContain('xss');
  });
});
