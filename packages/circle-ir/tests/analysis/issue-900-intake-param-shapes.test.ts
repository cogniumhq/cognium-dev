/**
 * cognium-dev#900 — the two parameter shapes the cve-intake fixtures use, with renamed
 * identifiers and their near misses:
 * - a parameter inside a multi-line object literal assigned to a local, which is then
 *   written to a shared cache (`const doc = {\n issuer: 'https://' + host,\n}; cache.set(k, doc)`);
 * - a read-through cache whose callback returns the parameter
 *   (`cache.fetch(key, () => mr.title)`), clean when the key names the viewer.
 * The CLI test on the byte-exact fixtures is packages/cli/tests/gates-nightly/
 * issue-900-cve-intake-cache-poisoning.test.ts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flows = async (code: string, sinkType = 'cache_poisoning') => {
  const ir = await analyze(code, 'lib/shape.js', 'javascript');
  return (ir.taint.flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);
};
const mod = (body: string) => `'use strict';\n\n${body}\n\nmodule.exports = { f };\n`;

describe('#900 intake shapes: multi-line object literal into a shared cache', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a parameter on a continuation line of the literal reaches cache.set', async () => {
    const fs = await flows(mod(`function f(origin) {\n  const meta = {\n    base: 'https://' + origin,\n    token_url: 'https://' + origin + '/token',\n  };\n  cache.set('meta', meta);\n  return meta;\n}`));
    expect(fs.length).toBeGreaterThan(0);
    expect(fs[0].sink_line).toBe(8);
  });

  it('a nested literal and an array element are followed too', async () => {
    const fs = await flows(mod(`function f(origin) {\n  const meta = {\n    links: [\n      { href: origin },\n    ],\n  };\n  cache.set('meta', meta);\n}`));
    expect(fs.length).toBeGreaterThan(0);
  });

  it('near miss: the value comes from configuration', async () => {
    expect(await flows(mod(`function f() {\n  const origin = 'id.example.com';\n  const meta = {\n    base: 'https://' + origin,\n  };\n  cache.set('meta', meta);\n}`))).toEqual([]);
  });

  it('near miss: a parameter used only inside a function in the literal does not feed the literal', async () => {
    expect(await flows(mod(`function f(origin) {\n  const meta = {\n    base: 'https://id.example.com',\n    log: () => {\n      console.log(origin);\n    },\n  };\n  cache.set('meta', meta);\n}`))).toEqual([]);
  });
});

describe('#900 intake shapes: read-through cache.fetch', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the callback returns a parameter field: cache_poisoning at cache.fetch', async () => {
    const fs = await flows(mod(`function f(issue) {\n  return cache.fetch('issue-body-' + issue.id, () => issue.body);\n}`));
    expect(fs.length).toBeGreaterThan(0);
    expect(fs[0].sink_line).toBe(4);
  });

  it('near miss: the key names the viewer (concatenation or template)', async () => {
    expect(await flows(mod(`function f(issue, viewer) {\n  return cache.fetch('issue-body-' + issue.id + '-' + viewer.id, () => issue.body);\n}`))).toEqual([]);
    expect(await flows(mod('function f(issue, currentUser) {\n  return cache.fetch(`issue-body-${issue.id}-${currentUser.id}`, () => issue.body);\n}'))).toEqual([]);
    expect(await flows(mod(`function f(issue, req) {\n  return cache.fetch('issue-' + issue.id + req.user.id, () => issue.body);\n}`))).toEqual([]);
  });

  it('a viewer word inside the key string is not the viewer', async () => {
    const fs = await flows(mod(`function f(issue) {\n  return cache.fetch('user-issue-' + issue.id, () => issue.body);\n}`));
    expect(fs.length).toBeGreaterThan(0);
  });

  it('near miss: the callback returns a constant', async () => {
    expect(await flows(mod(`function f(issue) {\n  return cache.fetch('issue-' + issue.id, () => 'pending');\n}`))).toEqual([]);
  });
});
