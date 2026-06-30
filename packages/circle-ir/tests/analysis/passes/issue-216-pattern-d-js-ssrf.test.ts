/**
 * Sprint 75 — #216 Pattern D (JS SSRF allowlist): 2 FPs
 *
 * Closes 2 of 9 remaining scorecard FPs from #216:
 *   - benign_fetch_allowlist.js: `new URL(req.query.target)` then
 *     `if (!ALLOWED.has(url.hostname)) return ...` then `fetch(url)`
 *   - benign_host_allowlist_fetch.js: raw host param then
 *     `if (!ALLOWED_HOSTS.includes(host)) return ...` then
 *     `fetch('https://${host}/data')`
 *
 * 7 Pattern-X (other-language + Pattern A TS interop) FPs remain on
 * #216 after Sprint 75.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#216 Sprint 75 — JS SSRF allowlist guard sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — benign_fetch_allowlist.js: Set.has() guard on URL.hostname sanitizes ssrf + ETE', async () => {
    const code = [
      "const ALLOWED = new Set(['api.example.com', 'cdn.example.com']);",
      'function handler(req, res) {',
      '  const url = new URL(req.query.target);',
      '  if (!ALLOWED.has(url.hostname)) {',
      "    return res.status(400).send('blocked');",
      '  }',
      '  return fetch(url);',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'benign_fetch_allowlist.js', 'javascript');
    const ssrf = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'ssrf');
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(ssrf.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-2 — benign_host_allowlist_fetch.js: Array.includes() guard on raw host sanitizes ssrf + ETE', async () => {
    const code = [
      "const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];",
      'async function handler(req, res) {',
      '  const host = req.query.host;',
      '  if (!ALLOWED_HOSTS.includes(host)) {',
      '    return res.status(400).end();',
      '  }',
      '  const r = await fetch(`https://${host}/data`);',
      '  return r;',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'benign_host_allowlist_fetch.js',
      'javascript',
    );
    const ssrf = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'ssrf');
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(ssrf.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-1 — allowlist guard on var A does NOT sanitize unguarded var B at fetch sink', async () => {
    // Guard fires on host extracted from req.query.host, but the fetch
    // actually uses req.query.other which was never guarded. ssrf must
    // STILL fire for the unguarded variable.
    const code = [
      "const ALLOWED_HOSTS = ['api.example.com'];",
      'async function handler(req, res) {',
      '  const host = req.query.host;',
      '  if (!ALLOWED_HOSTS.includes(host)) {',
      '    return res.status(400).end();',
      '  }',
      '  return fetch(req.query.other);',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'tp_unguarded.js', 'javascript');
    const ssrf = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'ssrf');
    expect(ssrf.length).toBeGreaterThan(0);
  });

  it('TP-2 — substring includes() on the guarded var does NOT sanitize ssrf', async () => {
    // String#includes is substring containment, not set membership.
    // `host.includes('example.com')` is a loose check that does NOT
    // prove the host is one of N fixed strings. ssrf must STILL fire.
    const code = [
      'async function handler(req, res) {',
      '  const host = req.query.host;',
      "  if (!host.includes('example.com')) {",
      '    return res.status(400).end();',
      '  }',
      '  return fetch(`https://${host}/data`);',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'tp_substring_check.js', 'javascript');
    const ssrf = (r.taint?.flows ?? []).filter((f: any) => f.sink_type === 'ssrf');
    expect(ssrf.length).toBeGreaterThan(0);
  });
});
