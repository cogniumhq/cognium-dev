/**
 * #895 — dns.promises.resolve with caller-controlled hostname is SSRF (CWE-918).
 * Mirrors sast-validation intake `dns_nul_resolve_tp.js` / safe mirror shapes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#895 dns.promises.resolve SSRF sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — tainted hostname at dns.promises.resolve reports ssrf', async () => {
    const code = [
      "import dns from 'dns';",
      'export async function handler(req) {',
      '  const host = req.query.name;',
      '  return dns.promises.resolve(host);',
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'dns_nul_resolve_tp.js', 'javascript');
    const ssrf = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'ssrf');
    expect(ssrf.length).toBeGreaterThan(0);
  });

  it('TN — NUL guard with fixed resolve target stays clean', async () => {
    const code = [
      "import dns from 'dns';",
      'export async function handler(req) {',
      '  const name = req.query.name;',
      "  if (name.includes('\\0')) {",
      "    throw new Error('bad');",
      '  }',
      "  return dns.promises.resolve('example.com');",
      '}',
      '',
    ].join('\n');
    const r = await analyze(code, 'dns_nul_resolve_safe.js', 'javascript');
    const ssrf = (r.taint?.flows ?? []).filter((f) => f.sink_type === 'ssrf');
    expect(ssrf.length).toBe(0);
  });
});
