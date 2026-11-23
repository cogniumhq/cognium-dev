/**
 * cognium-dev #900 slice S1 — request-derived host written to a module-scope
 * shared cache (OIDC discovery cache shape).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowsOf = (ir: Awaited<ReturnType<typeof analyze>>, sinkType: string) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

const OIDC_TP = `
const discoveryCache = new Map();

export function handle(req, res) {
  const host = req.headers.host;
  discoveryCache.set('issuer', host);
  res.json({ issuer: discoveryCache.get('issuer') });
}
`;

const SAFE_CONFIG_HOST = `
const discoveryCache = new Map();
const TRUSTED_HOST = 'api.example.com';

export function handle(req, res) {
  discoveryCache.set('issuer', TRUSTED_HOST);
  res.end('ok');
}
`;

describe('#900 S1: module-scope cache poisoning (JS)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports cache_poisoning when request host is stored in a shared Map', async () => {
    const ir = await analyze(OIDC_TP, 'OidcDiscoveryCache.js', 'javascript');
    expect(flowsOf(ir, 'cache_poisoning').length).toBeGreaterThan(0);
  });

  it('stays clean when the cache value comes from config, not the request', async () => {
    const ir = await analyze(SAFE_CONFIG_HOST, 'OidcDiscoveryCacheSafe.js', 'javascript');
    expect(flowsOf(ir, 'cache_poisoning')).toEqual([]);
  });
});
