/**
 * cognium-dev #900 slice S2 — MR title fragment cached with a key that omits the
 * viewer (`mr_title_frag_cache` intake shape): tainted `req.query.title` must
 * reach a module-scope `Map.set` value arg even when inline (no temp local).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowsOf = (ir: Awaited<ReturnType<typeof analyze>>, sinkType: string) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

const MR_TITLE_TP = `
const mrTitleFragCache = new Map();

export function cacheMrTitleFragment(req, res) {
  mrTitleFragCache.set(req.params.mrId, req.query.title);
  res.json({ frag: mrTitleFragCache.get(req.params.mrId) });
}
`;

const CONFIG_TITLE_SAFE = `
const mrTitleFragCache = new Map();
const DEFAULT_TITLE = 'Draft merge request';

export function cacheMrTitleFragment(_req, res) {
  mrTitleFragCache.set('mr-title-default', DEFAULT_TITLE);
}
`;

describe('#900 S2: mr_title_frag shared cache (JS)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports cache_poisoning when title is stored under an mr-only key', async () => {
    const ir = await analyze(MR_TITLE_TP, 'MrTitleFragCache.js', 'javascript');
    expect(flowsOf(ir, 'cache_poisoning').length).toBeGreaterThan(0);
  });

  it('stays clean when the cached title is from config, not the request', async () => {
    const ir = await analyze(CONFIG_TITLE_SAFE, 'MrTitleFragCacheSafe.js', 'javascript');
    expect(flowsOf(ir, 'cache_poisoning')).toEqual([]);
  });
});
