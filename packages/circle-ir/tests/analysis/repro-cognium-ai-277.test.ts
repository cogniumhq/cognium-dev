/**
 * cognium-ai#277 — SSRF via a Next.js/Remix route param was a false negative.
 *
 * The `JS_TAINTED_PATTERNS` recognised `req.params`/`event.params`/
 * `.searchParams.get`, but NOT the bare destructured route-params object that
 * the Next.js App Router (`GET(req, { params })`) and Remix (`loader({ params })`)
 * hand to a handler — so a multi-line flow `const x = params.url; fetch(x)`
 * (the shape of the strongest TP in the JS/TS study) was missed. A bare
 * `params.` pattern would over-fire, so it is gated to route-handler files (a
 * route-method/loader/action export + a destructured `params` binding) and
 * typed `http_path` (route segments).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const ssrf = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).some(f => f.sink_type === 'ssrf');

describe('cognium-ai#277 — Next.js/Remix route-param SSRF', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('Remix loader({ params }) → decode → fetch (multi-line, the repro)', async () => {
    const code = `
export async function loader({ params }) {
  const decoded = decodeURIComponent(params.url);
  const res = await fetch(decoded, { method: "HEAD" });
  return res;
}`;
    expect(ssrf(await analyze(code, 'getPreview.$url.ts', 'typescript'))).toBe(true);
  });

  it('Next.js App Router GET(req, { params }) → fetch', async () => {
    const code = `
export async function GET(req, { params }) {
  const target = params.url;
  return await fetch(target);
}`;
    expect(ssrf(await analyze(code, 'route.ts', 'typescript'))).toBe(true);
  });

  it('gate: params.<seg> is NOT sourced by this rule outside a route handler', async () => {
    // A plain helper still seeds nothing http_path-typed from the route rule.
    // (interprocedural_param may still apply — this asserts the route rule is
    // gated, i.e. no http_path source is added.)
    const code = `
function buildConfig(params) {
  const region = params.region;
  return { region };
}`;
    const r = await analyze(code, 'config.ts', 'typescript');
    const httpPath = (r.taint?.sources ?? []).filter(s => s.type === 'http_path');
    expect(httpPath.length).toBe(0);
  });
});
