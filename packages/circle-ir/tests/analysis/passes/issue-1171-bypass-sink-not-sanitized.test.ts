import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/** #1171 — bypassSecurityTrust* must not be treated as an XSS sanitizer on its own sink line. */
describe('#1171 Angular bypassSecurityTrust sink not self-sanitized', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('fires xss for bypassSecurityTrustHtml with route query param', async () => {
    const code = `export function f (route: any, sanitizer: any) {
  const q = route.snapshot.queryParams.q;
  return sanitizer.bypassSecurityTrustHtml(q);
}`;
    const r = await analyze(code, 'x.ts', 'typescript');
    const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss');
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });
});
