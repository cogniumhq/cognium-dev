/**
 * cognium-dev #285 — a C# host-allowlist guard was credited only when it sat on
 * an earlier source line than the sink, so adding one newline between the guard
 * and the sink flipped a false positive to clean with no AST or token change.
 *
 * `isCSharpSsrfHostAllowlistGuarded` skipped any guard whose line was not
 * strictly before the sink (`g.i >= sinkIdx`), which discards the compact
 * `if (host == "const") <sink>;` form entirely. `csThenBlock` already reports
 * `start === end === ifIdx` for a same-line then, so the containment check
 * handles it once the guard is allowed through.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const ssrf = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'ssrf');

const wrap = (body: string, params = 'string input') => [
  'using System.Net.Http;',
  'public class C {',
  `  public async System.Threading.Tasks.Task M(${params}) {`,
  body,
  '  }',
  '}',
].join('\n');

describe('#285 C# host-allowlist guard is credited regardless of line layout', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('guard and sink on the SAME line does not fire ssrf', async () => {
    const code = wrap('    if (new System.Uri(input).Host == "api.internal.example.com") await new HttpClient().GetAsync(input);');
    const r = await analyze(code, 'C.cs', 'csharp');
    expect(ssrf(r)).toEqual([]);
  });

  it('guard on its own line does not fire ssrf either (unchanged)', async () => {
    const code = wrap([
      '    if (new System.Uri(input).Host == "api.internal.example.com")',
      '      await new HttpClient().GetAsync(input);',
    ].join('\n'));
    const r = await analyze(code, 'C.cs', 'csharp');
    expect(ssrf(r)).toEqual([]);
  });

  it('the two layouts agree — one newline no longer changes the verdict', async () => {
    const oneLine = wrap('    if (new System.Uri(input).Host == "h.example.com") await new HttpClient().GetAsync(input);');
    const twoLine = wrap([
      '    if (new System.Uri(input).Host == "h.example.com")',
      '      await new HttpClient().GetAsync(input);',
    ].join('\n'));
    const a = await analyze(oneLine, 'C.cs', 'csharp');
    const b = await analyze(twoLine, 'C.cs', 'csharp');
    expect(ssrf(a).length).toBe(ssrf(b).length);
  });

  it('an unguarded sink still fires (recall)', async () => {
    const code = wrap('    await new HttpClient().GetAsync(input);');
    const r = await analyze(code, 'C.cs', 'csharp');
    expect(ssrf(r).length).toBeGreaterThan(0);
  });

  it('a same-line guard on an UNRELATED variable still fires (no over-credit)', async () => {
    const code = wrap(
      '    if (other == "x") await new HttpClient().GetAsync(input);',
      'string input, string other',
    );
    const r = await analyze(code, 'C.cs', 'csharp');
    expect(ssrf(r).length).toBeGreaterThan(0);
  });
});
