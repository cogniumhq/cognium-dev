/**
 * cognium-dev #286 D — C# `ssrf`: fixed `BaseAddress` + relative path.
 *
 * When an `HttpClient`'s `BaseAddress` is a compile-time constant, attacker
 * input can only extend the path, so the request cannot be redirected to
 * another host:
 *
 *   var client = new HttpClient { BaseAddress = new Uri("https://api.internal/") };
 *   await client.GetAsync("lookup/" + Uri.EscapeDataString(input));   // was ssrf
 *
 * Sink-filter Stage 15l, the C# analogue of Stage 15i (JS fixed-host URL
 * template). The negative cases below matter more than the positive one.
 *
 * **.NET ignores `BaseAddress` entirely when the request URI is absolute.**
 * So `client.GetAsync(input)` on a constant-base client is still a genuine
 * SSRF — the attacker supplies `https://evil.example` and the base is
 * discarded. Suppression therefore requires the argument to begin with a
 * *string literal* that is neither absolute nor protocol-relative, which is the
 * only way to prove the attacker cannot reach the host position. Same reasoning
 * as the same-origin literal prefix in #284 d1.
 *
 * Not fixed here, and filed separately: a *tainted* `BaseAddress`
 * (`new Uri(input)` with a constant path) reports nothing today. That is a
 * missed SSRF where the attacker controls the host outright — the opposite
 * defect, and strictly worse than the false positive fixed here. No test
 * asserts its current behaviour, because doing so would pin the bug.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const ssrf = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'ssrf' && !f.sanitized);

/** Constant BaseAddress client, with `arg` as the request argument. */
const withConstBase = (arg: string) =>
  analyze(
    [
      'using System;',
      'using System.Net.Http;',
      'using System.Threading.Tasks;',
      'public class D {',
      '    public async Task<string> Lookup(string input) {',
      '        var client = new HttpClient { BaseAddress = new Uri("https://api.internal.example.com/") };',
      `        var resp = await client.GetAsync(${arg});`,
      '        return await resp.Content.ReadAsStringAsync();',
      '    }',
      '}',
    ].join('\n'),
    'D.cs',
    'csharp'
  );

describe('#286 D: constant BaseAddress + relative path is not ssrf', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('suppresses the finding for a relative path built on a literal prefix', async () => {
    const r = await withConstBase('"lookup/" + Uri.EscapeDataString(input)');
    expect(ssrf(r).length).toBe(0);
  });

  it('suppresses it for a plain relative concat too', async () => {
    const r = await withConstBase('"lookup/" + input');
    expect(ssrf(r).length).toBe(0);
  });
});

describe('#286 D: the suppression must not swallow a real SSRF', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a BARE tainted argument still fires — .NET ignores BaseAddress for absolute URIs', async () => {
    // The attacker supplies `https://evil.example` and BaseAddress is discarded.
    // This is the case that makes the literal-prefix requirement necessary.
    const r = await withConstBase('input');
    expect(ssrf(r).length).toBeGreaterThan(0);
  });

  it('an absolute literal prefix still fires', async () => {
    const r = await withConstBase('"https://evil.example/" + input');
    expect(ssrf(r).length).toBeGreaterThan(0);
  });

  it('a protocol-relative literal prefix still fires', async () => {
    const r = await withConstBase('"//" + input');
    expect(ssrf(r).length).toBeGreaterThan(0);
  });

  it('a client with no BaseAddress still fires', async () => {
    const r = await analyze(
      [
        'using System;',
        'using System.Net.Http;',
        'using System.Threading.Tasks;',
        'public class E {',
        '    public async Task<string> Fetch(string input) {',
        '        var resp = await new HttpClient().GetAsync(input);',
        '        return await resp.Content.ReadAsStringAsync();',
        '    }',
        '}',
      ].join('\n'),
      'E.cs',
      'csharp'
    );
    expect(ssrf(r).length).toBeGreaterThan(0);
  });

  it('UriBuilder with a tainted host still fires (unrelated path, kept as a control)', async () => {
    const r = await analyze(
      [
        'using System;',
        'using System.Net.Http;',
        'using System.Threading.Tasks;',
        'public class F {',
        '    public async Task<string> Lookup(string input) {',
        '        var b = new UriBuilder(input);',
        '        var resp = await new HttpClient().GetAsync(b.Uri);',
        '        return await resp.Content.ReadAsStringAsync();',
        '    }',
        '}',
      ].join('\n'),
      'F.cs',
      'csharp'
    );
    expect(ssrf(r).length).toBeGreaterThan(0);
  });
});
