/**
 * cognium-dev#809 — a rejecting `Array.IndexOf` guard over a `static readonly`
 * string-literal array clears the guarded value for the sinks after it.
 *
 *   private static readonly string[] KnownHosts = { "status.example.net", … };
 *   if (Array.IndexOf(KnownHosts, target) < 0) { throw …; }
 *   await new HttpClient().GetStringAsync("https://" + target + "/ping");
 *
 * `System.Array.IndexOf` and `== -1` are the same check. The array must be a
 * literal-only field the file never writes, the guard must leave the method,
 * and a reassignment of the value after the guard ends the credit.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const ssrf = async (code: string) => {
  const r = await analyze(code, 'StatusProbe.cs', 'csharp');
  return (r.taint?.flows ?? []).filter((f) => f.sink_type === 'ssrf' && !f.sanitized);
};

const FIELD = 'private static readonly string[] KnownHosts = { "status.example.net", "health.example.net" };';
const GUARD = 'if (Array.IndexOf(KnownHosts, target) < 0) { throw new ArgumentException("target"); }';

const probe = (opts: { field?: string; guard?: string; between?: string; extra?: string; params?: string } = {}) => `using System;
using System.Net.Http;
using System.Threading.Tasks;
public class StatusProbe {
    ${opts.field ?? FIELD}
    ${opts.extra ?? ''}
    public async Task<string> Probe(${opts.params ?? 'string target'}) {
        ${opts.guard ?? GUARD}
        ${opts.between ?? ''}
        return await new HttpClient().GetStringAsync("https://" + target + "/ping");
    }
}
`;

describe('#809 C# Array.IndexOf guard over a static readonly literal array', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('clears the guarded value (Array.IndexOf < 0, throw)', async () => {
    expect(await ssrf(probe())).toHaveLength(0);
  });

  it('clears the guarded value (System.Array.IndexOf, throw without braces)', async () => {
    expect(await ssrf(probe({
      guard: 'if (System.Array.IndexOf(KnownHosts, target) < 0) throw new Exception("target");',
    }))).toHaveLength(0);
  });

  it('clears the guarded value (== -1, return)', async () => {
    expect(await ssrf(probe({
      guard: 'if (Array.IndexOf(KnownHosts, target) == -1) return "";',
    }))).toHaveLength(0);
  });

  it('clears the guarded value (new string[] initialiser, readonly static order)', async () => {
    expect(await ssrf(probe({
      field: 'static readonly private string[] KnownHosts = new string[] { "status.example.net" };',
      guard: 'if (System.Array.IndexOf(KnownHosts, target) < 0) return "";',
    }))).toHaveLength(0);
  });

  it('still reports with no guard', async () => {
    expect((await ssrf(probe({ guard: '' }))).length).toBeGreaterThan(0);
  });

  it('still reports when the guard body falls through', async () => {
    expect((await ssrf(probe({
      guard: 'if (Array.IndexOf(KnownHosts, target) < 0) { Console.WriteLine("unknown"); }',
    }))).length).toBeGreaterThan(0);
  });

  it('still reports when the array is not readonly', async () => {
    expect((await ssrf(probe({
      field: 'private static string[] KnownHosts = { "status.example.net", "health.example.net" };',
    }))).length).toBeGreaterThan(0);
  });

  it('still reports when the array is assigned from a parameter elsewhere', async () => {
    expect((await ssrf(probe({
      field: 'private static string[] KnownHosts = { "status.example.net" };',
      extra: 'public static void Configure(string[] hosts) { KnownHosts = hosts; }',
    }))).length).toBeGreaterThan(0);
  });

  it('still reports when an element of the readonly array is written', async () => {
    expect((await ssrf(probe({
      extra: 'public static void Configure(string extra) { KnownHosts[0] = extra; }',
    }))).length).toBeGreaterThan(0);
  });

  it('still reports when the array holds a non-literal element', async () => {
    expect((await ssrf(probe({
      field: 'private static readonly string[] KnownHosts = { "status.example.net", Environment.GetEnvironmentVariable("EXTRA_HOST") };',
    }))).length).toBeGreaterThan(0);
  });

  it('still reports when the value is reassigned after the guard', async () => {
    expect((await ssrf(probe({ between: 'target = Console.ReadLine();' }))).length).toBeGreaterThan(0);
  });

  it('still reports when a different variable is the one guarded', async () => {
    expect((await ssrf(probe({
      params: 'string target, string other',
      guard: 'if (Array.IndexOf(KnownHosts, other) < 0) { throw new ArgumentException("other"); }',
    }))).length).toBeGreaterThan(0);
  });
});
