/**
 * Three C# sink shapes that no registry row could reach, because the extractor
 * emitted no call for them — #503 (part 1), #340 and #336.
 *
 * `ir.calls` was empty for a property assignment and for a cast, and the
 * object-initializer form of a property assignment was skipped because its
 * left-hand side is a bare identifier rather than a member access. One piece
 * of extractor work, three issues.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const probe = async (code: string) => {
  const r = await analyze(code, 'P.cs', 'csharp');
  const t = r.taint ?? ({} as NonNullable<typeof r.taint>);
  return { sinks: t.sinks ?? [], flows: t.flows ?? [] };
};

describe('#503 part 1 — Response.StatusDescription is an xss sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reports a tainted status description', async () => {
    const { sinks, flows } = await probe(`using System.Web;
public class P { public void Bad(HttpRequest Request, HttpResponse Response) {
  string data = Request.QueryString["id"];
  Response.StatusDescription = "Bad " + data;
} }`);
    expect(sinks.some(s => s.type === 'xss')).toBe(true);
    expect(flows.length).toBeGreaterThan(0);
  });
});

describe('#340 — (MarkupString)x is an xss sink, like new MarkupString(x)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reports the cast form', async () => {
    const { sinks, flows } = await probe(`using Microsoft.AspNetCore.Components;
public class R { public MarkupString Run(string input) { return (MarkupString)input; } }`);
    expect(sinks.some(s => s.type === 'xss')).toBe(true);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('stays clean on a constant operand', async () => {
    const { flows } = await probe(`using Microsoft.AspNetCore.Components;
public class R { public MarkupString Run() { return (MarkupString)"<b>hi</b>"; } }`);
    expect(flows).toHaveLength(0);
  });

  it('does not double-report the constructor form', async () => {
    const { sinks } = await probe(`using Microsoft.AspNetCore.Components;
public class R { public MarkupString Run(string input) { return new MarkupString(input); } }`);
    expect(sinks.filter(s => s.type === 'xss')).toHaveLength(1);
  });
});

describe('#336 — a tainted HttpClient.BaseAddress is ssrf', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const client = (uri: string) => `using System; using System.Net.Http; using System.Threading.Tasks;
public class D { public async Task<string> L(string input) {
  var c = new HttpClient { BaseAddress = new Uri(${uri}) };
  var r = await c.GetAsync("lookup/1");
  return await r.Content.ReadAsStringAsync(); } }`;

  it('reports when the attacker controls the host, with constant request args', async () => {
    const { sinks, flows } = await probe(client('input'));
    expect(sinks.some(s => s.type === 'ssrf')).toBe(true);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('stays clean for a constant BaseAddress (#286 cell D must survive)', async () => {
    const { flows } = await probe(client('"https://api.internal/"'));
    expect(flows).toHaveLength(0);
  });

  it('does not fire on .BaseAddress of an unrelated type', async () => {
    const { sinks } = await probe(`using System;
public class D { public void L(string input) {
  var x = new MyThing { BaseAddress = new Uri(input) };
} }`);
    expect(sinks.some(s => s.type === 'ssrf')).toBe(false);
  });

  it('leaves the existing GetAsync(tainted) detection alone', async () => {
    const { flows } = await probe(`using System.Net.Http; using System.Threading.Tasks;
public class D { public async Task L(string input) { var c = new HttpClient(); await c.GetAsync(input); } }`);
    expect(flows.length).toBeGreaterThan(0);
  });
});
