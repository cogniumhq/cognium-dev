/**
 * cognium-dev #542 — the CWE-81 `StatusDescription` sink was gated on the
 * receiver's *name*, so `resp.StatusDescription = … + data` registered nothing
 * while `Response.StatusDescription = … + data` registered a sink.
 *
 * This is the sink-side twin of #501, which fixed the same mistake on the source
 * side: `HttpRequest req` was missed because it was not spelled `Request`. The
 * declared type is what makes a receiver a response; the identifier is not.
 *
 * Two things were wrong. `buildCSharpReceiverTypeMap` walked only
 * `variable_declaration`, so a receiver arriving as a *parameter* — the
 * canonical `void Bad(HttpRequest req, HttpResponse resp)` handler shape — had
 * no resolvable type at all. And the `StatusDescription` gate tested the name
 * only. Juliet names the parameter `resp`, which is why CWE-81 scored 0 of 9.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const run = (code: string) => analyze(code, 'P.cs', 'csharp');
const xssSinkLines = (r: Awaited<ReturnType<typeof run>>) =>
  (r.taint.sinks ?? []).filter(s => s.type === 'xss').map(s => s.line);

const handler = (recvDecl: string, recvUse: string) => `
using System.Web;
public class P {
  public void Bad(HttpRequest req, ${recvDecl}) {
    string data = req.QueryString["name"];
    ${recvUse}.StatusDescription = "<br>val " + data;
  }
}
`;

describe('#542 C# response sinks follow the declared type, not the name Response', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('registers the sink when the receiver is named Response', async () => {
    const r = await run(handler('HttpResponse Response', 'Response'));
    expect(xssSinkLines(r)).toContain(6);
  });

  it('registers the sink when the receiver is a differently-named HttpResponse parameter', async () => {
    // The regression: `resp` produced no sink at all.
    const r = await run(handler('HttpResponse resp', 'resp'));
    expect(xssSinkLines(r)).toContain(6);
    expect(r.taint.flows.some(f => f.sink_type === 'xss')).toBe(true);
  });

  it('accepts HttpResponseBase, the abstraction MVC hands controllers', async () => {
    const r = await run(handler('HttpResponseBase response', 'response'));
    expect(xssSinkLines(r)).toContain(6);
  });

  it('still refuses .StatusDescription on an unrelated declared type', async () => {
    const r = await run(`
using System.Web;
public class Job { public string StatusDescription { get; set; } }
public class P {
  public void Bad(HttpRequest req, Job job) {
    string data = req.QueryString["name"];
    job.StatusDescription = "<br>val " + data;
  }
}
`);
    expect(xssSinkLines(r)).toEqual([]);
  });

  it('resolves a receiver type from a parameter for the other type-gated properties too', async () => {
    // `BaseAddress` is class-gated to a resolved HttpClient (#336). Before the
    // parameter fix a passed-in client could not resolve, so the sink was lost.
    const r = await run(`
using System.Net.Http;
using System.Web;
public class P {
  public void Bad(HttpRequest req, HttpClient client) {
    string host = req.QueryString["h"];
    client.BaseAddress = new System.Uri(host);
  }
}
`);
    expect((r.taint.sinks ?? []).some(s => s.type === 'ssrf')).toBe(true);
  });

  it('does not confuse an unrelated local with the response parameter', async () => {
    const r = await run(`
using System.Web;
public class Job { public string StatusDescription { get; set; } }
public class P {
  public void Bad(HttpRequest req, HttpResponse resp) {
    string data = req.QueryString["name"];
    { Job other = new Job(); other.StatusDescription = data; }
    resp.StatusDescription = "<br>val " + data;
  }
}
`);
    // Line 8 is the response write, line 7 the unrelated Job write.
    expect(xssSinkLines(r)).toContain(8);
    expect(xssSinkLines(r)).not.toContain(7);
  });

  it('documents the flat receiver-type map: a same-named local wins over the parameter', async () => {
    // `buildCSharpReceiverTypeMap` is keyed by name with no scope tracking, so a
    // local declaration of the same name replaces the parameter's type for the
    // whole file. Locking the current behaviour rather than implying the map is
    // scope-aware: here the genuine `resp.StatusDescription` write is NOT
    // registered, because `resp` resolves to `Job`.
    const r = await run(`
using System.Web;
public class Job { public string StatusDescription { get; set; } }
public class P {
  public void Other() { Job resp = new Job(); resp.StatusDescription = "x"; }
  public void Bad(HttpRequest req, HttpResponse resp) {
    string data = req.QueryString["name"];
    resp.StatusDescription = "<br>val " + data;
  }
}
`);
    expect(xssSinkLines(r)).toEqual([]);
  });
});
