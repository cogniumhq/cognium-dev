/**
 * #503 — ASP.NET Core `Response.WriteAsync(x)` had a source but no sink, so the
 * flow could never be reported. The System.Web row
 * `{ method: 'Write', class: 'Response' }` does not cover the
 * `HttpResponseWritingExtensions` extension method Core uses.
 *
 * The shape already reached `ir.calls` with the receiver and the tainted
 * argument, so the fix is the registry row alone. The negative case locks the
 * scoping: `WriteAsync` on a non-Response receiver must stay silent.
 *
 * The CodeDom half of #503 is held separately — it has a measured corpus
 * consequence that needs an owner decision.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sinkTypes = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.sinks ?? []).map(s => s.type);

describe('#503 ASP.NET Core Response.WriteAsync is an xss sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires xss on a tainted WriteAsync body', async () => {
    const code = `using Microsoft.AspNetCore.Mvc;
public class PageController : Controller {
  public async System.Threading.Tasks.Task Render() {
    var q = Request.Query["q"];
    await Response.WriteAsync("<div>" + q + "</div>");
  }
}`;
    const r = await analyze(code, 'PageController.cs', 'csharp');
    expect(sinkTypes(r)).toContain('xss');
    expect((r.taint?.flows ?? []).length).toBeGreaterThan(0);
  });

  it('does not fire on Stream/StreamWriter WriteAsync (receiver is scoped)', async () => {
    const code = `using System.IO;
public class C {
  public async System.Threading.Tasks.Task Save(string data) {
    var writer = new StreamWriter("out.txt");
    await writer.WriteAsync(data);
  }
}`;
    const r = await analyze(code, 'C.cs', 'csharp');
    expect(sinkTypes(r)).not.toContain('xss');
  });

  it('keeps the System.Web Response.Write row firing', async () => {
    const code = `using System.Web;
public class P {
  public void Bad(HttpRequest Request, HttpResponse Response) {
    string data = Request.QueryString["id"];
    Response.Write("<div>" + data + "</div>");
  }
}`;
    const r = await analyze(code, 'P.cs', 'csharp');
    expect(sinkTypes(r)).toContain('xss');
  });
});
