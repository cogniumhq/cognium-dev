/**
 * cognium-dev#275 — modern .NET ecosystem sinks (Dapper / RestSharp /
 * controller `Content` / ReDoS), plus the C# generic-call extraction fix that
 * Dapper depends on.
 *
 * The generic-name defect is the load-bearing part: tree-sitter-c-sharp puts a
 * `generic_name` in the `name` field of `conn.Query<User>(sql)`, so the
 * extracted method name was `"Query<User>"` and matched no registry entry —
 * every generic C# call was invisible to the sink matcher, not just Dapper's.
 * `csharpBareName` strips the type-argument list.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const controller = (body: string, usings = '') => `${usings}using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult Get(string name) {
${body}
    return Ok();
  } }`;

const sinkTypes = async (code: string) => {
  const r = await analyze(code, 'C.cs', 'csharp');
  return {
    sinks: (r.taint?.sinks ?? []).map((s) => s.type),
    flows: (r.taint?.flows ?? []).map((f) => f.sink_type),
  };
};

describe('cognium-dev#275 — C# generic call extraction', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a generic call resolves to its bare method name (Query<User> -> Query)', async () => {
    const r = await analyze(
      controller('    var sql = "SELECT * FROM U WHERE n = \'" + name + "\'";\n    var x = _conn.Query<User>(sql);'),
      'C.cs', 'csharp',
    );
    expect(r.calls.some((c) => c.method_name === 'Query')).toBe(true);
    // The pre-fix behaviour — the type-argument list leaking into the name.
    expect(r.calls.some((c) => c.method_name === 'Query<User>')).toBe(false);
  });

  it('generic and non-generic Dapper calls behave identically', async () => {
    const sql = '    var sql = "SELECT * FROM U WHERE n = \'" + name + "\'";\n';
    for (const call of [
      'var x = _conn.Query<User>(sql);',
      'var x = _conn.Query(sql);',
      'var x = await _conn.QueryAsync<User>(sql);',
      'var x = _conn.Execute(sql);',
    ]) {
      const { flows } = await sinkTypes(controller(sql + '    ' + call));
      expect(flows, call).toContain('sql_injection');
    }
  });
});

describe('cognium-dev#275 — modern ecosystem sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('RestSharp `new RestClient(userUrl)` is an SSRF sink', async () => {
    const { flows } = await sinkTypes(
      controller('    var client = new RestClient(name);', 'using RestSharp; '),
    );
    expect(flows).toContain('ssrf');
  });

  it('controller `Content(html)` is an XSS sink', async () => {
    const { flows } = await sinkTypes(controller('    var h = "<div>" + name + "</div>";\n    Content(h, "text/html");'));
    expect(flows).toContain('xss');
  });

  it('a user-supplied regex PATTERN is ReDoS', async () => {
    const { flows } = await sinkTypes(
      controller('    var m = Regex.IsMatch("const input", name);', 'using System.Text.RegularExpressions; '),
    );
    expect(flows).toContain('redos');
  });

  it('a tainted regex INPUT with a constant pattern is NOT ReDoS (precision)', async () => {
    const { flows } = await sinkTypes(
      controller('    var m = Regex.IsMatch(name, "^[a-z]+$");', 'using System.Text.RegularExpressions; '),
    );
    expect(flows).not.toContain('redos');
  });

  it('Dapper sink names do not fire on an untainted same-named call (precision)', async () => {
    // RestSharp's `client.Execute(request)` shares the `Execute` method name
    // with Dapper's; arg 0 is a request object, so the taint gate keeps it clean.
    const { flows } = await sinkTypes(
      controller('    var client = new RestClient("https://fixed.example");\n    var resp = client.Execute(new RestRequest());', 'using RestSharp; '),
    );
    expect(flows).not.toContain('sql_injection');
  });
});

describe('cognium-dev#275 — receiver-carried and metadata taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flows = async (code: string) => {
    const r = await analyze(code, 'F.cs', 'csharp');
    return (r.taint?.flows ?? []).map((f) => f.sink_type);
  };

  const handler = (body: string, usings = '') => `${usings}using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public async Task<IActionResult> Get(string url) {
${body}
    return Ok();
  } }`;

  it('Flurl fluent form taints via the RECEIVER', async () => {
    expect(await flows(handler('    var r = await url.GetStringAsync();', 'using Flurl.Http; ')))
      .toContain('ssrf');
    expect(await flows(handler('    var r = await url.GetJsonAsync<Thing>();', 'using Flurl.Http; ')))
      .toContain('ssrf');
  });

  it('HttpClient keeps arg-0 SSRF detection (the receiver-prepend must not shift it)', async () => {
    expect(await flows(handler(
      '    var c = new HttpClient();\n    var r = await c.GetStringAsync(url);', 'using System.Net.Http; ',
    ))).toContain('ssrf');
  });

  it('HttpClient with a constant URL stays clean', async () => {
    expect(await flows(handler(
      '    var c = new HttpClient();\n    var r = await c.GetStringAsync("https://fixed.example");',
      'using System.Net.Http; ',
    ))).not.toContain('ssrf');
  });

  it('IFormFile.FileName is a taint source (upload path traversal)', async () => {
    const code = `using Microsoft.AspNetCore.Http; using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult Up(IFormFile file) {
    var path = "/uploads/" + file.FileName;
    using var s = System.IO.File.Create(path);
    return Ok();
  } }`;
    expect(await flows(code)).toContain('path_traversal');
  });

  it('a .FileName on an unrelated type is NOT a source (scoping)', async () => {
    const code = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult Up() {
    var info = new System.IO.FileInfo("/etc/fixed.txt");
    var path = "/uploads/" + info.FileName;
    using var s = System.IO.File.Create(path);
    return Ok();
  } }`;
    expect(await flows(code)).not.toContain('path_traversal');
  });
});

describe('cognium-dev#275 — header writes and MongoDB JS payloads', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flows = async (code: string) => {
    const r = await analyze(code, 'H.cs', 'csharp');
    return (r.taint?.flows ?? []).map((f) => f.sink_type);
  };

  const action = (body: string, usings = '') => `${usings}using System.Collections.Generic; using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult Get(string q) {
${body}
    return Ok();
  } }`;

  it('Response.Headers.Add(name, tainted) is CRLF injection', async () => {
    expect(await flows(action('    Response.Headers.Add("X-C", q);'))).toContain('crlf');
  });

  it('the Headers indexer form is CRLF injection too', async () => {
    expect(await flows(action('    Response.Headers["X-C"] = q;'))).toContain('crlf');
  });

  it('a constant header value does not fire', async () => {
    expect(await flows(action('    Response.Headers.Add("X-C", "fixed");'))).not.toContain('crlf');
  });

  // The header normalization keys on a `.Headers` receiver precisely so that
  // the ubiquitous bare `Add` is never registered as a sink.
  it('List.Add / Dictionary.Add / dictionary indexer are untouched (precision)', async () => {
    for (const body of [
      '    var items = new List<string>();\n    items.Add(q);',
      '    var d = new Dictionary<string,string>();\n    d.Add("k", q);',
      '    var d = new Dictionary<string,string>();\n    d["k"] = q;',
    ]) {
      expect(await flows(action(body)), body).not.toContain('crlf');
    }
  });

  it('BsonDocument.Parse(json) and new BsonJavaScript(code) are NoSQL injection', async () => {
    const u = 'using MongoDB.Bson; using MongoDB.Driver; ';
    expect(await flows(action('    var f = BsonDocument.Parse(q);', u))).toContain('nosql_injection');
    expect(await flows(action('    var js = new BsonJavaScript(q);', u))).toContain('nosql_injection');
  });
});

describe('cognium-dev#275 — local-redirect guards are sanitizers, not sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flows = async (code: string) => {
    const r = await analyze(code, 'L.cs', 'csharp');
    return (r.taint?.flows ?? []).map((f) => f.sink_type);
  };

  const go = (body: string) => `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult Go(string next) {
${body}
  } }`;

  it('an unguarded Redirect(tainted) still fires (recall preserved)', async () => {
    expect(await flows(go('    return Redirect(next);'))).toContain('open_redirect');
  });

  it('a Redirect guarded by Url.IsLocalUrl is credited as sanitized (was a false positive)', async () => {
    expect(await flows(go(
      '    if (Url.IsLocalUrl(next)) { return Redirect(next); }\n    return Redirect("/");',
    ))).not.toContain('open_redirect');
  });

  it('LocalRedirect is not a sink — the framework throws on a non-local URL', async () => {
    expect(await flows(go('    return LocalRedirect(next);'))).not.toContain('open_redirect');
  });
});
