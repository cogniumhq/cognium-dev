/**
 * C#/.NET Phase-1 — core CWE-family taint coverage (feat/csharp).
 *
 * Locks that the six core injection families fire end-to-end on hand-written
 * ASP.NET/BCL C# via the text-scan propagation path. Sinks are registered
 * `languages: ['csharp']` in config-loader (ADO.NET / System.IO / HttpClient /
 * Process / CSharpScript / Razor).
 *
 * KNOWN GAPS (next slices, tracked in the C#/.NET epic):
 *   - Sanitizer recognition on the text-scan path (HtmlEncode / Path.GetFileName
 *     do not yet break the chain — the propagation is not sanitizer-aware).
 *   - Deserialization (BinaryFormatter.Deserialize) needs receiver-type
 *     resolution — the receiver is an instance var, not the class name.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const has = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint?.flows ?? []).some(f => f.sink_type === t);

describe('C# Phase-1: core CWE families fire', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('SQL injection — new SqlCommand(concat)', async () => {
    const code = `
public class C {
  public void M(string id) {
    var q = "SELECT * FROM u WHERE id=" + id;
    var cmd = new SqlCommand(q, conn);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('command injection — Process.Start(concat)', async () => {
    const code = `
public class C {
  public void M(string cmd) {
    var full = "sh -c " + cmd;
    Process.Start(full);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'command_injection')).toBe(true);
  });

  it('path traversal — File.ReadAllText(concat)', async () => {
    const code = `
public class C {
  public void M(string p) {
    var full = "/data/" + p;
    var txt = File.ReadAllText(full);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'path_traversal')).toBe(true);
  });

  it('SSRF — HttpClient.GetAsync(concat)', async () => {
    const code = `
public class C {
  public async void M(string url) {
    var full = url + "?x=1";
    var c = new HttpClient();
    await c.GetAsync(full);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'ssrf')).toBe(true);
  });

  it('code injection — CSharpScript.EvaluateAsync(concat)', async () => {
    const code = `
public class C {
  public async void M(string code) {
    var full = "return " + code;
    await CSharpScript.EvaluateAsync(full);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'code_injection')).toBe(true);
  });

  it('XSS — Html.Raw(concat)', async () => {
    const code = `
public class C {
  public string M(string name) {
    var s = "<div>" + name + "</div>";
    return Html.Raw(s);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xss')).toBe(true);
  });
});

describe('C# Phase-1: additional families (LDAP / XPath / XXE)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('LDAP injection — new DirectorySearcher(filter)', async () => {
    const code = `
public class C {
  public void M(string user) {
    var filter = "(uid=" + user + ")";
    var s = new DirectorySearcher(filter);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'ldap_injection')).toBe(true);
  });

  it('XPath injection — doc.SelectSingleNode(xpath)', async () => {
    const code = `
public class C {
  public void M(System.Xml.XmlDocument doc, string u) {
    var xp = "//user[name='" + u + "']";
    var n = doc.SelectSingleNode(xp);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xpath_injection')).toBe(true);
  });

  it('XXE — XmlDocument.LoadXml(untrusted)', async () => {
    const code = `
public class C {
  public void M(string xml) {
    var doc = new XmlDocument();
    doc.LoadXml(xml);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xxe')).toBe(true);
  });
});

describe('C# Phase-1: precision that already holds', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('parameterized SqlCommand + AddWithValue does NOT fire (literal SQL)', async () => {
    const code = `
public class C {
  public void M(string id) {
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=@id", conn);
    cmd.Parameters.AddWithValue("@id", id);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });
});

describe('C# Phase-1: sanitizer awareness (sink-type-aware, text-scan path)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('HttpUtility.HtmlEncode(name) before Html.Raw suppresses XSS (2-hop chain)', async () => {
    const code = `
public class C {
  public string M(string name) {
    var safe = HttpUtility.HtmlEncode(name);
    var s = "<div>" + safe + "</div>";
    return Html.Raw(s);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xss')).toBe(false);
  });

  it('inline Html.Raw(HtmlEncode(name)) suppresses XSS', async () => {
    const code = `
public class C {
  public string M(string name) { return Html.Raw(HttpUtility.HtmlEncode(name)); }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xss')).toBe(false);
  });

  it('Path.GetFileName(p) before File.ReadAllText suppresses path traversal', async () => {
    const code = `
public class C {
  public void M(string p) {
    var name = Path.GetFileName(p);
    var full = "/data/" + name;
    var txt = File.ReadAllText(full);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'path_traversal')).toBe(false);
  });

  it('is sink-type-aware: HtmlEncode does NOT sanitize SQL — SQLi still fires', async () => {
    const code = `
public class C {
  public void M(string id) {
    var safe = HttpUtility.HtmlEncode(id);
    var q = "SELECT * FROM u WHERE id=" + safe;
    var cmd = new SqlCommand(q, conn);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });
});

describe('C# Phase-1: CommandText property-assignment SQL sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires on cmd.CommandText = "…" + taintedId (ADO.NET property sink)', async () => {
    const code = `
public class C {
  public IActionResult Get() {
    var id = Request.Query["id"];
    var cmd = new SqlCommand();
    cmd.CommandText = "SELECT * FROM u WHERE id=" + id;
    cmd.ExecuteReader();
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('fires on interpolated CommandText from a [FromQuery] param', async () => {
    const code = `
using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  [HttpGet] public IActionResult Get([FromQuery] string id) {
    var cmd = new SqlCommand();
    cmd.CommandText = $"SELECT * FROM u WHERE id={id}";
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('does NOT fire on a static-literal CommandText', async () => {
    const code = `
public class C {
  public IActionResult Get() {
    var cmd = new SqlCommand();
    cmd.CommandText = "SELECT * FROM u WHERE id=1";
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });

  it('does NOT fire when parameterized (literal CommandText + AddWithValue)', async () => {
    const code = `
public class C {
  public IActionResult Get() {
    var id = Request.Query["id"];
    var cmd = new SqlCommand();
    cmd.CommandText = "SELECT * FROM u WHERE id=@id";
    cmd.Parameters.AddWithValue("@id", id);
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });
});

// cognium-dev#271 — object-carried taint: `cmd.CommandText = tainted` taints the
// SqlCommand object, and a later `cmd.ExecuteScalar()`/`ExecuteReader()`/
// `ExecuteNonQuery()` (no-arg, tainted receiver) is the SQLi sink. This is the
// dominant NIST Juliet C# shape (source is `Console.ReadLine()`).
describe('C# Phase-1: object-carried taint (CommandText -> Execute* sink)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires on Console.ReadLine -> CommandText -> ExecuteScalar (Juliet shape)', async () => {
    const code = `
public class C {
  public void M(SqlConnection db) {
    string data = Console.ReadLine();
    using (SqlCommand cmd = new SqlCommand(null, db)) {
      cmd.CommandText = "select * from users where name='" + data + "'";
      object x = cmd.ExecuteScalar();
    }
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('fires on interpolated CommandText -> ExecuteReader', async () => {
    const code = `
public class C {
  public void M() {
    string data = Console.ReadLine();
    var cmd = new SqlCommand();
    cmd.CommandText = $"SELECT * FROM u WHERE n='{data}'";
    cmd.ExecuteReader();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('does NOT fire when CommandText is a static literal (data unused)', async () => {
    const code = `
public class C {
  public void M() {
    string data = Console.ReadLine();
    var cmd = new SqlCommand();
    cmd.CommandText = "SELECT 1";
    cmd.ExecuteScalar();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });

  it('does NOT fire when parameterized (data only via AddWithValue)', async () => {
    const code = `
public class C {
  public void M() {
    string data = Console.ReadLine();
    var cmd = new SqlCommand();
    cmd.CommandText = "SELECT * FROM u WHERE id=@id";
    cmd.Parameters.AddWithValue("@id", data);
    cmd.ExecuteReader();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });
});

// cognium-dev#276 — Process.Start(fileName, arguments) argv overload: taint in
// the `arguments` string (arg[1]) must fire command_injection, not just the
// single-string overload.
describe('C# Phase-1: Process.Start(fileName, arguments) argv overload (#276)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const has = (r: Awaited<ReturnType<typeof analyze>>, t = 'command_injection') =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === t);

  it('fires on Process.Start("/bin/sh", "-c " + arg)', async () => {
    const code = `
using System.Diagnostics;
public class C { public void M(string arg) { Process.Start("/bin/sh", "-c " + arg); } }`;
    expect(has(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });

  it('still fires on the single-string overload', async () => {
    const code = `
using System.Diagnostics;
public class C { public void M(string arg) { Process.Start("sh -c " + arg); } }`;
    expect(has(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });

  it('does NOT fire when both args are literals', async () => {
    const code = `
using System.Diagnostics;
public class C { public void M() { Process.Start("/bin/ls", "-la"); } }`;
    expect(has(await analyze(code, 'C.cs', 'csharp'))).toBe(false);
  });
});

// cognium-dev#277 — Environment.GetEnvironmentVariable(s) is an attacker-
// influenced source (containers / CI / .env loaders): env→shell and env→sql.
describe('C# Phase-1: Environment.GetEnvironmentVariable source (#277)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const has = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === t);

  it('fires on GetEnvironmentVariable -> Process.Start (env→shell)', async () => {
    const code = `
using System;
using System.Diagnostics;
public class C {
  public void M() {
    var cmd = Environment.GetEnvironmentVariable("START_CMD");
    Process.Start(cmd);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'command_injection')).toBe(true);
  });

  it('fires on GetEnvironmentVariable -> SqlCommand (env→sql)', async () => {
    const code = `
using System;
using System.Data.SqlClient;
public class C {
  public void M(SqlConnection cn) {
    var e = Environment.GetEnvironmentVariable("Q");
    var cmd = new SqlCommand("SELECT * FROM u WHERE n='" + e + "'", cn);
    cmd.ExecuteReader();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('does NOT fire when the env value only reaches a literal-safe use', async () => {
    const code = `
using System;
public class C {
  public void M() {
    var e = Environment.GetEnvironmentVariable("Q");
    System.Console.WriteLine("hello world");
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'command_injection')).toBe(false);
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });
});

// cognium-dev#272 — XXE sanitizer credit: XmlResolver=null / DtdProcessing
// Prohibit|Ignore are the documented XXE mitigations, so a hardened parse must
// not fire `xxe`.
describe('C# Phase-2: XXE hardening sanitizer (#272)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const xxe = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.sinks ?? []).some((s) => s.type === 'xxe');

  it('still fires on an unhardened XmlDocument.LoadXml', async () => {
    const code = `
using System.Xml;
public class C { public void M(string xml) { var d = new XmlDocument(); d.LoadXml(xml); } }`;
    expect(xxe(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });

  it('is credited by XmlResolver = null', async () => {
    const code = `
using System.Xml;
public class C { public void M(string xml) { var d = new XmlDocument(); d.XmlResolver = null; d.LoadXml(xml); } }`;
    expect(xxe(await analyze(code, 'C.cs', 'csharp'))).toBe(false);
  });

  it('is credited by DtdProcessing = Prohibit', async () => {
    const code = `
using System.Xml;
public class C {
  public void M(string xml) {
    var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
    var r = XmlReader.Create(new System.IO.StringReader(xml), s);
    var d = new XmlDocument();
    d.Load(r);
  }
}`;
    expect(xxe(await analyze(code, 'C.cs', 'csharp'))).toBe(false);
  });
});

// cognium-dev#274 (Q-25) — missing-public-doc for C#.
// cognium-dev#273/#275 — canonical missing sink categories (taint-gated).
describe('C# Phase-2: open_redirect / crlf / nosql sink categories (#273/#275)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const has = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === t);

  it('open_redirect: return Redirect(taintedUrl) fires; constant is clean', async () => {
    const tp = `
using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public IActionResult M([FromQuery] string url) { var u = url; return Redirect(u); }
}`;
    const safe = `
using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase { public IActionResult M() { return Redirect("/home"); } }`;
    expect(has(await analyze(tp, 'C.cs', 'csharp'), 'open_redirect')).toBe(true);
    expect(has(await analyze(safe, 'C.cs', 'csharp'), 'open_redirect')).toBe(false);
  });

  it('crlf: Response.AddHeader(name, taintedValue) fires', async () => {
    const code = `
using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public void M([FromQuery] string v) { var x = v; Response.AddHeader("X-Custom", x); }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'crlf')).toBe(true);
  });

  it('nosql: BsonDocument.Parse(taintedJson) fires; constant is clean', async () => {
    const tp = `
using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  public void M([FromQuery] string json) { var j = json; var f = BsonDocument.Parse(j); }
}`;
    const safe = `public class C { public void M() { var f = BsonDocument.Parse("{}"); } }`;
    expect(has(await analyze(tp, 'C.cs', 'csharp'), 'nosql_injection')).toBe(true);
    expect(has(await analyze(safe, 'C.cs', 'csharp'), 'nosql_injection')).toBe(false);
  });
});

describe('C# Phase-2: missing-public-doc (#274 Q-25)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const docFindings = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.findings ?? []).filter((f) => f.rule_id === 'missing-public-doc').map((f) => f.line);

  it('flags an undocumented public class and method; documented/private/internal stay clean', async () => {
    const code = `namespace App {
  /// <summary>A documented service.</summary>
  public class Svc {
    /// <summary>Does the thing.</summary>
    public void Documented() {}
    public void Undocumented(int x) {}
    private void Helper() {}
    internal void Internal() {}
  }
}`;
    const lines = docFindings(await analyze(code, 'Svc.cs', 'csharp'));
    expect(lines).toContain(6);   // Undocumented public method
    expect(lines).not.toContain(5); // Documented
    expect(lines).not.toContain(7); // private Helper
    expect(lines).not.toContain(8); // internal Internal
    expect(lines).not.toContain(3); // documented class
  });
});

// cognium-ai#317 — C# xxe/deserialization sinks are reached via param-seeded
// (interprocedural_param) sources, but that source was missing xxe/deserialization
// in the reach-map, so flows never formed and findings converted at 0%.
// cognium-ai#328 — Process.Start(constNonShellExe, arguments) argv form is not
// command injection (the non-shell exe receives args directly, no shell).
describe('C# Phase-2: Process.Start non-shell argv safe-shape (#328)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const cmdi = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === 'command_injection');
  const ctrl = (body: string) => `
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class C { public void M([FromQuery] string arg) { var a = arg; ${body} } }`;

  it('does NOT fire on a constant non-shell executable (git / dotnet)', async () => {
    expect(cmdi(await analyze(ctrl(`Process.Start("git", "clone " + a);`), 'C.cs', 'csharp'))).toBe(false);
    expect(cmdi(await analyze(ctrl(`Process.Start("dotnet", "run " + a);`), 'C.cs', 'csharp'))).toBe(false);
  });

  it('STILL fires on a shell executable (preserves #276)', async () => {
    for (const b of [`Process.Start("/bin/sh", "-c " + a);`, `Process.Start("cmd", "/c " + a);`, `Process.Start("powershell", "-Command " + a);`]) {
      expect(cmdi(await analyze(ctrl(b), 'C.cs', 'csharp'))).toBe(true);
    }
  });

  it('STILL fires on a variable executable and the single-string overload', async () => {
    const varExe = `using System.Diagnostics; using Microsoft.AspNetCore.Mvc;
public class C { public void M([FromQuery] string exe) { var e = exe; Process.Start(e, "sub"); } }`;
    expect(cmdi(await analyze(varExe, 'C.cs', 'csharp'))).toBe(true);
    expect(cmdi(await analyze(ctrl(`Process.Start("sh -c " + a);`), 'C.cs', 'csharp'))).toBe(true);
  });
});

// cognium-ai#326 Child B — ASP.NET ControllerBase.File(stream|bytes, contentType)
// is a result helper, not a path sink; the Java `new File(path)` sink over-matched it.
// cognium-ai#318 — C# ILogger log injection (CWE-117). Only the message
// template (arg[0]) is injectable; the structured form keeps taint in later args.
describe('C# Phase-2: ILogger log_injection (#318)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const has = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === 'log_injection');
  const ctrl = (body: string) => `
using Microsoft.AspNetCore.Mvc; using Microsoft.Extensions.Logging;
public class C : ControllerBase { private ILogger _logger; public void M([FromQuery] string u) { var x = u; ${body} } }`;

  it('fires when the tainted value is the log message', async () => {
    for (const b of [`_logger.LogInformation(x);`, `_logger.LogError("bad: " + x);`, `_logger.LogWarning(x);`]) {
      expect(has(await analyze(ctrl(b), 'C.cs', 'csharp'))).toBe(true);
    }
  });

  it('does NOT fire on structured logging (taint in a template argument) or a constant message', async () => {
    expect(has(await analyze(ctrl(`_logger.LogInformation("User {Id} did action", x);`), 'C.cs', 'csharp'))).toBe(false);
    expect(has(await analyze(ctrl(`_logger.LogInformation("app started");`), 'C.cs', 'csharp'))).toBe(false);
  });
});

// cognium-ai#326 Child C — a tainted var NAME appearing only inside a SQL string
// literal (parameterized `"… WHERE n=@n"`) must not taint the command object.
describe('C# Phase-2: parameterized query not sql_injection (#326 C)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const has = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === 'sql_injection');
  const M = (body: string) => `
using System.Data.SqlClient;
public class C {
  public void M([Microsoft.AspNetCore.Mvc.FromQuery] string n) {
${body}
  }
}`;

  it('does NOT fire on a parameterized query whose literal contains the param name', async () => {
    expect(has(await analyze(M(`    var cmd = new SqlCommand("SELECT * FROM u WHERE n=@n");\n    cmd.Parameters.AddWithValue("@n", n);\n    cmd.ExecuteReader();`), 'C.cs', 'csharp'))).toBe(false);
    expect(has(await analyze(M(`    var cmd = new SqlCommand("SELECT * FROM u WHERE n=@n");\n    cmd.ExecuteReader();`), 'C.cs', 'csharp'))).toBe(false);
  });

  it('STILL fires on genuine concatenation / interpolation into the command', async () => {
    expect(has(await analyze(M(`    var cmd = new SqlCommand("SELECT * FROM u WHERE n=" + n);\n    cmd.ExecuteReader();`), 'C.cs', 'csharp'))).toBe(true);
    expect(has(await analyze(M(`    var cmd = new SqlCommand();\n    cmd.CommandText = "SELECT * FROM u WHERE n=" + n;\n    cmd.ExecuteReader();`), 'C.cs', 'csharp'))).toBe(true);
  });
});

describe('C# Phase-2: ControllerBase.File() not path_traversal (#326 B)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const path = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === 'path_traversal');

  it('does NOT fire on File(stream, ct) / File(bytes, ct)', async () => {
    const s = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase { public IActionResult M(System.IO.Stream s) { return File(s, "application/pdf"); } }`;
    const b = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase { public IActionResult M(byte[] b) { return File(b, "application/pdf"); } }`;
    expect(path(await analyze(s, 'C.cs', 'csharp'))).toBe(false);
    expect(path(await analyze(b, 'C.cs', 'csharp'))).toBe(false);
  });

  it('STILL fires on a real path sink (File.ReadAllText of user input)', async () => {
    const code = `using System.IO; using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase { public string M([FromQuery] string p) { var x = p; return File.ReadAllText(x); } }`;
    expect(path(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });
});

describe('C# Phase-2: xxe / deserialization reach-map (#317)', () => {
  beforeAll(async () => { await initAnalyzer(); });
  const has = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
    (r.taint?.flows ?? []).some((f) => f.sink_type === t);

  it('a param flowing to XmlDocument.LoadXml forms an xxe flow', async () => {
    const code = `
using System.Xml;
public class C { public void M(string xml) { var d = new XmlDocument(); d.LoadXml(xml); } }`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xxe')).toBe(true);
  });

  it('a param flowing to BinaryFormatter.Deserialize forms a deserialization flow', async () => {
    const code = `
using System.Runtime.Serialization.Formatters.Binary;
public class C { public object M(System.IO.Stream s) { var bf = new BinaryFormatter(); return bf.Deserialize(s); } }`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'deserialization')).toBe(true);
  });

  it('a hardened parse (XmlResolver = null) stays clean', async () => {
    const code = `
using System.Xml;
public class C { public void M(string xml) { var d = new XmlDocument(); d.XmlResolver = null; d.LoadXml(xml); } }`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'xxe')).toBe(false);
  });

  // cognium-ai#318 — additional canonical polymorphic deserializers + the
  // DTD-resolving XmlTextReader.
  it('SoapFormatter / LosFormatter / ObjectStateFormatter fire deserialization', async () => {
    const cases = ['SoapFormatter', 'LosFormatter', 'ObjectStateFormatter'];
    for (const cls of cases) {
      const code = `
using System.IO;
public class C { public void M(string d, Stream s) { var f = new ${cls}(); f.Deserialize(d); } }`;
      expect(has(await analyze(code, 'C.cs', 'csharp'), 'deserialization')).toBe(true);
    }
  });

  it('new XmlTextReader(input) fires xxe; hardened (DtdProcessing=Prohibit) is clean', async () => {
    const unsafe = `
using System.Xml; using System.IO;
public class C { public void M(string d) { var r = new XmlTextReader(new StringReader(d)); while (r.Read()) {} } }`;
    const safe = `
using System.Xml; using System.IO;
public class C { public void M(string d) { var r = new XmlTextReader(new StringReader(d)); r.DtdProcessing = DtdProcessing.Prohibit; while (r.Read()) {} } }`;
    expect(has(await analyze(unsafe, 'C.cs', 'csharp'), 'xxe')).toBe(true);
    expect(has(await analyze(safe, 'C.cs', 'csharp'), 'xxe')).toBe(false);
  });
});

describe('C# Phase-1: explicit ASP.NET request sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('direct Request.Query["id"] read reaches a SQL sink', async () => {
    const code = `
public class C {
  public IActionResult Get() {
    var id = Request.Query["id"];
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id, conn);
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(true);
  });

  it('HttpContext.Request.Headers read reaches an SSRF sink', async () => {
    const code = `
public class C {
  public async Task<IActionResult> Get() {
    var u = HttpContext.Request.Headers["X-Url"];
    var c = new HttpClient();
    await c.GetAsync(u);
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'ssrf')).toBe(true);
  });

  it('does NOT seed a non-request read as a source', async () => {
    const code = `
public class C {
  public IActionResult Get() {
    var id = Config.Get("id");
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id, conn);
    return Ok();
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'sql_injection')).toBe(false);
  });
});

describe('C# Phase-1: insecure deserialization (via receiver-type resolution)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('BinaryFormatter.Deserialize(stream) fires (receiver bf resolved to BinaryFormatter)', async () => {
    const code = `
public class C {
  public object M(System.IO.Stream s) {
    var bf = new BinaryFormatter();
    return bf.Deserialize(s);
  }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'deserialization')).toBe(true);
  });

  it('does NOT flag JsonSerializer.Deserialize (not a BinaryFormatter sink)', async () => {
    const code = `
public class C {
  public object M(string json) { return JsonSerializer.Deserialize(json); }
}`;
    expect(has(await analyze(code, 'C.cs', 'csharp'), 'deserialization')).toBe(false);
  });
});
