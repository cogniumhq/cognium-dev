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

describe('C# Phase-1: known gaps (next slices)', () => {
  // Deserialization (BinaryFormatter.Deserialize) needs receiver-type resolution
  // — the receiver is an instance var, not the class name.
  it.todo('BinaryFormatter.Deserialize should fire (needs receiver-type resolution)');
});
