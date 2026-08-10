/**
 * C#/.NET Phase-0 spike — proof-of-life regression tests.
 *
 * These lock the spike's working slice: C# parses, IR extraction (types/methods/
 * params + invocation/object-creation calls) works, and a straight-line ASP.NET
 * SQLi flow fires end-to-end — including string interpolation — via the
 * text-based expression-scan propagation (buildJavaTaintedVars), WITHOUT a full
 * buildCSharpDFG. The parameterized/AddWithValue shape correctly does not fire.
 *
 * SPIKE SCOPE ONLY. This is not production C# support — no cross-file, no branch/
 * alias DFG, ~3 sink patterns. See the C#/.NET epic in .specifica/mvp/tasks.md.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sqli = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).some(f => f.sink_type === 'sql_injection');

describe('C# spike: parse + IR extraction', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('parses C# and extracts the class, method, and parameter', async () => {
    const code = `
namespace Demo {
  public class HomeController {
    public IActionResult Get(string id) { return Ok(); }
  }
}`;
    const r = await analyze(code, 'HomeController.cs', 'csharp');
    const types = r.types ?? [];
    expect(types.map(t => t.name)).toContain('HomeController');
    const m = types[0]?.methods.find(x => x.name === 'Get');
    expect(m).toBeDefined();
    expect(m?.parameters.map(p => p.name)).toContain('id');
  });

  it('extracts invocation_expression and object_creation_expression calls', async () => {
    const code = `
public class C {
  public void M(string id) {
    var cmd = new SqlCommand("q", conn);
    cmd.ExecuteReader();
  }
}`;
    const r = await analyze(code, 'C.cs', 'csharp');
    const names = (r.calls ?? []).map(c => c.method_name);
    expect(names).toContain('SqlCommand');    // object creation
    expect(names).toContain('ExecuteReader'); // invocation
  });
});

describe('C# spike: SQLi taint flow (text expression-scan path)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires on string concatenation into new SqlCommand', async () => {
    const code = `
public class C {
  public IActionResult Get(string id) {
    var q = "SELECT * FROM u WHERE id=" + id;
    var cmd = new SqlCommand(q, conn);
    return Ok();
  }
}`;
    expect(sqli(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });

  it('fires on string interpolation $"...{id}..." assigned then sunk', async () => {
    const code = `
public class C {
  public IActionResult Get(string id) {
    var q = $"SELECT * FROM u WHERE id={id}";
    var cmd = new SqlCommand(q, conn);
    return Ok();
  }
}`;
    expect(sqli(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });

  it('fires on interpolation passed directly into the sink', async () => {
    const code = `
public class C {
  public IActionResult Get(string id) {
    var cmd = new SqlCommand($"SELECT * FROM u WHERE id={id}", conn);
    return Ok();
  }
}`;
    expect(sqli(await analyze(code, 'C.cs', 'csharp'))).toBe(true);
  });

  it('does NOT fire on a parameterized query (literal SQL + AddWithValue)', async () => {
    const code = `
public class C {
  public IActionResult Get(string id) {
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=@id", conn);
    cmd.Parameters.AddWithValue("@id", id);
    return Ok();
  }
}`;
    expect(sqli(await analyze(code, 'C.cs', 'csharp'))).toBe(false);
  });
});
