/**
 * cognium-dev #530 — appending a tainted value to a `StringBuilder` did not
 * taint the builder, so reading it back with `ToString()` produced an untainted
 * value. A statement accumulated across several calls was therefore invisible
 * while the identical statement concatenated in one expression was caught.
 *
 * Not tied to one sink family: it hid SQL injection just as readily as code
 * injection. It is why NIST Juliet's CWE-94 family scored 0.0% — that corpus
 * builds the compiled source through `Append` — and a StringBuilder is the
 * idiomatic way to build anything multi-line in C#.
 *
 * Same shape as #271's ADO.NET command-object taint: taint enters an object and
 * is read back later, so it has to ride the object.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const run = (code: string) => analyze(code, 'P.cs', 'csharp');
const flowTypes = (r: Awaited<ReturnType<typeof run>>) =>
  (r.taint.flows ?? []).map(f => f.sink_type);

const sqlVia = (body: string) => `
using System;
using System.Text;
using System.Data.SqlClient;
public class P { public void Bad() {
  string data = Environment.GetEnvironmentVariable("ADD");
  StringBuilder sb = new StringBuilder("");
${body}
  var cmd = new SqlCommand(sb.ToString(), new SqlConnection("cs"));
  cmd.ExecuteNonQuery();
} }
`;

describe('#530 taint rides a StringBuilder from Append through ToString', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports a sink built by appending a tainted value', async () => {
    const r = await run(sqlVia('  sb.Append("SELECT * FROM u WHERE n=\'" + data + "\'");'));
    expect(flowTypes(r)).toContain('sql_injection');
  });

  it('stays clean when only constants are appended', async () => {
    const r = await run(sqlVia('  sb.Append("SELECT * FROM u WHERE n=\'constant\'");'));
    expect(flowTypes(r)).not.toContain('sql_injection');
  });

  for (const verb of ['AppendLine', 'AppendFormat'] as const) {
    it(`treats ${verb} like Append`, async () => {
      const r = await run(sqlVia(`  sb.${verb}("SELECT " + data);`));
      expect(flowTypes(r)).toContain('sql_injection');
    });
  }

  it('treats Insert like Append', async () => {
    const r = await run(sqlVia('  sb.Insert(0, "SELECT " + data);'));
    expect(flowTypes(r)).toContain('sql_injection');
  });

  it('resolves a builder declared with var', async () => {
    const r = await run(`
using System;
using System.Text;
using System.Data.SqlClient;
public class P { public void Bad() {
  string data = Environment.GetEnvironmentVariable("ADD");
  var sb = new StringBuilder("");
  sb.Append("SELECT " + data);
  var cmd = new SqlCommand(sb.ToString(), new SqlConnection("cs"));
  cmd.ExecuteNonQuery();
} }
`);
    expect(flowTypes(r)).toContain('sql_injection');
  });

  it('does not taint a receiver that is not a StringBuilder', async () => {
    // `Insert` and `Append` are far too common as names to match on a bare
    // receiver; the gate is the declared type.
    const r = await run(`
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
public class P { public void Bad() {
  string data = Environment.GetEnvironmentVariable("ADD");
  List<string> lst = new List<string>();
  lst.Insert(0, data);
  var cmd = new SqlCommand(lst.ToString(), new SqlConnection("cs"));
  cmd.ExecuteNonQuery();
} }
`);
    expect(flowTypes(r)).not.toContain('sql_injection');
  });

  it('does not count a variable name that only appears inside a string literal', async () => {
    const r = await run(`
using System;
using System.Text;
using System.Data.SqlClient;
public class P { public void Bad() {
  string id = Environment.GetEnvironmentVariable("ADD");
  StringBuilder sb = new StringBuilder("");
  sb.Append("SELECT * FROM u WHERE id=@id");
  var cmd = new SqlCommand(sb.ToString(), new SqlConnection("cs"));
  cmd.ExecuteNonQuery();
} }
`);
    expect(flowTypes(r)).not.toContain('sql_injection');
  });

  it('does not count a variable name that only appears in a comment', async () => {
    const r = await run(`
using System;
using System.Text;
using System.Data.SqlClient;
public class P { public void Bad() {
  string id = Environment.GetEnvironmentVariable("ADD");
  StringBuilder sb = new StringBuilder("");
  sb.Append("SELECT 1");   // never splices id
  var cmd = new SqlCommand(sb.ToString(), new SqlConnection("cs"));
  cmd.ExecuteNonQuery();
} }
`);
    expect(flowTypes(r)).not.toContain('sql_injection');
  });

  it('does not let a builder seeded in one method reach a sink in another', async () => {
    // The scan matches source variables by name across the whole file, and
    // Juliet reuses `sourceCode` in `Bad` and in every `Good*` variant. Without
    // the method gate a seed created correctly in `Bad` linked to the sink in
    // `GoodG2B`, whose own `data` is a hardcoded constant — 160 false positives
    // on the CWE-94 corpus.
    const r = await run(`
using System;
using System.Text;
using System.Data.SqlClient;
public class P {
  public void Bad() {
    string data = Environment.GetEnvironmentVariable("ADD");
    StringBuilder sb = new StringBuilder("");
    sb.Append("SELECT " + data);
    var cmd = new SqlCommand(sb.ToString(), new SqlConnection("cs"));
    cmd.ExecuteNonQuery();
  }
  public void GoodG2B() {
    string data = "10";
    StringBuilder sb = new StringBuilder("");
    sb.Append("SELECT " + data);
    var cmd = new SqlCommand(sb.ToString(), new SqlConnection("cs"));
    cmd.ExecuteNonQuery();
  }
}
`);
    // Exactly one SQL flow — Bad's. GoodG2B must not contribute one.
    const sqlFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqlFlows.length).toBeGreaterThan(0);
    for (const f of sqlFlows) expect(f.sink_line).toBeLessThan(14);
  });

  it('reports CodeDom compilation of a built source (#503 part 2)', async () => {
    const r = await run(`
using System;
using System.Text;
using System.CodeDom.Compiler;
public class P { public void Bad() {
  string data = Environment.GetEnvironmentVariable("ADD");
  StringBuilder sb = new StringBuilder("");
  sb.Append("class C {" + data + "}");
  CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
  CompilerResults cr = provider.CompileAssemblyFromSource(new CompilerParameters(), sb.ToString());
} }
`);
    expect(flowTypes(r)).toContain('code_injection');
  });

  it('reports CodeDom compilation of a directly concatenated source', async () => {
    const r = await run(`
using System;
using System.CodeDom.Compiler;
public class P { public void Bad() {
  string data = Environment.GetEnvironmentVariable("ADD");
  CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
  CompilerResults cr = provider.CompileAssemblyFromSource(new CompilerParameters(), "class C {" + data + "}");
} }
`);
    expect(flowTypes(r)).toContain('code_injection');
  });

  it('does not report CodeDom compilation of a constant source', async () => {
    const r = await run(`
using System.CodeDom.Compiler;
public class P { public void Bad() {
  CodeDomProvider provider = CodeDomProvider.CreateProvider("CSharp");
  CompilerResults cr = provider.CompileAssemblyFromSource(new CompilerParameters(), "class C {}");
} }
`);
    expect(flowTypes(r)).not.toContain('code_injection');
  });
});
