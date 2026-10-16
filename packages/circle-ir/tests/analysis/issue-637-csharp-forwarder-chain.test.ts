/**
 * C# project gate (#637, third slice): the callee decision is transitive. A call
 * into a project method that has no sink of its own but only hands the value on
 * to another project method (in a third file, depth <= 4) is not an
 * `external_taint_escape` when the chain ends in a registered sink: the sink (or
 * its absence after the callee-reach check) is what reports. Any hop that is
 * unresolved, ends in an external call, forwards somewhere else as well, stores
 * or returns the value, loops, or runs past four hops keeps the escape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

type F = { filePath: string; code: string };

const run = async (files: F[]) => {
  const pa = await analyzeProject(files.map(f => ({ ...f, language: 'csharp' as const })), {});
  const escapes: string[] = [];
  for (const fa of pa.files) {
    for (const s of fa.analysis.taint.sinks ?? []) {
      if (s.type === 'external_taint_escape') escapes.push(`${fa.file}:${s.line}`);
    }
    for (const f of fa.analysis.taint.flows ?? []) {
      if (f.sink_type === 'external_taint_escape') escapes.push(`${fa.file}:${f.sink_line}`);
    }
  }
  const paths = pa.taint_paths.map(p => `${p.sink.type}@${p.source.file}:${p.source.line}->${p.sink.file}:${p.sink.line}`);
  return { escapes, paths };
};

// Entry calls `<call>` for a tainted value on line 7 and line 12.
const entry = (first: string, second: string): string => `using System.Web;
public class Entry
{
    public void Raw(HttpRequest req)
    {
        string data = req.QueryString["name"];
        ${first}
    }
    public void Bound(HttpRequest req)
    {
        string data = req.QueryString["name"];
        ${second}
    }
}
`;

const store = `using System.Data.SqlClient;
public class Store
{
    public static void Find(string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name=@name", conn);
            cmd.Parameters.AddWithValue("@name", v);
            cmd.ExecuteReader();
        }
    }
    public static void FindRaw(string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from users where name='" + v + "'", conn);
            cmd.ExecuteReader();
        }
    }
}
`;

const relay = `public class Relay
{
    public static void Forward(string v)
    {
        Store.Find(v);
    }
    public static void ForwardRaw(string v)
    {
        Store.FindRaw(v);
    }
}
`;

const baseFiles = (): F[] => [
  { filePath: 'Entry.cs', code: entry('Relay.ForwardRaw(data);', 'Relay.Forward(data);') },
  { filePath: 'Relay.cs', code: relay },
  { filePath: 'Store.cs', code: store },
];

describe('C# forwarder chain is decided by the sinks at its end (#637)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('issue fixture: no escape at either Relay call; sql_injection only for the FindRaw chain', async () => {
    const r = await run(baseFiles());
    expect(r.escapes).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('sql_injection@Entry.cs:6->Store.cs:'))).not.toEqual([]);
    expect(r.paths.filter(p => p.includes('Entry.cs:11'))).toEqual([]);
  });

  it('renamed classes, methods and parameters behave the same', async () => {
    const files: F[] = [
      { filePath: 'Gate.cs', code: entry('Bridge.PassRaw(data);', 'Bridge.Pass(data);').replace('class Entry', 'class Gate') },
      {
        filePath: 'Bridge.cs',
        code: relay.replace('class Relay', 'class Bridge').replace('Forward', 'Pass').replace('ForwardRaw', 'PassRaw').replace(/\bv\b/g, 'payload').replace('Store', 'Lookup').replace('Store', 'Lookup'),
      },
      { filePath: 'Lookup.cs', code: store.replace('class Store', 'class Lookup').replace(/\bv\b/g, 'term') },
    ];
    // Entry method names differ per file; Bridge.Pass / Bridge.PassRaw are the project callees.
    const r = await run(files);
    expect(r.escapes).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('sql_injection@Gate.cs:6->Lookup.cs:'))).not.toEqual([]);
  });

  it('a chain of two forwarders (three files deep) is followed', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.ForwardRaw(data);', 'Relay.Forward(data);') },
      {
        filePath: 'Relay.cs',
        code: `public class Relay
{
    public static void Forward(string v) { Hop.Forward(v); }
    public static void ForwardRaw(string v) { Hop.ForwardRaw(v); }
}
`,
      },
      {
        filePath: 'Hop.cs',
        code: `public class Hop
{
    public static void Forward(string v) { Store.Find(v); }
    public static void ForwardRaw(string v) { Store.FindRaw(v); }
}
`,
      },
      { filePath: 'Store.cs', code: store },
    ];
    const r = await run(files);
    expect(r.escapes).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('sql_injection@Entry.cs:6->Store.cs:'))).not.toEqual([]);
  });

  it('an unresolved hop keeps the escape', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      { filePath: 'Relay.cs', code: `public class Relay\n{\n    public static void Forward(string v)\n    {\n        Vendor.Sdk.Send(v);\n    }\n}\n` },
      { filePath: 'Store.cs', code: store },
    ];
    const r = await run(files);
    expect(r.escapes).toContain('Entry.cs:7');
    expect(r.escapes).toContain('Entry.cs:12');
  });

  it('a relay that forwards to the project sink and to an unresolved call keeps the escape', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      {
        filePath: 'Relay.cs',
        code: `public class Relay\n{\n    public static void Forward(string v)\n    {\n        Store.Find(v);\n        Vendor.Sdk.Send(v);\n    }\n}\n`,
      },
      { filePath: 'Store.cs', code: store },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('a chain that ends in a project method with no registered sink keeps the escape', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      { filePath: 'Relay.cs', code: `public class Relay\n{\n    public static void Forward(string v)\n    {\n        Journal.Write(v);\n    }\n}\n` },
      { filePath: 'Journal.cs', code: `public class Journal\n{\n    public static void Write(string v)\n    {\n        Vendor.Sdk.Append(v);\n    }\n}\n` },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('a relay that also stores the value in a field keeps the escape', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      {
        filePath: 'Relay.cs',
        code: `public class Relay\n{\n    static string last;\n    public static void Forward(string v)\n    {\n        Store.Find(v);\n        last = v;\n    }\n}\n`,
      },
      { filePath: 'Store.cs', code: store },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('a relay that returns the value keeps the escape', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      {
        filePath: 'Relay.cs',
        code: `public class Relay\n{\n    public static string Forward(string v)\n    {\n        Store.Find(v);\n        return v;\n    }\n}\n`,
      },
      { filePath: 'Store.cs', code: store },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('a forwarding loop between two files terminates and keeps the escape', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Ping.Go(data);', 'Ping.Go(data);') },
      { filePath: 'Ping.cs', code: `public class Ping\n{\n    public static void Go(string v)\n    {\n        Pong.Go(v);\n    }\n}\n` },
      { filePath: 'Pong.cs', code: `public class Pong\n{\n    public static void Go(string v)\n    {\n        Ping.Go(v);\n    }\n}\n` },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('a chain longer than four hops keeps the escape', async () => {
    const hop = (name: string, next: string) => `public class ${name}\n{\n    public static void Go(string v)\n    {\n        ${next}.Go(v);\n    }\n}\n`;
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('H1.Go(data);', 'H1.Go(data);') },
      { filePath: 'H1.cs', code: hop('H1', 'H2') },
      { filePath: 'H2.cs', code: hop('H2', 'H3') },
      { filePath: 'H3.cs', code: hop('H3', 'H4') },
      { filePath: 'H4.cs', code: hop('H4', 'H5') },
      { filePath: 'H5.cs', code: hop('H5', 'H6') },
      { filePath: 'H6.cs', code: `public class H6\n{\n    public static void Go(string v)\n    {\n        Store.Find(v);\n    }\n}\n` },
      { filePath: 'Store.cs', code: store },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('the relay forwards a constant, not the parameter: no sink anywhere, the escape stays', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      { filePath: 'Relay.cs', code: `public class Relay\n{\n    public static void Forward(string v)\n    {\n        Store.Find("fixed");\n    }\n}\n` },
      { filePath: 'Store.cs', code: store },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });

  it('a same-named relay in another class does not stand in for the one called', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Other.Forward(data);', 'Other.Forward(data);') },
      { filePath: 'Relay.cs', code: relay },
      { filePath: 'Other.cs', code: `public class Other\n{\n    public static void Forward(string v)\n    {\n        Vendor.Sdk.Send(v);\n    }\n}\n` },
      { filePath: 'Store.cs', code: store },
    ];
    expect((await run(files)).escapes).toContain('Entry.cs:7');
  });
  it('a relay that transforms the value before passing it on keeps the escape', async () => {
    const mk = (call: string): F[] => [
      { filePath: 'Entry.cs', code: entry('Relay.Forward(data);', 'Relay.Forward(data);') },
      { filePath: 'Relay.cs', code: `public class Relay\n{\n    public static void Forward(string v)\n    {\n        ${call}\n    }\n}\n` },
      { filePath: 'Store.cs', code: store },
    ];
    for (const call of ['Store.FindRaw(v.Trim());', 'Store.FindRaw("x" + v);', 'Store.FindRaw(Clean(v));', 'string w = v; Store.FindRaw(w);']) {
      expect((await run(mk(call))).escapes, call).toContain('Entry.cs:7');
    }
  });

  it('the tainted value enters at the second parameter of the relay and the store', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.ForwardRaw("t", data);', 'Relay.Forward("t", data);') },
      {
        filePath: 'Relay.cs',
        code: `public class Relay
{
    public static void Forward(string table, string v) { Store.Find2(table, v); }
    public static void ForwardRaw(string table, string v) { Store.FindRaw2(table, v); }
}
`,
      },
      {
        filePath: 'Store.cs',
        code: `using System.Data.SqlClient;
public class Store
{
    public static void Find2(string table, string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from " + table + " where name=@name", conn);
            cmd.Parameters.AddWithValue("@name", v);
            cmd.ExecuteReader();
        }
    }
    public static void FindRaw2(string table, string v)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            SqlCommand cmd = new SqlCommand("select * from " + table + " where name='" + v + "'", conn);
            cmd.ExecuteReader();
        }
    }
}
`,
      },
    ];
    const r = await run(files);
    expect(r.escapes).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('sql_injection@Entry.cs:6->Store.cs:'))).not.toEqual([]);
    expect(r.paths.filter(p => p.includes('Entry.cs:11'))).toEqual([]);
  });

  it('a relay that reaches the same store through two forwarders is still decided', async () => {
    const files: F[] = [
      { filePath: 'Entry.cs', code: entry('Relay.ForwardRaw(data);', 'Relay.Forward(data);') },
      {
        filePath: 'Relay.cs',
        code: `public class Relay
{
    public static void Forward(string v)
    {
        Left.Go(v);
        Right.Go(v);
    }
    public static void ForwardRaw(string v) { Store.FindRaw(v); }
}
`,
      },
      { filePath: 'Left.cs', code: 'public class Left\n{\n    public static void Go(string v) { Store.Find(v); }\n}\n' },
      { filePath: 'Right.cs', code: 'public class Right\n{\n    public static void Go(string v) { Store.Find(v); }\n}\n' },
      { filePath: 'Store.cs', code: store },
    ];
    const r = await run(files);
    expect(r.escapes).toEqual([]);
    expect(r.paths.filter(p => p.startsWith('sql_injection@Entry.cs:6->Store.cs:'))).not.toEqual([]);
  });
});
