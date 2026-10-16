/**
 * C# project gate: a parameter-seeded sink finding is dropped when every
 * resolved in-project caller passes a constant at that parameter (#636, C# slice).
 *
 * Per-file analysis reports a sink that receives a `string` parameter with an
 * `interprocedural_param` seed, whether or not any caller passes tainted data.
 * `analyzeProject` knows the callers, so it drops the finding when every call
 * site passes a string literal (or a local assigned one literal), and keeps it
 * for tainted, mixed, unknown, unresolved, virtual and caller-less shapes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';

type F = { filePath: string; code: string };

const project = async (files: F[]) => {
  const pa = await analyzeProject(files.map(f => ({ ...f, language: 'csharp' as const })), {});
  const out = new Map<string, Array<{ sink_type: string; sink_line: number; source_type: string }>>();
  for (const fa of pa.files) {
    out.set(fa.file, (fa.analysis.taint.flows ?? []).map(f => ({
      sink_type: f.sink_type, sink_line: f.sink_line, source_type: f.source_type,
    })));
  }
  return { pa, flows: out };
};

const lineOf = (code: string, needle: string, nth = 0) => {
  let seen = -1;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle) && ++seen === nth) return i + 1;
  }
  return -1;
};

const dispatcher = `using System.Web;
public class Dispatcher
{
    public void HandleRequest(HttpRequest req)
    {
        string item = req.QueryString["item"];
        Worker.RunWithInput(item);
    }
    public void Nightly()
    {
        string label = "nightly-report";
        Worker.RunWithLabel(label);
    }
}
`;

const worker = `using System.Diagnostics;
public class Worker
{
    public static void RunWithInput(string arg)
    {
        Process.Start("tool.exe " + arg);
    }
    public static void RunWithLabel(string arg)
    {
        Process.Start("tool.exe " + arg);
    }
}
`;

const cmdAt = (flows: Map<string, Array<{ sink_type: string; sink_line: number }>>, file: string, line: number, type = 'command_injection') =>
  (flows.get(file) ?? []).some(f => f.sink_type === type && f.sink_line === line);

describe('C# constant-only callers (#636)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports the tainted-caller sink and drops the constant-caller sink', async () => {
    const { flows, pa } = await project([
      { filePath: 'Dispatcher.cs', code: dispatcher },
      { filePath: 'Worker.cs', code: worker },
    ]);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 0))).toBe(true);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 1))).toBe(false);
    expect(pa.taint_paths.some(p => p.sink.file === 'Worker.cs' && p.sink.line === lineOf(worker, 'Process.Start', 0))).toBe(true);
  });

  it('a literal argument passed directly is a constant', async () => {
    const caller = `public class Cron
{
    public void Tick()
    {
        Worker.RunWithLabel("hourly");
    }
}
`;
    const { flows } = await project([{ filePath: 'Cron.cs', code: caller }, { filePath: 'Worker.cs', code: worker }]);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 1))).toBe(false);
    // RunWithInput has no in-project caller here: it may be public API.
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 0))).toBe(true);
  });

  it('keeps a method with one constant caller and one tainted caller', async () => {
    const caller = `using System.Web;
public class Mixed
{
    public void A() { string s = "fixed"; Worker.RunWithLabel(s); }
    public void B(HttpRequest req) { string t = req.QueryString["t"]; Worker.RunWithLabel(t); }
}
`;
    const { flows } = await project([{ filePath: 'Mixed.cs', code: caller }, { filePath: 'Worker.cs', code: worker }]);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 1))).toBe(true);
  });

  it('keeps a public static method with no in-project caller', async () => {
    const { flows } = await project([{ filePath: 'Worker.cs', code: worker }, { filePath: 'Other.cs', code: 'public class Other { public void Run() { } }\n' }]);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 0))).toBe(true);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 1))).toBe(true);
  });

  it('keeps a method when one caller passes its own parameter', async () => {
    const caller = `public class Relay
{
    public void A() { string s = "fixed"; Worker.RunWithLabel(s); }
    public void B(string passedOn) { Worker.RunWithLabel(passedOn); }
}
`;
    const { flows } = await project([{ filePath: 'Relay.cs', code: caller }, { filePath: 'Worker.cs', code: worker }]);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 1))).toBe(true);
  });

  const entryRelayRunner = {
    entry: `using System.Web;
public class Entry
{
    public void Live(HttpRequest req)
    {
        string item = req.QueryString["item"];
        Relay.WithInput(item);
    }
    public void Nightly()
    {
        string label = "nightly-report";
        Relay.WithLabel(label);
    }
}
`,
    relay: `public class Relay
{
    public static void WithInput(string arg) { Runner.RunInput(arg); }
    public static void WithLabel(string arg) { Runner.RunLabel(arg); }
}
`,
    runner: `using System.Diagnostics;
public class Runner
{
    public static void RunInput(string arg) { Process.Start("tool.exe " + arg); }
    public static void RunLabel(string arg) { Process.Start("tool.exe " + arg); }
}
`,
  };

  it('drops a sink when constants reach it through forwarded parameters', async () => {
    const { flows, pa } = await project([
      { filePath: 'Entry.cs', code: entryRelayRunner.entry },
      { filePath: 'Relay.cs', code: entryRelayRunner.relay },
      { filePath: 'Runner.cs', code: entryRelayRunner.runner },
    ]);
    expect(cmdAt(flows, 'Runner.cs', lineOf(entryRelayRunner.runner, 'RunInput', 0))).toBe(true);
    expect(cmdAt(flows, 'Runner.cs', lineOf(entryRelayRunner.runner, 'RunLabel', 0))).toBe(false);
    expect(pa.taint_paths.some(p => p.sink.file === 'Runner.cs' && p.sink.line === lineOf(entryRelayRunner.runner, 'RunInput', 0))).toBe(true);
  });

  it('keeps forwarding when a second caller passes tainted data into the relay', async () => {
    const entry = entryRelayRunner.entry.replace(
      'Relay.WithLabel(label);',
      `Relay.WithLabel(label);
        Relay.WithLabel(req.QueryString["extra"]);`,
    );
    const { flows } = await project([
      { filePath: 'Entry.cs', code: entry },
      { filePath: 'Relay.cs', code: entryRelayRunner.relay },
      { filePath: 'Runner.cs', code: entryRelayRunner.runner },
    ]);
    expect(cmdAt(flows, 'Runner.cs', lineOf(entryRelayRunner.runner, 'RunLabel', 0))).toBe(true);
  });

  it('keeps a method when a local is reassigned to a non-constant before the call', async () => {
    const caller = `using System.Web;
public class Reassign
{
    public void A(HttpRequest req)
    {
        string s = "fixed";
        s = req.QueryString["x"];
        Worker.RunWithLabel(s);
    }
}
`;
    const { flows } = await project([{ filePath: 'Reassign.cs', code: caller }, { filePath: 'Worker.cs', code: worker }]);
    expect(cmdAt(flows, 'Worker.cs', lineOf(worker, 'Process.Start', 1))).toBe(true);
  });

  it('keeps a method whose constant caller goes through an unresolved receiver', async () => {
    const callee = `using System.Diagnostics;
public class Tool
{
    public void RunLabelled(string arg)
    {
        Process.Start("tool.exe " + arg);
    }
}
`;
    const caller = `public class Boot
{
    public void Go(IToolFactory factory)
    {
        var tool = factory.Create();
        string label = "boot";
        tool.RunLabelled(label);
    }
}
`;
    const { flows } = await project([{ filePath: 'Boot.cs', code: caller }, { filePath: 'Tool.cs', code: callee }]);
    expect(cmdAt(flows, 'Tool.cs', lineOf(callee, 'Process.Start'))).toBe(true);
  });

  it('keeps a virtual method even when its only caller passes a constant', async () => {
    const callee = `using System.Diagnostics;
public class BaseTool
{
    public virtual void RunLabelled(string arg)
    {
        Process.Start("tool.exe " + arg);
    }
}
`;
    const caller = `public class Boot
{
    public void Go()
    {
        string label = "boot";
        BaseTool.RunLabelled(label);
    }
}
`;
    const { flows } = await project([{ filePath: 'Boot.cs', code: caller }, { filePath: 'BaseTool.cs', code: callee }]);
    expect(cmdAt(flows, 'BaseTool.cs', lineOf(callee, 'Process.Start'))).toBe(true);
  });

  it('single-file analyze() output is unchanged', async () => {
    const both = `${dispatcher}\n${worker}`.replace('using System.Diagnostics;\n', '').replace('using System.Web;\n', 'using System.Web;\nusing System.Diagnostics;\n');
    const ir = await analyze(both, 'Both.cs', 'csharp');
    const sinks = (ir.taint.flows ?? []).filter(f => f.sink_type === 'command_injection').map(f => f.sink_line);
    expect(sinks).toContain(lineOf(both, 'Process.Start', 0));
    expect(sinks).toContain(lineOf(both, 'Process.Start', 1));
  });

  describe('SqlCommand sink', () => {
    const repo = `using System.Data.SqlClient;
public class Repo
{
    public static void FindByKey(string key, SqlConnection conn)
    {
        var cmd = new SqlCommand("SELECT * FROM t WHERE k = '" + key + "'", conn);
        cmd.ExecuteReader();
    }
    public static void FindByLabel(string label, SqlConnection conn)
    {
        var cmd = new SqlCommand("SELECT * FROM t WHERE k = '" + label + "'", conn);
        cmd.ExecuteReader();
    }
}
`;
    const callers = `using System.Web;
using System.Data.SqlClient;
public class Page
{
    public void Get(HttpRequest req, SqlConnection conn)
    {
        string k = req.QueryString["k"];
        Repo.FindByKey(k, conn);
    }
    public void Report(SqlConnection conn)
    {
        string name = "monthly";
        Repo.FindByLabel(name, conn);
    }
}
`;
    it('drops the constant-only caller, keeps the tainted and the caller-less shapes', async () => {
      const { flows } = await project([{ filePath: 'Page.cs', code: callers }, { filePath: 'Repo.cs', code: repo }]);
      expect(cmdAt(flows, 'Repo.cs', lineOf(repo, 'cmd.ExecuteReader', 0), 'sql_injection')
        || cmdAt(flows, 'Repo.cs', lineOf(repo, 'new SqlCommand', 0), 'sql_injection')).toBe(true);
      expect(cmdAt(flows, 'Repo.cs', lineOf(repo, 'cmd.ExecuteReader', 1), 'sql_injection')).toBe(false);
      expect(cmdAt(flows, 'Repo.cs', lineOf(repo, 'new SqlCommand', 1), 'sql_injection')).toBe(false);

      const alone = await project([{ filePath: 'Repo.cs', code: repo }, { filePath: 'Other.cs', code: 'public class Other { }\n' }]);
      const sqlLines = (alone.flows.get('Repo.cs') ?? []).filter(f => f.sink_type === 'sql_injection').length;
      expect(sqlLines).toBeGreaterThanOrEqual(2);
    });
  });
});
