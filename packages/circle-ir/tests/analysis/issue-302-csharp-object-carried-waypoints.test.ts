/**
 * cognium-dev #302 (from cognium-ai#330).
 *
 * ADO.NET object-carried SQL produced THREE `sql_injection` sinks for one
 * vulnerability — the zero-argument `new SqlCommand()`, the `CommandText`
 * write, and the real `Execute*` call — so every consumer reported 3 findings
 * at 3 lines for 1 bug, two of which cannot be triaged or patched.
 *
 * A zero-arg constructor has no argument to carry taint, so it is dropped as a
 * sink outright. The `CommandText` write is the waypoint that loads the command
 * object, and its duplicate flow is dropped only when a flow already reports a
 * later execution of the same object — so a shape whose execution is never
 * reported (Juliet-C# `CommandText_15`) keeps its only signal.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const sqlSinks = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.sinks ?? []).filter(s => s.type === 'sql_injection');

describe('#302 C# object-carried SQL: one vulnerability, one sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const carried = [
    'using System;',
    'using System.Data.SqlClient;',
    'public class C {',
    '  public void M() {',
    '    string data = Console.ReadLine();',
    '    SqlCommand cmd = new SqlCommand();',
    '    cmd.CommandText = "select * from users where name=\'" + data + "\'";',
    '    object x = cmd.ExecuteScalar();',
    '  }',
    '}',
  ].join('\n');

  it('drops the zero-argument constructor sink', async () => {
    const r = await analyze(carried, 'C.cs', 'csharp');
    const sinks = sqlSinks(r);
    expect(sinks.some(s => s.method === 'SqlCommand')).toBe(false);
    expect(sinks.some(s => s.line === 6)).toBe(false);
  });

  it('reports the vulnerability exactly once, at the Execute call', async () => {
    const r = await analyze(carried, 'C.cs', 'csharp');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(8);
  });

  it('keeps the CommandText flow when nothing executes the command (recall)', async () => {
    const code = [
      'using System;',
      'using System.Data.SqlClient;',
      'public class C {',
      '  public void NoExec() {',
      '    string data = Console.ReadLine();',
      '    SqlCommand cmd = new SqlCommand();',
      '    cmd.CommandText = "select * from users where name=\'" + data + "\'";',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.cs', 'csharp');
    const flows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(7);
  });

  it('keeps a constructor sink when the constructor itself takes concatenated SQL (recall)', async () => {
    const code = [
      'using System;',
      'using System.Data.SqlClient;',
      'public class C {',
      '  public void CtorConcat(SqlConnection conn) {',
      '    string data = Console.ReadLine();',
      '    SqlCommand cmd = new SqlCommand("select * from u where n=\'" + data + "\'", conn);',
      '    cmd.ExecuteReader();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.cs', 'csharp');
    expect(sqlSinks(r).some(s => s.method === 'SqlCommand')).toBe(true);
  });
});
