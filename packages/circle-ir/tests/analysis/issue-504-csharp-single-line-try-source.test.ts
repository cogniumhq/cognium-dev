/**
 * cognium-dev #504 — the same `Console.ReadLine()` assignment is seeded or
 * lost depending only on whether the `try` is written on one line. The
 * line-anchored assignment matcher never saw `data = …` nested in
 * `try { … } catch { }`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const run = (body: string) => analyze(body, 'P.cs', 'csharp');

describe('#504 C# source binding inside a single-line try', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('seeds io_input when ReadLine sits in a single-line try', async () => {
    const r = await run([
      'using System;',
      'using System.Diagnostics;',
      'public class P { public void Bad() {',
      '  string data = "";',
      '  try { data = Console.ReadLine(); } catch (Exception) { }',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    const sources = r.taint.sources.filter(s => s.type === 'io_input' && s.variable === 'data');
    expect(sources).toHaveLength(1);
    expect(sources[0].line).toBe(5);
  });

  it('still seeds io_input when the try block spans several lines', async () => {
    const r = await run([
      'using System;',
      'using System.Diagnostics;',
      'public class P { public void Bad() {',
      '  string data;',
      '  data = "";',
      '  try',
      '  {',
      '    data = Console.ReadLine();',
      '  }',
      '  catch (Exception exceptIO) { Console.WriteLine(exceptIO.Message); }',
      '  Process.Start("cmd.exe /c " + data);',
      '} }',
    ].join('\n'));
    const sources = r.taint.sources.filter(s => s.type === 'io_input' && s.variable === 'data');
    expect(sources).toHaveLength(1);
    expect(sources[0].line).toBe(8);
  });

  it('does not seed a single-line try that assigns a constant', async () => {
    const r = await run([
      'using System;',
      'public class P { public void Ok() {',
      '  string data = "";',
      '  try { data = "safe"; } catch (Exception) { }',
      '} }',
    ].join('\n'));
    expect(r.taint.sources.filter(s => s.type === 'io_input')).toHaveLength(0);
  });

  it('ignores a commented single-line try', async () => {
    const r = await run([
      'using System;',
      'public class P { public void Ok() {',
      '  // try { data = Console.ReadLine(); } catch (Exception) { }',
      '} }',
    ].join('\n'));
    expect(r.taint.sources.filter(s => s.type === 'io_input')).toHaveLength(0);
  });
});
