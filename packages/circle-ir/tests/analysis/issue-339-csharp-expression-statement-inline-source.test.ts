/**
 * cognium-dev #339 — a C# sink called as a bare expression statement with the
 * request read inline in its arguments was silent:
 *
 *   var s = File.Create(Path.Combine("/uploads", file.FileName));   // fired
 *           File.Create(Path.Combine("/uploads", file.FileName));   // silent
 *
 * `findCSharpRequestSources` only bound a source to the LHS of an assignment,
 * so a statement with no LHS carried no source at all. Java/Python/JS already
 * anchor inline reads on the statement line, so this was C#-only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const HEADER = [
  'using System;',
  'using System.IO;',
  'using Microsoft.AspNetCore.Http;',
  'using Microsoft.AspNetCore.Mvc;',
].join('\n');

const run = (params: string, body: string[]) =>
  analyze(
    [
      HEADER,
      'public class UploadController : Controller {',
      `  public void Run(${params}) {`,
      ...body.map(l => '    ' + l),
      '  }',
      '}',
    ].join('\n'),
    'UploadController.cs',
    'csharp'
  );

type Result = Awaited<ReturnType<typeof run>>;
const pathFlows = (r: Result) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);
const pathFindings = (r: Result) =>
  generateFindings(
    r.taint.sources, r.taint.sinks, r.dfg, 'UploadController.cs',
    undefined, 'csharp', r.taint.sanitizers ?? [], r.types, r.taint.flows,
  ).filter(f => f.type === 'path_traversal');

// Line of the first body statement in `run` (HEADER is 4 lines, then class + method).
const BODY = 7;

describe('#339 C# expression-statement sink with an inline request read', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('fires for the bare expression statement (IFormFile.FileName inline)', async () => {
    const r = await run('IFormFile file', [
      'File.Create(Path.Combine("/uploads", file.FileName));',
    ]);
    const flows = pathFlows(r);
    expect(flows).toHaveLength(1);
    expect(flows[0].source_line).toBe(BODY);
    expect(flows[0].sink_line).toBe(BODY);
    expect(pathFindings(r)).toHaveLength(1);
  });

  it('still fires once for the assigned form (no double report)', async () => {
    const r = await run('IFormFile file', [
      'var s = File.Create(Path.Combine("/uploads", file.FileName));',
    ]);
    expect(pathFlows(r)).toHaveLength(1);
    expect(pathFindings(r)).toHaveLength(1);
  });

  it('stays clean for a constant property read', async () => {
    const r = await run('Cfg cfg', [
      'File.Create(Path.Combine(cfg.Dir, "x"));',
    ]);
    expect(r.taint.sources.filter(s => s.line === BODY)).toHaveLength(0);
    expect(pathFlows(r)).toHaveLength(0);
  });

  it('fires for a [FromQuery] parameter in the expression-statement form', async () => {
    const r = await run('[FromQuery] string name', [
      'File.Create(Path.Combine("/uploads", name));',
    ]);
    expect(pathFlows(r)).toHaveLength(1);
  });

  it('fires for inline Request.Query and Console.ReadLine reads too', async () => {
    const q = await run('', ['File.Create(Path.Combine("/uploads", Request.Query["n"]));']);
    expect(pathFlows(q)).toHaveLength(1);
    const c = await run('', ['File.Create(Console.ReadLine());']);
    expect(pathFlows(c)).toHaveLength(1);
  });

  it('does not taint the next line by adjacency', async () => {
    // A source with no bound variable seeds every def on the FOLLOWING line;
    // the inline source must not turn the constant `x` into a tainted value.
    const r = await run('IFormFile file', [
      'Log(file.FileName);',
      'var x = "/tmp/a";',
      'File.Create(x);',
    ]);
    expect(pathFlows(r)).toHaveLength(0);
  });

  it('ignores a read that is the statement callee or receiver, not an argument', async () => {
    const r = await run('', [
      'Console.ReadLine();',
      'File.Delete("/tmp/a");',
    ]);
    expect(r.taint.sources.filter(s => s.type === 'io_input')).toHaveLength(0);
  });

  it('does not seed `.FileName` on a type that is not IFormFile', async () => {
    const r = await run('FileInfo fi', [
      'File.Create(Path.Combine("/uploads", fi.FileName));',
    ]);
    expect(pathFlows(r)).toHaveLength(0);
  });
});
