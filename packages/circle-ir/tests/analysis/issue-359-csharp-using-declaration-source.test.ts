/**
 * cognium-dev #359 (from cognium-ai#462) — a C# `using` declaration bound no
 * taint source, so a payload carried through a disposable went unreported and
 * the sink was then attributed to an unrelated source.
 *
 * The issue diagnosed this as "taint lost through `Convert.FromBase64String` →
 * `new MemoryStream`". It is not: neither of those is involved. The scanner's
 * assignment regex in `findCSharpRequestSources` allowed an optional `var` or
 * a type name before the variable, but not a leading `using`, so
 *
 *   var       ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]));   // bound
 *   using var ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]));   // NOT bound
 *   using (var ms = …)                                                              // NOT bound
 *   using var s  = Request.Query["b"];                                              // NOT bound either
 *
 * The nesting was a red herring — even the simplest `using var s =
 * Request.Query["b"]` bound nothing. Same class of defect as #350 (Java
 * try-with-resources): a resource-declaration syntax the scanner never looked
 * at, and `using` is the idiomatic form for exactly the disposables that carry
 * a payload (`MemoryStream`, `StreamReader`), so this is the common case.
 *
 * SECOND DEFECT ON THE ISSUE, and why it is covered here rather than fixed
 * separately: with no source in `Bin()`, `generateFindings` attached the
 * `Deserialize` sink to the only source the file had — a `Request.Query` read
 * in a *different* action. Restoring the binding makes the primary
 * `source.line` correct, which is the field the issue says consumers anchor
 * on. The residual is that `evidence.sources` can still LIST an unrelated
 * same-file source, because `isProximityVulnerability` pairs anything within
 * 50 lines in either direction, ignoring both the enclosing method and whether
 * the source even precedes the sink. That is a separate, broader defect; it
 * affects every language, and the verdict-signature harness cannot see it
 * (snapshots are built from `taint.flows`, and that pairing exists only in
 * `generateFindings`). Tracked on its own issue rather than changed blind.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const HEADER = [
  'using System;',
  'using System.IO;',
  'using System.Runtime.Serialization.Formatters.Binary;',
  'using Microsoft.AspNetCore.Mvc;',
].join('\n');

const run = (body: string[]) =>
  analyze(
    [
      HEADER,
      'public class C : Controller {',
      '  public IActionResult A() {',
      '    var bf = new BinaryFormatter();',
      ...body.map(l => '    ' + l),
      '    return Ok();',
      '  }',
      '}',
    ].join('\n'),
    'C.cs',
    'csharp'
  );

const cwe502 = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'deserialization' && !f.sanitized);

describe('#359 C# `using` declarations bind a taint source', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('binds a plain declaration (the shape that always worked)', async () => {
    const r = await run([
      'var ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]));',
      'var o = bf.Deserialize(ms);',
    ]);
    expect(cwe502(r).length).toBeGreaterThan(0);
  });

  it('binds a `using var` declaration — the reported false negative', async () => {
    const r = await run([
      'using var ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]));',
      'var o = bf.Deserialize(ms);',
    ]);
    expect(cwe502(r).length).toBeGreaterThan(0);
  });

  it('binds a classic `using (...)` statement', async () => {
    const r = await run([
      'using (var ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]))) {',
      '  var o = bf.Deserialize(ms);',
      '}',
    ]);
    expect(cwe502(r).length).toBeGreaterThan(0);
  });

  it('binds a `using var` with no nesting at all', async () => {
    // The row that shows the nesting was never the cause.
    const r = await run([
      'using var ms = new MemoryStream(Request.Query["b"]);',
      'var o = bf.Deserialize(ms);',
    ]);
    expect(cwe502(r).length).toBeGreaterThan(0);
  });

  it('binds `await using`', async () => {
    const r = await run([
      'await using var ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]));',
      'var o = bf.Deserialize(ms);',
    ]);
    expect(cwe502(r).length).toBeGreaterThan(0);
  });

  it('does not invent a source where there is no request read', async () => {
    const r = await run([
      'using var ms = new MemoryStream(new byte[] { 1, 2, 3 });',
      'var o = bf.Deserialize(ms);',
    ]);
    expect((r.taint.sources ?? []).filter(s => s.type === 'http_param')).toHaveLength(0);
  });

  it('attributes the sink to the source in its OWN action, not another one', async () => {
    // The cross-method mis-attribution reported on the issue. With the
    // `using` binding restored, the primary source.line is the read in the
    // same action (12) rather than the one in the next action (19).
    const code = [
      'using System;',
      'using System.IO;',
      'using System.Runtime.Serialization.Formatters.Binary;',
      'using Newtonsoft.Json;',
      'using Microsoft.AspNetCore.Mvc;',
      '',
      'public class HomeController : Controller',
      '{',
      '    public IActionResult Bin()',
      '    {',
      '        var bf = new BinaryFormatter();',
      '        using var ms = new MemoryStream(Convert.FromBase64String(Request.Query["b"]));',
      '        var o = bf.Deserialize(ms);',
      '        return Ok();',
      '    }',
      '',
      '    public IActionResult Newton()',
      '    {',
      '        string s = Request.Query["s"];',
      '        var o = JsonConvert.DeserializeObject(s);',
      '        return Ok();',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'HomeController.cs', 'csharp');
    const findings = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'HomeController.cs');
    const deser = findings.filter(f => f.type === 'deserialization');
    expect(deser.length).toBeGreaterThan(0);
    expect(deser[0].source?.line).toBe(12);
    // And a real DFG flow now exists for it, rather than proximity alone.
    expect(cwe502(r).length).toBeGreaterThan(0);
  });
});
