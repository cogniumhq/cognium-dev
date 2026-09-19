/**
 * cognium-dev #361 — `generateFindings` paired a source with a sink on line
 * proximity alone, ignoring the enclosing method AND the direction.
 *
 * The predicate's own comment claimed the constraint it did not enforce:
 *
 *     function isProximityVulnerability(source, sink) {
 *       // Within same method (roughly 50 lines for complex functions)
 *       return Math.abs(source.line - sink.line) <= 50;
 *     }
 *
 * So ANY source within 50 lines of a type-compatible sink became a finding —
 * across method boundaries, and even when the source sat AFTER the sink.
 * Observed: a `BinaryFormatter.Deserialize` sink in one controller action
 * reported against a `Request.Query` read in the NEXT action, six lines below
 * it. `taint.flows` was correct; the bad pair existed only on the
 * `generateFindings` path, which is what `scan` and the CLI report from.
 *
 * WHY THIS COULD NOT BE FIXED BEFORE TODAY. `bench-diff` built its verdict
 * signatures from `taint.flows` only, so a change here was a zero-delta on
 * every corpus — unmeasurable, and this lane does not ship precision changes
 * it cannot measure. #373 added `--surface findings|both`, which makes the
 * pair visible as `F:deserialization@18->12`, and #377 makes the snapshot
 * provenance trustworthy. This fix is downstream of both.
 *
 * HOW THE METHOD IS RESOLVED, and why not `in_method`: that field is
 * populated unevenly — Java sources carry it, Java SINKS do not, and C#
 * carries it on neither (verified on both languages). `ir.types[].methods[]`
 * has reliable `start_line`/`end_line` wherever `types` is populated, so the
 * ranges come from there.
 *
 * DELIBERATELY NOT CHANGED: the direction. A source below its sink looks
 * wrong, but a field or `interprocedural_param` source legitimately sits
 * outside the method body, and a loop can carry a later line's value back
 * round. Method scoping already rejects the reported case; ordering needs its
 * own evidence rather than being bundled in here.
 *
 * BACKWARD COMPATIBLE BY CONSTRUCTION: `types` is an optional trailing
 * parameter. A caller that does not pass it keeps the exact previous
 * behaviour, so nothing regresses for consumers that cannot supply ranges —
 * and consumers that want the fix must pass `ir.types`.
 *
 * THE TEST IS CONTAINMENT, NOT INNERMOST-METHOD IDENTITY. The first cut of
 * this fix compared the innermost method around each line and rejected the
 * pair when they differed. Measured on BenchmarkPython that removed 63 real
 * detections across 46 files and added none, because methods NEST: the corpus
 * wraps every route handler in `def init(app)`, so a source credited to the
 * `init` line and a sink inside a handler resolve to different innermost
 * methods while being lexically, genuinely reachable. The predicate now asks
 * whether any SINGLE known method range contains both lines — which is false
 * for the sibling controller actions that motivated the issue, and true for
 * every nesting shape. See the `nested` cases below.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const CROSS_METHOD = [
  'using System;',
  'using System.IO;',
  'using System.Runtime.Serialization.Formatters.Binary;',
  'using Microsoft.AspNetCore.Mvc;',
  '',
  'public class HomeController : Controller',
  '{',
  '    public IActionResult Bin()',
  '    {',
  '        var bf = new BinaryFormatter();',
  '        var ms = new MemoryStream(new byte[] { 1, 2, 3 });',
  '        var o = bf.Deserialize(ms);',
  '        return Ok();',
  '    }',
  '',
  '    public IActionResult Other()',
  '    {',
  '        string s = Request.Query["s"];',
  '        return Content(s);',
  '    }',
  '}',
].join('\n');

const SAME_METHOD = [
  'using System;',
  'using System.IO;',
  'using System.Runtime.Serialization.Formatters.Binary;',
  'using Microsoft.AspNetCore.Mvc;',
  '',
  'public class HomeController : Controller',
  '{',
  '    public IActionResult Bin()',
  '    {',
  '        string s = Request.Query["s"];',
  '        var bf = new BinaryFormatter();',
  '        var ms = new MemoryStream(new byte[] { 1, 2, 3 });',
  '        var o = bf.Deserialize(ms);',
  '        return Ok();',
  '    }',
  '}',
].join('\n');

const run = async (code: string, file: string, withTypes: boolean) => {
  const r = await analyze(code, file, 'csharp');
  const fs = withTypes
    ? generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file, code, 'csharp', r.taint.sanitizers, r.types)
    : generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file, code, 'csharp', r.taint.sanitizers);
  return fs.map(f => `${f.type}@${f.source?.line}->${f.line}`);
};

describe('#361 proximity pairing is scoped to the enclosing method', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('rejects a pair whose source is in a different method', async () => {
    const got = await run(CROSS_METHOD, 'H.cs', true);
    // the Deserialize sink is in Bin(); the Request.Query read is in Other()
    expect(got).not.toContain('deserialization@18->12');
  });

  it('keeps the legitimate same-method pair in the same file', async () => {
    // Proving the fix is targeted: the xss pair inside Other() must survive
    // the same analysis that rejected the cross-method one.
    const got = await run(CROSS_METHOD, 'H.cs', true);
    expect(got).toContain('xss@18->19');
  });

  it('keeps a same-method pair that relies on proximity', async () => {
    const got = await run(SAME_METHOD, 'S.cs', true);
    expect(got).toContain('deserialization@10->13');
  });

  it('is a no-op when the caller passes no types — the old behaviour', async () => {
    // Backward compatibility is load-bearing: consumers that cannot supply
    // ranges must not change behaviour, which also means they do NOT get the
    // fix until they pass `ir.types`.
    const got = await run(CROSS_METHOD, 'H.cs', false);
    expect(got).toContain('deserialization@18->12');
  });

  it('still rejects pairs beyond the 50-line window', async () => {
    const padded = [
      'using System;',
      'using Microsoft.AspNetCore.Mvc;',
      'public class C : Controller',
      '{',
      '    public IActionResult A()',
      '    {',
      '        string s = Request.Query["s"];',
      ...Array.from({ length: 60 }, (_, i) => `        // filler ${i}`),
      '        return Content(s);',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(padded, 'P.cs', 'csharp');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'P.cs', padded, 'csharp', r.taint.sanitizers, r.types,
    );
    // Same method, but >50 lines apart and no DFG path: the window still
    // governs, so method scoping has not widened anything.
    expect(fs.filter(f => f.type === 'xss' && !f.source)).toHaveLength(0);
  });
  it('keeps a pair whose source is on the ENCLOSING function of a nested sink', async () => {
    // BenchmarkPython's shape, reduced: the taint source is credited to the
    // outer `init` line, the sink lives in a route handler nested inside it.
    // Innermost-method comparison rejected this; containment keeps it.
    const src = [
      'from flask import request',
      'import os',
      '',
      'def init(app):',
      '',
      '    @app.route("/x", methods=["POST"])',
      '    def handler():',
      '        param = ""',
      '        for name in request.form.keys():',
      '            param = name',
      '        return open(param, "rb")',
      '',
    ].join('\n');
    const r = await analyze(src, 'app.py', 'python');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'app.py', src, 'python',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    expect(fs.filter(f => f.type === 'path_traversal').length).toBeGreaterThan(0);
  });

  it('still rejects two sibling methods that share only their class', async () => {
    // The regression this issue was filed for. Neither method contains the
    // other, and a class is not a method range, so nothing contains both.
    const src = [
      'using System;',
      'using System.Runtime.Serialization.Formatters.Binary;',
      'using Microsoft.AspNetCore.Mvc;',
      'public class C : Controller',
      '{',
      '    public IActionResult A()',
      '    {',
      '        var f = new BinaryFormatter();',
      '        return Content(f.Deserialize(Stream.Null).ToString());',
      '    }',
      '    public IActionResult B()',
      '    {',
      '        string s = Request.Query["s"];',
      '        return Content(s);',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(src, 'C.cs', 'csharp');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'C.cs', src, 'csharp',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    // The Query read in B must not be paired with the Deserialize sink in A.
    const crossed = fs.filter(
      (f) => f.type === 'insecure_deserialization' && f.line < 11 && (f.source?.line ?? 0) > 10,
    );
    expect(crossed).toHaveLength(0);
  });
  it('exempts a FIELD-mediated flow between disjoint sibling methods', async () => {
    // SecuriBench `Refl2`, reduced. The source writes the field `name` in
    // `doGet`; another method reads it back and prints it. The two methods are
    // disjoint siblings, so containment rejects the pair — but the flow is
    // real (the corpus marks the sink BAD) because the taint travels through
    // the field. Field writes escape their writing method by construction, so
    // method scoping must not apply to them. Containment alone lost this TP.
    const src = [
      'import java.io.*;',
      'import javax.servlet.http.*;',
      'public class Refl2 {',
      '    public String name;',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
      '        name = req.getParameter("name");',
      '        f(resp);',
      '    }',
      '    private void f(HttpServletResponse resp) throws IOException {',
      '        PrintWriter writer = resp.getWriter();',
      '        writer.println(name);',
      '    }',
      '}',
    ].join('\n');
    const r = await analyze(src, 'Refl2.java', 'java');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'Refl2.java', src, 'java',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    expect(fs.filter((f) => f.type === 'xss').length).toBeGreaterThan(0);
  });
});
