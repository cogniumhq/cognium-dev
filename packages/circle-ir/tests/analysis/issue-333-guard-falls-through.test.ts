/**
 * cognium-dev #333 — a path-containment guard was credited even when it does
 * not reject.
 *
 * `!full.startsWith(root)` only sanitises when the failing branch leaves. A
 * guard that merely logs lets control fall through to the sink, so the path was
 * never rejected. Three guards scanned forward from the guard line for a
 * `return`/`throw` without noticing the guard's own block had already closed:
 *
 *     if (!full.startsWith(root)) { log("odd"); }
 *     return read(full);              // <- this return was credited
 *
 * so they found the *enclosing method's* terminator and suppressed a genuine
 * `path_traversal`. Affected: `findJavaCanonicalPathStartsWithGuardSanitizers`,
 * `findJavaPathNormalizeStartsWithGuardSanitizers` and
 * `findJsPathResolveStartsWithGuardSanitizers`.
 *
 * `findRustCanonicalizeGuardSanitizers` was already correct — it requires the
 * guard line to open a block, brace-matches to the close and demands the
 * terminator inside — and is the model the shared `guardRejects` helper follows.
 * The C# guard added in #332 had the same check inline and now uses the helper.
 *
 * Tests assert at two levels, deliberately. Java asserts the finding, because
 * the end-to-end flow is detected there. JS asserts that the *sanitizer* is no
 * longer emitted: the `path.resolve` + `readFileSync` shape produces no
 * `path_traversal` flow even with no guard at all, so a finding-level assertion
 * would pass for the wrong reason and prove nothing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const traversal = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal' && !f.sanitized);

const guards = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
  (r.taint.sanitizers ?? []).filter(s => s.type === type);

describe('#333 Java getCanonicalPath containment guard', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const java = (guard: string[]) =>
    analyze(
      [
        'import java.io.*;',
        'import javax.servlet.http.*;',
        'public class J extends HttpServlet {',
        '  protected String read(HttpServletRequest req) throws IOException {',
        '    String p = req.getParameter("f");',
        '    File f = new File("/srv/data", p);',
        ...guard.map(l => '    ' + l),
        '    return new java.io.FileReader(f).toString();',
        '  }',
        '}',
      ].join('\n'),
      'J.java',
      'java'
    );

  it('a guard that falls through no longer suppresses the finding', async () => {
    const r = await java(['if (!f.getCanonicalPath().startsWith("/srv/data")) { System.out.println("odd"); }']);
    expect(traversal(r).length).toBeGreaterThan(0);
    expect(guards(r, 'java_canonical_startswith_guard').length).toBe(0);
  });

  it('a guard that returns still suppresses it', async () => {
    const r = await java([
      'if (!f.getCanonicalPath().startsWith("/srv/data"))',
      '  return null;',
    ]);
    expect(traversal(r).length).toBe(0);
    expect(guards(r, 'java_canonical_startswith_guard').length).toBeGreaterThan(0);
  });

  it('a single-line guard that returns still suppresses it', async () => {
    const r = await java(['if (!f.getCanonicalPath().startsWith("/srv/data")) return null;']);
    expect(traversal(r).length).toBe(0);
  });

  it('a block-form guard that returns inside still suppresses it', async () => {
    const r = await java([
      'if (!f.getCanonicalPath().startsWith("/srv/data")) {',
      '  return null;',
      '}',
    ]);
    expect(traversal(r).length).toBe(0);
  });

  it('a guard that throws still suppresses it', async () => {
    const r = await java([
      'if (!f.getCanonicalPath().startsWith("/srv/data"))',
      '  throw new IOException("escape");',
    ]);
    expect(traversal(r).length).toBe(0);
  });
});

describe('#333 Java Path.normalize containment guard', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const java = (guard: string[]) =>
    analyze(
      [
        'import java.nio.file.*;',
        'import javax.servlet.http.*;',
        'import java.io.IOException;',
        'public class N extends HttpServlet {',
        '  protected String read(HttpServletRequest req) throws IOException {',
        '    Path root = Paths.get("/srv/data");',
        '    String p = req.getParameter("f");',
        '    Path full = root.resolve(p).normalize();',
        ...guard.map(l => '    ' + l),
        '    return new String(Files.readAllBytes(full));',
        '  }',
        '}',
      ].join('\n'),
      'N.java',
      'java'
    );

  it('a guard that falls through no longer suppresses the finding', async () => {
    const r = await java(['if (!full.startsWith(root)) { System.out.println("odd"); }']);
    expect(traversal(r).length).toBeGreaterThan(0);
    expect(guards(r, 'java_path_normalize_startswith_guard').length).toBe(0);
  });

  it('a guard that returns still suppresses it', async () => {
    const r = await java([
      'if (!full.startsWith(root))',
      '  return null;',
    ]);
    expect(traversal(r).length).toBe(0);
    expect(guards(r, 'java_path_normalize_startswith_guard').length).toBeGreaterThan(0);
  });
});

describe('#333 JS path.resolve containment guard', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const js = (guard: string[]) =>
    analyze(
      [
        "const express = require('express');",
        "const path = require('path');",
        "const fs = require('fs');",
        'const app = express();',
        "const root = '/srv/data';",
        "app.get('/f', (req, res) => {",
        '  const full = path.resolve(root, req.query.f);',
        ...guard.map(l => '  ' + l),
        "  return res.send(fs.readFileSync(full, 'utf8'));",
        '});',
      ].join('\n'),
      'server.js',
      'javascript'
    );

  // Asserted at the sanitizer level on purpose: this shape yields no
  // path_traversal flow even with no guard at all, so a finding-level
  // assertion would pass regardless of the fix.
  it('a guard that falls through is no longer credited', async () => {
    const r = await js(["if (!full.startsWith(root)) { console.log('odd'); }"]);
    expect(guards(r, 'js_path_resolve_startswith_guard').length).toBe(0);
  });

  it('a guard that returns is still credited', async () => {
    const r = await js([
      'if (!full.startsWith(root))',
      '  return res.sendStatus(400);',
    ]);
    expect(guards(r, 'js_path_resolve_startswith_guard').length).toBeGreaterThan(0);
  });
});

describe('#333 C# guard still behaves as #332 established', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const cs = (guard: string[]) =>
    analyze(
      [
        'using System.IO;',
        'public class C {',
        '    public string Read(string input) {',
        '        var root = Path.GetFullPath("/srv/data") + Path.DirectorySeparatorChar;',
        '        var full = Path.GetFullPath(Path.Combine(root, input));',
        ...guard.map(l => '        ' + l),
        '        return File.ReadAllText(full);',
        '    }',
        '}',
      ].join('\n'),
      'C.cs',
      'csharp'
    );

  it('fall-through still fires after the refactor to the shared helper', async () => {
    const r = await cs(['if (!full.StartsWith(root)) { System.Console.WriteLine("odd"); }']);
    expect(traversal(r).length).toBeGreaterThan(0);
  });

  it('reject guard still suppresses after the refactor', async () => {
    const r = await cs(['if (!full.StartsWith(root))', '    return null;']);
    expect(traversal(r).length).toBe(0);
  });
});
