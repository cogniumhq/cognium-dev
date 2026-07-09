/**
 * cognium-dev #239 C4 residual (3.159.0) — Java `Path.getFileName()`
 * as a canonical path-traversal sanitizer.
 *
 * `Paths.get(userInput).getFileName().toString()` strips every path
 * component up to (and excluding) the trailing leaf. It's the standard
 * way to normalize an untrusted filename before joining it under a
 * fixed base. Reproduction fixture is `SafeToctou.java` from the
 * aisec safe-mirror set (path_traversal mistype).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#239 3.159.0 — Java Path.getFileName() path-traversal sanitizer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — SafeToctou.java repro: Paths.get(req).getFileName() sanitizes path_traversal', async () => {
    const code = [
      'package com.demo;',
      '',
      'import java.io.IOException;',
      'import java.io.OutputStream;',
      'import java.nio.file.Files;',
      'import java.nio.file.Path;',
      'import java.nio.file.Paths;',
      'import java.nio.file.StandardOpenOption;',
      'import javax.servlet.http.HttpServletRequest;',
      '',
      'public class SafeToctou {',
      '    private static final String BASE = "/var/app/data/";',
      '    public void write(HttpServletRequest request) throws IOException {',
      '        String leaf = Paths.get(request.getParameter("f")).getFileName().toString();',
      '        Path target = Paths.get(BASE, leaf);',
      '        try (OutputStream os = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW,',
      '                StandardOpenOption.WRITE)) {',
      '            os.write(request.getParameter("d").getBytes());',
      '        }',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'SafeToctou.java', 'java');
    const sanitizers = r.taint?.sanitizers ?? [];
    const gfn = sanitizers.filter(
      (s: any) => s.type === 'java_path_get_filename',
    );
    // Sanitizer emitted at assignment line and every downstream reference.
    expect(gfn.length).toBeGreaterThan(0);
    expect(gfn.some((s: any) => (s.sanitizes as string[]).includes('path_traversal'))).toBe(true);

    const pt = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'path_traversal',
    );
    expect(pt.length).toBe(0);
  });

  it('TN-2 — Path.of(...).getFileName() chain also sanitizes', async () => {
    const code = [
      'package com.demo;',
      '',
      'import java.nio.file.Path;',
      'import javax.servlet.http.HttpServletRequest;',
      '',
      'public class SafeToctouOf {',
      '    private static final String BASE = "/var/app/data/";',
      '    public void write(HttpServletRequest request) {',
      '        String leaf = Path.of(request.getParameter("f")).getFileName().toString();',
      '        Path target = Path.of(BASE, leaf);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'SafeToctouOf.java', 'java');
    const sanitizers = r.taint?.sanitizers ?? [];
    const gfn = sanitizers.filter(
      (s: any) => s.type === 'java_path_get_filename',
    );
    expect(gfn.length).toBeGreaterThan(0);
  });

  it('TP-1 — Part.getFileName() (multipart) does NOT emit path sanitizer', async () => {
    // Servlet Part.getFileName() is a taint SOURCE (user-controlled upload
    // filename), not a sanitizer. Must not fire the Paths-anchored emitter.
    const code = [
      'package com.demo;',
      '',
      'import javax.servlet.http.Part;',
      '',
      'public class UploadHandler {',
      '    public void handle(Part part) {',
      '        String name = part.getFileName();',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'UploadHandler.java', 'java');
    const sanitizers = r.taint?.sanitizers ?? [];
    const gfn = sanitizers.filter(
      (s: any) => s.type === 'java_path_get_filename',
    );
    expect(gfn.length).toBe(0);
  });

  it('TP-2 — bare .getFileName() without Paths.get / Path.of anchor does NOT sanitize', async () => {
    // A .getFileName() call on an unknown receiver is not automatically
    // safe. The emitter must be anchored to a Paths.get(...) / Path.of(...)
    // chain to know the receiver is a java.nio.file.Path.
    const code = [
      'package com.demo;',
      '',
      'import javax.servlet.http.HttpServletRequest;',
      '',
      'public class MysteryReceiver {',
      '    public String opaque(Object o) { return o.toString(); }',
      '    public void doIt(HttpServletRequest request) {',
      '        Object mystery = new Object();',
      '        String name = opaque(mystery);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'MysteryReceiver.java', 'java');
    const sanitizers = r.taint?.sanitizers ?? [];
    const gfn = sanitizers.filter(
      (s: any) => s.type === 'java_path_get_filename',
    );
    expect(gfn.length).toBe(0);
  });
});
