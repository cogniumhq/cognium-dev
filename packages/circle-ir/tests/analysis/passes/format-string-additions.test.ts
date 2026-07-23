/**
 * Tests for cognium-dev #264 — format_string (CWE-134) sink additions.
 *
 * Extends the pre-#264 format-string surface (String.format, Formatter,
 * System.out.printf, fmt.Sprintf/Printf/Errorf/Fprintf) with additional
 * receiver-family entries:
 *   Java: MessageFormat, PrintStream (non-System.out), PrintWriter
 *   Go:   log.{Printf, Fatalf, Panicf}
 *
 * Out of scope for #264 (documented in ticket): Python `str.format` /
 * `%`-operator LHS-taint (engine-level receiver-taint tracking gap),
 * SLF4J/JUL/log4j Logger patterns (log_injection vs format_string
 * classification policy).
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasFormatStringSink = (r: any) =>
  (r.taint?.sinks ?? []).some((s: any) => s.type === 'format_string');

describe('#264 — format_string sink additions', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — Java MessageFormat.format(pattern, args): format_string sink fires', async () => {
    const code = `import java.text.MessageFormat;
import javax.servlet.http.HttpServletRequest;

public class Svc {
  public String render(HttpServletRequest req, Object[] args) {
    String pattern = req.getParameter("pattern");
    MessageFormat mf = new MessageFormat(pattern);
    return mf.format(args);
  }

  public String staticShape(HttpServletRequest req, Object[] args) {
    String pattern = req.getParameter("pattern");
    return MessageFormat.format(pattern, args);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('TP — Java PrintStream.printf(fmt, ...) on a non-System.out stream fires', async () => {
    const code = `import java.io.PrintStream;
import javax.servlet.http.HttpServletRequest;

public class Svc {
  public void log(PrintStream out, HttpServletRequest req) {
    String fmt = req.getParameter("fmt");
    out.printf(fmt, req.getParameter("val"));
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('TP — Java PrintWriter.format(fmt, ...) fires', async () => {
    const code = `import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;

public class Svc {
  public void write(PrintWriter w, HttpServletRequest req) {
    String fmt = req.getParameter("fmt");
    w.format(fmt, "arg");
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('TP — Go log.Printf(fmt, ...) fires', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "log"',
      '  "net/http"',
      ')',
      '',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '  fmt := r.URL.Query().Get("fmt")',
      '  log.Printf(fmt, "arg")',
      '}',
    ].join('\n');
    const r = await analyze(code, 'main.go', 'go');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('TP — Go log.Fatalf(fmt, ...) fires', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "log"',
      '  "net/http"',
      ')',
      '',
      'func handler(r *http.Request) {',
      '  fmt := r.URL.Query().Get("fmt")',
      '  log.Fatalf(fmt)',
      '}',
    ].join('\n');
    const r = await analyze(code, 'main.go', 'go');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('Recall lock — existing String.format(fmt, ...) still fires (pre-#264 coverage preserved)', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;

public class Svc {
  public String go(HttpServletRequest req) {
    String fmt = req.getParameter("fmt");
    return String.format(fmt, "x");
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('Recall lock — fmt.Sprintf(fmt, ...) still fires (pre-#264 coverage preserved)', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "fmt"',
      '  "net/http"',
      ')',
      '',
      'func handler(r *http.Request) string {',
      '  f := r.URL.Query().Get("f")',
      '  return fmt.Sprintf(f, "x")',
      '}',
    ].join('\n');
    const r = await analyze(code, 'main.go', 'go');
    expect(hasFormatStringSink(r)).toBe(true);
  });

  it('FP-guard — literal format string does not fire (Java String.format)', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;

public class Svc {
  public String go(HttpServletRequest req) {
    String v = req.getParameter("v");
    return String.format("hello %s", v);
  }
}
`;
    const r = await analyze(code, 'Svc.java', 'java');
    // Literal format string, tainted arg — this is the SAFE shape;
    // no format_string sink should be emitted for the format-string
    // position. (Sink pattern targets arg[0], which is the literal here.)
    expect(hasFormatStringSink(r)).toBe(false);
  });
});
