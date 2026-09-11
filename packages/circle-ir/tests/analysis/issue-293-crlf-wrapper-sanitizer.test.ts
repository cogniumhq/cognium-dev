/**
 * cognium-dev #293 — a user-defined CRLF-stripping helper was not credited at
 * its call sites (the Java and Python `…SanitizerWrapped…` fixtures).
 *
 * `findJavaInlineCrlfStripLogSanitizers` only credits a strip applied on the
 * log line itself. When the strip lives in a helper, the sanitizer was detected
 * *inside the helper body* and never reached the call site:
 *
 *   private static String redact(String s) {
 *     return s.replace("\r", "_").replace("\n", "_");   // sanitizer seen HERE
 *   }
 *   logger.info("user=" + redact(req.getParameter("user")));  // still log_injection
 *
 * JS/TS already had `findJsWrapperFunctionSanitizers`; Java and Python did not.
 *
 * Scoped to CRLF / `log_injection` on purpose. The JS version also infers an
 * `xss` wrapper from an HTML char class, but #293 supplies no Java or Python
 * xss-wrapper fixture, and a sanitizer credit with no fixture behind it is how
 * a false negative gets shipped.
 *
 * The negatives are the point of this file: a helper only counts when it
 * actually strips `\r`/`\n`/`\t`. `slug()` doing `.replace(" ", "-")` is the
 * case that would quietly disable CWE-117 across a codebase if the strip
 * pattern were loosened to "any .replace()".
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const logInj = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'log_injection' && !f.sanitized);

const java = (helper: string[]) =>
  analyze(
    [
      'import javax.servlet.http.*;',
      'import java.util.logging.Logger;',
      'public class W extends HttpServlet {',
      ...helper.map(l => '    ' + l),
      '    public void wrapped(HttpServletRequest req) {',
      '        Logger.getLogger("app").info("user=" + clean(req.getParameter("user")));',
      '    }',
      '}',
    ].join('\n'),
    'W.java',
    'java'
  );

const python = (helper: string[]) =>
  analyze(
    [
      'import re',
      'import logging',
      'from flask import request',
      '',
      ...helper,
      '',
      'def wrapped():',
      '    user = request.args.get("user")',
      '    logging.info("user=%s", clean(user))',
    ].join('\n'),
    'w.py',
    'python'
  );

describe('#293 Java CRLF wrapper is credited at the call site', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('double-quoted replace("\\r", …) helper suppresses log_injection', async () => {
    // This form is the one the inline detector never covered.
    const r = await java([
      'private static String clean(String s) {',
      '    return s.replace("\\r", "_").replace("\\n", "_").replace("\\t", "_");',
      '}',
    ]);
    expect(logInj(r).length).toBe(0);
  });

  it('replaceAll("[\\r\\n]", …) helper suppresses it', async () => {
    const r = await java([
      'private static String clean(String s) {',
      '    return s.replaceAll("[\\r\\n]", "_");',
      '}',
    ]);
    expect(logInj(r).length).toBe(0);
  });

  it("char-form replace('\\n', …) helper suppresses it", async () => {
    const r = await java([
      'private static String clean(String s) {',
      "    return s.replace('\\n', '_');",
      '}',
    ]);
    expect(logInj(r).length).toBe(0);
  });

  it('a helper that does NOT strip CRLF still fires', async () => {
    const r = await java([
      'private static String clean(String s) {',
      '    return s.toUpperCase();',
      '}',
    ]);
    expect(logInj(r).length).toBeGreaterThan(0);
  });

  it('a helper replacing an UNRELATED character still fires', async () => {
    // `.replace(" ", "-")` is a slug, not a CRLF strip. Loosening the pattern
    // to "any .replace()" would disable CWE-117 wherever a helper touches text.
    const r = await java([
      'private static String clean(String s) {',
      '    return s.replace(" ", "-");',
      '}',
    ]);
    expect(logInj(r).length).toBeGreaterThan(0);
  });

  it('no helper at all still fires', async () => {
    const r = await analyze(
      [
        'import javax.servlet.http.*;',
        'import java.util.logging.Logger;',
        'public class R extends HttpServlet {',
        '    public void raw(HttpServletRequest req) {',
        '        Logger.getLogger("app").info("user=" + req.getParameter("user"));',
        '    }',
        '}',
      ].join('\n'),
      'R.java',
      'java'
    );
    expect(logInj(r).length).toBeGreaterThan(0);
  });
});

describe('#293 Python CRLF wrapper is credited at the call site', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('re.sub(r"[\\r\\n\\t]", …) helper suppresses log_injection', async () => {
    const r = await python([
      'def clean(s):',
      '    return re.sub(r"[\\r\\n\\t]", "_", s)',
    ]);
    expect(logInj(r).length).toBe(0);
  });

  it('str.replace("\\n", …) helper suppresses it', async () => {
    const r = await python([
      'def clean(s):',
      '    return s.replace("\\n", "_")',
    ]);
    expect(logInj(r).length).toBe(0);
  });

  it('a helper that does NOT strip CRLF still fires', async () => {
    const r = await python([
      'def clean(s):',
      '    return s.upper()',
    ]);
    expect(logInj(r).length).toBeGreaterThan(0);
  });

  it('a helper replacing an UNRELATED character still fires', async () => {
    const r = await python([
      'def clean(s):',
      '    return s.replace(" ", "-")',
    ]);
    expect(logInj(r).length).toBeGreaterThan(0);
  });
});
