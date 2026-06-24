/**
 * Sprint 47 — cognium-dev #161.
 *
 * Java `code_injection` (CWE-94) fires HIGH on Apache Commons JEXL and
 * template-engine compile/evaluate callsites (Handlebars, Mustache, Pebble,
 * Velocity, Freemarker, Thymeleaf). These are *library-API surface*
 * callsites — the engines are designed to evaluate caller-supplied
 * expressions/templates. The trust decision belongs to the caller, not
 * the library.
 *
 * Stage 9e in `sink-filter-pass.ts` tags such sinks with
 * `library-api-surface:caller-responsibility`; the central downgrade
 * hook in `analyzer.ts` then drops severity to MEDIUM. The sink + flow
 * still fire (so auditors can see the callsite) but the policy signal
 * is no longer HIGH.
 *
 * Recall: bona-fide `code_injection` sinks (SpEL `parser.parseExpression`,
 * ScriptEngine `engine.eval`, Class.forName arbitrary loader) remain
 * untagged and continue to fire at full severity.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';
import { LIBRARY_API_SURFACE_TAG } from '../../../src/analysis/library-api-surface-downgrade.js';

const codeInjectionSinks = (
  arr: Array<{ type?: string; tags?: string[]; line?: number }> | undefined,
) => (arr ?? []).filter((s) => s.type === 'code_injection');

const codeInjectionFlows = (
  arr: Array<{ sink_type?: string; tags?: string[]; sink_line?: number }> | undefined,
) => (arr ?? []).filter((f) => f.sink_type === 'code_injection');

describe('cognium-dev #161 — JEXL/Handlebars/template library-API surface', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP — JexlEngine.createExpression(tainted) — tagged + still emits sink
  // --------------------------------------------------------------------------
  it('JexlEngine.createExpression(tainted) — sink tagged library-api-surface', async () => {
    const code = `
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import javax.servlet.http.HttpServletRequest;
public class Eval {
  public Object run(JexlEngine jexl, HttpServletRequest req) {
    String expr = req.getParameter("expr");
    JexlExpression e = jexl.createExpression(expr);
    return e.evaluate(null);
  }
}`;
    const r = await analyze(code, 'Eval.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(true);
    const flows = codeInjectionFlows(r.taint?.flows);
    expect(flows.some((f) => f.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 2. FP — Handlebars.compile(tainted) — tagged
  // --------------------------------------------------------------------------
  it('Handlebars.compile(tainted) — sink tagged library-api-surface', async () => {
    const code = `
import com.github.jknack.handlebars.Handlebars;
import com.github.jknack.handlebars.Template;
import javax.servlet.http.HttpServletRequest;
public class T {
  public Template c(Handlebars hbs, HttpServletRequest req) throws Exception {
    String src = req.getParameter("tpl");
    return hbs.compile(src);
  }
}`;
    const r = await analyze(code, 'T.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(true);
  });

  // --------------------------------------------------------------------------
  // 3. FP — Expression.evaluate on JEXL Expression receiver — tagged
  // --------------------------------------------------------------------------
  it('JexlExpression.evaluate(ctx) — sink tagged when receiver is *Expression', async () => {
    const code = `
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlExpression;
public class Run {
  public Object go(JexlExpression e, JexlContext ctx) {
    return e.evaluate(ctx);
  }
}`;
    const r = await analyze(code, 'Run.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    // If the engine emits a sink for `.evaluate(...)`, it must be tagged.
    for (const s of sinks) {
      expect(s.tags?.includes(LIBRARY_API_SURFACE_TAG)).toBe(true);
    }
  });

  // --------------------------------------------------------------------------
  // 4. FP — Velocity engine compile — tagged
  // --------------------------------------------------------------------------
  it('VelocityEngine.compile(tainted) — sink tagged library-api-surface', async () => {
    const code = `
import org.apache.velocity.app.VelocityEngine;
import javax.servlet.http.HttpServletRequest;
public class V {
  public Object run(VelocityEngine ve, HttpServletRequest req) {
    String tpl = req.getParameter("t");
    return ve.compile(tpl);
  }
}`;
    const r = await analyze(code, 'V.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    // Any code_injection sink that fires on the .compile(...) callsite must
    // carry the library-api-surface tag.
    for (const s of sinks) {
      expect(s.tags?.includes(LIBRARY_API_SURFACE_TAG)).toBe(true);
    }
  });

  // --------------------------------------------------------------------------
  // 5. Recall — SpelExpressionParser.parseExpression remains untagged HIGH
  // --------------------------------------------------------------------------
  it('recall: SpEL parser.parseExpression(tainted) NOT tagged (real HIGH sink)', async () => {
    const code = `
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;
public class P {
  public void run(HttpServletRequest req) {
    String input = req.getParameter("expr");
    SpelExpressionParser parser = new SpelExpressionParser();
    parser.parseExpression(input);
  }
}`;
    const r = await analyze(code, 'P.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    expect(sinks.length).toBeGreaterThanOrEqual(1);
    // Real eval sink must NOT carry the library-api-surface tag.
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });

  // --------------------------------------------------------------------------
  // 6. Recall — javax.script ScriptEngine.eval(tainted) NOT tagged
  // --------------------------------------------------------------------------
  it('recall: ScriptEngine.eval(tainted) NOT tagged (real HIGH sink)', async () => {
    const code = `
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.HttpServletRequest;
public class S {
  public Object run(HttpServletRequest req) throws Exception {
    String src = req.getParameter("src");
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
    return engine.eval(src);
  }
}`;
    const r = await analyze(code, 'S.java', 'java');
    const sinks = codeInjectionSinks(r.taint?.sinks);
    // If the engine emits a code_injection sink for ScriptEngine.eval, it
    // must NOT be tagged library-api-surface (Nashorn / JSR-223 eval is a
    // real eval sink, not a library-API surface).
    expect(sinks.some((s) => s.tags?.includes(LIBRARY_API_SURFACE_TAG))).toBe(false);
  });
});
