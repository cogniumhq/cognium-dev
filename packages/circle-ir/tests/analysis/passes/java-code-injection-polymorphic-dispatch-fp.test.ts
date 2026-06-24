/**
 * Sprint 47 — cognium-dev #164.
 *
 * Java `code_injection` (CWE-94) fires on `parser.parseExpression(input)`
 * where `parser` iterates over a typed array of *literal* parser
 * constructions (`private static final X[] PARSERS = new X[] { new X(),
 * new X() };`). The dispatch target set is fully enumerated and consists
 * of stateless constructors only — no arbitrary class is reachable through
 * the receiver, so the call cannot be a real code-injection vector.
 *
 * Stage 9h in `sink-filter-pass.ts` suppresses these sinks when:
 *   - the receiver appears in a `for (X r : ARR)` foreach OR `ARR[i].m(...)`
 *     index-access form, AND
 *   - the same source file declares a matching
 *     `private static final X[] ARR = ... { new X(), new X() ... };` array
 *     whose elements are all `new <TypeName>(...)` literal expressions.
 *
 * Recall: dispatch over a `List<Parser>` populated at runtime, or arrays
 * whose elements include reflective lookups, remain unsuppressed.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const codeInjectionSinks = (
  arr: Array<{ type?: string; line?: number; method?: string; code?: string }> | undefined,
) => (arr ?? []).filter((s) => s.type === 'code_injection');

describe('cognium-dev #164 — polymorphic dispatch over static-final array literal', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // --------------------------------------------------------------------------
  // 1. FP — foreach over `private static final SpelExpressionParser[]`
  //         of `new SpelExpressionParser()` literals — suppressed
  // --------------------------------------------------------------------------
  it('foreach over typed array of new X() literals — no parseExpression sink', async () => {
    const code = `
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;
public class P {
  private static final SpelExpressionParser[] PARSERS = new SpelExpressionParser[] {
    new SpelExpressionParser(),
    new SpelExpressionParser()
  };
  public void run(HttpServletRequest req) {
    String input = req.getParameter("expr");
    for (SpelExpressionParser parser : PARSERS) {
      parser.parseExpression(input);
    }
  }
}`;
    const r = await analyze(code, 'P.java', 'java');
    const parseExprSinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'parseExpression');
    expect(parseExprSinks.length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 2. FP — index access `PARSERS[0].parseExpression(input)` — suppressed
  // --------------------------------------------------------------------------
  it('index access into typed array of new X() literals — no parseExpression sink', async () => {
    const code = `
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;
public class P {
  private static final SpelExpressionParser[] PARSERS = new SpelExpressionParser[] {
    new SpelExpressionParser(),
    new SpelExpressionParser()
  };
  public void run(HttpServletRequest req) {
    String input = req.getParameter("expr");
    PARSERS[0].parseExpression(input);
  }
}`;
    const r = await analyze(code, 'P.java', 'java');
    const parseExprSinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'parseExpression');
    expect(parseExprSinks.length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 3. FP — variant `= { new X(), new X() }` (no `new X[]` prefix) — suppressed
  // --------------------------------------------------------------------------
  it('shorthand init {new X(),...} foreach — no parseExpression sink', async () => {
    const code = `
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;
public class P {
  private static final SpelExpressionParser[] PARSERS = {
    new SpelExpressionParser(),
    new SpelExpressionParser()
  };
  public void run(HttpServletRequest req) {
    String input = req.getParameter("expr");
    for (SpelExpressionParser parser : PARSERS) {
      parser.parseExpression(input);
    }
  }
}`;
    const r = await analyze(code, 'P.java', 'java');
    const parseExprSinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'parseExpression');
    expect(parseExprSinks.length).toBe(0);
  });

  // --------------------------------------------------------------------------
  // 4. Recall — direct `parser.parseExpression(tainted)` still fires
  // --------------------------------------------------------------------------
  it('recall: direct SpEL parser.parseExpression(tainted) still fires', async () => {
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
    const parseExprSinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'parseExpression');
    expect(parseExprSinks.length).toBeGreaterThanOrEqual(1);
  });

  // --------------------------------------------------------------------------
  // 5. Recall — same shape but array NOT declared `private static final`
  //             must NOT be suppressed.
  // --------------------------------------------------------------------------
  it('recall: non-static-final array of new X() literals — sink still fires', async () => {
    const code = `
import org.springframework.expression.spel.standard.SpelExpressionParser;
import javax.servlet.http.HttpServletRequest;
public class P {
  public void run(HttpServletRequest req) {
    String input = req.getParameter("expr");
    SpelExpressionParser[] parsers = new SpelExpressionParser[] {
      new SpelExpressionParser(),
      new SpelExpressionParser()
    };
    for (SpelExpressionParser parser : parsers) {
      parser.parseExpression(input);
    }
  }
}`;
    const r = await analyze(code, 'P.java', 'java');
    const parseExprSinks = codeInjectionSinks(r.taint?.sinks).filter((s) => s.method === 'parseExpression');
    expect(parseExprSinks.length).toBeGreaterThanOrEqual(1);
  });
});
