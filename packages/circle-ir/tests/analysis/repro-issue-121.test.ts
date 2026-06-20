/**
 * Repro for cognium-dev#121 — `jwt-verify-disabled` (CWE-347) Java
 * branch fires on any `<receiver-containing-"parser">.parse(...)` call.
 *
 * Before the fix (`jwt-verify-disabled-pass.ts:161` — `receiver.includes('parser')`),
 * the rule produced critical-severity findings on:
 *   - local variables literally named `parser` (parser-combinator code)
 *   - classes whose name ends in `Parser` (ANTLR, FastDateParser, …)
 *   - any field/getter whose name contains the substring `parser`
 *
 * Across a 12-repo sample of popular Java OSS this produced 20 critical
 * FPs with zero true positives. The rule drove three repos to BLOCKED
 * trust score on the back of pure noise.
 *
 * Fix (`jwt-verify-disabled-pass.ts`): replace the substring check with
 * `/\bJwts\s*\.\s*parser\s*\(/.test(receiver)`, anchoring the match to
 * the JJWT-specific `Jwts.parser()` chain. Handles all idiomatic JJWT
 * 0.x shapes including chained builders and fully-qualified receivers;
 * rejects parser-combinator code, ANTLR runtime, date parsers, etc.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#121 — jwt-verify-disabled over-broad parser match', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const jwtFinds = (findings: Array<{ rule_id?: string }> | undefined) =>
    (findings ?? []).filter((f) => f.rule_id === 'jwt-verify-disabled');

  // ─── FP locks ────────────────────────────────────────────────────────

  it('FP: local variable named `parser` calling parse() — must NOT flag', async () => {
    // Shape: palantir/conjure Parsers.java:54, antlr4 runtime, etc.
    const code = `
public class T {
  public Object run(Parser<Object> parser, java.io.InputStream in) throws Exception {
    return parser.parse(in);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings)).toEqual([]);
  });

  it('FP: class name ending in `Parser` calling its own parse() — must NOT flag', async () => {
    // Shape: chinabugotech/hutool FastDateFormat.java:334, yamlbeans
    // DateTimeParser.java:86 (`parser.parse(s, pos)` where `parser` is a
    // `FastDateParser`).
    const code = `
public class T {
  public void run(FastDateParser parser, String s, java.text.ParsePosition pos) {
    parser.parse(s, pos);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings)).toEqual([]);
  });

  it('FP: ANTLR-style ParseTreePatternMatcher.parser().parse() — must NOT flag', async () => {
    // antlr4 ParseTreePatternMatcher.java:205 shape — `.parser()` getter
    // on an unrelated facade, then `.parse(...)`.
    const code = `
public class T {
  public Object run(Matcher m, String input) {
    return m.parser().parse(input);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings)).toEqual([]);
  });

  // ─── Positive recall locks ───────────────────────────────────────────

  it('TP: Jwts.parser().setSigningKey(secret).parse(token) — must flag', async () => {
    const code = `
import io.jsonwebtoken.Jwts;
public class T {
  public Object check(String tok, String secret) {
    return Jwts.parser().setSigningKey(secret).parse(tok);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    const f = jwtFinds(r.findings);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].cwe).toBe('CWE-347');
    expect(f[0].severity).toBe('critical');
  });

  it('TP: bare Jwts.parser().parse(token) — must flag', async () => {
    const code = `
import io.jsonwebtoken.Jwts;
public class T {
  public Object check(String tok) {
    return Jwts.parser().parse(tok);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('TP: fully-qualified io.jsonwebtoken.Jwts.parser().parse(token) — must flag', async () => {
    // No import — fully-qualified call. The receiver string contains
    // `Jwts.parser(` so the anchored gate still matches.
    const code = `
public class T {
  public Object check(String tok) {
    return io.jsonwebtoken.Jwts.parser().parse(tok);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  // ─── Safe-form recall (negative control) ─────────────────────────────

  it('NEG: Jwts.parser().setSigningKey(s).parseClaimsJws(t) — must NOT flag (safe form)', async () => {
    const code = `
import io.jsonwebtoken.Jwts;
public class T {
  public Object check(String tok, String secret) {
    return Jwts.parser().setSigningKey(secret).parseClaimsJws(tok);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings)).toEqual([]);
  });

  it('NEG: Jwts.parserBuilder().setSigningKey(s).build().parseClaimsJws(t) — must NOT flag (jjwt 0.11+ safe form)', async () => {
    const code = `
import io.jsonwebtoken.Jwts;
public class T {
  public Object check(String tok, String secret) {
    return Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(tok);
  }
}
`;
    const r = await analyze(code, 'T.java', 'java');
    expect(jwtFinds(r.findings)).toEqual([]);
  });
});
