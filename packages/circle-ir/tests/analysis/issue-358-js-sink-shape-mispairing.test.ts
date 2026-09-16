/**
 * cognium-dev #358 (from cognium-ai#460 / #419) — three JS/TS sink-shape
 * misclassifications, each of which then paired with an `interprocedural_param`
 * source and surfaced as a finding on a benign line.
 *
 * The three are independent bugs that happened to be reported together:
 *
 *  (a) `setTimeout(connect, delay)` -> code_injection. The #152/#188 guard
 *      already exempts arg[0] when it is an INLINE arrow or function
 *      expression, but `isFunctionCallbackArgument` drives off expression text
 *      starting with `(` or `function`, so a NAMED reference fell through.
 *      Now resolved against file-level declarations, the same text-level
 *      technique `isRegexReceiver` (#310) uses.
 *
 *  (b) `el.innerHTML = 'lit' + 'lit'` / `el.style.cssText = …` -> xss on a
 *      fully static assignment. Two emission paths had to be guarded, which is
 *      why a single fix looked half-done: `cssText` comes only from the
 *      line-regex scan in LanguageSourcesPass, while `innerHTML` ALSO matches
 *      the configured method sink via the synthetic CallInfo the JS extractor
 *      emits for `el.innerHTML = <rhs>`.
 *
 *  (c) `/re/.exec(url)` -> sql_injection. The JS/TS `Connection.exec` CWE-89
 *      entry carries `allow_unresolved_receiver`, and a regex literal IS an
 *      unresolved receiver. #310 fixed the command_injection twin and left
 *      this one, which is exactly what cognium-ai observed: the CWE-78 row
 *      disappeared and the CWE-89 row stayed.
 *
 * All three FPs are invisible in `taint.flows` for (a) and (b) — they reach
 * users through `generateFindings`, which pairs the sink inventory with
 * sources independently. So the assertions below go through `generateFindings`,
 * not `taint.flows`; testing the latter would have passed while the reported
 * bug survived.
 *
 * The negatives are the point: each shape has a true positive one line away
 * that must keep firing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { isProvablyLiteralExpression } from '../../src/analysis/literal-expression.js';

const findings = async (code: string) => {
  const r = await analyze(code, 'helper.js', 'javascript');
  return generateFindings(r.taint.sources, r.taint.sinks, r.dfg).map(f => f.type);
};

describe('#358 JS/TS sink shapes mispaired into findings', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('(a) setTimeout with a callback reference is not code injection', () => {
    it('does not fire for a named function reference', async () => {
      expect(
        await findings(`function connect() { return 1; }
function schedule(reconnectDelay) {
  setTimeout(connect, reconnectDelay);
}`)
      ).not.toContain('code_injection');
    });

    it('does not fire for a const-bound arrow reference', async () => {
      expect(
        await findings(`const connect = () => 1;
function schedule(d) { setTimeout(connect, d); }`)
      ).not.toContain('code_injection');
    });

    it('STILL fires for a string built from a parameter (the implicit-eval shape)', async () => {
      expect(
        await findings(`function schedule(code) {
  setTimeout("doThing(" + code + ")", 100);
}`)
      ).toContain('code_injection');
    });

    it('STILL fires for an unresolved identifier — it may hold a string', async () => {
      expect(
        await findings(`function schedule(userCode) { setTimeout(userCode, 0); }`)
      ).toContain('code_injection');
    });

    it('KNOWN LIMITATION: a same-named function declaration masks a string-valued local', async () => {
      // The lookup is file-wide and unscoped, so an unrelated declaration of
      // the same name satisfies it. Here `payload` at the sink holds a STRING
      // built from a parameter — genuine CWE-94 — but a `function payload()`
      // elsewhere in the file suppresses it.
      //
      // Pinned rather than left to be rediscovered. The #358 differential
      // dropped three sinks in vendored minified bundles for this reason:
      // single-letter names (`a`, `e`) always have some function-shaped
      // binding, so the argument being a callback *parameter* was never
      // actually established. Those drops were right on the merits, but by
      // accident.
      //
      // Accepted deliberately: the alternative fires on every idiomatic
      // `setTimeout(callbackParam, 0)`, which is what #358 reported. Fixing it
      // properly needs scope information this text-level check lacks.
      expect(
        await findings(`function payload() { return 1; }
function run(x) {
  const payload = "doThing(" + x + ")";
  setTimeout(payload, 0);
}`)
      ).not.toContain('code_injection');
    });
  });

  describe('(b) a provably literal DOM assignment is not xss', () => {
    it('does not fire for literal concatenation into innerHTML or cssText', async () => {
      expect(
        await findings(`function render(el, label) {
  el.style.cssText = 'color:' + 'red' + ';';
  el.innerHTML = '<div class="x">' + 'static' + '</div>';
}`)
      ).not.toContain('xss');
    });

    it('STILL fires when a parameter is concatenated in', async () => {
      expect(
        await findings(`function render(el, label) {
  el.innerHTML = '<div>' + label + '</div>';
}`)
      ).toContain('xss');
    });

    it('STILL fires for a template literal with an interpolation', async () => {
      expect(
        await findings('function render(el, label) {\n  el.innerHTML = `<div>${label}</div>`;\n}')
      ).toContain('xss');
    });
  });

  describe('(c) RegExp.prototype.exec is not a SQL execute', () => {
    it('does not fire for a regex literal receiver', async () => {
      expect(
        await findings(`function trim(url) { return /[\\])},.;!?]+$/.exec(url); }`)
      ).not.toContain('sql_injection');
    });

    it('does not fire for a variable bound to a regex', async () => {
      expect(
        await findings(`const RE = /^\\w+$/;
function trim(url) { return RE.exec(url); }`)
      ).not.toContain('sql_injection');
    });

    it('STILL fires for a real db.exec(sql)', async () => {
      expect(
        await findings(`function q(db, name) {
  return db.exec("SELECT * FROM t WHERE n='" + name + "'");
}`)
      ).toContain('sql_injection');
    });
  });

  // The proof bar for (b). Getting this wrong in the permissive direction
  // costs a false positive; getting it wrong the other way drops a real XSS,
  // so anything not demonstrably literal must return false.
  describe('isProvablyLiteralExpression', () => {
    it('accepts literals and literal concatenation', () => {
      expect(isProvablyLiteralExpression("'a'")).toBe(true);
      expect(isProvablyLiteralExpression("'a' + 'b'")).toBe(true);
      expect(isProvablyLiteralExpression("'<div class=\"x\">' + 'y'")).toBe(true);
      expect(isProvablyLiteralExpression('`static`')).toBe(true);
      expect(isProvablyLiteralExpression("'a' + 'b';")).toBe(true);
    });

    it('rejects anything with a runtime value', () => {
      expect(isProvablyLiteralExpression("'a' + b")).toBe(false);
      expect(isProvablyLiteralExpression('`a${b}`')).toBe(false);
      expect(isProvablyLiteralExpression('f()')).toBe(false);
      expect(isProvablyLiteralExpression('x')).toBe(false);
      expect(isProvablyLiteralExpression('')).toBe(false);
    });

    it('rejects an expression that continues past this line', () => {
      // The shape actually reported on #358: a trailing `+`, RHS on the next
      // line. Unjudgeable from one line, so it must keep the sink.
      expect(isProvablyLiteralExpression("'<div…' +")).toBe(false);
      expect(isProvablyLiteralExpression("'unterminated")).toBe(false);
    });
  });
});
