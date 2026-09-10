/**
 * cognium-dev #281 — `SeverityContext.confidence` was never passed.
 *
 * `calculateSeverity` accepts `confidence` and gates two escalations on
 * `confidence > 0.8`, but `generateFindings`' call site omitted it, so it always
 * fell back to the 0.5 default and neither rule could fire. Every HIGH_SINKS
 * type (`xss`, `path_traversal`, `xxe`, `ssrf`, `ldap_injection`,
 * `xpath_injection`) was therefore structurally incapable of being rated
 * `high` on the generateFindings path — it capped at `medium` regardless of
 * evidence.
 *
 * The threading is monotonic: every confidence gate is a `> 0.8` escalation
 * placed ahead of the lower fallbacks and no rule tests for low confidence, so
 * it can raise a severity but never lower one, and the finding set is
 * unchanged. These tests pin both halves of that.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { calculateSeverity, HIGH_SINKS } from '../../src/analysis/rules.js';

const findingsFor = async (code: string, file: string, lang: 'java' | 'python') => {
  const ir = await analyze(code, file, lang);
  return generateFindings(
    ir.taint.sources, ir.taint.sinks, ir.dfg, file, code, lang, ir.taint.sanitizers ?? [],
  );
};

describe('#281 confidence reaches the severity rules', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a high-confidence servlet XSS flow is rated high, not capped at medium', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class X extends HttpServlet {',
      '  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {',
      '    String p = req.getParameter("p");',
      '    res.getWriter().write("<div>" + p + "</div>");',
      '  }',
      '}',
    ].join('\n');
    const xss = (await findingsFor(code, 'X.java', 'java')).filter(f => f.type === 'xss');
    expect(xss.length).toBeGreaterThan(0);
    const top = xss.find(f => (f.confidence ?? 0) > 0.8);
    expect(top, 'expected an xss finding with confidence > 0.8').toBeDefined();
    expect(top!.severity).toBe('high');
  });

  it('every HIGH_SINKS type can now reach high (the rule is reachable at all)', () => {
    for (const sinkType of HIGH_SINKS) {
      expect(
        calculateSeverity({ sinkType, pathExists: true, confidence: 0.9 }),
        `${sinkType} should reach high at confidence 0.9`,
      ).toBe('high');
      // Below the gate it must still be medium — the escalation is confidence-gated,
      // not unconditional.
      expect(
        calculateSeverity({ sinkType, pathExists: true, confidence: 0.5 }),
      ).toBe('medium');
    }
  });

  it('severity is monotonic in confidence — raising it never lowers a rating', () => {
    const order = { low: 0, medium: 1, high: 2, critical: 3 } as const;
    const sinkTypes = [...HIGH_SINKS, 'sql_injection', 'command_injection'] as const;
    for (const sinkType of sinkTypes) {
      for (const pathExists of [true, false]) {
        for (const sourceType of [undefined, 'http_param']) {
          let prev = -1;
          for (const confidence of [0, 0.3, 0.5, 0.7, 0.81, 0.9, 1]) {
            const sev = calculateSeverity({ sinkType, pathExists, confidence, sourceType });
            expect(order[sev]).toBeGreaterThanOrEqual(prev);
            prev = order[sev];
          }
        }
      }
    }
  });
});
