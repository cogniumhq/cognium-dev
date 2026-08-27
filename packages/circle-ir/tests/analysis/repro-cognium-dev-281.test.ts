/**
 * cognium-dev#281 — `SeverityContext.confidence` is never passed, so every
 * HIGH_SINKS family is structurally capped at `medium`.
 *
 * `calculateSeverity` accepts a `confidence` field and gates two of its rules
 * on `confidence > 0.8`. Its only caller (`generateFindings`) passes just
 * `{sourceType, sinkType, pathExists}`, so `confidence` always falls back to
 * the `0.5` default and both rules are unreachable. With
 * `pathExists && isHigh && confidence > 0.8` dead, every HIGH_SINKS member
 * (xss, path_traversal, xxe, ssrf, ldap_injection, xpath_injection) falls
 * through to `if (pathExists) return 'medium'` and can never be rated `high`.
 *
 * Note the caller *does* compute a real confidence — `calculateConfidence` runs
 * on the very next line and is stamped onto the finding — it is simply never
 * fed back into the severity decision.
 *
 * CHARACTERIZATION TEST. These assert today's (defective) behaviour so the
 * blast radius of a fix is visible. When #281 is fixed, the `medium`
 * expectations below must be updated to the new intended tiering, and the
 * change re-validated against OWASP Benchmark / Juliet / SecuriBench — this
 * re-tiers findings upward across every consumer.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { calculateSeverity, HIGH_SINKS } from '../../src/analysis/rules.js';

const SSRF_SERVLET = [
  'package com.example;',
  'import javax.servlet.http.*;',
  'import java.net.*;',
  'public class SsrfServlet extends HttpServlet {',
  '    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {',
  '        String target = request.getParameter("url");',
  '        URL u = new URL(target);',
  '        u.openConnection().getInputStream();',
  '    }',
  '}',
].join('\n');

describe('cognium-dev#281 — the confidence gate is dead', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('calculateSeverity CAN return high for a HIGH_SINKS type — when confidence is supplied', () => {
    // The function itself is correct; it is the call site that starves it.
    expect(calculateSeverity({
      sourceType: 'http_param', sinkType: 'ssrf', pathExists: true, confidence: 0.95,
    })).toBe('high');
  });

  it('...but omitting confidence (what the caller does) yields medium', () => {
    expect(calculateSeverity({
      sourceType: 'http_param', sinkType: 'ssrf', pathExists: true,
    })).toBe('medium');
  });

  it('every HIGH_SINKS family is capped at medium when confidence is omitted', () => {
    for (const sinkType of HIGH_SINKS) {
      expect(calculateSeverity({ sourceType: 'http_param', sinkType, pathExists: true }))
        .toBe('medium');
    }
  });

  it('end-to-end: a servlet SSRF is rated medium despite its own confidence exceeding 0.8', async () => {
    const r = await analyze(SSRF_SERVLET, 'SsrfServlet.java', 'java');
    const findings = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'SsrfServlet.java', SSRF_SERVLET, 'java',
      r.taint.sanitizers ?? [],
    );
    const ssrf = findings.filter((f) => f.type === 'ssrf');
    expect(ssrf).toHaveLength(1);
    // The finding's *own* confidence clears the rule's 0.8 threshold...
    expect(ssrf[0].confidence).toBeGreaterThan(0.8);
    // ...yet the severity is medium, because that value never reaches
    // calculateSeverity. This is the defect, asserted as-is.
    expect(ssrf[0].severity).toBe('medium');
  });

  it('CRITICAL_SINKS are unaffected — they do not depend on the dead gate', async () => {
    const code = SSRF_SERVLET
      .replace('import java.net.*;', '')
      .replace('URL u = new URL(target);', '')
      .replace('u.openConnection().getInputStream();', 'Runtime.getRuntime().exec(target);');
    const r = await analyze(code, 'C.java', 'java');
    const findings = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'C.java', code, 'java', r.taint.sanitizers ?? [],
    );
    const cmdi = findings.filter((f) => f.type === 'command_injection');
    expect(cmdi.length).toBeGreaterThan(0);
    expect(cmdi[0].severity).toBe('critical');
  });
});
