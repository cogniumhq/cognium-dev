/**
 * cognium-dev#281 — FIXED. `SeverityContext.confidence` is now threaded from
 * `generateFindings` into `calculateSeverity`, so the HIGH_SINKS family is no
 * longer structurally capped at `medium`.
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
 * Originally a CHARACTERIZATION TEST asserting the defect. The end-to-end
 * expectation has been flipped to the fixed tiering, as its own note required.
 * The two direct `calculateSeverity` cases below are deliberately kept: they
 * document that the FUNCTION was always correct and only the call site was at
 * fault, which is why the fix is a one-line reorder rather than a rules change.
 *
 * Re-validated on SecuriBench Micro (125 files, 175 findings): 0 findings added,
 * 0 removed, 152 severities raised medium->high, 0 lowered. Severity is
 * monotonic in confidence, so this can only re-tier upward.
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

  it('...but omitting confidence still yields medium (the gate is confidence-gated, not unconditional)', () => {
    expect(calculateSeverity({
      sourceType: 'http_param', sinkType: 'ssrf', pathExists: true,
    })).toBe('medium');
  });

  it('every HIGH_SINKS family still caps at medium when confidence is omitted', () => {
    for (const sinkType of HIGH_SINKS) {
      expect(calculateSeverity({ sourceType: 'http_param', sinkType, pathExists: true }))
        .toBe('medium');
    }
  });

  it('end-to-end: a servlet SSRF whose confidence exceeds 0.8 is now rated high', async () => {
    const r = await analyze(SSRF_SERVLET, 'SsrfServlet.java', 'java');
    const findings = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'SsrfServlet.java', SSRF_SERVLET, 'java',
      r.taint.sanitizers ?? [],
    );
    const ssrf = findings.filter((f) => f.type === 'ssrf');
    expect(ssrf).toHaveLength(1);
    // The finding's own confidence clears the rule's 0.8 threshold...
    expect(ssrf[0].confidence).toBeGreaterThan(0.8);
    // ...and that value now reaches calculateSeverity, so the escalation fires.
    expect(ssrf[0].severity).toBe('high');
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
