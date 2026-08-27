/**
 * cognium-dev#282 — `http_param -> xxe` is missing from the reach map, so
 * servlet XXE is silently dropped at the finding layer.
 *
 * `canSourceReachSink` lists `xxe` under `http_body` but not under
 * `http_param`, `http_query`, `http_header` or `http_cookie`. A servlet that
 * parses `request.getParameter(...)` therefore produces a valid `xxe` sink and
 * a valid `http_param` source, but `generateFindings` emits nothing — the same
 * "two paths disagree" shape as the log_injection / format_string /
 * nosql_injection omission fixed for cognium-ai#129, which did not cover xxe.
 *
 * CHARACTERIZATION TEST. The `http_param` expectations assert today's
 * (defective) behaviour. When #282 is fixed they must flip to `true` / a
 * non-empty finding list; the `http_body` cases below are the recall guard
 * that must keep passing either way.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings, canSourceReachSink } from '../../src/analysis/findings.js';

const xxeServlet = (method: string, read: string) => [
  'package com.example;',
  'import javax.servlet.http.*;',
  'import javax.xml.parsers.*;',
  'public class XxeServlet extends HttpServlet {',
  `    protected void ${method}(HttpServletRequest request, HttpServletResponse response) throws Exception {`,
  `        String xml = ${read};`,
  '        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();',
  '        DocumentBuilder db = dbf.newDocumentBuilder();',
  '        db.parse(xml);',
  '    }',
  '}',
].join('\n');

const PARAM_XXE = xxeServlet('doGet', 'request.getParameter("xml")');
const BODY_XXE = xxeServlet('doPost', 'request.getReader().readLine()');

describe('cognium-dev#282 — xxe reach-map omission', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const findingsFor = async (code: string) => {
    const r = await analyze(code, 'XxeServlet.java', 'java');
    return {
      ir: r,
      findings: generateFindings(
        r.taint.sources, r.taint.sinks, r.dfg, 'XxeServlet.java', code, 'java',
        r.taint.sanitizers ?? [],
      ),
    };
  };

  it('the reach map omits xxe for every request-derived source except http_body', () => {
    expect(canSourceReachSink('http_body', 'xxe')).toBe(true);   // recall guard
    expect(canSourceReachSink('http_param', 'xxe')).toBe(false); // the defect
    expect(canSourceReachSink('http_query', 'xxe')).toBe(false);
  });

  it('source and sink are both detected for the http_param servlet', async () => {
    const { ir } = await findingsFor(PARAM_XXE);
    expect(ir.taint.sinks.some((s) => s.type === 'xxe')).toBe(true);
    expect(ir.taint.sources.some((s) => s.type === 'http_param')).toBe(true);
  });

  it('...yet no xxe finding is emitted (the silent FN)', async () => {
    const { findings } = await findingsFor(PARAM_XXE);
    expect(findings.filter((f) => f.type === 'xxe')).toHaveLength(0);
  });

  it('the http_body variant DOES emit, proving the fixture shape is sound', async () => {
    const { findings } = await findingsFor(BODY_XXE);
    const xxe = findings.filter((f) => f.type === 'xxe');
    expect(xxe.length).toBeGreaterThan(0);
    // Capped at medium by the separate #281 defect.
    expect(xxe[0].severity).toBe('medium');
  });
});
