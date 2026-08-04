/**
 * cognium-ai#129 — `generateFindings` dropped `log_injection`, `format_string`,
 * and `nosql_injection` flows.
 *
 * These three sink families were absent from the `canSourceReachSink` reach
 * map, so `generateFindings` skipped every `http_* → {log_injection,
 * format_string, nosql_injection}` flow even though `taint.sinks` and
 * `taint.flows` already contained a valid, unsanitized source→sink flow. The
 * two paths disagreed; consumers building their report from `generateFindings`
 * (the standard path) missed all such detections. These lock the reach-map
 * entries and the end-to-end emission.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings, canSourceReachSink } from '../../src/analysis/findings.js';

describe('cognium-ai#129 — log_injection / format_string / nosql_injection reach the finding layer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const findings = async (code: string, file: string, lang: string) => {
    const r = await analyze(code, file, lang);
    return generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file, code, lang);
  };

  it('http_param → log_injection is in the reach map', () => {
    expect(canSourceReachSink('http_param', 'log_injection')).toBe(true);
    expect(canSourceReachSink('http_param', 'format_string')).toBe(true);
    expect(canSourceReachSink('http_param', 'nosql_injection')).toBe(true);
  });

  it('Go log.Printf(userInput) emits a CWE-117 log_injection finding (the issue repro)', async () => {
    const go = [
      'package main',
      'import ("log"; "net/http")',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '    user := r.URL.Query().Get("user")',
      '    log.Printf("login attempt: %s", user)',
      '}',
    ].join('\n');
    const f = await findings(go, 'h.go', 'go');
    const li = f.filter((x) => x.type === 'log_injection');
    expect(li.length).toBe(1);
    expect(li[0].cwe).toBe('CWE-117');
    expect(li[0].line).toBe(5); // sink line, matching taint.flows
  });

  it('JS console.log(userInput) emits a log_injection finding', async () => {
    const js = "app.get('/x', (req, res) => { const u = req.query.user; console.log('attempt ' + u); });";
    const f = await findings(js, 'a.js', 'javascript');
    expect(f.some((x) => x.type === 'log_injection')).toBe(true);
  });

  it('taint.flows and generateFindings now agree on log_injection (no dropped flow)', async () => {
    const go = [
      'package main',
      'import ("log"; "net/http")',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '    user := r.URL.Query().Get("user")',
      '    log.Printf("%s", user)',
      '}',
    ].join('\n');
    const r = await analyze(go, 'h.go', 'go');
    const flowHasLog = (r.taint.flows ?? []).some((fl) => fl.sink_type === 'log_injection');
    const findingHasLog = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, 'h.go', go, 'go')
      .some((x) => x.type === 'log_injection');
    expect(flowHasLog).toBe(true);
    expect(findingHasLog).toBe(true); // was false before the fix — the two paths agree now
  });
});
