/**
 * Regression lock for cognium-dev #265.
 *
 * `JSON.parse(userInput)` is the SAFE alternative to `eval` — it parses
 * data, it does not execute code. It must never be classified as a
 * CWE-94 (code_injection) sink. In circle-ir it is registered as a
 * sanitizer (`{ method: 'parse', class: 'JSON', removes: [...] }`), so
 * a tainted value flowing into `JSON.parse` produces no code_injection
 * sink, no code_injection flow, and no CWE-94 finding.
 *
 * #265 reported a benchmark FP on `xss_eval_safe_json`, but the root
 * cause was the HTML harness's file-level `hasSource && hasSink`
 * co-occurrence heuristic (circle-ir-ai `run-html.ts:664`), which flags
 * on the co-located `console.log` (log_injection) sink and ignores
 * flows/findings/CWE — NOT a circle-ir sink-set defect. This test pins
 * the engine's correct behavior so a future change can't regress
 * `JSON.parse` into an eval-class sink.
 *
 * The `eval` positive control proves the assertions are meaningful:
 * eval(userInput) MUST still fire code_injection.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

describe('cognium-dev #265 — JSON.parse is not a CWE-94 code_injection sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const codeInjSinks = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.sinks ?? []).filter(s => s.type === 'code_injection');
  const codeInjFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).filter(f => f.sink_type === 'code_injection');
  const cwe94Findings = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.findings ?? []).filter(f => f.cwe === 'CWE-94' || f.cwe === 'CWE-094');

  it('JS — JSON.parse(userInput) emits no code_injection sink/flow/finding', async () => {
    const code = `const params = new URLSearchParams(window.location.search);
const data = params.get('data');
const parsed = JSON.parse(data);
console.log(parsed);`;
    const r = await analyze(code, 'safe.js', 'javascript');
    expect(codeInjSinks(r)).toHaveLength(0);
    expect(codeInjFlows(r)).toHaveLength(0);
    expect(cwe94Findings(r)).toHaveLength(0);
  });

  it('HTML — the exact #265 benchmark case emits no code_injection sink/flow/finding', async () => {
    const code = `<!DOCTYPE html>
<html>
<body>
<script>
  const params = new URLSearchParams(window.location.search);
  const data = params.get('data');
  const parsed = JSON.parse(data);
  console.log(parsed);
</script>
</body>
</html>`;
    const r = await analyze(code, 'xss_eval_safe_json.html', 'html');
    expect(codeInjSinks(r)).toHaveLength(0);
    expect(codeInjFlows(r)).toHaveLength(0);
    expect(cwe94Findings(r)).toHaveLength(0);
  });

  it('positive control — eval(userInput) DOES fire code_injection', async () => {
    // Proves the negative assertions above are meaningful: the eval-class
    // sink the safe JSON.parse case is contrasted against must still fire.
    const code = `const params = new URLSearchParams(window.location.search);
const data = params.get('data');
eval(data);`;
    const r = await analyze(code, 'unsafe.js', 'javascript');
    expect(codeInjSinks(r).length).toBeGreaterThan(0);
  });
});
