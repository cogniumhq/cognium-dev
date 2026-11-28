/**
 * Template-engine sinks are reported as `template_injection` (CWE-1336).
 *
 * Compiling or rendering a template from text the caller controls
 * (`template.New("p").Parse(src)`, `jinja2.Template(src)`,
 * `Handlebars.compile(src)`, `Velocity.evaluate(ctx, w, tag, src)`) is
 * template injection, not eval-style code injection. Template-engine sinks are
 * registered with `type: 'code_injection'` and `cwe: 'CWE-1336'`. While a
 * file is analysed they go through every code-injection rule unchanged
 * (sanitizer credit, source-to-sink reach, the Java code-injection filters,
 * library-surface tags), so whether a flow is reported does not change. When
 * the file's analysis is complete, `reportTemplateInjection` gives those sinks
 * and their flows their own type. Eval-style sinks (`eval`, `new Function`,
 * `ScriptEngine.eval`) keep `code_injection` and CWE-94.
 *
 * Steps that run after that point (cross-file paths, the project gates,
 * `generateFindings`) read `template_injection` through `ruleSinkType`, which
 * maps it back to the code-injection rules.
 */

import type { SinkType, TaintFlowInfo, TaintSink } from '../types/index.js';

export const TEMPLATE_INJECTION_CWE = 'CWE-1336';

/**
 * Retype the template-engine sinks of one file, and the flows into them, from
 * `code_injection` to `template_injection`. A flow is retyped only when every
 * code-injection sink on its line is a template-engine sink, so a line that
 * also holds an eval-style sink keeps reporting `code_injection`.
 */
export function reportTemplateInjection(taint: { sinks: TaintSink[]; flows?: TaintFlowInfo[] }): void {
  const templateLines = new Set<number>();
  const evalLines = new Set<number>();
  for (const s of taint.sinks) {
    if (s.type !== 'code_injection') continue;
    (s.cwe === TEMPLATE_INJECTION_CWE ? templateLines : evalLines).add(s.line);
  }
  if (templateLines.size === 0) return;
  for (const s of taint.sinks) {
    if (s.type === 'code_injection' && s.cwe === TEMPLATE_INJECTION_CWE) s.type = 'template_injection';
  }
  for (const f of taint.flows ?? []) {
    if (f.sink_type === 'code_injection' && templateLines.has(f.sink_line) && !evalLines.has(f.sink_line)) {
      f.sink_type = 'template_injection';
    }
  }
}

/**
 * The sink type whose rules (reach, sanitizer credit, gates) apply to
 * `sinkType`: template injection follows code injection's.
 */
export function ruleSinkType(sinkType: SinkType): SinkType;
export function ruleSinkType(sinkType: string): string;
export function ruleSinkType(sinkType: string): string {
  return sinkType === 'template_injection' ? 'code_injection' : sinkType;
}
