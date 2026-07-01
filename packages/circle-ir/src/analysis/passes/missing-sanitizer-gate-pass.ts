/**
 * Pass: missing-sanitizer-gate (#107, CWE-79)
 *
 * Detects HTML-attribute / HTML-output methods that pass caller-supplied
 * values to a sink (writer.addAttribute, print, write, etc.) without any
 * sanitizer-shaped call dominating the sink on all control-flow paths.
 *
 * Motivating pattern — CVE-2023-37908 (xwiki-rendering `XHTMLWikiPrinter`):
 *
 *   void cleanAttributes(String elementName, Map<String,String> attributes) {
 *     for (Entry<String,String> e : attributes.entrySet()) {
 *       writer.addAttribute(e.getKey(), e.getValue());   // SINK
 *     }
 *   }
 *
 * The fix wraps the sink in `isAttributeAllowed(elementName, k, v)`. This
 * pass models that shape as a dominator check: for each HTML output sink
 * in a candidate method, at least one sanitizer-named call must dominate
 * the sink block. If none does, we emit a speculative finding.
 *
 * Detection is intentionally permissive (name-only matching on both sinks
 * and sanitizers, no receiver-type resolution). To keep the default CLI
 * surface unchanged, findings are marked `confidence: 'medium'` and are
 * suppressed by `applyConfidenceFilter` unless the caller opts in via
 * `analyze(..., { includeSpeculative: true })`. Downstream verifiers
 * (`circle-ir-ai`, `cognium-ai`) receive the full stream and adjudicate.
 *
 * Language: Java only. Deferred to future work for JS/Python once we have
 * real-world FP/TP telemetry from downstream adjudication.
 *
 * Dedup: at most one finding per method.
 *
 * See: docs/PASSES.md #107, cognium-dev#153.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { MethodInfo } from '../../types/index.js';
import { DominatorGraph } from '../../graph/dominator-graph.js';
import { classifyEntryPointTier } from '../entry-point-detection.js';

/**
 * HTML-output sink method names (Java, initial set).
 *
 * Name-only match. Covers DOM/SAX attribute writes, XMLStreamWriter/Writer
 * output, XWiki/WikiPrinter XML output methods, and PrintWriter-style
 * HTML-building helpers.
 */
const HTML_OUTPUT_SINKS: ReadonlySet<string> = new Set([
  // DOM / SAX attribute writes
  'addAttribute', 'setAttribute',
  // XMLStreamWriter / Writer
  'write', 'writeAttribute', 'writeRaw',
  'writeStartElement', 'writeEndElement', 'writeCharacters',
  // XWiki WikiPrinter / XMLWriter
  'printXML', 'printXMLElement', 'printXMLStartElement',
  'printXMLEndElement', 'printRaw',
  // PrintWriter
  'print', 'println', 'printf',
  // StringBuilder-ish HTML builders
  'append', 'format',
]);

/**
 * Sanitizer-shaped method names (Java, initial set).
 *
 * Name-only match; no attempt to resolve the sanitizer's declaring class.
 * Covers common patterns: allow-list gates (`isAttributeAllowed`),
 * generic sanitize/clean/escape helpers, and standard HTML/XML escapers
 * from Apache Commons, OWASP ESAPI, Spring, and hand-rolled utilities.
 *
 * A prefix rule (`SANITIZER_PREFIX_RE`) additionally matches call sites
 * whose method name starts with `clean|sanitize|escape|encode` followed
 * by an uppercase letter (e.g. `cleanAttributes`, `escapeHtml4`) so that
 * project-local wrapper names satisfy the gate without needing to be
 * enumerated here.
 */
const SANITIZER_METHODS: ReadonlySet<string> = new Set([
  'isAttributeAllowed', 'isElementAllowed', 'isSafe',
  'sanitize', 'clean', 'escape', 'encode',
  'forHtml', 'forHtmlAttribute', 'forHtmlContent',
  'encodeForHTML', 'encodeForHTMLAttribute',
  'escapeHtml', 'escapeHtml4', 'escapeXml',
  'htmlEscape', 'xmlEscape',
]);

const SANITIZER_PREFIX_RE = /^(?:clean|sanitize|escape|encode)[A-Z]/;

function isSanitizerCall(methodName: string): boolean {
  return SANITIZER_METHODS.has(methodName) || SANITIZER_PREFIX_RE.test(methodName);
}

/**
 * Regex matched against a `String` parameter's name (case-insensitive).
 * A `String` parameter only counts toward the parameter-type gate when
 * its name suggests it carries HTML/XML content or an attribute value.
 */
const STRING_PARAM_NAME_PATTERN = /attr|attribute|html|xml|body|content/i;

export interface MissingSanitizerGateResult {
  findings: number;
}

export class MissingSanitizerGatePass implements AnalysisPass<MissingSanitizerGateResult> {
  readonly name = 'missing-sanitizer-gate';
  readonly category = 'security' as const;

  run(ctx: PassContext): MissingSanitizerGateResult {
    const { graph, language } = ctx;

    if (language !== 'java') return { findings: 0 };

    const { cfg, calls, types } = graph.ir;
    if (cfg.blocks.length === 0 || cfg.edges.length === 0) return { findings: 0 };
    if (calls.length === 0) return { findings: 0 };

    const file = graph.ir.meta.file;

    // Partition call sites once.
    const sinkCalls: Array<{ line: number; method: string }> = [];
    const sanitizerLines: number[] = [];
    for (const call of calls) {
      if (HTML_OUTPUT_SINKS.has(call.method_name)) {
        sinkCalls.push({ line: call.location.line, method: call.method_name });
      }
      if (isSanitizerCall(call.method_name)) {
        sanitizerLines.push(call.location.line);
      }
    }
    if (sinkCalls.length === 0) return { findings: 0 };

    const blockContainingLine = (line: number) =>
      cfg.blocks.find(b => b.start_line <= line && line <= b.end_line) ?? null;

    // Per-method DominatorGraph cache.
    //
    // The file-level CFG has one `type='entry'` block per method, but a
    // single `DominatorGraph(cfg)` uses only ONE entry (block 0 or the
    // first `type='entry'`), so every other method's blocks are marked
    // unreachable and `dominates()` returns false. We build one
    // DominatorGraph per method using that method's own entry block.
    const domByMethodKey = new Map<string, DominatorGraph | null>();
    const getDomForMethod = (
      methodKey: string,
      method: MethodInfo,
    ): DominatorGraph | null => {
      if (domByMethodKey.has(methodKey)) return domByMethodKey.get(methodKey) ?? null;
      // Prefer a `type='entry'` block whose line range is inside the
      // method (the real Java CFG shape). Fall back to the first block
      // that lies within the method — sufficient for minimal test
      // fixtures where the entry block sits outside the method range.
      const entry =
        cfg.blocks.find(
          b =>
            b.type === 'entry' &&
            b.start_line >= method.start_line &&
            b.end_line <= method.end_line,
        ) ??
        cfg.blocks.find(
          b => b.start_line >= method.start_line && b.end_line <= method.end_line,
        );
      const dom = entry ? new DominatorGraph(cfg, entry.id) : null;
      domByMethodKey.set(methodKey, dom);
      return dom;
    };

    const reportedMethods = new Set<string>();
    let count = 0;

    for (const sink of sinkCalls) {
      const sinkBlock = blockContainingLine(sink.line);
      if (!sinkBlock) continue;

      const methodInfo = graph.methodAtLine(sink.line);
      if (!methodInfo) continue;

      const methodKey = `${methodInfo.type.name}::${methodInfo.method.name}`;
      if (reportedMethods.has(methodKey)) continue;

      // Skip Tier 1 entry points — the configured xss / CWE-79 sinks
      // and taint sources already cover the network trust boundary; this
      // pass targets the intra-library helper shape.
      const tier = classifyEntryPointTier(methodInfo.method, methodInfo.type, {
        types,
        language,
      });
      if (tier === 'TIER_1_ENTRY_POINT') continue;

      // Parameter-type gate: the method must accept at least one
      // caller-supplied attribute/HTML-shaped value.
      if (!methodAcceptsHtmlShapedParam(methodInfo.method)) continue;

      const dom = getDomForMethod(methodKey, methodInfo.method);
      if (!dom) continue;

      const { start_line, end_line } = methodInfo.method;

      // Restrict sanitizer calls to those inside the same method.
      const sanitizersInMethod = sanitizerLines.filter(
        l => l >= start_line && l <= end_line,
      );

      const dominated = sanitizersInMethod.some(sanLine => {
        const sanBlock = blockContainingLine(sanLine);
        return sanBlock !== null && dom.dominates(sanBlock.id, sinkBlock.id);
      });

      if (!dominated) {
        reportedMethods.add(methodKey);
        count++;
        ctx.addFinding({
          id: `missing-sanitizer-gate-${file}-${sink.line}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-79',
          severity: 'medium',
          level: 'note',
          confidence: 'medium',
          message:
            `HTML output sink \`${sink.method}()\` at line ${sink.line} is not ` +
            `dominated by any sanitizer call in method \`${methodInfo.method.name}\`. ` +
            `Caller-supplied attribute/HTML values may reach the sink unescaped.`,
          file,
          line: sink.line,
          fix:
            `Gate the sink on all paths with an allow-list check ` +
            `(e.g. \`isAttributeAllowed(...)\`) or wrap the argument in an HTML/XML ` +
            `escaper (\`escapeHtml\`, \`encodeForHTMLAttribute\`, \`forHtmlAttribute\`).`,
          evidence: { sink: sink.method, method: methodInfo.method.name },
        });
      }
    }

    return { findings: count };
  }
}

/**
 * True iff the method accepts at least one parameter whose declared type
 * is `Map<String,String>` / `Attributes` (SAX), or a `String` whose name
 * suggests it carries HTML/XML content or an attribute value.
 *
 * Whitespace-tolerant on the `Map<String,String>` variant. Loose on
 * `String` deliberately — xwiki's `cleanAttributes(String elementName, ...)`
 * fires on this leg.
 */
function methodAcceptsHtmlShapedParam(method: MethodInfo): boolean {
  for (const p of method.parameters) {
    if (!p.type) continue;
    const type = p.type.replace(/\s+/g, '');
    if (type === 'Attributes') return true;
    if (type.startsWith('Map<String,String')) return true;
    if (type === 'String' && STRING_PARAM_NAME_PATTERN.test(p.name)) return true;
  }
  return false;
}
