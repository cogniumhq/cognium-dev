/**
 * Pass: xml-entity-expansion (CWE-776 / CWE-611, category: security)
 *
 * Pattern pass — flags XML parser instantiation that does *not* disable
 * DTD / external-entity processing in the same file. This covers:
 *   - Billion-laughs / quadratic blow-up DoS (CWE-776)
 *   - External-entity disclosure (CWE-611) [already partially covered by
 *     existing xxe taint sinks; this pass adds the config-level signal]
 *
 * Detection (Java):
 *   Factory instantiation:
 *     - `SAXParserFactory.newInstance()`
 *     - `DocumentBuilderFactory.newInstance()`
 *     - `XMLInputFactory.newInstance()` (StAX)
 *     - `SchemaFactory.newInstance(...)`
 *     - `TransformerFactory.newInstance()`
 *   Safe-feature setters (any of these in the same file silences the
 *   finding for that factory class):
 *     - `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
 *     - `setFeature("http://xml.org/sax/features/external-general-entities", false)`
 *     - `setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
 *     - `setProperty(XMLInputFactory.SUPPORT_DTD, false)`
 *     - `setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "")`
 *
 * Detection (Python):
 *   - `xml.etree.ElementTree.parse` / `fromstring` — defxml advises
 *     `defusedxml.ElementTree` instead.
 *   - `lxml.etree.parse(...)` without `XMLParser(resolve_entities=False)`
 *     argument. We only fire if `resolve_entities=False` does NOT appear
 *     in the file.
 *
 * Note: the existing `xxe` taint sinks (`SAXParser.parse`, `XMLReader.parse`,
 * etc.) already fire when *tainted* XML reaches the parser. This pass is
 * the orthogonal *configuration* signal — fire even on hard-coded inputs
 * because billion-laughs is exploitable via any attacker-supplied entity
 * file even when the parse() argument itself is trusted.
 *
 * Issue: #86, Sprint 6.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

const JAVA_FACTORIES = new Set<string>([
  'SAXParserFactory',
  'DocumentBuilderFactory',
  'XMLInputFactory',
  'SchemaFactory',
  'TransformerFactory',
]);

// "Disallow DTD" / safe-feature evidence — any one of these in the file
// suppresses the warning. Conservative on purpose: a missed feature still
// fires; FPs only on cross-file configuration.
//
// Extended in 3.102.0 (#166) to recognize JDK 8u121+ entity-limit
// hardening (jdk.xml.*Limit properties), the Apache load-external-dtd
// feature disable, and the XMLConstants secure-processing feature.
const JAVA_SAFE_EVIDENCE_RE =
  /(disallow-doctype-decl|external-general-entities|external-parameter-entities|SUPPORT_DTD|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|load-external-dtd|feature\/secure-processing|FEATURE_SECURE_PROCESSING|jdk\.xml\.(?:totalEntitySizeLimit|entityExpansionLimit|maxGeneralEntitySizeLimit|maxParameterEntitySizeLimit|elementAttributeLimit)|setXIncludeAware\s*\(\s*false\s*\)|setExpandEntityReferences\s*\(\s*false\s*\))/;

// #173 — output-only TransformerFactory shape:
//   - file contains DOMSource / StreamResult construction
//   - file contains NO StreamSource / SAXSource / InputSource
//     (i.e., factory never reads attacker-controllable bytes)
const JAVA_XML_OUTPUT_ONLY_RE =
  /\bnew\s+(?:DOMSource|StreamResult)\s*\(/;
const JAVA_XML_PARSE_INPUT_RE =
  /\bnew\s+(?:StreamSource|SAXSource|InputSource)\s*\(/;

// #173 — empty-DocumentBuilder shape:
//   - file calls builder.newDocument() (creates empty in-memory tree)
//   - file calls NO builder.parse(...) (never reads bytes)
const JAVA_DOC_BUILDER_NEW_DOCUMENT_RE = /\.\s*newDocument\s*\(\s*\)/;
const JAVA_DOC_BUILDER_PARSE_RE =
  /(?:DocumentBuilder|builder)\s*\.\s*parse\s*\(/;

const PY_LXML_PARSER_INSECURE_DEFAULT_RE = /\bresolve_entities\s*=\s*False\b/;

interface Detection {
  pattern: string;
  api: string;
  cwe: string;
}

export interface XmlEntityExpansionResult {
  findings: Array<{
    line: number;
    language: string;
    pattern: string;
    api: string;
  }>;
}

export class XmlEntityExpansionPass
  implements AnalysisPass<XmlEntityExpansionResult>
{
  readonly name = 'xml-entity-expansion';
  readonly category = 'security' as const;

  run(ctx: PassContext): XmlEntityExpansionResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: XmlEntityExpansionResult['findings'] = [];
    const code = ctx.code ?? '';

    if (language === 'java') {
      const safeInFile = JAVA_SAFE_EVIDENCE_RE.test(code);
      if (safeInFile) return { findings };

      // #173 — output-only TransformerFactory + empty DocumentBuilder.
      // File-level heuristics; conservative-bias (only suppress when the
      // file shows ONLY the safe shape and NO unsafe shape).
      const isXmlOutputOnly =
        JAVA_XML_OUTPUT_ONLY_RE.test(code) &&
        !JAVA_XML_PARSE_INPUT_RE.test(code);
      const isDocumentBuilderEmptyOnly =
        JAVA_DOC_BUILDER_NEW_DOCUMENT_RE.test(code) &&
        !JAVA_DOC_BUILDER_PARSE_RE.test(code);

      for (const call of graph.ir.calls) {
        const det = this.detectJavaCall(call);
        if (!det) continue;
        // #173 — suppress when factory is only used for output / empty doc.
        if (det.api === 'TransformerFactory' && isXmlOutputOnly) continue;
        if (det.api === 'DocumentBuilderFactory' && isDocumentBuilderEmptyOnly)
          continue;
        const line = call.location.line;
        findings.push({ line, language, ...det });
        ctx.addFinding({
          id: `${this.name}-${file}-${line}-${det.api}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: det.cwe,
          severity: 'high',
          level: 'error',
          message:
            `${det.api} created without disabling DTD / external-entity ` +
            'processing. Vulnerable to billion-laughs / quadratic ' +
            'blow-up DoS (CWE-776) and external-entity disclosure ' +
            '(CWE-611). Add `setFeature("http://apache.org/xml/features/' +
            'disallow-doctype-decl", true)` (or the equivalent) before ' +
            'parsing.',
          file,
          line,
          fix: this.fixForJava(det.api),
          evidence: { ...det, language, safeFeatureInFile: false },
        });
      }
      return { findings };
    }

    if (language === 'python') {
      const safeInFile = PY_LXML_PARSER_INSECURE_DEFAULT_RE.test(code) ||
                        /\bdefusedxml\b/.test(code);
      if (safeInFile) return { findings };

      for (const call of graph.ir.calls) {
        const det = this.detectPythonCall(call);
        if (!det) continue;
        const line = call.location.line;
        findings.push({ line, language, ...det });
        ctx.addFinding({
          id: `${this.name}-${file}-${line}-${det.api}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: det.cwe,
          severity: 'high',
          level: 'error',
          message:
            `${det.api} called without an entity-safe parser. Vulnerable ` +
            'to billion-laughs / quadratic blow-up DoS (CWE-776) and ' +
            'external-entity disclosure (CWE-611). Use `defusedxml` or pass ' +
            'an `XMLParser(resolve_entities=False)` to lxml.',
          file,
          line,
          fix: this.fixForPython(det.api),
          evidence: { ...det, language, safeFeatureInFile: false },
        });
      }
      return { findings };
    }

    return { findings };
  }

  private detectJavaCall(call: CallInfo): Detection | null {
    if (call.method_name !== 'newInstance') return null;
    const recv = call.receiver ?? '';
    const recvType = call.receiver_type ?? '';
    for (const factory of JAVA_FACTORIES) {
      if (recv === factory || recvType === factory ||
          recv.endsWith('.' + factory) || recvType.endsWith('.' + factory)) {
        return {
          pattern: `${factory}.newInstance()`,
          api: factory,
          cwe: 'CWE-776',
        };
      }
    }
    return null;
  }

  private detectPythonCall(call: CallInfo): Detection | null {
    const recv = call.receiver ?? '';
    const method = call.method_name;
    // lxml.etree.parse / lxml.etree.fromstring
    if ((method === 'parse' || method === 'fromstring' || method === 'XML') &&
        (recv === 'etree' || recv.endsWith('.etree'))) {
      return {
        pattern: `etree.${method}`,
        api: `lxml.etree.${method}`,
        cwe: 'CWE-776',
      };
    }
    // xml.etree.ElementTree.parse / fromstring
    if ((method === 'parse' || method === 'fromstring') &&
        (recv === 'ET' || recv === 'ElementTree' ||
         recv.endsWith('.ElementTree'))) {
      return {
        pattern: `ElementTree.${method}`,
        api: `xml.etree.ElementTree.${method}`,
        cwe: 'CWE-776',
      };
    }
    return null;
  }

  private fixForJava(api: string): string {
    if (api === 'SAXParserFactory') {
      return (
        'Call `factory.setFeature("http://apache.org/xml/features/' +
        'disallow-doctype-decl", true)` and ' +
        '`factory.setXIncludeAware(false)` before `newSAXParser()`.'
      );
    }
    if (api === 'DocumentBuilderFactory') {
      return (
        'Call `factory.setFeature("http://apache.org/xml/features/' +
        'disallow-doctype-decl", true)` and ' +
        '`factory.setExpandEntityReferences(false)` before ' +
        '`newDocumentBuilder()`.'
      );
    }
    if (api === 'XMLInputFactory') {
      return (
        'Call `factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)` ' +
        'and `factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_' +
        'ENTITIES, false)` before `createXMLStreamReader`.'
      );
    }
    return (
      'Use `XMLConstants.FEATURE_SECURE_PROCESSING` and explicitly disable ' +
      'DTD / external-entity loading on the factory before parsing.'
    );
  }

  private fixForPython(api: string): string {
    if (api.startsWith('lxml.etree')) {
      return (
        'Pass an explicit parser: ' +
        '`etree.parse(src, parser=etree.XMLParser(resolve_entities=False, ' +
        'no_network=True))`. Even better, use the `defusedxml.lxml` wrapper.'
      );
    }
    return (
      'Replace `xml.etree.ElementTree` with `defusedxml.ElementTree`, which ' +
      'disables DTD / entity processing by default.'
    );
  }
}
