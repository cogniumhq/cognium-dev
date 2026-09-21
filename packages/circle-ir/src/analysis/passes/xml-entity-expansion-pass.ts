/**
 * Pass: xml-entity-expansion (CWE-611 / CWE-776, category: security)
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
 *   Safe-feature setters. Any of these in the file silences a factory
 *   UNLESS that factory is a local variable which provably never receives
 *   one (no hardening-capable setter on it in its method, never passed to
 *   another call, never returned) — so one hardened factory no longer masks
 *   an unhardened one beside it:
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
 * CWE is assigned PER API, by which weakness the unhardened default actually
 * leaves open (#426) — the same per-API reasoning `language-sources-pass`
 * applies to Python's `xml.sax`:
 *   - Java JAXP factories  -> CWE-611. External entity resolution is ON by
 *     default, while JAXP has shipped a default entity-expansion limit for
 *     years, so the live risk on a current JDK is external entities. Every
 *     hardening token this pass looks for is an external-entity control.
 *   - `lxml.etree`         -> CWE-611. `resolve_entities` defaults on.
 *   - `xml.etree.ElementTree` -> CWE-776. It never resolves external entities;
 *     what remains is entity expansion.
 * The JS variant of this rule (`libxmljs` `noent: true`) already reported
 * CWE-611, so before this the rule disagreed with itself across languages.
 *
 * Issue: #86, Sprint 6.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo, TypeInfo } from '../../types/index.js';

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

// Any call that CAN carry XML hardening, on any receiver — factory, parser,
// reader, validator or transformer. Matched by name, not argument, because the
// feature string is routinely a constant declared elsewhere.
const JAVA_HARDENING_SETTER_RE =
  /\.\s*(?:setFeature|setAttribute|setProperty|setXIncludeAware|setExpandEntityReferences)\s*\(/;

// A factory consumed in the same expression that creates it — never bound to a
// name, so it can never be configured.
const JAVA_FACTORY_CHAINED_RE =
  /\bnewInstance\s*\([^()]*\)\s*\.\s*(?:newDocumentBuilder|newSAXParser|newTransformer|newTemplates|newSchema|createXMLStreamReader|createXMLEventReader)\s*\(/;

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
      // Hardening evidence used to silence the WHOLE file, so one hardened
      // factory masked every other factory beside it. When evidence exists,
      // keep only the factories that provably never receive it (see
      // `isProvablyUnhardened`); anything ambiguous stays silent, as before.
      // `jdk.xml.*` limits are set process-wide (System.setProperty), so they
      // reach every factory regardless of which variable the file touches.
      const processWide = safeInFile && /jdk\.xml\./.test(code);
      const lines = safeInFile ? code.split('\n') : [];
      const methodRanges = safeInFile ? this.methodRanges(graph.ir.types) : [];

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
        if (safeInFile && (processWide || !this.isProvablyUnhardened(lines, line, methodRanges, det.api)))
          continue;
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
            'processing. Vulnerable to external-entity disclosure ' +
            '(CWE-611) and billion-laughs / quadratic blow-up DoS ' +
            '(CWE-776). Add `setFeature("http://apache.org/xml/features/' +
            'disallow-doctype-decl", true)` (or the equivalent) before ' +
            'parsing.',
          file,
          line,
          fix: this.fixForJava(det.api),
          evidence: { ...det, language, safeFeatureInFile: safeInFile },
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
            (det.cwe === 'CWE-611'
              ? 'to external-entity disclosure (CWE-611) and billion-laughs / ' +
                'quadratic blow-up DoS (CWE-776). '
              : 'to billion-laughs / quadratic blow-up DoS (CWE-776). ') +
            'Use `defusedxml` or pass ' +
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

  private methodRanges(types: TypeInfo[] | undefined): Array<[number, number]> {
    const out: Array<[number, number]> = [];
    for (const t of types ?? []) {
      for (const m of t.methods ?? []) {
        if (typeof m.start_line === 'number' && typeof m.end_line === 'number')
          out.push([m.start_line, m.end_line]);
      }
    }
    return out;
  }

  /**
   * In a file that DOES contain hardening evidence, is the factory created on
   * `line` one that provably never receives it?
   *
   * Deliberately one-sided. It answers true for exactly two shapes:
   *
   *   1. CHAINED — `Factory.newInstance().newDocumentBuilder()`, where the
   *      product is not handed on or returned either.
   *   2. LOCAL — `Factory f = Factory.newInstance();` where the enclosing method
   *      builds a parser from `f`, never hands `f` to another call, and never
   *      returns it.
   *
   * and in both only when the enclosing method contains NO hardening-capable
   * setter on ANY receiver, since hardening may land on the factory's product
   * (`parser.getXMLReader().setFeature(…)`) rather than the factory.
   *
   * Every other shape — a field, a helper that takes the factory, a caller that
   * receives it — may be hardened somewhere this check cannot see, so it keeps
   * the previous file-level silence.
   *
   * A TransformerFactory additionally needs a `StreamSource` in its method: that
   * is the input the transformer parses with its OWN parser. Fed a `DOMSource`
   * it parses nothing, and fed a `SAXSource` it uses the reader it was given —
   * whose hardening is that reader's business, not this factory's.
   */
  private isProvablyUnhardened(
    lines: string[],
    line: number,
    methodRanges: Array<[number, number]>,
    api: string,
  ): boolean {
    // Innermost enclosing method; without one the factory's reach is unknown.
    let range: [number, number] | null = null;
    for (const r of methodRanges) {
      if (line < r[0] || line > r[1]) continue;
      if (!range || r[1] - r[0] < range[1] - range[0]) range = r;
    }
    if (!range) return false;
    // The creating statement, joined to its `;` — `newInstance(` is often broken
    // across lines after the opening parenthesis.
    let decl = '';
    let declEnd = line;
    for (; declEnd <= Math.min(line + 3, range[1]); declEnd++) {
      decl += ' ' + (lines[declEnd - 1] ?? '').trim();
      if (decl.includes(';')) break;
    }
    const body = lines.slice(line - 1, range[1]).join('\n');
    if (api === 'TransformerFactory' && !/\bnew\s+StreamSource\s*\(/.test(body))
      return false;

    // Hardening need not land on the factory: `parser.getXMLReader().setFeature(…)`
    // and `parser.setProperty(…)` harden its PRODUCT. So a method containing any
    // hardening-capable setter, on any receiver, is not provable either way.
    if (JAVA_HARDENING_SETTER_RE.test(body)) return false;

    const chained = JAVA_FACTORY_CHAINED_RE.exec(decl);
    if (chained) {
      // The product may still be handed to a helper that hardens it.
      const prod = /[\w>\]]\s+([A-Za-z_$][\w$]*)\s*=/.exec(decl);
      if (!prod) return true;
      const pn = prod[1].replace(/\$/g, '\\$');
      const after = lines.slice(declEnd, range[1]).join('\n');
      return !new RegExp(`[(,]\\s*${pn}\\s*[,)]|\\breturn\\s+${pn}\\s*;`).test(after);
    }

    // `Type name = …newInstance(…);` — a declaration ending the statement, so
    // `name` is a local bound to the factory itself and not to a chained result.
    const m = /[\w>\]]\s+([A-Za-z_$][\w$]*)\s*=\s*[\w.]*\bnewInstance\s*\([^()]*\)\s*;/.exec(decl);
    if (!m) return false;
    const name = m[1].replace(/\$/g, '\\$');
    const rest = lines.slice(declEnd, range[1]).join('\n');
    // Only a factory that goes on to build a parser matters; one created to
    // inspect (`factory.getClass()`) and dropped parses nothing.
    const builds = new RegExp(
      `\\b${name}\\s*\\.\\s*(?:newDocumentBuilder|newSAXParser|newTransformer|newTemplates|newSchema|createXMLStreamReader|createXMLEventReader)\\s*\\(`,
    );
    if (!builds.test(rest)) return false;
    // Passed to another call (`harden(dbf)`, `x.configure(a, dbf)`) or returned.
    const escapes = new RegExp(`[(,]\\s*${name}\\s*[,)]|\\breturn\\s+${name}\\s*;`);
    if (escapes.test(rest)) return false;
    return true;
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
          cwe: 'CWE-611',
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
        cwe: 'CWE-611',
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
