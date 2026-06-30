/**
 * LanguageSourcesPass
 *
 * Detects taint sources and sinks that are not covered by config-based
 * pattern matching (analyzer.js / taint-matcher).  Handles language-specific
 * patterns that require text-level heuristics:
 *   - Java: getter methods returning tainted constructor fields
 *   - JavaScript/TypeScript: assignment sources, DOM XSS property sinks
 *   - Python: assignment sources, return-XSS sinks, trust-boundary violations
 *
 * Also computes the forward-taint maps (pyTaintedVars / jsTaintedVars) that
 * SinkFilterPass uses to reduce false positives.
 *
 * Depends on: taint-matcher, constant-propagation
 */

import type { TaintSource, TaintSink, TaintSanitizer, TypeInfo, SourceType, SastFinding, DFG } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import { attachSourceLineCode } from '../taint-matcher.js';

// ---------------------------------------------------------------------------
// Pattern tables (moved from analyzer.ts)
// ---------------------------------------------------------------------------

const JS_DOM_XSS_SINKS = [
  { pattern: /\.innerHTML\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /\.outerHTML\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /document\.write\s*\(/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /document\.writeln\s*\(/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /\.insertAdjacentHTML\s*\(/, type: 'xss' as const, cwe: 'CWE-79', severity: 'critical' as const },
  { pattern: /\.src\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'high' as const },
  { pattern: /\.href\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'high' as const },
  { pattern: /\.cssText\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'medium' as const },
  { pattern: /style\.textContent\s*=/, type: 'xss' as const, cwe: 'CWE-79', severity: 'high' as const },
];

export const JS_TAINTED_PATTERNS = [
  { pattern: /\breq\.query\b/, type: 'http_param' as const },
  { pattern: /\breq\.params\b/, type: 'http_param' as const },
  { pattern: /\breq\.body\b/, type: 'http_body' as const },
  { pattern: /\breq\.headers\b/, type: 'http_header' as const },
  { pattern: /\breq\.cookies\b/, type: 'http_cookie' as const },
  { pattern: /\breq\.url\b/, type: 'http_path' as const },
  { pattern: /\breq\.path\b/, type: 'http_path' as const },
  { pattern: /\breq\.originalUrl\b/, type: 'http_path' as const },
  { pattern: /\breq\.files?\b/, type: 'file_input' as const },
  { pattern: /\brequest\.query\b/, type: 'http_param' as const },
  { pattern: /\brequest\.params\b/, type: 'http_param' as const },
  { pattern: /\brequest\.body\b/, type: 'http_body' as const },
  { pattern: /\brequest\.headers\b/, type: 'http_header' as const },
  { pattern: /\bctx\.query\b/, type: 'http_param' as const },
  { pattern: /\bctx\.params\b/, type: 'http_param' as const },
  { pattern: /\bctx\.request\b/, type: 'http_body' as const },
  { pattern: /\bprocess\.env\b/, type: 'env_input' as const },
  { pattern: /\bprocess\.argv\b/, type: 'io_input' as const },
  { pattern: /\blocation\.search\b/, type: 'http_param' as const },
  { pattern: /\blocation\.hash\b/, type: 'http_param' as const },
  { pattern: /\blocation\.href\b/, type: 'http_path' as const },
  { pattern: /\bdocument\.getElementById\b/, type: 'dom_input' as const },
  { pattern: /\bdocument\.querySelector\b/, type: 'dom_input' as const },
  // Narrow to event-based DOM input reads: `e.target.value`, `event.target.value`.
  // The formerly broad `/\.value\b/` matched any `.value` property (e.g. `result.value`,
  // `node.value` in TypeScript) generating false positives in non-browser code.
  { pattern: /\b(?:event|e)\.(?:target\.)?value\b/, type: 'dom_input' as const },
  // Browser property-based sources (assigned to variables then used in sinks)
  { pattern: /\bdocument\.referrer\b/, type: 'http_header' as const },
  { pattern: /\bdocument\.cookie\b/, type: 'http_cookie' as const },
  { pattern: /\bwindow\.name\b/, type: 'dom_input' as const },
  { pattern: /\bdocument\.URL\b/, type: 'http_path' as const },
  { pattern: /\bdocument\.documentURI\b/, type: 'http_path' as const },
  { pattern: /\blocation\.pathname\b/, type: 'http_path' as const },
  // DOM propagation globals - deprecated/obscure but still exploitable as taint conduits.
  // Writing attacker-controlled data here and reading it back preserves taint (DOMPropagation pattern).
  { pattern: /\bwindow\.status\b/, type: 'dom_input' as const },
  { pattern: /\bdocument\.title\b/, type: 'dom_input' as const },
  { pattern: /\bhistory\.state\b/, type: 'dom_input' as const },
  { pattern: /\blocalStorage\.getItem\b/, type: 'dom_input' as const },
  { pattern: /\bsessionStorage\.getItem\b/, type: 'dom_input' as const },
];

const PYTHON_TAINTED_PATTERNS = [
  { pattern: /\brequest\.args\b/,              type: 'http_param'  as SourceType },
  { pattern: /\brequest\.form\b/,              type: 'http_body'   as SourceType },
  { pattern: /\brequest\.json\b/,              type: 'http_body'   as SourceType },
  { pattern: /\brequest\.data\b/,              type: 'http_body'   as SourceType },
  { pattern: /\brequest\.files?\b/,            type: 'file_input'  as SourceType },
  { pattern: /\brequest\.headers?\b/,          type: 'http_header' as SourceType },
  { pattern: /\brequest\.cookies\b/,           type: 'http_cookie' as SourceType },
  { pattern: /\brequest\.GET\b/,               type: 'http_param'  as SourceType },
  { pattern: /\brequest\.POST\b/,              type: 'http_body'   as SourceType },
  { pattern: /\brequest\.META\b/,              type: 'http_header' as SourceType },
  { pattern: /\brequest\.FILES\b/,             type: 'file_input'  as SourceType },
  { pattern: /\brequest\.query_params\b/,      type: 'http_param'  as SourceType },
  { pattern: /\brequest\.path_params\b/,       type: 'http_param'  as SourceType },
  { pattern: /\brequest\.query_string\b/,      type: 'http_param'  as SourceType },
  { pattern: /\brequest\.get_data\s*\(/,       type: 'http_body'   as SourceType },
  { pattern: /\bget_form_parameter\s*\(/,      type: 'http_body'   as SourceType },
  { pattern: /\bget_query_parameter\s*\(/,     type: 'http_param'  as SourceType },
  { pattern: /\bget_header_value\s*\(/,        type: 'http_header' as SourceType },
  { pattern: /\bget_cookie_value\s*\(/,        type: 'http_cookie' as SourceType },
  // Sprint 72 (#183 residual): `input()` is registered in
  // configs/sources/python.json but was not in the forward-taint regex
  // registry, so `name = input()` was not added to pyTaintedVars. Closes
  // the deferred `getattr(obj, input())()` reflection-invocation shape.
  { pattern: /\binput\s*\(/,                   type: 'io_input'    as SourceType },
];

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface LanguageSourcesResult {
  additionalSources: TaintSource[];
  additionalSinks: TaintSink[];
  /**
   * Language-specific sanitizers (e.g. Bash regex-allowlist guards) emitted
   * alongside sources/sinks. Merged into the sanitizer set in
   * `SinkFilterPass`.
   */
  additionalSanitizers: TaintSanitizer[];
  /**
   * Python forward-taint map: variable name → first tainted line.
   * Used by SinkFilterPass to reduce XPath/XSS false positives.
   */
  pyTaintedVars: Map<string, number>;
  /**
   * Python sanitized-variable set (apostrophe-guard + .replace() sanitizers).
   * Used by SinkFilterPass to suppress sanitized XPath sinks.
   */
  pySanitizedVars: Set<string>;
  /**
   * JavaScript forward-taint map: variable name → first tainted line.
   * Used by SinkFilterPass to suppress spurious XSS sinks.
   */
  jsTaintedVars: Map<string, number>;
}

// ---------------------------------------------------------------------------
// Pass
// ---------------------------------------------------------------------------

export class LanguageSourcesPass implements AnalysisPass<LanguageSourcesResult> {
  readonly name = 'language-sources';
  readonly category = 'security' as const;

  run(ctx: PassContext): LanguageSourcesResult {
    const { graph, code, language } = ctx;
    const { types } = graph.ir;
    const constProp = ctx.getResult<ConstantPropagatorResult>('constant-propagation');

    const additionalSources: TaintSource[] = [];
    const additionalSinks: TaintSink[] = [];
    const additionalSanitizers: TaintSanitizer[] = [];

    // -- Java: getter methods that return tainted constructor fields ----------
    additionalSources.push(...findGetterSources(types, constProp.instanceFieldTaint, code));

    // -- Cross-language: OOP constructor-injected field flow (issue #78) ------
    //
    // Pattern: a constructor assigns a tainted value (HTTP source or a
    // tainted constructor parameter) to a `this.<field>` / `self.<field>`
    // slot. Methods of the same class read the field directly or through a
    // getter / @property. We emit synthetic sources bound to `this.<field>`
    // / `self.<field>` (and to the getter name) at the assignment / getter
    // line, so the variable-name scan in TaintPropagationPass connects them
    // to sinks in other methods of the same class.
    additionalSources.push(...findOopFieldReadSources(types, code, language));

    // -- Java (#78 round 2): static field stores inside the same class -------
    additionalSources.push(...findStaticFieldSources(types, code, language));

    // -- Java (#78 round 2): non-bean setter/getter chains -------------------
    additionalSources.push(...findSetterChainSources(types, code, language));

    // -- JavaScript/TypeScript: assignment sources and DOM XSS sinks ---------
    additionalSources.push(...findJavaScriptAssignmentSources(code, language));

    const jsDOMSinks = findJavaScriptDOMSinks(code, language);
    for (const s of jsDOMSinks) {
      const alreadyExists = additionalSinks.some(x => x.line === s.line && x.cwe === s.cwe);
      if (!alreadyExists) {
        additionalSinks.push({
          type: 'xss',
          cwe: s.cwe,
          line: s.line,
          location: s.location,
          method: s.method,
          confidence: 1.0,
        });
      }
    }

    // -- Python: assignment sources, trust-boundary sinks, return-XSS sinks --
    additionalSources.push(...findPythonAssignmentSources(code, language));

    const pyTaintedVars = language === 'python' ? buildPythonTaintedVars(code) : new Map<string, number>();
    const pySanitizedVars = language === 'python' ? buildPythonSanitizedVars(code, pyTaintedVars) : new Set<string>();

    if (language === 'python' && pyTaintedVars.size > 0) {
      for (const v of findPythonTrustBoundaryViolations(code, pyTaintedVars)) {
        const alreadyExists = additionalSinks.some(s => s.line === v.sinkLine && s.type === 'trust_boundary');
        if (!alreadyExists) {
          additionalSinks.push({
            type: 'trust_boundary',
            cwe: 'CWE-501',
            line: v.sinkLine,
            location: `session write at line ${v.sinkLine}`,
            confidence: 0.85,
          });
        }
      }

      for (const r of findPythonReturnXSSSinks(code, pyTaintedVars)) {
        const alreadyExists = additionalSinks.some(s => s.line === r.sinkLine && s.type === 'xss');
        if (!alreadyExists) {
          additionalSinks.push({
            type: 'xss',
            cwe: 'CWE-79',
            line: r.sinkLine,
            location: `return HTML with user input at line ${r.sinkLine}`,
            confidence: 0.9,
          });
        }
      }

      // Sprint 68 — #183: reflection-invocation sinks for
      //   (a) direct  `getattr(obj, taint)()`  (single-line two-call)
      //   (b) aliased `fn = getattr(obj, taint); ...; fn()` (two-stmt)
      // Conservative: requires the 2nd `getattr` arg to be in pyTaintedVars
      // AND the result to be invoked (gates against the benign data-access
      // shape `value = getattr(obj, name)` or 3-arg `getattr(o, n, default)`).
      for (const r of findPythonReflectionInvocationSinks(code, pyTaintedVars)) {
        const alreadyExists = additionalSinks.some(
          s => s.line === r.sinkLine && s.type === 'code_injection' && s.method === r.method
        );
        if (!alreadyExists) {
          additionalSinks.push({
            type: 'code_injection',
            cwe: 'CWE-94',
            line: r.sinkLine,
            location: `reflection invocation (getattr result called) with tainted attribute name at line ${r.sinkLine}`,
            method: r.method,
            confidence: 0.85,
          });
        }
      }
    }

    const jsTaintedVars = buildJavaScriptTaintedVars(code, language);

    // -- Bash/Shell: taint sources + pattern-based findings --
    if (language === 'bash') {
      additionalSources.push(...findBashTaintSources(code, graph.ir.dfg));
      const bashFindings = findBashPatternFindings(code, graph.ir.meta.file);
      for (const finding of bashFindings) {
        ctx.addFinding(finding);
      }
      additionalSanitizers.push(...findBashRegexAllowlistSanitizers(code));
      additionalSanitizers.push(...findBashRealpathPrefixGuardSanitizers(code));
    }

    // -- Go: safe-handler sanitizer detectors (cognium-dev #102 Sprint 24) --
    if (language === 'go') {
      additionalSanitizers.push(...findGoMapAllowlistGuardSanitizers(code));
      additionalSanitizers.push(...findGoHtmlTemplateImportSanitizers(code));
      // Sprint 78 (#190): Go ECB-mode weak-crypto detection.
      const goMisconfigFindings = findGoPatternFindings(code, graph.ir.meta.file);
      for (const finding of goMisconfigFindings) {
        ctx.addFinding(finding);
      }
      // Sprint 81 (#189): Go xss — fmt.Fprint(f|ln) to http.ResponseWriter.
      for (const finding of findGoXssFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 82 (#189): Go open_redirect — Header().Set("Location", taint).
      for (const finding of findGoLocationHeaderOpenRedirectFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 83 (#189): Go code_injection — plugin.Open / plugin.Lookup.
      for (const finding of findGoPluginOpenCodeInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 84 (#189): Go nosql_injection — *mongo.Collection FindOne / Find
      // / Insert / Update / Delete / Aggregate with bson.M{...tainted}.
      for (const finding of findGoMongoNosqlInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 87 (#189): Go ldap_injection — go-ldap NewSearchRequest with
      // a tainted filter argument (slot 7).
      for (const finding of findGoLdapInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 89 (#189): Go insecure_deserialization — encoding/gob
      // NewDecoder(r.Body).Decode(&v).
      for (const finding of findGoGobDeserializationFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 90 (#189): Go XXE — encoding/xml NewDecoder(r.Body) with
      // Strict=false or custom Entity map.
      for (const finding of findGoXmlDecoderXxeFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
    }

    // -- Python: safe-handler sanitizer detectors (cognium-dev #114 Sprint 31) --
    if (language === 'python') {
      additionalSanitizers.push(...findPythonNetlocAllowlistGuardSanitizers(code));
      additionalSanitizers.push(...findPythonRangeCheckGuardSanitizers(code));
      // Sprint 74 (#216 Pattern B): regex-allowlist wrapper functions,
      // var-aware set-membership xss guard, and defusedxml import-alias
      // recognition.
      additionalSanitizers.push(...findPythonRegexAllowlistWrapperSanitizers(code));
      additionalSanitizers.push(...findPythonSetMembershipXssGuardSanitizers(code));
      additionalSanitizers.push(...findPythonDefusedXmlSanitizers(code));
      // Sprint 77a (#216 Pattern X): Jinja2 Environment(autoescape=...) +
      // .render(...) sanitizer.
      additionalSanitizers.push(...findPythonJinjaAutoescapeSanitizers(code));
      // Sprint 71 (#190): pattern-based misconfig findings for subscript/context
      // assignment shapes (cors-wildcard-origin, xfo-csp-mismatch, tls-verify-
      // disabled) that the language-agnostic detectors miss in Python.
      const pyMisconfigFindings = findPythonPatternFindings(code, graph.ir.meta.file);
      for (const finding of pyMisconfigFindings) {
        ctx.addFinding(finding);
      }
      // Sprint 81 (#189): Python xss — Flask string-concat / f-string returns
      // and Jinja Markup wrap bypass.
      for (const finding of findPythonFlaskStringConcatXssFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      for (const finding of findPythonJinjaMarkupXssFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 82 (#189): Python open_redirect — resp.headers["Location"] = taint.
      for (const finding of findPythonHeadersSubscriptOpenRedirectFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 83 (#189): Python code_injection — code.InteractiveInterpreter
      // / InteractiveConsole / compile_command on Flask request input.
      for (const finding of findPythonInteractiveInterpreterCodeInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 84 (#189): Python nosql_injection — mongoengine `__raw__={"$where":
      // <tainted-string-concat>}` JS-string injection through MongoDB $where.
      for (const finding of findPythonMongoengineWhereNosqlInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 86 (#189): Python format_string — `<tainted> % args` and
      // `<tainted>.format(args)` where the format template comes from
      // an HTTP request extractor.
      for (const finding of findPythonTaintedFormatStringFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 86 (#189): Python crlf / header injection —
      // `response.headers['X-Custom'] = <tainted>` (Flask/Werkzeug).
      for (const finding of findPythonHeaderCrlfInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 90 (#189): Python SSTI — jinja2.Template(<tainted>).render(...).
      for (const finding of findPythonJinjaTemplateSstiFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
    }

    // -- Rust: safe-handler sanitizer detectors (cognium-dev #115 Sprint 31) --
    if (language === 'rust') {
      additionalSanitizers.push(...findRustSetAllowlistGuardSanitizers(code));
      additionalSanitizers.push(...findRustCanonicalizeGuardSanitizers(code));
      // Sprint 77a (#216 Pattern X): argv-form Command::new(literal).arg(...)
      // sanitizer.
      additionalSanitizers.push(...findRustArgvCommandSanitizers(code));
      // Sprint 71 (#190): Rust reqwest builder `danger_accept_invalid_*(true)`
      // is `tls-verify-disabled` — same rule as the Python/JS shapes.
      const rustMisconfigFindings = findRustPatternFindings(code, graph.ir.meta.file);
      for (const finding of rustMisconfigFindings) {
        ctx.addFinding(finding);
      }
      // Sprint 78 (#190): additional Rust misconfig pattern detectors —
      // hardcoded-credential, insecure-cookie (builder chain),
      // jwt-verify-disabled, weak-crypto (raw ECB block ops).
      for (const finding of findRustHardcodedCredentialFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      for (const finding of findRustInsecureCookieFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      for (const finding of findRustJwtVerifyDisabledFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      for (const finding of findRustWeakCryptoEcbFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 82 (#189): Rust open_redirect — append_header(("Location", taint)).
      for (const finding of findRustAppendHeaderTupleOpenRedirectFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 83 (#189): Rust code_injection — evalexpr crate, libloading,
      // mlua/rlua dynamic-load shapes on Actix/Axum request bodies.
      for (const finding of findRustEvalCrateCodeInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 87 (#189): Rust ldap_injection — ldap3 LdapConn::search with
      // tainted filter argument (slot 3).
      for (const finding of findRustLdapInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 87 (#189): Rust log_injection — log crate macros
      // (info!/warn!/error!/debug!/trace!) with tainted format args.
      for (const finding of findRustLogInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
    }

    // -- JavaScript/TypeScript: Sprint 73 (#216 Pattern A + B) — ETE
    // sanitizer-chain recognition (JSON.parse / bcrypt.hash / csv
    // '-prefix) plus wrapper-function recognition for xss / log_injection.
    if (language === 'javascript' || language === 'typescript' || language === 'htmljs') {
      additionalSanitizers.push(...findJsSafeJsonParseSanitizers(code));
      additionalSanitizers.push(...findJsCryptoHashSanitizers(code));
      additionalSanitizers.push(...findJsCsvFormulaPrefixSanitizers(code));
      additionalSanitizers.push(...findJsWrapperFunctionSanitizers(code));
      // Sprint 75 (#216 Pattern D): JS SSRF allow-list guard (var-aware).
      additionalSanitizers.push(...findJsSsrfAllowlistGuardSanitizers(code));
      // Sprint 77b (#216 Pattern X): JS/TS argv-form execFile/spawn and
      // parameterized SQL placeholder sanitizers.
      additionalSanitizers.push(...findJsArgvFormExecSanitizers(code));
      additionalSanitizers.push(...findJsParameterizedSqlSanitizers(code));
      // Sprint 78 (#190): JS misconfig pattern findings — libxmljs noent:true.
      for (const finding of findJsPatternFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 81 (#189): JS/TS xss — Vue v-html directive tied to tainted
      // template binding, and Angular DomSanitizer.bypassSecurityTrust*.
      for (const finding of findJsVueVHtmlXssFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      for (const finding of findTsAngularBypassXssFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 82 (#189): JS/HTML DOM open_redirect — location.href /
      // window.location / location.assign|replace() / <meta>.content shapes
      // sourced from URLSearchParams / location.search|hash.
      for (const finding of findJsDomOpenRedirectFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 83 (#189): JS code_injection — indirect eval forms
      // ((0, eval)(x), globalThis.eval(x), aliased eval).
      for (const finding of findJsIndirectEvalCodeInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 86 (#189): JS format_string — `util.format(<tainted>, ...)`
      // where the format template comes from an HTTP request extractor.
      for (const finding of findJsUtilFormatFormatStringFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 87 (#189): JS/TS ldap_injection — ldapjs/ldapts
      // client.search(base, { filter: <tainted>, ... }).
      for (const finding of findJsLdapInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 89 (#189): JS insecure_deserialization —
      // JSON.parse(req.body) on raw / text bodies.
      for (const finding of findJsJsonParseBodyFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 89 (#189): JS xpath_injection — DOM
      // document.evaluate(<tainted>, ...).
      for (const finding of findJsDomXpathInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 90 (#189): JS template_injection — Handlebars.compile /
      // ejs.render / ejs.compile with a tainted source.
      for (const finding of findJsTemplateInjectionSstiFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
    }

    // -- Java: Sprint 73 (#216 Pattern A) — Jackson readValue / Gson
    // fromJson recognized as ETE terminator (does not affect
    // configured `deserialization` sinks).
    if (language === 'java') {
      additionalSanitizers.push(...findJavaSafeJsonParseSanitizers(code));
      // Sprint 76 (#216 Pattern B): Java inline sanitizer recognition.
      additionalSanitizers.push(
        ...findJavaPathNormalizeStartsWithGuardSanitizers(code),
      );
      additionalSanitizers.push(...findJavaInlineCrlfStripLogSanitizers(code));
      // Sprint 77a (#216 Pattern X): argv-form exec sanitizer.
      additionalSanitizers.push(...findJavaArgvFormExecSanitizers(code));
      // Sprint 78 (#190): Java misconfig pattern findings —
      // jwt-verify-disabled (auth0 JWT.decode bare) +
      // tls-verify-disabled (empty-body X509TrustManager).
      for (const finding of findJavaPatternFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 81 (#189): Java xss — HttpServletResponse.getWriter().{print,
      // println,write} receiver-chain that the configured PrintWriter sink
      // doesn't resolve.
      for (const finding of findJavaResponseWriterXssFindings(code, graph.ir.meta.file)) {
        ctx.addFinding(finding);
      }
      // Sprint 84 (#189): Java nosql_injection — MongoCollection find / insert /
      // update / delete / aggregate with Filters.eq("k", <tainted servlet input>).
      for (const finding of findJavaMongoNosqlInjectionFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
      // Sprint 85 (#189): Java ssrf — `new URL(<tainted>)` →
      // `.openStream()` / `.openConnection()` / `.getContent()` receiver
      // chains (basic_fetch + weak_allowlist variants).
      for (const finding of findJavaUrlOpenStreamSsrfFindings(
        code,
        graph.ir.meta.file,
      )) {
        ctx.addFinding(finding);
      }
    }

    // Sprint 70 (#151): cross-language env-secret → external-network exfiltration.
    // Pattern findings only — no taint flow required (composed-flow shape that
    // the engine misses because the env source and the egress sink are
    // co-located in one file but the taint propagator doesn't classify
    // env-reads as taint sources for this exfil sink).
    if (
      language === 'python' ||
      language === 'javascript' ||
      language === 'typescript' ||
      language === 'go'
    ) {
      const exfilFindings = findExternalSecretExfiltrationFindings(
        code,
        graph.ir.meta.file,
        language
      );
      for (const finding of exfilFindings) {
        ctx.addFinding(finding);
      }
    }

    // Attach trimmed source-line text to each emitted source/sink so consumers
    // (LLM enrichment, SARIF reporters) can render the offending line without
    // re-reading the file.
    attachSourceLineCode(additionalSources, additionalSinks, code);

    return { additionalSources, additionalSinks, additionalSanitizers, pyTaintedVars, pySanitizedVars, jsTaintedVars };
  }
}

// ---------------------------------------------------------------------------
// Helpers (moved verbatim from analyzer.ts)
// ---------------------------------------------------------------------------

import type { FieldTaintInfo } from '../constant-propagation/types.js';

function findGetterSources(
  types: TypeInfo[],
  instanceFieldTaint: Map<string, FieldTaintInfo>,
  _sourceCode: string
): TaintSource[] {
  const sources: TaintSource[] = [];
  if (instanceFieldTaint.size === 0) return sources;

  for (const type of types) {
    for (const method of type.methods) {
      const methodName = method.name;
      let potentialFieldName: string | null = null;
      if (methodName.startsWith('get') && methodName.length > 3) {
        potentialFieldName = methodName.charAt(3).toLowerCase() + methodName.substring(4);
      } else if (methodName.startsWith('is') && methodName.length > 2) {
        potentialFieldName = methodName.charAt(2).toLowerCase() + methodName.substring(3);
      }

      if (method.parameters.length === 0) {
        const fieldsToCheck = potentialFieldName
          ? [potentialFieldName, methodName]
          : [methodName];

        for (const fieldName of fieldsToCheck) {
          const fieldTaint = instanceFieldTaint.get(fieldName);
          if (fieldTaint && fieldTaint.className === type.name) {
            sources.push({
              type: 'constructor_field',
              location: `${type.name}.${methodName}() returns tainted field '${fieldName}' (from constructor param '${fieldTaint.sourceParam}')`,
              severity: 'high',
              line: method.start_line,
              confidence: 0.95,
            });
            break;
          }
        }
      }

      for (const [fieldName, fieldTaint] of instanceFieldTaint) {
        if (fieldTaint.className === type.name) {
          if (methodName === fieldName && method.parameters.length === 0) {
            const alreadyAdded = sources.some(s => s.location.includes(`${type.name}.${methodName}()`));
            if (!alreadyAdded) {
              sources.push({
                type: 'constructor_field',
                location: `${type.name}.${methodName}() returns tainted field '${fieldName}' (from constructor param '${fieldTaint.sourceParam}')`,
                severity: 'high',
                line: method.start_line,
                confidence: 0.95,
              });
            }
          }
        }
      }
    }
  }

  return sources;
}

/**
 * Issue #78 — OOP constructor-injected field flow (Java + Python).
 *
 * For each class, identify fields that the constructor assigns from either
 * (a) a constructor parameter, or (b) an HTTP source expression. Then emit
 * synthetic sources keyed on the field-access expression itself
 * (`this.<field>`, `self.<field>`) and — for single-return getters /
 * properties — on the getter name. Downstream `TaintPropagationPass`
 * connects these to sinks in OTHER methods of the same class via its
 * variable-name scan.
 *
 * Scoped to Java + Python because those are the languages where the
 * constructor-field flow is the dominant OOP taint pattern. JS uses
 * `this.<field>` too, but DOM/HTTP sources there are already covered by
 * `findJavaScriptAssignmentSources`.
 */
function findOopFieldReadSources(
  types: TypeInfo[],
  sourceCode: string,
  language: string,
): TaintSource[] {
  if (
    language !== 'java' &&
    language !== 'python' &&
    language !== 'javascript' &&
    language !== 'typescript'
  ) return [];
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');
  const isPython = language === 'python';
  const isJs = language === 'javascript' || language === 'typescript';
  const isJava = language === 'java';
  const SELF = isPython ? 'self' : 'this';

  // Common Java HTTP-source receivers / methods. Conservative: matches
  // `request.getParameter` style calls but not arbitrary `foo.getName()`.
  const javaHttpPattern = /\b(?:req|request|httpRequest|servletRequest|httpServletRequest)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getPathInfo|getRequestURI|getRequestURL|getInputStream|getReader)\b/;

  // Match `this.<field> = <rhs>` or `self.<field> = <rhs>`. Anchored variant
  // (Python/Java line-per-stmt convention) AND a global variant for JS/TS,
  // whose constructors commonly inline assignments on the same line as the
  // opening brace:  `constructor(name) { this.name = name; }`.
  const fieldAssignRe = new RegExp(`^\\s*${SELF}\\.([A-Za-z_]\\w*)\\s*=\\s*(.+?)(?:;\\s*)?$`);
  const fieldAssignReG = new RegExp(`${SELF}\\.([A-Za-z_]\\w*)\\s*=\\s*([^;}\\n]+)`, 'g');
  const commentPrefix = isPython ? '#' : '//';

  for (const type of types) {
    if (type.kind !== 'class') continue;
    if (type.name === '<module>') continue;

    // Locate constructor.
    //   - Python: __init__
    //   - JavaScript/TypeScript: literal method name `constructor`
    //   - Java: method whose name === class name
    let ctor: typeof type.methods[number] | undefined;
    for (const m of type.methods) {
      if (isPython) {
        if (m.name === '__init__') { ctor = m; break; }
      } else if (isJs) {
        if (m.name === 'constructor') { ctor = m; break; }
      } else if (isJava) {
        if (m.name === type.name) { ctor = m; break; }
      }
    }
    if (!ctor) continue;

    // Constructor parameter name set (skip the implicit `self` / `this`).
    const paramNames = new Set<string>();
    for (const p of ctor.parameters) {
      if (p.name === 'self' || p.name === 'this') continue;
      paramNames.add(p.name);
    }

    // Field → { assignment line, derived source type } map.
    const fieldTaint = new Map<string, { line: number; type: SourceType }>();
    const ctorStart = ctor.start_line;
    const ctorEnd = ctor.end_line;
    for (let i = ctorStart - 1; i < Math.min(ctorEnd, lines.length); i++) {
      const line = lines[i] ?? '';
      if (line.trim().startsWith(commentPrefix)) continue;

      // Collect (fieldName, rhs) pairs from this line. Anchored regex
      // catches one-stmt-per-line shapes (Python/Java); global regex
      // additionally catches inline assignments in JS/TS constructors.
      const pairs: Array<{ field: string; rhs: string }> = [];
      const anchored = line.match(fieldAssignRe);
      if (anchored) pairs.push({ field: anchored[1], rhs: anchored[2].trim().replace(/;\s*$/, '') });
      if (isJs) {
        for (const m of line.matchAll(fieldAssignReG)) {
          const field = m[1];
          const rhs = m[2].trim().replace(/;\s*$/, '');
          if (!pairs.some(p => p.field === field)) pairs.push({ field, rhs });
        }
      }
      if (pairs.length === 0) continue;

      for (const { field: fieldName, rhs } of pairs) {
        let sourceType: SourceType | null = null;
        if (paramNames.has(rhs)) {
          sourceType = 'interprocedural_param';
        } else if (isJava && javaHttpPattern.test(rhs)) {
          sourceType = 'http_param';
        } else if (isPython) {
          for (const { pattern, type } of PYTHON_TAINTED_PATTERNS) {
            if (pattern.test(rhs)) { sourceType = type; break; }
          }
        } else if (isJs) {
          for (const { pattern, type } of JS_TAINTED_PATTERNS) {
            if (pattern.test(rhs)) { sourceType = type; break; }
          }
        }
        if (sourceType) {
          fieldTaint.set(fieldName, { line: i + 1, type: sourceType });
        }
      }
    }

    if (fieldTaint.size === 0) continue;

    // Emit one source per tainted field, bound to `(self|this).<field>` so
    // any method whose body references that expression on a sink line is
    // matched by the variable-name scan in TaintPropagationPass.
    for (const [fieldName, info] of fieldTaint) {
      sources.push({
        type: info.type,
        location: `${type.name}.${SELF}.${fieldName} (constructor-injected field, #78)`,
        severity: 'high',
        line: info.line,
        confidence: 0.85,
        variable: `${SELF}.${fieldName}`,
      });
    }

    // Detect getters / @property accessors whose body is a single
    // `return (this|self).<taintedField>` and emit a source bound to the
    // call-shape used by callers.
    for (const m of type.methods) {
      if (m === ctor) continue;
      // A getter takes only the implicit receiver (Python) or no params (Java).
      const nonSelfParams = m.parameters.filter(p => p.name !== 'self' && p.name !== 'this');
      if (nonSelfParams.length !== 0) continue;

      const mStart = m.start_line;
      const mEnd = m.end_line;
      let returnedField: string | null = null;
      let returnStatementCount = 0;
      // Match `return (this|self).<field>` anywhere on a line — handles
      // both single-line Java getters (`public String getName() { return this.name; }`)
      // and multi-line getters / @property bodies.
      const returnRe = new RegExp(`\\breturn\\s+${SELF}\\.([A-Za-z_]\\w*)\\s*[;}]?`);
      // cognium-dev #105 (Sprint 21 B.1) — recognise allowlist-style
      // guards inside the getter body. When the getter contains an
      // `if <ref> (not in|in) <UPPER_CONST>:` membership check followed
      // within ≤2 lines by `raise` / `abort` / `return None` / `return ""`,
      // treat the getter as a sanitizer rather than a taint source: the
      // unmatched-host branch raises, so the value that flows past the
      // guard is constrained to the allowlist. Conventional UPPER_SNAKE
      // constant naming distinguishes a true allowlist from an incidental
      // cache lookup (e.g. `if x in self.CACHE: return self.url` — the
      // GUARD.1-noisy fixture).
      // Python:  `if [self.]url not in self.ALLOWED:` + `raise`/`abort`/`return None`
      // Java/JS: `if (!ALLOWED.contains(x))` / `!ALLOWED.includes(x)`/`!ALLOWED.has(x)`
      //          + `throw`/`return null`
      const guardRePy = /\bif\s+[\w.]+\s+(?:not\s+)?in\s+(?:self\.)?[A-Z_][A-Z0-9_]*\s*:/;
      const guardThrowRePy = /^\s*(?:raise\b|abort\b|return\s+(?:None\b|''|""|\)?$))/;
      const guardReJv = /\bif\s*\(\s*!\s*(?:this\.)?[A-Z_][A-Z0-9_]*\s*\.\s*(?:contains|includes|has|matches)\s*\(/;
      const guardThrowReJv = /^\s*(?:throw\b|return\s+null\b)/;
      const guardRe = isPython ? guardRePy : guardReJv;
      const guardThrowRe = isPython ? guardThrowRePy : guardThrowReJv;
      let hasAllowlistGuard = false;

      for (let i = mStart - 1; i < Math.min(mEnd, lines.length); i++) {
        const raw = lines[i] ?? '';
        const trimmed = raw.trim();
        if (!trimmed) continue;
        if (trimmed.startsWith(commentPrefix)) continue;
        const rm = trimmed.match(returnRe);
        if (rm) {
          returnedField = rm[1];
          returnStatementCount++;
        } else if (/\breturn\b/.test(trimmed)) {
          // Body contains a non-matching return → not a simple getter.
          returnStatementCount = 99;
          break;
        }
        // Allowlist guard detection — look ahead ≤2 lines for the throw/raise.
        if (guardRe.test(trimmed)) {
          for (let j = i + 1; j < Math.min(i + 4, mEnd, lines.length); j++) {
            const next = (lines[j] ?? '');
            if (guardThrowRe.test(next)) { hasAllowlistGuard = true; break; }
          }
        }
      }
      if (returnStatementCount === 1 && returnedField && fieldTaint.has(returnedField) && !hasAllowlistGuard) {
        const fieldInfo = fieldTaint.get(returnedField)!;
        // Java: caller writes `getName()` / `this.getName()` / `obj.getName()`.
        //   → match `\bgetName\b`.
        // Python @property: caller writes `self.target` / `obj.target`.
        //   → match `\bself\.target\b` (paren-less access).
        const getterVar = isPython ? `${SELF}.${m.name}` : m.name;
        sources.push({
          type: fieldInfo.type,
          location: `${type.name}.${m.name} returns tainted field '${returnedField}' (#78)`,
          severity: 'high',
          line: m.start_line,
          confidence: 0.85,
          variable: getterVar,
        });
      }
    }
  }

  return sources;
}

/**
 * Issue #78 round 2 — Static field stores (intra-class, Java).
 *
 * Pattern:
 *   class Config {
 *     private static String dbHost;
 *     public static void init(HttpServletRequest req) {
 *       dbHost = req.getParameter("h");   // taint flows in
 *     }
 *     public static Process query() {
 *       return Runtime.getRuntime().exec(dbHost);  // tainted use
 *     }
 *   }
 *
 * For each Java class, walk static-method bodies for assignments to a
 * static field (either bare `<field>` or `<ClassName>.<field>`). When the
 * RHS matches a known HTTP source receiver expression, emit a synthetic
 * source with `variable: '<field>'` (and `'<ClassName>.<field>'` for
 * qualified reads). The variable-name scan in `TaintPropagationPass`
 * then matches sink expressions in sibling methods that reference the
 * field by its bare name.
 *
 * Confidence 0.85 — same band as the constructor-injected field path.
 * Java only (Python `staticmethod` patterns are handled separately by
 * `findPythonAssignmentSources`).
 */
function findStaticFieldSources(
  types: TypeInfo[],
  sourceCode: string,
  language: string,
): TaintSource[] {
  if (language !== 'java') return [];
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');

  const javaHttpPattern = /\b(?:req|request|httpRequest|servletRequest|httpServletRequest)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getPathInfo|getRequestURI|getRequestURL|getInputStream|getReader)\b/;

  for (const type of types) {
    if (type.kind !== 'class') continue;
    if (type.name === '<module>') continue;

    const staticFields = new Set<string>();
    for (const f of type.fields) {
      if (f.modifiers.includes('static')) staticFields.add(f.name);
    }
    if (staticFields.size === 0) continue;

    const qualifiedAssignRe = new RegExp(
      `^\\s*${type.name}\\.([A-Za-z_]\\w*)\\s*=\\s*(.+?)(?:;\\s*)?$`,
    );
    const bareAssignRe = /^\s*([A-Za-z_]\w*)\s*=\s*(.+?)(?:;\s*)?$/;

    for (const m of type.methods) {
      if (!m.modifiers.includes('static')) continue;
      const mStart = m.start_line;
      const mEnd = m.end_line;

      for (let i = mStart - 1; i < Math.min(mEnd, lines.length); i++) {
        const line = lines[i] ?? '';
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//')) continue;

        let fieldName: string | null = null;
        let rhs: string | null = null;
        const qm = trimmed.match(qualifiedAssignRe);
        if (qm) {
          fieldName = qm[1];
          rhs = qm[2];
        } else {
          const bm = trimmed.match(bareAssignRe);
          if (bm) {
            fieldName = bm[1];
            rhs = bm[2];
          }
        }
        if (!fieldName || !rhs) continue;
        if (!staticFields.has(fieldName)) continue;
        rhs = rhs.trim().replace(/;\s*$/, '');

        if (!javaHttpPattern.test(rhs)) continue;

        sources.push({
          type: 'http_param',
          location: `${type.name}.${fieldName} static field set in ${m.name}() — #78 round 2`,
          severity: 'high',
          line: i + 1,
          confidence: 0.85,
          variable: fieldName,
        });
        sources.push({
          type: 'http_param',
          location: `${type.name}.${fieldName} static field (qualified read alias) — #78 round 2`,
          severity: 'high',
          line: i + 1,
          confidence: 0.85,
          variable: `${type.name}.${fieldName}`,
        });
      }
    }
  }

  return sources;
}

/**
 * Issue #78 round 2 — Non-bean setter/getter chains (Java).
 *
 * Pattern:
 *   class User {
 *     private String cred;
 *     public void setCred(String c) { this.cred = c; }
 *     public String getCred() { return this.cred; }
 *   }
 *   // caller:
 *   User u = new User();
 *   u.setCred(req.getParameter("c"));
 *   stmt.executeQuery("... " + u.getCred() + " ...");
 *
 * Strategy: for each class, build a `field -> { setter, getter }` map.
 * A setter is a 1-param method whose only body statement is
 * `this.<field> = <param>;`. A getter is a 0-param method whose only
 * body statement is `return this.<field>;`. Then walk the whole source
 * for setter call sites whose argument matches a known HTTP source —
 * emit a synthetic source on the setter call line bound to the *getter*
 * method name, so the variable-name scan in `TaintPropagationPass`
 * matches `\bgetX\b` in any downstream sink expression.
 *
 * Confidence 0.75 — slightly lower than the direct constructor-field
 * path because the call ordering is heuristic.
 */
function findSetterChainSources(
  types: TypeInfo[],
  sourceCode: string,
  language: string,
): TaintSource[] {
  if (language !== 'java') return [];
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');

  const javaHttpPattern = /\b(?:req|request|httpRequest|servletRequest|httpServletRequest)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getPathInfo|getRequestURI|getRequestURL|getInputStream|getReader)\b/;

  for (const type of types) {
    if (type.kind !== 'class') continue;
    if (type.name === '<module>') continue;

    // Build setter/getter pairs by inspecting per-method bodies.
    const pairs = new Map<string, { setter?: string; getter?: string }>();
    const setterRe = /this\.([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;?/;
    const getterRe = /return\s+this\.([A-Za-z_]\w*)\s*;?/;

    for (const m of type.methods) {
      if (m.name === type.name) continue; // skip constructor
      const mStart = m.start_line;
      const mEnd = m.end_line;

      // Join the method declaration + body into one string, then isolate the
      // content between the first `{` and the matching last `}`. Handles
      // both single-line methods (`void setX(String x){ this.x = x; }`) and
      // multi-line bodies.
      const fullBody = lines.slice(mStart - 1, Math.min(mEnd, lines.length)).join('\n');
      const open = fullBody.indexOf('{');
      const close = fullBody.lastIndexOf('}');
      if (open < 0 || close < 0 || close <= open) continue;
      const inner = fullBody
        .slice(open + 1, close)
        .replace(/\/\/[^\n]*/g, '') // strip line comments
        .trim();
      if (!inner) continue;

      // Setter?
      const sm = inner.match(setterRe);
      if (sm && m.parameters.length === 1 && sm[2] === m.parameters[0].name) {
        // Reject if there's *another* statement beyond the matched one.
        const remainder = inner.replace(sm[0], '').trim();
        if (!remainder) {
          const entry = pairs.get(sm[1]) ?? {};
          entry.setter = m.name;
          pairs.set(sm[1], entry);
          continue;
        }
      }
      // Getter?
      const gm = inner.match(getterRe);
      if (gm && m.parameters.length === 0) {
        const remainder = inner.replace(gm[0], '').trim();
        if (!remainder) {
          const entry = pairs.get(gm[1]) ?? {};
          entry.getter = m.name;
          pairs.set(gm[1], entry);
        }
      }
    }

    // For each (field, setter, getter) triple, search the whole source
    // for `<recv>.<setter>(<arg>)` where <arg> matches an HTTP source.
    for (const [, { setter, getter }] of pairs) {
      if (!setter || !getter) continue;
      const setterCallRe = new RegExp(
        `\\b([A-Za-z_]\\w*)\\.${setter}\\s*\\(\\s*([^)]+?)\\s*\\)\\s*;?`,
      );
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//')) continue;
        const cm = trimmed.match(setterCallRe);
        if (!cm) continue;
        const arg = cm[2];
        if (!javaHttpPattern.test(arg)) continue;
        sources.push({
          type: 'http_param',
          location: `${type.name}.${setter}(tainted) → ${type.name}.${getter}() chain — #78 round 2`,
          severity: 'high',
          line: i + 1,
          confidence: 0.75,
          variable: getter,
        });
      }
    }
  }

  return sources;
}

function findJavaScriptAssignmentSources(sourceCode: string, language: string): TaintSource[] {
  if (!['javascript', 'typescript'].includes(language)) return [];
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    const lineNumber = lineNum + 1;
    const assignmentMatch = line.match(/(?:(?:var|let|const)\s+)?(\w+)\s*=\s*(.+)/);
    if (!assignmentMatch) continue;
    const [, varName, rhs] = assignmentMatch;

    for (const { pattern, type } of JS_TAINTED_PATTERNS) {
      if (pattern.test(rhs)) {
        const alreadyExists = sources.some(s => s.line === lineNumber && s.type === type);
        if (!alreadyExists) {
          sources.push({
            type,
            location: `${varName} = ${rhs.trim().substring(0, 50)}${rhs.length > 50 ? '...' : ''}`,
            severity: 'high',
            line: lineNumber,
            confidence: 1.0,
            variable: varName,
          });
        }
        break;
      }
    }
  }

  return sources;
}

function findPythonAssignmentSources(sourceCode: string, language: string): TaintSource[] {
  if (language !== 'python') return [];
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    const lineNumber = lineNum + 1;
    if (line.trimStart().startsWith('#')) continue;

    const assignmentMatch = line.match(/^(\s*\w[\w.]*)\s*(?::\s*\w[\w\[\], .]*)?\s*=\s*(.+)/);
    if (!assignmentMatch) continue;
    const rhs = assignmentMatch[2];

    for (const { pattern, type } of PYTHON_TAINTED_PATTERNS) {
      if (pattern.test(rhs)) {
        const varMatch = line.match(/^\s*(\w+)\s*/);
        const varName = varMatch ? varMatch[1] : 'unknown';
        const alreadyExists = sources.some(s => s.line === lineNumber && s.type === type);
        if (!alreadyExists) {
          sources.push({
            type,
            location: `${varName} = ${rhs.trim().substring(0, 50)}${rhs.length > 50 ? '...' : ''}`,
            severity: 'high',
            line: lineNumber,
            confidence: 0.95,
            variable: varName,
          });
        }
        break;
      }
    }
  }

  return sources;
}

export function buildPythonTaintedVars(sourceCode: string): Map<string, number> {
  const tainted = new Map<string, number>();
  const containerTainted = new Map<string, number>();
  const lines = sourceCode.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('#')) continue;

    const subscriptAssign = line.match(/^\s*([\p{L}\p{N}_]+)\[(['"])([^'"]+)\2\]\s*=\s*(.+)$/u);
    if (subscriptAssign) {
      const [, container, , key, rhs2] = subscriptAssign;
      const isTaintedRhs = [...tainted.keys()].some(v => new RegExp(`(?<![\\p{L}\\p{N}_])${v}(?![\\p{L}\\p{N}_])`, 'u').test(rhs2));
      if (isTaintedRhs) containerTainted.set(`${container}['${key}']`, i + 1);
      continue;
    }

    const setCallMatch = line.match(/^\s*([\p{L}\p{N}_]+)\.set\s*\(\s*(['"])([^'"]+)\2\s*,\s*(['"])([^'"]+)\4\s*,\s*(.+?)\s*\)$/u);
    if (setCallMatch) {
      const [, obj, , section, , key, rhs2] = setCallMatch;
      const isTaintedRhs = [...tainted.keys()].some(v => new RegExp(`(?<![\\p{L}\\p{N}_])${v}(?![\\p{L}\\p{N}_])`, 'u').test(rhs2));
      if (isTaintedRhs) containerTainted.set(`${obj}['${section}']['${key}']`, i + 1);
      continue;
    }

    // Mutating container methods that taint the receiver (#20):
    //   lst.append(taintedVar) / lst.extend(taintedVar) / lst.insert(i, taintedVar) /
    //   set.add(taintedVar) / queue.put(taintedVar)
    // Mark the receiver as tainted so subsequent reads (`lst[0]`, `lst.pop()`,
    // bare `lst` in a list literal, etc.) propagate taint via the standard
    // word-boundary scan below.
    const containerAppendMatch = line.match(/^\s*([\p{L}\p{N}_]+)\.(append|extend|insert|add|push|put|appendleft)\s*\(\s*(.+?)\s*\)\s*$/u);
    if (containerAppendMatch) {
      const [, receiver, , argExpr] = containerAppendMatch;
      const argIsTainted = [...tainted.keys()].some(v => new RegExp(`(?<![\\p{L}\\p{N}_])${v}(?![\\p{L}\\p{N}_])`, 'u').test(argExpr));
      const argIsDirectSource = PYTHON_TAINTED_PATTERNS.some(p => p.pattern.test(argExpr));
      if (argIsTainted || argIsDirectSource) tainted.set(receiver, tainted.get(receiver) ?? (i + 1));
      continue;
    }

    const augAssign = line.match(/^\s*([\p{L}\p{N}_]+)\s*\+=\s*(.+)$/u);
    if (augAssign) {
      const [, augLhs, augRhs] = augAssign;
      const rhsTainted = [...tainted.keys()].some(v => new RegExp(`(?<![\\p{L}\\p{N}_])${v}(?![\\p{L}\\p{N}_])`, 'u').test(augRhs));
      if (rhsTainted || tainted.has(augLhs)) tainted.set(augLhs, tainted.get(augLhs) ?? (i + 1));
      continue;
    }

    const forLoopMatch = line.match(/^\s*for\s+([\p{L}\p{N}_]+)\s+in\s+(.+?)(?:\s*:\s*)?$/u);
    if (forLoopMatch) {
      const [, iterVar, iterExpr] = forLoopMatch;
      const isDirectSource = PYTHON_TAINTED_PATTERNS.some(p => p.pattern.test(iterExpr));
      const isPropagated = [...tainted.keys()].some(v => new RegExp(`(?<![\\p{L}\\p{N}_])${v}(?![\\p{L}\\p{N}_])`, 'u').test(iterExpr));
      if (isDirectSource || isPropagated) tainted.set(iterVar, i + 1);
      continue;
    }

    const assignMatch = line.match(/^\s*([\p{L}\p{N}_]+)\s*=\s*(.+)$/u);
    if (!assignMatch) continue;
    const [, lhs, rhs] = assignMatch;

    const isDirectSource = PYTHON_TAINTED_PATTERNS.some(p => p.pattern.test(rhs));
    let propagatedFrom: string | undefined;

    const dictAccessMatch = rhs.trim().match(/^([\p{L}\p{N}_]+)\[(['"])([^'"]+)\2\]$/u);
    if (dictAccessMatch) {
      const [, container, , key] = dictAccessMatch;
      if (containerTainted.has(`${container}['${key}']`)) propagatedFrom = `${container}['${key}']`;
    }

    if (!propagatedFrom) {
      const confGetMatch = rhs.trim().match(/^([\p{L}\p{N}_]+)\.get\s*\(\s*(['"])([^'"]+)\2\s*,\s*(['"])([^'"]+)\4\s*\)$/u);
      if (confGetMatch) {
        const [, obj, , section, , key] = confGetMatch;
        if (containerTainted.has(`${obj}['${section}']['${key}']`)) propagatedFrom = `${obj}['${section}']['${key}']`;
      }
    }

    if (!propagatedFrom) {
      const isSafeEnvRead = /\bos\.environ\.get\s*\(/.test(rhs) || /\bos\.getenv\s*\(/.test(rhs);
      if (!isSafeEnvRead) propagatedFrom = [...tainted.keys()].find(v => new RegExp(`(?<![\\p{L}\\p{N}_])${v}(?![\\p{L}\\p{N}_])`, 'u').test(rhs));
    }

    if (isDirectSource) {
      tainted.set(lhs, i + 1);
    } else if (propagatedFrom !== undefined) {
      tainted.set(lhs, i + 1);
    } else if (tainted.has(lhs)) {
      const prevNonBlank = lines.slice(0, i).reverse().find(l => l.trim() && !l.trimStart().startsWith('#'));
      const isNullGuard = prevNonBlank !== undefined && (
        new RegExp(`^\\s*if\\s+not\\s+${lhs}\\s*:`).test(prevNonBlank) ||
        new RegExp(`^\\s*if\\s+${lhs}\\s+is\\s+None\\s*:`).test(prevNonBlank)
      );
      if (!isNullGuard) tainted.delete(lhs);
    }
  }

  return tainted;
}

export function buildPythonSanitizedVars(sourceCode: string, pyTaintedVars: Map<string, number>): Set<string> {
  const sanitized = new Set<string>();
  const lines = sourceCode.split('\n');

  // Apostrophe-guard: if "'" in var: return/raise/abort/...
  for (let i = 0; i < lines.length - 1; i++) {
    const m = lines[i].match(/^\s*if\s+(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s+in\s+(\w+)\s*:/);
    if (!m) continue;
    const ifIndent = (lines[i].match(/^(\s*)/) ?? ['', ''])[1].length;
    let foundExit = false;
    for (let j = i + 1; j <= Math.min(i + 5, lines.length - 1); j++) {
      const jLine = lines[j] ?? '';
      if (!jLine.trim()) continue;
      const jIndent = (jLine.match(/^(\s*)/) ?? ['', ''])[1].length;
      if (jIndent <= ifIndent) break;
      if (/^(return|raise|abort|continue|break)\b/.test(jLine.trim())) { foundExit = true; break; }
    }
    if (foundExit) sanitized.add(m[1]);
  }

  // Propagate sanitization through assignments: if bar is sanitized and query = f"...{bar}...", query is also sanitized
  for (const line of lines) {
    const am = line.match(/^\s*(\w+)\s*=\s*(.+)$/);
    if (!am) continue;
    const [, lhs, rhs] = am;
    if ([...sanitized].some(v => new RegExp(`\\b${v}\\b`).test(rhs))) sanitized.add(lhs);
  }

  // Inline .replace() sanitizer: query = f"...{bar.replace('\'', '&apos;')}..."
  for (const line of lines) {
    const am = line.match(/^\s*(\w+)\s*=\s*(.+)$/);
    if (!am) continue;
    const [, lhs, rhs] = am;
    const hasReplaceOnTainted = [...pyTaintedVars.keys()].some(v =>
      new RegExp(`\\b${v}\\.replace\\s*\\(`).test(rhs)
    );
    if (hasReplaceOnTainted) sanitized.add(lhs);
  }

  return sanitized;
}

export function findPythonTrustBoundaryViolations(
  sourceCode: string,
  taintedVars: Map<string, number>
): Array<{ sourceLine: number; sinkLine: number }> {
  if (taintedVars.size === 0) return [];
  const violations: Array<{ sourceLine: number; sinkLine: number }> = [];
  const lines = sourceCode.split('\n');
  const SESSION_WRITE = /(?:flask\.)?session\[([^\]]+)\]\s*=\s*(.+)$/;
  const taintedKeys = [...taintedVars.keys()];
  const earliestSourceLine = Math.min(...[...taintedVars.values()]);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('#')) continue;
    const m = line.match(SESSION_WRITE);
    if (!m) continue;
    const [, keyExpr, valueExpr] = m;
    const keyTainted   = taintedKeys.some(v => new RegExp(`\\b${v}\\b`).test(keyExpr));
    const valueTainted = taintedKeys.some(v => new RegExp(`\\b${v}\\b`).test(valueExpr));
    if (keyTainted || valueTainted) violations.push({ sourceLine: earliestSourceLine, sinkLine: i + 1 });
  }

  return violations;
}

// #147 — Jinja2 safe render-context. Mirror of the matcher-layer gate in
// taint-matcher.ts (isSafeJinjaRenderCall). When the template SOURCE is
// a string literal, Jinja2 auto-escapes context values by default so the
// `return render_template_string("lit", **ctx)` /
// `return Template("lit").render(**ctx)` / bare `return Template("lit")`
// shapes are XSS-safe even if `ctx` references tainted vars. Tainted
// template-source variants (concat / identifier / call result / f-string)
// keep the sink — conservative-bias by literal-only match.
const JINJA_LITERAL_ARG_RE_FRAG = `(?:"[^"\\\\]*"|'[^'\\\\]*')`;
const JINJA_SAFE_RTS_RE = new RegExp(
  `^(?:flask\\.|jinja2\\.)?render_template_string\\s*\\(\\s*${JINJA_LITERAL_ARG_RE_FRAG}\\s*[,)]`
);
const JINJA_SAFE_TEMPLATE_RE = new RegExp(
  `^(?:jinja2\\.)?Template\\s*\\(\\s*${JINJA_LITERAL_ARG_RE_FRAG}\\s*\\)(?:\\s*\\.render\\s*\\(|\\s*$)`
);

function isSafeJinjaReturnExpr(expr: string): boolean {
  const trimmed = expr.trim();
  return JINJA_SAFE_RTS_RE.test(trimmed) || JINJA_SAFE_TEMPLATE_RE.test(trimmed);
}

function findPythonReturnXSSSinks(
  sourceCode: string,
  taintedVars: Map<string, number>
): Array<{ sinkLine: number }> {
  if (taintedVars.size === 0) return [];
  const sinks: Array<{ sinkLine: number }> = [];
  const lines = sourceCode.split('\n');
  const taintedKeys = [...taintedVars.keys()];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('#')) continue;
    const returnMatch = line.match(/^\s*(?:return|yield)\s+(.+)$/);
    if (!returnMatch) continue;
    const expr = returnMatch[1];
    const hasTaintedVar = taintedKeys.some(v => new RegExp(`\\b${v}\\b`).test(expr));
    if (!hasTaintedVar) continue;
    const looksLikeHTML = expr.includes('<') || /['"]\s*\+/.test(expr) || /\+\s*['"]/.test(expr) || /f['"][^'"]*\{/.test(expr);
    if (!looksLikeHTML) continue;
    // #147 — Jinja2 safe render-context: skip safe literal-template shapes.
    if (isSafeJinjaReturnExpr(expr)) continue;
    sinks.push({ sinkLine: i + 1 });
  }

  return sinks;
}

/**
 * Sprint 68 — #183: Python `getattr(obj, taint)()` reflection invocation.
 *
 * Detects two shapes that arrive at an attribute look-up by tainted name
 * and then invoke the result as a callable:
 *
 *   1. DIRECT:  `... getattr(obj, name)(...) ...`        (single-line two-call)
 *   2. ALIASED: `fn = getattr(obj, name)` then later `fn(...)` (two-stmt)
 *
 * `name` must be in `taintedVars` (i.e. flowed from a known Python source).
 * 3-arg `getattr(obj, name, default)` is excluded — the default-value form
 * is the idiomatic Python "safe attribute read" pattern and almost always
 * indicates the caller treats the result as a value, not a callable.
 *
 * Sink placement:
 *   - DIRECT:  sink at the line containing both the `getattr` call and the
 *     trailing `(...)`. The engine's flow logic connects via the `name`
 *     argument on that call site.
 *   - ALIASED: sink at the BIND line (where `getattr(obj, name)` actually
 *     references `name` as a call argument). Required because the
 *     downstream invocation line (`fn()`) has zero args, and the engine's
 *     `flows.push` path keys off tainted call arguments, not callees. The
 *     aliased branch is still gated on detecting the subsequent invocation,
 *     so a bare `value = getattr(obj, name)` with no later call does NOT
 *     fire.
 */
function findPythonReflectionInvocationSinks(
  sourceCode: string,
  taintedVars: Map<string, number>
): Array<{ sinkLine: number; method: string }> {
  if (taintedVars.size === 0) return [];
  const sinks: Array<{ sinkLine: number; method: string }> = [];
  const lines = sourceCode.split('\n');

  // 2-arg only: reject `getattr(obj, name, default)`. The 2nd group MUST
  // be a bare identifier (so we can check membership in taintedVars).
  const directRe =
    /\bgetattr\s*\(\s*[^,()]+\s*,\s*([A-Za-z_][\w]*)\s*\)\s*\(/;
  // Aliased binding: `alias = getattr(obj, name)` with strictly 2 args.
  const bindRe =
    /^\s*([A-Za-z_][\w]*)\s*=\s*getattr\s*\(\s*[^,()]+\s*,\s*([A-Za-z_][\w]*)\s*\)\s*$/;

  type Alias = { name: string; bindLine: number };
  const aliases: Alias[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('#')) continue;

    const dm = line.match(directRe);
    if (dm && taintedVars.has(dm[1])) {
      sinks.push({ sinkLine: i + 1, method: 'getattr' });
      continue;
    }

    const bm = line.match(bindRe);
    if (bm && taintedVars.has(bm[2])) {
      aliases.push({ name: bm[1], bindLine: i + 1 });
    }
  }

  if (aliases.length === 0) return sinks;

  // Second pass: for each alias, look for an invocation `<alias>(...)` on a
  // later line. If found, emit the sink at the BIND line (see header note).
  const firedBindLines = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('#')) continue;
    const lineNum = i + 1;
    for (const a of aliases) {
      if (lineNum <= a.bindLine) continue;
      if (firedBindLines.has(a.bindLine)) continue;
      // Plain invocation: `<alias>(...)`. Reject method-style `o.alias(...)`.
      const invokeRe = new RegExp(`(?<![\\w.])${a.name}\\s*\\(`);
      if (invokeRe.test(line)) {
        sinks.push({ sinkLine: a.bindLine, method: 'getattr' });
        firedBindLines.add(a.bindLine);
      }
    }
  }

  return sinks;
}

function findJavaScriptDOMSinks(sourceCode: string, language: string): Array<{
  type: string; cwe: string; severity: string; line: number; location: string; method?: string;
}> {
  if (!['javascript', 'typescript'].includes(language)) return [];
  const sinks: Array<{ type: string; cwe: string; severity: string; line: number; location: string; method?: string }> = [];
  const lines = sourceCode.split('\n');

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    const lineNumber = lineNum + 1;
    for (const { pattern, type, cwe, severity } of JS_DOM_XSS_SINKS) {
      if (pattern.test(line)) {
        let method = 'innerHTML';
        if (line.includes('.outerHTML')) method = 'outerHTML';
        else if (line.includes('document.write(')) method = 'document.write';
        else if (line.includes('document.writeln(')) method = 'document.writeln';
        else if (line.includes('.insertAdjacentHTML')) method = 'insertAdjacentHTML';
        else if (line.includes('.src')) method = 'src';
        else if (line.includes('.href')) method = 'href';
        else if (line.includes('.cssText')) method = 'cssText';
        else if (line.includes('style.textContent')) method = 'textContent';

        const alreadyExists = sinks.some(s => s.line === lineNumber && s.cwe === cwe);
        if (!alreadyExists) {
          sinks.push({ type, cwe, severity, line: lineNumber, location: line.trim().substring(0, 80), method });
        }
        break;
      }
    }
  }

  return sinks;
}

export function buildJavaScriptTaintedVars(sourceCode: string, language: string): Map<string, number> {
  if (!['javascript', 'typescript'].includes(language)) return new Map();
  const tainted = new Map<string, number>();
  const lines = sourceCode.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    const assignMatch = line.match(/(?:(?:var|let|const)\s+)?(\w+)\s*=\s*(.+)/);
    if (!assignMatch) continue;
    const [, lhs, rhs] = assignMatch;
    if (['if', 'while', 'for', 'return', 'true', 'false', 'null', 'undefined', 'case'].includes(lhs)) continue;
    const isDirectSource = JS_TAINTED_PATTERNS.some(p => p.pattern.test(rhs));
    const isTaintedPropagation = tainted.size > 0 && [...tainted.keys()].some(v => new RegExp(`\\b${v}\\b`).test(rhs));
    if (isDirectSource || isTaintedPropagation) tainted.set(lhs, i + 1);
  }

  return tainted;
}

/**
 * Rust let-binding alias expansion (cognium-dev #71).
 *
 * Given a seed set of already-tainted variable names (typed-extractor
 * parameters like `name: web::Path<String>`, plus method-call sources whose
 * `let <var> = req.match_info()...` binding was reverse-engineered in
 * `taint-matcher.ts`), iteratively propagate taint through `let X = ...`
 * and `X = ...` lines whose RHS references any already-tainted name.
 *
 * The fixpoint loop is bounded by the number of distinct let-bindings, so
 * it terminates in O(lines × tainted) worst case — fine for any realistic
 * Rust source file.
 */
export function buildRustTaintedVars(
  sourceCode: string,
  seedVars: Set<string>,
): Map<string, number> {
  const derived = new Map<string, number>();
  const knownTainted = new Set(seedVars);
  const lines = sourceCode.split('\n');

  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trimStart();
      if (trimmed.startsWith('//')) continue;
      // Prefer let-binding match. Falls back to bare assignment.
      const letMatch = line.match(
        /^\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::\s*[^=]+)?=\s*(.+?)(?:;|$)/,
      );
      const assignMatch = !letMatch
        ? line.match(/^\s*([A-Za-z_]\w*)\s*=\s*(.+?)(?:;|$)/)
        : null;
      const m = letMatch ?? assignMatch;
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      // Skip Rust keywords that can appear in LHS-like positions of the regex.
      if (lhs === 'if' || lhs === 'while' || lhs === 'for' || lhs === 'match' || lhs === 'return') continue;
      if (knownTainted.has(lhs)) continue;
      const ref = [...knownTainted].some(v => new RegExp(`\\b${v}\\b`).test(rhs));
      if (ref) {
        derived.set(lhs, i + 1);
        knownTainted.add(lhs);
        changed = true;
      }
    }
  }
  return derived;
}

// ---------------------------------------------------------------------------
// Bash/Shell taint sources
// ---------------------------------------------------------------------------

/** Positional parameter names that are always external input. */
const BASH_POSITIONAL_PARAMS = new Set(['1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '*']);

/** Common untrusted environment variable name patterns. */
const BASH_UNTRUSTED_ENV_PATTERNS = [
  /^USER_INPUT$/i,
  /^QUERY_STRING$/i,
  /^REQUEST_/i,
  /^HTTP_/i,
  /^REMOTE_/i,
  /^CONTENT_TYPE$/i,
  /^CONTENT_LENGTH$/i,
  /^PATH_INFO$/i,
  /^SCRIPT_NAME$/i,
  /^SERVER_NAME$/i,
  // Sprint 57 #198: RPC/CMD/EXEC/EVAL/SHELL-class env vars seen in recent
  // CVE intake (CVE-2025-67038 HTTP RPC pattern and similar). These names
  // are conventionally used to pass attacker-controlled payloads into
  // shell handlers via HTTP-to-CGI bridges.
  /^RPC_/i,
  /^XMLRPC/i,
  /^JSONRPC/i,
  /^CMD_/i,
  /^EXEC_/i,
  /^EVAL_/i,
  /^SHELL_/i,
];

/** Commands whose output should be treated as tainted network data. */
const BASH_NETWORK_COMMANDS = new Set(['curl', 'wget', 'nc', 'ncat']);

/** Commands whose output should be treated as tainted file data. */
const BASH_FILE_COMMANDS = new Set(['cat', 'head', 'tail', 'less', 'more', 'awk', 'sed', 'cut', 'grep']);

/**
 * Find Bash taint sources: positional params, command substitution from
 * network/file, and known untrusted environment variables.
 */
function findBashTaintSources(sourceCode: string, dfg: DFG): TaintSource[] {
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');
  const definedVars = new Set(dfg.defs.filter(d => d.kind === 'local').map(d => d.variable));

  // Issue #73: track brace depth so that `$1`-`$9` / `$@` / `$*` inside a
  // function body are NOT flagged as script-CLI-arg sources — they're the
  // function's own parameters, populated by the caller. Only the outermost
  // scope (depth === 0) takes positional parameters from the script CLI.
  //
  // Function-declaration syntax recognised:
  //   `name() {`        — POSIX form
  //   `function name {` — Bash form (with or without parens)
  //   `function name() {`
  // The opening `{` may be on the next line; we treat any `{` on a line that
  // also contains a function header as the start of the body. Brace counting
  // is intentionally simple — it won't perfectly handle strings/heredocs
  // containing literal braces, but is sufficient for the common case and
  // matches how tree-sitter-bash defines `function_definition` scopes.
  const fnHeaderRe = /^\s*(?:function\s+)?[A-Za-z_][\w-]*\s*\(\s*\)\s*\{?\s*$|^\s*function\s+[A-Za-z_][\w-]*\s*\{?\s*$/;
  let braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNumber = i + 1;
    if (trimmed.startsWith('#')) continue;

    const insideFunction = braceDepth > 0;

    // 1. Positional parameters: $1-$9, $@, $*
    //    Suppressed inside function bodies (#73 part 1).
    if (!insideFunction) {
      const positionalRe = /\$([1-9@*])|\$\{([1-9@*])\}/g;
      let m: RegExpExecArray | null;
      while ((m = positionalRe.exec(line)) !== null) {
        const param = m[1] ?? m[2];
        const alreadyExists = sources.some(s => s.line === lineNumber && s.variable === param);
        if (!alreadyExists) {
          sources.push({
            type: 'io_input',
            location: `positional parameter $${param}`,
            severity: 'high',
            line: lineNumber,
            confidence: 1.0,
            variable: param,
          });
        }
      }
    }

    // Update brace depth AFTER scanning the line, so positional params on
    // the function-header line itself (rare; usually empty) still count as
    // top-level. The `{` opens the body for subsequent lines.
    if (fnHeaderRe.test(line) || /^\s*[A-Za-z_][\w-]*\s*\(\s*\)\s*\{/.test(line)) {
      // Function header (with or without inline `{`).
      const openBracesOnLine = (line.match(/\{/g) ?? []).length;
      const closeBracesOnLine = (line.match(/\}/g) ?? []).length;
      braceDepth += openBracesOnLine - closeBracesOnLine;
    } else {
      // Non-header line — only count braces if we're already inside a
      // function (cheap heuristic to avoid mis-counting braces in
      // command-group / subshell constructs at top level).
      if (braceDepth > 0) {
        const openBracesOnLine = (line.match(/\{/g) ?? []).length;
        const closeBracesOnLine = (line.match(/\}/g) ?? []).length;
        braceDepth += openBracesOnLine - closeBracesOnLine;
        if (braceDepth < 0) braceDepth = 0;
      }
    }

    // 2. Command substitution from network: VAR=$(curl ...) or VAR=`curl ...`
    const cmdSubAssign = trimmed.match(/^(\w+)=\$\((\w+)\s/);
    const cmdSubBacktick = trimmed.match(/^(\w+)=`(\w+)\s/);
    const csMatch = cmdSubAssign ?? cmdSubBacktick;
    if (csMatch) {
      const [, varName, cmd] = csMatch;
      if (BASH_NETWORK_COMMANDS.has(cmd)) {
        sources.push({
          type: 'network_input',
          location: `${varName}=$(${cmd} ...) — network command output`,
          severity: 'high',
          line: lineNumber,
          confidence: 0.9,
          variable: varName,
        });
      } else if (BASH_FILE_COMMANDS.has(cmd)) {
        sources.push({
          type: 'file_input',
          location: `${varName}=$(${cmd} ...) — file command output`,
          severity: 'medium',
          line: lineNumber,
          confidence: 0.7,
          variable: varName,
        });
      }
    }

    // 3. Environment variables: $VAR where VAR was never assigned in the script
    //    and matches known untrusted env patterns
    const envRe = /\$([A-Z][A-Z0-9_]{2,})|\$\{([A-Z][A-Z0-9_]{2,})\}/g;
    let em: RegExpExecArray | null;
    while ((em = envRe.exec(line)) !== null) {
      const envVar = em[1] ?? em[2];
      // Only flag if not defined in the script and matches untrusted patterns
      if (!definedVars.has(envVar) && BASH_UNTRUSTED_ENV_PATTERNS.some(p => p.test(envVar))) {
        const alreadyExists = sources.some(s => s.line === lineNumber && s.variable === envVar);
        if (!alreadyExists) {
          sources.push({
            type: 'env_input',
            location: `environment variable $${envVar}`,
            severity: 'medium',
            line: lineNumber,
            confidence: 0.8,
            variable: envVar,
          });
        }
      }
    }
  }

  return sources;
}

// ---------------------------------------------------------------------------
// Bash/Shell pattern-based findings
// ---------------------------------------------------------------------------

const BASH_CREDENTIAL_PATTERN = /^(.*?)(password|passwd|secret|api_?key|token|auth_token|private_key|access_key)\s*=\s*["']?([^"'\s$][^"'\s]*)["']?\s*$/i;

// Sprint 65 (#216): suppress predictable-temp-file when the same /tmp/X path
// is verified by a checksum tool later in the script. This breaks the TOCTOU
// substitution risk that justifies the warning.
const BASH_CHECKSUM_VERIFY_PATTERN = /\b(?:sha(?:1|224|256|384|512)sum|md5sum|cksum|b2sum)\s+(?:-c\b|--check\b)/;

function collectChecksumVerifiedTmpPaths(lines: string[]): Set<string> {
  const verified = new Set<string>();
  for (const line of lines) {
    if (!BASH_CHECKSUM_VERIFY_PATTERN.test(line)) continue;
    const matches = line.match(/\/tmp\/[^\s"'$|`]+/g);
    if (!matches) continue;
    for (const p of matches) verified.add(p);
  }
  return verified;
}

// Sprint 65 (#216): suppress predictable-temp-file when the /tmp file is the
// WRITE TARGET of an archive command (tar/zip/gzip/7z/bzip2/xz). The file is
// being produced, not consumed, so there is no TOCTOU read race.
const BASH_ARCHIVE_EXT_PATTERN = /\.(?:tgz|tar\.gz|tar\.bz2|tar\.xz|tar|tbz2|txz|zip|gz|bz2|xz|7z)$/i;

function isArchiveOutputContext(line: string, tmpRel: string): boolean {
  if (!BASH_ARCHIVE_EXT_PATTERN.test(tmpRel)) return false;
  // tar with a create flag (c) anywhere in the flag cluster: tar czf, tar -cf, tar cvjf, etc.
  if (/\btar\b/.test(line) && /(?:^|\s)-?[A-Za-z]*c[A-Za-z]*\b/.test(line)) return true;
  if (/\bzip\b/.test(line) && !/\bunzip\b/.test(line)) return true;
  if (/\bgzip\b/.test(line) && /(?:-c\b|--stdout\b|>)/.test(line)) return true;
  if (/\bbzip2\b/.test(line) && /(?:-c\b|--stdout\b|>)/.test(line)) return true;
  if (/\bxz\b/.test(line) && /(?:-c\b|--stdout\b|>)/.test(line)) return true;
  if (/\b7z\s+a\b/.test(line)) return true;
  return false;
}

export function findBashPatternFindings(sourceCode: string, file: string): SastFinding[] {
  const findings: SastFinding[] = [];
  const lines = sourceCode.split('\n');
  const checksumVerifiedTmpPaths = collectChecksumVerifiedTmpPaths(lines);

  // Sprint 69 (#199): unverified-package-install — `dpkg -i`, `rpm -i/-U`,
  // `apt(-get|itude) install <.deb>`, `yum|dnf|zypper install <.rpm>` of a
  // file path that was not verified by a signature (gpg --verify / rpm
  // --checksig / dpkg --verify) or checksum (sha{1,256,512}sum -c / b2sum
  // -c) earlier in the script. The shape covers the daemon-pkg-install
  // CVE class (FN-CVE-B03) where a tainted URL is downloaded then
  // installed without integrity check.
  const scriptHasVerifier = hasIntegrityVerifierAnywhere(lines);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNumber = i + 1;

    // Skip comments
    if (trimmed.startsWith('#')) continue;

    // 1. Hardcoded credentials: PASSWORD="secret123"
    const credMatch = trimmed.match(BASH_CREDENTIAL_PATTERN);
    if (credMatch) {
      const value = credMatch[3];
      // Skip empty, variable references, and command substitutions
      if (value && !value.startsWith('$') && !value.startsWith('(') && value.length > 1) {
        findings.push({
          id: `hardcoded-credential-${file}-${lineNumber}`,
          pass: 'language-sources',
          category: 'security',
          rule_id: 'hardcoded-credential',
          cwe: 'CWE-798',
          severity: 'high',
          level: 'error',
          message: `Hardcoded credential: ${credMatch[2]} contains a literal value`,
          file,
          line: lineNumber,
          snippet: trimmed.substring(0, 80),
        });
      }
    }

    // 2. Cleartext HTTP in curl/wget
    if (/\b(curl|wget)\b/.test(trimmed) && /\bhttp:\/\//.test(trimmed)) {
      findings.push({
        id: `cleartext-transmission-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'cleartext-transmission',
        cwe: 'CWE-319',
        severity: 'medium',
        level: 'warning',
        message: 'Cleartext HTTP transmission: use https:// instead of http://',
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 80),
      });
    }

    // 3. Predictable /tmp file (no variable in path)
    const tmpMatch = trimmed.match(/\/tmp\/([^\s"'$]+)/);
    if (tmpMatch && !/mktemp/.test(trimmed)) {
      const tmpRel = tmpMatch[1];
      const tmpPath = `/tmp/${tmpRel}`;
      // Sprint 65 (#216): suppress when path is checksum-verified or is an
      // archive WRITE target. Both shapes are benign-by-construction.
      const isChecksumVerified = checksumVerifiedTmpPaths.has(tmpPath);
      const isArchiveOutput = isArchiveOutputContext(trimmed, tmpRel);
      if (!isChecksumVerified && !isArchiveOutput) {
        findings.push({
          id: `predictable-temp-file-${file}-${lineNumber}`,
          pass: 'language-sources',
          category: 'security',
          rule_id: 'predictable-temp-file',
          cwe: 'CWE-377',
          severity: 'medium',
          level: 'warning',
          message: `Predictable temp file: /tmp/${tmpRel}. Use mktemp instead`,
          file,
          line: lineNumber,
          snippet: trimmed.substring(0, 80),
        });
      }
    }

    // 4. Insecure file permissions: chmod 777 or chmod 666
    if (/\bchmod\b/.test(trimmed) && /\b(777|666)\b/.test(trimmed)) {
      const mode = trimmed.match(/\b(777|666)\b/)![1];
      findings.push({
        id: `insecure-file-permission-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'insecure-file-permission',
        cwe: 'CWE-732',
        severity: 'medium',
        level: 'warning',
        message: `Insecure file permission: chmod ${mode} grants excessive access`,
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 80),
      });
    }

    // 5. Unsafe archive extraction: tar with extract flags and no --strip-components
    if (/\btar\b/.test(trimmed) && /(-x|--extract)/.test(trimmed) && !/--strip-components/.test(trimmed)) {
      findings.push({
        id: `unsafe-archive-extraction-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'unsafe-archive-extraction',
        cwe: 'CWE-22',
        severity: 'medium',
        level: 'warning',
        message: 'Unsafe archive extraction: tar -x without --strip-components may allow path traversal',
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 80),
      });
    }

    // 6. Unverified package install (Sprint 69, #199)
    if (!scriptHasVerifier) {
      const installer = matchUnverifiedPackageInstall(trimmed);
      if (installer) {
        findings.push({
          id: `unverified-package-install-${file}-${lineNumber}`,
          pass: 'language-sources',
          category: 'security',
          rule_id: 'unverified-package-install',
          cwe: 'CWE-494',
          severity: 'high',
          level: 'error',
          message: `Unverified package install via ${installer}: package contents are not integrity-checked (no gpg/sha256sum verify in script)`,
          file,
          line: lineNumber,
          snippet: trimmed.substring(0, 80),
        });
      }
    }

    // 7. Weak hash command (Sprint 71, #190): `md5`, `sha1`, `md5sum`,
    // `sha1sum` invoked as a command (pipeline or standalone). Modern
    // best-practice is `sha256sum`/`sha512sum`/`b2sum`. The verify form
    // (`-c`/`--check`) is informational, not a fresh hash emission, but
    // the algorithm is still broken — we still fire.
    const weakHashAlg = matchBashWeakHashCommand(trimmed);
    if (weakHashAlg) {
      findings.push({
        id: `weak-hash-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'weak-hash',
        cwe: 'CWE-328',
        severity: 'medium',
        level: 'warning',
        message: `Weak hash algorithm: ${weakHashAlg} is cryptographically broken. Use sha256sum or sha512sum`,
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 80),
      });
    }
  }

  return findings;
}

/**
 * Sprint 71 (#190): match a bare bash `md5` / `sha1` / `md5sum` / `sha1sum`
 * invocation. Returns the algorithm name when found, else null.
 *
 * Recognition rules:
 *   - Word-boundary match on `md5`, `sha1`, `md5sum`, `sha1sum`.
 *   - The token must appear at the start of the line OR immediately after
 *     a pipeline operator (`|`) or shell separator (`;`, `&&`, `||`).
 *   - Reject when the token appears inside an obvious algorithm-name
 *     string literal (e.g. `"md5sum"` as an argv).
 */
function matchBashWeakHashCommand(line: string): string | null {
  // Algorithm name + boundary: either followed by whitespace, end-of-line,
  // a redirect, or another pipe.
  const re = /(?:^|[|;]|&&|\|\|)\s*(md5sum|sha1sum|md5|sha1)\b(?!\s*=)/;
  const m = line.match(re);
  if (!m) return null;
  // Reject `-c` / `--check` verify form? No — broken algorithm regardless.
  return m[1];
}

/**
 * Sprint 69 (#199): return the installer name when `line` is a package-install
 * command of a file PATH (not a registry package name).
 *
 *   dpkg -i / -I / -U / --install            → 'dpkg'
 *   rpm  -i / -U / --install / --upgrade     → 'rpm'
 *   apt-get|apt|aptitude install …/*.deb     → 'apt-get'|'apt'|'aptitude'
 *   yum|dnf|zypper install …/*.rpm           → 'yum'|'dnf'|'zypper'
 *
 * For apt/yum/dnf/zypper the install target must be an explicit .deb/.rpm
 * file path (otherwise the call is a normal repository-managed install and
 * not the FN shape we model).
 */
function matchUnverifiedPackageInstall(line: string): string | null {
  // dpkg -i / -I / -U / --install
  if (/\bdpkg\b/.test(line) && /(?:^|\s)(?:-[a-zA-Z]*[iIU][a-zA-Z]*|--install)\b/.test(line)) {
    return 'dpkg';
  }
  // rpm -i / -U / --install / --upgrade (reject -e/--erase, -q/--query, -V/--verify)
  if (/\brpm\b/.test(line) && /(?:^|\s)(?:-[a-zA-Z]*[iU][a-zA-Z]*|--install|--upgrade)\b/.test(line)
      && !/--(?:verify|checksig|erase|query)\b/.test(line)) {
    return 'rpm';
  }
  // apt-get|apt|aptitude install <.deb path>
  const aptMatch = line.match(/\b(apt-get|apt|aptitude)\s+install\b/);
  if (aptMatch && /\.deb\b/.test(line)) {
    return aptMatch[1];
  }
  // yum|dnf|zypper install <.rpm path>
  const yumMatch = line.match(/\b(yum|dnf|zypper)\s+install\b/);
  if (yumMatch && /\.rpm\b/.test(line)) {
    return yumMatch[1];
  }
  return null;
}

/**
 * Sprint 69 (#199): True iff the script contains any integrity-verifier
 * invocation that would gate a subsequent install (signature or checksum).
 * Whole-script check, not per-path — matches the corpus's "verify-then-
 * install" idiom where the gpg/sha verify references a separate path or
 * inline data.
 */
function hasIntegrityVerifierAnywhere(lines: string[]): boolean {
  const sigRe = /\b(?:gpg(?:v|2)?|gpg)\s+(?:[^|]*\s)?--verify\b/;
  const rpmSigRe = /\brpm\s+(?:[^|]*\s)?--checksig\b/;
  const dpkgSigRe = /\bdpkg\s+(?:[^|]*\s)?--verify\b/;
  const sumRe = /\b(?:sha(?:1|224|256|384|512)sum|md5sum|cksum|b2sum)\s+(?:[^|]*\s)?(?:-c|--check)\b/;
  for (const line of lines) {
    if (sigRe.test(line) || rpmSigRe.test(line) || dpkgSigRe.test(line) || sumRe.test(line)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Bash regex-allowlist sanitizers (Sprint 11 — #73.2)
// ---------------------------------------------------------------------------

/**
 * Detect the idiomatic bash regex-allowlist guard:
 *
 *   if [[ ! "$var" =~ ^[a-zA-Z0-9_]+$ ]]; then exit 1; fi
 *
 * When the guard's `then` branch terminates execution (exit/return/die) and
 * the regex is a tight character-class allowlist, subsequent uses of `$var`
 * are constrained to the allowlisted alphabet — effectively a sanitizer.
 *
 * We emit `TaintSanitizer` entries at every line from the line AFTER the
 * `if` through end-of-file. This is intentionally coarse: the test
 * `checkSanitized` only consults the sink's line, so a per-line emission
 * gives a simple forward-scoped clear without DFG block tracking. The
 * sanitizer covers the injection sink-types most relevant to user input
 * fed to shell utilities.
 *
 * Safe-regex predicate rejects anything that isn't anchored, contains
 * `.*` / `.+`, contains alternation, or contains backrefs.
 */
function findBashRegexAllowlistSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Captures: 1=variable, 2=regex body, 3=terminator (exit|return|die)
  const guardRe = /^\s*if\s+\[\[\s*!\s*"?\$\{?(\w+)\}?"?\s*=~\s*(\S+)\s*\]\]\s*;\s*then\s+(exit|return|die)\b/;

  for (let i = 0; i < lines.length; i++) {
    const m = guardRe.exec(lines[i]);
    if (!m) continue;
    const regexLiteral = m[2];
    if (!isSafeBashAllowlistRegex(regexLiteral)) continue;

    // Sanitizer applies from the next source line through end-of-file. We
    // emit per-line entries so the line-keyed `checkSanitized` lookup
    // finds them at any downstream sink line.
    const ifLine1Indexed = i + 1;
    for (let l = ifLine1Indexed + 1; l <= lines.length; l++) {
      sanitizers.push({
        type: 'regex_allowlist',
        method: '=~',
        line: l,
        sanitizes: [
          'command_injection',
          'path_traversal',
          'sql_injection',
          'code_injection',
          'ssrf',
          'xss',
          'open_redirect',
          'log_injection',
        ],
      });
    }
  }

  return sanitizers;
}

/**
 * A regex literal is a "safe allowlist" if:
 *  - It is anchored at both ends (`^…$`).
 *  - It contains no wildcard quantifier (`.*` / `.+`).
 *  - It contains no alternation (`|`).
 *  - It contains no backreference (`\1`, `\2`, …).
 *  - Every token is a bracketed character class, a plain alnum / safe punct,
 *    an escape, or a `+`/`*`/`?` quantifier — no free-form `.`, no shell
 *    expansion characters.
 */
function isSafeBashAllowlistRegex(literal: string): boolean {
  if (!literal.startsWith('^') || !literal.endsWith('$')) return false;
  const body = literal.slice(1, -1);
  if (body.length === 0) return false;
  if (body.includes('.*') || body.includes('.+')) return false;
  if (body.includes('|')) return false;
  if (/\\\d/.test(body)) return false;

  // Token whitelist:
  //  - `\[[^\]]+\][+*?]?` — char class with optional quantifier
  //  - `\\.`              — escaped metacharacter
  //  - `[A-Za-z0-9_\-./]` — literal safe chars
  //  - `[+*?]`            — quantifier on the preceding token
  const safeToken = /\[[^\]]+\][+*?]?|\\.|[A-Za-z0-9_\-./]|[+*?]/g;
  let consumed = 0;
  let match: RegExpExecArray | null;
  while ((match = safeToken.exec(body)) !== null) {
    if (match.index !== consumed) return false;
    consumed += match[0].length;
  }
  return consumed === body.length;
}

// ---------------------------------------------------------------------------
// Bash realpath + case prefix-guard sanitizer (Sprint 23 — #102)
// ---------------------------------------------------------------------------

/**
 * Detect the canonical "canonicalize-then-prefix-check" shape used by
 * defensive shell scripts to keep tainted paths inside an allowed root:
 *
 *   resolved=$(realpath "$f")
 *   case "$resolved" in
 *     "$UPLOAD_ROOT"/*) cat "$resolved" ;;
 *     *) echo denied; exit 1 ;;
 *   esac
 *
 * Properties needed for the sanitizer to fire:
 *   1. A `case "$VAR" in` block whose head matches a variable.
 *   2. At least one literal/var prefix arm — e.g. `"$ROOT"/*)`, `"/tmp"/*)`,
 *      `/var/uploads/*)`. The prefix must be anchored (no leading wildcard).
 *   3. A catch-all `*)` arm whose body terminates execution
 *      (`exit`, `return`, or `die`).
 *
 * When matched we emit a `realpath_prefix_guard` sanitizer for every line
 * inside the `case…esac` block. Because `checkSanitized` is line-keyed,
 * the sanitizer suppresses any path/command/code/ssrf/log sink that
 * appears inside the case body — exactly where the safe branches live.
 *
 * Conservative by design: if the catch-all does NOT terminate, OR no
 * prefix arm is present, no sanitizer is emitted (e.g. open-ended
 * `case "$x" in *)` fall-through is still treated as tainted).
 */
function findBashRealpathPrefixGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  const caseOpen = /^\s*case\s+"?\$\{?\w+\}?"?\s+in\b/;
  const esacClose = /^\s*esac\b/;
  // An arm pattern is everything up to the first unparenthesised `)`.
  // `arm[1]` is the trimmed pattern text.
  const armOpener = /^\s*([^)\s][^)]*?)\)/;
  // A prefix arm starts with a literal path or a `"$VAR"` expansion and
  // is followed by `/` (root prefix) or `*` (already anchored). The
  // leading character must not itself be `*` — that's the catch-all.
  const prefixArm = /^(?:"\$\{?\w+\}?"|"[^"]*"|\/[\w\-./]+|\$\{?\w+\}?|[\w\-./]+)(?:\/|\*)/;
  // Catch-all is exactly `*` (with optional leading `|`).
  const catchAllArm = /^(?:\*|\\\*)$/;

  let i = 0;
  while (i < lines.length) {
    if (!caseOpen.test(lines[i])) {
      i++;
      continue;
    }
    // Find matching esac (no nesting support — bash case rarely nests
    // inside another case, and the conservative early-exit means we'd
    // simply skip emitting the sanitizer rather than mis-emit).
    let caseEnd = -1;
    for (let j = i + 1; j < lines.length; j++) {
      if (esacClose.test(lines[j])) {
        caseEnd = j;
        break;
      }
    }
    if (caseEnd === -1) {
      i++;
      continue;
    }

    let hasPrefixArm = false;
    let hasTerminalCatchAll = false;

    for (let j = i + 1; j < caseEnd; j++) {
      const armMatch = armOpener.exec(lines[j]);
      if (!armMatch) continue;
      const pattern = armMatch[1].trim();

      if (catchAllArm.test(pattern)) {
        // Catch-all arm — search this line through the next arm (or
        // esac) for a terminator. The body may span multiple lines if
        // `;;` is on its own line.
        let bodyEnd = caseEnd;
        for (let k = j + 1; k < caseEnd; k++) {
          if (armOpener.test(lines[k])) {
            bodyEnd = k;
            break;
          }
        }
        const armBody = lines.slice(j, bodyEnd).join(' ');
        if (/\b(exit|return|die)\b/.test(armBody)) {
          hasTerminalCatchAll = true;
        }
      } else if (prefixArm.test(pattern)) {
        hasPrefixArm = true;
      }
    }

    if (hasPrefixArm && hasTerminalCatchAll) {
      // Per-line sanitizer entries for the entire case body. 1-indexed.
      for (let l = i + 1; l <= caseEnd + 1; l++) {
        sanitizers.push({
          type: 'realpath_prefix_guard',
          method: 'case',
          line: l,
          sanitizes: [
            'path_traversal',
            'command_injection',
            'code_injection',
            'ssrf',
            'open_redirect',
            'log_injection',
          ],
        });
      }
    }

    i = caseEnd + 1;
  }

  return sanitizers;
}

// ---------------------------------------------------------------------------
// Go safe-handler sanitizer detectors (cognium-dev #102 Sprint 24)
// ---------------------------------------------------------------------------

/**
 * Detect Go allow-list guard pattern:
 *
 *   if !allowedHosts[host] {
 *     http.Error(w, "forbidden", 403)
 *     return
 *   }
 *
 * The map identifier must look like an allow-list (UPPER_SNAKE, or
 * camelCase containing "allowed"/"accepted"/"whitelist"/"permitted").
 * The if-block body must contain `return`, `panic(`, or `os.Exit(`
 * within at most 25 lines from the guard.
 *
 * When matched we emit per-line sanitizers for every line downstream of
 * the guard close brace so that any ssrf/path/sql/open_redirect sink in
 * the safe branch is suppressed. (cognium-dev #102 FP-20)
 */
function findGoMapAllowlistGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `if !<mapName>[<key>] {`  — optional whitespace, optional `_ ,`
  // ignored. Captures the map identifier in group 1.
  const guardOpen = /^\s*if\s+!\s*([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]\s*\{/;
  // Allow-list naming heuristic.
  const allowlistName = /^(?:[A-Z][A-Z0-9_]+|.*?(allowed|accepted|whitelist|permitted|valid|approved).*)$/i;

  for (let i = 0; i < lines.length; i++) {
    const m = guardOpen.exec(lines[i]);
    if (!m) continue;
    const mapName = m[1];
    if (!allowlistName.test(mapName)) continue;

    // Search for terminator within 25 lines or until matching `}`.
    let depth = 1;
    let closeLine = -1;
    let bodyHasTerminator = false;
    const maxScan = Math.min(lines.length, i + 26);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (/\b(return|panic\s*\(|os\.Exit\s*\()/.test(line)) {
        bodyHasTerminator = true;
      }
      // Crude brace tracking — counts braces outside string/comment.
      // For the conservative allow-list shape this is sufficient.
      for (const ch of line) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (depth === 0) {
        closeLine = j;
        break;
      }
    }
    if (closeLine === -1 || !bodyHasTerminator) continue;

    // Emit per-line sanitizers for every line AFTER the guard's closing
    // brace through end of file. `checkSanitized` is line-keyed so this
    // suppresses the relevant sink types in the safe branch.
    for (let l = closeLine + 2; l <= lines.length; l++) {
      sanitizers.push({
        type: 'go_map_allowlist_guard',
        method: 'if',
        line: l,
        sanitizes: [
          'ssrf',
          'open_redirect',
          'path_traversal',
          'sql_injection',
          'command_injection',
          'external_taint_escape',
        ],
      });
    }
  }

  return sanitizers;
}

/**
 * Detect Go `html/template` import and treat all `Execute` /
 * `ExecuteTemplate` calls in the file as auto-escaping sanitizers for
 * xss. `html/template` auto-escapes interpolated values; `text/template`
 * does not. If BOTH packages are imported in the same file the
 * detection bails out (ambiguous — fall back to per-call class
 * resolution). (cognium-dev #102 FP-19b)
 */
function findGoHtmlTemplateImportSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];

  const hasHtmlTemplate = /["\s]html\/template["\s]/.test(code);
  const hasTextTemplate = /["\s]text\/template["\s]/.test(code);
  if (!hasHtmlTemplate) return sanitizers;
  if (hasTextTemplate) return sanitizers;

  const lines = code.split('\n');
  const execCall = /\.(Execute|ExecuteTemplate)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    if (!execCall.test(lines[i])) continue;
    sanitizers.push({
      type: 'html_template_auto_escape',
      method: 'Execute',
      line: i + 1,
      sanitizes: ['xss', 'external_taint_escape', 'open_redirect'],
    });
  }

  return sanitizers;
}

/**
 * Detect Python netloc / membership allow-list guards (cognium-dev #114).
 *
 * Pattern recognized:
 *
 *   if host not in ALLOWED_HOSTS:
 *       return "blocked", 400
 *   # rest of function is safe for open_redirect / ssrf
 *
 * Body must contain a terminator (return/raise/abort/sys.exit) within
 * 25 lines (mirrors the Go map-allowlist heuristic). Allow-list name
 * must match UPPER_SNAKE or contain allowed|whitelist|... tokens.
 *
 * Emits per-line sanitizers from the next non-guard line through the end
 * of file. Sink-line lookup is line-keyed so the safe branch is filtered.
 */
function findPythonNetlocAllowlistGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `if <ident> not in <ALLOWLIST>:` (handles both bare ident and
  // `urlparse(x).netloc` LHS — only the RHS allow-list name is captured).
  const guardOpen = /^(\s*)if\s+.+?\s+not\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$/;
  const allowlistName = /^(?:[A-Z][A-Z0-9_]+|.*?(allowed|accepted|whitelist|permitted|valid|approved).*)$/i;
  const terminator = /\b(return|raise|abort\s*\(|sys\.exit\s*\()/;

  for (let i = 0; i < lines.length; i++) {
    const m = guardOpen.exec(lines[i]);
    if (!m) continue;
    const guardIndent = m[1].length;
    const allowName = m[2];
    if (!allowlistName.test(allowName)) continue;

    // Walk the indented body of the if-block (Python is whitespace-scoped).
    // Body lines are those indented deeper than the guard; the block
    // ends on the first line at <= guardIndent that is non-empty.
    let bodyHasTerminator = false;
    let blockEnd = -1;
    const maxScan = Math.min(lines.length, i + 26);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (line.trim() === '') continue;
      const indent = line.length - line.trimStart().length;
      if (indent <= guardIndent) {
        blockEnd = j - 1;
        break;
      }
      if (terminator.test(line)) bodyHasTerminator = true;
    }
    if (blockEnd === -1) blockEnd = Math.min(lines.length - 1, i + 25);
    if (!bodyHasTerminator) continue;

    // Emit per-line sanitizers from the first line after the if-block
    // through end of file. 1-indexed line numbers.
    for (let l = blockEnd + 2; l <= lines.length; l++) {
      sanitizers.push({
        type: 'python_netloc_allowlist_guard',
        method: 'if',
        line: l,
        sanitizes: [
          'open_redirect',
          'ssrf',
          'path_traversal',
          'external_taint_escape',
        ],
      });
    }
  }

  return sanitizers;
}

/**
 * Detect Python numeric range-check guards followed by use of the
 * guarded variable (cognium-dev #114 defect 2).
 *
 * Pattern recognized:
 *
 *   qty = int(request.args.get("qty", "0"))
 *   if qty < 1 or qty > MAX_QTY:
 *       return "out of range", 400
 *   ...use qty in arithmetic + str()...
 *
 * `int(...)` already strips xss in DEFAULT_SANITIZERS, but the
 * sanitization is lost through arithmetic and str() concat. A numeric
 * range-check guard on a tainted-but-cast int proves the value is a
 * bounded integer; the resulting string-concat output cannot carry xss.
 *
 * Conservative shape: the comparison operands must be numeric literals
 * or UPPER_SNAKE constants (e.g. MAX_QTY). The guard body must contain
 * a terminator.
 */
function findPythonRangeCheckGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `if <ident> <op> <num|CONST> [or/and <ident> <op> <num|CONST>]?:`
  // Matches single- and two-sided range checks. Identifier must repeat.
  const rangeGuard = /^(\s*)if\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<>]=?\s*(?:\d+|-?\d+\.?\d*|[A-Z][A-Z0-9_]+)\s*(?:(?:or|and)\s+\2\s*[<>]=?\s*(?:\d+|-?\d+\.?\d*|[A-Z][A-Z0-9_]+)\s*)?:\s*$/;
  const terminator = /\b(return|raise|abort\s*\(|sys\.exit\s*\()/;

  for (let i = 0; i < lines.length; i++) {
    const m = rangeGuard.exec(lines[i]);
    if (!m) continue;
    const guardIndent = m[1].length;

    let bodyHasTerminator = false;
    let blockEnd = -1;
    const maxScan = Math.min(lines.length, i + 26);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (line.trim() === '') continue;
      const indent = line.length - line.trimStart().length;
      if (indent <= guardIndent) {
        blockEnd = j - 1;
        break;
      }
      if (terminator.test(line)) bodyHasTerminator = true;
    }
    if (blockEnd === -1) blockEnd = Math.min(lines.length - 1, i + 25);
    if (!bodyHasTerminator) continue;

    for (let l = blockEnd + 2; l <= lines.length; l++) {
      sanitizers.push({
        type: 'python_range_check_guard',
        method: 'if',
        line: l,
        sanitizes: ['xss', 'external_taint_escape'],
      });
    }
  }

  return sanitizers;
}

/**
 * Detect Python regex-fullmatch allow-list wrapper functions
 * (cognium-dev #216 Sprint 74 Pattern B).
 *
 * Pattern recognized:
 *
 *   def checked_uid(uid):
 *       if not re.fullmatch(r"[a-zA-Z0-9_-]+", uid):
 *           abort(400)
 *       return uid
 *
 * Two-pass: (1) scan for `def NAME(arg):` declarations whose body
 * contains `if not re.fullmatch(<TIGHT_REGEX>, arg): <terminator>`
 * and returns `arg`; (2) for every line containing `NAME(...)` outside
 * the declaration, emit a sanitizer.
 *
 * "Tight" regex means a character-class allow-list that admits only
 * alphanumerics and a small fixed set of safe separators
 * ([A-Za-z0-9], \w, plus optional `-`, `_`, `.`). Such an allow-list
 * strips every injection metacharacter, so the sanitizer lists
 * ldap/xpath/sql/command/path-traversal/xss + ETE.
 *
 * Loose patterns like `.*` or `.+` are rejected (TP-controls cover
 * the bypass case where the wrapper return value is not what reaches
 * the sink).
 */
function findPythonRegexAllowlistWrapperSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Match `def NAME(arg):` — single argument, no default.
  const defOpen = /^(\s*)def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*:\s*$/;
  // Tight char-class allow-list: starts with `[` followed by safe ranges
  // and an explicit `+` / `*` / `{n,m}` quantifier; or `\w+`-style.
  const tightRegex = /r?["'](?:\^)?(?:\\w[+*]|\\d[+*]|\[[A-Za-z0-9_\\\-\.\s]+\][+*]|[A-Za-z0-9_\-\.]+)(?:\$)?["']/;
  const terminator = /\b(return\s+(?:None|"|'|\(|\[|\{|False|jsonify|make_response|redirect|abort)|raise\s+\w|abort\s*\(|sys\.exit\s*\()/;

  // Pass 1: discover wrappers.
  type WrapperInfo = { name: string; defLine: number; defIndent: number };
  const wrappers: WrapperInfo[] = [];

  for (let i = 0; i < lines.length; i++) {
    const m = defOpen.exec(lines[i]);
    if (!m) continue;
    const defIndent = m[1].length;
    const wrapperName = m[2];
    const argName = m[3];

    // Walk the indented body of the def. Look for
    // `if not re.fullmatch(<tight>, <arg>): <terminator>` and `return arg`.
    let foundGuard = false;
    let returnsArg = false;
    let blockEnd = -1;
    const maxScan = Math.min(lines.length, i + 40);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (line.trim() === '') continue;
      const indent = line.length - line.trimStart().length;
      if (indent <= defIndent) {
        blockEnd = j - 1;
        break;
      }
      if (!foundGuard) {
        const guard = new RegExp(
          `if\\s+not\\s+re\\.(?:fullmatch|match)\\s*\\(\\s*(${tightRegex.source})\\s*,\\s*${argName}\\s*\\)\\s*:`,
        );
        if (guard.test(line)) {
          // Confirm the next deeper-indented line is a terminator.
          for (let k = j + 1; k < maxScan; k++) {
            const klin = lines[k];
            if (klin.trim() === '') continue;
            const kindent = klin.length - klin.trimStart().length;
            if (kindent <= indent) break;
            if (terminator.test(klin)) foundGuard = true;
            break;
          }
        }
      }
      if (new RegExp(`^\\s*return\\s+${argName}\\s*$`).test(line)) {
        returnsArg = true;
      }
    }
    if (blockEnd === -1) blockEnd = Math.min(lines.length - 1, i + 39);
    if (!foundGuard || !returnsArg) continue;

    wrappers.push({ name: wrapperName, defLine: i, defIndent });
  }

  if (wrappers.length === 0) return sanitizers;

  // The kinds a tight-regex wrapper sanitizes.
  const wrapperKinds = [
    'ldap_injection',
    'xpath_injection',
    'sql_injection',
    'command_injection',
    'path_traversal',
    'xss',
    'external_taint_escape',
  ] as const;

  // Pass 2: var-aware emission. For each call of the form
  //   `<VALIDATED> = NAME(...)`
  // mark every subsequent line in the same function block that
  // references `<VALIDATED>` as a sanitizer for the wrapper kinds.
  // This avoids over-suppressing unrelated tainted vars introduced
  // later in the same function.
  for (const w of wrappers) {
    const assignedCallRe = new RegExp(
      `^(\\s*)([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*${w.name}\\s*\\(`,
    );
    const bareCallRe = new RegExp(`\\b${w.name}\\s*\\(`);

    for (let i = 0; i < lines.length; i++) {
      if (i === w.defLine) continue;
      const line = lines[i];
      if (!bareCallRe.test(line)) continue;

      // Skip calls inside the wrapper's own body.
      if (i > w.defLine) {
        const lineIndent = line.length - line.trimStart().length;
        if (lineIndent > w.defIndent) {
          let stillInside = true;
          for (let k = w.defLine + 1; k < i; k++) {
            const kline = lines[k];
            if (kline.trim() === '') continue;
            const kindent = kline.length - kline.trimStart().length;
            if (kindent <= w.defIndent) {
              stillInside = false;
              break;
            }
          }
          if (stillInside) continue;
        }
      }

      // Emit a sanitizer at the call line itself (covers ETE on a
      // single-line `NAME(req.args.get(...))` shape).
      sanitizers.push({
        type: 'python_regex_allowlist_wrapper',
        method: w.name,
        line: i + 1,
        sanitizes: [...wrapperKinds],
      });

      // If the call result is assigned to a variable, track it and
      // emit sanitizers on every later line in the same function
      // block that mentions that variable name. End the scan when
      // we leave the call's enclosing block.
      const am = assignedCallRe.exec(line);
      if (!am) continue;
      const callIndent = am[1].length;
      const validated = am[2];
      const validatedRe = new RegExp(`\\b${validated}\\b`);

      for (let j = i + 1; j < lines.length; j++) {
        const jline = lines[j];
        if (jline.trim() === '') continue;
        const jindent = jline.length - jline.trimStart().length;
        if (jindent < callIndent) break;
        if (validatedRe.test(jline)) {
          sanitizers.push({
            type: 'python_regex_allowlist_wrapper',
            method: w.name,
            line: j + 1,
            sanitizes: [...wrapperKinds],
          });
        }
      }
    }
  }

  return sanitizers;
}

/**
 * Detect Python set-membership allow-list guards that should sanitize
 * `xss` flows (cognium-dev #216 Sprint 74 Pattern B, SSTI fixture).
 *
 * Pattern recognized:
 *
 *   t = request.args.get("t", "")
 *   if t not in ALLOWED:
 *       abort(403)
 *   env.from_string("{{ " + t + " }}").render()
 *
 * The existing `findPythonNetlocAllowlistGuardSanitizers` already
 * handles the source pattern but cannot list `xss` as a blanket
 * sanitizer (over-suppression risk: a different unguarded variable
 * later in the same handler would be incorrectly cleared). This
 * detector is variable-aware: it only emits an `xss` sanitizer on
 * lines that actually reference the guarded variable.
 */
function findPythonSetMembershipXssGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `if <ident> not in <ALLOWLIST>:`
  const guardOpen = /^(\s*)if\s+([A-Za-z_][A-Za-z0-9_]*)\s+not\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$/;
  const allowlistName = /^(?:[A-Z][A-Z0-9_]+|.*?(allowed|accepted|whitelist|permitted|valid|approved).*)$/i;
  const terminator = /\b(return|raise|abort\s*\(|sys\.exit\s*\()/;

  for (let i = 0; i < lines.length; i++) {
    const m = guardOpen.exec(lines[i]);
    if (!m) continue;
    const guardIndent = m[1].length;
    const guardedVar = m[2];
    const allowName = m[3];
    if (!allowlistName.test(allowName)) continue;

    let bodyHasTerminator = false;
    let blockEnd = -1;
    const maxScan = Math.min(lines.length, i + 26);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (line.trim() === '') continue;
      const indent = line.length - line.trimStart().length;
      if (indent <= guardIndent) {
        blockEnd = j - 1;
        break;
      }
      if (terminator.test(line)) bodyHasTerminator = true;
    }
    if (blockEnd === -1) blockEnd = Math.min(lines.length - 1, i + 25);
    if (!bodyHasTerminator) continue;

    // Var-aware emission: only lines that reference the guarded var.
    const varRe = new RegExp(`\\b${guardedVar}\\b`);
    for (let l = blockEnd + 2; l <= lines.length; l++) {
      const lineText = lines[l - 1];
      if (!varRe.test(lineText)) continue;
      sanitizers.push({
        type: 'python_set_membership_xss_guard',
        method: 'if',
        line: l,
        sanitizes: ['xss', 'external_taint_escape'],
      });
    }
  }

  return sanitizers;
}

/**
 * Detect Python `defusedxml` import-alias usage as xxe sanitizer
 * (cognium-dev #216 Sprint 74 Pattern B).
 *
 * defusedxml is the canonical Python defense against XML External
 * Entity (CWE-611) attacks — its parsers reject DTD and entity
 * expansion by design. Recognize three import shapes:
 *
 *   import defusedxml.ElementTree as ET
 *   from defusedxml.ElementTree import fromstring
 *   import defusedxml as DX
 *
 * For every line that calls `<alias>.<method>(...)` (module-alias
 * shape) or bare `<name>(...)` (from-import shape) emit a sanitizer
 * with `sanitizes: ['xxe', 'external_taint_escape']`.
 */
function findPythonDefusedXmlSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Aliases bound to a defusedxml.* module (or defusedxml itself).
  const moduleAliases = new Set<string>();
  // Names imported FROM defusedxml.*.
  const fromNames = new Set<string>();

  const importAs = /^\s*import\s+defusedxml(?:\.[A-Za-z_][A-Za-z0-9_.]*)?\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*$/;
  const importBare = /^\s*import\s+defusedxml(?:\.([A-Za-z_][A-Za-z0-9_.]*))?\s*$/;
  const fromImport = /^\s*from\s+defusedxml(?:\.[A-Za-z_][A-Za-z0-9_.]*)?\s+import\s+(.+)$/;

  for (const raw of lines) {
    const line = raw.replace(/#.*$/, '');
    let m: RegExpExecArray | null;
    if ((m = importAs.exec(line))) {
      moduleAliases.add(m[1]);
      continue;
    }
    if ((m = importBare.exec(line))) {
      // `import defusedxml.ElementTree` → callers use full
      // `defusedxml.ElementTree.fromstring`. Bind the leaf segment
      // when present, else `defusedxml`.
      if (m[1]) {
        moduleAliases.add(m[1].split('.').pop()!);
      }
      moduleAliases.add('defusedxml');
      continue;
    }
    if ((m = fromImport.exec(line))) {
      const items = m[1].split(',');
      for (const item of items) {
        const trimmed = item.trim().replace(/[()\\]/g, '');
        if (!trimmed) continue;
        const asMatch = /^([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)$/.exec(trimmed);
        if (asMatch) {
          fromNames.add(asMatch[2]);
        } else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed)) {
          fromNames.add(trimmed);
        }
      }
    }
  }

  if (moduleAliases.size === 0 && fromNames.size === 0) return sanitizers;

  // Emit per-line sanitizers at each call site.
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip import lines themselves.
    if (/^\s*(?:import|from)\s+/.test(line)) continue;

    let matched = false;
    for (const alias of moduleAliases) {
      const re = new RegExp(`\\b${alias}\\s*\\.\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\(`);
      if (re.test(line)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      for (const name of fromNames) {
        const re = new RegExp(`\\b${name}\\s*\\(`);
        if (re.test(line)) {
          matched = true;
          break;
        }
      }
    }
    if (!matched) continue;

    sanitizers.push({
      type: 'python_defusedxml_import',
      method: 'defusedxml',
      line: i + 1,
      sanitizes: ['xxe', 'external_taint_escape'],
    });
  }

  return sanitizers;
}

/**
 * Detect Rust HashSet/HashMap host allow-list guards (cognium-dev #115 FP-23).
 *
 * Pattern recognized:
 *
 *   if !ALLOWED.contains(&host) {
 *       return Ok(HttpResponse::Forbidden().finish());
 *   }
 *
 * Or `!allowed.contains_key(&host)` for HashMap. Set/map identifier must
 * pass the allow-list name heuristic. Body must contain a terminator
 * (return / Err( / panic!). Emits per-line sanitizers downstream.
 */
function findRustSetAllowlistGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `if !<setName>.(contains|contains_key)(<arg>) {`
  const guardOpen = /^\s*if\s+!\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:contains|contains_key)\s*\(/;
  const allowlistName = /^(?:[A-Z][A-Z0-9_]+|.*?(allowed|accepted|whitelist|permitted|valid|approved).*)$/i;
  const terminator = /\b(return|Err\s*\(|panic!\s*\(|HttpResponse::(?:Forbidden|BadRequest|Unauthorized))/;

  for (let i = 0; i < lines.length; i++) {
    const m = guardOpen.exec(lines[i]);
    if (!m) continue;
    const setName = m[1];
    if (!allowlistName.test(setName)) continue;

    // Find matching `}` via brace depth tracking.
    let depth = 0;
    // Count braces on guard line first to seed depth.
    for (const ch of lines[i]) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    if (depth <= 0) continue; // No opening brace on guard line, skip.

    let closeLine = -1;
    let bodyHasTerminator = false;
    const maxScan = Math.min(lines.length, i + 26);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (terminator.test(line)) bodyHasTerminator = true;
      for (const ch of line) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (depth === 0) {
        closeLine = j;
        break;
      }
    }
    if (closeLine === -1 || !bodyHasTerminator) continue;

    for (let l = closeLine + 2; l <= lines.length; l++) {
      sanitizers.push({
        type: 'rust_set_allowlist_guard',
        method: 'if',
        line: l,
        sanitizes: [
          'ssrf',
          'open_redirect',
          'command_injection',
          'external_taint_escape',
        ],
      });
    }
  }

  return sanitizers;
}

/**
 * Detect Rust path-prefix guards using `canonicalize()` /
 * `starts_with()` (cognium-dev #115 FP-22).
 *
 * Pattern recognized:
 *
 *   let canonical = base.join(name).canonicalize()?;
 *   if !canonical.starts_with(&ROOT) {
 *       return Err(...);
 *   }
 *   fs::read(canonical)  // safe — bound to ROOT
 *
 * Conservative: require an explicit `if !x.starts_with(&Y) { ... }` shape
 * with a body terminator. The receiver `x` need not be named
 * `canonical` — `.canonicalize()?.starts_with(...)` chains also match.
 *
 * Emits per-line sanitizers downstream of the guard close brace.
 */
function findRustCanonicalizeGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `if !<expr>.starts_with(<arg>)` — match the negated prefix check.
  // The expr may be a simple ident or a chain like `x.canonicalize()?`.
  const guardOpen = /^\s*if\s+!\s*[A-Za-z_][\w?.()&]*\.starts_with\s*\(/;
  const terminator = /\b(return|Err\s*\(|panic!\s*\(|HttpResponse::(?:Forbidden|BadRequest|Unauthorized|NotFound))/;

  for (let i = 0; i < lines.length; i++) {
    if (!guardOpen.test(lines[i])) continue;

    let depth = 0;
    for (const ch of lines[i]) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    if (depth <= 0) continue;

    let closeLine = -1;
    let bodyHasTerminator = false;
    const maxScan = Math.min(lines.length, i + 26);
    for (let j = i + 1; j < maxScan; j++) {
      const line = lines[j];
      if (terminator.test(line)) bodyHasTerminator = true;
      for (const ch of line) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (depth === 0) {
        closeLine = j;
        break;
      }
    }
    if (closeLine === -1 || !bodyHasTerminator) continue;

    for (let l = closeLine + 2; l <= lines.length; l++) {
      sanitizers.push({
        type: 'rust_canonicalize_guard',
        method: 'if',
        line: l,
        sanitizes: [
          'path_traversal',
          'xss',
          'ssrf',
          'external_taint_escape',
        ],
      });
    }
  }

  return sanitizers;
}

// ---------------------------------------------------------------------------
// Sprint 73 (#216 Pattern A + B) — JS/Java safe-handler sanitizer
// recognition for the synthetic `external_taint_escape` (CWE-668) fallback
// flow, plus JS user-defined wrapper-function recognition for `xss` /
// `log_injection`.
//
// Suppression mechanism: `taint-propagation-pass.ts:198-232` already
// filters ETE flows when ANY sanitizer between source and sink lists
// `external_taint_escape` in its `sanitizes` array. These detectors emit
// the sanitizer entries so the existing filter can do its job.
//
// Conservative scoping: each detector restricts `sanitizes` to the
// minimum justifiable set so configured (real) sinks are unaffected.
// ---------------------------------------------------------------------------

/**
 * Java: Jackson `mapper.readValue(...)` and Gson `gson.fromJson(...)`
 * construct typed POJOs from JSON. Without `enableDefaultTyping` they
 * cannot instantiate attacker-chosen classes, so the synthetic ETE
 * fallback over-fires. The configured `deserialization` sink remains
 * unaffected (different sink_type, gated at the sink line).
 */
function findJavaSafeJsonParseSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');
  const safeParse = /\.(?:readValue|fromJson)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    if (!safeParse.test(lines[i])) continue;
    sanitizers.push({
      type: 'java_safe_json_parse',
      method: 'readValue',
      line: i + 1,
      sanitizes: ['external_taint_escape'],
    });
  }
  return sanitizers;
}

/**
 * JS: `JSON.parse(...)` produces only primitives / plain objects. It
 * cannot execute code (unlike `eval` / `Function` / `vm.runInNewContext`,
 * which remain configured sinks).
 */
function findJsSafeJsonParseSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');
  const safeParse = /\bJSON\.parse\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    if (!safeParse.test(lines[i])) continue;
    sanitizers.push({
      type: 'js_safe_json_parse',
      method: 'JSON.parse',
      line: i + 1,
      sanitizes: ['external_taint_escape'],
    });
  }
  return sanitizers;
}

/**
 * JS: one-way crypto hashes destroy original content. Bcrypt/argon2/
 * scrypt/createHash...digest cannot be reversed. The `weak-password-hash`
 * rule fires independently for MD5/SHA1 algorithms.
 */
function findJsCryptoHashSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');
  // bcrypt.hash(...) / bcrypt.hashSync(...)
  // argon2.hash(...)
  // crypto.scrypt(...) / crypto.scryptSync(...)
  // crypto.createHash(...) / hash.digest(...)
  const hashCall = /\b(?:bcrypt|argon2)\s*\.\s*hash(?:Sync)?\s*\(|\bcrypto\s*\.\s*(?:scrypt(?:Sync)?|createHash)\s*\(|\.digest\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    if (!hashCall.test(lines[i])) continue;
    sanitizers.push({
      type: 'js_crypto_hash',
      method: 'hash',
      line: i + 1,
      sanitizes: ['external_taint_escape'],
    });
  }
  return sanitizers;
}

/**
 * JS: Excel-formula-injection sanitizer. Prepending a literal single
 * quote (`'`) to a CSV cell prevents Excel/LibreOffice from interpreting
 * the value as a formula. Scoped to ETE only — the `'` prefix does NOT
 * mitigate xss, command_injection, sql_injection, etc.
 */
function findJsCsvFormulaPrefixSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');
  // Template literal `'${x}...` — leading `'` inside backticks.
  const tickPrefix = /`'\$\{/;
  // Concat form  "'" + x  or  '\'' + x
  const concatPrefix = /["']\\?'["']\s*\+\s*[A-Za-z_]/;
  for (let i = 0; i < lines.length; i++) {
    if (tickPrefix.test(lines[i]) || concatPrefix.test(lines[i])) {
      sanitizers.push({
        type: 'js_csv_formula_prefix',
        method: "'-prefix",
        line: i + 1,
        sanitizes: ['external_taint_escape'],
      });
    }
  }
  return sanitizers;
}

/**
 * JS: user-defined wrapper functions that perform a `.replace(...)`
 * against a recognizable threat-character class. Two-pass:
 *
 *   1. Discover wrappers — `function NAME(...) { ... .replace(/.../...) }`
 *      or arrow form `const NAME = (...) => { ... .replace(...) }`.
 *      Classify by the character class:
 *        - `[&<>"']` → xss + external_taint_escape
 *        - `[\r\n\t]` → log_injection + external_taint_escape
 *   2. For every call site `NAME(...)`, emit a sanitizer at that line
 *      listing the wrapper's kinds.
 *
 * Conservative: requires explicit `.replace` against a recognizable
 * threat-set. Custom wrappers using different escape strategies (e.g.
 * URL encode) are not yet covered.
 */
function findJsWrapperFunctionSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  type WrapperKind = 'xss' | 'log_injection' | 'external_taint_escape';
  const wrappers = new Map<string, Set<WrapperKind>>();

  const fnDeclRe = /\bfunction\s+([A-Za-z_]\w*)\s*\(/;
  const arrowDeclRe = /\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>/;
  // Threat-char classes — must appear inside a .replace(/.../, ...) call.
  const xssCharClass = /\.replace\s*\(\s*\/[^/]*[&<>"'][^/]*\//;
  const crlfCharClass = /\.replace\s*\(\s*\/[^/]*(?:\\r|\\n|\\t)[^/]*\//;

  for (let i = 0; i < lines.length; i++) {
    const m = fnDeclRe.exec(lines[i]) ?? arrowDeclRe.exec(lines[i]);
    if (!m) continue;
    const name = m[1];
    // Scan up to 8 lines for the body's .replace(...) call.
    const body = lines.slice(i, Math.min(lines.length, i + 8)).join('\n');
    const kinds = new Set<WrapperKind>();
    if (xssCharClass.test(body)) {
      kinds.add('xss');
      kinds.add('external_taint_escape');
    }
    if (crlfCharClass.test(body)) {
      kinds.add('log_injection');
      kinds.add('external_taint_escape');
    }
    if (kinds.size > 0) wrappers.set(name, kinds);
  }
  if (wrappers.size === 0) return sanitizers;

  for (let i = 0; i < lines.length; i++) {
    for (const [name, kinds] of wrappers) {
      // Skip the declaration line itself.
      const declSelf = new RegExp(`\\b(?:function|const|let|var)\\s+${name}\\b`);
      if (declSelf.test(lines[i])) continue;
      const callRe = new RegExp(`\\b${name}\\s*\\(`);
      if (!callRe.test(lines[i])) continue;
      sanitizers.push({
        type: 'js_wrapper_function',
        method: name,
        line: i + 1,
        sanitizes: [...kinds],
      });
    }
  }
  return sanitizers;
}

/**
 * JS/TS: SSRF allow-list guard sanitizer (cognium-dev #216 Sprint 75
 * Pattern D).
 *
 * Pattern recognized:
 *
 *   const ALLOWED = new Set(['api.example.com', 'cdn.example.com']);
 *   const url = new URL(req.query.target);
 *   if (!ALLOWED.has(url.hostname)) {
 *       return res.status(400).send('blocked');
 *   }
 *   fetch(url);            // safe — host is one of N fixed strings
 *
 * Or the bare-host shape:
 *
 *   const ALLOWED_HOSTS = ['api.example.com'];
 *   const host = req.query.host;
 *   if (!ALLOWED_HOSTS.includes(host)) {
 *       return res.status(400).end();
 *   }
 *   fetch(`https://${host}/data`);
 *
 * Set-membership against a fixed allow-list proves the value is byte-
 * identical to one of N developer-chosen literals. The detector is
 * **variable-aware**: it captures the guarded variable name AND any
 * upstream aliases (`new URL(<v>).hostname` / `.host`) and only emits
 * sanitizers on subsequent lines in the same block that reference one
 * of those names. This prevents over-suppressing an unrelated unguarded
 * variable later in the same handler (Sprint 74 TP-2 lesson).
 *
 * Existing `sink-filter-pass.ts:775-812` Stage 8 guard handles
 * `open_redirect` / `crlf` at the sink line; this detector expands the
 * mechanism to `ssrf` via the language-sources sanitizer path.
 *
 * Conservative shape:
 *   - guard call must be `<ALLOW>.has(<v>)` or `<ALLOW>.includes(<v>)`
 *     or `<ALLOW>.indexOf(<v>) < 0` (negation `!` or `< 0` required)
 *   - <ALLOW> identifier matches UPPER_SNAKE or allowed|whitelist|...
 *   - body must contain a terminator (return / throw / res.status...end)
 *   - String#includes substring check (`host.includes('example.com')`)
 *     does NOT qualify — TP-2 control proves this.
 */
function findJsSsrfAllowlistGuardSanitizers(code: string): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Build alias map: `const <v> = new URL(<src>).hostname` (or .host).
  // Maps alias name → source identifier (e.g. `url` → req.query.target chain).
  // For the SSRF detector we only need the alias name itself so a Set is
  // sufficient — once an alias is allow-list-checked, the original `new URL`
  // expression input is also considered guarded by transitivity through it.
  const urlAliasToHostAlias = new Map<string, string>();
  const urlAliasDecl =
    /\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*new\s+URL\s*\(\s*([A-Za-z_][\w.[\]'"`]*)\s*\)/;
  const hostAliasDecl =
    /\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.(?:hostname|host)\b/;
  // alias → upstream url-alias
  const hostFromUrl = new Map<string, string>();

  for (const line of lines) {
    const ua = urlAliasDecl.exec(line);
    if (ua) urlAliasToHostAlias.set(ua[1], ua[2]);
    const ha = hostAliasDecl.exec(line);
    if (ha) hostFromUrl.set(ha[1], ha[2]);
  }

  // `ALLOW.has(<v>)`, `ALLOW.includes(<v>)`, `ALLOW.indexOf(<v>)`
  // (with leading `!` for has/includes, or `< 0` for indexOf).
  const allowlistName =
    /^(?:[A-Z][A-Z0-9_]+|.*?(allowed|accepted|whitelist|permitted|valid|approved).*)$/i;
  const guardHas = /if\s*\(\s*!\s*([A-Za-z_]\w*)\s*\.\s*(?:has|includes)\s*\(\s*([A-Za-z_]\w*)(?:\s*\.\s*(?:hostname|host))?\s*\)\s*\)/;
  const guardIndexOf = /if\s*\(\s*([A-Za-z_]\w*)\s*\.\s*indexOf\s*\(\s*([A-Za-z_]\w*)(?:\s*\.\s*(?:hostname|host))?\s*\)\s*<\s*0\s*\)/;
  const terminator =
    /\b(return|throw|res\s*\.\s*status\s*\([^)]*\)\s*\.\s*(?:send|end|json)\s*\()/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let m = guardHas.exec(line);
    let allow: string | null = null;
    let guardedVar: string | null = null;
    if (m) {
      allow = m[1];
      guardedVar = m[2];
    } else {
      m = guardIndexOf.exec(line);
      if (m) {
        allow = m[1];
        guardedVar = m[2];
      }
    }
    if (!allow || !guardedVar) continue;
    if (!allowlistName.test(allow)) continue;

    // Find the guard block opening brace and matching close.
    // The brace may be on the same line (`if (...) {`) or the next.
    // We scan forward for a body terminator within ~25 lines.
    let bodyHasTerminator = false;
    let blockEnd = -1;
    const maxScan = Math.min(lines.length, i + 26);
    // Naive brace tracking: count `{` and `}` starting at the guard line.
    let braceDepth = 0;
    let started = false;
    for (let j = i; j < maxScan; j++) {
      const ln = lines[j];
      for (const ch of ln) {
        if (ch === '{') {
          braceDepth++;
          started = true;
        } else if (ch === '}') {
          braceDepth--;
          if (started && braceDepth === 0) {
            blockEnd = j;
            break;
          }
        }
      }
      if (started && j > i && terminator.test(ln)) bodyHasTerminator = true;
      if (blockEnd !== -1) break;
    }
    if (!started) continue;
    if (blockEnd === -1) continue;
    if (!bodyHasTerminator) continue;

    // Build set of names whose subsequent references are sanitized.
    // Start with guardedVar. When the inline guard reads `.hostname` /
    // `.host` of a known `new URL(<src>)` alias, guardedVar IS the url
    // alias itself (captured by `([A-Za-z_]\w*)` before `(?:\.hostname)?`),
    // so `fetch(url)` later naturally matches.
    const safeNames = new Set<string>([guardedVar]);
    // If guardedVar is itself a host-alias declared as `const h = u.hostname`,
    // the upstream url alias is also safe.
    if (hostFromUrl.has(guardedVar)) {
      safeNames.add(hostFromUrl.get(guardedVar)!);
    }
    // If guardedVar IS a url alias, any host-alias derived from it is safe.
    for (const [hostName, urlName] of hostFromUrl) {
      if (urlName === guardedVar) safeNames.add(hostName);
    }
    // Silence unused-var lint for the upstream-url map: it is intentionally
    // built but not directly consulted in the current emission path
    // (guardedVar covers the url alias because the guard regex matches the
    // url identifier itself when `.hostname` is the inline accessor).
    void urlAliasToHostAlias;

    const refRes = [...safeNames].map(
      (n) => new RegExp(`\\b${n}\\b`),
    );

    // Var-aware emission: lines after the guard block referencing one of
    // the safe names get a sanitizer.
    for (let l = blockEnd + 2; l <= lines.length; l++) {
      const lineText = lines[l - 1];
      if (!refRes.some((re) => re.test(lineText))) continue;
      sanitizers.push({
        type: 'js_ssrf_allowlist_guard',
        method: 'if',
        line: l,
        sanitizes: ['ssrf', 'external_taint_escape'],
      });
    }
  }

  return sanitizers;
}

/**
 * JS/TS: argv-form `execFile`/`spawn`/`execFileSync`/`spawnSync` with
 * a string-literal program and an array literal argv (cognium-dev #216
 * Sprint 77b Pattern X).
 *
 * Pattern recognized:
 *
 *   execFile('echo', ['--', arg], () => {});
 *   spawn('grep', ['--', pattern, '/var/log/app.log']);
 *   execFileSync('cat', [path]);
 *
 * Argv-form exec with a string-literal program splits arguments into
 * the argv slot with no shell interpretation, so a tainted argv element
 * cannot smuggle shell metacharacters into a separate command.
 *
 * The shell-via-argv form `execFile('sh', ['-c', tainted])` is excluded
 * since `-c` re-enables shell parsing of the subsequent argv slot. A
 * tainted-program slot `execFile(prog, [arg])` is NOT matched (TP-2
 * control), nor is the single-string `exec("cmd " + arg)` form (TP-1
 * control — `exec` itself spawns a shell regardless).
 *
 * Emits a `command_injection` + `external_taint_escape` sanitizer at
 * that line.
 */
function findJsArgvFormExecSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // execFile/spawn (+Sync) with a string-literal program and array argv.
  // Quoted program slot, then comma, then `[`.
  const argvExecRe =
    /\b(?:execFile|spawn)(?:Sync)?\s*\(\s*(?:'[^']*'|"[^"]*"|`[^`]*`)\s*,\s*\[/;
  // Shell-via-argv exclusion: program is sh/bash/etc. (possibly with a
  // leading path like /bin/ or /usr/bin/) AND first argv is "-c".
  const shellArgvRe =
    /\b(?:execFile|spawn)(?:Sync)?\s*\(\s*['"`](?:[\w./-]*\/)?(?:sh|bash|zsh|ksh|dash|cmd(?:\.exe)?|powershell|pwsh)['"`]\s*,\s*\[\s*['"`]-c['"`]/;

  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (!argvExecRe.test(text)) continue;
    if (shellArgvRe.test(text)) continue;
    sanitizers.push({
      type: 'js_argv_form_exec',
      method: 'execFile',
      line: i + 1,
      sanitizes: ['command_injection', 'external_taint_escape'],
    });
  }

  return sanitizers;
}

/**
 * JS/TS: parameterized SQL query sanitizer (cognium-dev #216 Sprint 77b
 * Pattern X).
 *
 * Pattern recognized:
 *
 *   await pool.query('SELECT * FROM users WHERE name = $1', [name]);
 *   await conn.execute('SELECT * FROM users WHERE id = ?', [id]);
 *   await client.query(`UPDATE u SET name = $1 WHERE id = $2`, [name, id]);
 *
 * The query string is a STRING-LITERAL (`'...'` / `"..."` / `` `...` ``
 * with no `${}` interpolation) that contains positional placeholders
 * (`$1`-style PostgreSQL or `?` MySQL/SQLite), AND a second argument
 * that begins with `[` (array literal of bound parameters). The driver
 * binds those parameters at the protocol layer rather than splicing
 * them into the SQL text, so the tainted values cannot become SQL.
 *
 * The concat form `pool.query("SELECT * FROM u WHERE n = '" + name + "'")`
 * and the interpolated template literal
 * `` pool.query(`SELECT * FROM u WHERE n = '${name}'`) `` are NOT
 * matched and continue to fire `sql_injection` (TP-1 / TP-2 controls).
 *
 * Emits a `sql_injection` + `external_taint_escape` sanitizer at that
 * line.
 */
function findJsParameterizedSqlSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // `.query(...)` / `.execute(...)` with a non-interpolating string
  // literal containing $N or ? placeholders, followed by `, [`.
  // Single quotes:
  const singleRe =
    /\.\s*(?:query|execute)\s*\(\s*'([^'\\]*(?:\\.[^'\\]*)*)'\s*,\s*\[/;
  // Double quotes:
  const doubleRe =
    /\.\s*(?:query|execute)\s*\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"\s*,\s*\[/;
  // Backticks WITHOUT `${...}` interpolation:
  const tickRe = /\.\s*(?:query|execute)\s*\(\s*`([^`]*)`\s*,\s*\[/;

  const placeholderRe = /(?:\$\d+|\?)/;

  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    let sql: string | null = null;

    const s = singleRe.exec(text);
    if (s) sql = s[1];
    if (sql == null) {
      const d = doubleRe.exec(text);
      if (d) sql = d[1];
    }
    if (sql == null) {
      const t = tickRe.exec(text);
      // Reject template literals that interpolate values.
      if (t && !/\$\{/.test(t[1])) sql = t[1];
    }
    if (sql == null) continue;
    if (!placeholderRe.test(sql)) continue;

    sanitizers.push({
      type: 'js_parameterized_sql',
      method: 'query',
      line: i + 1,
      sanitizes: ['sql_injection', 'external_taint_escape'],
    });
  }

  return sanitizers;
}

/**
 * Java: Path.resolve(...).normalize() + startsWith(ROOT) guard
 * sanitizer (cognium-dev #216 Sprint 76 Pattern B).
 *
 * Pattern recognized:
 *
 *   private static final Path ROOT = Paths.get("/data");
 *   public Path safe(String name) throws Exception {
 *       Path full = ROOT.resolve(name).normalize();
 *       if (!full.startsWith(ROOT)) throw new SecurityException("escape");
 *       return full;
 *   }
 *
 * Note: `.normalize()` alone is not safe (absolute-path arguments
 * replace ROOT entirely); the load-bearing check is the subsequent
 * `<full>.startsWith(<ROOT>)` guard with a terminator. Both the
 * normalize chain and the matching guard must be present to emit
 * the sanitizer.
 *
 * Emits a `path_traversal` + `external_taint_escape` sanitizer at
 * the resolve line and at every subsequent line that references the
 * normalized variable.
 */
function findJavaPathNormalizeStartsWithGuardSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // <var> = <root>.resolve(<arg>).normalize()
  // Also accepts Paths.get(<root>, <arg>).normalize() and
  // Path.of(<root>, <arg>).normalize() chained forms.
  const resolveNormalizeRe =
    /\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*resolve\s*\([^)]*\)\s*\.\s*normalize\s*\(\s*\)/;
  const startsWithGuardRe = (varName: string, rootName: string) =>
    new RegExp(
      `if\\s*\\(\\s*!\\s*${varName}\\s*\\.\\s*startsWith\\s*\\(\\s*${rootName}\\s*\\)\\s*\\)`,
    );
  const terminatorRe = /\b(throw|return)\b/;

  // First pass: find every normalize-chain declaration and remember
  // its line + variable + root identifier.
  const candidates: Array<{
    line: number;
    fullVar: string;
    rootVar: string;
  }> = [];
  for (let i = 0; i < lines.length; i++) {
    const m = resolveNormalizeRe.exec(lines[i]);
    if (!m) continue;
    candidates.push({ line: i + 1, fullVar: m[1], rootVar: m[2] });
  }
  if (candidates.length === 0) return sanitizers;

  // Second pass: confirm each candidate has a matching startsWith
  // guard with a terminator on the same or next line.
  for (const c of candidates) {
    const guardRe = startsWithGuardRe(c.fullVar, c.rootVar);
    let guardLine = -1;
    // Search ahead up to 6 lines for the guard.
    for (
      let l = c.line;
      l < Math.min(lines.length, c.line + 6);
      l++
    ) {
      if (!guardRe.test(lines[l])) continue;
      // The terminator may be on the same line (single-line if) or on
      // the next line (block-form if).
      if (
        terminatorRe.test(lines[l]) ||
        (l + 1 < lines.length && terminatorRe.test(lines[l + 1]))
      ) {
        guardLine = l + 1;
        break;
      }
    }
    if (guardLine < 0) continue;

    // Emit on the resolve line and on every subsequent line that
    // references the normalized variable (covers the `return full;`
    // / `Files.read(full)` / etc. sink sites).
    const varRefRe = new RegExp(`\\b${c.fullVar}\\b`);
    sanitizers.push({
      type: 'java_path_normalize_startswith_guard',
      method: 'normalize',
      line: c.line,
      sanitizes: ['path_traversal', 'external_taint_escape'],
    });
    for (let l = c.line; l < lines.length; l++) {
      if (!varRefRe.test(lines[l])) continue;
      sanitizers.push({
        type: 'java_path_normalize_startswith_guard',
        method: 'normalize',
        line: l + 1,
        sanitizes: ['path_traversal', 'external_taint_escape'],
      });
    }
  }

  return sanitizers;
}

/**
 * Java: inline CRLF/tab-strip wrapper at log-call site (cognium-dev
 * #216 Sprint 76 Pattern B).
 *
 * Pattern recognized:
 *
 *   log.info("event=user_lookup value={}", user.replaceAll("[\\r\\n\\t]", "_"));
 *
 * The CRLF-strip `.replaceAll("[\\r\\n...]", ...)` (or
 * `.replace('\\n'|'\\r'|'\\t', ...)`) must appear as a *direct*
 * argument inside a recognized slf4j/log4j/JUL log-method call on
 * the same source line. A `.replaceAll(...)` on a different earlier
 * line (assigned to a temp variable) is NOT recognized — this
 * preserves TP firing on a separately-tainted log argument.
 *
 * Emits a `log_injection` + `external_taint_escape` sanitizer at
 * that line.
 */
function findJavaInlineCrlfStripLogSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Recognized log method receivers: common slf4j / log4j / JUL
  // identifiers. Restricted set avoids matching arbitrary
  // `something.info(...)` calls.
  const logCallStart =
    /\b(?:log|logger|LOG|LOGGER|slog|LOGGER_)\s*\.\s*(?:info|warn|error|debug|trace|fatal|severe|warning|fine|finer|finest|config)\s*\(/;
  // Threat-char regex literal classes that count as a CRLF strip.
  // Java string-literal escapes use \\r / \\n / \\t inside a "..."
  // source. We accept either character-class `[...\r\n...]` or a
  // single-char `replace('\n', ...)` / `replace('\r', ...)` /
  // `replace('\t', ...)` form.
  const crlfReplaceAll =
    /\.\s*replaceAll\s*\(\s*"\[[^"]*\\\\?[rnt][^"]*\]"/;
  const crlfReplaceChar =
    /\.\s*replace\s*\(\s*'(?:\\\\?[rnt])'\s*,/;

  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (!logCallStart.test(text)) continue;
    if (!crlfReplaceAll.test(text) && !crlfReplaceChar.test(text)) continue;
    sanitizers.push({
      type: 'java_inline_crlf_strip_log',
      method: 'replaceAll',
      line: i + 1,
      sanitizes: ['log_injection', 'external_taint_escape'],
    });
  }

  return sanitizers;
}

/**
 * Java: argv-form `Runtime.getRuntime().exec(new String[]{...})` and
 * `new ProcessBuilder(new String[]{...})` sanitizer (cognium-dev #216
 * Sprint 77a Pattern X).
 *
 * Pattern recognized:
 *
 *   Runtime.getRuntime().exec(new String[]{"echo", "--", arg});
 *   new ProcessBuilder(new String[]{"ls", "-l", dir});
 *
 * Argv-form exec splits the program and arguments into a fixed array
 * with no shell interpretation, so a tainted argv element cannot
 * smuggle shell metacharacters into a separate command. The
 * single-string form `exec("echo " + arg)` is NOT matched and remains
 * a `command_injection` finding (TP-1 control).
 *
 * Emits a `command_injection` + `external_taint_escape` sanitizer at
 * that line.
 */
function findJavaArgvFormExecSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // .exec(new String[]{...}) -- Runtime, Process, Desktop, etc.
  const argvExecRe =
    /\.\s*exec\s*\(\s*new\s+String\s*\[\s*\]\s*\{/;
  // new ProcessBuilder(new String[]{...})
  const argvPbRe =
    /\bnew\s+ProcessBuilder\s*\(\s*new\s+String\s*\[\s*\]\s*\{/;

  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (!argvExecRe.test(text) && !argvPbRe.test(text)) continue;
    sanitizers.push({
      type: 'java_argv_form_exec',
      method: 'exec',
      line: i + 1,
      sanitizes: ['command_injection', 'external_taint_escape'],
    });
  }

  return sanitizers;
}

/**
 * Rust: argv-form `Command::new("literal").arg(...).arg(...)` sanitizer
 * (cognium-dev #216 Sprint 77a Pattern X).
 *
 * Pattern recognized:
 *
 *   Command::new("grep").arg(p).arg("/var/log/app.log").status();
 *
 * Argv-form exec with a string-literal program splits arguments into
 * the argv slot with no shell interpretation. Tainted-program slot
 * `Command::new(prog).arg(...)` is NOT matched (TP-2 control), and
 * explicit shell-via-argv `Command::new("sh").arg("-c")` /
 * `Command::new("bash").arg("-c")` is excluded since `-c` re-enables
 * shell parsing of the tainted slot.
 *
 * Emits a `command_injection` + `external_taint_escape` sanitizer at
 * that line.
 */
function findRustArgvCommandSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Command::new("LITERAL").arg(... -- literal program + at least one .arg().
  const argvCommandRe =
    /\bCommand\s*::\s*new\s*\(\s*"[^"]*"\s*\)\s*\.\s*arg\s*\(/;
  // Shell-via-argv exclusion: Command::new("sh"/"bash"/...).arg("-c"/...)
  const shellArgvRe =
    /\bCommand\s*::\s*new\s*\(\s*"(?:sh|bash|zsh|ksh|dash|cmd(?:\.exe)?|powershell|pwsh)"\s*\)\s*\.\s*arg\s*\(\s*"-c"/;

  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (!argvCommandRe.test(text)) continue;
    if (shellArgvRe.test(text)) continue;
    sanitizers.push({
      type: 'rust_argv_command',
      method: 'arg',
      line: i + 1,
      sanitizes: ['command_injection', 'external_taint_escape'],
    });
  }

  return sanitizers;
}

/**
 * Python: Jinja2 `Environment(..., autoescape=...)` + `.render(...)`
 * autoescape sanitizer (cognium-dev #216 Sprint 77a Pattern X).
 *
 * Pattern recognized:
 *
 *   env = Environment(loader=..., autoescape=select_autoescape(["html"]))
 *   env.get_template("hello.html").render(name=name)
 *
 * Autoescape-on environments html-escape all `.render(**ctx)` output
 * by default, blocking xss. `autoescape=False` / `None` / `0`
 * environments are NOT matched (TP-3 control), and only env vars
 * declared with an explicit `autoescape=` keyword argument are
 * recognized.
 *
 * Emits an `xss` + `external_taint_escape` sanitizer at every
 * `env.get_template(...).render(...)` chained call line.
 */
function findPythonJinjaAutoescapeSanitizers(
  code: string,
): TaintSanitizer[] {
  const sanitizers: TaintSanitizer[] = [];
  const lines = code.split('\n');

  // Find Environment(...) assigned to an identifier and require an
  // autoescape= keyword somewhere on the same line. Two-regex form so
  // nested parens (e.g. PackageLoader("app", "templates")) inside the
  // Environment(...) call don't break the match.
  const envAssignRe =
    /\b([A-Za-z_]\w*)\s*=\s*Environment\s*\(/;
  const autoescapeOnRe = /\bautoescape\s*=/;
  // Explicit "off" forms that must NOT be recognized.
  const autoescapeOffRe = /\bautoescape\s*=\s*(?:False|None|0)\b/;

  const envVars = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const m = envAssignRe.exec(lines[i]);
    if (!m) continue;
    if (!autoescapeOnRe.test(lines[i])) continue;
    if (autoescapeOffRe.test(lines[i])) continue;
    envVars.add(m[1]);
  }
  if (envVars.size === 0) return sanitizers;

  // Emit at every `<env>.get_template(...).render(...)` chain.
  for (const envVar of envVars) {
    const renderChainRe = new RegExp(
      `\\b${envVar}\\s*\\.\\s*get_template\\s*\\([^)]*\\)\\s*\\.\\s*render\\s*\\(`,
    );
    for (let i = 0; i < lines.length; i++) {
      if (!renderChainRe.test(lines[i])) continue;
      sanitizers.push({
        type: 'python_jinja_autoescape',
        method: 'render',
        line: i + 1,
        sanitizes: ['xss', 'external_taint_escape'],
      });
    }
  }

  return sanitizers;
}

// ---------------------------------------------------------------------------
// Sprint 70 (#151) — external-secret-exfiltration composed-flow detection.
//
// Models the trust-corpus FN-TQ-01 shape: an env-read secret variable that
// is transmitted in the BODY of an outbound HTTPS request to a non-internal
// host. The detector is intentionally narrow:
//
//   - SOURCE: env read assigned to a local var (Python `os.environ` /
//     `os.getenv`, JS/TS `process.env.X`, Go `os.Getenv`).
//   - SINK: HTTP POST/PUT/PATCH/DELETE/request to a literal URL whose host
//     is NOT internal (loopback, RFC1918, `.internal.`, `.local`, `.lan`,
//     `.corp`, or single-label intranet).
//   - GATE: secret var (or a JS carrier var defined from a secret) appears
//     in the request body / form args, NOT exclusively in headers /
//     Authorization context.
//
// CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).
// ---------------------------------------------------------------------------

function collectEnvSecretVars(lines: string[], language: string): Map<string, number> {
  const out = new Map<string, number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (language === 'python') {
      // var = os.environ["..."] | os.environ.get(...) | os.getenv(...)
      const m = line.match(/^\s*(\w+)\s*=\s*os\.(?:environ\s*[\[.]|getenv\b)/);
      if (m) out.set(m[1], i + 1);
    } else if (language === 'javascript' || language === 'typescript') {
      // const/let/var X = process.env.NAME | process.env["NAME"]
      const m = line.match(/(?:^|\s|;)(?:const|let|var)\s+(\w+)\s*=\s*process\.env\b/);
      if (m) out.set(m[1], i + 1);
    } else if (language === 'go') {
      // X := os.Getenv("...")  or  X = os.Getenv(...)
      const m = line.match(/^\s*(\w+)\s*:?=\s*os\.Getenv\s*\(/);
      if (m) out.set(m[1], i + 1);
    }
  }
  return out;
}

function isExternalHostUrl(url: string): boolean {
  const lower = url.toLowerCase();
  if (!/^https?:\/\//.test(lower)) return false;
  const host = lower.replace(/^https?:\/\//, '').split(/[/?#:]/)[0];
  if (!host) return false;
  if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '::1') return false;
  if (/^10\./.test(host)) return false;
  if (/^192\.168\./.test(host)) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
  // Common internal markers
  if (host.includes('.internal.') || host.endsWith('.internal') || host.startsWith('internal.')) return false;
  if (host.endsWith('.local') || host.endsWith('.lan') || host.endsWith('.corp')) return false;
  // Single-label hostnames (no dot) are intranet
  if (!host.includes('.')) return false;
  return true;
}

// Walk forward from `start` (first char inside open paren) until the matching
// close paren is found. Honors string literals to avoid false matches.
function findBalancedCallEnd(code: string, start: number): number {
  let depth = 1;
  let i = start;
  let inStr: '"' | "'" | '`' | null = null;
  while (i < code.length) {
    const ch = code[i];
    if (inStr) {
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === inStr) inStr = null;
    } else {
      if (ch === '"' || ch === "'" || ch === '`') inStr = ch;
      else if (ch === '(') depth++;
      else if (ch === ')') {
        depth--;
        if (depth === 0) return i;
      }
    }
    i++;
  }
  return -1;
}

// Walk forward from `start` until a top-level comma or end-of-args is found.
// Used to extract a kwarg's value substring (Python `headers=…` etc.).
function findKwargValueEnd(s: string, start: number): number {
  let depth = 0;
  let inStr: '"' | "'" | '`' | null = null;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inStr = ch as '"' | "'" | '`';
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) return i;
      depth--;
    } else if (ch === ',' && depth === 0) {
      return i;
    }
  }
  return s.length;
}

function lineOfCharIndex(code: string, charIdx: number): number {
  let line = 1;
  for (let i = 0; i < charIdx && i < code.length; i++) {
    if (code[i] === '\n') line++;
  }
  return line;
}

function makeExfilFinding(
  file: string,
  line: number,
  snippet: string,
  fired: string[],
  receiver: string
): SastFinding {
  return {
    id: `external-secret-exfiltration-${file}-${line}`,
    pass: 'language-sources',
    category: 'security',
    rule_id: 'external-secret-exfiltration',
    cwe: 'CWE-200',
    severity: 'high',
    level: 'error',
    message: `Environment secret(s) ${fired.join(', ')} transmitted in request body to external host via ${receiver}`,
    file,
    line,
    snippet: snippet.substring(0, 120),
  };
}

export function findExternalSecretExfiltrationFindings(
  code: string,
  file: string,
  language: string
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const secretVars = collectEnvSecretVars(lines, language);
  if (secretVars.size === 0) return out;

  if (language === 'python') {
    out.push(...findPythonExfilCalls(code, file, secretVars));
  } else if (language === 'javascript' || language === 'typescript') {
    out.push(...findJavaScriptExfilCalls(code, file, secretVars));
  } else if (language === 'go') {
    out.push(...findGoExfilCalls(code, file, secretVars));
  }
  return out;
}

function findPythonExfilCalls(
  code: string,
  file: string,
  secretVars: Map<string, number>
): SastFinding[] {
  const out: SastFinding[] = [];
  const callRe = /\b(requests|httpx)\.(post|put|patch|delete|request)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(code))) {
    const argStart = m.index + m[0].length;
    const argEnd = findBalancedCallEnd(code, argStart);
    if (argEnd < 0) continue;
    const args = code.slice(argStart, argEnd);
    // First arg is URL literal (skip leading whitespace/newlines)
    const urlMatch = args.match(/^\s*["']([^"']+)["']/);
    if (!urlMatch) continue;
    if (!isExternalHostUrl(urlMatch[1])) continue;

    // Split into body-context vs headers-context
    const headersIdx = args.search(/\bheaders\s*=/);
    let headersStr = '';
    let bodyStr = args;
    if (headersIdx >= 0) {
      const eqIdx = args.indexOf('=', headersIdx);
      const valueStart = eqIdx + 1;
      const headersEnd = findKwargValueEnd(args, valueStart);
      headersStr = args.slice(valueStart, headersEnd);
      bodyStr = args.slice(0, headersIdx) + ' ' + args.slice(headersEnd);
    }

    const fired: string[] = [];
    for (const v of secretVars.keys()) {
      const re = new RegExp(`\\b${v}\\b`);
      if (re.test(bodyStr) && !re.test(headersStr)) fired.push(v);
    }
    if (fired.length > 0) {
      const line = lineOfCharIndex(code, m.index);
      out.push(
        makeExfilFinding(file, line, code.slice(m.index, Math.min(argEnd + 1, m.index + 120)), fired, `${m[1]}.${m[2]}`)
      );
    }
  }
  return out;
}

function findJavaScriptExfilCalls(
  code: string,
  file: string,
  secretVars: Map<string, number>
): SastFinding[] {
  const out: SastFinding[] = [];
  const allLines = code.split('\n');

  // Build carrier vars: any `const|let|var NAME = …<secret-ref>…`
  const carriers = new Set<string>();
  const carrierRe = /(?:^|[\s;{])(?:const|let|var)\s+(\w+)\s*=\s*([^;\n]+)/g;
  let cm: RegExpExecArray | null;
  while ((cm = carrierRe.exec(code))) {
    const name = cm[1];
    const rhs = cm[2];
    for (const v of secretVars.keys()) {
      if (new RegExp(`\\b${v}\\b`).test(rhs)) {
        carriers.add(name);
        break;
      }
    }
  }
  const taintedRefs = new Set<string>([...secretVars.keys(), ...carriers]);

  // Match common outbound network call shapes
  const networkRe =
    /\b(https?\.(?:request|get)|fetch|axios\.(?:post|put|patch|request|delete))\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = networkRe.exec(code))) {
    const argStart = m.index + m[0].length;
    const argEnd = findBalancedCallEnd(code, argStart);
    if (argEnd < 0) continue;
    const args = code.slice(argStart, argEnd);
    // URL literal (string or template)
    const urlMatch = args.match(/^\s*(?:["']([^"']+)["']|`([^`$]+)`)/);
    if (!urlMatch) continue;
    const url = urlMatch[1] || urlMatch[2];
    if (!isExternalHostUrl(url)) continue;

    // Split body vs headers within the call args. JS uses object literal
    // fields `headers: {…}` and (optionally) `body: …`.
    const headersIdx = args.search(/\bheaders\s*:/);
    let headersStr = '';
    let restStr = args;
    if (headersIdx >= 0) {
      const valueStart = args.indexOf(':', headersIdx) + 1;
      const headersEnd = findKwargValueEnd(args, valueStart);
      headersStr = args.slice(valueStart, headersEnd);
      restStr = args.slice(0, headersIdx) + ' ' + args.slice(headersEnd);
    }

    const fired = new Set<string>();
    for (const v of taintedRefs) {
      const re = new RegExp(`\\b${v}\\b`);
      if (re.test(restStr) && !re.test(headersStr)) fired.add(v);
    }

    // Forward scan: req.write(VAR) / req.end(VAR) within next 20 lines
    const callLine = lineOfCharIndex(code, m.index);
    const windowEnd = Math.min(allLines.length, callLine + 20);
    const writeWindow = allLines.slice(callLine, windowEnd).join('\n');
    const writeRe = /\b\w+\.(?:write|end)\s*\(\s*(\w+)/g;
    let wm: RegExpExecArray | null;
    while ((wm = writeRe.exec(writeWindow))) {
      if (taintedRefs.has(wm[1])) fired.add(wm[1]);
    }

    if (fired.size > 0) {
      out.push(
        makeExfilFinding(
          file,
          callLine,
          code.slice(m.index, Math.min(argEnd + 1, m.index + 120)),
          [...fired],
          m[1]
        )
      );
    }
  }
  return out;
}

function findGoExfilCalls(
  code: string,
  file: string,
  secretVars: Map<string, number>
): SastFinding[] {
  const out: SastFinding[] = [];
  const patterns: Array<{ re: RegExp; urlArgIndex: 0 | 1; receiver: string }> = [
    { re: /\bhttp\.PostForm\s*\(/g, urlArgIndex: 0, receiver: 'http.PostForm' },
    { re: /\bhttp\.Post\s*\(/g, urlArgIndex: 0, receiver: 'http.Post' },
    { re: /\bhttp\.NewRequest\s*\(/g, urlArgIndex: 1, receiver: 'http.NewRequest' },
  ];

  for (const { re, urlArgIndex, receiver } of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(code))) {
      const argStart = m.index + m[0].length;
      const argEnd = findBalancedCallEnd(code, argStart);
      if (argEnd < 0) continue;
      const args = code.slice(argStart, argEnd);

      // Skip the leading non-URL arg(s) when needed
      let urlSearchSlice = args;
      if (urlArgIndex === 1) {
        const firstComma = findKwargValueEnd(args, 0);
        if (firstComma >= args.length) continue;
        urlSearchSlice = args.slice(firstComma + 1);
      }
      const urlMatch = urlSearchSlice.match(/^\s*["`]([^"`]+)["`]/);
      if (!urlMatch) continue;
      if (!isExternalHostUrl(urlMatch[1])) continue;

      const fired: string[] = [];
      for (const v of secretVars.keys()) {
        if (new RegExp(`\\b${v}\\b`).test(args)) fired.push(v);
      }
      if (fired.length > 0) {
        const line = lineOfCharIndex(code, m.index);
        out.push(
          makeExfilFinding(file, line, code.slice(m.index, Math.min(argEnd + 1, m.index + 120)), fired, receiver)
        );
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sprint 71 (#190) — Python pattern-finding extensions for cells where the
// existing detectors only cover non-Python shapes.
// ---------------------------------------------------------------------------

/**
 * Emit Python `cors-wildcard-origin`, `xfo-csp-mismatch`, and
 * `tls-verify-disabled` findings for the subscript-assignment / context-
 * assignment shapes that the language-agnostic detectors miss.
 *
 *   cors-wildcard-origin:
 *     `resp.headers['Access-Control-Allow-Origin'] = '*'`
 *
 *   xfo-csp-mismatch:
 *     `resp.headers['X-Frame-Options'] = 'DENY' | 'SAMEORIGIN'`
 *     correlated with
 *     `resp.headers['Content-Security-Policy'] = '... frame-ancestors *|http* ...'`
 *
 *   tls-verify-disabled:
 *     `ctx.verify_mode = ssl.CERT_NONE`  OR
 *     `ctx.check_hostname = False`
 */
export function findPythonPatternFindings(code: string, file: string): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  // Subscript-style header assignment: `<recv>.headers['NAME'] = 'VAL'`
  // `NAME` is any quoted key (single or double). `VAL` is anything to EOL.
  const subscriptHeaderRe = /\.headers\s*\[\s*['"]([^'"]+)['"]\s*\]\s*=\s*(.+)$/;

  // For xfo-csp-mismatch correlation we collect XFO and CSP values per file.
  type HeaderHit = { line: number; value: string };
  const xfoHits: HeaderHit[] = [];
  const cspHits: HeaderHit[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const lineNumber = i + 1;

    const sm = trimmed.match(subscriptHeaderRe);
    if (sm) {
      const headerName = sm[1];
      const rhs = sm[2].trim();
      const headerLower = headerName.toLowerCase();

      // 1. cors-wildcard-origin
      if (headerLower === 'access-control-allow-origin') {
        // Wildcard literal — single, double, or echoed back any-origin var.
        // Conservative: only fire on a bare '*' literal.
        const valMatch = rhs.match(/^['"]\*['"]/);
        if (valMatch) {
          out.push({
            id: `cors-wildcard-origin-${file}-${lineNumber}`,
            pass: 'language-sources',
            category: 'security',
            rule_id: 'cors-wildcard-origin',
            cwe: 'CWE-942',
            severity: 'medium',
            level: 'warning',
            message:
              "CORS Access-Control-Allow-Origin set to wildcard '*': any origin may read responses",
            file,
            line: lineNumber,
            snippet: trimmed.substring(0, 100),
          });
        }
      }

      // Collect for xfo-csp correlation
      if (headerLower === 'x-frame-options') {
        xfoHits.push({ line: lineNumber, value: rhs });
      } else if (headerLower === 'content-security-policy') {
        cspHits.push({ line: lineNumber, value: rhs });
      }
    }

    // 3. tls-verify-disabled (ssl context post-create mutation)
    //    `<x>.verify_mode = ssl.CERT_NONE`   OR
    //    `<x>.check_hostname = False`
    if (/\bverify_mode\s*=\s*ssl\.CERT_NONE\b/.test(trimmed)) {
      out.push({
        id: `tls-verify-disabled-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'tls-verify-disabled',
        cwe: 'CWE-295',
        severity: 'high',
        level: 'error',
        message: 'TLS certificate verification disabled: ssl context verify_mode set to CERT_NONE',
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 100),
      });
    } else if (/\bcheck_hostname\s*=\s*False\b/.test(trimmed)) {
      out.push({
        id: `tls-verify-disabled-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'tls-verify-disabled',
        cwe: 'CWE-295',
        severity: 'high',
        level: 'error',
        message: 'TLS hostname verification disabled: ssl context check_hostname set to False',
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 100),
      });
    }
  }

  // 2. xfo-csp-mismatch — fire iff at least one XFO=DENY|SAMEORIGIN and at
  //    least one CSP with permissive `frame-ancestors` (wildcard or http*).
  //    The mismatch indicates the dev set XFO to deny framing but a
  //    permissive CSP `frame-ancestors` directive overrides XFO on modern
  //    browsers (CSP wins).
  const restrictiveXfo = xfoHits.find(h =>
    /['"](?:DENY|SAMEORIGIN)['"]/i.test(h.value)
  );
  const permissiveCsp = cspHits.find(h => {
    // Extract the policy string body.
    const pm = h.value.match(/['"]([^'"]+)['"]/);
    if (!pm) return false;
    const policy = pm[1];
    const faMatch = policy.match(/frame-ancestors\s+([^;]+)/i);
    if (!faMatch) return false;
    const directive = faMatch[1].trim();
    // Permissive iff bare *, contains http://, or contains https://* wildcard host
    return /(^|\s)\*(\s|$)/.test(directive) || /\bhttps?:\/\//i.test(directive);
  });
  if (restrictiveXfo && permissiveCsp) {
    out.push({
      id: `xfo-csp-mismatch-${file}-${restrictiveXfo.line}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xfo-csp-mismatch',
      cwe: 'CWE-1021',
      severity: 'medium',
      level: 'warning',
      message:
        'X-Frame-Options/CSP frame-ancestors mismatch: XFO restricts framing but CSP frame-ancestors is permissive (CSP overrides on modern browsers)',
      file,
      line: restrictiveXfo.line,
      snippet: lines[restrictiveXfo.line - 1].trim().substring(0, 100),
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Sprint 71 (#190) — Rust pattern-finding extensions.
// ---------------------------------------------------------------------------

/**
 * Emit Rust `tls-verify-disabled` for `reqwest`-style builders that opt out
 * of certificate / hostname validation:
 *
 *   `.danger_accept_invalid_certs(true)`
 *   `.danger_accept_invalid_hostnames(true)`
 *
 * Conservative: requires the literal `true` argument; `false` (re-enable) is
 * benign and is ignored.
 */
export function findRustPatternFindings(code: string, file: string): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const re = /\.\s*(danger_accept_invalid_certs|danger_accept_invalid_hostnames)\s*\(\s*true\s*\)/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    const m = trimmed.match(re);
    if (!m) continue;
    const method = m[1];
    const what = method === 'danger_accept_invalid_certs' ? 'certificate' : 'hostname';
    out.push({
      id: `tls-verify-disabled-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'tls-verify-disabled',
      cwe: 'CWE-295',
      severity: 'high',
      level: 'error',
      message: `TLS ${what} verification disabled: reqwest builder ${method}(true)`,
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sprint 78 (#190) — Tier-2 misconfig pattern extensions for Rust, Java, Go,
// and JS that the dedicated misconfig passes don't yet recognize.
// ---------------------------------------------------------------------------

/**
 * Rust `hardcoded-credential` (CWE-798). Pattern:
 *   `(pub|const|static) <NAME>: &str = "literal";` where NAME matches
 *   /api[_]?key|secret|token|password|passwd|pwd|auth/i and the literal is
 *   non-trivial (length > 8 and not a placeholder).
 */
export function findRustHardcodedCredentialFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const re =
    /\b(?:pub\s+)?(?:const|static)\s+([A-Z][A-Z0-9_]*)\s*:\s*&\s*'?[a-z_]*\s*str\s*=\s*"([^"]+)"/;
  const nameRe = /(?:^|_)(?:API[_]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|AUTH)(?:_|$)/i;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    const m = trimmed.match(re);
    if (!m) continue;
    const name = m[1];
    const value = m[2];
    if (!nameRe.test(name)) continue;
    if (value.length < 8) continue;
    if (/^(?:xxx|todo|fixme|placeholder|changeme)/i.test(value)) continue;
    out.push({
      id: `hardcoded-credential-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'hardcoded-credential',
      cwe: 'CWE-798',
      severity: 'high',
      level: 'error',
      message: `Hardcoded credential: const ${name} contains a literal secret value`,
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Rust `insecure-cookie` (CWE-1004 / CWE-614). Pattern:
 *   `Cookie::build(...)` chain that explicitly calls `.secure(false)` or
 *   `.http_only(false)` (or both). The dedicated `insecure-cookie-pass.ts`
 *   handles the `format!("Set-Cookie: ...")` shape but not the actix-web
 *   builder chain.
 */
export function findRustInsecureCookieFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const builderRe = /\bCookie\s*::\s*build\s*\(/;
  const insecureFlagRe = /\.\s*(?:secure|http_only)\s*\(\s*false\s*\)/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    if (!builderRe.test(trimmed)) continue;
    if (!insecureFlagRe.test(trimmed)) continue;
    out.push({
      id: `insecure-cookie-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'insecure-cookie',
      cwe: 'CWE-1004',
      severity: 'medium',
      level: 'warning',
      message:
        'Insecure cookie: Cookie::build chain disables Secure / HttpOnly flag(s)',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Rust `jwt-verify-disabled` (CWE-347). Pattern:
 *   `.insecure_disable_signature_validation()` method call on a
 *   jsonwebtoken `Validation` value. Any presence of this method
 *   disables the signature check.
 */
export function findRustJwtVerifyDisabledFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const re = /\.\s*insecure_disable_signature_validation\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    if (!re.test(trimmed)) continue;
    out.push({
      id: `jwt-verify-disabled-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'jwt-verify-disabled',
      cwe: 'CWE-347',
      severity: 'critical',
      level: 'error',
      message:
        'JWT signature verification disabled: ' +
        'Validation::insecure_disable_signature_validation() forfeits signature enforcement',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Rust `weak-crypto` (CWE-327). Pattern (raw ECB via `aes` crate):
 *   any line that calls `.encrypt_block(` or `.decrypt_block(` on a
 *   block-cipher receiver constructed via `Aes128::new` / `Aes192::new` /
 *   `Aes256::new` / `Aes128Ecb` / `Aes256Ecb`. We collect the cipher
 *   constructor lines in a first pass (variable name → seen) and emit
 *   on every `.encrypt_block(` / `.decrypt_block(` line in the same file.
 *
 *   The wrapped CBC/GCM/CTR forms go through `Cbc::<Aes128, ...>::new`
 *   or `Aes128Gcm::new` — those do NOT call `.encrypt_block` directly
 *   and so are not matched.
 */
export function findRustWeakCryptoEcbFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const ctorRe = /\bAes(?:128|192|256)(?:Ecb)?\s*::\s*new\s*\(/;
  const blockOpRe = /\.\s*(encrypt_block|decrypt_block)\s*\(/;
  // First: confirm the file uses raw block-cipher construction (Aes*::new)
  // — without that, a stray `.encrypt_block(` on some other type isn't
  // necessarily ECB.
  let sawCtor = false;
  for (const line of lines) {
    if (ctorRe.test(line)) { sawCtor = true; break; }
  }
  if (!sawCtor) return out;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    if (!blockOpRe.test(trimmed)) continue;
    out.push({
      id: `weak-crypto-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'weak-crypto',
      cwe: 'CWE-327',
      severity: 'high',
      level: 'error',
      message:
        'Weak crypto (ECB mode): raw Aes::encrypt_block/decrypt_block ' +
        'leaks repeating-block patterns. Use AES-GCM, AES-CTR, or ' +
        'AES-CBC with an HMAC.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Java pattern findings — Sprint 78 (#190):
 *   - `jwt-verify-disabled` (CWE-347): bare `JWT.decode(<token>)` on the
 *     auth0 `com.auth0.jwt.JWT` class. `decode` is documented as
 *     "decode the token without performing any verification"; only
 *     `JWT.require(...).build().verify(token)` enforces the signature.
 *   - `tls-verify-disabled` (CWE-295): anonymous `X509TrustManager`
 *     implementation whose `checkServerTrusted` body is empty
 *     (returns void without raising). This trust-nothing implementation
 *     accepts every certificate.
 */
export function findJavaPatternFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  // jwt-verify-disabled: `JWT.decode(<expr>)`. Anchored to the `JWT.`
  // receiver to avoid matching unrelated `decode(` calls on Base64,
  // URLDecoder, etc. Guarded against the safer `JWT.require(...).build()
  // .verify(...)` chain by requiring `decode` to appear without
  // `.verify(` later on the same line.
  const jwtDecodeRe = /\bJWT\s*\.\s*decode\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    if (!jwtDecodeRe.test(trimmed)) continue;
    if (/\.\s*verify\s*\(/.test(trimmed)) continue;
    out.push({
      id: `jwt-verify-disabled-${file}-${i + 1}-decode`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'jwt-verify-disabled',
      cwe: 'CWE-347',
      severity: 'critical',
      level: 'error',
      message:
        'JWT signature not verified: auth0 `JWT.decode(token)` parses ' +
        'without checking the signature. Use `JWT.require(<algorithm>)' +
        '.build().verify(token)` to enforce verification.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }

  // tls-verify-disabled: anonymous X509TrustManager with empty
  // checkServerTrusted body. Two-pass: locate the anonymous-class start
  // line (`new X509TrustManager() {`), then scan ahead for the
  // `checkServerTrusted(...)` method signature whose `{...}` body is
  // empty (no `throw`, no `if`).
  const anonStartRe = /\bnew\s+X509TrustManager\s*\(\s*\)\s*\{/;
  const checkServerSig = /\bcheckServerTrusted\s*\([^)]*\)\s*(?:throws\s+[^\{]*)?\{\s*\}/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!anonStartRe.test(raw)) continue;
    // Scan up to 15 lines ahead for the empty-body checkServerTrusted.
    const end = Math.min(lines.length, i + 16);
    let foundAt = -1;
    for (let j = i; j < end; j++) {
      if (checkServerSig.test(lines[j])) {
        foundAt = j;
        break;
      }
    }
    if (foundAt < 0) continue;
    out.push({
      id: `tls-verify-disabled-${file}-${foundAt + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'tls-verify-disabled',
      cwe: 'CWE-295',
      severity: 'high',
      level: 'error',
      message:
        'TLS certificate verification disabled: anonymous X509TrustManager ' +
        'with empty checkServerTrusted body accepts every certificate.',
      file,
      line: foundAt + 1,
      snippet: lines[foundAt].trim().substring(0, 100),
    });
  }

  return out;
}

/**
 * Go pattern findings — Sprint 78 (#190):
 *   - `weak-crypto` (CWE-327): raw ECB usage via `aes.NewCipher(...)`
 *     followed by a direct `<cipher>.Encrypt(` / `.Decrypt(` call on the
 *     constructed value (no `cipher.NewCBCEncrypter` / `NewGCM` / `NewCTR`
 *     wrapper). The Go stdlib `aes.Cipher` exposes `Encrypt` / `Decrypt`
 *     that operate on a single 16-byte block — calling these directly is
 *     ECB mode.
 *
 *   Algorithm:
 *     1. Collect every `<v>, _ := aes.NewCipher(...)` cipher variable.
 *     2. If the file contains a `cipher.NewGCM(<v>)` / `cipher.NewCBC*(<v>)`
 *        / `cipher.NewCTR(<v>)` wrapping line for that variable, skip it
 *        (wrapped mode is not ECB).
 *     3. Otherwise emit on every `<v>.Encrypt(` / `<v>.Decrypt(` line.
 */
export function findGoPatternFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const cipherVars = new Set<string>();
  const ctorRe =
    /\b([a-zA-Z_]\w*)\s*(?:,\s*[a-zA-Z_]\w*)?\s*:?=\s*aes\.NewCipher\s*\(/;
  for (const line of lines) {
    const m = line.match(ctorRe);
    if (m) cipherVars.add(m[1]);
  }
  if (cipherVars.size === 0) return out;
  // Drop wrapped ciphers (CBC/GCM/CTR/OFB/CFB) — those are not ECB.
  for (const v of Array.from(cipherVars)) {
    const wrapRe = new RegExp(
      `\\bcipher\\.New(?:GCM|CBCEncrypter|CBCDecrypter|CTR|OFB|CFBEncrypter|CFBDecrypter)\\s*\\(\\s*${v}\\b`,
    );
    for (const line of lines) {
      if (wrapRe.test(line)) { cipherVars.delete(v); break; }
    }
  }
  if (cipherVars.size === 0) return out;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    for (const v of cipherVars) {
      const opRe = new RegExp(`\\b${v}\\s*\\.\\s*(?:Encrypt|Decrypt)\\s*\\(`);
      if (!opRe.test(trimmed)) continue;
      out.push({
        id: `weak-crypto-${file}-${i + 1}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'weak-crypto',
        cwe: 'CWE-327',
        severity: 'high',
        level: 'error',
        message:
          'Weak crypto (ECB mode): raw aes.Cipher.Encrypt/Decrypt on a ' +
          'block leaks repeating-block patterns. Wrap with cipher.NewGCM, ' +
          'cipher.NewCTR, or cipher.NewCBCEncrypter + HMAC.',
        file,
        line: i + 1,
        snippet: trimmed.substring(0, 100),
      });
      break;
    }
  }
  return out;
}

/**
 * JS pattern findings — Sprint 78 (#190):
 *   - `xml-entity-expansion` (CWE-611 / CWE-776): libxmljs `parseXml`
 *     (and `parseXmlString`) called with `{ noent: true }` resolves
 *     external entities, enabling XXE / billion-laughs. The default is
 *     `noent: false`; only the explicit-true form is unsafe.
 */
export function findJsPatternFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');
  const parseRe = /\blibxml(?:js)?\s*\.\s*parseXml(?:String)?\s*\(/;
  const noentTrueRe = /\bnoent\s*:\s*true\b/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    if (!parseRe.test(trimmed)) continue;
    if (!noentTrueRe.test(trimmed)) continue;
    out.push({
      id: `xml-entity-expansion-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xml-entity-expansion',
      cwe: 'CWE-611',
      severity: 'high',
      level: 'error',
      message:
        'XML external entity resolution enabled: libxmljs parseXml ' +
        'called with `noent: true` resolves external entities (XXE / ' +
        'billion-laughs). Omit the flag or set `noent: false`.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sprint 81 (#189) — xss-cluster FN coverage. Six per-language pattern
// detectors that emit SastFinding{rule_id:'xss'} directly, bypassing the
// source→sink→flow construction where the engine can't yet build a flow
// (e.g. Python string-concat / f-string, Java receiver-chain typing).
// ---------------------------------------------------------------------------

/**
 * Go xss — `fmt.Fprint(f|ln)?(w, ...)` writing tainted data directly to an
 * `http.ResponseWriter`. Two-pass:
 *
 *   1. Discover ResponseWriter parameter names by scanning function
 *      signatures `(<name> http.ResponseWriter, ...)`.
 *   2. For every `fmt.Fprint(f|ln)?(<name>, <format>, <args...>)` whose
 *      first argument matches a discovered name, emit xss UNLESS one of
 *      the args is wrapped in a recognized HTML escaper
 *      (`html.EscapeString` / `template.HTMLEscapeString` /
 *      `template.HTMLEscaper`).
 */
export function findGoXssFindings(code: string, file: string): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const rwNames = new Set<string>();
  const sigRe = /\(\s*([A-Za-z_]\w*)\s+http\.ResponseWriter\b/g;
  for (const line of lines) {
    let m: RegExpExecArray | null;
    sigRe.lastIndex = 0;
    while ((m = sigRe.exec(line)) !== null) rwNames.add(m[1]);
  }
  if (rwNames.size === 0) return out;

  const escaperRe =
    /\b(?:html|template)\.(?:EscapeString|HTMLEscapeString|HTMLEscaper|JSEscapeString|URLQueryEscaper)\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    const callRe =
      /\bfmt\.Fprint(?:f|ln)?\s*\(\s*([A-Za-z_]\w*)\s*,\s*([\s\S]*)\)\s*(?:\/\/.*)?$/;
    const m = trimmed.match(callRe);
    if (!m) continue;
    if (!rwNames.has(m[1])) continue;
    const tail = m[2];
    if (escaperRe.test(tail)) continue;
    // Require at least one identifier in tail outside string literals.
    if (!/[A-Za-z_]\w*/.test(tail.replace(/"[^"]*"|`[^`]*`/g, ''))) continue;
    out.push({
      id: `xss-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xss',
      cwe: 'CWE-79',
      severity: 'high',
      level: 'error',
      message:
        'Reflected XSS: fmt.Fprint writes data to http.ResponseWriter ' +
        'without HTML escaping. Wrap user-controlled args with ' +
        'html.EscapeString / template.HTMLEscapeString.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Java xss — `<recv>.getWriter().{print,println,write,printf,format,append}
 * (<arg>)` chained call where `<recv>` is typed `HttpServletResponse`.
 * The receiver-chain form bypasses the configured `PrintWriter.print`
 * sink because the engine doesn't yet trace `HttpServletResponse
 * .getWriter()` → `PrintWriter` type resolution.
 *
 * Conservative: only fires when the receiver token matches a parameter
 * named with the `HttpServletResponse` type AND no recognized HTML
 * encoder wraps the argument.
 */
export function findJavaResponseWriterXssFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const respNames = new Set<string>();
  const sigRe = /\bHttpServletResponse\s+([A-Za-z_]\w*)\b/g;
  for (const line of lines) {
    let m: RegExpExecArray | null;
    sigRe.lastIndex = 0;
    while ((m = sigRe.exec(line)) !== null) respNames.add(m[1]);
  }
  if (respNames.size === 0) return out;

  const safeWrapRe =
    /\b(?:Encode\.(?:forHtml|forHtmlAttribute|forHtmlContent|forJavaScript)|StringEscapeUtils\.escape(?:Html3|Html4|EcmaScript|Xml)|HtmlUtils\.htmlEscape(?:Decimal|Hex)?|Escaper\.escapeHtml|HtmlEscapers\.(?:escapeHtml|htmlEscaper)|Encoder\.encodeForHTML(?:Attribute)?|Jsoup\.clean)\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    const chainRe =
      /\b([A-Za-z_]\w*)\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(print|println|write|printf|format|append)\s*\(([\s\S]*)\)\s*;?\s*(?:\/\/.*)?$/;
    const m = trimmed.match(chainRe);
    if (!m) continue;
    const recv = m[1];
    if (!respNames.has(recv)) continue;
    const args = m[3];
    if (safeWrapRe.test(args)) continue;
    // Skip when args is a pure string-literal call like `print("hello")`.
    // Anything else (`+`-concat, bare identifier, method call) is a write
    // of dynamic content that should have gone through an HTML encoder.
    const argsTrim = args.trim();
    if (/^"(?:\\.|[^"\\])*"$/.test(argsTrim)) continue;
    if (!/[A-Za-z_]\w*/.test(argsTrim)) continue;
    out.push({
      id: `xss-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xss',
      cwe: 'CWE-79',
      severity: 'high',
      level: 'error',
      message:
        'Reflected XSS: HttpServletResponse.getWriter().' +
        m[2] +
        '(...) writes data to the response without HTML escaping. ' +
        'Wrap user-controlled values with OWASP Encode.forHtml / ' +
        'StringEscapeUtils.escapeHtml4 / Jsoup.clean.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Vue xss — `template: '<...v-html="<var>"...>'` directive binding to a
 * variable that is sourced from a tainted location (URLSearchParams,
 * location.search/hash, route.query/params, fetch, etc.).
 *
 * Conservative: when the bound variable is a literal initializer
 * (`<var>: 'static'`) or sourced from a non-recognized location, no
 * finding is emitted.
 */
export function findJsVueVHtmlXssFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const sourceRe =
    /\b(?:URLSearchParams|location\s*\.\s*(?:search|hash|href|pathname)|window\s*\.\s*location|route\s*\.\s*(?:query|params)|router\s*\.\s*(?:currentRoute|query)|\$route\s*\.\s*(?:query|params)|fetch\s*\(|axios\s*\.\s*(?:get|post)|XMLHttpRequest|document\s*\.\s*location)\b/;

  const tplRe = /\btemplate\s*:\s*(['"`])([\s\S]*?)\1/g;
  let tm: RegExpExecArray | null;
  const boundVars = new Set<string>();
  while ((tm = tplRe.exec(code)) !== null) {
    const tpl = tm[2];
    const vhRe = /\bv-html\s*=\s*"([^"]+)"/g;
    let vm: RegExpExecArray | null;
    while ((vm = vhRe.exec(tpl)) !== null) {
      const expr = vm[1].trim();
      const idMatch = expr.match(/^([A-Za-z_$][\w$]*)/);
      if (idMatch) boundVars.add(idMatch[1]);
    }
  }
  if (boundVars.size === 0) return out;

  // Build a set of variables transitively tainted by a recognized source
  // pattern: `const params = new URLSearchParams(...)` taints `params`,
  // then `const q = params.get('q')` taints `q` (one-hop).
  const taintedSet = new Set<string>();
  const assignRe =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g;
  let am: RegExpExecArray | null;
  // First pass: direct source-pattern assignments.
  assignRe.lastIndex = 0;
  while ((am = assignRe.exec(code)) !== null) {
    if (sourceRe.test(am[2])) taintedSet.add(am[1]);
  }
  // Second pass: one-hop through tainted vars (limit 3 iterations).
  for (let pass = 0; pass < 3; pass++) {
    assignRe.lastIndex = 0;
    const before = taintedSet.size;
    while ((am = assignRe.exec(code)) !== null) {
      if (taintedSet.has(am[1])) continue;
      for (const tv of taintedSet) {
        if (new RegExp(`\\b${tv}\\b`).test(am[2])) {
          taintedSet.add(am[1]);
          break;
        }
      }
    }
    if (taintedSet.size === before) break;
  }

  const taintedBindings = new Set<string>();
  for (const v of boundVars) {
    const bindRe = new RegExp(`\\b${v}\\s*[:=]\\s*([^,;\\n]+)`);
    for (const line of lines) {
      const m = line.match(bindRe);
      if (!m) continue;
      const val = m[1];
      if (sourceRe.test(val)) {
        taintedBindings.add(v);
        break;
      }
      let found = false;
      for (const tv of taintedSet) {
        if (new RegExp(`\\b${tv}\\b`).test(val)) {
          taintedBindings.add(v);
          found = true;
          break;
        }
      }
      if (found) break;
    }
    const propsRe = new RegExp(
      `\\bprops\\s*:\\s*\\[[^\\]]*['"\`]${v}['"\`][^\\]]*\\]`,
    );
    if (propsRe.test(code)) taintedBindings.add(v);
  }

  if (taintedBindings.size === 0) return out;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!/v-html\s*=/.test(raw)) continue;
    const vm = raw.match(/v-html\s*=\s*"([^"]+)"/);
    if (!vm) continue;
    const idMatch = vm[1].trim().match(/^([A-Za-z_$][\w$]*)/);
    if (!idMatch || !taintedBindings.has(idMatch[1])) continue;
    out.push({
      id: `xss-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xss',
      cwe: 'CWE-79',
      severity: 'high',
      level: 'error',
      message:
        'Vue v-html XSS: directive binds to "' +
        idMatch[1] +
        '" which is sourced from user-controlled input. Use {{ }} ' +
        'interpolation (auto-escapes) or sanitize the HTML with ' +
        'DOMPurify before binding.',
      file,
      line: i + 1,
      snippet: raw.trim().substring(0, 100),
    });
  }
  return out;
}

/**
 * Angular xss — `<recv>.bypassSecurityTrust(Html|Script|Url|ResourceUrl|
 * Style)(<arg>)` where `<recv>` is typed `DomSanitizer`. Skip when
 * `<arg>` is a string literal (intentional safe-by-author escape hatch).
 */
export function findTsAngularBypassXssFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const sanitizerNames = new Set<string>();
  const declRe =
    /\b(?:public|private|protected|readonly|\s)?\s*([A-Za-z_$][\w$]*)\s*:\s*DomSanitizer\b/g;
  let m: RegExpExecArray | null;
  declRe.lastIndex = 0;
  while ((m = declRe.exec(code)) !== null) sanitizerNames.add(m[1]);
  if (sanitizerNames.size === 0) return out;

  const assignRe = /\bthis\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\b/g;
  let am: RegExpExecArray | null;
  assignRe.lastIndex = 0;
  while ((am = assignRe.exec(code)) !== null) {
    if (sanitizerNames.has(am[2])) sanitizerNames.add(am[1]);
  }

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    const callRe =
      /\b(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\.\s*bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)\s*\(([\s\S]*?)\)/;
    const cm = trimmed.match(callRe);
    if (!cm) continue;
    const recv = cm[1];
    if (!sanitizerNames.has(recv)) continue;
    const arg = cm[3].trim();
    if (/^(['"`])[^'"`]*\1$/.test(arg)) continue;
    out.push({
      id: `xss-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xss',
      cwe: 'CWE-79',
      severity: 'high',
      level: 'error',
      message:
        'Angular XSS: DomSanitizer.bypassSecurityTrust' +
        cm[2] +
        '() opts out of Angular\'s built-in sanitization for a ' +
        'non-literal argument. Prefer leaving Angular\'s default ' +
        'sanitizer in place, or sanitize the input with DOMPurify ' +
        'before bypassing.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Python Flask xss — route function returning HTML built from a
 * `request.<args|form|values|files>.get(...)` value via string concat,
 * f-string, %, or .format(). Bypasses the engine's flow construction
 * gap for these string ops.
 *
 * Conservative: requires a Flask-style route decorator (`@<x>.route(`)
 * above the function; skip when the variable is escape()-wrapped.
 */
export function findPythonFlaskStringConcatXssFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  type Fn = { name: string; startLine: number; endLine: number };
  const fns: Fn[] = [];
  const defRe = /^(\s*)def\s+([A-Za-z_]\w*)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const dm = raw.match(defRe);
    if (!dm) continue;
    const indent = dm[1].length;
    let hasRoute = false;
    for (let j = i - 1; j >= 0; j--) {
      const prev = lines[j].trim();
      if (prev === '' || prev.startsWith('#')) continue;
      if (!prev.startsWith('@')) break;
      if (/@\s*[A-Za-z_]\w*\s*\.\s*route\s*\(/.test(prev) ||
          /@\s*route\s*\(/.test(prev)) {
        hasRoute = true;
      }
    }
    if (!hasRoute) continue;
    let end = lines.length;
    for (let k = i + 1; k < lines.length; k++) {
      const ln = lines[k];
      if (!ln.trim()) continue;
      const ind = ln.match(/^(\s*)/)?.[1].length ?? 0;
      if (ind <= indent) { end = k; break; }
    }
    fns.push({ name: dm[2], startLine: i + 1, endLine: end });
  }
  if (fns.length === 0) return out;

  const requestSourceRe =
    /\b([A-Za-z_]\w*)\s*=\s*request\s*\.\s*(?:args|form|values|files|json|cookies|headers)(?:\s*\.\s*get\s*\(|\s*\[)/;
  const escapeWrapRe =
    /\b(?:html\.escape|markupsafe\.escape|escape|markupsafe\.Markup\s*\.\s*escape|werkzeug\.utils\.escape)\s*\(/;

  for (const fn of fns) {
    const taintedVars = new Set<string>();
    for (let li = fn.startLine; li < fn.endLine; li++) {
      const raw = lines[li];
      const rm = raw.match(requestSourceRe);
      if (rm) taintedVars.add(rm[1]);
    }

    for (let li = fn.startLine; li < fn.endLine; li++) {
      const raw = lines[li];
      const trimmed = raw.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const retMatch = trimmed.match(/^(?:return|yield)\s+(.+)$/);
      if (!retMatch) continue;
      const expr = retMatch[1];

      const inlineSource =
        /\brequest\s*\.\s*(?:args|form|values|files|cookies|headers)(?:\s*\.\s*get\s*\(|\s*\[)/.test(
          expr,
        );
      const hasTaintedVar = [...taintedVars].some(v =>
        new RegExp(`\\b${v}\\b`).test(expr),
      );

      if (!hasTaintedVar && !inlineSource) continue;
      if (escapeWrapRe.test(expr)) continue;

      const buildsHtml =
        (/['"`]\s*\+/.test(expr) || /\+\s*['"`]/.test(expr)) ||
        // f-string with interpolation. Allow any non-`{` char between the
        // opening quote and the first `{` (Python f-strings may embed `"`
        // when single-quoted and vice-versa, e.g. f'<a href="{u}">').
        /\bf['"`][^{\n]*\{[^}]+\}/.test(expr) ||
        /['"`]\s*%\s*[^=]/.test(expr) ||
        /['"`]\.\s*format\s*\(/.test(expr);
      if (!buildsHtml) continue;

      out.push({
        id: `xss-${file}-${li + 1}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        level: 'error',
        message:
          'Reflected XSS: Flask route returns HTML built from request ' +
          'input via string concatenation / f-string / format. Wrap ' +
          'user input with markupsafe.escape() or render via a ' +
          'Jinja2 template (autoescape on by default).',
        file,
        line: li + 1,
        snippet: trimmed.substring(0, 100),
      });
      break;
    }
  }
  return out;
}

/**
 * Python Jinja2 Markup-bypass xss — `Markup(<var>)` where `<var>` is
 * request-sourced, then passed into a `<X>.render(...)` call. The
 * `Markup` wrap deliberately disables Jinja autoescape for the value.
 *
 * Namespace-scoped alias tracking (Sprint 74 lesson): only treats
 * `Markup` as dangerous when imported from `markupsafe` or `flask`,
 * and only when no user-defined `class Markup` shadows the import.
 */
export function findPythonJinjaMarkupXssFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const importRe =
    /^\s*from\s+(?:markupsafe|flask)\s+import\s+(?:[^#\n]*\b)?Markup\b/m;
  const classDefRe = /^\s*class\s+Markup\b/m;
  if (!importRe.test(code)) return out;
  if (classDefRe.test(code)) return out;

  const requestSourceRe =
    /\b([A-Za-z_]\w*)\s*=\s*request\s*\.\s*(?:args|form|values|files|json|cookies|headers)(?:\s*\.\s*get\s*\(|\s*\[)/;
  const taintedVars = new Set<string>();
  for (const line of lines) {
    const m = line.match(requestSourceRe);
    if (m) taintedVars.add(m[1]);
  }
  if (taintedVars.size === 0) return out;

  if (!/\.\s*render\s*\(/.test(code)) return out;

  const markupCallRe = /\bMarkup\s*\(\s*([A-Za-z_]\w*)\s*[,)]/g;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    let mm: RegExpExecArray | null;
    markupCallRe.lastIndex = 0;
    while ((mm = markupCallRe.exec(trimmed)) !== null) {
      const argName = mm[1];
      if (!taintedVars.has(argName)) continue;
      out.push({
        id: `xss-${file}-${i + 1}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        level: 'error',
        message:
          'Jinja2 autoescape bypass: Markup(' +
          argName +
          ') wraps a request-derived value, disabling autoescape when ' +
          'rendered. Pass the raw value to render() and let Jinja2 ' +
          'auto-escape, or sanitize with bleach.clean first.',
        file,
        line: i + 1,
        snippet: trimmed.substring(0, 100),
      });
      break;
    }
  }
  return out;
}

/**
 * Go open_redirect — `<rw>.Header().Set("Location", <expr>)` where
 * `<rw>` is bound to `http.ResponseWriter`. The configured sink rows
 * for `Header.Set` are typed `crlf` (CWE-113); the same line is also a
 * CWE-601 open_redirect when the header key is exactly `"Location"`
 * (case-insensitive). This pattern detector emits the open_redirect
 * finding directly, complementing the engine's crlf classification.
 *
 * Sprint 82 (#189): closes go__v02_location_header.
 *
 * Conservative: only fires when the receiver matches a parameter typed
 * `http.ResponseWriter` AND the literal key value is `Location` AND no
 * recognized URL-allowlist sanitizer wraps the value argument.
 */
export function findGoLocationHeaderOpenRedirectFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const rwNames = new Set<string>();
  const sigRe = /\(\s*([A-Za-z_]\w*)\s+http\.ResponseWriter\b/g;
  for (const line of lines) {
    let m: RegExpExecArray | null;
    sigRe.lastIndex = 0;
    while ((m = sigRe.exec(line)) !== null) rwNames.add(m[1]);
  }
  if (rwNames.size === 0) return out;

  // Recognized URL-allowlist / strict-equality sanitizers. Conservative
  // — keeps the FP set tight (Sprint 74 lesson). `url.Parse` alone is
  // not a sanitizer; we require an `IsAbs`/`Host`/`==` check.
  const safeWrapRe =
    /\b(?:net\/url|url)\.Parse\b[\s\S]{0,120}?\b(?:IsAbs|Host)\b|\bstrings\.HasPrefix\s*\(/;

  // Match: `<rw>.Header().Set("Location", <expr>)` — also accept
  // `Add` (header-stacking variant) which has the same redirect effect.
  const callRe =
    /\b([A-Za-z_]\w*)\s*\.\s*Header\s*\(\s*\)\s*\.\s*(?:Set|Add)\s*\(\s*(['"])([^'"]+)\2\s*,\s*([\s\S]*)\)\s*(?:\/\/.*)?$/;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    const m = trimmed.match(callRe);
    if (!m) continue;
    const recv = m[1];
    if (!rwNames.has(recv)) continue;
    const key = m[3];
    if (key.toLowerCase() !== 'location') continue;
    const valExpr = m[4];
    // Skip when the value is a pure string literal (no taint shape).
    const valTrim = valExpr.trim();
    if (/^"(?:\\.|[^"\\])*"$/.test(valTrim)) continue;
    if (safeWrapRe.test(valExpr)) continue;
    out.push({
      id: `open_redirect-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'open_redirect',
      cwe: 'CWE-601',
      severity: 'high',
      level: 'error',
      message:
        'Open redirect: ResponseWriter.Header().Set("Location", ...) ' +
        'writes a user-controlled value into the Location header without ' +
        'validating the target. Restrict to an allow-list of hosts/paths ' +
        'or compare against a known-safe set before issuing the redirect.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Python Flask open_redirect — `<resp>.headers["Location"] = <expr>`
 * subscript-assignment shape. The engine's configured sinks for
 * Flask `Response.headers` model the dict-add form but not subscript
 * assignment, so the open_redirect signal is missed even though the
 * source (`request.args.get`) is detected.
 *
 * Sprint 82 (#189): closes py__v02_location_header.
 *
 * Conservative: requires the rhs to be a recognized request-source
 * variable OR an inline `request.<x>.get/[]` expression. Skips when
 * the value is wrapped in a recognized URL-allowlist call.
 */
export function findPythonHeadersSubscriptOpenRedirectFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  const requestSourceRe =
    /\b([A-Za-z_]\w*)\s*=\s*request\s*\.\s*(?:args|form|values|files|json|cookies|headers)(?:\s*\.\s*get\s*\(|\s*\[)/;
  const taintedVars = new Set<string>();
  for (const line of lines) {
    const m = line.match(requestSourceRe);
    if (m) taintedVars.add(m[1]);
  }

  // Recognized URL-allowlist sanitizers (tight, Sprint 74 lesson).
  const safeWrapRe =
    /\b(?:urllib\.parse\.urlparse|urlparse)\s*\([\s\S]{0,120}?\bnetloc\b|\b(?:startswith)\s*\(/;

  const subscriptRe =
    /\b([A-Za-z_]\w*)\s*\.\s*headers\s*\[\s*(['"])([^'"]+)\2\s*\]\s*=\s*(.+)$/;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = trimmed.match(subscriptRe);
    if (!m) continue;
    const key = m[3];
    if (key.toLowerCase() !== 'location') continue;
    const rhs = m[4].replace(/\s*(?:#.*)?$/, '').trim();
    // Skip pure string literal.
    if (/^['"](?:\\.|[^'"\\])*['"]$/.test(rhs)) continue;
    // Skip when wrapped in a recognized allowlist check.
    if (safeWrapRe.test(rhs)) continue;

    const hasTaintedVar = [...taintedVars].some(v =>
      new RegExp(`\\b${v}\\b`).test(rhs),
    );
    const inlineSource =
      /\brequest\s*\.\s*(?:args|form|values|files|cookies|headers|json)(?:\s*\.\s*get\s*\(|\s*\[)/.test(
        rhs,
      );
    if (!hasTaintedVar && !inlineSource) continue;

    out.push({
      id: `open_redirect-${file}-${i + 1}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'open_redirect',
      cwe: 'CWE-601',
      severity: 'high',
      level: 'error',
      message:
        'Open redirect: response.headers["Location"] = ... assigns a ' +
        'user-controlled value to the Location header. Validate the URL ' +
        'against an allow-list of trusted hosts before sending.',
      file,
      line: i + 1,
      snippet: trimmed.substring(0, 100),
    });
  }
  return out;
}

/**
 * Rust open_redirect — Actix/Rocket builder pattern
 * `<builder>.append_header(("Location", <expr>))` or
 * `.insert_header(("Location", <expr>))` where the value traces back
 * to a `web::Query` / `web::Path` / `Form` extractor. The tuple-arg
 * form is the idiomatic Actix HeaderName→HeaderValue API; the
 * engine's configured sinks model single-arg `set_header(value)` but
 * not the tuple builder shape.
 *
 * Sprint 82 (#189): closes rust__v01_redirect_param.
 *
 * Conservative: requires the function to accept a recognized
 * `web::Query` / `web::Path` / `web::Form` / `HttpRequest` parameter
 * and the value expression to reference it (directly, or transitively
 * via a `.get(...)` / `.cloned()` / `.unwrap_or_default()` chain).
 */
export function findRustAppendHeaderTupleOpenRedirectFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  // Discover request-extractor parameter names.
  const extractorRe =
    /\b([A-Za-z_]\w*)\s*:\s*(?:web\s*::\s*)?(?:Query|Path|Form|Json)\s*<|\b([A-Za-z_]\w*)\s*:\s*&?\s*HttpRequest\b/g;
  const extractorParams = new Set<string>();
  for (const line of lines) {
    let m: RegExpExecArray | null;
    extractorRe.lastIndex = 0;
    while ((m = extractorRe.exec(line)) !== null) {
      const name = m[1] ?? m[2];
      if (name) extractorParams.add(name);
    }
  }
  if (extractorParams.size === 0) return out;

  // Build transitive tainted-let set: `let v = <expr>` where <expr>
  // references an extractor param or a previously tainted var.
  const taintedVars = new Set<string>(extractorParams);
  const letRe = /\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*([^;]+);/g;
  for (let pass = 0; pass < 4; pass++) {
    const before = taintedVars.size;
    let lm: RegExpExecArray | null;
    letRe.lastIndex = 0;
    while ((lm = letRe.exec(code)) !== null) {
      const name = lm[1];
      const rhs = lm[2];
      if (taintedVars.has(name)) continue;
      for (const tv of taintedVars) {
        if (new RegExp(`\\b${tv}\\b`).test(rhs)) {
          taintedVars.add(name);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }

  const safeWrapRe =
    /\b(?:Url\s*::\s*parse|url\s*::\s*Url\s*::\s*parse)\s*\([\s\S]{0,160}?\b(?:host_str|host|origin)\b/;

  const tupleCallRe =
    /\.\s*(?:append_header|insert_header)\s*\(\s*\(\s*(['"])([^'"]+)\1\s*,\s*([^)]*?)\s*\)\s*\)/g;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    let cm: RegExpExecArray | null;
    tupleCallRe.lastIndex = 0;
    while ((cm = tupleCallRe.exec(raw)) !== null) {
      const key = cm[2];
      if (key.toLowerCase() !== 'location') continue;
      const valExpr = cm[3];
      if (/^['"](?:\\.|[^'"\\])*['"]$/.test(valExpr.trim())) continue;
      if (safeWrapRe.test(valExpr)) continue;
      const hasTainted = [...taintedVars].some(v =>
        new RegExp(`\\b${v}\\b`).test(valExpr),
      );
      if (!hasTainted) continue;
      out.push({
        id: `open_redirect-${file}-${i + 1}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'open_redirect',
        cwe: 'CWE-601',
        severity: 'high',
        level: 'error',
        message:
          'Open redirect: HttpResponse builder ' +
          '.append_header(("Location", ...)) sets the Location header from ' +
          'a request-derived value without allow-list validation. Parse ' +
          'with url::Url::parse and compare host_str against an allow-list.',
        file,
        line: i + 1,
        snippet: trimmed.substring(0, 100),
      });
      break;
    }
  }
  return out;
}

/**
 * JS/HTML DOM open_redirect — assignment / call patterns that drive
 * `location.href`, `window.location`, `document.location`,
 * `location.assign(...)`, `location.replace(...)`, or `<elem>.content
 * = '...;url=' + ...` (meta-refresh DOM shape) where the right-hand
 * side traces back to a DOM source (`location.search`,
 * `location.hash`, `URLSearchParams.get(...)`, `document.referrer`,
 * `window.name`).
 *
 * Sprint 82 (#189): closes html__v01_redirect_param,
 * html__v03_meta_refresh, htmljs__v03_meta_refresh.
 *
 * Conservative: only fires when the rhs expression contains (or
 * references a var that contains) a recognized DOM source token;
 * never fires on literal-only assignments.
 */
export function findJsDomOpenRedirectFindings(
  code: string,
  file: string,
): SastFinding[] {
  const out: SastFinding[] = [];
  const lines = code.split('\n');

  // DOM source pattern — direct references to user-controlled URL
  // pieces. `document.referrer` / `window.name` round out the common
  // taint sources beyond URLSearchParams.
  const domSourceRe =
    /\blocation\s*\.\s*(?:search|hash|href|pathname)\b|\bwindow\s*\.\s*location\s*\.\s*(?:search|hash|href|pathname)\b|\bURLSearchParams\b|\bdocument\s*\.\s*(?:referrer|URL|location\s*\.\s*(?:search|hash|href|pathname))\b|\bwindow\s*\.\s*name\b/;

  // Transitive tainted variable set: `const x = <DOM source ...>`,
  // then `const y = x.get(...)`, etc.
  const taintedVars = new Set<string>();
  const assignRe =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g;
  let am: RegExpExecArray | null;
  assignRe.lastIndex = 0;
  while ((am = assignRe.exec(code)) !== null) {
    if (domSourceRe.test(am[2])) taintedVars.add(am[1]);
  }
  for (let pass = 0; pass < 4; pass++) {
    const before = taintedVars.size;
    assignRe.lastIndex = 0;
    while ((am = assignRe.exec(code)) !== null) {
      if (taintedVars.has(am[1])) continue;
      for (const tv of taintedVars) {
        if (new RegExp(`\\b${tv}\\b`).test(am[2])) {
          taintedVars.add(am[1]);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }

  // Recognized sanitizers (tight): explicit allow-list check against a
  // known set / startsWith on a same-origin literal prefix.
  const safeWrapRe =
    /\b(?:startsWith|includes)\s*\(\s*['"`]\/[^'"`]*['"`]\s*\)|\bnew\s+URL\s*\([\s\S]{0,80}?\)\s*\.\s*(?:origin|hostname)\s*===/;

  const containsTaint = (expr: string): boolean => {
    if (domSourceRe.test(expr)) return true;
    for (const tv of taintedVars) {
      if (new RegExp(`\\b${tv}\\b`).test(expr)) return true;
    }
    return false;
  };

  // Sink shape (a1): `[<X>.]location.href = <expr>`.
  const hrefSinkRe =
    /\b(?:(?:window|document|self|top|parent)\s*\.\s*)?location\s*\.\s*href\s*=\s*([^;\n]+?)\s*;?\s*(?:\/\/.*)?$/;
  // Sink shape (a2): `window.location = <expr>` etc.
  const locSinkRe =
    /\b(?:window|document|self|top|parent)\s*\.\s*location\s*=\s*([^;\n]+?)\s*;?\s*(?:\/\/.*)?$/;
  // Sink shape (a3): `<elem>.content = <expr>` — only counts when the
  // rhs looks like a meta-refresh string (`'...url=' + ...`). Allow `;`
  // inside string literals on the rhs (meta-refresh format is
  // `'<delay>;url=<...>'`), so match up to newline then trim trailing
  // semicolon/comment manually.
  const contentSinkRe =
    /\.\s*content\s*=\s*([^\n]+?)\s*$/;
  // Sink shape (b): `[<X>.]location.assign(<expr>)` /
  // `[<X>.]location.replace(<expr>)`.
  const callSinkRe =
    /\b(?:(?:window|document|self|top|parent)\s*\.\s*)?location\s*\.\s*(?:assign|replace)\s*\(\s*([^)]+)\)/;

  const emit = (line: number, msg: string, snippet: string) => {
    out.push({
      id: `open_redirect-${file}-${line}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'open_redirect',
      cwe: 'CWE-601',
      severity: 'high',
      level: 'error',
      message: msg,
      file,
      line,
      snippet: snippet.substring(0, 100),
    });
  };

  const isLiteralOnly = (expr: string): boolean =>
    /^['"`](?:\\.|[^'"`\\])*['"`]$/.test(expr.trim());

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    let matched = false;

    // (a1) location.href = ...
    const hm = trimmed.match(hrefSinkRe);
    if (hm) {
      const rhs = hm[1].trim();
      if (!isLiteralOnly(rhs) && containsTaint(rhs) && !safeWrapRe.test(rhs)) {
        emit(
          i + 1,
          'Open redirect: assignment to location.href uses a value ' +
            'derived from a URL query/hash without allow-list validation. ' +
            'Compare the target origin to a known-safe set before navigating.',
          trimmed,
        );
        matched = true;
      }
    }

    // (a2) window.location = ... (skip if already matched as href)
    if (!matched) {
      const lm = trimmed.match(locSinkRe);
      if (lm) {
        const rhs = lm[1].trim();
        if (!isLiteralOnly(rhs) && containsTaint(rhs) && !safeWrapRe.test(rhs)) {
          emit(
            i + 1,
            'Open redirect: assignment to window.location uses a value ' +
              'derived from a URL query/hash without allow-list validation. ' +
              'Compare the target origin to a known-safe set before navigating.',
            trimmed,
          );
          matched = true;
        }
      }
    }

    // (a3) <elem>.content = '...url=' + ... (meta-refresh DOM shape)
    if (!matched) {
      const cm = trimmed.match(contentSinkRe);
      if (cm) {
        // Strip trailing `;` and comment from captured rhs.
        const rhs = cm[1].replace(/\s*\/\/.*$/, '').replace(/\s*;\s*$/, '').trim();
        if (
          !isLiteralOnly(rhs) &&
          /['"`][^'"`]*\burl\s*=/i.test(rhs) &&
          containsTaint(rhs) &&
          !safeWrapRe.test(rhs)
        ) {
          emit(
            i + 1,
            'Open redirect: DOM assignment to <meta>.content with a ' +
              'meta-refresh URL built from a URL query/hash without ' +
              'allow-list validation. Validate origin before navigating.',
            trimmed,
          );
          matched = true;
        }
      }
    }

    // (b) location.assign(...) / location.replace(...)
    if (!matched) {
      const callm = trimmed.match(callSinkRe);
      if (callm) {
        const arg = callm[1].trim();
        if (!isLiteralOnly(arg) && containsTaint(arg) && !safeWrapRe.test(arg)) {
          emit(
            i + 1,
            'Open redirect: location.assign / location.replace invoked ' +
              'with a value derived from a URL query/hash without allow-' +
              'list validation. Validate origin before navigating.',
            trimmed,
          );
        }
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sprint 83 (issue #189 — code_injection cluster, 8 FN cells)
// ---------------------------------------------------------------------------
// Per-language pattern detectors that close 4 remaining code_injection FN
// shapes that the configured-sink path does not cover:
//   - Go plugin.Open / plugin.Lookup with *http.Request-derived path
//   - JS indirect eval forms: (0, eval)(x), globalThis.eval(x), aliased eval
//   - Python code.InteractiveInterpreter / InteractiveConsole / compile_command
//   - Rust evalexpr crate, libloading dynamic load, mlua/rlua .load().exec
// ---------------------------------------------------------------------------

/**
 * Sprint 83 detector A — Go `plugin.Open(<tainted>)` / `plugin.Lookup(...)`.
 * Loading a Go plugin executes the loaded module's init() functions and
 * makes its exported symbols callable, which is a code-injection sink
 * equivalent to dynamic library loading. Fires when the path argument
 * traces back to an `*http.Request` extractor (FormValue / URL.Query /
 * PostFormValue / Header.Get / Cookie) within the same function.
 */
export function findGoPluginOpenCodeInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\bplugin\s*\.\s*(?:Open|Lookup)\s*\(/.test(code)) return findings;

  const lines = code.split('\n');
  const reqExtractRe =
    /\b\w+\s*\.\s*(?:FormValue|PostFormValue|URL\.Query\(\)\.Get|Header\.Get|Cookie)\s*\(/;
  const httpReqParamRe = /\*\s*http\.Request\b/;
  const callRe = /\bplugin\s*\.\s*(?:Open|Lookup)\s*\(\s*([^)]*)\s*\)/;
  const sinkLabel = (op: string) =>
    op === 'Lookup'
      ? 'Go plugin.Lookup'
      : 'Go plugin.Open';

  // Discover taint vars per func: lines with *http.Request param scope are
  // the candidate funcs. Track assignments downstream until next `func` token.
  type Func = { start: number; end: number };
  const funcs: Func[] = [];
  let cur: Func | null = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (/^func\b/.test(t)) {
      if (cur) {
        cur.end = i - 1;
        funcs.push(cur);
      }
      cur = { start: i, end: lines.length - 1 };
    }
  }
  if (cur) funcs.push(cur);

  for (const fn of funcs) {
    const header = lines[fn.start];
    if (!httpReqParamRe.test(header)) continue;
    const taintedVars = new Set<string>();
    // Up to 3 passes: discover transitively-tainted vars from request extractors.
    for (let pass = 0; pass < 3; pass++) {
      const before = taintedVars.size;
      for (let i = fn.start; i <= fn.end; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        const assignMatch = trimmed.match(
          /^(\w+)\s*(?::=|=)\s*(.+?)(?:\s*\/\/.*)?$/,
        );
        if (!assignMatch) continue;
        const lhs = assignMatch[1];
        const rhs = assignMatch[2];
        if (taintedVars.has(lhs)) continue;
        if (reqExtractRe.test(rhs)) {
          taintedVars.add(lhs);
          continue;
        }
        // Aliasing existing taint
        for (const v of taintedVars) {
          const re = new RegExp(`\\b${v}\\b`);
          if (re.test(rhs)) {
            taintedVars.add(lhs);
            break;
          }
        }
      }
      if (taintedVars.size === before) break;
    }
    if (taintedVars.size === 0) continue;
    for (let i = fn.start; i <= fn.end; i++) {
      const line = lines[i];
      const m = line.match(callRe);
      if (!m) continue;
      const arg = m[1].trim();
      if (arg.length === 0) continue;
      // skip clear literal-only constants
      if (/^"[^"]*"$/.test(arg)) continue;
      let tainted = false;
      // direct extractor call as argument
      if (reqExtractRe.test(arg)) tainted = true;
      else {
        for (const v of taintedVars) {
          const re = new RegExp(`\\b${v}\\b`);
          if (re.test(arg)) {
            tainted = true;
            break;
          }
        }
      }
      if (!tainted) continue;
      const op = /\bplugin\s*\.\s*Lookup\b/.test(line) ? 'Lookup' : 'Open';
      findings.push({
        id: `code_injection-${file}-${i + 1}-go-plugin-${op.toLowerCase()}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        level: 'error',
        message:
          `Code injection: ${sinkLabel(op)} called with a path/symbol derived ` +
          'from an *http.Request without an allow-list. Loading a plugin ' +
          'runs its init() and exposes arbitrary exported symbols. Restrict ' +
          'the path to a trusted directory or use a fixed allow-list.',
        file,
        line: i + 1,
        snippet: line.trim(),
      });
    }
  }
  return findings;
}

/**
 * Sprint 83 detector B — JS indirect eval forms.
 * Configured `eval` sink matches direct `eval(x)` but misses:
 *   - `(0, eval)(x)` comma-operator indirect call
 *   - `globalThis.eval(x)` / `global.eval(x)` / `window.eval(x)` / `self.eval(x)`
 *   - aliased eval: `const f = eval; f(x)` then `f(taint)`
 * Fires when the argument traces back to req.body / req.query / req.params /
 * req.headers / req.cookies (Express/Koa-style request extractor).
 */
export function findJsIndirectEvalCodeInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\beval\b/.test(code)) return findings;

  const lines = code.split('\n');
  // request extractor (assignment rhs)
  const reqExtractRe =
    /\breq(?:uest)?\s*\.\s*(?:body|query|params|headers|cookies)\b/;
  // First: discover indirect-eval aliases: `const f = eval;`, `let f = eval`
  const aliasRe =
    /^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:globalThis\s*\.\s*eval|global\s*\.\s*eval|window\s*\.\s*eval|self\s*\.\s*eval|eval)\s*;?\s*$/;
  const aliases = new Set<string>();
  for (const line of lines) {
    const m = line.match(aliasRe);
    if (m) aliases.add(m[1]);
  }

  // Discover transitively-tainted vars
  const taintedVars = new Set<string>();
  const assignRe =
    /^\s*(?:const|let|var)\s+(\w+)\s*=\s*(.+?);?\s*$/;
  const reassignRe = /^\s*(\w+)\s*=\s*(.+?);?\s*$/;
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (const line of lines) {
      const m = line.match(assignRe) || line.match(reassignRe);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (lhs === 'const' || lhs === 'let' || lhs === 'var') continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        const re = new RegExp(`\\b${v}\\b`);
        if (re.test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }

  // Patterns: (0, eval)(x); globalThis.eval(x); aliased f(x)
  const indirectCommaRe = /\(\s*0\s*,\s*eval\s*\)\s*\(\s*([^)]*)\s*\)/;
  const indirectMemberRe =
    /\b(?:globalThis|global|window|self)\s*\.\s*eval\s*\(\s*([^)]*)\s*\)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    // skip comment lines and alias-declaration lines themselves
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    if (aliasRe.test(line)) continue;
    let arg: string | null = null;
    let formLabel = '';
    let m = trimmed.match(indirectCommaRe);
    if (m) {
      arg = m[1].trim();
      formLabel = '(0, eval)(...) indirect eval';
    }
    if (!arg) {
      m = trimmed.match(indirectMemberRe);
      if (m) {
        arg = m[1].trim();
        formLabel = 'globalThis.eval / window.eval / self.eval indirect eval';
      }
    }
    if (!arg && aliases.size > 0) {
      for (const a of aliases) {
        const aliasCallRe = new RegExp(`\\b${a}\\s*\\(\\s*([^)]*)\\s*\\)`);
        const mm = trimmed.match(aliasCallRe);
        if (mm) {
          arg = mm[1].trim();
          formLabel = `aliased eval reference \`${a}(...)\``;
          break;
        }
      }
    }
    if (arg === null) continue;
    if (arg.length === 0) continue;
    // skip literal-only string args
    if (/^['"`][^'"`]*['"`]$/.test(arg)) continue;
    let tainted = false;
    if (reqExtractRe.test(arg)) tainted = true;
    else {
      for (const v of taintedVars) {
        const re = new RegExp(`\\b${v}\\b`);
        if (re.test(arg)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    findings.push({
      id: `code_injection-${file}-${i + 1}-js-indirect-eval`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'code_injection',
      cwe: 'CWE-94',
      severity: 'critical',
      level: 'error',
      message:
        `Code injection: ${formLabel} called with a value derived from ` +
        'an HTTP request body/query/headers. Indirect eval forms still ' +
        'execute arbitrary code in the global scope. Remove the eval and ' +
        'parse the input with a safe data parser instead.',
      file,
      line: i + 1,
      snippet: trimmed,
    });
  }
  return findings;
}

/**
 * Sprint 83 detector C — Python `code` stdlib REPL / compile_command.
 * `code.InteractiveInterpreter().runsource(s)`, `runcode(c)`, `push(line)` and
 * `code.InteractiveConsole().push(line)`, plus `code.compile_command(s)` —
 * all execute or compile arbitrary Python source. Fires when the argument
 * traces back to a Flask `request.*` extractor; gated on `import code`
 * to avoid colliding with user-defined `code` variables.
 */
export function findPythonInteractiveInterpreterCodeInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Require `import code` namespace gate to avoid clashing with user-defined
  // identifiers named `code`.
  if (!/^\s*import\s+code\b/m.test(code)) return findings;
  if (
    !/\bcode\s*\.\s*(?:InteractiveInterpreter|InteractiveConsole|compile_command)\b/.test(
      code,
    )
  ) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\brequest\s*\.\s*(?:args|form|values|files|json|cookies|headers|get_data|get_json)\b/;

  // Discover transitively-tainted vars
  const taintedVars = new Set<string>();
  const assignRe = /^\s*(\w+)\s*=\s*(.+?)\s*(?:#.*)?$/;
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (const line of lines) {
      const m = line.match(assignRe);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        const re = new RegExp(`\\b${v}\\b`);
        if (re.test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }

  // Sink call patterns
  // a) code.InteractiveInterpreter(...).{runsource,runcode,push}(arg)
  // b) code.InteractiveConsole(...).{runsource,runcode,push,interact}(arg)
  // c) code.compile_command(arg, ...)
  const callRe =
    /\bcode\s*\.\s*(?:InteractiveInterpreter|InteractiveConsole)\s*\([^)]*\)\s*\.\s*(runsource|runcode|push|interact)\s*\(\s*([^),]+)/;
  const compileRe = /\bcode\s*\.\s*compile_command\s*\(\s*([^),]+)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    let arg: string | null = null;
    let formLabel = '';
    const m1 = trimmed.match(callRe);
    if (m1) {
      arg = m1[2].trim();
      formLabel = `code.${/Interpreter/.test(trimmed) ? 'InteractiveInterpreter' : 'InteractiveConsole'}().${m1[1]}`;
    }
    if (!arg) {
      const m2 = trimmed.match(compileRe);
      if (m2) {
        arg = m2[1].trim();
        formLabel = 'code.compile_command';
      }
    }
    if (arg === null) continue;
    if (arg.length === 0) continue;
    if (/^['"][^'"]*['"]$/.test(arg)) continue;
    let tainted = false;
    if (reqExtractRe.test(arg)) tainted = true;
    else {
      for (const v of taintedVars) {
        const re = new RegExp(`\\b${v}\\b`);
        if (re.test(arg)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    findings.push({
      id: `code_injection-${file}-${i + 1}-py-interactive-interpreter`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'code_injection',
      cwe: 'CWE-94',
      severity: 'critical',
      level: 'error',
      message:
        `Code injection: ${formLabel}(...) called with a value derived from ` +
        'a Flask request extractor. The Python `code` module compiles and ' +
        'executes arbitrary source. Remove the call and validate input ' +
        'against a fixed allow-list instead.',
      file,
      line: i + 1,
      snippet: trimmed,
    });
  }
  return findings;
}

/**
 * Sprint 83 detector D — Rust eval-crate / dynamic-load sinks.
 * Rust has no language-level eval; the canonical sinks are:
 *   - `evalexpr::eval(...)` (and `_with_context|_boolean|_int|_float|_string|_tuple|_empty`)
 *   - `libloading::Library::new(...)` (dynamic library load)
 *   - `mlua::Lua::new().load(<src>).{exec,eval,call}(...)` / rlua equivalent
 * Fires when the argument traces back to an Actix-web extractor: a plain
 * `body: String|Bytes`, a `web::Query<T>` / `web::Path<T>` / `web::Form<T>` /
 * `web::Json<T>` / `HttpRequest` param, or `axum::body::Bytes`/`String` etc.
 */
export function findRustEvalCrateCodeInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (
    !/\b(?:evalexpr\s*::\s*eval|libloading\s*::\s*Library\s*::\s*new|\.\s*load\s*\([^)]*\)\s*\.\s*(?:exec|eval|call))/.test(
      code,
    )
  ) {
    return findings;
  }

  const lines = code.split('\n');

  // Discover per-function tainted params: scan `fn ...(params)` headers and
  // mark params with extractor types as tainted.
  const extractorTypeRe =
    /:\s*(?:String|Bytes|bytes::Bytes|axum::body::Bytes|web::Query\b|web::Path\b|web::Form\b|web::Json\b|HttpRequest\b|actix_web::HttpRequest\b)/;
  type Fn = { start: number; end: number; tainted: Set<string> };
  const fns: Fn[] = [];
  let cur: Fn | null = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (/^\s*(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*\(/.test(t)) {
      if (cur) {
        cur.end = i - 1;
        fns.push(cur);
      }
      cur = { start: i, end: lines.length - 1, tainted: new Set() };
      // collect param idents whose type matches extractor
      const headerJoined = (() => {
        let j = i;
        let s = '';
        while (j < lines.length && !/\{\s*$/.test(s)) {
          s += lines[j];
          if (/\{\s*$/.test(lines[j])) break;
          j++;
          if (j - i > 12) break;
        }
        return s;
      })();
      // params are between first '(' and matching ')'
      const open = headerJoined.indexOf('(');
      const close = headerJoined.lastIndexOf(')');
      if (open !== -1 && close > open) {
        const params = headerJoined.substring(open + 1, close);
        // Split by top-level commas
        let depth = 0;
        let buf = '';
        const parts: string[] = [];
        for (const ch of params) {
          if (ch === '<' || ch === '(') depth++;
          else if (ch === '>' || ch === ')') depth--;
          if (ch === ',' && depth === 0) {
            parts.push(buf);
            buf = '';
            continue;
          }
          buf += ch;
        }
        if (buf.trim().length > 0) parts.push(buf);
        for (const p of parts) {
          const pm = p.match(/(?:mut\s+)?(\w+)\s*:/);
          if (!pm) continue;
          if (extractorTypeRe.test(p)) cur.tainted.add(pm[1]);
        }
      }
    }
  }
  if (cur) fns.push(cur);

  // Inside each function, scan assignments (let / let mut) to propagate
  // taint from existing tainted vars into new bindings.
  for (const fn of fns) {
    for (let pass = 0; pass < 3; pass++) {
      const before = fn.tainted.size;
      for (let i = fn.start; i <= fn.end; i++) {
        const t = lines[i].trim();
        const m = t.match(/^let\s+(?:mut\s+)?(\w+)\s*(?::\s*[^=]+)?=\s*(.+?);?$/);
        if (!m) continue;
        const lhs = m[1];
        const rhs = m[2];
        if (fn.tainted.has(lhs)) continue;
        for (const v of fn.tainted) {
          const re = new RegExp(`\\b${v}\\b`);
          if (re.test(rhs)) {
            fn.tainted.add(lhs);
            break;
          }
        }
      }
      if (fn.tainted.size === before) break;
    }
  }

  const evalExprRe =
    /\bevalexpr\s*::\s*eval(?:_with_context|_boolean|_int|_float|_string|_tuple|_empty)?\s*\(\s*([^)]+)\s*\)/;
  const libloadingRe =
    /\blibloading\s*::\s*Library\s*::\s*new\s*\(\s*([^)]+)\s*\)/;
  const luaLoadRe =
    /\.\s*load\s*\(\s*([^)]+)\s*\)\s*\.\s*(?:exec|eval|call)\b/;

  for (const fn of fns) {
    if (fn.tainted.size === 0) continue;
    for (let i = fn.start; i <= fn.end; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      let arg: string | null = null;
      let formLabel = '';
      let m = trimmed.match(evalExprRe);
      if (m) {
        arg = m[1].trim();
        formLabel = 'evalexpr::eval';
      }
      if (!arg) {
        m = trimmed.match(libloadingRe);
        if (m) {
          arg = m[1].trim();
          formLabel = 'libloading::Library::new';
        }
      }
      if (!arg) {
        m = trimmed.match(luaLoadRe);
        if (m) {
          arg = m[1].trim();
          formLabel = 'mlua/rlua Lua::load().{exec|eval|call}';
        }
      }
      if (arg === null) continue;
      if (arg.length === 0) continue;
      // unwrap leading '&' borrow
      let unwrapped = arg.replace(/^&\s*/, '').trim();
      if (/^"[^"]*"$/.test(unwrapped)) continue;
      let tainted = false;
      for (const v of fn.tainted) {
        const re = new RegExp(`\\b${v}\\b`);
        if (re.test(unwrapped)) {
          tainted = true;
          break;
        }
      }
      if (!tainted) continue;
      findings.push({
        id: `code_injection-${file}-${i + 1}-rust-eval-crate`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'code_injection',
        cwe: 'CWE-94',
        severity: 'critical',
        level: 'error',
        message:
          `Code injection: ${formLabel}(...) called with a value derived ` +
          'from an HTTP request extractor (body / Query / Path / Form / ' +
          'Json / HttpRequest). The expression / library / Lua chunk is ' +
          'executed as code. Remove the dynamic-eval path or restrict ' +
          'input to a fixed allow-list.',
        file,
        line: i + 1,
        snippet: trimmed,
      });
    }
  }
  return findings;
}

/**
 * Sprint 84 detector A (#189) — Go MongoDB driver nosql_injection.
 * The Go MongoDB driver call shape `coll.FindOne(ctx, bson.M{"k": <taint>})`
 * (and siblings: Find / InsertOne / InsertMany / UpdateOne / UpdateMany /
 * DeleteOne / DeleteMany / FindOneAndUpdate / FindOneAndDelete /
 * FindOneAndReplace / Aggregate) is not modeled by configured sinks (those
 * cover Node.js Mongo only). Fires when the filter argument (after `ctx`)
 * references a value transitively derived from `*http.Request` extractors
 * (URL.Query().Get / FormValue / PostFormValue / Header.Get / Cookie).
 */
export function findGoMongoNosqlInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Gate: require some hint of the mongo-driver / bson namespace usage.
  if (!/(\bbson\s*\.\s*[MDAE]\b|mongo-driver|\*\s*mongo\.Collection)/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\b\w+\s*\.\s*(?:FormValue|PostFormValue|URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get|Header\s*\.\s*Get|Cookie)\s*\(/;
  const httpReqParamRe = /\*\s*http\.Request\b/;
  const opsAlt =
    '(?:FindOne|Find|InsertOne|InsertMany|UpdateOne|UpdateMany|DeleteOne|DeleteMany|FindOneAndUpdate|FindOneAndDelete|FindOneAndReplace|Aggregate)';
  // Match call-site head only; balanced parens for args are extracted below.
  const callHeadRe = new RegExp(`\\.\\s*(${opsAlt})\\s*\\(`);
  function extractBalanced(line: string, openIdx: number): string | null {
    let depth = 0;
    for (let k = openIdx; k < line.length; k++) {
      const ch = line[k];
      if (ch === '(') depth++;
      else if (ch === ')') {
        depth--;
        if (depth === 0) return line.substring(openIdx + 1, k);
      }
    }
    return null;
  }

  type Func = { start: number; end: number };
  const funcs: Func[] = [];
  let cur: Func | null = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (/^func\b/.test(t)) {
      if (cur) {
        cur.end = i - 1;
        funcs.push(cur);
      }
      cur = { start: i, end: lines.length - 1 };
    }
  }
  if (cur) funcs.push(cur);

  for (const fn of funcs) {
    const header = lines[fn.start];
    if (!httpReqParamRe.test(header)) continue;
    const taintedVars = new Set<string>();
    for (let pass = 0; pass < 3; pass++) {
      const before = taintedVars.size;
      for (let i = fn.start; i <= fn.end; i++) {
        const trimmed = lines[i].trim();
        const assignMatch = trimmed.match(
          /^(\w+)\s*(?::=|=)\s*(.+?)(?:\s*\/\/.*)?$/,
        );
        if (!assignMatch) continue;
        const lhs = assignMatch[1];
        const rhs = assignMatch[2];
        if (taintedVars.has(lhs)) continue;
        if (reqExtractRe.test(rhs)) {
          taintedVars.add(lhs);
          continue;
        }
        for (const v of taintedVars) {
          if (new RegExp(`\\b${v}\\b`).test(rhs)) {
            taintedVars.add(lhs);
            break;
          }
        }
      }
      if (taintedVars.size === before) break;
    }
    if (taintedVars.size === 0) continue;

    for (let i = fn.start; i <= fn.end; i++) {
      const line = lines[i];
      const m = callHeadRe.exec(line);
      if (!m) continue;
      const op = m[1];
      const openIdx = m.index + m[0].length - 1;
      const args = extractBalanced(line, openIdx);
      if (args === null || args.length === 0) continue;
      let tainted = reqExtractRe.test(args);
      if (!tainted) {
        for (const v of taintedVars) {
          if (new RegExp(`\\b${v}\\b`).test(args)) {
            tainted = true;
            break;
          }
        }
      }
      if (!tainted) continue;
      findings.push({
        id: `nosql_injection-${file}-${i + 1}-go-mongo-${op.toLowerCase()}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'nosql_injection',
        cwe: 'CWE-943',
        severity: 'critical',
        level: 'error',
        message:
          `NoSQL injection: Go MongoDB driver \`${op}(...)\` called with a ` +
          'filter derived from *http.Request input. Untrusted values inside ' +
          'a `bson.M` / `bson.D` filter can be operator objects (e.g. ' +
          '`{"$ne": null}`) and bypass authentication/intent. Validate or ' +
          'coerce the value to a primitive before building the filter.',
        file,
        line: i + 1,
        snippet: line.trim(),
      });
    }
  }
  return findings;
}

/**
 * Sprint 84 detector B (#189) — Java Mongo driver nosql_injection.
 * Mongo Java driver shape `users.find(eq("k", <taint>))` (and siblings)
 * is not modeled by configured sinks (those cover Node.js Mongo only).
 * Fires when the receiver call payload references a value transitively
 * derived from servlet request extractors (request.getParameter /
 * getHeader / getCookies / getReader / getQueryString / getPart).
 */
export function findJavaMongoNosqlInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Gate: require some hint of MongoCollection / Filters / Document use.
  if (!/(MongoCollection\b|com\.mongodb\b|\bFilters\b|\bnew\s+Document\s*\()/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\b\w+\s*\.\s*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getReader|getQueryString|getRequestURI|getInputStream|getPart|getParts)\s*\(/;
  const opsAlt =
    '(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|replaceOne|aggregate|countDocuments|distinct)';
  const callRe = new RegExp(`\\.\\s*(${opsAlt})\\s*\\(([\\s\\S]*?)\\)`);

  // Whole-file 3-pass taint propagation across simple `Type name = expr;`
  // and `name = expr;` assignments. Lightweight; suitable for the fixture
  // set without paying for full Java scope tracking.
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      const a = t.match(/^(?:final\s+)?(?:[\w<>?,\[\]]+\s+)?(\w+)\s*=\s*(.+?);?$/);
      if (!a) continue;
      const lhs = a[1];
      const rhs = a[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(callRe);
    if (!m) continue;
    const op = m[1];
    const args = m[2];
    if (args.trim().length === 0) continue;
    let tainted = reqExtractRe.test(args);
    if (!tainted) {
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(args)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    findings.push({
      id: `nosql_injection-${file}-${i + 1}-java-mongo-${op.toLowerCase()}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'nosql_injection',
      cwe: 'CWE-943',
      severity: 'critical',
      level: 'error',
      message:
        `NoSQL injection: Java Mongo driver \`${op}(...)\` called with a ` +
        'filter derived from servlet request input. Untrusted values can ' +
        'reach BSON operator positions and bypass intent. Validate the ' +
        'input type before constructing the filter (e.g. require String).',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 84 detector C (#189) — Python mongoengine `$where` JS-string injection.
 * The shape `User.objects(__raw__={'$where': "this.x == '" + n + "'"})`
 * (and aliases via `$where` key with string concat / f-string) bypasses
 * the configured nosql sinks. Fires when the `$where` value references
 * a value transitively derived from Flask/Django/FastAPI request input.
 */
export function findPythonMongoengineWhereNosqlInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Gate: require literal '$where' to appear in the file.
  if (!/['"]\$where['"]/.test(code)) return findings;

  const lines = code.split('\n');
  const reqExtractRe =
    /\b(?:request\.(?:args|form|values|json|files|cookies|headers|data)\b|flask\.request\b)/;

  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('#')) continue;
      const a = t.match(/^(\w+)\s*=\s*(.+?)$/);
      if (!a) continue;
      const lhs = a[1];
      const rhs = a[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }

  const whereRe = /['"]\$where['"]\s*:\s*([^,}\n]+)/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(whereRe);
    if (!m) continue;
    const valueExpr = m[1].trim();
    // Pure string literal (no concat, no f-string interp): safe.
    if (/^"[^"]*"$/.test(valueExpr) || /^'[^']*'$/.test(valueExpr)) continue;
    let tainted = reqExtractRe.test(valueExpr);
    if (!tainted) {
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(valueExpr)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    findings.push({
      id: `nosql_injection-${file}-${i + 1}-py-mongoengine-where`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'nosql_injection',
      cwe: 'CWE-943',
      severity: 'critical',
      level: 'error',
      message:
        'NoSQL injection: mongoengine `__raw__={"$where": ...}` payload ' +
        'derived from HTTP request input. The `$where` operator evaluates ' +
        'JavaScript on the server; tainted string concatenation lets an ' +
        'attacker inject arbitrary JS. Replace `$where` with field-based ' +
        'operators or validate the input.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 85 detector (#189) — Java SSRF via `new URL(<tainted>)` →
 * `.openStream()` / `.openConnection()` / `.getContent()` receiver chains
 * that the configured `URL.openStream` / `URL.openConnection` sinks
 * recognize but the cross-statement flow construction misses (URL value
 * passes through an intermediate local variable). Also fires when the
 * tainted URL is gated only by a weak allowlist — a scheme-only check
 * such as `url.startsWith("https://")` is NOT a sanitizer because the
 * host is still attacker-controlled.
 */
export function findJavaUrlOpenStreamSsrfFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Gate: require URL construction + a fetch-style method call.
  if (
    !/\bnew\s+URL\s*\(/.test(code) &&
    !/\bURI\s*\.\s*create\s*\(/.test(code)
  ) {
    return findings;
  }
  if (!/\.\s*(?:openStream|openConnection|getContent)\s*\(/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\b\w+\s*\.\s*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getReader|getQueryString|getRequestURI|getInputStream|getPart|getParts)\s*\(/;

  // Whole-file 3-pass taint propagation. Tracks straightforward
  // `Type name = expr;` / `name = expr;` assignments. Notably
  // includes the `new URL(<tainted>)` wrapper — substring match on
  // the rhs is sufficient because no built-in URL constructor erases
  // taint.
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      const a = t.match(/^(?:final\s+)?(?:[\w<>?,\[\]]+\s+)?(\w+)\s*=\s*(.+?);?$/);
      if (!a) continue;
      const lhs = a[1];
      const rhs = a[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  const sinkRe = /\.\s*(openStream|openConnection|getContent)\s*\(/;
  const seen = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(sinkRe);
    if (!m) continue;
    const op = m[1];
    const sinkIdx = line.indexOf(`.${op}`);
    if (sinkIdx < 0) continue;
    // Identify the receiver span: everything to the left of the `.op(`
    // call. The receiver may be a chained call (e.g.
    // `new URL(url).openStream()`) — treat the entire pre-call span as
    // the analysis target and ask whether any tainted var appears in it.
    const head = line.substring(0, sinkIdx + 1);
    let tainted = reqExtractRe.test(head);
    if (!tainted) {
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(head)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    const key = `${i + 1}:${op}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      id: `ssrf-${file}-${i + 1}-java-url-${op.toLowerCase()}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'ssrf',
      cwe: 'CWE-918',
      severity: 'critical',
      level: 'error',
      message:
        `SSRF: Java \`URL.${op}()\` invoked on a URL derived from servlet ` +
        'request input. Even when an `if (url.startsWith("https://"))` ' +
        'guard is present, the host portion remains attacker-controlled — ' +
        'use a strict host allowlist (parse the URL, check `getHost()`) ' +
        'before issuing the request.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 86 detector A (#189) — Python uncontrolled format-string.
 *
 * Two shapes:
 *   1. `<tainted> % args`                 — old-style percent formatting
 *   2. `<tainted>.format(args)`           — `str.format` API
 *
 * When the format string itself comes from HTTP request input, an
 * attacker can probe arbitrary attributes/items via `str.format`
 * (`{0.__class__.__init__.__globals__}`) or crash the process via
 * malformed `%` specifiers. CWE-134.
 */
export function findPythonTaintedFormatStringFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Gate: the file must use a Flask/Django/FastAPI request extractor.
  if (
    !/\b(?:request\.(?:args|form|values|json|files|cookies|headers|data)|flask\.request)\b/.test(
      code,
    )
  ) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\b(?:request\.(?:args|form|values|json|files|cookies|headers|data)\b|flask\.request\b)/;

  // 3-pass whole-file taint propagation across simple `name = expr`
  // assignments.
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('#')) continue;
      const a = t.match(/^(\w+)\s*=\s*(.+?)$/);
      if (!a) continue;
      const lhs = a[1];
      const rhs = a[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  // Percent format: `<name> % <rhs>` where `<name>` is tainted and not a
  // string literal. Avoid false-fire on `2 % x` etc. by gating on
  // taintedVar appearing as the LHS of `%`.
  const percentRe = /\b(\w+)\s*%\s*[\(\[\{"'\w]/;
  // str.format(...): `<name>.format(`
  const dotFormatRe = /\b(\w+)\s*\.\s*format\s*\(/;
  const seen = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const t = line.trim();
    if (t.startsWith('#')) continue;

    // Percent format
    const pm = line.match(percentRe);
    if (pm && taintedVars.has(pm[1])) {
      // Avoid string literal LHS (already a literal would have been
      // assigned as a literal, but we double-check the var was tainted —
      // which the check above asserts).
      const key = `${i + 1}:percent`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({
          id: `format_string-${file}-${i + 1}-py-percent`,
          pass: 'language-sources',
          category: 'security',
          rule_id: 'format_string',
          cwe: 'CWE-134',
          severity: 'high',
          level: 'error',
          message:
            'Format-string injection: Python `<tainted> % args` uses an ' +
            'HTTP-request-controlled format string. Malformed specifiers can ' +
            'crash the handler (TypeError) and `%(name)s` access can reveal ' +
            'arbitrary mapping keys. Use a literal format string and pass ' +
            'untrusted values as arguments only.',
          file,
          line: i + 1,
          snippet: line.trim(),
        });
      }
    }

    // str.format
    const dm = line.match(dotFormatRe);
    if (dm && taintedVars.has(dm[1])) {
      const key = `${i + 1}:dotformat`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({
          id: `format_string-${file}-${i + 1}-py-strformat`,
          pass: 'language-sources',
          category: 'security',
          rule_id: 'format_string',
          cwe: 'CWE-134',
          severity: 'high',
          level: 'error',
          message:
            'Format-string injection: Python `<tainted>.format(...)` lets ' +
            'the attacker control the format template. Field-access shapes ' +
            'such as `{0.__class__.__init__.__globals__}` can leak module ' +
            'globals (e.g. secret keys). Use a literal template and pass ' +
            'untrusted values as positional/keyword arguments only.',
          file,
          line: i + 1,
          snippet: line.trim(),
        });
      }
    }
  }
  return findings;
}

/**
 * Sprint 86 detector B (#189) — JavaScript uncontrolled format-string
 * via Node `util.format(<tainted>, ...args)`. `util.format` honours
 * `%s`/`%d`/`%j`/`%O` specifiers; a tainted format string can fingerprint
 * argument types and is the documented sink for CWE-134 in Node.
 */
export function findJsUtilFormatFormatStringFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\butil\s*\.\s*format\s*\(/.test(code)) return findings;
  if (!/\breq\s*\.\s*(?:query|body|params|headers|cookies)\b/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\breq\s*\.\s*(?:query|body|params|headers|cookies)\b/;

  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('//')) continue;
      const a = t.match(/^(?:const|let|var)\s+(\w+)\s*=\s*(.+?);?$/);
      if (!a) continue;
      const lhs = a[1];
      const rhs = a[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  // util.format(<firstArg>, ...) — check whether <firstArg> is tainted.
  const callRe = /\butil\s*\.\s*format\s*\(\s*([\w.]+)\s*[,)]/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(callRe);
    if (!m) continue;
    const arg = m[1];
    // First token of dotted path is the var name.
    const root = arg.split('.')[0];
    if (!taintedVars.has(root) && !reqExtractRe.test(arg)) continue;
    findings.push({
      id: `format_string-${file}-${i + 1}-js-util-format`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'format_string',
      cwe: 'CWE-134',
      severity: 'medium',
      level: 'error',
      message:
        'Format-string injection: Node `util.format(<tainted>, ...)` uses ' +
        'an HTTP-request-controlled format string. The attacker can ' +
        'manipulate `%s`/`%j`/`%O` specifiers to alter the rendered ' +
        'output. Pass user input as a subsequent argument with a literal ' +
        'format string.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 86 detector C (#189) — Python HTTP header CRLF injection via
 * Flask/Werkzeug `response.headers['X-Custom'] = <tainted concat>` or
 * `response.headers.add(...)` / `response.headers.set(...)`. CWE-113.
 */
export function findPythonHeaderCrlfInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\b\w+\s*\.\s*headers\b/.test(code)) return findings;
  if (
    !/\b(?:request\.(?:args|form|values|json|files|cookies|headers|data)|flask\.request)\b/.test(
      code,
    )
  ) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\b(?:request\.(?:args|form|values|json|files|cookies|headers|data)\b|flask\.request\b)/;

  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('#')) continue;
      const a = t.match(/^(\w+)\s*=\s*(.+?)$/);
      if (!a) continue;
      const lhs = a[1];
      const rhs = a[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  // Patterns:
  //   resp.headers['X-Custom'] = <expr>
  //   resp.headers.add('X-Custom', <expr>)
  //   resp.headers.set('X-Custom', <expr>)
  //   resp.headers.update({'X-Custom': <expr>})
  const subscriptRe =
    /\b\w+\s*\.\s*headers\s*\[\s*['"][^'"]+['"]\s*\]\s*=\s*(.+)$/;
  const methodRe =
    /\b\w+\s*\.\s*headers\s*\.\s*(?:add|set|setdefault|append)\s*\(\s*['"][^'"]+['"]\s*,\s*(.+?)\)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const t = line.trim();
    if (t.startsWith('#')) continue;
    let expr: string | null = null;
    const sm = line.match(subscriptRe);
    if (sm) expr = sm[1];
    else {
      const mm = line.match(methodRe);
      if (mm) expr = mm[1];
    }
    if (!expr) continue;
    let tainted = reqExtractRe.test(expr);
    if (!tainted) {
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(expr)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    findings.push({
      id: `crlf-${file}-${i + 1}-py-headers`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'crlf',
      cwe: 'CWE-113',
      severity: 'medium',
      level: 'error',
      message:
        'CRLF / header injection: Python Flask/Werkzeug ' +
        '`response.headers[...] = <tainted>` lets an attacker inject a ' +
        '`\\r\\n` sequence and forge additional headers or split the ' +
        'response body. Validate the value (reject control characters) or ' +
        'use a fixed allowlist.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 87 detector A (#189) — JavaScript / TypeScript LDAP injection
 * via ldapjs / ldapts `client.search(base, { filter: <tainted>, ... })`.
 *
 * ldapjs and ldapts share the same call shape: `client.search(base, opts,
 * cb)` where `opts.filter` is the LDAP filter string. When an attacker
 * controls the filter content, they can break out of the intended filter
 * (e.g. `*)(uid=*` injection) to enumerate the directory. CWE-90.
 *
 * The detector tracks taint propagation from Express request extractors
 * (`req.query.X`, `req.body.X`, `req.params.X`, `req.headers.X`,
 * `req.cookies.X`) through both `let|const|var` assignments and
 * template-literal / `+`-concat construction of the filter string.
 */
export function findJsLdapInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  // Gate: must reference an ldapjs/ldapts-shaped `.search(...)` call AND
  // an Express-shaped request extractor.
  if (!/\.\s*search\s*\(/.test(code)) return findings;
  if (!/\breq\s*\.\s*(?:query|body|params|headers|cookies)\b/.test(code)) {
    return findings;
  }
  // Soft library gate — only fire when ldapjs or ldapts is in the file.
  if (!/\b(?:ldapjs|ldapts|require\(['"]ldapjs['"]\)|from\s+['"]ldapts['"])\b/.test(
    code,
  )) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe = /\breq\s*\.\s*(?:query|body|params|headers|cookies)\b/;
  const taintedVars = new Set<string>();

  // 3-pass whole-file taint propagation across `(const|let|var) x = expr`.
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('//')) continue;
      const m = t.match(/^(?:const|let|var)\s+(\w+)(?:\s*:\s*[^=]+)?\s*=\s*(.+?);?$/);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  // Find lines containing `filter: <expr>` (object property) where the
  // expression resolves to a tainted symbol, plus the shorthand
  // `{ filter, ... }` / `{ ..., filter }` form (ES6 property shorthand
  // means `{ filter }` is equivalent to `{ filter: filter }`).
  const filterPropRe = /\bfilter\s*:\s*([^,}\n]+)/;
  const filterShorthandRe = /(?:^|[\{,])\s*filter\s*[,}]/;
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fm = line.match(filterPropRe);
    let expr: string | null = null;
    if (fm) {
      expr = fm[1].trim();
    } else if (filterShorthandRe.test(line)) {
      // Shorthand: value is the local symbol named "filter".
      expr = 'filter';
    } else {
      continue;
    }
    // Tainted if any tainted var appears in the expression.
    let tainted = false;
    for (const v of taintedVars) {
      if (new RegExp(`\\b${v}\\b`).test(expr)) {
        tainted = true;
        break;
      }
    }
    if (!tainted) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `ldap_injection-${file}-${i + 1}-js-ldap-filter`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'ldap_injection',
      cwe: 'CWE-90',
      severity: 'critical',
      level: 'error',
      message:
        'LDAP injection: ldapjs/ldapts `client.search(..., { filter: ' +
        '<tainted>, ... })` lets the attacker break out of the filter ' +
        'expression (e.g. `*)(uid=*`) and enumerate the directory. ' +
        'Escape the user input with a tight allowlist (`[A-Za-z0-9_-]+`) ' +
        'or use a structured filter builder.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 87 detector B (#189) — Go LDAP injection via go-ldap/ldap.v3
 * `ldap.NewSearchRequest(base, scope, deref, sizeLimit, timeLimit,
 * typesOnly, <tainted-filter>, attributes, controls)`.
 *
 * The 7th positional argument is the LDAP filter. The detector tracks
 * tainted strings derived from `r.URL.Query().Get(...)` / `r.Form.Get`
 * / `r.PostForm.Get` / `r.FormValue` / `r.PostFormValue` through
 * `:=`/`=` assignments and `fmt.Sprintf` calls, then fires when the
 * filter slot resolves to a tainted symbol. CWE-90.
 */
export function findGoLdapInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\bldap\s*\.\s*NewSearchRequest\s*\(/.test(code)) return findings;
  if (!/\br\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)|Form|PostForm|FormValue|PostFormValue|Header)/.test(
    code,
  )) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe =
    /\br\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get|Form\s*\.\s*Get|PostForm\s*\.\s*Get|FormValue|PostFormValue|Header\s*\.\s*Get)\s*\(/;

  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('//')) continue;
      // `name := expr` or `name = expr`
      const m = t.match(/^(\w+)\s*(?::=|=)\s*(.+?)$/);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  // Multiline-tolerant scan: NewSearchRequest call may span several
  // lines. Find each opener and collect its full argument span.
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const openIdx = lines[i].indexOf('NewSearchRequest(');
    if (openIdx === -1) continue;
    // Aggregate text from `i` until we balance the parens.
    let depth = 0;
    let buf = '';
    let endLine = i;
    let started = false;
    for (let j = i; j < Math.min(i + 25, lines.length); j++) {
      for (const ch of lines[j]) {
        if (ch === '(') {
          depth++;
          started = true;
        } else if (ch === ')') {
          depth--;
        }
        buf += ch;
        if (started && depth === 0) {
          endLine = j;
          break;
        }
      }
      if (started && depth === 0) break;
      buf += '\n';
    }
    // buf now contains "NewSearchRequest(...)". Strip prefix.
    const argsStart = buf.indexOf('(');
    if (argsStart === -1) continue;
    const args = buf.substring(argsStart + 1, buf.length - 1);
    // Top-level split on commas (string-literal aware).
    const parts: string[] = [];
    {
      let d = 0;
      let b = '';
      let inStr: string | null = null;
      for (let k = 0; k < args.length; k++) {
        const ch = args[k];
        if (inStr) {
          if (ch === '\\') {
            b += ch + (args[k + 1] ?? '');
            k++;
            continue;
          }
          if (ch === inStr) inStr = null;
          b += ch;
          continue;
        }
        if (ch === '"' || ch === '`') {
          inStr = ch;
          b += ch;
          continue;
        }
        if (ch === '(' || ch === '[' || ch === '{') d++;
        else if (ch === ')' || ch === ']' || ch === '}') d--;
        if (ch === ',' && d === 0) {
          parts.push(b);
          b = '';
          continue;
        }
        b += ch;
      }
      if (b.trim().length > 0) parts.push(b);
    }
    if (parts.length < 7) continue;
    const filterExpr = parts[6].trim();
    let tainted = false;
    for (const v of taintedVars) {
      if (new RegExp(`\\b${v}\\b`).test(filterExpr)) {
        tainted = true;
        break;
      }
    }
    if (!tainted) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `ldap_injection-${file}-${i + 1}-go-newsearchrequest`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'ldap_injection',
      cwe: 'CWE-90',
      severity: 'critical',
      level: 'error',
      message:
        'LDAP injection: go-ldap `ldap.NewSearchRequest(..., <tainted ' +
        'filter>, ...)` lets the attacker break out of the filter ' +
        'expression and enumerate the directory. Escape the user input ' +
        'with `ldap.EscapeFilter(...)` or use a structured filter ' +
        'builder.',
      file,
      line: i + 1,
      snippet: (lines[i] + (endLine > i ? ' …' : '')).trim(),
    });
  }
  return findings;
}

/**
 * Sprint 87 detector C (#189) — Rust LDAP injection via ldap3
 * `LdapConn::search(base, scope, &<tainted-filter>, attrs)` (and the
 * async `Ldap::search(...)` mirror).
 *
 * The 3rd positional argument is the LDAP filter. Tainted strings come
 * from actix-web `web::Query<HashMap<String, String>>` / `web::Path` /
 * `web::Form` / `web::Json` parameter types (extractor handlers) and
 * propagate through `let` bindings and `format!(...)` macros. CWE-90.
 */
export function findRustLdapInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\.\s*search\s*\(/.test(code)) return findings;
  if (!/\b(?:ldap3|LdapConn|Ldap)\b/.test(code)) return findings;

  const lines = code.split('\n');
  const extractorTypeRe =
    /:\s*(?:String|Bytes|bytes::Bytes|axum::body::Bytes|web::Query\b|web::Path\b|web::Form\b|web::Json\b|HttpRequest\b|actix_web::HttpRequest\b)/;

  // Discover per-function tainted params: scan `fn ...(params)` headers.
  type Fn = { start: number; end: number; tainted: Set<string> };
  const fns: Fn[] = [];
  let cur: Fn | null = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (/^\s*(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*\(/.test(t)) {
      if (cur) {
        cur.end = i - 1;
        fns.push(cur);
      }
      cur = { start: i, end: lines.length - 1, tainted: new Set() };
      // Assemble multi-line header.
      let headerJoined = '';
      for (let j = i; j < Math.min(i + 12, lines.length); j++) {
        headerJoined += lines[j];
        if (/\{\s*$/.test(lines[j])) break;
      }
      const open = headerJoined.indexOf('(');
      const close = headerJoined.lastIndexOf(')');
      if (open !== -1 && close > open) {
        const params = headerJoined.substring(open + 1, close);
        let depth = 0;
        let buf = '';
        const parts: string[] = [];
        for (const ch of params) {
          if (ch === '<' || ch === '(') depth++;
          else if (ch === '>' || ch === ')') depth--;
          if (ch === ',' && depth === 0) {
            parts.push(buf);
            buf = '';
            continue;
          }
          buf += ch;
        }
        if (buf.trim().length > 0) parts.push(buf);
        for (const p of parts) {
          const pm = p.match(/(?:mut\s+)?(\w+)\s*:/);
          if (!pm) continue;
          if (extractorTypeRe.test(p)) cur.tainted.add(pm[1]);
        }
      }
    }
  }
  if (cur) fns.push(cur);

  // Propagate taint through `let` bindings.
  for (const fn of fns) {
    for (let pass = 0; pass < 3; pass++) {
      const before = fn.tainted.size;
      for (let i = fn.start; i <= fn.end; i++) {
        const t = lines[i].trim();
        const m = t.match(/^let\s+(?:mut\s+)?(\w+)\s*(?::\s*[^=]+)?=\s*(.+?);?$/);
        if (!m) continue;
        const lhs = m[1];
        const rhs = m[2];
        if (fn.tainted.has(lhs)) continue;
        for (const v of fn.tainted) {
          if (new RegExp(`\\b${v}\\b`).test(rhs)) {
            fn.tainted.add(lhs);
            break;
          }
        }
      }
      if (fn.tainted.size === before) break;
    }
  }

  // Multiline-tolerant `.search(` call walker.
  const seen = new Set<number>();
  for (const fn of fns) {
    if (fn.tainted.size === 0) continue;
    for (let i = fn.start; i <= fn.end; i++) {
      const searchIdx = lines[i].indexOf('.search(');
      if (searchIdx === -1) continue;
      // Assemble args span.
      let depth = 0;
      let buf = '';
      let started = false;
      for (let j = i; j < Math.min(i + 15, lines.length); j++) {
        const startCol = j === i ? searchIdx : 0;
        for (let k = startCol; k < lines[j].length; k++) {
          const ch = lines[j][k];
          if (ch === '(') {
            depth++;
            started = true;
          } else if (ch === ')') {
            depth--;
          }
          buf += ch;
          if (started && depth === 0) break;
        }
        if (started && depth === 0) break;
        buf += '\n';
      }
      const argsStart = buf.indexOf('(');
      if (argsStart === -1) continue;
      const args = buf.substring(argsStart + 1, buf.length - 1);
      // String-literal aware top-level comma split.
      const parts: string[] = [];
      {
        let d = 0;
        let b = '';
        let inStr: string | null = null;
        for (let k = 0; k < args.length; k++) {
          const ch = args[k];
          if (inStr) {
            if (ch === '\\') {
              b += ch + (args[k + 1] ?? '');
              k++;
              continue;
            }
            if (ch === inStr) inStr = null;
            b += ch;
            continue;
          }
          if (ch === '"') {
            inStr = ch;
            b += ch;
            continue;
          }
          if (ch === '(' || ch === '[' || ch === '{') d++;
          else if (ch === ')' || ch === ']' || ch === '}') d--;
          if (ch === ',' && d === 0) {
            parts.push(b);
            b = '';
            continue;
          }
          b += ch;
        }
        if (b.trim().length > 0) parts.push(b);
      }
      // ldap3 search signature: search(base, scope, filter, attrs)
      if (parts.length < 3) continue;
      const filterExpr = parts[2].trim();
      let tainted = false;
      for (const v of fn.tainted) {
        if (new RegExp(`\\b${v}\\b`).test(filterExpr)) {
          tainted = true;
          break;
        }
      }
      if (!tainted) continue;
      if (seen.has(i + 1)) continue;
      seen.add(i + 1);
      findings.push({
        id: `ldap_injection-${file}-${i + 1}-rust-ldap3-search`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'ldap_injection',
        cwe: 'CWE-90',
        severity: 'critical',
        level: 'error',
        message:
          'LDAP injection: ldap3 `LdapConn::search(..., &<tainted ' +
          'filter>, ...)` lets the attacker break out of the filter ' +
          'expression and enumerate the directory. Escape the user input ' +
          'or use a structured filter builder.',
        file,
        line: i + 1,
        snippet: lines[i].trim(),
      });
    }
  }
  return findings;
}

/**
 * Sprint 87 detector D (#189) — Rust log injection via the `log` crate
 * macros (`info!`, `warn!`, `error!`, `debug!`, `trace!`) where a
 * tainted value is interpolated into the format args.
 *
 * Unsanitized CRLF in log lines can split log entries, forge
 * authentication events, or escape into log-aggregation pipelines that
 * parse newlines as record boundaries. CWE-117.
 */
export function findRustLogInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\b(?:info|warn|error|debug|trace)\s*!\s*\(/.test(code)) return findings;
  if (!/\b(?:log|tracing)\b/.test(code)) return findings;

  const lines = code.split('\n');
  const extractorTypeRe =
    /:\s*(?:String|Bytes|bytes::Bytes|axum::body::Bytes|web::Query\b|web::Path\b|web::Form\b|web::Json\b|HttpRequest\b|actix_web::HttpRequest\b)/;

  type Fn = { start: number; end: number; tainted: Set<string> };
  const fns: Fn[] = [];
  let cur: Fn | null = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (/^\s*(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*\(/.test(t)) {
      if (cur) {
        cur.end = i - 1;
        fns.push(cur);
      }
      cur = { start: i, end: lines.length - 1, tainted: new Set() };
      let headerJoined = '';
      for (let j = i; j < Math.min(i + 12, lines.length); j++) {
        headerJoined += lines[j];
        if (/\{\s*$/.test(lines[j])) break;
      }
      const open = headerJoined.indexOf('(');
      const close = headerJoined.lastIndexOf(')');
      if (open !== -1 && close > open) {
        const params = headerJoined.substring(open + 1, close);
        let depth = 0;
        let buf = '';
        const parts: string[] = [];
        for (const ch of params) {
          if (ch === '<' || ch === '(') depth++;
          else if (ch === '>' || ch === ')') depth--;
          if (ch === ',' && depth === 0) {
            parts.push(buf);
            buf = '';
            continue;
          }
          buf += ch;
        }
        if (buf.trim().length > 0) parts.push(buf);
        for (const p of parts) {
          const pm = p.match(/(?:mut\s+)?(\w+)\s*:/);
          if (!pm) continue;
          if (extractorTypeRe.test(p)) cur.tainted.add(pm[1]);
        }
      }
    }
  }
  if (cur) fns.push(cur);

  for (const fn of fns) {
    for (let pass = 0; pass < 3; pass++) {
      const before = fn.tainted.size;
      for (let i = fn.start; i <= fn.end; i++) {
        const t = lines[i].trim();
        const m = t.match(/^let\s+(?:mut\s+)?(\w+)\s*(?::\s*[^=]+)?=\s*(.+?);?$/);
        if (!m) continue;
        const lhs = m[1];
        const rhs = m[2];
        if (fn.tainted.has(lhs)) continue;
        for (const v of fn.tainted) {
          if (new RegExp(`\\b${v}\\b`).test(rhs)) {
            fn.tainted.add(lhs);
            break;
          }
        }
      }
      if (fn.tainted.size === before) break;
    }
  }

  const macroRe = /\b(info|warn|error|debug|trace)\s*!\s*\(\s*([^;]+?)\)\s*;?\s*$/;
  const seen = new Set<string>();
  for (const fn of fns) {
    if (fn.tainted.size === 0) continue;
    for (let i = fn.start; i <= fn.end; i++) {
      const line = lines[i];
      const m = line.match(macroRe);
      if (!m) continue;
      const macroName = m[1];
      const argSpan = m[2];
      // Split on top-level commas to separate the fmt-string from args.
      const parts: string[] = [];
      {
        let d = 0;
        let b = '';
        let inStr: string | null = null;
        for (let k = 0; k < argSpan.length; k++) {
          const ch = argSpan[k];
          if (inStr) {
            if (ch === '\\') {
              b += ch + (argSpan[k + 1] ?? '');
              k++;
              continue;
            }
            if (ch === inStr) inStr = null;
            b += ch;
            continue;
          }
          if (ch === '"') {
            inStr = ch;
            b += ch;
            continue;
          }
          if (ch === '(' || ch === '[' || ch === '{') d++;
          else if (ch === ')' || ch === ']' || ch === '}') d--;
          if (ch === ',' && d === 0) {
            parts.push(b);
            b = '';
            continue;
          }
          b += ch;
        }
        if (b.trim().length > 0) parts.push(b);
      }
      if (parts.length < 2) continue;
      // Any of the format args (parts[1..]) being tainted = fire.
      let tainted = false;
      for (let p = 1; p < parts.length; p++) {
        for (const v of fn.tainted) {
          if (new RegExp(`\\b${v}\\b`).test(parts[p])) {
            tainted = true;
            break;
          }
        }
        if (tainted) break;
      }
      if (!tainted) continue;
      const key = `${i + 1}:${macroName}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `log_injection-${file}-${i + 1}-rust-${macroName}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'log_injection',
        cwe: 'CWE-117',
        severity: 'medium',
        level: 'warning',
        message:
          `Log injection: Rust \`${macroName}!(...)\` interpolates a ` +
          'tainted value into the log line. Unsanitized CRLF lets an ' +
          'attacker forge log entries or split records. Strip control ' +
          'characters or use a structured logging API.',
        file,
        line: i + 1,
        snippet: line.trim(),
      });
    }
  }
  return findings;
}

/**
 * Sprint 89 detector A (#189) — Go insecure deserialization via
 * `encoding/gob` `gob.NewDecoder(<req-body>).Decode(&v)`.
 *
 * The `gob` package will reconstruct arbitrary Go values, and any
 * registered concrete type can be instantiated by the attacker through
 * `gob.Register(...)` side effects. Decoding directly from
 * `r.Body` (`*http.Request`) without authenticated framing is unsafe.
 * CWE-502.
 */
export function findGoGobDeserializationFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\bgob\s*\.\s*NewDecoder\s*\(/.test(code)) return findings;
  if (!/\*http\.Request\b/.test(code) && !/\bhttp\.HandlerFunc\b/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  // Track variables holding a *gob.Decoder constructed from req body.
  const decoderFromBody = new Set<string>();
  const newDecoderAssignRe =
    /^(\w+)\s*(?::=|=)\s*gob\s*\.\s*NewDecoder\s*\(\s*([^)]+)\)/;
  for (const raw of lines) {
    const t = raw.trim();
    if (t.startsWith('//')) continue;
    const m = t.match(newDecoderAssignRe);
    if (!m) continue;
    const lhs = m[1];
    const arg = m[2];
    if (/\b\w+\s*\.\s*Body\b/.test(arg)) {
      decoderFromBody.add(lhs);
    }
  }

  const seen = new Set<number>();
  if (decoderFromBody.size > 0) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith('//')) continue;
      const m = line.match(/\b(\w+)\s*\.\s*Decode\s*\(/);
      if (!m) continue;
      if (!decoderFromBody.has(m[1])) continue;
      if (seen.has(i + 1)) continue;
      seen.add(i + 1);
      findings.push({
        id: `insecure_deserialization-${file}-${i + 1}-go-gob`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'insecure_deserialization',
        cwe: 'CWE-502',
        severity: 'critical',
        level: 'error',
        message:
          'Insecure deserialization: `gob.NewDecoder(req.Body).Decode(...)` ' +
          'reconstructs arbitrary registered Go types from attacker-controlled ' +
          'bytes. Use an authenticated framing (signed/MAC payloads), avoid ' +
          'decoding interface{} values, or switch to a schema-bound format ' +
          '(JSON with explicit types, Protocol Buffers).',
        file,
        line: i + 1,
        snippet: line.trim(),
      });
    }
  }
  // Inline form — `gob.NewDecoder(req.Body).Decode(&v)`.
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('//')) continue;
    if (
      !/\bgob\s*\.\s*NewDecoder\s*\(\s*\w+\s*\.\s*Body\s*\)\s*\.\s*Decode\s*\(/.test(
        line,
      )
    ) {
      continue;
    }
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `insecure_deserialization-${file}-${i + 1}-go-gob-inline`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'insecure_deserialization',
      cwe: 'CWE-502',
      severity: 'critical',
      level: 'error',
      message:
        'Insecure deserialization: `gob.NewDecoder(req.Body).Decode(...)` ' +
        'reconstructs arbitrary registered Go types from attacker-controlled ' +
        'bytes. Use an authenticated framing (signed/MAC payloads), avoid ' +
        'decoding interface{} values, or switch to a schema-bound format ' +
        '(JSON with explicit types, Protocol Buffers).',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 89 detector B (#189) — JS insecure deserialization via
 * `JSON.parse(req.body)`.
 *
 * Express applications that register `express.text(...)` or
 * `bodyParser.raw(...)` middleware leave `req.body` as an
 * attacker-controlled string. Passing it through `JSON.parse(...)`
 * exposes prototype-pollution paths if the parsed object is then
 * merged into trusted state or used as a property bag. CWE-502 /
 * CWE-1321 (prototype-pollution adjacent).
 *
 * Conservative gate: only fire on `JSON.parse(<expr>)` where
 * `<expr>` resolves to `req.body` (the only express extractor that
 * is genuinely a raw string when text/raw bodyparsing is used).
 */
export function findJsJsonParseBodyFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\bJSON\s*\.\s*parse\s*\(/.test(code)) return findings;
  if (!/\breq\s*\.\s*body\b/.test(code)) return findings;

  const lines = code.split('\n');
  const reqBodyRe = /\breq\s*\.\s*body\b/;
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('//')) continue;
      const m = t.match(/^(?:const|let|var)\s+(\w+)(?:\s*:\s*[^=]+)?\s*=\s*(.+?);?$/);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (reqBodyRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }

  const callRe = /\bJSON\s*\.\s*parse\s*\(\s*([^)]+?)\s*\)/g;
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('//')) continue;
    callRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = callRe.exec(line)) !== null) {
      const arg = m[1];
      let tainted = reqBodyRe.test(arg);
      if (!tainted) {
        for (const v of taintedVars) {
          if (new RegExp(`\\b${v}\\b`).test(arg)) {
            tainted = true;
            break;
          }
        }
      }
      if (!tainted) continue;
      if (seen.has(i + 1)) continue;
      seen.add(i + 1);
      findings.push({
        id: `insecure_deserialization-${file}-${i + 1}-js-jsonparse-body`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'insecure_deserialization',
        cwe: 'CWE-502',
        severity: 'high',
        level: 'warning',
        message:
          '`JSON.parse(req.body)` deserializes attacker-controlled bytes ' +
          'directly. With `express.text()` / `bodyParser.raw()` middleware ' +
          '`req.body` is an unvetted string; the parsed object can carry a ' +
          '`__proto__` payload that pollutes downstream property lookups. ' +
          'Validate against a schema (zod/ajv) before consuming the value.',
        file,
        line: i + 1,
        snippet: line.trim(),
      });
    }
  }
  return findings;
}

/**
 * Sprint 89 detector C (#189) — JS DOM XPath injection via
 * `document.evaluate(<tainted>, ...)`.
 *
 * The DOM `XPathEvaluator.evaluate()` API takes a string XPath
 * expression as its first argument. When that string is built from
 * `location.search` / `location.hash` / URLSearchParams without
 * escaping, the attacker can rewrite the query (e.g. injecting
 * `' or '1'='1`-style predicates) and exfiltrate other nodes. CWE-643.
 *
 * Gate: file must reference `XPathResult` (strong DOM-XPath signal)
 * AND call `.evaluate(`, AND contain a browser taint source
 * (`location.search`, `location.hash`, `URLSearchParams`).
 */
export function findJsDomXpathInjectionFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\.\s*evaluate\s*\(/.test(code)) return findings;
  if (!/\bXPathResult\b/.test(code)) return findings;
  const browserSourceRe =
    /\b(?:location\s*\.\s*(?:search|hash|href)|URLSearchParams|window\s*\.\s*name|document\s*\.\s*cookie)\b/;
  if (!browserSourceRe.test(code)) return findings;

  const lines = code.split('\n');
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('//')) continue;
      const m = t.match(/^(?:const|let|var)\s+(\w+)(?:\s*:\s*[^=]+)?\s*=\s*(.+?);?$/);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (browserSourceRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  const evalRe = /\.\s*evaluate\s*\(\s*([^,)]+)/;
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('//')) continue;
    const m = line.match(evalRe);
    if (!m) continue;
    const arg = m[1].trim();
    let tainted = false;
    for (const v of taintedVars) {
      if (new RegExp(`\\b${v}\\b`).test(arg)) {
        tainted = true;
        break;
      }
    }
    if (!tainted) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `xpath_injection-${file}-${i + 1}-js-dom-evaluate`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xpath_injection',
      cwe: 'CWE-643',
      severity: 'high',
      level: 'warning',
      message:
        'XPath injection: `document.evaluate(<tainted>, ...)` lets the ' +
        'attacker break out of the XPath expression and read sibling ' +
        'nodes. Bind user input through XPath variables / parameterized ' +
        'expressions, or escape with an allowlist before concatenation.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 90 detector A (#189) — Go XXE via `encoding/xml` decoder with
 * `d.Strict = false` (allows DTD-like constructs and custom Entity
 * resolution to be configured on the decoder). When the source stream
 * is `*http.Request.Body`, the attacker can submit a payload that
 * triggers entity-expansion / external-entity reads through the
 * `Entity` map. CWE-611 / CWE-776.
 */
export function findGoXmlDecoderXxeFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\bxml\s*\.\s*NewDecoder\s*\(/.test(code)) return findings;
  if (!/\*http\.Request\b/.test(code) && !/\bhttp\.HandlerFunc\b/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  // Track decoder vars constructed from req.Body.
  const decoderFromBody = new Map<string, number>(); // var -> line idx
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.startsWith('//')) continue;
    const m = t.match(
      /^(\w+)\s*(?::=|=)\s*xml\s*\.\s*NewDecoder\s*\(\s*([^)]+)\)/,
    );
    if (!m) continue;
    if (/\b\w+\s*\.\s*Body\b/.test(m[2])) decoderFromBody.set(m[1], i);
  }
  if (decoderFromBody.size === 0) return findings;

  // Only fire if downstream we see `<dec>.Strict = false` or
  // `<dec>.Entity = ...` (entity-map override).
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('//')) continue;
    const m = line.match(
      /\b(\w+)\s*\.\s*(?:Strict\s*=\s*false|Entity\s*=)\b/,
    );
    if (!m) continue;
    if (!decoderFromBody.has(m[1])) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `xml_entity_expansion-${file}-${i + 1}-go-xml-decoder`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'xml_entity_expansion',
      cwe: 'CWE-611',
      severity: 'high',
      level: 'warning',
      message:
        'XXE: Go `xml.NewDecoder(req.Body)` with `Strict = false` (or a ' +
        'custom `Entity` map) allows entity references that the standard ' +
        'library normally rejects. Keep `Strict = true` and avoid setting ' +
        '`Entity` from attacker-controlled inputs.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 90 detector B (#189) — Python SSTI via Jinja2
 * `Template(<tainted>).render(...)`.
 *
 * Constructing a `jinja2.Template` from attacker-controlled source
 * gives the attacker the entire Jinja sandbox-escape surface
 * (`{{ ''.__class__.__mro__[1].__subclasses__() ... }}`). CWE-1336.
 *
 * Gate: file must import `jinja2.Template` AND construct it from a
 * Flask/FastAPI request extractor (request.args/form/values/json/data).
 */
export function findPythonJinjaTemplateSstiFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (!/\bfrom\s+jinja2\s+import\s+[^#\n]*\bTemplate\b/.test(code) &&
      !/\bjinja2\s*\.\s*Template\b/.test(code)) {
    return findings;
  }
  const reqExtractRe =
    /\brequest\s*\.\s*(?:args|form|values|json|data|cookies|headers)\b/;
  if (!reqExtractRe.test(code)) return findings;

  const lines = code.split('\n');
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('#')) continue;
      const m = t.match(/^(\w+)\s*=\s*(.+?)$/);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  const ctorRe = /\b(?:jinja2\s*\.\s*)?Template\s*\(\s*([^)]+?)\s*\)/;
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('#')) continue;
    const m = line.match(ctorRe);
    if (!m) continue;
    const arg = m[1].trim();
    let tainted = reqExtractRe.test(arg);
    if (!tainted) {
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(arg)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `template_injection-${file}-${i + 1}-py-jinja-template`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'template_injection',
      cwe: 'CWE-1336',
      severity: 'critical',
      level: 'error',
      message:
        'Server-side template injection: `jinja2.Template(<tainted>).render()` ' +
        'compiles attacker-controlled source. Sandbox-escape gadgets such as ' +
        '`{{ ().__class__.__bases__[0].__subclasses__() }}` lead to RCE. ' +
        'Render fixed templates with user data passed as context variables.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}

/**
 * Sprint 90 detector C (#189) — JS SSTI via `Handlebars.compile(<tainted>)`
 * or `ejs.render(<tainted>, ...)` / `ejs.compile(<tainted>)`.
 *
 * Compiling an attacker-controlled template lets the attacker execute
 * arbitrary code through helper-shadowing / prototype gadgets
 * (Handlebars CVE-2019-19919 chains, EJS render-options escape). CWE-1336.
 */
export function findJsTemplateInjectionSstiFindings(
  code: string,
  file: string,
): SastFinding[] {
  const findings: SastFinding[] = [];
  if (typeof code !== 'string' || code.length === 0) return findings;
  if (
    !/\bHandlebars\s*\.\s*compile\s*\(/.test(code) &&
    !/\bejs\s*\.\s*(?:render|compile)\s*\(/.test(code)
  ) {
    return findings;
  }
  if (!/\breq\s*\.\s*(?:query|body|params|headers|cookies)\b/.test(code)) {
    return findings;
  }

  const lines = code.split('\n');
  const reqExtractRe = /\breq\s*\.\s*(?:query|body|params|headers|cookies)\b/;
  const taintedVars = new Set<string>();
  for (let pass = 0; pass < 3; pass++) {
    const before = taintedVars.size;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t.startsWith('//')) continue;
      const m = t.match(/^(?:const|let|var)\s+(\w+)(?:\s*:\s*[^=]+)?\s*=\s*(.+?);?$/);
      if (!m) continue;
      const lhs = m[1];
      const rhs = m[2];
      if (taintedVars.has(lhs)) continue;
      if (reqExtractRe.test(rhs)) {
        taintedVars.add(lhs);
        continue;
      }
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(rhs)) {
          taintedVars.add(lhs);
          break;
        }
      }
    }
    if (taintedVars.size === before) break;
  }
  if (taintedVars.size === 0) return findings;

  const callRe =
    /\b(Handlebars\s*\.\s*compile|ejs\s*\.\s*(?:render|compile))\s*\(\s*([^,)]+)/;
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('//')) continue;
    const m = line.match(callRe);
    if (!m) continue;
    const arg = m[2].trim();
    let tainted = reqExtractRe.test(arg);
    if (!tainted) {
      for (const v of taintedVars) {
        if (new RegExp(`\\b${v}\\b`).test(arg)) {
          tainted = true;
          break;
        }
      }
    }
    if (!tainted) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `template_injection-${file}-${i + 1}-js-${m[1].replace(/[\s.]/g, '').toLowerCase()}`,
      pass: 'language-sources',
      category: 'security',
      rule_id: 'template_injection',
      cwe: 'CWE-1336',
      severity: 'critical',
      level: 'error',
      message:
        'Server-side template injection: compiling/rendering a template ' +
        'whose source is attacker-controlled (`Handlebars.compile(...)` / ' +
        '`ejs.render(...)`) opens helper-shadowing and prototype-gadget RCE ' +
        'paths. Use a fixed template and pass user data as context.',
      file,
      line: i + 1,
      snippet: line.trim(),
    });
  }
  return findings;
}
