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
  if (language !== 'java' && language !== 'python') return [];
  const sources: TaintSource[] = [];
  const lines = sourceCode.split('\n');
  const isPython = language === 'python';
  const SELF = isPython ? 'self' : 'this';

  // Common Java HTTP-source receivers / methods. Conservative: matches
  // `request.getParameter` style calls but not arbitrary `foo.getName()`.
  const javaHttpPattern = /\b(?:req|request|httpRequest|servletRequest|httpServletRequest)\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getPathInfo|getRequestURI|getRequestURL|getInputStream|getReader)\b/;

  const fieldAssignRe = new RegExp(`^\\s*${SELF}\\.([A-Za-z_]\\w*)\\s*=\\s*(.+?)(?:;\\s*)?$`);
  const commentPrefix = isPython ? '#' : '//';

  for (const type of types) {
    if (type.kind !== 'class') continue;
    if (type.name === '<module>') continue;

    // Locate constructor.
    let ctor: typeof type.methods[number] | undefined;
    for (const m of type.methods) {
      if (isPython) {
        if (m.name === '__init__') { ctor = m; break; }
      } else {
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
      const m = line.match(fieldAssignRe);
      if (!m) continue;
      const fieldName = m[1];
      const rhs = m[2].trim().replace(/;\s*$/, '');

      let sourceType: SourceType | null = null;
      if (paramNames.has(rhs)) {
        sourceType = 'interprocedural_param';
      } else if (!isPython && javaHttpPattern.test(rhs)) {
        sourceType = 'http_param';
      } else if (isPython) {
        for (const { pattern, type } of PYTHON_TAINTED_PATTERNS) {
          if (pattern.test(rhs)) { sourceType = type; break; }
        }
      }
      if (sourceType) {
        fieldTaint.set(fieldName, { line: i + 1, type: sourceType });
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
      }
      if (returnStatementCount === 1 && returnedField && fieldTaint.has(returnedField)) {
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
    sinks.push({ sinkLine: i + 1 });
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

export function findBashPatternFindings(sourceCode: string, file: string): SastFinding[] {
  const findings: SastFinding[] = [];
  const lines = sourceCode.split('\n');

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
      findings.push({
        id: `predictable-temp-file-${file}-${lineNumber}`,
        pass: 'language-sources',
        category: 'security',
        rule_id: 'predictable-temp-file',
        cwe: 'CWE-377',
        severity: 'medium',
        level: 'warning',
        message: `Predictable temp file: /tmp/${tmpMatch[1]}. Use mktemp instead`,
        file,
        line: lineNumber,
        snippet: trimmed.substring(0, 80),
      });
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
  }

  return findings;
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
