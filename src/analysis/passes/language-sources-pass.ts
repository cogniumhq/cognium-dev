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

import type { TaintSource, TaintSink, TypeInfo, SourceType } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';

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

    // -- Java: getter methods that return tainted constructor fields ----------
    additionalSources.push(...findGetterSources(types, constProp.instanceFieldTaint, code));

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

    return { additionalSources, additionalSinks, pyTaintedVars, pySanitizedVars, jsTaintedVars };
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

    const subscriptAssign = line.match(/^\s*(\w+)\[(['"])([^'"]+)\2\]\s*=\s*(.+)$/);
    if (subscriptAssign) {
      const [, container, , key, rhs2] = subscriptAssign;
      const isTaintedRhs = [...tainted.keys()].some(v => new RegExp(`\\b${v}\\b`).test(rhs2));
      if (isTaintedRhs) containerTainted.set(`${container}['${key}']`, i + 1);
      continue;
    }

    const setCallMatch = line.match(/^\s*(\w+)\.set\s*\(\s*(['"])([^'"]+)\2\s*,\s*(['"])([^'"]+)\4\s*,\s*(.+?)\s*\)$/);
    if (setCallMatch) {
      const [, obj, , section, , key, rhs2] = setCallMatch;
      const isTaintedRhs = [...tainted.keys()].some(v => new RegExp(`\\b${v}\\b`).test(rhs2));
      if (isTaintedRhs) containerTainted.set(`${obj}['${section}']['${key}']`, i + 1);
      continue;
    }

    const augAssign = line.match(/^\s*(\w+)\s*\+=\s*(.+)$/);
    if (augAssign) {
      const [, augLhs, augRhs] = augAssign;
      const rhsTainted = [...tainted.keys()].some(v => new RegExp(`\\b${v}\\b`).test(augRhs));
      if (rhsTainted || tainted.has(augLhs)) tainted.set(augLhs, tainted.get(augLhs) ?? (i + 1));
      continue;
    }

    const forLoopMatch = line.match(/^\s*for\s+(\w+)\s+in\s+(.+?)(?:\s*:\s*)?$/);
    if (forLoopMatch) {
      const [, iterVar, iterExpr] = forLoopMatch;
      const isDirectSource = PYTHON_TAINTED_PATTERNS.some(p => p.pattern.test(iterExpr));
      const isPropagated = [...tainted.keys()].some(v => new RegExp(`\\b${v}\\b`).test(iterExpr));
      if (isDirectSource || isPropagated) tainted.set(iterVar, i + 1);
      continue;
    }

    const assignMatch = line.match(/^\s*(\w+)\s*=\s*(.+)$/);
    if (!assignMatch) continue;
    const [, lhs, rhs] = assignMatch;

    const isDirectSource = PYTHON_TAINTED_PATTERNS.some(p => p.pattern.test(rhs));
    let propagatedFrom: string | undefined;

    const dictAccessMatch = rhs.trim().match(/^(\w+)\[(['"])([^'"]+)\2\]$/);
    if (dictAccessMatch) {
      const [, container, , key] = dictAccessMatch;
      if (containerTainted.has(`${container}['${key}']`)) propagatedFrom = `${container}['${key}']`;
    }

    if (!propagatedFrom) {
      const confGetMatch = rhs.trim().match(/^(\w+)\.get\s*\(\s*(['"])([^'"]+)\2\s*,\s*(['"])([^'"]+)\4\s*\)$/);
      if (confGetMatch) {
        const [, obj, , section, , key] = confGetMatch;
        if (containerTainted.has(`${obj}['${section}']['${key}']`)) propagatedFrom = `${obj}['${section}']['${key}']`;
      }
    }

    if (!propagatedFrom) {
      const isSafeEnvRead = /\bos\.environ\.get\s*\(/.test(rhs) || /\bos\.getenv\s*\(/.test(rhs);
      if (!isSafeEnvRead) propagatedFrom = [...tainted.keys()].find(v => new RegExp(`\\b${v}\\b`).test(rhs));
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
