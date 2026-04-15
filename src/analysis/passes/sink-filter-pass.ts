/**
 * SinkFilterPass
 *
 * Applies the four-stage sink filtering pipeline to eliminate false positives,
 * followed by language-specific XPath/XSS suppression.
 *
 * Filter stages (applied in order):
 *   1. Dead code — remove sinks on unreachable lines
 *   2. Clean array elements — strong updates via constant propagation
 *   3. Clean variables — arguments proven non-tainted by constant propagation
 *   4. Sanitized sinks — sinks wrapped by a recognised sanitizer call
 *   5. Python XPath FP reduction
 *   6. JavaScript setAttribute FP reduction (safe attribute names)
 *   7. JavaScript XSS FP reduction
 *
 * Depends on: taint-matcher, constant-propagation, language-sources
 */

import type { TaintSource, TaintSink, TaintSanitizer } from '../../types/index.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { TaintMatcherResult } from './taint-matcher-pass.js';
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';
import type { LanguageSourcesResult } from './language-sources-pass.js';
import { JS_TAINTED_PATTERNS } from './language-sources-pass.js';

/**
 * Common XSS sanitizer patterns for JavaScript/TypeScript.
 * These indicate the assigned value has been sanitized before use.
 */
const JS_XSS_SANITIZERS = [
  /\bDOMPurify\.sanitize\s*\(/,
  /\bsanitizeHtml\s*\(/,
  /\bsanitize\s*\(/,
  /\bescapeHtml\s*\(/,
  /\bescapeHTML\s*\(/,
  /\bhtmlEscape\s*\(/,
  /\bxss\s*\(/,              // xss library
  /\bxssFilters\./,          // xss-filters library
  /\bvalidator\.escape\s*\(/,
  /\b(?:he|entities)\.encode\s*\(/,
  /\bencodeURIComponent\s*\(/,
  /\bencodeURI\s*\(/,
  /\bcreateSafeHTML\s*\(/,
  /\btrustAsHtml\s*\(/,      // Angular
  /\bbypassSecurityTrust/,   // Angular
];

export interface SinkFilterResult {
  /** Merged sources: taint-matcher + language-sources. */
  sources: TaintSource[];
  /** Filtered sinks. */
  sinks: TaintSink[];
  sanitizers: TaintSanitizer[];
}

export class SinkFilterPass implements AnalysisPass<SinkFilterResult> {
  readonly name = 'sink-filter';
  readonly category = 'security' as const;

  run(ctx: PassContext): SinkFilterResult {
    const { graph, language } = ctx;
    const { calls, dfg } = graph.ir;

    const taintMatcher = ctx.getResult<TaintMatcherResult>('taint-matcher');
    const constProp    = ctx.getResult<ConstantPropagatorResult>('constant-propagation');
    const langSources  = ctx.getResult<LanguageSourcesResult>('language-sources');

    // Merge sources and sinks from both upstream passes.
    const sources: TaintSource[] = [...taintMatcher.sources, ...langSources.additionalSources];

    // Build merged sinks, deduplicating JS DOM sinks that may overlap with config sinks.
    const sinks: TaintSink[] = [...taintMatcher.sinks];
    for (const s of langSources.additionalSinks) {
      if (!sinks.some(x => x.line === s.line && x.cwe === s.cwe && x.type === s.type)) {
        sinks.push(s);
      }
    }
    const sanitizers = taintMatcher.sanitizers;

    // Stage 1 — dead code
    let filtered = sinks.filter(sink => !constProp.unreachableLines.has(sink.line));

    // Stage 2 — clean array elements
    filtered = filterCleanArraySinks(filtered, calls, constProp.taintedArrayElements, constProp.symbols);

    // Stage 3 — clean variables
    filtered = filterCleanVariableSinks(
      filtered, calls, constProp.tainted, constProp.symbols,
      dfg, constProp.sanitizedVars, constProp.synchronizedLines,
    );

    // Stage 4 — sanitized sinks
    filtered = filterSanitizedSinks(filtered, sanitizers, calls);

    // Stage 5 — Python XPath FP reduction
    if (language === 'python') {
      const { pyTaintedVars, pySanitizedVars } = langSources;
      const sourceLines = ctx.code.split('\n');
      filtered = filtered.filter(sink => {
        if (sink.type !== 'xpath_injection') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';
        const taintedVarOnLine = [...pyTaintedVars.keys()].find(v =>
          new RegExp(`\\b${v}\\b`).test(sinkLineText)
        );
        if (!taintedVarOnLine) return false;
        if (pySanitizedVars.has(taintedVarOnLine)) return false;
        if (new RegExp(`\\.xpath\\s*\\([^)]*\\b\\w+\\s*=\\s*\\b${taintedVarOnLine}\\b`).test(sinkLineText)) return false;
        return true;
      });
    }

    // Build call-by-line index for Stages 6–7.
    const callsByLine = new Map<number, typeof calls>();
    for (const call of calls) {
      const existing = callsByLine.get(call.location.line) ?? [];
      existing.push(call);
      callsByLine.set(call.location.line, existing);
    }

    // Stage 6 — JavaScript setAttribute FP reduction
    // Only flag setAttribute when the attribute name is dangerous (on*, style, srcdoc).
    if (['javascript', 'typescript'].includes(language)) {
      filtered = filtered.filter(sink => {
        if (sink.method !== 'setAttribute') return true;
        const callsAtSink = callsByLine.get(sink.line) ?? [];
        const setAttrCalls = callsAtSink.filter(c => c.method_name === 'setAttribute');
        for (const call of setAttrCalls) {
          const firstArg = call.arguments[0];
          if (!firstArg) continue;
          // If first arg is a string literal, check if it's a dangerous attribute
          const attrName = firstArg.literal ?? (
            firstArg.expression && !firstArg.variable && isStringLiteralExpression(firstArg.expression)
              ? firstArg.expression.trim().replace(/^['"]|['"]$/g, '')
              : null
          );
          if (attrName != null) {
            const lower = String(attrName).toLowerCase();
            if (/^on\w+$/.test(lower) || lower === 'style' || lower === 'srcdoc') return true;
            return false; // Safe attribute like 'title', 'class', 'id', etc.
          }
          // Attribute name is dynamic — keep as dangerous (conservative)
          return true;
        }
        return true;
      });
    }

    // Stage 7 — JavaScript XSS FP reduction
    if (['javascript', 'typescript'].includes(language)) {
      const { jsTaintedVars } = langSources;
      const sourceLines = ctx.code.split('\n');

      filtered = filtered.filter(sink => {
        if (sink.type !== 'xss') return true;
        const sinkLineText = sourceLines[sink.line - 1] ?? '';

        // 6a. If a sanitizer is used on this line, suppress the finding
        if (JS_XSS_SANITIZERS.some(p => p.test(sinkLineText))) return false;

        // 6b. If the RHS is a pure string literal, suppress (e.g., `.innerHTML = "<div>Hello</div>"`)
        //     Match: `.innerHTML = "..."` or `.innerHTML = '...'` or `.innerHTML = `...``
        const assignmentMatch = sinkLineText.match(/\.(?:innerHTML|outerHTML)\s*=\s*(.+)/);
        if (assignmentMatch) {
          // Strip trailing semicolon and whitespace
          const rhs = assignmentMatch[1].trim().replace(/;$/, '').trim();
          // Pure double-quoted string literal
          if (/^"[^"]*"$/.test(rhs)) return false;
          // Pure single-quoted string literal
          if (/^'[^']*'$/.test(rhs)) return false;
          // Template literal without interpolation
          if (/^`[^`]*`$/.test(rhs) && !rhs.includes('${')) return false;
          // Empty string
          if (rhs === '""' || rhs === "''" || rhs === '``') return false;
        }

        // 6c. If known tainted vars exist, require one on this line to keep the sink
        if (jsTaintedVars.size > 0) {
          if ([...jsTaintedVars.keys()].some(v => new RegExp(`\\b${v}\\b`).test(sinkLineText))) return true;
          if (JS_TAINTED_PATTERNS.some(p => p.pattern.test(sinkLineText))) return true;
          return false;
        }

        // 6d. No tainted vars tracked — check if line has any obvious taint source patterns
        //     If none found and RHS looks like a variable, keep the sink (conservative)
        if (JS_TAINTED_PATTERNS.some(p => p.pattern.test(sinkLineText))) return true;

        // 6e. Check if RHS is a known constant from constant propagation
        if (assignmentMatch) {
          const rhsClean = assignmentMatch[1].trim().replace(/;$/, '').trim();
          // If RHS is just an identifier, check if it's a known constant
          const identMatch = rhsClean.match(/^(\w+)$/);
          if (identMatch) {
            const varName = identMatch[1];
            const symbolInfo = constProp.symbols.get(varName);
            if (symbolInfo && symbolInfo.type === 'string') return false;
          }
        }

        // Default: keep the sink (conservative when no taint info available)
        return true;
      });
    }

    return { sources, sinks: filtered, sanitizers };
  }
}

// ---------------------------------------------------------------------------
// Helpers (moved verbatim from analyzer.ts)
// ---------------------------------------------------------------------------

import type { CircleIR } from '../../types/index.js';

type Symbols = Map<string, { value: string | number | boolean | null; type: string; sourceLine: number }>;

/**
 * Evaluate a simple arithmetic expression containing only digits, spaces, and
 * the operators +, -, *, /, and parentheses. Uses a recursive descent parser
 * so no dynamic code execution (Function / eval) is needed.
 */
function evalArithmetic(input: string): number | null {
  let pos = 0;
  const len = input.length;

  function peek(): string { return input[pos] ?? ''; }
  function consume(): string { return input[pos++] ?? ''; }
  function skipWs(): void { while (pos < len && input[pos] === ' ') pos++; }

  function parseNumber(): number | null {
    skipWs();
    const chars: string[] = [];
    if (peek() === '-') { chars.push(consume()); }
    while (pos < len && /[\d.]/.test(input[pos]!)) chars.push(consume());
    if (chars.length === 0 || (chars.length === 1 && chars[0] === '-')) return null;
    const n = parseFloat(chars.join(''));
    return isFinite(n) ? n : null;
  }

  function parseFactor(): number | null {
    skipWs();
    if (peek() === '(') {
      consume(); // '('
      const val = parseExpr();
      skipWs();
      if (peek() === ')') consume();
      return val;
    }
    return parseNumber();
  }

  function parseTerm(): number | null {
    let left = parseFactor();
    if (left === null) return null;
    while (true) {
      skipWs();
      const op = peek();
      if (op !== '*' && op !== '/') break;
      consume();
      const right = parseFactor();
      if (right === null) return null;
      left = op === '*' ? left * right : (right === 0 ? null : left / right);
      if (left === null) return null;
    }
    return left;
  }

  function parseExpr(): number | null {
    let left = parseTerm();
    if (left === null) return null;
    while (true) {
      skipWs();
      const op = peek();
      if (op !== '+' && op !== '-') break;
      consume();
      const right = parseTerm();
      if (right === null) return null;
      left = op === '+' ? left + right : left - right;
    }
    return left;
  }

  if (!/^[\d\s+\-*/().]+$/.test(input)) return null;
  const result = parseExpr();
  skipWs();
  return pos === input.length ? result : null;
}

function evaluateSimpleExpression(expr: string, symbols: Symbols): string {
  let evaluated = expr;
  for (const [name, val] of symbols) {
    if (val.type === 'int' || val.type === 'float') {
      const regex = new RegExp(`\\b${name}\\b`, 'g');
      evaluated = evaluated.replace(regex, String(val.value));
    }
  }
  const result = evalArithmetic(evaluated);
  if (result !== null && !isNaN(result)) return String(Math.floor(result));
  return expr;
}

function isStringLiteralExpression(expr: string): boolean {
  const trimmed = expr.trim();
  return (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
         (trimmed.startsWith("'") && trimmed.endsWith("'"));
}

function filterCleanArraySinks(
  sinks: CircleIR['taint']['sinks'],
  calls: CircleIR['calls'],
  taintedArrayElements: Map<string, Set<string>>,
  symbols: Symbols,
): CircleIR['taint']['sinks'] {
  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const callsAtSink = callsByLine.get(sink.line) ?? [];
    for (const call of callsAtSink) {
      for (const arg of call.arguments) {
        const arrayAccessMatch = arg.expression?.match(/^(\w+)\[(\d+|[^[\]]+)\]$/);
        if (arrayAccessMatch) {
          const arrayName = arrayAccessMatch[1];
          let indexStr = arrayAccessMatch[2];
          indexStr = evaluateSimpleExpression(indexStr, symbols);
          const taintedIndices = taintedArrayElements.get(arrayName);
          if (taintedIndices !== undefined) {
            const isTainted = taintedIndices.has(indexStr) || taintedIndices.has('*');
            if (!isTainted) return false;
          }
        }
      }
    }
    return true;
  });
}

export function filterCleanVariableSinks(
  sinks: CircleIR['taint']['sinks'],
  calls: CircleIR['calls'],
  taintedVars: Set<string>,
  symbols: Symbols,
  dfg?: CircleIR['dfg'],
  sanitizedVars?: Set<string>,
  synchronizedLines?: Set<number>,
): CircleIR['taint']['sinks'] {
  const fieldNames = new Set<string>();
  if (dfg) {
    for (const def of dfg.defs) {
      if (def.kind === 'field') fieldNames.add(def.variable);
    }
  }

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const callsAtSink = callsByLine.get(sink.line) ?? [];
    const isInSynchronizedBlock = synchronizedLines?.has(sink.line) ?? false;

    // Only evaluate the call that matched the sink pattern — not nested inner calls at the
    // same line (e.g. System.getProperty("user.dir") inside r.exec(args,...,new File(...))).
    // sink.method is set by findSinks to call.method_name; language-sources sinks also carry it.
    const relevantCalls = sink.method
      ? callsAtSink.filter(c => c.method_name === sink.method)
      : callsAtSink;

    for (const call of relevantCalls) {
      let allArgsAreClean = true;
      const methodName = call.in_method;

      for (const arg of call.arguments) {
        // Skip the command-name argument in shell calls (e.g., arg[0]="curl" for `curl -s URL`).
        // The command name itself has literal=null and expression matching the method name.
        if (arg.expression === call.method_name && !arg.variable && arg.literal == null) continue;

        if (arg.variable && !arg.expression?.includes('[')) {
          const varName = arg.variable;
          const scopedName = methodName ? `${methodName}:${varName}` : varName;

          if (fieldNames.has(varName) && !isInSynchronizedBlock) { allArgsAreClean = false; continue; }
          if (sanitizedVars?.has(scopedName) || sanitizedVars?.has(varName)) continue;
          if (taintedVars.has(scopedName) || taintedVars.has(varName)) { allArgsAreClean = false; continue; }

          const symbolValue = symbols.get(scopedName) ?? symbols.get(varName);
          if (symbolValue && symbolValue.type !== 'unknown') continue;

          allArgsAreClean = false;
        } else {
          if (arg.literal != null) continue;
          if (arg.expression && !arg.variable && isStringLiteralExpression(arg.expression)) continue;
          allArgsAreClean = false;
        }
      }

      if (allArgsAreClean && call.arguments.length > 0) return false;
    }

    return true;
  });
}

export function filterSanitizedSinks(
  sinks: CircleIR['taint']['sinks'],
  sanitizers: CircleIR['taint']['sanitizers'],
  calls: CircleIR['calls'],
): CircleIR['taint']['sinks'] {
  if (!sanitizers || sanitizers.length === 0) return sinks;

  const sanitizersByLine = new Map<number, typeof sanitizers>();
  for (const san of sanitizers) {
    const existing = sanitizersByLine.get(san.line) ?? [];
    existing.push(san);
    sanitizersByLine.set(san.line, existing);
  }

  const callsByLine = new Map<number, typeof calls>();
  for (const call of calls) {
    const existing = callsByLine.get(call.location.line) ?? [];
    existing.push(call);
    callsByLine.set(call.location.line, existing);
  }

  return sinks.filter(sink => {
    const lineSanitizers = sanitizersByLine.get(sink.line);
    if (!lineSanitizers || lineSanitizers.length === 0) return true;

    for (const san of lineSanitizers) {
      if (san.sanitizes.includes(sink.type as typeof san.sanitizes[number])) {
        const lineCalls = callsByLine.get(sink.line) ?? [];
        for (const call of lineCalls) {
          for (const arg of call.arguments) {
            const expr = arg.expression || '';
            const sanMethodMatch = san.method.match(/(?:(\w+)\.)?(\w+)\(\)/);
            if (sanMethodMatch) {
              const sanMethodName = sanMethodMatch[2];
              const sanClassName  = sanMethodMatch[1];
              if (sanClassName) {
                if (expr.includes(`${sanClassName}.${sanMethodName}(`)) return false;
              } else if (expr.includes(`${sanMethodName}(`)) {
                return false;
              }
            }
          }
        }
      }
    }
    return true;
  });
}
