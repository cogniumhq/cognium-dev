/**
 * PromptInjectionSafetyGatePass — cognium-dev #267
 *
 * Drops `prompt_injection` (CWE-1427) sinks whose untrusted content is
 * *delimiter-wrapped* — enclosed in matched boundary markers
 * (`<user_question>…</user_question>`, fences) that keep it as data rather
 * than instructions. Removes the false positive on the delimiter-wrapped
 * "safe mirror" of the OWASP-LLM LLM01 probe pairs while leaving genuine
 * prompt-injection flows untouched.
 *
 * The engine already fires `prompt_injection` when tainted input reaches an
 * LLM-client call (#248); the gap this closes is precision on the wrapped
 * safe-mitigation shape.
 *
 * Scope decision — *role separation alone is NOT treated as a sanitizer*
 * here: `{"role":"user","content":untrusted}` continues to fire, matching
 * #248's must-fire contract (untrusted reaching an LLM prompt is a finding
 * even in the user channel). Only affirmative delimiter-wrapping suppresses.
 *
 * Conservative by construction: a sink is dropped ONLY when EVERY dynamic
 * content placement is delimiter-wrapped and none lands in the instruction
 * channel (system/assistant role, or instruction concat/interpolation). Any
 * ambiguity — unparsed value, standalone value, dynamic+dynamic concat —
 * keeps the sink (no recall loss). Runs after SinkFilterPass and before
 * TaintPropagationPass so flow generators never see a dropped sink.
 *
 * Builder-pattern aware: when the request is constructed in a prior
 * statement (Go/Java `req := ChatCompletionRequest{Messages: …}`) and passed
 * as a bare arg, the gate traces the builder var(s) to see the message
 * structure.
 *
 * Pillar I note: `prompt_injection` / CWE-1427 is a deterministic taint
 * category (#248). This gate is pure structural analysis of the call site —
 * no model invocation, no LLM concepts in its API surface.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { TaintSink } from '../../types/index.js';

export interface PromptInjectionSafetyGateResult {
  droppedSafe: number;
}

/**
 * A string literal is a *delimiter* (structural boundary marker) rather
 * than *instruction text* when it is a short tag/fence-like token:
 * `<user_question>`, `</user_question>`, `[data]`, ```` ``` ````, `"""`,
 * `---`, `###`, `<<<`. Instruction literals ("Follow policy.") contain free
 * words and do not match.
 */
export function isDelimiterLiteral(lit: string): boolean {
  const s = lit.trim();
  if (s.length === 0) return true;
  return (
    /^<\/?[\w.-]+\s*\/?>$/.test(s) ||
    /^\[\/?[\w.-]+\]$/.test(s) ||
    /^`{1,3}[\w-]*$/.test(s) ||
    /^"""[\w-]*$/.test(s) ||
    /^[#*=_~-]{2,}$/.test(s) ||
    /^<{2,}[\w-]*$/.test(s) ||
    /^[\w-]*>{2,}$/.test(s)
  );
}

/**
 * Scan a balanced expression starting at `start`, stopping at a top-level
 * `,` or a closing `) ] }` that closes the enclosing structure. Tracks
 * bracket depth and string state so `}`/`)` inside strings (f-string
 * `{user}`, template `${user}`) or nested calls do not truncate the value.
 */
export function scanValue(code: string, start: number): string {
  let depth = 0;
  let str: string | null = null;
  let out = '';
  for (let i = start; i < code.length; i++) {
    const c = code[i];
    if (str) {
      out += c;
      if (c === str && code[i - 1] !== '\\') str = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      str = c;
      out += c;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') { depth++; out += c; continue; }
    if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
      out += c;
      continue;
    }
    if (c === ',' && depth === 0) break;
    out += c;
  }
  return out.trim();
}

function stringLiterals(expr: string): string[] {
  return [...expr.matchAll(/"([^"]*)"|'([^']*)'/g)].map(m => m[1] ?? m[2] ?? '');
}

/** Reference to a bare identifier (a dynamic value) once literals removed. */
function hasIdentifier(expr: string): boolean {
  return /[A-Za-z_$][\w$]*/.test(expr.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, ' '));
}

/** A content value that is entirely a string literal (no dynamic part). */
function isPureLiteral(valueExpr: string): boolean {
  const stripped = valueExpr.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, ' ');
  return !/[A-Za-z_$][\w$]*/.test(stripped);
}

/** `+`-concat mixing a dynamic value with a NON-delimiter string literal. */
function isInstructionConcat(valueExpr: string): boolean {
  if (!valueExpr.includes('+')) return false;
  if (!hasIdentifier(valueExpr)) return false;
  const lits = stringLiterals(valueExpr);
  if (lits.length === 0) return false;
  return !lits.every(isDelimiterLiteral);
}

/**
 * f-string / template literal that mixes untrusted interpolation with free
 * instruction text: `f"Follow policy. {user}"` / `` `Follow policy. ${user}` ``.
 * Pure interpolation (`f"{user}"`) is not instruction-mixing.
 */
function isMixedTemplate(v: string): boolean {
  const fstr = v.match(/\bf(["'])((?:\\.|(?!\1).)*)\1/);
  if (fstr) {
    const body = fstr[2];
    if (/\{[^}]+\}/.test(body) && /\w/.test(body.replace(/\{[^}]*\}/g, ''))) return true;
  }
  const tmpl = v.match(/`([^`]*)`/);
  if (tmpl) {
    const body = tmpl[1];
    if (/\$\{[^}]+\}/.test(body) && /\w/.test(body.replace(/\$\{[^}]*\}/g, ''))) return true;
  }
  return false;
}

/**
 * Assignment-operator matcher for `<var> := …` / `<var> = …`, excluding the
 * comparisons `==` / `<=` / `>=` / `!=`. `:=` is matched directly; a plain
 * `=` must not be preceded by `=<>!` nor followed by `=`.
 */
function assignmentRe(varName: string, flags = ''): RegExp {
  return new RegExp(`\\b${varName}\\s*(?::=|(?<![=<>!])=(?!=))\\s*`, flags);
}

/** Resolve a bare-identifier content value one hop back to its assignment RHS. */
function resolveAssignmentRHS(varName: string, codeLines: string[]): string | undefined {
  const re = assignmentRe(varName);
  for (const line of codeLines) {
    const m = line.match(re);
    if (m && m.index !== undefined) {
      return scanValue(line, m.index + m[0].length);
    }
  }
  return undefined;
}

/**
 * Classify a fully-scanned content expression.
 *   'safe'    — standalone dynamic value or delimiter-wrapped concat
 *   'unsafe'  — instruction concat / instruction-mixing template
 *   'unknown' — dynamic+dynamic concat / unrecognized — kept
 */
function classifyExpr(v: string): 'safe' | 'unsafe' | 'unknown' {
  if (isMixedTemplate(v)) return 'unsafe';
  if (v.includes('+')) {
    if (isInstructionConcat(v)) return 'unsafe';
    const lits = stringLiterals(v);
    if (lits.length > 0 && lits.every(isDelimiterLiteral) && hasIdentifier(v)) return 'safe';
    return 'unknown'; // dynamic+dynamic / complex — never claim safe
  }
  // No '+', no instruction-mixing template: a standalone value placed as
  // the whole content. Whether this is "safe" (role-separation as the
  // mitigation) is a security-semantics choice that conflicts with #248's
  // must-fire contract — left as 'unknown' (kept) pending that decision;
  // only delimiter-wrapping is treated as an affirmative sanitizer.
  return 'unknown';
}

/**
 * Classify one dynamic content placement, resolving a bare identifier one
 * hop back so `wrapped = "<q>"+x+"</q>"; content: wrapped` and
 * `bad = "instr "+x; content: bad` are judged on their construction.
 */
function classifyContentPlacement(val: string, codeLines: string[]): 'safe' | 'unsafe' | 'unknown' {
  const v = val.trim();
  if (/^[A-Za-z_$][\w$]*$/.test(v)) {
    const rhs = resolveAssignmentRHS(v, codeLines);
    // Unresolved bare identifier (param, source var, or local whose
    // construction we can't see) — standalone/role-separated placement,
    // which is NOT an affirmative sanitizer (kept; see scope note).
    if (rhs === undefined) return 'unknown';
    return classifyExpr(rhs);
  }
  return classifyExpr(v);
}

/**
 * Classify a prompt-injection call site.
 *   'unsafe'  — untrusted in the instruction channel, or mixed into instructions
 *   'safe'    — every dynamic content is standalone role-separated or delimiter-wrapped
 *   'unknown' — no confident classification (kept)
 */
export function classifyPromptCall(
  callCode: string,
  codeLines: string[],
): 'unsafe' | 'safe' | 'unknown' {
  const contentRe = /["']?[Cc]ontent["']?\s*[:=]\s*/g;
  let m: RegExpExecArray | null;
  let sawDynamic = false;
  let allSafe = true;

  while ((m = contentRe.exec(callCode)) !== null) {
    const val = scanValue(callCode, m.index + m[0].length);
    if (val === '' || isPureLiteral(val)) continue;
    sawDynamic = true;

    // Role context: nearest preceding `role: "..."` in the same object.
    const ctx = callCode.slice(Math.max(0, m.index - 80), m.index);
    const roleM = ctx.match(/["']?[Rr]ole["']?\s*[:=]\s*["'](\w+)["'][^"']*$/);
    const role = roleM ? roleM[1].toLowerCase() : 'user';
    if (role === 'system' || role === 'assistant') return 'unsafe';

    const placement = classifyContentPlacement(val, codeLines);
    if (placement === 'unsafe') return 'unsafe';
    if (placement !== 'safe') allSafe = false;
  }

  if (!sawDynamic) return 'unknown';
  return allSafe ? 'safe' : 'unknown';
}

/**
 * Scan a statement RHS across lines, stopping at a top-level newline (Go/
 * builder style) or a closing bracket that ends the expression — so a
 * multi-line composite literal `T{ … }` is captured whole. Tracks bracket
 * depth and string state.
 */
function scanRhsAcrossLines(text: string, start: number): string {
  let depth = 0;
  let str: string | null = null;
  let out = '';
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (str) {
      out += c;
      if (c === str && text[i - 1] !== '\\') str = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { str = c; out += c; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; out += c; continue; }
    if (c === ')' || c === ']' || c === '}') { if (depth === 0) break; depth--; out += c; continue; }
    if (c === '\n' && depth === 0) break;
    out += c;
  }
  return out.trim();
}

/** Full multi-line RHS of `var := …` / `var = …`. */
function resolveBuilderRhs(varName: string, joined: string): string | undefined {
  const re = assignmentRe(varName, 'g');
  const m = re.exec(joined);
  if (m) return scanRhsAcrossLines(joined, m.index + m[0].length);
  return undefined;
}

/**
 * Builder-pattern support (Go/Java): when the request is built in a prior
 * statement (`req := ChatCompletionRequest{Messages: …}`) and passed as a
 * bare arg to the client call, the role/content structure is not on the
 * sink line. Gather the builder text for each identifier arg of the call,
 * recursively inlining referenced builder vars (bounded), so the classifier
 * can see the message structure. Returns the concatenated builder region.
 */
function collectBuilderRegion(callCode: string, joined: string): string {
  const parts: string[] = [];
  const seen = new Set<string>();
  const stack = [...callCode.matchAll(/[A-Za-z_$][\w$]*/g)].map(x => x[0]);
  let budget = 40;
  while (stack.length > 0 && budget-- > 0) {
    const v = stack.pop()!;
    if (seen.has(v)) continue;
    seen.add(v);
    const rhs = resolveBuilderRhs(v, joined);
    if (rhs) {
      parts.push(rhs);
      for (const mm of rhs.matchAll(/[A-Za-z_$][\w$]*/g)) stack.push(mm[0]);
    }
  }
  return parts.join('\n');
}

/**
 * Classify a prompt-injection sink, first on the call line (Python/JS inline
 * message shape) and — when that is inconclusive — over the builder region
 * for the call's arg vars (Go/Java builder shape).
 */
export function classifyPromptSink(
  callCode: string,
  codeLines: string[],
): 'unsafe' | 'safe' | 'unknown' {
  const direct = classifyPromptCall(callCode, codeLines);
  if (direct !== 'unknown') return direct;
  const region = collectBuilderRegion(callCode, codeLines.join('\n'));
  if (!region) return 'unknown';
  return classifyPromptCall(region, codeLines);
}

export class PromptInjectionSafetyGatePass
  implements AnalysisPass<PromptInjectionSafetyGateResult>
{
  readonly name = 'prompt-injection-safety-gate';
  readonly category = 'security' as const;

  run(ctx: PassContext): PromptInjectionSafetyGateResult {
    const { graph, code } = ctx;

    const sinks: TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;
    if (sinks.length === 0) return { droppedSafe: 0 };

    const codeLines = code.split('\n');
    let droppedSafe = 0;

    const kept = sinks.filter(sink => {
      if (sink.type !== 'prompt_injection') return true;
      const callCode = sink.code ?? codeLines[sink.line - 1] ?? '';
      if (!callCode) return true;
      if (classifyPromptSink(callCode, codeLines) === 'safe') {
        droppedSafe++;
        return false;
      }
      return true;
    });

    if (droppedSafe > 0) {
      sinks.length = 0;
      sinks.push(...kept);
    }
    return { droppedSafe };
  }
}
