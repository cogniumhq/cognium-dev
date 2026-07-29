/**
 * PromptInjectionSafetyGatePass — cognium-dev #267
 *
 * Drops `prompt_injection` (CWE-1427) sinks whose untrusted content is
 * placed *safely* — delimited data or role-separated user input, not mixed
 * into the instruction channel. Removes the false positive on the "safe
 * mirror" of the OWASP-LLM LLM01 probe pairs while leaving genuine
 * prompt-injection flows (untrusted concatenated/interpolated into
 * instructions, or placed in a system/assistant role) untouched.
 *
 * The engine already fires `prompt_injection` when tainted input reaches an
 * LLM-client call (#248); the gap this closes is precision — the same call
 * is flagged whether the untrusted value is folded into the system prompt
 * (a true positive) or passed as a standalone role-separated / delimiter-
 * wrapped user message (the recommended mitigation — a false positive).
 *
 * Conservative by construction: a sink is dropped ONLY when EVERY dynamic
 * content placement is affirmatively safe (standalone role-separated value
 * or delimiter-wrapped) and none lands in the instruction channel. Any
 * ambiguity — unparsed value, dynamic+dynamic concat, unknown shape — keeps
 * the sink (no recall loss). Runs after SinkFilterPass and before
 * TaintPropagationPass so flow generators never see a dropped sink.
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

/** Resolve a bare-identifier content value one hop back to its assignment RHS. */
function resolveAssignmentRHS(varName: string, codeLines: string[]): string | undefined {
  const assignRe = new RegExp(`\\b${varName}\\s*:?=\\s*`);
  for (const line of codeLines) {
    const m = line.match(assignRe);
    if (m && m.index !== undefined) {
      // Skip `==` / `<=` / `>=` / `!=` comparisons.
      const before = line[m.index + m[0].length - 2];
      if (before && '=<>!'.includes(before)) continue;
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
  // No '+', no instruction-mixing template: a standalone value (identifier,
  // member access, call) placed as the whole content is role-separated.
  return 'safe';
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
    if (rhs === undefined) return 'safe'; // param / unresolved local — standalone
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
      if (classifyPromptCall(callCode, codeLines) === 'safe') {
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
