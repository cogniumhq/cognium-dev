/**
 * SpeculativePromptParamSourcePass — cognium-dev #267
 *
 * OPT-IN, OFF-BY-DEFAULT. When `AnalyzerOptions.speculativeParamSources` is
 * set, seeds function parameters as untrusted sources within functions that
 * already contain a `prompt_injection` (CWE-1427) sink. This unblocks
 * library / agent / SDK code whose untrusted entry point is a bare
 * parameter (`func Ask(user string, client *LLM)`) — there is no in-file
 * request source to seed taint, so the param → prompt-sink flow never fires
 * under the deterministic default.
 *
 * This is a deliberately speculative, higher-FP heuristic. It is gated
 * behind an explicit flag that defaults OFF, so the precision-sensitive
 * benchmarks (OWASP / Juliet / SecuriBench) — which never set it — are
 * unaffected and the 0%-FPR moat is preserved. Scope is bounded to
 * parameters of functions containing a prompt-construction sink, not every
 * function parameter.
 *
 * Runs after the sink gates (so the prompt_injection sink set is final) and
 * before TaintPropagationPass, appending to the sink-filter source set so
 * the normal flow generators connect param → sink. Pillar-I clean: no model
 * invocation, no LLM identifiers in its surface (`prompt_injection` /
 * CWE-1427 is the established deterministic taint category, #248).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SinkFilterResult } from './sink-filter-pass.js';
import type { TaintSource, TaintSink, TaintFlowInfo, TypeInfo } from '../../types/index.js';
import { isInstructionConcat } from './prompt-injection-safety-gate-pass.js';

/**
 * Extract the RHS expression of a `return …` or `<var> = …` / `<var> := …`
 * statement, so it can be checked for prompt-construction. Returns undefined
 * when the line is neither.
 */
function returnOrAssignRhs(text: string): string | undefined {
  const t = text.trim();
  const ret = t.match(/^return\s+(.+?);?$/);
  if (ret) return ret[1];
  const asg = t.match(/^[A-Za-z_$][\w$.]*\s*(?::=|(?<![=<>!])=(?!=))\s*(.+?);?$/);
  if (asg) return asg[1];
  return undefined;
}

/**
 * Heuristic: does a string literal read like LLM *prompt / instruction*
 * text rather than an incidental separator or short token? Used to keep the
 * client-less construction detector off ordinary string concatenation
 * (`"/" + name`, `"Hello, " + name`) that structurally looks identical but
 * is not a prompt. Fires on instruction phrasing or a full sentence.
 */
export function looksLikePromptText(lit: string): boolean {
  const s = lit.trim();
  if (
    /\b(you are|you're|assistant|system prompt|follow (the )?(policy|instructions|rules)|act as|your task|instructions?\s*:|ignore (all )?previous|do not reveal|respond (to|with|as)|answer the (question|user)|you (must|should|will)|helpful (ai|assistant))\b/i.test(s)
  ) {
    return true;
  }
  const words = s.split(/\s+/).filter(Boolean);
  return words.length >= 4 && s.length >= 20;
}

/** String-literal operands of an expression. */
function literalsOf(expr: string): string[] {
  return [...expr.matchAll(/"([^"]*)"|'([^']*)'|`([^`]*)`/g)].map(m => m[1] ?? m[2] ?? m[3] ?? '');
}

/**
 * Detect *client-less* prompt-construction flows (cognium-dev #267,
 * speculative). A function that returns or assigns an instruction-literal
 * concatenated with one of its own parameters builds a prompt from
 * untrusted input even without an LLM-client call
 * (`func BuildPrompt(user string) string { return "You are a bot. " + user }`).
 * Emitted directly as `prompt_injection` (CWE-1427) flows — there is no
 * call sink for the flow generators to match. Delimiter-wrapped concats are
 * NOT instruction-concat, so the safe mirror produces no flow.
 *
 * Off-default: only invoked when `speculativeParamSources` is set (the
 * benchmarks never enable it).
 */
export function detectPromptConstructionFlows(
  codeLines: string[],
  types: TypeInfo[],
): TaintFlowInfo[] {
  const flows: TaintFlowInfo[] = [];
  const seen = new Set<string>();
  for (const type of types) {
    for (const method of type.methods) {
      const params = (method.parameters ?? [])
        .map(p => ({ name: p.name, line: p.line ?? method.start_line }))
        .filter(p => p.name && p.name !== '_');
      if (params.length === 0) continue;
      for (let line = method.start_line; line <= method.end_line; line++) {
        const text = codeLines[line - 1] ?? '';
        const rhs = returnOrAssignRhs(text);
        if (!rhs || !isInstructionConcat(rhs)) continue;
        // Require an actual prompt/instruction-looking literal — not just any
        // non-delimiter string — so ordinary concatenation is not flagged.
        if (!literalsOf(rhs).some(looksLikePromptText)) continue;
        const param = params.find(p => new RegExp(`\\b${p.name}\\b`).test(rhs));
        if (!param) continue;
        const key = `${param.line}|${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        flows.push({
          source_line: param.line,
          sink_line: line,
          source_type: 'http_body',
          sink_type: 'prompt_injection',
          path: [
            { variable: param.name, line: param.line, type: 'source' },
            { variable: param.name, line, type: 'sink' },
          ],
          confidence: 1.0,
          sanitized: false,
        });
      }
    }
  }
  return flows;
}

export interface SpeculativePromptParamSourceResult {
  added: number;
}

/**
 * A parameter is a plausible untrusted-text entry point when its type is
 * unknown (untyped languages — Python/JS) or string-ish. Handle/dependency
 * params (a client, context, writer, DB, logger — typically pointer or
 * well-known infrastructure types) are skipped to keep the speculative FP
 * surface off obviously-non-data parameters.
 */
export function looksLikeTextParam(type: string | null | undefined): boolean {
  if (!type) return true; // untyped (Python/JS/TS `any`) — cannot exclude
  const t = type.trim();
  if (t.startsWith('*') || t.startsWith('&')) return false; // pointer/handle
  if (/\b(Client|Context|Writer|Reader|Conn|DB|Logger|Handler|Server|Request|Response|Pool|Session|Engine|Service|Repository|Config)\b/.test(t)) {
    return false;
  }
  return /(?:^|\b)(string|str|String|text|any|object|interface\{\}|\[\]byte|\[\]string|List\[str\]|Optional\[str\])(?:\b|$)/i.test(t) ||
    // TS unions / plain identifiers without a handle keyword default to text.
    /^[A-Za-z_$][\w$<>[\], |]*$/.test(t);
}

export class SpeculativePromptParamSourcePass
  implements AnalysisPass<SpeculativePromptParamSourceResult>
{
  readonly name = 'speculative-prompt-param-source';
  readonly category = 'security' as const;

  constructor(private readonly enabled: boolean) {}

  run(ctx: PassContext): SpeculativePromptParamSourceResult {
    if (!this.enabled) return { added: 0 };
    if (!ctx.hasResult('sink-filter')) return { added: 0 };

    const sinkFilter = ctx.getResult<SinkFilterResult>('sink-filter');
    const { types } = ctx.graph.ir;

    const promptSinks: TaintSink[] = sinkFilter.sinks.filter(
      s => s.type === 'prompt_injection',
    );
    if (promptSinks.length === 0) return { added: 0 };
    const existing = new Set(
      sinkFilter.sources
        .filter(s => typeof s.variable === 'string')
        .map(s => `${s.variable}:${s.line}`),
    );

    const added: TaintSource[] = [];
    for (const type of types) {
      for (const method of type.methods) {
        // Only functions that actually contain a prompt-construction sink.
        const hasPromptSink = promptSinks.some(
          s => s.line >= method.start_line && s.line <= method.end_line,
        );
        if (!hasPromptSink) continue;

        for (const param of method.parameters) {
          if (!param.name || param.name === '_') continue;
          if (!looksLikeTextParam(param.type)) continue;
          const line = param.line ?? method.start_line;
          const key = `${param.name}:${line}`;
          if (existing.has(key)) continue;
          existing.add(key);
          added.push({
            // `http_body` reaches `prompt_injection` via the flow
            // generators; a generic untrusted request-shaped type.
            type: 'http_body',
            location: `speculative untrusted parameter '${param.name}' in ${method.name}`,
            severity: 'high',
            line,
            confidence: 1.0,
            variable: param.name,
            in_method: method.name,
          });
        }
      }
    }

    if (added.length > 0) {
      sinkFilter.sources.push(...added);
    }
    return { added: added.length };
  }
}
