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
import type { TaintSource, TaintSink } from '../../types/index.js';

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
    const promptSinks: TaintSink[] = sinkFilter.sinks.filter(
      s => s.type === 'prompt_injection',
    );
    if (promptSinks.length === 0) return { added: 0 };

    const { types } = ctx.graph.ir;
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
