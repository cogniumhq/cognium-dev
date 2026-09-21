/**
 * Shared fixture helpers for pass-level unit tests.
 *
 * Extracted because the credential/crypto and hygiene passes added in #439
 * all need the same minimal CircleIR + PassContext, and eight copies of it
 * would drift. Existing test files keep their local copies; this is for new
 * ones.
 */
import { CodeGraph } from '../../../src/graph/code-graph.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';

export function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.py', language: 'python', loc: 20, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {},
    ...overrides,
  };
}

export function makeCtx(
  ir: CircleIR,
  code = '',
  language?: string,
): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code,
    language: language ?? ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

/** A call with positional args given as `[expression, variableName?]` tuples. */
export function call(
  receiver: string | null,
  method: string,
  args: Array<[string, string?]>,
  line = 10,
  inMethod?: string,
) {
  return {
    method_name: method,
    receiver,
    in_method: inMethod ?? null,
    arguments: args.map(([expression, variable], position) => ({
      position,
      expression,
      variable: variable ?? null,
      // `literal` holds the VALUE, not the source text: quotes stripped,
      // numbers as written, and null for anything that is not a constant.
      // Passes read it both ways — `literalAt()` strips quotes defensively,
      // but cache-no-vary compares `arguments[0].literal` directly — so a
      // quoted spelling here silently fails to match a header name.
      literal: /^["'`]/.test(expression)
        ? expression.slice(1, -1)
        : /^-?\d+$/.test(expression)
          ? expression
          : null,
    })),
    location: { line, column: 1 },
  };
}
