/**
 * Tests for MissingSanitizerGatePass — CWE-79 speculative HTML output gate.
 *
 * Uses minimal IR fixtures (no WASM parsing); mirrors the shape of the
 * missing-guard-dom test suite.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext, SastFinding } from '../../../src/graph/analysis-pass.js';
import type { CircleIR } from '../../../src/types/index.js';
import { MissingSanitizerGatePass } from '../../../src/analysis/passes/missing-sanitizer-gate-pass.js';
import { applyConfidenceFilter } from '../../../src/analysis/confidence-filter.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Printer.java', language: 'java', loc: 40, hash: '' },
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

function makeCtx(ir: CircleIR, language?: string): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code: '',
    language: language ?? ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

function makeMethod(
  name: string,
  start: number,
  end: number,
  parameters: Array<{ name: string; type: string | null }> = [],
  annotations: string[] = [],
) {
  return {
    name,
    return_type: 'void' as const,
    parameters: parameters.map(p => ({ ...p, annotations: [] })),
    annotations,
    modifiers: ['public'] as string[],
    start_line: start,
    end_line: end,
  };
}

function makeClass(
  name: string,
  methods: ReturnType<typeof makeMethod>[],
  annotations: string[] = [],
) {
  return {
    name,
    kind: 'class' as const,
    package: null,
    extends: null,
    implements: [] as string[],
    annotations,
    methods,
    fields: [] as never[],
    start_line: 1,
    end_line: 60,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('MissingSanitizerGatePass', () => {
  it('TP-1: cleanAttributes-shape method with no sanitizer → 1 finding (medium confidence)', () => {
    // Method `cleanAttributes(String elementName, Map<String,String> attrs)`
    // calls writer.addAttribute(k, v) in a loop; no isAttributeAllowed guard.
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 10 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 8, column: 0 },
          in_method: 'cleanAttributes',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('cleanAttributes', 5, 10, [
          { name: 'elementName', type: 'String' },
          { name: 'attrs', type: 'Map<String,String>' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('missing-sanitizer-gate');
    expect(ctx.findings[0].cwe).toBe('CWE-79');
    expect(ctx.findings[0].level).toBe('note');
    expect(ctx.findings[0].confidence).toBe('medium');
    expect(ctx.findings[0].line).toBe(8);
  });

  it('TP-2: sink not dominated by sanitizer (sanitizer on sibling branch) → 1 finding', () => {
    // entry → cond (l4) → { thenBlock: sanitizer at l6 } | { elseBlock: sink at l9 }
    // The sanitizer is only reachable on one path; sink block is not dominated.
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'branch', start_line: 4, end_line: 4 },
          { id: 2, type: 'normal', start_line: 5, end_line: 7 },
          { id: 3, type: 'normal', start_line: 8, end_line: 11 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' as const },
          { from: 1, to: 2, type: 'true' as const },
          { from: 1, to: 3, type: 'false' as const },
        ],
      },
      calls: [
        {
          method_name: 'isAttributeAllowed',
          receiver: 'sanitizer',
          arguments: [],
          location: { line: 6, column: 0 },
          in_method: 'render',
        },
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 9, column: 0 },
          in_method: 'render',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('render', 3, 12, [
          { name: 'attrs', type: 'Map<String,String>' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('missing-sanitizer-gate');
  });

  it('TN-1: isAttributeAllowed dominates sink → 0 findings', () => {
    // entry → sanitizer-block (l4-l6, contains isAttributeAllowed at l5)
    //        → sink-block (l7-l11, contains addAttribute at l9)
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 4, end_line: 6 },
          { id: 2, type: 'normal', start_line: 7, end_line: 11 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' as const },
          { from: 1, to: 2, type: 'sequential' as const },
        ],
      },
      calls: [
        {
          method_name: 'isAttributeAllowed',
          receiver: 'sanitizer',
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'render',
        },
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 9, column: 0 },
          in_method: 'render',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('render', 4, 11, [
          { name: 'attrs', type: 'Map<String,String>' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('TN-2: escapeHtml wrapper on sink arg satisfies gate → 0 findings', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 3, end_line: 8 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'escapeHtml',
          receiver: 'StringEscapeUtils',
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'render',
        },
        {
          method_name: 'print',
          receiver: 'writer',
          arguments: [],
          location: { line: 6, column: 0 },
          in_method: 'render',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('render', 3, 8, [
          { name: 'body', type: 'String' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('TN-3: sink method has no Map/Attributes/String param → 0 findings (param gate)', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 10 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 8, column: 0 },
          in_method: 'renderFixed',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('renderFixed', 5, 10, [
          { name: 'count', type: 'int' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('TN-4: Tier 1 entry point (@RestController class) → 0 findings (entry-point gate)', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 10 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 8, column: 0 },
          in_method: 'handle',
        },
      ],
      types: [makeClass(
        'PageController',
        [makeMethod('handle', 5, 10, [
          { name: 'attrs', type: 'Map<String,String>' },
        ], ['RequestMapping'])],
        ['RestController'],
      )],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('TN-5: non-Java language → 0 findings (language gate)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'printer.py', language: 'python', loc: 10, hash: '' },
      calls: [
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 5, column: 0 },
          in_method: 'render',
        },
      ],
    });

    const ctx = makeCtx(ir, 'python');
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(0);
  });

  it('speculative gating: default suppresses; includeSpeculative preserves', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 10 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'addAttribute',
          receiver: 'writer',
          arguments: [],
          location: { line: 8, column: 0 },
          in_method: 'cleanAttributes',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('cleanAttributes', 5, 10, [
          { name: 'attrs', type: 'Map<String,String>' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].confidence).toBe('medium');

    // Default: applyConfidenceFilter with includeSpeculative=false drops it.
    expect(applyConfidenceFilter(ctx.findings, false)).toHaveLength(0);
    // Opt-in: with includeSpeculative=true, the finding is preserved.
    expect(applyConfidenceFilter(ctx.findings, true)).toHaveLength(1);
  });

  it('dedup: 3 unguarded sinks in one method → exactly 1 finding', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'normal', start_line: 5, end_line: 20 },
        ],
        edges: [{ from: 0, to: 1, type: 'sequential' as const }],
      },
      calls: [
        {
          method_name: 'addAttribute',
          receiver: 'w',
          arguments: [],
          location: { line: 7, column: 0 },
          in_method: 'render',
        },
        {
          method_name: 'addAttribute',
          receiver: 'w',
          arguments: [],
          location: { line: 12, column: 0 },
          in_method: 'render',
        },
        {
          method_name: 'print',
          receiver: 'w',
          arguments: [],
          location: { line: 17, column: 0 },
          in_method: 'render',
        },
      ],
      types: [makeClass('Printer', [
        makeMethod('render', 5, 20, [
          { name: 'attrs', type: 'Map<String,String>' },
        ]),
      ])],
    });

    const ctx = makeCtx(ir);
    new MissingSanitizerGatePass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
  });
});
