/**
 * Tests for CodeGraph — the shared, lazily-indexed graph object.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../src/graph/index.js';
import type { CircleIR } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 20, hash: 'abc123' },
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

// ---------------------------------------------------------------------------
// DFG indexes
// ---------------------------------------------------------------------------

describe('CodeGraph - DFG indexes', () => {
  it('indexes defById', () => {
    const ir = makeIR({
      dfg: {
        defs: [
          { id: 1, variable: 'x', line: 5, kind: 'local' },
          { id: 2, variable: 'y', line: 10, kind: 'param' },
        ],
        uses: [],
        chains: [],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.defById.get(1)?.variable).toBe('x');
    expect(g.defById.get(2)?.variable).toBe('y');
    expect(g.defById.get(99)).toBeUndefined();
    // Second access returns cached value
    expect(g.defById.size).toBe(2);
  });

  it('indexes defsByLine', () => {
    const ir = makeIR({
      dfg: {
        defs: [
          { id: 1, variable: 'a', line: 5, kind: 'local' },
          { id: 2, variable: 'b', line: 5, kind: 'local' },
          { id: 3, variable: 'c', line: 9, kind: 'local' },
        ],
        uses: [],
        chains: [],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.defsByLine.get(5)?.length).toBe(2);
    expect(g.defsByLine.get(9)?.length).toBe(1);
    expect(g.defsByLine.get(99)).toBeUndefined();
  });

  it('indexes defsByVar', () => {
    const ir = makeIR({
      dfg: {
        defs: [
          { id: 1, variable: 'x', line: 3, kind: 'local' },
          { id: 2, variable: 'x', line: 7, kind: 'local' },
        ],
        uses: [],
        chains: [],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.defsByVar.get('x')?.length).toBe(2);
    expect(g.defsByVar.get('z')).toBeUndefined();
  });

  it('indexes usesByLine', () => {
    const ir = makeIR({
      dfg: {
        defs: [],
        uses: [
          { id: 1, variable: 'x', line: 10, def_id: 1 },
          { id: 2, variable: 'x', line: 10, def_id: 1 },
        ],
        chains: [],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.usesByLine.get(10)?.length).toBe(2);
    expect(g.usesByLine.get(99)).toBeUndefined();
  });

  it('indexes usesByDefId (only uses with non-null def_id)', () => {
    const ir = makeIR({
      dfg: {
        defs: [{ id: 1, variable: 'x', line: 5, kind: 'local' }],
        uses: [
          { id: 1, variable: 'x', line: 10, def_id: 1 },
          { id: 2, variable: 'x', line: 12, def_id: null },
        ],
        chains: [],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.usesByDefId.get(1)?.length).toBe(1);
    expect(g.usesByDefId.get(null as unknown as number)).toBeUndefined();
  });

  it('indexes chainsByFromDef', () => {
    const ir = makeIR({
      dfg: {
        defs: [],
        uses: [],
        chains: [
          { from_def: 1, to_def: 2, via: 'x' },
          { from_def: 1, to_def: 3, via: 'x' },
        ],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.chainsByFromDef.get(1)?.length).toBe(2);
    expect(g.chainsByFromDef.get(99)).toBeUndefined();
  });

  it('handles empty chains array', () => {
    const ir = makeIR({ dfg: { defs: [], uses: [], chains: [] } });
    const g = new CodeGraph(ir);
    expect(g.chainsByFromDef.size).toBe(0);
  });

  it('handles undefined chains (no chains field)', () => {
    const ir = makeIR({ dfg: { defs: [], uses: [] } });
    const g = new CodeGraph(ir);
    expect(g.chainsByFromDef.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Call indexes
// ---------------------------------------------------------------------------

describe('CodeGraph - call indexes', () => {
  const call1 = {
    method_name: 'execute',
    receiver: 'stmt',
    arguments: [],
    location: { line: 15, column: 4 },
    in_method: 'doQuery',
  };
  const call2 = {
    method_name: 'getParameter',
    receiver: 'req',
    arguments: [],
    location: { line: 15, column: 20 },
    in_method: 'doQuery',
  };

  it('indexes callsByLine', () => {
    const ir = makeIR({ calls: [call1, call2] });
    const g = new CodeGraph(ir);
    expect(g.callsByLine.get(15)?.length).toBe(2);
    expect(g.callsByLine.get(99)).toBeUndefined();
  });

  it('indexes callsByMethod', () => {
    const ir = makeIR({ calls: [call1, call2] });
    const g = new CodeGraph(ir);
    expect(g.callsByMethod.get('execute')?.length).toBe(1);
    expect(g.callsByMethod.get('getParameter')?.length).toBe(1);
    expect(g.callsByMethod.get('missing')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Type / method indexes
// ---------------------------------------------------------------------------

describe('CodeGraph - type/method indexes', () => {
  const type1 = {
    name: 'UserService',
    kind: 'class' as const,
    package: 'com.example',
    extends: null,
    implements: [],
    annotations: [],
    methods: [
      {
        name: 'getUser',
        return_type: 'User',
        parameters: [],
        annotations: [],
        modifiers: ['public'],
        start_line: 10,
        end_line: 20,
      },
      {
        name: 'saveUser',
        return_type: 'void',
        parameters: [],
        annotations: [],
        modifiers: ['public'],
        start_line: 22,
        end_line: 35,
      },
    ],
    fields: [],
    start_line: 5,
    end_line: 40,
  };

  it('indexes methodsByName', () => {
    const ir = makeIR({ types: [type1] });
    const g = new CodeGraph(ir);
    expect(g.methodsByName.get('getUser')?.length).toBe(1);
    expect(g.methodsByName.get('saveUser')?.length).toBe(1);
    expect(g.methodsByName.get('missing')).toBeUndefined();
  });

  it('methodAtLine returns enclosing method', () => {
    const ir = makeIR({ types: [type1] });
    const g = new CodeGraph(ir);
    expect(g.methodAtLine(15)?.method.name).toBe('getUser');
    expect(g.methodAtLine(25)?.method.name).toBe('saveUser');
  });

  it('methodAtLine returns null when no method contains line', () => {
    const ir = makeIR({ types: [type1] });
    const g = new CodeGraph(ir);
    expect(g.methodAtLine(100)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Taint indexes
// ---------------------------------------------------------------------------

describe('CodeGraph - taint indexes', () => {
  it('indexes sanitizersByLine', () => {
    const ir = makeIR({
      taint: {
        sources: [],
        sinks: [],
        sanitizers: [
          { type: 'html_escape', method: 'escapeHtml', line: 8, sanitizes: ['xss'] },
          { type: 'sql_escape', method: 'PreparedStatement.setString', line: 8, sanitizes: ['sql_injection'] },
        ],
      },
    });
    const g = new CodeGraph(ir);
    expect(g.sanitizersByLine.get(8)?.length).toBe(2);
    expect(g.sanitizersByLine.get(99)).toBeUndefined();
  });

  it('handles empty sanitizers', () => {
    const g = new CodeGraph(makeIR());
    expect(g.sanitizersByLine.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Query primitives
// ---------------------------------------------------------------------------

describe('CodeGraph - query primitives', () => {
  const dfg = {
    defs: [
      { id: 1, variable: 'input', line: 5, kind: 'param' as const },
      { id: 2, variable: 'query', line: 8, kind: 'local' as const },
      { id: 3, variable: 'query', line: 12, kind: 'local' as const },
    ],
    uses: [
      { id: 1, variable: 'input', line: 8, def_id: 1 },
      { id: 2, variable: 'query', line: 15, def_id: 2 },
      { id: 3, variable: 'query', line: 15, def_id: null },
    ],
    chains: [
      { from_def: 1, to_def: 2, via: 'input' },
      { from_def: 2, to_def: 3, via: 'query' },
    ],
  };

  const g = new CodeGraph(makeIR({ dfg }));

  it('defsAtLine returns defs at that line', () => {
    expect(g.defsAtLine(5).length).toBe(1);
    expect(g.defsAtLine(8).length).toBe(1);
    expect(g.defsAtLine(99).length).toBe(0);
  });

  it('usesAtLine returns uses at that line', () => {
    expect(g.usesAtLine(8).length).toBe(1);
    expect(g.usesAtLine(15).length).toBe(2);
    expect(g.usesAtLine(99).length).toBe(0);
  });

  it('usesOfDef returns uses for a defId', () => {
    expect(g.usesOfDef(2).length).toBe(1);
    expect(g.usesOfDef(99).length).toBe(0);
  });

  it('callsAtLine returns empty when no calls at line', () => {
    expect(g.callsAtLine(5).length).toBe(0);
  });

  it('chainsFrom returns outgoing chains', () => {
    expect(g.chainsFrom(1).length).toBe(1);
    expect(g.chainsFrom(99).length).toBe(0);
  });

  it('laterDefsOfVar filters by line range', () => {
    // defs of 'query' at lines 8 and 12
    const later = g.laterDefsOfVar('query', 7, 15);
    expect(later.length).toBe(2);

    const narrow = g.laterDefsOfVar('query', 8, 11);
    expect(narrow.length).toBe(0);  // strictly after 8, at or before 11 → none

    const one = g.laterDefsOfVar('query', 8, 12);
    expect(one.length).toBe(1);  // line 12 is ≤ 12 and > 8
  });

  it('propagateTaintedDefIds follows chains to fixpoint', () => {
    // seed: def 1 is tainted → chains: 1→2, 2→3
    const result = g.propagateTaintedDefIds(new Set([1]));
    expect(result.has(1)).toBe(true);
    expect(result.has(2)).toBe(true);
    expect(result.has(3)).toBe(true);
  });

  it('propagateTaintedDefIds with empty seed returns empty set', () => {
    const result = g.propagateTaintedDefIds(new Set());
    expect(result.size).toBe(0);
  });

  it('propagateTaintedDefIds does not mutate input seed', () => {
    const seed = new Set([1]);
    g.propagateTaintedDefIds(seed);
    expect(seed.size).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Lazy init caching — second access returns same Map instance
// ---------------------------------------------------------------------------

describe('CodeGraph - lazy init caching', () => {
  it('returns same Map instance on repeated access', () => {
    const g = new CodeGraph(makeIR({ dfg: { defs: [{ id: 1, variable: 'x', line: 1, kind: 'local' }], uses: [], chains: [] } }));
    const first = g.defsByLine;
    const second = g.defsByLine;
    expect(first).toBe(second);
  });
});
