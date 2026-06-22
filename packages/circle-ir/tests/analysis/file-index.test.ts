/**
 * Unit tests for the FileIndex pre-index helpers introduced in 3.89.0
 * (perf/cross-file-pre-index — issue #141).
 *
 * The helpers live in `src/resolution/cross-file.ts`:
 *   - `buildFileIndex(ir)` → returns six lookup maps used by the resolver
 *     hot loops (callsByLine, defsByLine, usesByLine, callsByMethod,
 *     sinksByMethod, defsByMethod).
 *
 * These tests lock the index semantics that the resolver depends on:
 *   1. Empty IR → empty maps.
 *   2. Per-line buckets preserve original array order (matches `Array.filter`).
 *   3. Per-method buckets respect `[start_line, end_line]` boundaries
 *      (matches the pre-refactor `c.location.line >= start && <= end` filters).
 *   4. Per-method buckets are sorted by line ascending (matches the
 *      pre-refactor `.filter(...).sort((a, b) => a.line - b.line)` pipeline
 *      that the resolver used in `findInterproceduralTaintPaths`).
 *   5. Per-method buckets handle nested method ranges (outer class method
 *      containing an inner anonymous-class method).
 */

import { describe, it, expect } from 'vitest';
import { buildFileIndex } from '../../src/resolution/cross-file.js';
import type {
  CircleIR,
  CallInfo,
  TaintSink,
  DFGDef,
  DFGUse,
  MethodInfo,
  TypeInfo,
} from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers — minimal IR builders for tests
// ---------------------------------------------------------------------------

function emptyIR(file = 'A.java'): CircleIR {
  return {
    meta: { circle_ir: '3.0', file, language: 'java', loc: 0, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function method(name: string, start: number, end: number): MethodInfo {
  return {
    name,
    return_type: 'void',
    parameters: [],
    annotations: [],
    modifiers: ['public'],
    start_line: start,
    end_line: end,
  };
}

function type(name: string, methods: MethodInfo[]): TypeInfo {
  return {
    name,
    kind: 'class',
    package: null,
    extends: null,
    implements: [],
    annotations: [],
    methods,
    fields: [],
    start_line: methods[0]?.start_line ?? 1,
    end_line: methods[methods.length - 1]?.end_line ?? 1,
  };
}

function call(methodName: string, line: number): CallInfo {
  return {
    method_name: methodName,
    receiver: null,
    arguments: [],
    location: { line, column: 0 },
  };
}

function sink(line: number, sinkType: TaintSink['type'] = 'sql_injection'): TaintSink {
  return {
    type: sinkType,
    cwe: 'CWE-89',
    line,
    location: `line ${line}`,
    confidence: 0.9,
  };
}

function def(id: number, variable: string, line: number, kind: DFGDef['kind'] = 'local'): DFGDef {
  return { id, variable, line, kind };
}

function use(id: number, variable: string, line: number, defId: number | null = null): DFGUse {
  return { id, variable, line, def_id: defId };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FileIndex — buildFileIndex (3.89.0 #141 pre-index)', () => {
  describe('empty input', () => {
    it('returns six empty maps for an empty IR', () => {
      const idx = buildFileIndex(emptyIR());
      expect(idx.callsByLine.size).toBe(0);
      expect(idx.defsByLine.size).toBe(0);
      expect(idx.usesByLine.size).toBe(0);
      expect(idx.callsByMethod.size).toBe(0);
      expect(idx.sinksByMethod.size).toBe(0);
      expect(idx.defsByMethod.size).toBe(0);
    });
  });

  describe('per-line bucketing (matches Array.filter insertion order)', () => {
    it('callsByLine groups multiple calls on the same line, preserving original array order', () => {
      const ir = emptyIR();
      const c1 = call('foo', 10);
      const c2 = call('bar', 10);
      const c3 = call('baz', 11);
      const c4 = call('qux', 10);
      ir.calls.push(c1, c2, c3, c4);

      const idx = buildFileIndex(ir);
      expect(idx.callsByLine.get(10)).toEqual([c1, c2, c4]);
      expect(idx.callsByLine.get(11)).toEqual([c3]);
      expect(idx.callsByLine.get(12)).toBeUndefined();
    });

    it('defsByLine buckets DFG defs by line', () => {
      const ir = emptyIR();
      const d1 = def(1, 'a', 5);
      const d2 = def(2, 'b', 5);
      const d3 = def(3, 'c', 7);
      ir.dfg.defs.push(d1, d2, d3);

      const idx = buildFileIndex(ir);
      expect(idx.defsByLine.get(5)).toEqual([d1, d2]);
      expect(idx.defsByLine.get(7)).toEqual([d3]);
    });

    it('usesByLine buckets DFG uses by line', () => {
      const ir = emptyIR();
      const u1 = use(1, 'a', 3);
      const u2 = use(2, 'a', 3);
      ir.dfg.uses.push(u1, u2);

      const idx = buildFileIndex(ir);
      expect(idx.usesByLine.get(3)).toEqual([u1, u2]);
    });
  });

  describe('per-method bucketing (matches start_line/end_line range filter)', () => {
    it('callsByMethod respects [start_line, end_line] inclusive bounds', () => {
      const m = method('foo', 10, 20);
      const ir = emptyIR();
      ir.types.push(type('A', [m]));

      const before = call('x', 9);     // before start — excluded
      const onStart = call('x', 10);   // on start — included
      const inside = call('x', 15);    // inside — included
      const onEnd = call('x', 20);     // on end — included
      const after = call('x', 21);     // after end — excluded
      ir.calls.push(before, onStart, inside, onEnd, after);

      const idx = buildFileIndex(ir);
      expect(idx.callsByMethod.get(m)).toEqual([onStart, inside, onEnd]);
    });

    it('callsByMethod returns calls sorted by line ascending (matches resolver expectations)', () => {
      const m = method('foo', 1, 50);
      const ir = emptyIR();
      ir.types.push(type('A', [m]));

      // Push out-of-order; index must sort.
      const c20 = call('x', 20);
      const c5 = call('x', 5);
      const c30 = call('x', 30);
      const c10 = call('x', 10);
      ir.calls.push(c20, c5, c30, c10);

      const idx = buildFileIndex(ir);
      const inMethod = idx.callsByMethod.get(m);
      expect(inMethod).toBeDefined();
      const lines = inMethod!.map(c => c.location.line);
      expect(lines).toEqual([5, 10, 20, 30]);
    });

    it('sinksByMethod respects method range and sorts by line', () => {
      const m = method('foo', 5, 15);
      const ir = emptyIR();
      ir.types.push(type('A', [m]));

      const s12 = sink(12);
      const s7 = sink(7);
      const sBefore = sink(4);  // out of range
      const sAfter = sink(16);  // out of range
      ir.taint.sinks.push(s12, s7, sBefore, sAfter);

      const idx = buildFileIndex(ir);
      const inMethod = idx.sinksByMethod.get(m);
      expect(inMethod).toBeDefined();
      expect(inMethod!.map(s => s.line)).toEqual([7, 12]);
    });

    it('defsByMethod respects method range', () => {
      const m = method('foo', 100, 200);
      const ir = emptyIR();
      ir.types.push(type('A', [m]));

      const dIn1 = def(1, 'a', 100);
      const dIn2 = def(2, 'b', 150);
      const dOut = def(3, 'c', 99);
      ir.dfg.defs.push(dIn1, dIn2, dOut);

      const idx = buildFileIndex(ir);
      const inMethod = idx.defsByMethod.get(m);
      expect(inMethod).toBeDefined();
      expect(inMethod!.map(d => d.id)).toEqual([1, 2]);
    });

    it('uses MethodInfo object identity as the key (different MethodInfo instances yield different buckets)', () => {
      const m1 = method('foo', 1, 10);
      const m2 = method('foo', 1, 10);  // same name+range, different object
      const ir = emptyIR();
      ir.types.push(type('A', [m1]));   // only m1 is in the index input

      ir.calls.push(call('x', 5));

      const idx = buildFileIndex(ir);
      expect(idx.callsByMethod.get(m1)).toHaveLength(1);
      // m2 was never iterated; lookup must miss even though its values are identical.
      expect(idx.callsByMethod.get(m2)).toBeUndefined();
    });
  });

  describe('overlapping/nested methods (e.g. inner anonymous classes)', () => {
    it('returns the same call to both enclosing and enclosed methods (matches pre-3.89.0 filter semantics)', () => {
      // Outer method spans lines 10-50; inner anonymous-class method spans 25-35.
      // A call at line 30 falls inside BOTH ranges and the pre-refactor
      // filters returned it from both buckets — buildFileIndex must too.
      const outer = method('outer', 10, 50);
      const inner = method('innerLambda', 25, 35);
      const ir = emptyIR();
      ir.types.push(type('Outer', [outer]));
      ir.types.push(type('InnerLambda$1', [inner]));

      const sharedCall = call('doIt', 30);
      ir.calls.push(sharedCall);

      const idx = buildFileIndex(ir);
      expect(idx.callsByMethod.get(outer)).toEqual([sharedCall]);
      expect(idx.callsByMethod.get(inner)).toEqual([sharedCall]);
    });
  });

  describe('large input invariants', () => {
    it('all calls inside a method range appear in callsByMethod exactly once', () => {
      const m = method('big', 1, 1000);
      const ir = emptyIR();
      ir.types.push(type('Big', [m]));

      const calls: CallInfo[] = [];
      for (let i = 1; i <= 1000; i++) calls.push(call(`m${i}`, i));
      ir.calls.push(...calls);

      const idx = buildFileIndex(ir);
      const inMethod = idx.callsByMethod.get(m);
      expect(inMethod).toBeDefined();
      expect(inMethod).toHaveLength(1000);
      // First/last must be the line-1 and line-1000 calls (sorted by line).
      expect(inMethod![0].location.line).toBe(1);
      expect(inMethod![999].location.line).toBe(1000);
    });
  });
});
