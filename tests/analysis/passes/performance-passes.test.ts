/**
 * Tests for the six Phase-4 analysis passes:
 *   - InfiniteLoopPass
 *   - DeepInheritancePass
 *   - RedundantLoopPass
 *   - UnboundedCollectionPass
 *   - SerialAwaitPass
 *   - ReactInlineJsxPass
 *
 * Each pass has a positive case (should detect) and a negative case (should not detect).
 * Uses minimal IR fixtures — no WASM parsing required.
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';

import { InfiniteLoopPass } from '../../../src/analysis/passes/infinite-loop-pass.js';
import { DeepInheritancePass } from '../../../src/analysis/passes/deep-inheritance-pass.js';
import { RedundantLoopPass } from '../../../src/analysis/passes/redundant-loop-pass.js';
import { UnboundedCollectionPass } from '../../../src/analysis/passes/unbounded-collection-pass.js';
import { SerialAwaitPass } from '../../../src/analysis/passes/serial-await-pass.js';
import { ReactInlineJsxPass } from '../../../src/analysis/passes/react-inline-jsx-pass.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 50, hash: 'abc123' },
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

function makeCtx(ir: CircleIR, code: string, language?: string): PassContext & { findings: SastFinding[] } {
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

// ---------------------------------------------------------------------------
// InfiniteLoopPass
// ---------------------------------------------------------------------------

describe('InfiniteLoopPass', () => {
  it('detects a loop with no exit edge', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.java', language: 'java', loc: 20, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 3, end_line: 3 },
          { id: 2, type: 'normal', start_line: 4, end_line: 6 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
          // No exit edge from block 1 to anything outside the loop body
        ],
      },
    });
    const code = `
void run() {
  while (true) {
    doWork();
    Thread.sleep(100);
  }
}`;
    const ctx = makeCtx(ir, code, 'java');
    const result = new InfiniteLoopPass().run(ctx);

    expect(result.potentialInfiniteLoops.length).toBeGreaterThanOrEqual(1);
    expect(ctx.findings.some(f => f.rule_id === 'infinite-loop')).toBe(true);
  });

  it('does not flag a loop with a break statement in source', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.java', language: 'java', loc: 10, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
    });
    const code = `
while (true) {
  if (done) break;
  process();
}`;
    const ctx = makeCtx(ir, code, 'java');
    const result = new InfiniteLoopPass().run(ctx);

    expect(result.potentialInfiniteLoops).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag bounded C-style for loop with .length', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 10, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 4 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
    });
    const code = `function process(arr) {
  for (var i = 0; i < arr.length; i++) {
    doWork(arr[i]);
  }
}`;
    const ctx = makeCtx(ir, code, 'javascript');
    const result = new InfiniteLoopPass().run(ctx);
    expect(result.potentialInfiniteLoops).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag bounded C-style for loop with variable limit', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 10, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 4 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
    });
    const code = `function process(items) {
  for (let i = 0; i < count; i++) {
    doWork(items[i]);
  }
}`;
    const ctx = makeCtx(ir, code, 'javascript');
    const result = new InfiniteLoopPass().run(ctx);
    expect(result.potentialInfiniteLoops).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('still flags while(true) with no exit', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 10, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 4 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
    });
    const code = `function run() {
  while (true) {
    doWork();
  }
}`;
    const ctx = makeCtx(ir, code, 'javascript');
    const result = new InfiniteLoopPass().run(ctx);
    expect(result.potentialInfiniteLoops.length).toBeGreaterThanOrEqual(1);
    expect(ctx.findings.some(f => f.rule_id === 'infinite-loop')).toBe(true);
  });

  it('still flags for(;;) with no exit', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.js', language: 'javascript', loc: 10, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 4 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
    });
    const code = `function run() {
  for (;;) {
    doWork();
  }
}`;
    const ctx = makeCtx(ir, code, 'javascript');
    const result = new InfiniteLoopPass().run(ctx);
    expect(result.potentialInfiniteLoops.length).toBeGreaterThanOrEqual(1);
    expect(ctx.findings.some(f => f.rule_id === 'infinite-loop')).toBe(true);
  });

  it('skips bash language', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.sh', language: 'bash', loc: 5, hash: '' },
      cfg: {
        blocks: [{ id: 0, type: 'loop', start_line: 1, end_line: 3 }, { id: 1, type: 'normal', start_line: 2, end_line: 2 }],
        edges: [{ from: 0, to: 1, type: 'true' }, { from: 1, to: 0, type: 'back' }],
      },
    });
    const ctx = makeCtx(ir, 'while true; do echo hi; done', 'bash');
    new InfiniteLoopPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DeepInheritancePass
// ---------------------------------------------------------------------------

describe('DeepInheritancePass', () => {
  it('detects inheritance depth > 5', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Order.java', language: 'java', loc: 50, hash: '' },
      types: [
        { name: 'A', kind: 'class', package: null, extends: null, implements: [], annotations: [], methods: [], fields: [], start_line: 1, end_line: 5 },
        { name: 'B', kind: 'class', package: null, extends: 'A', implements: [], annotations: [], methods: [], fields: [], start_line: 10, end_line: 15 },
        { name: 'C', kind: 'class', package: null, extends: 'B', implements: [], annotations: [], methods: [], fields: [], start_line: 20, end_line: 25 },
        { name: 'D', kind: 'class', package: null, extends: 'C', implements: [], annotations: [], methods: [], fields: [], start_line: 30, end_line: 35 },
        { name: 'E', kind: 'class', package: null, extends: 'D', implements: [], annotations: [], methods: [], fields: [], start_line: 40, end_line: 45 },
        { name: 'F', kind: 'class', package: null, extends: 'E', implements: [], annotations: [], methods: [], fields: [], start_line: 50, end_line: 55 },
        // G is depth 6: A→B→C→D→E→F→G
        { name: 'G', kind: 'class', package: null, extends: 'F', implements: [], annotations: [], methods: [], fields: [], start_line: 60, end_line: 65 },
      ],
    });
    const ctx = makeCtx(ir, '', 'java');
    const result = new DeepInheritancePass().run(ctx);

    expect(result.deepClasses.some(c => c.className === 'G')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'deep-inheritance')).toBe(true);
  });

  it('does not flag inheritance depth ≤ 5', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Order.java', language: 'java', loc: 30, hash: '' },
      types: [
        { name: 'Base', kind: 'class', package: null, extends: null, implements: [], annotations: [], methods: [], fields: [], start_line: 1, end_line: 5 },
        { name: 'Child', kind: 'class', package: null, extends: 'Base', implements: [], annotations: [], methods: [], fields: [], start_line: 10, end_line: 20 },
      ],
    });
    const ctx = makeCtx(ir, '', 'java');
    const result = new DeepInheritancePass().run(ctx);

    expect(result.deepClasses).toHaveLength(0);
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips rust and bash', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.rs', language: 'rust', loc: 5, hash: '' },
    });
    const ctx = makeCtx(ir, '', 'rust');
    new DeepInheritancePass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// RedundantLoopPass
// ---------------------------------------------------------------------------

describe('RedundantLoopPass', () => {
  it('skips .length in JS/TS (O(1) property access) but flags .size()', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      dfg: { defs: [], uses: [], chains: [] },
    });
    // .length is O(1) in JS/TS — should NOT be flagged
    const code = `
const arr = [1, 2, 3];
for (let i = 0; i < 10; i++) {
  const n = arr.length;
  process(n);
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new RedundantLoopPass().run(ctx);
    expect(result.invariants.some(v => v.expression.includes('arr.length'))).toBe(false);
  });

  it('flags .length in Java (may be a method call)', () => {
    const javaIR = makeIR({
      meta: { circle_ir: '3.0', file: 'Test.java', language: 'java', loc: 5, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      dfg: { defs: [], uses: [], chains: [] },
    });
    const javaCode = `
String[] arr = new String[10];
for (int i = 0; i < 10; i++) {
  int n = arr.length;
  process(n);
}`;
    const ctx = makeCtx(javaIR, javaCode, 'java');
    const result = new RedundantLoopPass().run(ctx);
    expect(result.invariants.some(v => v.expression.includes('arr.length'))).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'redundant-loop-computation')).toBe(true);
  });

  it('does not flag .length on a variable that is modified inside the loop', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 6 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      dfg: {
        defs: [{ id: 1, variable: 'arr', line: 4, kind: 'local' }],
        uses: [],
        chains: [],
      },
    });
    const code = `
const list = [];
for (let i = 0; i < 10; i++) {
  arr = getItems(i);
  const n = arr.length;
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new RedundantLoopPass().run(ctx);

    // arr is modified at line 4 (inside loop body lines 3-6), so arr.length should not be flagged
    expect(result.invariants.filter(v => v.variable === 'arr')).toHaveLength(0);
  });

  it('skips bash', () => {
    const ctx = makeCtx(makeIR(), 'for i in 1 2 3; do echo $i; done', 'bash');
    new RedundantLoopPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('detects Object.keys(obj) inside a loop on an unmodified variable', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      dfg: { defs: [], uses: [], chains: [] },
    });
    const code = `
const obj = { a: 1, b: 2 };
for (let i = 0; i < 10; i++) {
  const keys = Object.keys(obj);
  process(keys);
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new RedundantLoopPass().run(ctx);
    expect(result.invariants.some(v => v.expression.includes('Object.keys(obj)'))).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'redundant-loop-computation')).toBe(true);
  });

  it('detects Math.sqrt(n) inside a loop on an unmodified variable', () => {
    const ir = makeIR({
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 2, end_line: 2 },
          { id: 2, type: 'normal', start_line: 3, end_line: 5 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      dfg: { defs: [], uses: [], chains: [] },
    });
    const code = `
const n = 100;
for (let i = 0; i < 10; i++) {
  const root = Math.sqrt(n);
  process(root);
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new RedundantLoopPass().run(ctx);
    expect(result.invariants.some(v => v.expression.includes('Math.sqrt(n)'))).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'redundant-loop-computation')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// UnboundedCollectionPass
// ---------------------------------------------------------------------------

describe('UnboundedCollectionPass', () => {
  it('detects a collection that only grows inside a loop', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 20, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 3, end_line: 3 },
          { id: 2, type: 'normal', start_line: 4, end_line: 6 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      calls: [
        {
          method_name: 'push',
          receiver: 'results',
          arguments: [],
          location: { line: 5, column: 2 },
        },
      ],
    });
    const code = `
const results = [];
while (hasMore()) {
  const item = fetchNext();
  results.push(item);
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new UnboundedCollectionPass().run(ctx);

    expect(result.unboundedCollections.some(c => c.receiver === 'results')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'unbounded-collection')).toBe(true);
  });

  it('does not flag a loop where the collection is also cleared', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'test.ts', language: 'typescript', loc: 20, hash: '' },
      cfg: {
        blocks: [
          { id: 0, type: 'entry', start_line: 1, end_line: 1 },
          { id: 1, type: 'loop', start_line: 3, end_line: 3 },
          { id: 2, type: 'normal', start_line: 4, end_line: 8 },
        ],
        edges: [
          { from: 0, to: 1, type: 'sequential' },
          { from: 1, to: 2, type: 'true' },
          { from: 2, to: 1, type: 'back' },
        ],
      },
      calls: [
        { method_name: 'push', receiver: 'buf', arguments: [], location: { line: 5, column: 2 } },
        { method_name: 'clear', receiver: 'buf', arguments: [], location: { line: 7, column: 2 } },
      ],
    });
    const code = `
const buf = [];
while (stream.hasData()) {
  const chunk = stream.read();
  buf.push(chunk);
  if (buf.length >= 100) {
    flush(buf); buf.clear();
  }
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new UnboundedCollectionPass().run(ctx);

    expect(result.unboundedCollections.filter(c => c.receiver === 'buf')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// SerialAwaitPass
// ---------------------------------------------------------------------------

describe('SerialAwaitPass', () => {
  it('detects two independent consecutive awaits in same function', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'service.ts', language: 'typescript', loc: 20, hash: '' },
      types: [{
        name: 'UserService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'loadData',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: ['async'],
          start_line: 2,
          end_line: 8,
        }],
        fields: [],
        start_line: 1,
        end_line: 10,
      }],
      dfg: {
        defs: [
          { id: 1, variable: 'user', line: 3, kind: 'local' },
          { id: 2, variable: 'orders', line: 4, kind: 'local' },
        ],
        uses: [],
        chains: [],
      },
    });
    const code = `class UserService {
  async loadData() {
    const user = await fetchUser(id);
    const orders = await fetchOrders(id);
    return { user, orders };
  }
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new SerialAwaitPass().run(ctx);

    expect(result.serialAwaits.length).toBeGreaterThanOrEqual(1);
    expect(ctx.findings.some(f => f.rule_id === 'serial-await')).toBe(true);
  });

  it('does not flag awaits with data dependency', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'service.ts', language: 'typescript', loc: 15, hash: '' },
      types: [{
        name: 'OrderService',
        kind: 'class',
        package: null,
        extends: null,
        implements: [],
        annotations: [],
        methods: [{
          name: 'load',
          return_type: null,
          parameters: [],
          annotations: [],
          modifiers: ['async'],
          start_line: 2,
          end_line: 6,
        }],
        fields: [],
        start_line: 1,
        end_line: 7,
      }],
      dfg: {
        defs: [
          { id: 1, variable: 'user', line: 3, kind: 'local' },
          { id: 2, variable: 'orders', line: 4, kind: 'local' },
        ],
        uses: [],
        chains: [],
      },
    });
    const code = `class OrderService {
  async load() {
    const user = await fetchUser();
    const orders = await fetchOrders(user.id);
    return orders;
  }
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new SerialAwaitPass().run(ctx);

    // orders depends on user.id, so should not be flagged
    expect(result.serialAwaits).toHaveLength(0);
  });

  it('skips non-JS/TS languages', () => {
    const ctx = makeCtx(makeIR(), 'await foo()', 'python');
    new SerialAwaitPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// ReactInlineJsxPass
// ---------------------------------------------------------------------------

describe('ReactInlineJsxPass', () => {
  it('detects inline object in JSX prop', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'App.tsx', language: 'typescript', loc: 10, hash: '' },
    });
    const code = `function App() {
  return (
    <UserCard data={{ name: 'Alice', age: 30 }} />
  );
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new ReactInlineJsxPass().run(ctx);

    expect(result.inlineProps.some(p => p.propName === 'data' && p.kind === 'object')).toBe(true);
    expect(ctx.findings.some(f => f.rule_id === 'react-inline-jsx')).toBe(true);
  });

  it('detects inline arrow function in JSX prop', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Button.tsx', language: 'typescript', loc: 8, hash: '' },
    });
    const code = `function Button() {
  return <Btn onClick={() => handleClick(id)} label="go" />;
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new ReactInlineJsxPass().run(ctx);

    expect(result.inlineProps.some(p => p.propName === 'onClick' && p.kind === 'arrow')).toBe(true);
  });

  it('does not flag style={{ (idiomatic)', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'Box.tsx', language: 'typescript', loc: 5, hash: '' },
    });
    const code = `function Box() {
  return <div style={{ color: 'red', margin: 0 }}>hi</div>;
}`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new ReactInlineJsxPass().run(ctx);

    // style is in skip list
    expect(result.inlineProps.filter(p => p.propName === 'style')).toHaveLength(0);
  });

  it('does not flag files with no JSX content', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'utils.ts', language: 'typescript', loc: 5, hash: '' },
    });
    const code = `export function add(a: number, b: number): number { return a + b; }`;
    const ctx = makeCtx(ir, code, 'typescript');
    const result = new ReactInlineJsxPass().run(ctx);

    expect(result.inlineProps).toHaveLength(0);
  });

  it('skips non-JS/TS languages', () => {
    const ctx = makeCtx(makeIR(), '<Component data={{}} />', 'python');
    new ReactInlineJsxPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});
