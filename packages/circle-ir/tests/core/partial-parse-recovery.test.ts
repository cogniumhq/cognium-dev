/**
 * cognium-dev#1307 — a partial parse reports `state: 'partial'` with the
 * error span, and keeps the declarations around the syntax error instead
 * of dropping them.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

function methodsOf(ir: CircleIR, typeName: string): string[] {
  return ir.types.find((t) => t.name === typeName)?.methods.map((m) => m.name) ?? [];
}

describe('partial parse keeps declarations (#1307)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('parse_status', () => {
    it('reports complete on a clean parse', async () => {
      const ir = await analyze('function ok() { return 1; }\n', 'ok.js', 'javascript');
      expect(ir.parse_status?.state).toBe('complete');
      expect(ir.parse_status?.error_locations).toEqual([]);
    });

    it('reports partial with the error span, in source order', async () => {
      const code = [
        'public class A {',
        '  void before() { int x = 1; }',
        '  @@ garbage',
        '  void after() { int z = 2; }',
        '}',
      ].join('\n');
      const ir = await analyze(code, 'A.java', 'java');
      expect(ir.parse_status?.state).toBe('partial');
      const locs = ir.parse_status?.error_locations ?? [];
      expect(locs.length).toBeGreaterThan(0);
      expect(locs[0]).toEqual({ line: 3, column: 2, end_line: 3, end_column: 3 });
      const order = locs.map((l) => l.line * 1000 + l.column);
      expect(order).toEqual([...order].sort((a, b) => a - b));
    });

    it('past 50 errors, reports the first 50 in source order', async () => {
      const methods = Array.from({ length: 60 }, (_, i) => `  void m${i}() { int x = ; }`);
      const code = ['public class Many {', ...methods, '}'].join('\n');
      const ir = await analyze(code, 'Many.java', 'java');
      const status = ir.parse_status!;
      expect(status.error_count).toBeGreaterThan(50);
      expect(status.error_locations).toHaveLength(50);
      // One error per method line, lines 2 .. 61: the first 50 are lines 2 .. 51.
      expect(status.error_locations.map((l) => l.line)).toEqual(
        Array.from({ length: 50 }, (_, i) => i + 2),
      );
    });
  });

  describe('JavaScript / TypeScript', () => {
    it('JS: a broken function header keeps the functions and classes after it', async () => {
      const code = [
        'function before(a) { return a + 1; }',
        'function broken( { return ; }',
        'function after(b) { return b * 2; }',
        'class Tail { m() { return 1; } }',
        '',
      ].join('\n');
      const ir = await analyze(code, 'a.js', 'javascript');
      expect(ir.parse_status?.state).toBe('partial');
      expect(ir.parse_status?.error_locations[0]).toMatchObject({ line: 2, column: 0 });
      expect(methodsOf(ir, '<module>')).toEqual(['before', 'after']);
      expect(methodsOf(ir, 'Tail')).toEqual(['m']);
      const after = ir.types.find((t) => t.name === '<module>')?.methods.find((m) => m.name === 'after');
      expect(after?.start_line).toBe(3);
      expect(ir.types.find((t) => t.name === 'Tail')?.start_line).toBe(4);
    });

    it('TSX: an unclosed JSX element keeps the components after it', async () => {
      const code = [
        'export function Before() { return <div>hi</div>; }',
        'const y = <div>;',
        'export function After() { return <span/>; }',
        '',
      ].join('\n');
      const ir = await analyze(code, 'a.tsx', 'typescript');
      expect(ir.parse_status?.state).toBe('partial');
      expect(methodsOf(ir, '<module>')).toEqual(['Before', 'After']);
    });

    it('leaves a clean file unchanged', async () => {
      const code = 'function a() {}\nclass B { m() {} }\n';
      const ir = await analyze(code, 'a.js', 'javascript');
      expect(methodsOf(ir, '<module>')).toEqual(['a']);
      expect(methodsOf(ir, 'B')).toEqual(['m']);
    });
  });

  describe('Java', () => {
    it('an unclosed method body keeps the next method', async () => {
      const code = [
        'public class A {',
        '  void before() { int x = 1; }',
        '  void broken() { if (a) { }',
        '  public String after(String q) throws Exception { return q; }',
        '}',
        'class B { void m() {} }',
        '',
      ].join('\n');
      const ir = await analyze(code, 'A.java', 'java');
      expect(ir.parse_status?.state).toBe('partial');
      expect(methodsOf(ir, 'A')).toEqual(['before', 'broken', 'after']);
      const after = ir.types.find((t) => t.name === 'A')?.methods.find((m) => m.name === 'after');
      expect(after?.start_line).toBe(4);
      expect(after?.parameters.map((p) => p.name)).toEqual(['q']);
      expect(methodsOf(ir, 'B')).toEqual(['m']);
    });

    it('an annotated method after an unclosed body is kept', async () => {
      const code = [
        'public class A {',
        '  void broken() {',
        '    while (x) {',
        '  }',
        '',
        '  @Override',
        '  public java.util.Map<String, Integer> after() {',
        '    return null;',
        '  }',
        '}',
        '',
      ].join('\n');
      const ir = await analyze(code, 'A.java', 'java');
      expect(methodsOf(ir, 'A')).toContain('after');
    });

    it('does not split a broken method at its own control-flow lines', async () => {
      const code = [
        'public class A {',
        '  void broken() {',
        '    if (a) {',
        '    } else if (b) {',
        '    int y = ;',
        '  }',
        '}',
        '',
      ].join('\n');
      const ir = await analyze(code, 'A.java', 'java');
      expect(methodsOf(ir, 'A')).toEqual(['broken']);
    });
  });
});
