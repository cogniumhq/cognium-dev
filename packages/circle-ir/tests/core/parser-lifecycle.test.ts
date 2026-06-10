/**
 * Parser lifecycle regression tests (issue #16).
 *
 * Guards against tree-sitter WASM state accumulation that previously caused
 * a ~20pp benchmark regression when 120 Java projects shared a single
 * initAnalyzer() call versus running each in its own subprocess.
 *
 * The fix: cache Parser instances per language (no per-call WASM Parser
 * allocation) and dispose Tree objects after each analyze() returns.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { createParser, disposeTree, parse } from '../../src/core/index.js';

describe('parser lifecycle', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reuses one Parser instance per language across many parse() calls', async () => {
    const a = await createParser('java');
    const b = await createParser('java');
    const c = await createParser('java');
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('repeated analyze() returns stable IR (no state pollution)', async () => {
    const code = `
package com.example;

public class Foo {
    public String greet(String name) {
        return "Hello " + name;
    }
}
`;

    const baseline = await analyze(code, 'Foo.java', 'java');

    // Run 50 additional iterations. With the previous unbounded-Tree leak,
    // accumulated WASM state caused observable changes in extracted IR
    // across long runs. After the fix, every iteration must match the
    // baseline byte-for-byte (modulo non-deterministic fields like findings
    // ordering — none expected for this snippet).
    for (let i = 0; i < 50; i++) {
      const next = await analyze(code, 'Foo.java', 'java');
      expect(next.types).toEqual(baseline.types);
      expect(next.calls).toEqual(baseline.calls);
      expect(next.imports).toEqual(baseline.imports);
      expect(next.exports).toEqual(baseline.exports);
    }
  });

  it('disposeTree() is a no-op on null/undefined and safe to call twice', async () => {
    expect(() => disposeTree(null)).not.toThrow();
    expect(() => disposeTree(undefined)).not.toThrow();

    const tree = await parse('class X {}', 'java');
    disposeTree(tree);
    // Second dispose must not throw — the public contract.
    expect(() => disposeTree(tree)).not.toThrow();
  });
});
