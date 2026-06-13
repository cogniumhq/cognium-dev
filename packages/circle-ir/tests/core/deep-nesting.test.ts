/**
 * Regression test for cognium-ai#88 — Java AST parser stack overflow on
 * deeply nested binary string concatenation (e.g. CoreNLP's
 * DefaultTeXHyphenData.java, 4500+ "..." + "..." segments).
 *
 * Tree-sitter parses left-associative `+` chains as a deeply nested binary
 * AST: ((("a" + "b") + "c") + "d") ... — depth ~= number of segments. The
 * IR build walks the tree via the recursive `walkTree` helper, which blows
 * the V8 stack at ~5K-10K depth.
 *
 * This test forces a parse on a synthetic file with 6000 concatenated
 * literals. Before the iterative-walk fix, this throws
 * `RangeError: Maximum call stack size exceeded` inside `walkTree`. After
 * the fix, it must complete and produce a usable IR.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze } from '../../src/analyzer.js';
import { initAnalyzer } from '../../src/analyzer.js';

function makeDeeplyConcatenatedJava(n: number): string {
  const parts = Array.from({ length: n }, (_, i) => `".pat${i}\\n"`);
  return `package edu.stanford.nlp.ie.pascal;
public class DefaultTeXHyphenData {
  public static final String hyphenData =
    ${parts.join(' +\n    ')};
}
`;
}

describe('deep-nesting regression (cognium-ai#88)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('analyzes 6000-segment string concatenation without stack overflow', async () => {
    const code = makeDeeplyConcatenatedJava(6000);
    const result = await analyze(code, 'DefaultTeXHyphenData.java', 'java');
    expect(result).toBeDefined();
    expect(result.parse_status?.success).toBe(true);
  }, 30000);

  it('analyzes 10000-segment string concatenation without stack overflow', async () => {
    const code = makeDeeplyConcatenatedJava(10000);
    const result = await analyze(code, 'DefaultTeXHyphenData.java', 'java');
    expect(result).toBeDefined();
    expect(result.parse_status?.success).toBe(true);
  }, 60000);
});
