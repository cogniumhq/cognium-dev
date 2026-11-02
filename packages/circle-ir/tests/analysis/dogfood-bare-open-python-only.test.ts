/**
 * Dogfood 2026-10-31 (circle-ir navigation-index.ts): a TypeScript local helper
 * named `open` (`const xo = open(x, a)`) was reported as a resource leak.
 * A bare `open(...)` is a resource factory only as Python's built-in;
 * `Selector.open()`-style receiver calls are unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const leaks = async (code: string, file: string, lang: 'typescript' | 'python') =>
  ((await analyze(code, file, lang)).findings ?? []).filter(f => f.rule_id === 'resource-leak');

describe('resource-leak: a bare open() is a factory only in Python', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a TS helper named open is not a resource', async () => {
    const code = `export class Idx {
  private same(a: { v: boolean }, b: { v: boolean }, across: boolean): boolean {
    const open = (t: { v: boolean }, c: { v: boolean }): boolean => across && t.v && c.v;
    return [a].every((x, i) => {
      const xo = open(x, a);
      const yo = open(b, b);
      if (xo && yo) return true;
      return i === 0;
    });
  }
}`;
    expect(await leaks(code, 'f.ts', 'typescript')).toHaveLength(0);
  });

});
