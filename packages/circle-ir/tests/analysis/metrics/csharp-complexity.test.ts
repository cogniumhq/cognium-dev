/**
 * C# complexity metrics — end-to-end (buildCSharpCFG -> types -> complexity pass).
 *
 * Before the dedicated C# CFG builder, C# rode the Java statement path, which
 * dropped `foreach`/`switch_section`, so McCabe under-counted (and often did
 * not attribute at all). These assert the full chain now produces per-method
 * cyclomatic complexity with C#-aware branch counting.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

function mccabe(metrics: { name: string; value: number; description?: string }[]) {
  const out = new Map<string, number>();
  for (const m of metrics) {
    if (m.name === 'cyclomatic_complexity' && m.description) {
      out.set(m.description.replace(/^method:\s*/, ''), m.value);
    }
  }
  return out;
}

describe('C# complexity metrics (end-to-end)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('emits per-method cyclomatic complexity for C# methods', async () => {
    const code = `class C {
      int Branchy(string s) {
        if (s == "a") { return 1; }
        foreach (var y in s) { Use(y); }
        switch (s) { case "p": return 2; case "q": return 3; default: return 4; }
        return 0;
      }
      int Straight(int a) { return a + 1; }
    }`;
    const r = await analyze(code, 'C.cs', 'csharp');
    const vg = mccabe(r.metrics?.metrics ?? []);

    // A straight-line method is 1; the branchy method is strictly greater.
    expect(vg.get('Straight')).toBe(1);
    expect(vg.get('Branchy')).toBeGreaterThan(1);
    expect(vg.get('Branchy')!).toBeGreaterThan(vg.get('Straight')!);
  });

  it('foreach contributes a loop (was invisible on the Java path)', async () => {
    const withLoop = `class C { int M(int[] xs) { foreach (var y in xs) { Use(y); } return 0; } }`;
    const noLoop = `class C { int M(int[] xs) { return 0; } }`;
    const a = await analyze(withLoop, 'C.cs', 'csharp');
    const b = await analyze(noLoop, 'C.cs', 'csharp');
    expect(mccabe(a.metrics?.metrics ?? []).get('M')!).toBeGreaterThan(
      mccabe(b.metrics?.metrics ?? []).get('M')!,
    );
    // loop_complexity counts back edges — the foreach must register one.
    const loop = (a.metrics?.metrics ?? []).find((m) => m.name === 'loop_complexity');
    expect(loop?.value).toBeGreaterThanOrEqual(1);
  });
});
