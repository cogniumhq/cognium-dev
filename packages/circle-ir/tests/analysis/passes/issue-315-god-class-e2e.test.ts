/**
 * cognium-dev #315 (from cognium-ai#198) — `god-class` cell.
 *
 * The cell alleged that the pass does not discriminate between a smelly class
 * and its refactored counterpart. Probed end-to-end, it discriminates — and on
 * more axes than a first read suggests. A finding needs 2 of 3 of `WMC > 47`
 * (SonarQube), `LCOM2 > 0.8`, `CBO > 14` (SATD), and real source reaches that
 * bar through three different pairings:
 *
 *   methods  deps |  WMC  LCOM2  CBO | result via
 *   ---------------+------------------+-----------------
 *        50    20  |  100   0.78   20 | fires  WMC + CBO
 *        20    20  |   40   0.83   20 | fires  LCOM2 + CBO
 *        10    20  |   20   0.91   20 | fires  LCOM2 + CBO
 *        30     3  |   60   0.81    3 | fires  WMC + LCOM2
 *        20     3  |    -      -    3 | silent
 *         4     2  |    -      -    2 | silent
 *
 * Note LCOM2 *falls* as method count rises on this fixture shape (0.91 -> 0.83
 * -> 0.78): more methods per field group means more pairs share a field. So the
 * pass is not merely a size gate — a 10-method class with many collaborators
 * fires, while a 20-method class with three does not.
 *
 * That means the cell cannot be adjudicated as "insensitive": whether a given
 * contrastive pair fires depends on which metric its shape stresses, and the
 * original pairs are not synced here. What is settled is that the pass does
 * discriminate on real source.
 *
 * `god-class.test.ts` already covers the threshold arithmetic, but it does so
 * against hand-built `CircleIR` literals — it never runs `analyze()`. That left
 * the actual subject of this cell untested: whether real source, taken through
 * type extraction, CFG construction and the pass's inline CK metrics, yields
 * values that cross the thresholds at all. These tests close that gap so a
 * regression in any of those stages shows up as a recall loss here rather than
 * as a silent quality-pass hole.
 *
 * Thresholds are asserted as inequalities, not exact numbers, so that a CFG or
 * metric refinement does not fail the test for the wrong reason.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

const godClass = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.findings ?? []).filter(f => f.rule_id === 'god-class');

/**
 * A class that is genuinely god-class scale: `methods` methods each carrying one
 * branch (so WMC ≈ 2 × methods), `deps` fields of distinct external types (CBO),
 * and every method touching exactly one of 8 unrelated data fields, so most
 * method pairs share no field (LCOM2).
 */
function monster(methods: number, deps: number): string {
  const types = Array.from({ length: deps }, (_, i) => `Dep${i}`);
  const lines = ['package x;'];
  for (const t of types) lines.push(`import com.ex.${t};`);
  lines.push('public class Monster {');
  types.forEach((t, i) => lines.push(`  private ${t} dep${i};`));
  for (let i = 0; i < 8; i++) lines.push(`  private String f${i};`);
  for (let i = 0; i < methods; i++) {
    const fi = i % 8;
    lines.push(`  public String m${i}(String a) {`);
    lines.push(`    if (a != null) { this.f${fi} = a; } else { this.f${fi} = ""; }`);
    lines.push(`    return this.f${fi};`);
    lines.push('  }');
  }
  lines.push('}');
  return lines.join('\n');
}

describe('#315 god-class discriminates on real source (end-to-end)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('flags a genuinely god-class-scale Java class', async () => {
    const r = await analyze(monster(50, 20), 'Monster.java', 'java');
    const hits = godClass(r);
    expect(hits.length).toBe(1);

    // The pipeline must actually produce threshold-crossing metrics, which is
    // the part the literal-IR tests cannot check.
    const ev = hits[0].evidence as { wmc: number; lcom2: number; cbo: number };
    expect(ev.wmc).toBeGreaterThan(47);
    expect(ev.cbo).toBeGreaterThan(14);
    expect(ev.lcom2).toBeGreaterThanOrEqual(0);
    expect(ev.lcom2).toBeLessThanOrEqual(1);
  });

  it('stays silent on a moderately smelly class — thresholds are not "any smell"', async () => {
    const lines = [
      'package x;',
      'import com.ex.A;',
      'import com.ex.B;',
      'import com.ex.C;',
      'public class Mildly {',
      '  private A a; private B b; private C c;',
      '  private String s;',
    ];
    for (let i = 0; i < 10; i++) {
      lines.push(`  public String n${i}(String v) { if (v == null) return ""; this.s = v; return this.s; }`);
    }
    lines.push('}');
    const r = await analyze(lines.join('\n'), 'Mildly.java', 'java');
    expect(godClass(r).length).toBe(0);
  });

  it('stays silent on a small cohesive class', async () => {
    const r = await analyze([
      'package x;',
      'import com.ex.A;',
      'public class Clean {',
      '  private A a;',
      '  private String s;',
      '  public String p0() { return this.s; }',
      '  public String p1() { return this.s; }',
      '  public String p2() { return this.s; }',
      '  public String p3() { return this.s; }',
      '}',
    ].join('\n'), 'Clean.java', 'java');
    expect(godClass(r).length).toBe(0);
  });

  it('fires via LCOM2 + CBO on a SMALL class with many collaborators', async () => {
    // 10 methods → WMC 20, well under 47, yet this fires: LCOM2 0.91 and CBO 20
    // are both over. Pins that the pass is not a size gate, which is the
    // assumption that made this cell look like a discrimination failure.
    const r = await analyze(monster(10, 20), 'SmallButCoupled.java', 'java');
    const hits = godClass(r);
    expect(hits.length).toBe(1);
    const ev = hits[0].evidence as { wmc: number; lcom2: number; cbo: number };
    expect(ev.wmc).toBeLessThan(47);
    expect(ev.lcom2).toBeGreaterThan(0.8);
    expect(ev.cbo).toBeGreaterThan(14);
  });

  it('fires via WMC + LCOM2 with only three collaborators', async () => {
    // The complement: CBO 3 is far under, WMC 60 and LCOM2 0.81 carry it.
    const r = await analyze(monster(30, 3), 'ManyMethodsFewDeps.java', 'java');
    const hits = godClass(r);
    expect(hits.length).toBe(1);
    const ev = hits[0].evidence as { wmc: number; lcom2: number; cbo: number };
    expect(ev.cbo).toBeLessThan(14);
    expect(ev.wmc).toBeGreaterThan(47);
  });

  it('stays silent when only one threshold is crossed', async () => {
    // 20 methods, 3 deps: WMC 40 under, CBO 3 under. The 2-of-3 rule withholds.
    const r = await analyze(monster(20, 3), 'Borderline.java', 'java');
    expect(godClass(r).length).toBe(0);
  });
});
