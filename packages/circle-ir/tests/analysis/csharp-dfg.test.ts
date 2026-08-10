/**
 * C#/.NET Phase-1 Slice 4 — buildCSharpDFG.
 *
 * The spike found buildJavaDFG yields 0 defs on C# (divergent def-site node
 * names). buildCSharpDFG populates ir.dfg with parameter/local/assignment defs,
 * identifier uses with reaching-def resolution, and def-use chains. Locks that
 * the DFG is non-empty and that the chains trace the source→sink data flow.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('C# Slice 4: buildCSharpDFG populates ir.dfg', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('extracts parameter and local defs (was 0 under buildJavaDFG)', async () => {
    const code = `
public class C {
  public IActionResult Get(string id) {
    var q = "SELECT * FROM u WHERE id=" + id;
    var cmd = new SqlCommand(q, conn);
    return Ok();
  }
}`;
    const r = await analyze(code, 'C.cs', 'csharp');
    const defs = r.dfg?.defs ?? [];
    expect(defs.length).toBeGreaterThan(0);
    const byName = new Map(defs.map(d => [d.variable, d]));
    expect(byName.get('id')?.kind).toBe('param');
    expect(byName.get('q')?.kind).toBe('local');
    expect(byName.get('cmd')?.kind).toBe('local');
  });

  it('builds def-use chains tracing the taint path id → q → cmd', async () => {
    const code = `
public class C {
  public IActionResult Get(string id) {
    var q = "SELECT * FROM u WHERE id=" + id;
    var cmd = new SqlCommand(q, conn);
    return Ok();
  }
}`;
    const r = await analyze(code, 'C.cs', 'csharp');
    const defs = r.dfg?.defs ?? [];
    const chains = r.dfg?.chains ?? [];
    const idOf = (name: string) => defs.find(d => d.variable === name)?.id;
    // id → q and q → cmd links present.
    expect(chains.some(c => c.from_def === idOf('id') && c.to_def === idOf('q'))).toBe(true);
    expect(chains.some(c => c.from_def === idOf('q') && c.to_def === idOf('cmd'))).toBe(true);
  });

  it('resolves identifier uses to their reaching definitions', async () => {
    const code = `
public class C {
  public void M(string id) {
    var q = id;
  }
}`;
    const r = await analyze(code, 'C.cs', 'csharp');
    const uses = r.dfg?.uses ?? [];
    const idDef = (r.dfg?.defs ?? []).find(d => d.variable === 'id')?.id;
    // the use of `id` on the RHS resolves to its param def.
    expect(uses.some(u => u.variable === 'id' && u.def_id === idDef)).toBe(true);
  });
});
