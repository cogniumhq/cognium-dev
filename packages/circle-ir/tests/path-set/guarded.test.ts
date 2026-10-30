import { describe, it, expect } from 'vitest';
import { analyzeProject, deriveBranchFacts, pathSetDiff, pathSetOf, lineDominates } from '../../src/index.js';
import type { BranchFact, ProjectAnalysis } from '../../src/index.js';

const FILE = 'src/main/java/demo/Files2.java';

const cls = (body: string): string => `package demo;
import java.nio.file.*;
import javax.servlet.http.*;
public class Files2 {
  private final Path base = Path.of("/srv/data");
  public byte[] read(HttpServletRequest req) throws Exception {
    String name = req.getParameter("name");
${body}
  }
}`;

/** One expression: the engine flags the path-building call inside the file access. */
const BASE = cls(`    return Files.readAllBytes(base.resolve(name));`);

/** Path built on its own line, then read: no check. */
const SPLIT = cls(`    Path real = base.resolve(name).toRealPath();
    return Files.readAllBytes(real);`);

/** The same, with a containment check before the read. */
const CHECKED = cls(`    Path real = base.resolve(name).toRealPath();
    if (!real.startsWith(base.toRealPath())) {
      throw new IllegalArgumentException("outside");
    }
    return Files.readAllBytes(real);`);

/** A check that does not read the path's data. */
const UNRELATED = cls(`    Path real = base.resolve(name).toRealPath();
    if (!enabled()) {
      throw new IllegalStateException("off");
    }
    return Files.readAllBytes(real);`);

async function load(code: string): Promise<{ p: ProjectAnalysis; b: Record<string, BranchFact[]> }> {
  return {
    p: await analyzeProject([{ code, filePath: FILE, language: 'java' }]),
    b: { [FILE]: await deriveBranchFacts(code, 'java') },
  };
}

describe('endpoints (T3c)', () => {
  it('keys a path by the file access its path-building sink feeds, so splitting the expression changes nothing', async () => {
    const a = await load(BASE);
    const s = await load(SPLIT);
    const d = pathSetDiff(a.p, s.p, { cwe: 22 });
    expect(d.entries.length).toBeGreaterThan(0);
    expect(d.counts.added).toBe(0);
    expect(d.counts.unchanged).toBe(d.entries.length);
    const after = d.entries[0].after;
    expect(after?.sink.call.method).toBe('readAllBytes');
    expect(after?.sink.intermediate?.call.method).toBe('resolve');
  });
});

describe('guarded (T3b)', () => {
  it('reports a containment check of the path data as guarded, with the check', async () => {
    const a = await load(BASE);
    const c = await load(CHECKED);
    const d = pathSetDiff(a.p, c.p, { cwe: 22, branches: { before: a.b, after: c.b } });
    expect(d.counts).toMatchObject({ guarded: 1, added: 0, unchanged: 0 });
    const e = d.entries[0];
    expect(e.change).toBe('guarded');
    expect(e.state).toEqual({ before: 'present', after: 'guarded' });
    expect(e.after?.guard).toEqual({ file: FILE, line: 9, method: 'startsWith', negated: true, sinkSide: false, callValue: true });
  });

  it('is not guarded without branch facts, or by a check that does not read the path data', async () => {
    const a = await load(BASE);
    const c = await load(CHECKED);
    expect(pathSetDiff(a.p, c.p, { cwe: 22 }).counts.unchanged).toBe(1);
    const u = await load(UNRELATED);
    expect(pathSetDiff(a.p, u.p, { cwe: 22, branches: { before: a.b, after: u.b } }).counts.unchanged).toBe(1);
  });

  it('carries guard and state on the one-tree set', async () => {
    const c = await load(CHECKED);
    const set = pathSetOf(c.p, { cwe: 22, branches: c.b });
    expect(set.paths.every(p => p.state === 'guarded' && p.guard !== undefined)).toBe(true);
  });

  it('lineDominates follows the method CFG', async () => {
    const c = await load(CHECKED);
    const ir = c.p.files[0].analysis;
    expect(lineDominates(ir, 9, 12)).toBe(true);
    expect(lineDominates(ir, 10, 12)).toBe(false);
    expect(lineDominates(ir, 9, 99)).toBe(false);
  });
});
