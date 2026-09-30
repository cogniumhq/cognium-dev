/**
 * #424 — `analyzeProject` retains every file's full `CircleIR` plus a
 * `CodeGraph` per file for the whole run, and `CrossFileResolver` then
 * resolves with all of them live. On NIST Juliet Java (40,855 files, ~216 MB)
 * that peak aborts the process with a V8 heap OOM: no result, no partial
 * findings, and a signal-kill indistinguishable from a crash in the caller.
 *
 * The ceiling does not lower the peak — only the streaming redesign can. It
 * converts the failure mode into a partial result plus a flag. These tests
 * lock that contract, and above all that BOTH ceilings default to off.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const mkFiles = (n: number, body = 'public class C { }') =>
  Array.from({ length: n }, (_, i) => ({
    code: body,
    filePath: `src/F${i}.java`,
    language: 'java' as const,
  }));

describe('#424 analyzeProject size ceiling', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('is off by default — every file is analysed and no flag is set', async () => {
    const r = await analyzeProject(mkFiles(5));
    expect(r.files).toHaveLength(5);
    expect(r.project_size_budget_exceeded).toBeUndefined();
  });

  it('maxProjectFiles stops the loop and flags the partial result', async () => {
    const r = await analyzeProject(mkFiles(5), { maxProjectFiles: 2 });
    expect(r.files).toHaveLength(2);
    expect(r.project_size_budget_exceeded).toBe(true);
  });

  it('maxProjectSourceChars stops the loop and flags the partial result', async () => {
    const body = 'public class C { }';
    // Budget for exactly two files: the third would cross it.
    const r = await analyzeProject(mkFiles(5, body), {
      maxProjectSourceChars: body.length * 2,
    });
    expect(r.files).toHaveLength(2);
    expect(r.project_size_budget_exceeded).toBe(true);
  });

  it('a ceiling larger than the project is not reached', async () => {
    const r = await analyzeProject(mkFiles(3), {
      maxProjectFiles: 100,
      maxProjectSourceChars: 1_000_000,
    });
    expect(r.files).toHaveLength(3);
    expect(r.project_size_budget_exceeded).toBeUndefined();
  });

  it('0 is treated as off, not as an immediate stop', async () => {
    const r = await analyzeProject(mkFiles(3), {
      maxProjectFiles: 0,
      maxProjectSourceChars: 0,
    });
    expect(r.files).toHaveLength(3);
    expect(r.project_size_budget_exceeded).toBeUndefined();
  });

  it('keeps analysing — the truncated result is still a real analysis', async () => {
    const vulnerable = `import java.sql.*;
public class C {
  public void run(javax.servlet.http.HttpServletRequest req, Connection conn) throws Exception {
    String id = req.getParameter("id");
    conn.createStatement().executeQuery("SELECT * FROM u WHERE id=" + id);
  }
}`;
    const files = [
      { code: vulnerable, filePath: 'src/A.java', language: 'java' as const },
      { code: vulnerable, filePath: 'src/B.java', language: 'java' as const },
    ];
    const r = await analyzeProject(files, { maxProjectFiles: 1 });
    expect(r.files).toHaveLength(1);
    expect(r.project_size_budget_exceeded).toBe(true);
    expect(r.files[0].analysis.taint.flows.length).toBeGreaterThan(0);
  });
});
