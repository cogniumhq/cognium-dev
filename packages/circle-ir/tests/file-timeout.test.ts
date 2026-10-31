/**
 * cognium-dev#1007 — opt-in per-file analysis time limit.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject, AnalysisTimeoutError } from '../src/analyzer.js';
import * as publicApi from '../src/index.js';

const JAVA = `
package app;
public class A {
  public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {
    String id = req.getParameter("id");
    st.executeQuery("SELECT * FROM t WHERE id = " + id);
  }
}
`;

// Large enough that a 1 ms limit is always passed by the time parsing ends.
const BIG_BASH = Array.from({ length: 4000 }, (_, i) => `v${i}=$(echo "$x${i}" | grep foo)`).join('\n');

describe('fileTimeoutMs', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('is exported from the public entry', () => {
    expect(publicApi.AnalysisTimeoutError).toBe(AnalysisTimeoutError);
  });

  it('leaves the output unchanged when unset or 0', async () => {
    const a = await analyze(JAVA, 'A.java', 'java');
    const b = await analyze(JAVA, 'A.java', 'java', { fileTimeoutMs: 0 });
    const c = await analyze(JAVA, 'A.java', 'java', { fileTimeoutMs: 600_000 });
    const strip = (x: unknown) => JSON.stringify(x, (k, v) => (k === 'timestamp' || k === 'analyzed_at' ? undefined : v));
    expect(strip(b)).toBe(strip(a));
    expect(strip(c)).toBe(strip(a));
    expect(a.taint.flows.length).toBeGreaterThan(0);
  });

  it('throws AnalysisTimeoutError once the limit is passed', async () => {
    let err: unknown;
    try {
      await analyze(BIG_BASH, 'big.sh', 'bash', { fileTimeoutMs: 1 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AnalysisTimeoutError);
    const t = err as AnalysisTimeoutError;
    expect(t.file).toBe('big.sh');
    expect(t.elapsedMs).toBeGreaterThan(0);
    expect(typeof t.phase).toBe('string');
  });

  it('analyzeProject skips a timed-out file, lists it, and keeps the rest', async () => {
    const project = await analyzeProject(
      [
        { code: BIG_BASH, filePath: 'big.sh', language: 'bash' },
        { code: JAVA, filePath: 'A.java', language: 'java' },
      ],
      { fileTimeoutMs: 1 },
    );
    expect(project.timed_out_files?.map((t) => t.file)).toContain('big.sh');
    expect(project.files.map((f) => f.file)).not.toContain('big.sh');
  });

  it('analyzeProject has no timed_out_files field without the option', async () => {
    const project = await analyzeProject([{ code: JAVA, filePath: 'A.java', language: 'java' }]);
    expect(project.timed_out_files).toBeUndefined();
  });
});
