/**
 * cognium-dev#1324 — `analyzeProject` takes each file's IR from `analyzeFile`
 * when given, in input order, with the same timeout and error handling.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject, AnalysisTimeoutError } from '../src/analyzer.js';
import type { SupportedLanguage } from '../src/types/index.js';

const A = `
package app;
public class A {
  public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {
    st.executeQuery("SELECT * FROM t WHERE id = " + new B().id(req));
  }
}
`;
const B = `
package app;
public class B {
  public String id(javax.servlet.http.HttpServletRequest req) { return req.getParameter("id"); }
}
`;
const files: Array<{ code: string; filePath: string; language: SupportedLanguage }> = [
  { code: A, filePath: 'app/A.java', language: 'java' },
  { code: B, filePath: 'app/B.java', language: 'java' },
];
const strip = (x: unknown) => JSON.stringify(x, (k, v) => (k === 'analyzed_at' ? undefined : v));

describe('analyzeProject analyzeFile hook', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('gives the same result as analyze(), with files resolved out of order', async () => {
    const plain = await analyzeProject(files);
    // Start both, finish the second first: the merge must still follow input order.
    const pending = new Map(files.map((f, i) => [
      f.filePath,
      new Promise((r) => setTimeout(r, i === 0 ? 30 : 0)).then(() => analyze(f.code, f.filePath, f.language)),
    ]));
    const seen: string[] = [];
    const hooked = await analyzeProject(files, {
      analyzeFile: (_code, filePath) => { seen.push(filePath); return pending.get(filePath)!; },
    });
    expect(seen).toEqual(['app/A.java', 'app/B.java']);
    expect(strip(hooked)).toBe(strip(plain));
  });

  it('records an AnalysisTimeoutError from the hook and rethrows any other error', async () => {
    const timed = await analyzeProject(files, {
      analyzeFile: async (code, filePath, language) => {
        if (filePath === 'app/A.java') throw new AnalysisTimeoutError(filePath, 5, 'parse');
        return analyze(code, filePath, language);
      },
    });
    expect(timed.timed_out_files).toEqual([{ file: 'app/A.java', elapsed_ms: 5, phase: 'parse' }]);
    expect(timed.files.map((f) => f.file)).toEqual(['app/B.java']);

    await expect(analyzeProject(files, {
      analyzeFile: async () => { throw new Error('Failed to parse code'); },
    })).rejects.toThrow('Failed to parse code');
  });
});
