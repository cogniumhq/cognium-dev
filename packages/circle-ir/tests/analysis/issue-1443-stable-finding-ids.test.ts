/**
 * cognium-dev#1443 — `generateFindings` ids were a per-file counter
 * (`vuln1`, `vuln2`, … in emit order). Two files both had a `vuln1`, and an id
 * shifted when another finding in the same file came or went, so a re-scan
 * could not tell "same finding" from "different finding" by id.
 *
 * The id is now derived from `CWE|file|declaration|rule` — the key
 * `cognium-dev recheck` uses — with no line in it. `Finding.key` carries that
 * key as text.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { declAt } from '../../src/path-set/path-set.js';
import { deriveStableIds } from '../../src/stable-ids/index.js';
import type { Finding } from '../../src/types/index.js';

async function findingsOf(code: string, file: string, withIds = false): Promise<Finding[]> {
  const r = await analyze(code, file, 'java');
  const ids = withIds ? await deriveStableIds(code, file, 'java') : undefined;
  return generateFindings(
    r.taint.sources, r.taint.sinks, r.dfg, file, code, 'java',
    r.taint.sanitizers, r.types, r.taint.flows, ids,
  );
}

const header = [
  'import javax.servlet.http.*;',
  'public class A extends HttpServlet {',
];
const cmdMethod = [
  '  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
  '    String p = req.getParameter("p");',
  '    Runtime.getRuntime().exec(p);',
  '  }',
];
const sqlMethod = [
  '  public void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
  '    String q = req.getParameter("q");',
  '    java.sql.Connection c = java.sql.DriverManager.getConnection("jdbc:x");',
  '    c.createStatement().executeQuery("SELECT * FROM t WHERE a = \'" + q + "\'");',
  '  }',
];
const footer = ['}'];
const src = (...parts: string[][]): string => parts.flat().join('\n') + '\n';

const byType = (fs: Finding[], t: string): Finding => {
  const f = fs.find(x => x.type === t);
  expect(f, `no ${t} finding`).toBeDefined();
  return f!;
};

describe('#1443 — stable finding ids', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('the same finding in two files gets two ids', async () => {
    const code = src(header, cmdMethod, footer);
    const a = byType(await findingsOf(code, 'web/A.java'), 'command_injection');
    const b = byType(await findingsOf(code, 'admin/A.java'), 'command_injection');
    expect(a.id).not.toBe(b.id);
  });

  it('keeps the id when lines are inserted above the sink', async () => {
    const before = byType(await findingsOf(src(header, cmdMethod, footer), 'A.java'), 'command_injection');
    const shifted = src(header, ['  // one', '  // two', '  private int n = 0;'], cmdMethod, footer);
    const after = byType(await findingsOf(shifted, 'A.java'), 'command_injection');
    expect(after.line).toBe(before.line + 3);
    expect(after.id).toBe(before.id);
    expect(after.key).toBe(before.key);
  });

  it('keeps the id when an unrelated finding in the same file disappears', async () => {
    const both = await findingsOf(src(header, sqlMethod, cmdMethod, footer), 'A.java');
    expect(both.length).toBeGreaterThanOrEqual(2);
    const cmdBefore = byType(both, 'command_injection');
    byType(both, 'sql_injection');

    // The SQL sink is fixed (constant query): its finding goes, the other stays.
    const fixedSql = sqlMethod.map(l => l.includes('executeQuery') ? '    c.createStatement().executeQuery("SELECT 1");' : l);
    const one = await findingsOf(src(header, fixedSql, cmdMethod, footer), 'A.java');
    expect(one.some(f => f.type === 'sql_injection')).toBe(false);
    expect(byType(one, 'command_injection').id).toBe(cmdBefore.id);
  });

  it('keys on CWE|file|declaration|rule, with no line', async () => {
    const code = src(header, cmdMethod, footer);
    const f = byType(await findingsOf(code, 'A.java'), 'command_injection');
    expect(f.key).toBe('CWE-78|A.java|A.java#A.doGet(HttpServletRequest,HttpServletResponse)|command_injection');
    expect(f.id).not.toMatch(/^vuln\d+$/);
  });

  it('uses the ids@0.1 declaration id when the caller passes stable ids (the recheck key)', async () => {
    const code = src(header, cmdMethod, footer);
    const f = byType(await findingsOf(code, 'A.java', true), 'command_injection');
    const r = await analyze(code, 'A.java', 'java');
    const decl = declAt('A.java', r, f.line, await deriveStableIds(code, 'A.java', 'java'));
    expect(decl.scheme).toBe('ids@0.1');
    expect(f.key).toBe(`CWE-78|A.java|${decl.id}|command_injection`);
  });

  it('gives two findings of one rule in one declaration distinct ids', async () => {
    const twoSinks = [
      '  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '    String p = req.getParameter("p");',
      '    Runtime.getRuntime().exec(p);',
      '    Runtime.getRuntime().exec("sh -c " + p);',
      '  }',
    ];
    const all = await findingsOf(src(header, twoSinks, footer), 'A.java');
    const fs = all.filter(f => f.type === 'command_injection');
    expect(fs.length).toBe(2);
    expect(fs[0].key).toBe(fs[1].key);
    expect(fs[0].id).not.toBe(fs[1].id);
    expect(new Set(all.map(f => f.id)).size).toBe(all.length);
  });
});
