/**
 * `recheck` (E20/engine): the deterministic re-check of a code-fix change.
 * A Java servlet before and after: a fixed SQL injection reads `gone`, a version
 * that only moves lines keeps it `still-present`, and a new command injection is
 * `new-high` and fails the no-new-high rule (exit 1).
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { applyBaseline, parseRecheckOptions, RECHECK_SCHEMA, type RecheckReport } from '../src/recheck';
import { UsageError } from '../src/utils/options';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');
const FILE = 'src/main/java/app/Lookup.java';

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

const servlet = (body: string, pad = '') => `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Lookup extends HttpServlet {
${pad}  private Connection conn;
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String id = req.getParameter("id");
${body}
  }
}
`;
const VULN = `    Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");`;
const FIXED = `    PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");
    ps.setString(1, id);
    ps.executeQuery();`;
const NEW_CMD = `${FIXED}
    Runtime.getRuntime().exec("ping " + id);`;

const trees: Record<string, string> = {};
let work: string;

function tree(name: string, code: string): string {
  const root = join(work, name);
  mkdirSync(join(root, 'src/main/java/app'), { recursive: true });
  writeFileSync(join(root, FILE), code);
  trees[name] = root;
  return root;
}

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), 'recheck-'));
  tree('before', servlet(VULN));
  tree('fixed', servlet(FIXED));
  tree('moved', servlet(VULN, '  // a comment\n  // and another\n  // and a third\n'));
  tree('new-high', servlet(NEW_CMD));
});
afterAll(() => rmSync(work, { recursive: true, force: true }));

describe('recheck CLI on a Java fix', () => {
  let baselinePath: string;

  test('before: emits keyed findings (no verdicts) and exits 0', async () => {
    baselinePath = join(work, 'before.json');
    const r = await runCli(['recheck', trees.before, '--changed', FILE, '-o', baselinePath]);
    expect(r.code).toBe(0);
    const rep = JSON.parse(readFileSync(baselinePath, 'utf8')) as RecheckReport;
    expect(rep.schema).toBe(RECHECK_SCHEMA);
    expect(rep.files).toEqual([FILE]);
    const sql = rep.findings.find(f => f.cwe === 'CWE-89');
    expect(sql).toBeDefined();
    expect(sql!.decl.scheme).toBe('ids@0.1');
    expect(sql!.key).not.toMatch(/\|\d+\|/); // no line numbers in the key
    expect(rep.verdicts).toBeUndefined();
  }, 60_000);

  test('fixed: the SQL injection is gone and the rule passes', async () => {
    const r = await runCli(['recheck', trees.fixed, '--changed', FILE, '--baseline', baselinePath]);
    expect(r.code).toBe(0);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.verdicts!.find(v => v.cwe === 'CWE-89')!.verdict).toBe('gone');
    expect(rep.summary!.newHigh).toBe(0);
    expect(rep.noNewHigh).toBe('pass');
  }, 60_000);

  test('moved lines only: still-present, matched by declaration not line', async () => {
    const r = await runCli(['recheck', trees.moved, '--changed', FILE, '--baseline', baselinePath]);
    expect(r.code).toBe(0);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    const v = rep.verdicts!.find(x => x.cwe === 'CWE-89')!;
    expect(v.verdict).toBe('still-present');
    expect(rep.summary!.gone).toBe(0);
  }, 60_000);

  test('a new command injection is new-high: the rule fails and the exit code is 1', async () => {
    const r = await runCli(['recheck', trees['new-high'], '--changed', FILE, '--baseline', baselinePath]);
    expect(r.code).toBe(1);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.verdicts!.find(v => v.cwe === 'CWE-78')!.verdict).toBe('new-high');
    expect(rep.verdicts!.find(v => v.cwe === 'CWE-89')!.verdict).toBe('gone');
    expect(rep.noNewHigh).toBe('fail');
  }, 60_000);

  test('the same files give the same report', async () => {
    const a = await runCli(['recheck', trees.before, '--changed', FILE]);
    const b = await runCli(['recheck', trees.before, '--changed', FILE]);
    expect(a.stdout).toBe(b.stdout);
  }, 60_000);

  test('a changed file deleted by the fix is skipped, its findings gone', async () => {
    const r = await runCli(['recheck', trees.fixed, '--changed', `${FILE},src/main/java/app/Removed.java`, '--baseline', baselinePath]);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.skipped).toEqual([{ file: 'src/main/java/app/Removed.java', reason: 'not present' }]);
  }, 60_000);

  test('usage errors exit 2', async () => {
    expect((await runCli(['recheck', trees.before])).code).toBe(2);
    expect((await runCli(['recheck', trees.before, '--changed', FILE, '--baseline', join(work, 'missing.json')])).code).toBe(2);
  }, 60_000);
});

describe('parseRecheckOptions / applyBaseline (pure)', () => {
  test('requires --changed and dedupes the list', () => {
    expect(() => parseRecheckOptions({})).toThrow(UsageError);
    expect(parseRecheckOptions({ changed: 'b.java, a.java,b.java' }).changed).toEqual(['a.java', 'b.java']);
  });

  test('verdicts by key, severity decides new-high vs new-other', () => {
    const f = (key: string, severity: string) => ({ key, cwe: key.split('|')[0], rule: 'r', severity, file: 'F.java', line: 1, decl: { scheme: 'ids@0.1', id: 'x', name: 'x' }, kind: 'flow' as const });
    const before: RecheckReport = { schema: RECHECK_SCHEMA, files: ['F.java'], skipped: [], findings: [f('CWE-89|F|m|sql', 'critical'), f('CWE-79|F|m|xss', 'high')] };
    const after: RecheckReport = { schema: RECHECK_SCHEMA, files: ['F.java'], skipped: [], findings: [f('CWE-79|F|m|xss', 'high'), f('CWE-22|F|m|path', 'high'), f('CWE-117|F|m|log', 'medium')] };
    const r = applyBaseline(after, before);
    const by = Object.fromEntries(r.verdicts!.map(v => [v.cwe, v.verdict]));
    expect(by).toEqual({ 'CWE-89': 'gone', 'CWE-79': 'still-present', 'CWE-22': 'new-high', 'CWE-117': 'new-other' });
    expect(r.summary).toEqual({ gone: 1, stillPresent: 1, newHigh: 1, newOther: 1 });
    expect(r.noNewHigh).toBe('fail');
  });
});
