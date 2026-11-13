/**
 * `recheck` (E20/engine): the deterministic re-check of a code-fix change.
 * A Java servlet before and after: a fixed SQL injection reads `gone`, a version
 * that only moves lines keeps it `still-present`, and a new command injection is
 * `new-high` and fails the no-new-high rule (exit 1). R1–R4: a fake fix fails
 * `--expect-gone`, a fix that does not parse is `unknown` (exit 3), findings and
 * verdicts carry evidence, and `--changed-from` scopes by change closure.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { applyBaseline, applyTargets, computeRecheck, parseRecheckOptions, recheckExitCode, RECHECK_SCHEMA, type RecheckEvidence, type RecheckFinding, type RecheckReport } from '../src/recheck';
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
    const before: RecheckReport = { schema: RECHECK_SCHEMA, scope: 'files', files: ['F.java'], skipped: [], partialFiles: [], findings: [f('CWE-89|F|m|sql', 'critical'), f('CWE-79|F|m|xss', 'high')] };
    const after: RecheckReport = { schema: RECHECK_SCHEMA, scope: 'files', files: ['F.java'], skipped: [], partialFiles: [], findings: [f('CWE-79|F|m|xss', 'high'), f('CWE-22|F|m|path', 'high'), f('CWE-117|F|m|log', 'medium')] };
    const r = applyBaseline(after, before);
    const by = Object.fromEntries(r.verdicts!.map(v => [v.cwe, v.verdict]));
    expect(by).toEqual({ 'CWE-89': 'gone', 'CWE-79': 'still-present', 'CWE-22': 'new-high', 'CWE-117': 'new-other' });
    expect(r.summary).toEqual({ gone: 1, stillPresent: 1, newHigh: 1, newOther: 1, unknown: 0 });
    expect(r.noNewHigh).toBe('fail');
  });
});

// ── R1–R4 (recheck-check §10): a fix verifier, not a key diff ────────────────

const sqlKeyOf = (rep: RecheckReport) => rep.findings.find(f => f.cwe === 'CWE-89')!.key;

describe('R1 --expect-gone: the targeted key must be gone', () => {
  let baselinePath: string;
  let target: string;
  const RENAMED = `    String userValue = id;
    Statement st = conn.createStatement();
    String query = "SELECT * FROM t WHERE id = '" + userValue + "'";
    st.executeQuery(query);`;
  const HTML_ENCODED = `    id = org.owasp.esapi.ESAPI.encoder().encodeForHTML(id);
${VULN}`;

  beforeAll(async () => {
    tree('fake-rename', servlet(RENAMED));
    tree('fake-html', servlet(HTML_ENCODED));
    baselinePath = join(work, 'r1-before.json');
    await runCli(['recheck', trees.before, '--changed', FILE, '-o', baselinePath]);
    target = sqlKeyOf(JSON.parse(readFileSync(baselinePath, 'utf8')));
  }, 60_000);

  test('a fake fix (rename) is still-present: fixed fails and the exit code is 1', async () => {
    const r = await runCli(['recheck', trees['fake-rename'], '--changed', FILE, '--baseline', baselinePath, '--expect-gone', target]);
    expect(r.code).toBe(1);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.noNewHigh).toBe('pass');
    expect(rep.fixed).toBe('fail');
    expect(rep.targets).toEqual([{ key: target, verdict: 'still-present', fixed: false }]);
  }, 60_000);

  test('an HTML encoder before a SQL sink does not count as fixed', async () => {
    const r = await runCli(['recheck', trees['fake-html'], '--changed', FILE, '--baseline', baselinePath, '--expect-gone', target]);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    const t = rep.targets![0];
    expect(t.fixed).toBe(false);
    expect(rep.fixed).toBe('fail');
    expect(r.code).toBe(1);
    // The engine drops the SQL flow after an HTML encoder; the verdict says why, and the fix check refuses it.
    expect(t).toEqual({ key: target, verdict: 'gone', reason: 'sanitized-by', fixed: false });
    const v = rep.verdicts!.find(x => x.key === target)!;
    expect(v.sanitizerCoversSink).toBe(false);
    expect(v.sanitizers!.some(s => s.method.includes('encodeForHTML'))).toBe(true);
  }, 60_000);

  test('a real fix passes the fix check with exit 0', async () => {
    const r = await runCli(['recheck', trees.fixed, '--changed', FILE, '--baseline', baselinePath, '--expect-gone', target]);
    expect(r.code).toBe(0);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.fixed).toBe('pass');
    expect(rep.targets![0]).toMatchObject({ key: target, verdict: 'gone', fixed: true });
  }, 60_000);

  test('a key the baseline does not hold fails; --expect-gone without a baseline is a usage error', async () => {
    const r = await runCli(['recheck', trees.fixed, '--changed', FILE, '--baseline', baselinePath, '--expect-gone', 'CWE-89|nope|x|sql_injection']);
    expect(r.code).toBe(1);
    expect((JSON.parse(r.stdout) as RecheckReport).targets![0]).toEqual({ key: 'CWE-89|nope|x|sql_injection', verdict: 'not-in-baseline', fixed: false });
    expect((await runCli(['recheck', trees.fixed, '--changed', FILE, '--expect-gone', target])).code).toBe(2);
  }, 60_000);
});

describe('R2 parse guard: never gone from a partially parsed file', () => {
  const PY = 'app.py';
  const app = (userBody: string) => `from flask import Flask, request
import sqlite3, subprocess
app = Flask(__name__)

@app.route('/user')
def user():
    name = request.args.get('name')
    cur = sqlite3.connect('x').cursor()
${userBody}
    return 'ok'

@app.route('/ping')
def ping():
    host = request.args.get('host')
    subprocess.call("ping " + host, shell=True)
    return 'ok'
`;
  let before: string;
  let broken: string;

  beforeAll(() => {
    before = join(work, 'py-before');
    broken = join(work, 'py-broken');
    mkdirSync(before, { recursive: true });
    mkdirSync(broken, { recursive: true });
    writeFileSync(join(before, PY), app(`    cur.execute("SELECT * FROM u WHERE n = '" + name + "'")`));
    // The fix leaves `execute(` unclosed: a SyntaxError.
    writeFileSync(join(broken, PY), app(`    cur.execute("SELECT * FROM u WHERE n = ?", (name,)`));
  });

  test('a syntax error in the fix: verdicts unknown (parse-error), file listed partial, exit 3', async () => {
    const baselinePath = join(work, 'py-before.json');
    expect((await runCli(['recheck', before, '--changed', PY, '-o', baselinePath])).code).toBe(0);
    const base = JSON.parse(readFileSync(baselinePath, 'utf8')) as RecheckReport;
    const targets = base.findings.filter(f => f.cwe === 'CWE-89' || f.cwe === 'CWE-78').map(f => f.key);
    expect(targets.length).toBe(2);

    const r = await runCli(['recheck', broken, '--changed', PY, '--baseline', baselinePath, '--expect-gone', targets.join(',')]);
    expect(r.code).toBe(3);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.partialFiles.map(p => p.file)).toEqual([PY]);
    for (const key of targets) {
      const v = rep.verdicts!.find(x => x.key === key)!;
      expect(v.verdict).toBe('unknown');
      expect(v.reason).toBe('parse-error');
    }
    expect(rep.summary!.gone).toBe(0);
    expect(rep.fixed).toBe('fail');
  }, 60_000);
});

describe('R3 evidence on every finding and verdict', () => {
  test('flow findings carry source, sink, hops, sanitizers and a line-free fingerprint', async () => {
    const a = JSON.parse((await runCli(['recheck', trees.before, '--changed', FILE])).stdout) as RecheckReport;
    const b = JSON.parse((await runCli(['recheck', trees.moved, '--changed', FILE])).stdout) as RecheckReport;
    const fa = a.findings.find(f => f.cwe === 'CWE-89')!;
    const fb = b.findings.find(f => f.cwe === 'CWE-89')!;
    expect(fa.evidence!.source).toMatchObject({ file: FILE, line: 7, type: 'http_param' });
    expect(fa.evidence!.sink).toMatchObject({ file: FILE, line: 9, type: 'sql_injection' });
    expect(fa.evidence!.hops.length).toBeGreaterThan(0);
    expect(fa.evidence!.sanitizers_in_path).toEqual([]);
    expect(fa.evidence!.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(fb.line).not.toBe(fa.line);
    expect(fb.evidence!.fingerprint).toBe(fa.evidence!.fingerprint);
  }, 60_000);

  test('every gone has a reason and the baseline evidence; every verdict carries evidence', async () => {
    const baselinePath = join(work, 'r3-before.json');
    await runCli(['recheck', trees.before, '--changed', FILE, '-o', baselinePath]);
    const rep = JSON.parse((await runCli(['recheck', trees['new-high'], '--changed', FILE, '--baseline', baselinePath])).stdout) as RecheckReport;
    for (const v of rep.verdicts!) expect(v.evidence).toBeDefined();
    const gone = rep.verdicts!.filter(v => v.verdict === 'gone');
    expect(gone.length).toBeGreaterThan(0);
    for (const v of gone) expect(v.reason).toBeDefined();
    const deleted = JSON.parse((await runCli(['recheck', trees.fixed, '--changed', `${FILE},src/main/java/app/Removed.java`, '--baseline', baselinePath])).stdout) as RecheckReport;
    expect(deleted.verdicts!.find(v => v.cwe === 'CWE-89')!.verdict).toBe('gone');
  }, 60_000);

  test('a baseline key whose file the after run did not analyse is unknown (not-analysed), exit 3', async () => {
    const other = 'src/main/java/app/Other.java';
    mkdirSync(join(trees.before, 'src/main/java/app'), { recursive: true });
    writeFileSync(join(trees.before, other), 'package app;\npublic class Other {}\n');
    const baselinePath = join(work, 'r3-x1.json');
    await runCli(['recheck', trees.before, '--changed', FILE, '-o', baselinePath]);
    const r = await runCli(['recheck', trees.before, '--changed', other, '--baseline', baselinePath]);
    expect(r.code).toBe(3);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.verdicts!.every(v => v.verdict === 'unknown' && v.reason === 'not-analysed')).toBe(true);
    rmSync(join(trees.before, other));
  }, 60_000);
});

describe('R4 --changed-from: scope by change closure', () => {
  let repo: string;
  const CALLER = 'src/main/java/app/Caller.java';
  const HELPER = 'src/main/java/app/Shell.java';
  const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  const caller = (body: string) => `package app;
import javax.servlet.http.*;
public class Caller extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String host = req.getParameter("host");
${body}
  }
}
`;

  beforeAll(() => {
    repo = join(work, 'repo');
    mkdirSync(join(repo, 'src/main/java/app'), { recursive: true });
    writeFileSync(join(repo, CALLER), caller('    res.getWriter().println("ok");'));
    writeFileSync(join(repo, HELPER), `package app;
public class Shell {
  public static void runCmd(String arg) throws Exception {
    Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping " + arg});
  }
}
`);
    git('init', '-q');
    git('-c', 'user.name=t', '-c', 'user.email=t@example.com', 'add', '-A');
    git('-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'base');
    // The change touches only the caller: it now passes the request value to the unchanged helper.
    writeFileSync(join(repo, CALLER), caller('    Shell.runCmd(host);'));
    writeFileSync(join(repo, 'src/main/java/app/Extra.java'), 'package app;\npublic class Extra {}\n');
  });

  test('the changed list comes from git, untracked files included', async () => {
    const { changedFromGit } = await import('../src/recheck');
    expect(changedFromGit(repo, 'HEAD')).toEqual([CALLER, 'src/main/java/app/Extra.java']);
  }, 60_000);

  test('a new command injection in an unchanged helper, reached from the changed caller, is new-high', async () => {
    const r = await runCli(['recheck', repo, '--changed-from', 'HEAD']);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.scope).toBe('closure');
    expect(rep.changedFrom).toBe('HEAD');
    const v = rep.verdicts!.find(x => x.cwe === 'CWE-78' && x.verdict === 'new-high');
    expect(v).toBeDefined();
    expect(v!.evidence!.source!.file).toBe(CALLER);
    expect(r.code).toBe(1);
  }, 60_000);

  test('a bad ref is a usage error; --changed and --changed-from together are a usage error', async () => {
    expect((await runCli(['recheck', repo, '--changed-from', 'no-such-ref'])).code).toBe(2);
    expect(() => parseRecheckOptions({ changed: 'a.java', 'changed-from': 'HEAD' })).toThrow(UsageError);
    expect(parseRecheckOptions({ 'changed-from': 'HEAD' }).scope).toBe('closure');
    expect(() => parseRecheckOptions({ 'changed-from': '--output=x' })).toThrow(UsageError);
  }, 60_000);
});

describe('applyTargets / recheckExitCode (pure)', () => {
  const v = (key: string, verdict: NonNullable<RecheckReport['verdicts']>[number]['verdict'], extra = {}) =>
    ({ key, verdict, cwe: 'CWE-89', rule: 'sql_injection', severity: 'critical', file: 'F', line: 1, ...extra });
  const rep = (verdicts: NonNullable<RecheckReport['verdicts']>): RecheckReport => ({
    schema: RECHECK_SCHEMA, scope: 'files', files: ['F'], skipped: [], partialFiles: [], findings: [], verdicts,
    summary: { gone: 0, stillPresent: 0, newHigh: 0, newOther: 0, unknown: verdicts.filter(x => x.verdict === 'unknown').length },
    noNewHigh: 'pass',
  });

  test('gone passes; still-present, unknown and a non-covering sanitizer fail', () => {
    expect(applyTargets(rep([v('a', 'gone', { reason: 'sink-removed' })]), ['a']).fixed).toBe('pass');
    expect(applyTargets(rep([v('a', 'still-present')]), ['a']).fixed).toBe('fail');
    expect(applyTargets(rep([v('a', 'unknown', { reason: 'parse-error' })]), ['a']).fixed).toBe('fail');
    expect(applyTargets(rep([v('a', 'gone', { reason: 'sanitized-by', sanitizerCoversSink: false })]), ['a']).fixed).toBe('fail');
    expect(applyTargets(rep([v('a', 'gone', { reason: 'sanitized-by', sanitizerCoversSink: true })]), ['a']).fixed).toBe('pass');
  });

  test('exit 3 on unknown before 1 on a failed check', () => {
    expect(recheckExitCode(rep([v('a', 'gone')]))).toBe(0);
    expect(recheckExitCode(applyTargets(rep([v('a', 'still-present')]), ['a']))).toBe(1);
    expect(recheckExitCode(applyTargets(rep([v('a', 'unknown')]), ['a']))).toBe(3);
  });
});

describe('recheck on a TypeScript CWE-532 fix (sensitive-data-in-log)', () => {
  const TS_FILE = 'src/worker.ts';
  const FIXTURES = join(import.meta.dir, '..', '..', 'circle-ir', 'tests', 'fixtures', 'sensitive-data-in-log');
  let baselinePath: string;
  let keys: string[];

  function tsTree(name: string, fixture: string): string {
    const root = join(work, name);
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, TS_FILE), readFileSync(join(FIXTURES, fixture), 'utf8'));
    return root;
  }

  beforeAll(async () => {
    tsTree('ts-before', 'vulnerable.ts');
    tsTree('ts-fixed', 'fixed.ts');
    baselinePath = join(work, 'ts-before.json');
    await runCli(['recheck', join(work, 'ts-before'), '--changed', TS_FILE, '-o', baselinePath]);
    const rep = JSON.parse(readFileSync(baselinePath, 'utf8')) as RecheckReport;
    keys = rep.findings.filter(f => f.cwe === 'CWE-532').map(f => f.key);
  }, 60_000);

  test('before: findings keyed CWE-532 × declaration × rule', () => {
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k.startsWith(`CWE-532|${TS_FILE}|`)).toBe(true);
      expect(k.endsWith('|sensitive-data-in-log')).toBe(true);
    }
  });

  test('fixed: every CWE-532 key is gone, --expect-gone passes', async () => {
    const r = await runCli(['recheck', join(work, 'ts-fixed'), '--changed', TS_FILE, '--baseline', baselinePath, '--expect-gone', keys.join(',')]);
    expect(r.code).toBe(0);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.fixed).toBe('pass');
    expect(rep.verdicts!.filter(v => v.cwe === 'CWE-532').every(v => v.verdict === 'gone')).toBe(true);
    expect(rep.findings.filter(f => f.cwe === 'CWE-532')).toEqual([]);
  }, 60_000);

  test('unchanged: the keys are still-present and --expect-gone fails', async () => {
    const r = await runCli(['recheck', join(work, 'ts-before'), '--changed', TS_FILE, '--baseline', baselinePath, '--expect-gone', keys[0]]);
    expect(r.code).toBe(1);
    expect((JSON.parse(r.stdout) as RecheckReport).targets![0]).toMatchObject({ key: keys[0], verdict: 'still-present', fixed: false });
  }, 60_000);
});

describe('recheck on a TypeScript CWE-862 fix (missing-auth-middleware)', () => {
  const TS_FILE = 'src/notes.ts';
  const FIXTURES = join(import.meta.dir, '..', '..', 'circle-ir', 'tests', 'fixtures', 'missing-auth-middleware');
  let baselinePath: string;
  let keys: string[];

  function tsTree(name: string, fixture: string): string {
    const root = join(work, name);
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, TS_FILE), readFileSync(join(FIXTURES, fixture), 'utf8'));
    return root;
  }

  beforeAll(async () => {
    tsTree('authz-before', 'vulnerable.ts');
    tsTree('authz-fixed', 'fixed.ts');
    baselinePath = join(work, 'authz-before.json');
    await runCli(['recheck', join(work, 'authz-before'), '--changed', TS_FILE, '-o', baselinePath]);
    const rep = JSON.parse(readFileSync(baselinePath, 'utf8')) as RecheckReport;
    keys = rep.findings.filter(f => f.rule === 'missing-auth-middleware').map(f => f.key);
  }, 60_000);

  test('before: keyed CWE-862 × declaration × rule', () => {
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k.startsWith(`CWE-862|${TS_FILE}|`)).toBe(true);
      expect(k.endsWith('|missing-auth-middleware')).toBe(true);
    }
  });

  test('fixed: every key is gone, --expect-gone passes', async () => {
    const r = await runCli(['recheck', join(work, 'authz-fixed'), '--changed', TS_FILE, '--baseline', baselinePath, '--expect-gone', keys.join(',')]);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.verdicts!.filter(v => v.rule === 'missing-auth-middleware').every(v => v.verdict === 'gone')).toBe(true);
    expect(rep.findings.filter(f => f.rule === 'missing-auth-middleware')).toEqual([]);
    expect(rep.targets!.every(t => t.verdict === 'gone' && t.fixed)).toBe(true);
  }, 60_000);

  test('unchanged: the keys are still-present and --expect-gone fails', async () => {
    const r = await runCli(['recheck', join(work, 'authz-before'), '--changed', TS_FILE, '--baseline', baselinePath, '--expect-gone', keys.join(',')]);
    expect(r.code).toBe(1);
    const rep = JSON.parse(r.stdout) as RecheckReport;
    expect(rep.targets!.every(t => t.verdict === 'still-present' && t.fixed === false)).toBe(true);
  }, 60_000);
});

/**
 * G1: a flow in an inline route handler is keyed by the handler's positional
 * stable id, so an inserted statement re-keys it. A no-op must not read `gone`:
 * the moved key is `still-present` (`rekeyed`, matched by flow identity) or, when
 * more than one finding could be it, `unknown`; the after key is not also new.
 */
describe('recheck G1: a re-keyed declaration is still-present, never gone (JS and TS)', () => {
  const FIX = join(import.meta.dir, 'fixtures', 'recheck-rekey');
  const CLASSES: Array<{ id: string; cwe: string }> = [
    { id: '89', cwe: 'CWE-89' }, { id: '79', cwe: 'CWE-79' }, { id: '22', cwe: 'CWE-22' },
    { id: '78', cwe: 'CWE-78' }, { id: '918', cwe: 'CWE-918' },
  ];
  /** n2: one statement after line 1; n3: one statement as the first line of the handler. */
  const top = (code: string) => code.replace(/\n/, '\nconst reviewedAt = 1;\n');
  const inner = (code: string) => code.replace(/(function \w+\([^)]*\) \{\n)/, '$1  const reviewedAt = 1;\n');

  async function run(name: string, file: string, code: string, baseline?: RecheckReport, expectGone: string[] = []): Promise<RecheckReport> {
    const root = join(work, 'g1', name);
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, file), code);
    let baselinePath: string | undefined;
    if (baseline) {
      baselinePath = join(work, 'g1', `${name}.baseline.json`);
      writeFileSync(baselinePath, JSON.stringify(baseline));
    }
    return computeRecheck(root, { changed: [file], scope: 'files', expectGone, ...(baselinePath ? { baseline: baselinePath } : {}) });
  }

  for (const lang of ['js', 'ts'] as const) {
    for (const c of CLASSES) {
      const file = `src/app.${lang}`;
      const vuln = readFileSync(join(FIX, `${c.id}.vuln.${lang}`), 'utf8');
      const fixed = readFileSync(join(FIX, `${c.id}.fixed.${lang}`), 'utf8');

      test(`${c.cwe} ${lang}: no-ops keep the key (still-present or unknown), a fix is gone with a reason`, async () => {
        const base = await run(`${c.id}-${lang}-base`, file, vuln);
        const target = base.findings.find(f => f.cwe === c.cwe);
        expect(target).toBeDefined();
        const flowKeys = base.findings.filter(f => f.kind === 'flow').map(f => f.key);

        for (const [variant, code] of [['top', top(vuln)], ['inner', inner(vuln)]] as const) {
          expect(code).not.toBe(vuln);
          const rep = await run(`${c.id}-${lang}-${variant}`, file, code, base, [target!.key]);
          for (const key of flowKeys) {
            const v = rep.verdicts!.find(x => x.key === key)!;
            expect(['still-present', 'unknown'], `${variant} ${key}`).toContain(v.verdict);
            if (v.reason === 'rekeyed') {
              expect(v.matchedBy).toBe('flow-identity');
              expect(rep.findings.map(f => f.key)).toContain(v.rekeyedTo!);
            }
          }
          expect(rep.summary!.gone, variant).toBe(0);
          expect(rep.summary!.newHigh + rep.summary!.newOther, variant).toBe(0);
          expect(rep.fixed, variant).toBe('fail'); // re-keyed and still there: not fixed
        }

        const fx = await run(`${c.id}-${lang}-fixed`, file, fixed, base);
        const v = fx.verdicts!.find(x => x.key === target!.key)!;
        expect(v.verdict).toBe('gone');
        expect(v.reason).not.toBe('declaration-removed');
      }, 60_000);
    }
  }

  const twoHandlers = (handler: (route: string) => string) =>
    `const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\n${handler('/a')}${handler('/b')}`;

  test('two anonymous handlers that differ only by route: an inserted import re-keys both, both still-present', async () => {
    // The source is the handler line, so the route keeps the two flows apart; the
    // first handler takes the second's old positional id, which must not count.
    const file = 'src/app.js';
    const code = twoHandlers(route => `app.get('${route}', (req, res) => {\n  exec('ping -c 1 ' + req.query.host, (err, out) => res.end());\n});\n`);
    const base = await run('routes-base', file, code);
    const keys = base.findings.filter(f => f.cwe === 'CWE-78').map(f => f.key);
    expect(keys.length).toBe(2);
    const rep = await run('routes-top', file, top(code), base, keys);
    for (const key of keys) {
      expect(rep.verdicts!.find(x => x.key === key)).toMatchObject({ verdict: 'still-present', reason: 'rekeyed' });
    }
    expect(rep.summary).toMatchObject({ gone: 0, newHigh: 0, newOther: 0, unknown: 0 });

    // Fix the second handler and insert the import: the first keeps its flow, the
    // second's key reads gone, though the first now holds that key's old id.
    const fixedB = top(code).replace(/(app\.get\('\/b'[^]*?)exec\('ping -c 1 ' \+ req\.query\.host/, "$1exec('ping -c 1 localhost'");
    const fx = await run('routes-fix-b', file, fixedB, base);
    const [ka, kb] = [...keys].sort((x, y) => base.findings.find(f => f.key === x)!.line - base.findings.find(f => f.key === y)!.line);
    expect(fx.verdicts!.find(x => x.key === ka)).toMatchObject({ verdict: 'still-present' });
    expect(fx.verdicts!.find(x => x.key === kb)!.verdict).toBe('gone');
    expect(fx.summary).toMatchObject({ newHigh: 0, unknown: 0 });
  }, 60_000);

  test('two identical vulnerable handlers, one statement inserted above both: unknown, never gone', async () => {
    const file = 'src/app.js';
    const code = twoHandlers(route => `app.get('${route}', (req, res) => {\n  const host = req.query.host;\n  exec('ping -c 1 ' + host, (err, out) => res.end());\n});\n`);
    const base = await run('dup-base', file, code);
    const keys = base.findings.filter(f => f.cwe === 'CWE-78').map(f => f.key);
    expect(keys.length).toBe(2);
    const rep = await run('dup-top', file, top(code), base, keys);
    for (const key of keys) {
      const v = rep.verdicts!.find(x => x.key === key)!;
      expect(v.verdict).toBe('unknown');
      expect(v.reason).toBe('rekey-ambiguous');
      expect(v.rekeyCandidates!.length).toBe(2);
    }
    expect(rep.summary!.gone).toBe(0);
    expect(rep.summary!.newHigh).toBe(0);
    expect(rep.fixed).toBe('fail');
    expect(recheckExitCode(rep)).toBe(3);
  }, 60_000);

  test('a fix that adds an import and parameterizes the query is gone with a real reason', async () => {
    for (const lang of ['js', 'ts'] as const) {
      const file = `src/app.${lang}`;
      const imp = lang === 'js' ? "const helmet = require('helmet');" : "import helmet from 'helmet';";
      const vuln = readFileSync(join(FIX, `89.vuln.${lang}`), 'utf8');
      const fixed = readFileSync(join(FIX, `89.fixed.${lang}`), 'utf8').replace(/\n/, `\n${imp}\n`);
      const base = await run(`import-fix-${lang}-base`, file, vuln);
      const key = base.findings.find(f => f.cwe === 'CWE-89')!.key;
      const rep = await run(`import-fix-${lang}`, file, fixed, base, [key]);
      const v = rep.verdicts!.find(x => x.key === key)!;
      expect(v.verdict).toBe('gone');
      expect(v.reason).toBe('sanitized-by');
      expect(v.sanitizerCoversSink).toBe(true);
      expect(v.successorDecl).toBeDefined();
      expect(rep.fixed).toBe('pass');
    }
  }, 60_000);

  test('a 0.2 baseline is still read, and its flow findings still match by identity', async () => {
    const file = 'src/app.js';
    const vuln = readFileSync(join(FIX, '89.vuln.js'), 'utf8');
    const base = await run('v02-base', file, vuln);
    const rep = await run('v02-top', file, top(vuln), { ...base, schema: 'cognium-recheck@0.2' as typeof RECHECK_SCHEMA });
    expect(rep.schema).toBe('cognium-recheck@0.3');
    expect(rep.summary!.gone).toBe(0);
  }, 60_000);
});

describe('applyBaseline flow identity (pure)', () => {
  const finding = (key: string, sinkCode: string, extra: Partial<RecheckEvidence> = {}): RecheckFinding => ({
    key, cwe: 'CWE-89', rule: 'sql_injection', severity: 'critical', file: 'a.js', line: 1,
    decl: { scheme: 'ids@0.1', id: key, name: key }, kind: 'flow',
    evidence: {
      fingerprint: key, source: { file: 'a.js', line: 1, type: 'http_param', code: 'const id = req.query.id;' },
      sink: { file: 'a.js', line: 2, type: 'sql_injection', code: sinkCode }, hops: [], sanitizers_in_path: [], ...extra,
    },
  });
  const report = (findings: RecheckFinding[]): RecheckReport => ({ schema: RECHECK_SCHEMA, scope: 'files', files: ['a.js'], skipped: [], partialFiles: [], findings });
  const SINK = "db.query('SELECT * FROM t WHERE id = ' + id);";

  test('one moved key, whitespace changed: still-present, rekeyedTo, not new', () => {
    const r = applyBaseline(report([finding('K2', SINK.replace(' + ', '+'))]), report([finding('K1', SINK)]));
    expect(r.verdicts).toEqual([expect.objectContaining({ key: 'K1', verdict: 'still-present', reason: 'rekeyed', rekeyedTo: 'K2', matchedBy: 'flow-identity' })]);
    expect(r.summary).toEqual({ gone: 0, stillPresent: 1, newHigh: 0, newOther: 0, unknown: 0 });
  });

  test('a changed sink, source or sanitizer set does not match: gone plus new-high', () => {
    for (const after of [
      finding('K2', "db.query('SELECT * FROM t WHERE id = ?', [id]);"),
      finding('K2', SINK, { source: { file: 'a.js', line: 1, type: 'http_param', code: 'const id = Number(req.query.id);' } }),
      finding('K2', SINK, { sanitizers_in_path: ['escape'] }),
    ]) {
      const r = applyBaseline(report([after]), report([finding('K1', SINK)]));
      expect(r.verdicts!.map(v => [v.key, v.verdict])).toEqual([['K1', 'gone'], ['K2', 'new-high']]);
    }
  });

  test('one lost key, two candidates: unknown, and both candidates stay new (one of them is)', () => {
    const r = applyBaseline(report([finding('K2', SINK), finding('K3', SINK)]), report([finding('K1', SINK)]));
    expect(r.verdicts!.find(v => v.key === 'K1')).toMatchObject({ verdict: 'unknown', reason: 'rekey-ambiguous', rekeyCandidates: ['K2', 'K3'] });
    expect(r.summary).toMatchObject({ gone: 0, unknown: 1, newHigh: 2 });
  });

  test('two lost keys, one candidate: both unknown, the candidate not new', () => {
    const r = applyBaseline(report([finding('K3', SINK)]), report([finding('K1', SINK), finding('K2', SINK)]));
    expect(r.summary).toEqual({ gone: 0, stillPresent: 0, newHigh: 0, newOther: 0, unknown: 2 });
  });

  test('a key that now holds a different flow is not still-present by key: the flows are matched by identity', () => {
    const src = (code: string) => ({ source: { file: 'a.js', line: 1, type: 'http_param', code } });
    const before = report([finding('K1', SINK, src("app.get('/a', (req, res) => {")), finding('K2', SINK, src("app.get('/b', (req, res) => {"))]);
    const after = report([finding('K2', SINK, src("app.get('/a', (req, res) => {")), finding('K3', SINK, src("app.get('/b', (req, res) => {"))]);
    const r = applyBaseline(after, before);
    expect(r.verdicts!.map(v => [v.key, v.verdict, v.rekeyedTo])).toEqual([['K1', 'still-present', 'K2'], ['K2', 'still-present', 'K3']]);
    expect(r.summary).toEqual({ gone: 0, stillPresent: 2, newHigh: 0, newOther: 0, unknown: 0 });
  });

  test('same key, changed sink (a fix that is still reported): still-present by key, as before', () => {
    const r = applyBaseline(report([finding('K1', "db.query(sanitize(id));")]), report([finding('K1', SINK)]));
    expect(r.verdicts).toEqual([expect.objectContaining({ key: 'K1', verdict: 'still-present' })]);
    expect(r.verdicts![0].rekeyedTo).toBeUndefined();
  });

  test('a finding without sink code (a 0.1 baseline) is never matched by identity', () => {
    const old = finding('K1', SINK);
    delete old.evidence!.sink.code;
    const r = applyBaseline(report([finding('K2', SINK)]), report([old]));
    expect(r.verdicts!.map(v => [v.key, v.verdict])).toEqual([['K1', 'gone'], ['K2', 'new-high']]);
  });
});
