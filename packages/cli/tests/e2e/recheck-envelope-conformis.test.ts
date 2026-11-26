/**
 * L2 hermetic E2E: cognium-recheck@0.4 stdout must match the fields conformis
 * code-security/javascript RX-1/RX-2 read from engine facts (evaluate.ts rx1/rx2).
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
type RecheckReport = {
  schema: string;
  verdicts?: Array<{ key: string; verdict: string; cwe: string; rule: string; file: string; line: number; reason?: string }>;
  targets?: Array<{ key: string; verdict: string; reason?: string; fixed: boolean }>;
  fixed?: 'pass' | 'fail';
  noNewHigh?: 'pass' | 'fail';
  partialFiles?: Array<{ file: string }>;
  skipped?: Array<{ file: string; reason?: string }>;
  findings: Array<{ key: string; cwe: string; line: number }>;
  summary?: { newHigh: number; unknown?: number };
};

const RECHECK_SCHEMA = 'cognium-recheck@0.4';

const CLI = join(import.meta.dir, '..', '..', 'src', 'cli.ts');
const FILE = 'src/main/java/app/Lookup.java';
const RECHECK_SCHEMAS = new Set(['cognium-recheck@0.1', 'cognium-recheck@0.2', 'cognium-recheck@0.3', 'cognium-recheck@0.4']);
const VERDICTS = new Set(['gone', 'still-present', 'new-high', 'new-other', 'unknown', 'not-in-baseline']);

/** Mirrors conformis `recheckReport` + `rx1` (service/src/checks/evaluate.ts). */
function observeRx1(body: RecheckReport) {
  if (!RECHECK_SCHEMAS.has(body.schema)) throw new Error(`unexpected schema ${body.schema}`);
  if (!Array.isArray(body.verdicts)) throw new Error('missing verdicts');
  const targets = (Array.isArray(body.targets) ? body.targets : []).map(t => ({
    key: String(t?.key ?? ''),
    verdict: VERDICTS.has(t.verdict) ? t.verdict : 'unknown',
    ...(t.reason === undefined ? {} : { reason: String(t.reason) }),
    fixed: t.fixed === true,
    rekeyed: t.verdict === 'gone' && t.reason === 'declaration-removed',
  }));
  return {
    targets,
    fixed: body.fixed === 'pass' ? 'pass' : body.fixed === 'fail' ? 'fail' : null,
    open: targets.filter(t => !t.fixed).map(t => `${t.key} (${t.verdict}${t.reason ? `: ${t.reason}` : ''})`).join('; '),
    undecided: targets.filter(t => t.verdict === 'unknown' || t.verdict === 'not-in-baseline').map(t => t.key).join(', '),
    rekeyedKeys: targets.filter(t => t.rekeyed).map(t => t.key).join(', '),
  };
}

/** Mirrors conformis `rx2`. */
function observeRx2(body: RecheckReport) {
  const vs = body.verdicts ?? [];
  const newHigh = vs
    .filter(v => v?.verdict === 'new-high')
    .map(v => ({ key: String(v.key), cwe: String(v.cwe), rule: String(v.rule), file: String(v.file), line: Number(v.line) }));
  return {
    newHigh,
    newOther: vs.filter(v => v?.verdict === 'new-other').length,
    partialFiles: (Array.isArray(body.partialFiles) ? body.partialFiles : []).map(x => String((x as { file?: string }).file ?? x)),
    skipped: (Array.isArray(body.skipped) ? body.skipped : [])
      .filter(x => (x as { reason?: string }).reason !== 'not present')
      .map(x => String((x as { file?: string }).file ?? x)),
  };
}

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { stdout: 'pipe', stderr: 'pipe', env: { ...process.env, NO_COLOR: '1' } });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

const servlet = (body: string) => `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Lookup extends HttpServlet {
  private Connection conn;
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
const RENAMED = `    String userValue = id;
    Statement st = conn.createStatement();
    String query = "SELECT * FROM t WHERE id = '" + userValue + "'";
    st.executeQuery(query);`;

let work: string;
const trees: Record<string, string> = {};

function tree(name: string, code: string): string {
  const root = join(work, name);
  mkdirSync(join(root, 'src/main/java/app'), { recursive: true });
  writeFileSync(join(root, FILE), code);
  trees[name] = root;
  return root;
}

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), 'recheck-env-'));
  tree('before', servlet(VULN));
  tree('fixed', servlet(FIXED));
  tree('fake-rename', servlet(RENAMED));
  tree('new-high', servlet(NEW_CMD));
});
afterAll(() => rmSync(work, { recursive: true, force: true }));

describe('recheck envelope for conformis RX-1/RX-2 (TA-recheck-envelope-conformis)', () => {
  let baselinePath: string;
  let sqlKey: string;

  beforeAll(async () => {
    baselinePath = join(work, 'baseline.json');
    const r = await runCli(['recheck', trees.before, '--changed', FILE, '-o', baselinePath]);
    expect(r.code).toBe(0);
    const base = JSON.parse(readFileSync(baselinePath, 'utf8')) as RecheckReport;
    sqlKey = base.findings.find(f => f.cwe === 'CWE-89')!.key;
  }, 90_000);

  test('TA-recheck-envelope-conformis-1: baseline compare emits conformis-readable schema and verdicts', async () => {
    const { stdout } = await runCli(['recheck', trees.fixed, '--changed', FILE, '--baseline', baselinePath]);
    const rep = JSON.parse(stdout) as RecheckReport;
    expect(rep.schema).toBe(RECHECK_SCHEMA);
    expect(Array.isArray(rep.verdicts)).toBe(true);
    expect(() => observeRx1(rep)).not.toThrow();
    expect(() => observeRx2(rep)).not.toThrow();
  }, 90_000);

  test('TA-recheck-envelope-conformis-2: RX-1 pass on a real SQLi fix', async () => {
    const { stdout, code } = await runCli([
      'recheck', trees.fixed, '--changed', FILE, '--baseline', baselinePath, '--expect-gone', sqlKey,
    ]);
    expect(code).toBe(0);
    const rep = JSON.parse(stdout) as RecheckReport;
    const rx1 = observeRx1(rep);
    expect(rep.fixed).toBe('pass');
    expect(rx1.fixed).toBe('pass');
    expect(rx1.targets).toEqual([expect.objectContaining({ key: sqlKey, verdict: 'gone', fixed: true })]);
    expect(rx1.rekeyedKeys).toBe('');
  }, 90_000);

  test('TA-recheck-envelope-conformis-3: RX-1 fail lists open target on a fake rename fix', async () => {
    const { stdout, code } = await runCli([
      'recheck', trees['fake-rename'], '--changed', FILE, '--baseline', baselinePath, '--expect-gone', sqlKey,
    ]);
    expect(code).toBe(1);
    const rep = JSON.parse(stdout) as RecheckReport;
    const rx1 = observeRx1(rep);
    expect(rep.fixed).toBe('fail');
    expect(rx1.fixed).toBe('fail');
    expect(rx1.open).toContain(sqlKey);
    expect(rx1.open).toContain('still-present');
    expect(rx1.undecided).toBe('');
  }, 90_000);

  test('TA-recheck-envelope-conformis-4: RX-2 new-high count matches noNewHigh fail', async () => {
    const { stdout, code } = await runCli(['recheck', trees['new-high'], '--changed', FILE, '--baseline', baselinePath]);
    expect(code).toBe(1);
    const rep = JSON.parse(stdout) as RecheckReport;
    expect(rep.noNewHigh).toBe('fail');
    const rx2 = observeRx2(rep);
    expect(rx2.newHigh).toHaveLength(1);
    expect(rx2.newHigh[0].cwe).toBe('CWE-78');
    expect(rep.summary!.newHigh).toBe(rx2.newHigh.length);
  }, 90_000);

  test('TA-recheck-envelope-conformis-5: partial parse lists file and marks target undecided', async () => {
    const pyFile = 'app.py';
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
    const before = join(work, 'env-py-before');
    const broken = join(work, 'env-py-broken');
    mkdirSync(before, { recursive: true });
    mkdirSync(broken, { recursive: true });
    writeFileSync(join(before, pyFile), app(`    cur.execute("SELECT * FROM u WHERE n = '" + name + "'")`));
    writeFileSync(join(broken, pyFile), app(`    cur.execute("SELECT * FROM u WHERE n = ?", (name,)`));
    const pyBaseline = join(work, 'env-py-before.json');
    expect((await runCli(['recheck', before, '--changed', pyFile, '-o', pyBaseline])).code).toBe(0);
    const base = JSON.parse(readFileSync(pyBaseline, 'utf8')) as RecheckReport;
    const keys = base.findings.filter(f => f.cwe === 'CWE-89' || f.cwe === 'CWE-78').map(f => f.key);
    expect(keys.length).toBe(2);
    const { stdout, code } = await runCli([
      'recheck', broken, '--changed', pyFile, '--baseline', pyBaseline, '--expect-gone', keys.join(','),
    ]);
    expect(code).toBe(3);
    const rep = JSON.parse(stdout) as RecheckReport;
    const rx1 = observeRx1(rep);
    const rx2 = observeRx2(rep);
    expect(rx2.partialFiles).toEqual([pyFile]);
    expect(rx1.undecided.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(rx1.undecided).toContain(key);
    }
  }, 90_000);
});