/**
 * #1324 — a directory scan runs its per-file phase on `--threads` workers.
 * The output must not depend on the thread count, and a file whose analysis
 * fails or times out is reported as it is in the one-thread scan.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { AnalysisTimeoutError } from 'circle-ir';
import { ScanPool, scanPoolSize, decodeScanError } from '../src/scan-pool';

const CLI = join(import.meta.dir, '..', 'src', 'cli.ts');
let root: string;

async function scan(...args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  const proc = Bun.spawn([process.execPath, 'run', CLI, 'scan', ...args], {
    cwd: root, stdout: 'pipe', stderr: 'pipe', env: { ...process.env, NO_COLOR: '1' },
  });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { stdout, stderr, code: await proc.exited };
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'cog-threads-'));
  const app = join(root, 'app');
  mkdirSync(join(app, 'routes'), { recursive: true });
  mkdirSync(join(app, 'lib'), { recursive: true });
  writeFileSync(join(app, 'lib', 'db.js'), [
    `const { exec } = require('child_process');`,
    `function run(cmd) { exec('ls ' + cmd); }`,
    `function query(conn, id) { return conn.query('SELECT * FROM t WHERE id = ' + id); }`,
    `module.exports = { run, query };`,
  ].join('\n'));
  for (let i = 0; i < 8; i++) {
    writeFileSync(join(app, 'routes', `r${i}.js`), [
      `const express = require('express');`,
      `const { run, query } = require('../lib/db');`,
      `const router = express.Router();`,
      `router.get('/a${i}', (req, res) => { run(req.query.p); res.send(req.query.q); });`,
      `router.get('/b${i}', (req, res) => { query(req.app.db, req.params.id); eval(req.body.code); });`,
      `module.exports = router;`,
    ].join('\n'));
  }
  writeFileSync(join(app, 'Main.java'), [
    'import javax.servlet.http.*;',
    'public class Main extends HttpServlet {',
    '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {',
    '    Runtime.getRuntime().exec(req.getParameter("c"));',
    '  }',
    '}',
  ].join('\n'));
  // A servlet hands a response-backed PrintStream to a helper in another file.
  const stream = join(root, 'stream');
  mkdirSync(stream);
  writeFileSync(join(stream, 'S.java'), [
    'import javax.servlet.http.*;',
    'import java.io.*;',
    'public class S extends HttpServlet {',
    '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {',
    '    String p = req.getParameter("p");',
    '    new Report().write(new PrintStream(resp.getOutputStream()), p);',
    '  }',
    '}',
  ].join('\n'));
  writeFileSync(join(stream, 'Report.java'), [
    'import java.io.*;',
    'public class Report {',
    '  public void write(PrintStream ps, String v) {',
    '    ps.println(v);',
    '  }',
    '}',
  ].join('\n'));
  const slow = join(root, 'slow');
  mkdirSync(slow);
  writeFileSync(join(slow, 'big.sh'), Array.from({ length: 4000 }, (_, i) => `v${i}=$(echo "$x${i}" | grep foo)`).join('\n'));
  writeFileSync(join(slow, 'a.js'), `const x = 1;\nmodule.exports = x;\n`);
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('directory scan threads', () => {
  test('--threads 1 and --threads 3 give byte-identical SARIF and JSON', async () => {
    const [s1, s3] = await Promise.all([
      scan('app', '-f', 'sarif', '-q', '--threads', '1'),
      scan('app', '-f', 'sarif', '-q', '--threads', '3'),
    ]);
    expect(JSON.parse(s1.stdout).runs[0].results.length).toBeGreaterThan(5);
    expect(s3.stdout).toBe(s1.stdout);
    expect(s3.code).toBe(s1.code);

    const strip = (t: string): string => { const j = JSON.parse(t); delete j.timestamp; return JSON.stringify(j); };
    const [j1, j3] = await Promise.all([
      scan('app', '-f', 'json', '-q', '--threads', '1'),
      scan('app', '-f', 'json', '-q', '--threads', '3'),
    ]);
    expect(strip(j3.stdout)).toBe(strip(j1.stdout));
  }, 120_000);

  test("a helper's print to a response-backed PrintStream is xss at --threads 1 and 2", async () => {
    const xssIn = (t: string): string[] => JSON.parse(t).runs[0].results
      .filter((r: { ruleId: string }) => r.ruleId === 'xss')
      .map((r: { locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }> }) =>
        `${r.locations[0].physicalLocation.artifactLocation.uri.split('/').pop()}:${r.locations[0].physicalLocation.region.startLine}`);
    const [s1, s2] = await Promise.all([
      scan('stream', '-f', 'sarif', '-q', '--threads', '1'),
      scan('stream', '-f', 'sarif', '-q', '--threads', '2'),
    ]);
    expect(xssIn(s1.stdout)).toContain('Report.java:4');
    expect(xssIn(s2.stdout)).toContain('Report.java:4');
  }, 60_000);

  test('a timed-out file is still reported at --threads 3', async () => {
    const { stdout, stderr } = await scan('slow', '-f', 'sarif', '--threads', '3', '--file-timeout-ms', '1');
    const run0 = JSON.parse(stdout).runs[0];
    expect(run0.invocations[0].executionSuccessful).toBe(false);
    const timedOut = run0.invocations[0].toolExecutionNotifications
      .filter((n: { properties?: { reason?: string } }) => n.properties?.reason === 'file-timeout')
      .map((n: { locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }) =>
        n.locations[0].physicalLocation.artifactLocation.uri);
    expect(timedOut.some((u: string) => u.endsWith('big.sh'))).toBe(true);
    expect(stderr).toContain('not analysed');
  }, 60_000);
});

describe('scan pool', () => {
  const script = join(import.meta.dir, 'scan-pool-worker.ts');
  const inProcess = async (req: { name: string }) => ({ name: req.name, where: 'main' });

  test('size is --threads, capped by the CPUs and the file count', () => {
    expect(scanPoolSize(4, 100, 16)).toBe(4);
    expect(scanPoolSize(32, 100, 16)).toBe(16);
    expect(scanPoolSize(4, 2, 16)).toBe(2);
    expect(scanPoolSize(1, 100, 16)).toBe(1);
  });

  test('a file that throws rejects with the in-process error; the other files finish', async () => {
    const pool = new ScanPool({ size: 2, script, workerData: null, runInProcess: inProcess, decodeError: decodeScanError });
    const names = ['a', 'throws', 'b', 'times-out', 'c'];
    const settled = await Promise.allSettled(names.map((name) => pool.run({ name })));
    pool.close();
    expect(settled.map((s) => s.status)).toEqual(['fulfilled', 'rejected', 'fulfilled', 'rejected', 'fulfilled']);
    expect(settled.filter((s) => s.status === 'fulfilled').map((s) => (s as PromiseFulfilledResult<{ name: string; where: string }>).value))
      .toEqual([{ name: 'a', where: 'worker' }, { name: 'b', where: 'worker' }, { name: 'c', where: 'worker' }]);

    const thrown = (settled[1] as PromiseRejectedResult).reason as Error;
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown.message).toBe('Failed to parse code');

    // The timeout comes back as the class `analyzeProject` records in `timed_out_files`.
    const timeout = (settled[3] as PromiseRejectedResult).reason;
    expect(timeout).toBeInstanceOf(AnalysisTimeoutError);
    expect(timeout.message).toBe(new AnalysisTimeoutError('src/slow.sh', 7, 'parse').message);
    expect([timeout.file, timeout.elapsedMs, timeout.phase]).toEqual(['src/slow.sh', 7, 'parse']);
  }, 30_000);

  test('a worker that dies hands its file to the main thread, and the scan goes on', async () => {
    const pool = new ScanPool({ size: 2, script, workerData: null, runInProcess: inProcess, decodeError: decodeScanError });
    const out = await Promise.all(['a', 'crashes', 'b', 'c', 'd'].map((name) => pool.run({ name })));
    pool.close();
    expect(out.map((r) => r.name)).toEqual(['a', 'crashes', 'b', 'c', 'd']);
    expect(out[1].where).toBe('main');
  }, 30_000);

  test('a worker that cannot start leaves every file to the main thread', async () => {
    const pool = new ScanPool({ size: 2, script: join(import.meta.dir, 'no-such-worker.ts'), workerData: null, runInProcess: inProcess, decodeError: decodeScanError });
    const out = await Promise.all(['a', 'b', 'c'].map((name) => pool.run({ name })));
    pool.close();
    expect(out).toEqual([{ name: 'a', where: 'main' }, { name: 'b', where: 'main' }, { name: 'c', where: 'main' }]);
  }, 30_000);
});
