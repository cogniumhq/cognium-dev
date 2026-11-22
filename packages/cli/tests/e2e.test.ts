import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { resolve, join } from 'path';
import { writeFileSync, unlinkSync, existsSync, mkdtempSync, mkdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';

// ─── Helpers ────────────────────────────────────────────────────────────────

const CLI = resolve(import.meta.dir, '../src/cli.ts');
const FIXTURES = resolve(import.meta.dir, 'fixtures');
const VULN_FILE = join(FIXTURES, 'VulnController.java');
const CLEAN_FILE = join(FIXTURES, 'CleanService.java');
const TS_FILE = join(FIXTURES, 'simple.ts');

interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function run(...args: string[]): Promise<RunResult> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env, NO_COLOR: '1' },
    cwd: FIXTURES,
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  return { stdout, stderr, exitCode };
}

// ─── Scan: text output ──────────────────────────────────────────────────────

describe('scan (text)', () => {
  test('detects SQL injection in vulnerable Java file', async () => {
    const { stdout, exitCode } = await run('scan', VULN_FILE, '-q');
    expect(stdout).toContain('sql_injection');
    expect(exitCode).toBe(1);
  }, 30_000);

  test('clean file produces exit code 0', async () => {
    const { exitCode } = await run('scan', CLEAN_FILE, '-q');
    expect(exitCode).toBe(0);
  }, 30_000);

  test('shows CWE identifier for findings', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-q');
    expect(stdout).toContain('CWE-89');
  }, 30_000);

  test('shows fix suggestion for SQL injection', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-q');
    expect(stdout).toContain('Fix:');
  }, 30_000);
});

// ─── Scan: JSON output ──────────────────────────────────────────────────────

describe('scan (json)', () => {
  test('produces valid JSON with vulnerabilities', async () => {
    const { stdout, exitCode } = await run('scan', VULN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.version).toBeDefined();
    expect(parsed.results).toBeArray();
    expect(parsed.results.length).toBeGreaterThan(0);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    expect(vulns.length).toBeGreaterThan(0);
    expect(vulns.some((v: any) => v.type === 'sql_injection')).toBe(true);
    expect(exitCode).toBe(1);
  }, 30_000);

  test('clean file JSON has zero vulnerabilities', async () => {
    const { stdout, exitCode } = await run('scan', CLEAN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    expect(vulns.length).toBe(0);
    expect(exitCode).toBe(0);
  }, 30_000);

  test('JSON includes summary counts', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.summary).toBeDefined();
    expect(parsed.summary.filesScanned).toBe(1);
    expect(parsed.summary.totalVulnerabilities).toBeGreaterThan(0);
  }, 30_000);
});

// ─── Scan: SARIF output ─────────────────────────────────────────────────────

describe('scan (sarif)', () => {
  test('produces valid SARIF 2.1.0', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'sarif', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  }, 30_000);

  test('SARIF results include ruleId and level', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'sarif', '-q');
    const parsed = JSON.parse(stdout);
    const result = parsed.runs[0].results[0];
    expect(result.ruleId).toBeDefined();
    expect(result.level).toBeDefined();
  }, 30_000);
});

// ─── Files not fully analysed are reported, never shown as clean ────────────

describe('files not fully analysed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cognium-partial-'));
  const syntaxError = join(dir, 'A.java');
  // Line 3 lacks its semicolon.
  writeFileSync(syntaxError, 'class A {\n  void a() {\n    int y = 2\n    System.out.println(y);\n  }\n}\n');
  const slowDir = join(dir, 'slow');
  // Large enough that parsing alone passes a 1 ms per-file limit.
  mkdirSync(slowDir);
  writeFileSync(join(slowDir, 'big.sh'), Array.from({ length: 4000 }, (_, i) => `v${i}=$(echo "$x${i}" | grep foo)`).join('\n'));

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  test('a syntax error is counted in JSON (errors: 0 alone no longer hides it)', async () => {
    const { stdout, stderr } = await run('scan', syntaxError, '-f', 'json');
    const parsed = JSON.parse(stdout);
    expect(parsed.summary.filesWithParseErrors).toBe(1);
    expect(parsed.results[0].parse_errors.lines).toContain(3);
    expect(stderr).toContain('1 with syntax errors');
  }, 30_000);

  test('a syntax error is marked in text output and counted in the summary', async () => {
    const { stdout } = await run('scan', syntaxError);
    expect(stdout).toContain('[PARTIAL]');
    expect(stdout).toContain('1 file(s) had syntax errors; findings in them may be incomplete');
  }, 30_000);

  test('a syntax error is a SARIF warning at its line', async () => {
    const { stdout } = await run('scan', syntaxError, '-f', 'sarif', '-q');
    const inv = JSON.parse(stdout).runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(true);
    expect(inv.toolExecutionNotifications[0].properties.reason).toBe('parse-error');
    expect(inv.toolExecutionNotifications[0].locations[0].physicalLocation.region.startLine).toBe(3);
  }, 30_000);

  test('a directory scan reports a timed-out file in SARIF and marks the run unsuccessful', async () => {
    const { stdout, stderr } = await run('scan', slowDir, '-f', 'sarif', '--file-timeout-ms', '1');
    const run0 = JSON.parse(stdout).runs[0];
    expect(run0.results).toHaveLength(0);
    expect(run0.invocations[0].executionSuccessful).toBe(false);
    const n = run0.invocations[0].toolExecutionNotifications[0];
    expect(n.level).toBe('error');
    expect(n.properties.reason).toBe('file-timeout');
    expect(n.locations[0].physicalLocation.artifactLocation.uri).toEndWith('big.sh');
    expect(stderr).toContain('1 not analysed');
  }, 30_000);

  test('a single-file scan reports a timed-out file as a timeout', async () => {
    const { stdout } = await run('scan', join(slowDir, 'big.sh'), '-f', 'sarif', '-q', '--file-timeout-ms', '1');
    const n = JSON.parse(stdout).runs[0].invocations[0].toolExecutionNotifications[0];
    expect(n.properties.reason).toBe('file-timeout');
  }, 30_000);
});

// ─── The entry-path gate's drops are counted, with the flag that keeps them ─

describe('require-entry-path drops are reported', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cognium-gate-'));
  const servlet = (name: string, method: string, base: string) =>
    `import javax.servlet.http.*;\npublic class ${name}${base} {\n  public void ${method}(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n    Runtime.getRuntime().exec(req.getParameter("c"));\n  }\n}\n`;
  writeFileSync(join(dir, 'Entry.java'), servlet('Entry', 'doGet', ' extends HttpServlet'));
  // Nothing calls Helper.util, so the gate drops its command injection.
  writeFileSync(join(dir, 'Helper.java'), servlet('Helper', 'util', ''));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  test('SARIF carries a note with the count and the flag; JSON counts it', async () => {
    const sarif = JSON.parse((await run('scan', dir, '-f', 'sarif', '-q')).stdout);
    const notes = sarif.runs[0].invocations[0].toolExecutionNotifications
      .filter((n: { properties: { reason: string } }) => n.properties.reason === 'entry-path-gate');
    expect(notes).toHaveLength(1);
    expect(notes[0].level).toBe('note');
    expect(notes[0].message.text).toContain('--disable-pass require-entry-path');
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(true);
  }, 60_000);

  test('the flag in the note brings the finding back and the count to 0', async () => {
    const gated = JSON.parse((await run('scan', dir, '-f', 'json', '-q', '--category', 'security')).stdout);
    const ungated = JSON.parse((await run('scan', dir, '-f', 'json', '-q', '--category', 'security', '--disable-pass', 'require-entry-path')).stdout);
    const helperVulns = (j: { results: Array<{ file: string; vulnerabilities: unknown[] }> }) =>
      j.results.find(r => r.file.endsWith('Helper.java'))?.vulnerabilities.length ?? 0;
    expect(gated.summary.entryPathDropped).toBeGreaterThanOrEqual(1);
    expect(helperVulns(gated)).toBe(0);
    expect(ungated.summary.entryPathDropped).toBe(0);
    expect(helperVulns(ungated)).toBeGreaterThanOrEqual(1);
  }, 60_000);
});

// ─── An empty scan still writes a valid report ──────────────────────────────

describe('empty directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cognium-empty-'));
  const outFile = join(dir, 'out.sarif');
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  test('-f sarif -o writes a valid empty SARIF run and exits 0', async () => {
    const { exitCode, stderr } = await run('scan', dir, '-f', 'sarif', '-o', outFile);
    expect(exitCode).toBe(0);
    expect(stderr).toContain('No supported files found');
    expect(existsSync(outFile)).toBe(true);
    const doc = JSON.parse(await Bun.file(outFile).text());
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0].results).toEqual([]);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications[0].properties.reason).toBe('no-files');
  }, 30_000);

  test('-f json writes an empty report to stdout', async () => {
    const { stdout, exitCode } = await run('scan', dir, '-f', 'json', '-q');
    expect(exitCode).toBe(0);
    expect(JSON.parse(stdout).summary.filesScanned).toBe(0);
  }, 30_000);
});

// ─── Scan: exit codes ───────────────────────────────────────────────────────

describe('exit codes', () => {
  test('exit 1 for security findings', async () => {
    const { exitCode } = await run('scan', VULN_FILE, '-q');
    expect(exitCode).toBe(1);
  }, 30_000);

  test('exit 0 for clean scan', async () => {
    const { exitCode } = await run('scan', CLEAN_FILE, '-q');
    expect(exitCode).toBe(0);
  }, 30_000);

  test('exit 2 for nonexistent path', async () => {
    const { exitCode } = await run('scan', '/nonexistent/path/file.java', '-q');
    expect(exitCode).toBe(2);
  }, 30_000);

  // 1 means findings. A usage or config error used to exit 1 as well, so a CI
  // gate could not tell a typo from a vulnerable codebase.
  test('a usage error exits 2, not the findings code', async () => {
    for (const args of [
      ['scan', VULN_FILE, '-f', 'xml'],
      ['scan', VULN_FILE, '--severity', 'urgent'],
      ['scan', VULN_FILE, '--threads', '0'],
      ['scan'],
      ['frobnicate'],
      ['scan', VULN_FILE, '--frobnicate'],
    ]) {
      const { exitCode, stderr } = await run(...args);
      expect(exitCode).toBe(2);
      expect(stderr).toContain('Error');
    }
  }, 60_000);

  // An unknown option used to be ignored: `--severty high` ran a full scan at
  // the default severity and exited by its findings.
  test('an unknown option is refused before any scan work', async () => {
    const { exitCode, stdout, stderr } = await run('scan', VULN_FILE, '-f', 'json', '--severty', 'high');
    expect(exitCode).toBe(2);
    expect(stdout).toBe('');
    expect(stderr).toContain("unknown option '--severty' for 'scan'");
  }, 30_000);

  test('a config error exits 2', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cognium-config-'));
    try {
      const badJson = join(dir, 'bad.json');
      writeFileSync(badJson, '{ not json');
      const badSeverity = join(dir, 'severity.json');
      writeFileSync(badSeverity, JSON.stringify({ severity: 'urgent' }));
      expect((await run('scan', VULN_FILE, '-q', '--profile', badJson)).exitCode).toBe(2);
      expect((await run('scan', VULN_FILE, '-q', '--profile', badSeverity)).exitCode).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});

// ─── Scan: filtering ────────────────────────────────────────────────────────

describe('scan filtering', () => {
  test('--severity critical shows only critical findings', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--severity', 'critical');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    for (const v of vulns) {
      expect(v.severity).toBe('critical');
    }
  }, 30_000);

  test('--category security filters to security only', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--category', 'security');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    for (const v of vulns) {
      expect(v.category).toBe('security');
    }
  }, 30_000);

  test('--exclude-cwe CWE-89 removes SQL injection findings', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--exclude-cwe', 'CWE-89');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    const sqlVulns = vulns.filter((v: any) => v.cwe === 'CWE-89');
    expect(sqlVulns.length).toBe(0);
  }, 30_000);
});

// ─── Scan: directory mode ───────────────────────────────────────────────────

describe('scan directory', () => {
  test('scans all files in a directory', async () => {
    const { stdout } = await run('scan', FIXTURES, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.summary.filesScanned).toBeGreaterThanOrEqual(2);
  }, 60_000);

  test('--language java restricts to Java files only', async () => {
    const { stdout } = await run('scan', FIXTURES, '-f', 'json', '-q', '-l', 'java');
    const parsed = JSON.parse(stdout);
    for (const result of parsed.results) {
      expect(result.file).toEndWith('.java');
    }
  }, 60_000);

  test('invalid --language exits 2 instead of scanning nothing (cognium-dev#443)', async () => {
    const { stdout, stderr, exitCode } = await run('scan', FIXTURES, '-f', 'json', '-q', '--language', 'ruby');
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Invalid language: ruby');
    expect(stderr).toContain('Valid options:');
    expect(stdout.trim()).toBe('');
  }, 30_000);

  test('typo --language jaba exits 2 (cognium-dev#443)', async () => {
    const { stderr, exitCode } = await run('scan', '.', '-q', '-l', 'jaba');
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Invalid language: jaba');
    expect(stderr).toContain('java');
  }, 30_000);
});

// ─── TypeScript grammar (#409) ──────────────────────────────────────────────

describe('typescript grammar (cognium-dev#409)', () => {
  // The CLI used to load tree-sitter-javascript for `.ts`. The interface
  // method signature on line 5 then error-recovered into a `query(...)` call
  // and was reported as sql_injection + missing-await.
  const FILE = join(FIXTURES, 'sql-client-interface.ts');

  test('interface method signature is not reported; real concat query still is', async () => {
    const { stdout } = await run('scan', FILE, '-f', 'json', '-q');
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    expect(vulns.filter((v: any) => v.line === 5)).toEqual([]);
    expect(vulns.some((v: any) => v.type === 'missing-await')).toBe(false);
    expect(vulns.some((v: any) => v.type === 'sql_injection' && v.line === 12)).toBe(true);
    expect(vulns.some((v: any) => v.type === 'sql_injection' && v.line === 17)).toBe(false);
  }, 30_000);
});

// ─── Metrics ────────────────────────────────────────────────────────────────

describe('metrics', () => {
  test('produces text metrics for a file', async () => {
    const { stdout, exitCode } = await run('metrics', VULN_FILE, '-q');
    expect(exitCode).toBe(0);
    // Should include common metric names
    expect(stdout).toContain('cyclomatic');
  }, 30_000);

  test('produces JSON metrics', async () => {
    const { stdout, exitCode } = await run('metrics', VULN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.version).toBeDefined();
    expect(parsed.files).toBeArray();
    expect(parsed.files.length).toBeGreaterThan(0);
    expect(parsed.files[0].metrics).toBeArray();
    expect(parsed.summary).toBeDefined();
    expect(exitCode).toBe(0);
  }, 30_000);

  test('--category complexity filters metrics', async () => {
    const { stdout } = await run('metrics', VULN_FILE, '-f', 'json', '-q', '--category', 'complexity');
    const parsed = JSON.parse(stdout);
    for (const fm of parsed.files) {
      for (const m of fm.metrics) {
        expect(m.category).toBe('complexity');
      }
    }
  }, 30_000);

  test('metrics for TypeScript file', async () => {
    const { stdout, exitCode } = await run('metrics', TS_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.files.length).toBeGreaterThan(0);
    expect(exitCode).toBe(0);
  }, 30_000);
});

// ─── Config integration ─────────────────────────────────────────────────────

describe('config integration', () => {
  const configPath = join(FIXTURES, 'cognium.config.json');

  afterAll(() => {
    if (existsSync(configPath)) unlinkSync(configPath);
  });

  test('--disable-pass removes findings from a disableable pass', async () => {
    // Scan the TS fixture which may produce quality findings (e.g., naming-convention)
    // Core taint passes (taint-matcher, taint-propagation, etc.) are always enabled,
    // so we test with a non-core pass. Verify the flag is accepted and doesn't crash.
    const { exitCode } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--disable-pass', 'dead-code,naming-convention');
    // SQL injection should still be found (core passes unaffected)
    expect(exitCode).toBe(1);
  }, 60_000);

  test('config file suppressions remove findings by type', async () => {
    // Suppressions match vuln.type — use 'sql_injection' to suppress the finding
    const config = {
      suppressions: [
        { pass: 'sql_injection', file: 'VulnController.java' },
      ],
    };
    writeFileSync(configPath, JSON.stringify(config));

    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--profile', configPath);
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    const hasSql = vulns.some((v: any) => v.type === 'sql_injection');
    expect(hasSql).toBe(false);

    unlinkSync(configPath);
  }, 30_000);

  test('config file with severity filter applies defaults', async () => {
    const config = {
      severity: 'critical',
    };
    writeFileSync(configPath, JSON.stringify(config));

    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--profile', configPath);
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    for (const v of vulns) {
      expect(v.severity).toBe('critical');
    }

    unlinkSync(configPath);
  }, 30_000);

  test('config file disabling non-core passes via passes object', async () => {
    // Core security passes cannot be disabled. Test with a quality pass.
    const config = {
      passes: {
        'dead-code': false,
        'naming-convention': false,
      },
    };
    writeFileSync(configPath, JSON.stringify(config));

    // Should still find SQL injection (core pass) — verify config loading doesn't break
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--profile', configPath);
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    const hasSql = vulns.some((v: any) => v.type === 'sql_injection');
    expect(hasSql).toBe(true);

    unlinkSync(configPath);
  }, 30_000);
});

// ─── #412: suppressions apply to cross-file taint ───────────────────────────

describe('cross-file suppressions (#412)', () => {
  const dir = join(FIXTURES, 'cross-file-taint');
  const profile = join(dir, 'cognium.config.json');

  afterAll(() => {
    if (existsSync(profile)) unlinkSync(profile);
  });

  test('directory scan reports a cross-file taint path', async () => {
    const { stdout, exitCode } = await run('scan', dir, '-f', 'json', '-q', '--category', 'security');
    const parsed = JSON.parse(stdout);
    expect(parsed.summary.crossFileTaintPaths).toBeGreaterThan(0);
    expect(exitCode).toBe(1);
  }, 60_000);

  test('config suppressions drop cross-file paths and their SARIF results', async () => {
    writeFileSync(profile, JSON.stringify({
      suppressions: [{ pass: 'command_injection' }],
    }));

    const { stdout, exitCode } = await run(
      'scan', dir, '-f', 'json', '-q', '--category', 'security', '--profile', profile,
    );
    const parsed = JSON.parse(stdout);
    expect(parsed.summary.crossFileTaintPaths).toBe(0);
    expect(parsed.cross_file_taint_paths).toEqual([]);

    const remainingSecurity = parsed.results
      .flatMap((r: { vulnerabilities: Array<{ category: string }> }) => r.vulnerabilities)
      .filter((v: { category: string }) => v.category === 'security');
    expect(exitCode).toBe(remainingSecurity.length > 0 ? 1 : 0);

    const sarifRun = await run(
      'scan', dir, '-f', 'sarif', '-q', '--category', 'security', '--profile', profile,
    );
    const sarif = JSON.parse(sarifRun.stdout);
    const ruleIds = (sarif.runs?.[0]?.results ?? []).map((r: { ruleId: string }) => r.ruleId);
    expect(ruleIds.every((id: string) => !String(id).startsWith('cross-file-'))).toBe(true);

    unlinkSync(profile);
  }, 60_000);
});

// ─── Other commands ─────────────────────────────────────────────────────────

describe('other commands', () => {
  test('version command prints version', async () => {
    const { stdout, exitCode } = await run('version');
    expect(stdout).toContain('cognium');
    expect(exitCode).toBe(0);
  }, 10_000);

  test('list-passes shows pass registry', async () => {
    const { stdout, exitCode } = await run('list-passes');
    expect(stdout).toContain('taint-matcher');
    expect(stdout).toContain('dead-code');
    expect(exitCode).toBe(0);
  }, 10_000);

  test('list-passes with category filter', async () => {
    const { stdout } = await run('list-passes', 'reliability');
    expect(stdout).toContain('dead-code');
    // Should not contain security-only passes
    expect(stdout).not.toContain('taint-matcher');
  }, 10_000);

  test('no arguments shows help', async () => {
    const { stdout } = await run();
    expect(stdout).toContain('USAGE');
    expect(stdout).toContain('cognium');
  }, 10_000);

  test('--help shows help', async () => {
    const { stdout } = await run('--help');
    expect(stdout).toContain('USAGE');
  }, 10_000);
});

// ─── Output file ────────────────────────────────────────────────────────────

describe('output file', () => {
  const outFile = join(FIXTURES, '__test_output.json');

  afterAll(() => {
    if (existsSync(outFile)) unlinkSync(outFile);
  });

  test('-o writes results to file', async () => {
    await run('scan', VULN_FILE, '-f', 'json', '-q', '-o', outFile);
    expect(existsSync(outFile)).toBe(true);
    const content = await Bun.file(outFile).text();
    const parsed = JSON.parse(content);
    expect(parsed.results).toBeArray();

    unlinkSync(outFile);
  }, 30_000);
});

// ─── #424: project size ceiling ─────────────────────────────────────────────

describe('#424 project size ceiling', () => {
  test('a truncated scan is never silent, even when the kept subset is clean', async () => {
    // The hole this locks: `shouldOutput` is false unless there are findings,
    // errors, --verbose, --output or a non-text format. Without the truncation
    // clause, a project stopped at the ceiling whose analysed subset happens to
    // have no findings skips BOTH the warning and the summary, and exits 0 —
    // a clean-scan claim over files that were never read.
    const r = await run('scan', '.', '--max-project-source-chars', '120');
    expect(r.stdout).toContain('Project size ceiling reached');
    expect(r.stdout).toContain('NOT a clean scan');
  });

  test('reports analysed-of-discovered, not the discovered count alone', async () => {
    const r = await run('scan', '.', '--max-project-source-chars', '120');
    expect(r.stdout).toMatch(/\d+ of \d+ file\(s\) analysed|analysed \d+ of \d+ files/);
  });

  test('a first file that alone exceeds the cap is still analysed', async () => {
    // The read loop keeps it so a scan is never silently empty. The cap is
    // therefore enforced only there — passing it to analyzeProject as well
    // would drop that same file and analyse zero files.
    const r = await run('scan', '.', '--max-project-source-chars', '1');
    expect(r.stdout).toContain('Project size ceiling reached');
    expect(r.stdout).not.toMatch(/analysed 0 of/);
  });

  test('0 disables the cap and restores the plain summary', async () => {
    const r = await run('scan', '.', '--max-project-source-chars', '0');
    expect(r.stdout).not.toContain('Project size ceiling reached');
  });

  test('an invalid value warns and does not fail the scan', async () => {
    const r = await run('scan', '.', '--max-project-source-chars', 'abc');
    expect(r.stderr).toContain('invalid --max-project-source-chars');
  });
});
