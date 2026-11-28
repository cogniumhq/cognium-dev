/**
 * What a scan report says beyond its findings, end to end through the CLI:
 *
 *   - a report is written even when nothing could be analysed, and it counts
 *     the files that were skipped because no analyser handles their type;
 *   - a taint finding carries its trace: JSON `source`, SARIF `codeFlows`
 *     ordered source → steps → sink;
 *   - a call into a helper in another file that the cross-file phase follows
 *     to a real sink is reported once, as that sink, not also as data
 *     escaping to an unknown method.
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { resolve, join } from 'path';
import { writeFileSync, existsSync, mkdtempSync, mkdirSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import Ajv from 'ajv-draft-04';
import sarifSchema from './fixtures/sarif-schema-2.1.0.json';

const CLI = resolve(import.meta.dir, '../src/cli.ts');

const ajv = new Ajv({ allErrors: true, strict: false });
const validateSarif = ajv.compile(sarifSchema as object);
const schemaErrors = (doc: unknown): string[] =>
  validateSarif(doc) ? [] : (validateSarif.errors ?? []).map(e => `${e.instancePath || '/'} ${e.message}`);

async function run(cwd: string, ...args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env, NO_COLOR: '1' },
    cwd,
  });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { stdout, stderr, exitCode: await proc.exited };
}

const root = mkdtempSync(join(tmpdir(), 'cognium-report-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function project(name: string, files: Record<string, string>): string {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true });
  for (const [f, code] of Object.entries(files)) writeFileSync(join(dir, f), code);
  return dir;
}

type Loc = { location: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } }; message: { text: string } } };
const steps = (result: { codeFlows: Array<{ threadFlows: Array<{ locations: Loc[] }> }> }) =>
  result.codeFlows[0].threadFlows[0].locations.map(l =>
    `${l.location.physicalLocation.artifactLocation.uri.split('/').pop()}:${l.location.physicalLocation.region?.startLine}`);

// ─── Only files no analyser handles ─────────────────────────────────────────

describe('a folder with no supported files', () => {
  let dir: string;
  beforeAll(() => {
    dir = project('markup-only', {
      'Banner.vue': '<template>\n  <div v-html="msg"></div>\n</template>\n',
      'notes.md': '# notes\n',
    });
  });

  test('-f json -o writes a report with an empty result list and the skipped files by extension', async () => {
    const out = join(root, 'markup-only.json');
    const { exitCode, stderr } = await run(dir, 'scan', '.', '-f', 'json', '-o', out);
    expect(exitCode).toBe(0);
    expect(stderr).toContain('No supported files found');
    expect(stderr).toContain('2 file(s) skipped: no analyser for their type (.md: 1, .vue: 1)');
    expect(existsSync(out)).toBe(true);
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    expect(doc.results).toEqual([]);
    expect(doc.summary.filesScanned).toBe(0);
    expect(doc.summary.unsupportedFiles).toBe(2);
    expect(doc.summary.unsupportedFilesByExtension).toEqual({ '.md': 1, '.vue': 1 });
  }, 30_000);

  test('-f sarif -o writes a valid empty run that says why it is empty and what was skipped', async () => {
    const out = join(root, 'markup-only.sarif');
    const { exitCode } = await run(dir, 'scan', '.', '-f', 'sarif', '-o', out, '-q');
    expect(exitCode).toBe(0);
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    expect(schemaErrors(doc)).toEqual([]);
    expect(doc.runs[0].results).toEqual([]);
    const notes = doc.runs[0].invocations[0].toolExecutionNotifications;
    expect(notes.map((n: { properties: { reason: string } }) => n.properties.reason)).toEqual(['no-files', 'unsupported-files']);
    expect(notes[1].properties.unsupportedFilesByExtension).toEqual({ '.md': 1, '.vue': 1 });
  }, 30_000);

  test('a single unsupported file given by name is counted too', async () => {
    const { stdout, exitCode } = await run(dir, 'scan', 'Banner.vue', '-f', 'json', '-q');
    expect(exitCode).toBe(0);
    expect(JSON.parse(stdout).summary.unsupportedFilesByExtension).toEqual({ '.vue': 1 });
  }, 30_000);
});

describe('a folder with supported and unsupported files', () => {
  test('counts only the files no analyser handles; dot-files and read resources are not counted', async () => {
    const dir = project('mixed', {
      'main.go': 'package main\n\nfunc main() {}\n',
      'README.md': '# readme\n',
      'LICENSE': 'MIT\n',
      'app.properties': 'a=b\n',
      '.env': 'X=1\n',
    });
    const { stdout } = await run(dir, 'scan', '.', '-f', 'json', '-q');
    const doc = JSON.parse(stdout);
    expect(doc.summary.filesScanned).toBe(1);
    expect(doc.summary.unsupportedFilesByExtension).toEqual({ '(none)': 1, '.md': 1 });
  }, 30_000);

  test('--language leaves other supported languages out without counting them as unsupported', async () => {
    const dir = project('two-languages', {
      'main.go': 'package main\n\nfunc main() {}\n',
      'app.py': 'print(1)\n',
    });
    const { stdout } = await run(dir, 'scan', '.', '-f', 'json', '-q', '--language', 'go');
    expect(JSON.parse(stdout).summary.unsupportedFiles).toBe(0);
  }, 30_000);
});

// ─── A helper in another file ───────────────────────────────────────────────

describe('a request value passed to a redirect helper in another file', () => {
  let dir: string;
  beforeAll(() => {
    dir = project('go-redirect-helper', {
      'handler.go': [
        'package main',
        '',
        'import "net/http"',
        '',
        'func next(w http.ResponseWriter, r *http.Request) {',
        '\tdest := r.URL.Query().Get("next")',
        '\tsendTo(w, r, dest)',
        '}',
        '',
        'func main() {',
        '\thttp.HandleFunc("/next", next)',
        '\thttp.ListenAndServe(":8080", nil)',
        '}',
        '',
      ].join('\n'),
      'helper.go': [
        'package main',
        '',
        'import "net/http"',
        '',
        'func sendTo(w http.ResponseWriter, r *http.Request, dest string) {',
        '\thttp.Redirect(w, r, dest, http.StatusFound)',
        '}',
        '',
      ].join('\n'),
    });
  });

  test('JSON: one open redirect with its source; no escape at the helper call', async () => {
    const { stdout, exitCode } = await run(dir, 'scan', '.', '-f', 'json', '-q', '--category', 'security');
    expect(exitCode).toBe(1);
    const doc = JSON.parse(stdout);
    const vulns = doc.results.flatMap((r: { file: string; vulnerabilities: Array<{ type: string; line: number; source?: { file: string; line: number } }> }) =>
      r.vulnerabilities.map(v => ({ file: r.file.split('/').pop(), ...v })));
    expect(vulns.map((v: { type: string }) => v.type)).toEqual(['open_redirect']);
    expect(vulns[0].file).toBe('helper.go');
    expect(vulns[0].line).toBe(6);
    expect(vulns[0].source.file.endsWith('handler.go')).toBe(true);
    expect(vulns[0].source.line).toBe(6);
    const paths = doc.cross_file_taint_paths;
    expect(paths.map((p: { sink: { type: string } }) => p.sink.type)).toEqual(['open_redirect']);
    expect(paths[0].hops.map((h: { file: string; line: number }) => `${h.file.split('/').pop()}:${h.line}`))
      .toEqual(['handler.go:6', 'handler.go:7', 'helper.go:6']);
  }, 30_000);

  test('SARIF: valid, and both results trace source → call → sink', async () => {
    const { stdout } = await run(dir, 'scan', '.', '-f', 'sarif', '-q', '--category', 'security');
    const doc = JSON.parse(stdout);
    expect(schemaErrors(doc)).toEqual([]);
    const results = doc.runs[0].results;
    expect(results.map((r: { ruleId: string }) => r.ruleId).sort()).toEqual(['cross-file-open_redirect', 'open_redirect']);
    const perFile = results.find((r: { ruleId: string }) => r.ruleId === 'open_redirect');
    const crossFile = results.find((r: { ruleId: string }) => r.ruleId === 'cross-file-open_redirect');
    expect(steps(perFile)).toEqual(['handler.go:6', 'helper.go:6']);
    expect(steps(crossFile)).toEqual(['handler.go:6', 'handler.go:7', 'helper.go:6']);
  }, 30_000);
});

describe('a request value used as the source of a Go template', () => {
  test('is template injection (CWE-1336), not code injection', async () => {
    const dir = project('go-template-source', {
      'main.go': [
        'package main',
        '',
        'import (',
        '\t"net/http"',
        '\t"text/template"',
        ')',
        '',
        'func preview(w http.ResponseWriter, r *http.Request) {',
        '\tsrc := r.URL.Query().Get("t")',
        '\tt, err := template.New("p").Parse(src)',
        '\tif err != nil {',
        '\t\treturn',
        '\t}',
        '\tt.Execute(w, nil)',
        '}',
        '',
      ].join('\n'),
    });
    const { stdout } = await run(dir, 'scan', '.', '-f', 'json', '-q', '--category', 'security');
    const doc = JSON.parse(stdout);
    const vulns = doc.results.flatMap((r: { vulnerabilities: Array<{ type: string; cwe: string; line: number }> }) => r.vulnerabilities);
    expect(vulns.map((v: { type: string; cwe: string; line: number }) => [v.type, v.cwe, v.line])).toEqual([['template_injection', 'CWE-1336', 10]]);
  }, 30_000);
});
