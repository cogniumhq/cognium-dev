import { describe, test, expect } from 'bun:test';
import { resolve } from 'path';
import { TOOL_ARGUMENTS_NOTE, TOOL_ARGUMENTS_TAG } from 'circle-ir';
import { dedupeVulnerabilities } from '../src/cli.js';
import { formatResults, formatSARIF, taintFlowMessage, type CrossFileData } from '../src/formatters.js';

/**
 * A Java path-traversal finding whose source is the tool's own arguments
 * (`main`'s `String[]`, a commons-cli option, a Mojo `@Parameter`) says so in
 * its message, and carries the `tool-arguments:local-input` tag. It is still
 * reported, at the same severity.
 */

const CLI = resolve(import.meta.dir, '../src/cli.ts');
const FIXTURE = resolve(import.meta.dir, 'fixtures', 'tool-arguments');

const vuln = (over: Record<string, unknown> = {}): any => ({
  type: 'path_traversal', severity: 'high', message: 'm', line: 9, cwe: 'CWE-22', category: 'security', ...over,
});

const crossFile = (tags?: string[]): CrossFileData => ({
  taintPaths: [{
    id: 'tp-1',
    source: { file: 'Runner.java', line: 15, type: 'io_input', code: '' },
    sink: { file: 'Report.java', line: 9, type: 'path_traversal', cwe: 'CWE-22', code: '' },
    hops: [],
    sanitizers_in_path: [],
    path_exists: true,
    confidence: 0.35,
    ...(tags ? { tags } : {}),
  }],
  crossFileCalls: [],
});

describe('taintFlowMessage', () => {
  test('a flow from the tool\'s own arguments says so', () => {
    const flow = { sink_type: 'path_traversal', source_line: 3, sink_line: 4 };
    expect(taintFlowMessage(flow)).toBe('path_traversal vulnerability: tainted data flows from line 3 to line 4');
    expect(taintFlowMessage({ ...flow, tags: [TOOL_ARGUMENTS_TAG] }))
      .toBe(`path_traversal vulnerability: tainted data flows from line 3 to line 4 — ${TOOL_ARGUMENTS_NOTE}`);
  });
});

describe('dedupeVulnerabilities and the tool-arguments tag', () => {
  test('a sink that another source also reaches keeps the plain finding', () => {
    const out = dedupeVulnerabilities([vuln({ tags: [TOOL_ARGUMENTS_TAG], message: 'tagged' }), vuln({ message: 'plain' })]);
    expect(out).toHaveLength(1);
    expect(out[0].message).toBe('plain');
    expect(out[0].tags).toBeUndefined();
  });

  test('a sink every source of which is a tool argument keeps the tag', () => {
    const out = dedupeVulnerabilities([vuln({ tags: [TOOL_ARGUMENTS_TAG] }), vuln({ tags: [TOOL_ARGUMENTS_TAG] })]);
    expect(out).toHaveLength(1);
    expect(out[0].tags).toEqual([TOOL_ARGUMENTS_TAG]);
  });

  test('a higher severity still wins over the tie-break', () => {
    const out = dedupeVulnerabilities([vuln({ severity: 'medium' }), vuln({ tags: [TOOL_ARGUMENTS_TAG] })]);
    expect(out[0].tags).toEqual([TOOL_ARGUMENTS_TAG]);
  });
});

describe('cross-file paths from the tool\'s own arguments', () => {
  test('text output adds the note under the path', () => {
    expect(formatResults([], false, crossFile([TOOL_ARGUMENTS_TAG]))).toContain(TOOL_ARGUMENTS_NOTE);
    expect(formatResults([], false, crossFile())).not.toContain(TOOL_ARGUMENTS_NOTE);
  });

  test('SARIF carries the note and the tag', () => {
    const [tagged] = JSON.parse(formatSARIF([], crossFile([TOOL_ARGUMENTS_TAG]))).runs[0].results;
    expect(tagged.message.text).toContain(TOOL_ARGUMENTS_NOTE);
    expect(tagged.properties.tags).toEqual([TOOL_ARGUMENTS_TAG]);
    const [plain] = JSON.parse(formatSARIF([], crossFile())).runs[0].results;
    expect(plain.message.text).not.toContain(TOOL_ARGUMENTS_NOTE);
    expect(plain.properties.tags).toBeUndefined();
  });
});

describe('scan of a small command-line tool', () => {
  test('labels main(String[] args) and the CommandLine option, not a sink another source reaches', async () => {
    const proc = Bun.spawn(['bun', 'run', CLI, 'scan', FIXTURE, '-f', 'json', '-q'], {
      stdout: 'pipe', stderr: 'pipe', env: { ...process.env, NO_COLOR: '1' }, cwd: FIXTURE,
    });
    const stdout = await new Response(proc.stdout).text();
    await proc.exited;
    const json = JSON.parse(stdout);
    const pt = (file: string) => json.results
      .filter((r: any) => r.file.endsWith(file))
      .flatMap((r: any) => r.vulnerabilities)
      .filter((v: any) => v.type === 'path_traversal');

    const fromMain = pt('Runner.java').find((v: any) => v.line === 11);
    expect(fromMain).toBeDefined();
    expect(fromMain.severity).toBe('high');
    expect(fromMain.tags).toContain(TOOL_ARGUMENTS_TAG);
    expect(fromMain.message).toContain(TOOL_ARGUMENTS_NOTE);
    // Report.setTarget's own parameter also reaches this sink: the plain finding stays
    const mixed = pt('Report.java').find((v: any) => v.line === 9);
    expect(mixed).toBeDefined();
    expect(mixed.severity).toBe('high');
    expect(mixed.tags ?? []).not.toContain(TOOL_ARGUMENTS_TAG);
    expect(mixed.message).not.toContain(TOOL_ARGUMENTS_NOTE);

    const fromOption = json.cross_file_taint_paths.filter((p: any) => p.sink.type === 'path_traversal' && p.source.file.endsWith('Runner.java'));
    expect(fromOption.length).toBeGreaterThan(0);
    expect(fromOption.every((p: any) => p.tags?.includes(TOOL_ARGUMENTS_TAG))).toBe(true);
  }, 30_000);
});
