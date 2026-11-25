/**
 * SARIF conformance.
 *
 * `formatSARIF` output is consumed by GitHub code scanning (via
 * cognium-ai-action) and by the Buildkite plugin, and neither reports a
 * useful error when the document is malformed: code scanning rejects the
 * whole upload, so a single bad `startLine` silently drops every finding in
 * the run. Unit tests elsewhere assert individual fields; this file asserts
 * the document as a whole is valid SARIF 2.1.0.
 *
 * The schema is vendored (tests/fixtures/sarif-schema-2.1.0.json) rather than
 * fetched, so CI stays hermetic and this suite cannot go red because the OASIS
 * repo moved a file — which it has: the URL the formatter emits as `$schema`
 * (master/Schemata/…) is a 404 today, the spec now lives under
 * main/sarif-2.1/schema/.
 */
import { describe, test, expect } from 'bun:test';
import Ajv from 'ajv-draft-04';
import { formatSARIF, type ScanResult, type CrossFileData } from '../src/formatters';
import sarifSchema from './fixtures/sarif-schema-2.1.0.json';

const ajv = new Ajv({ allErrors: true, strict: false });
const validateSarif = ajv.compile(sarifSchema as object);

function validate(doc: unknown): string[] {
  return validateSarif(doc)
    ? []
    : (validateSarif.errors ?? []).map(e => `${e.instancePath || '/'} ${e.message}`);
}

function vuln(over: Partial<ScanResult['vulnerabilities'][0]> = {}) {
  return {
    type: 'SQL Injection',
    severity: 'critical',
    message: 'Untrusted input reaches a SQL sink',
    line: 42,
    cwe: 'CWE-89',
    category: 'security',
    ...over,
  } as ScanResult['vulnerabilities'][0];
}

describe('SARIF 2.1.0 conformance', () => {
  test('empty scan produces a valid document that says why it is empty', () => {
    const doc = JSON.parse(formatSARIF([]));
    expect(validate(doc)).toEqual([]);
    expect(doc.runs[0].results).toEqual([]);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications[0].properties).toEqual({ reason: 'no-files' });
  });

  test('clean file with no vulnerabilities is valid', () => {
    const results: ScanResult[] = [{ file: 'src/Clean.java', vulnerabilities: [] }];
    expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
  });

  test('single finding produces a valid document', () => {
    const results: ScanResult[] = [{ file: 'src/Vuln.java', vulnerabilities: [vuln()] }];
    expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
  });

  test('every severity maps to a SARIF level the schema accepts', () => {
    for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
      const results: ScanResult[] = [
        { file: 'src/Vuln.java', vulnerabilities: [vuln({ severity })] },
      ];
      expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
    }
  });

  test('optional finding fields do not break the document', () => {
    const results: ScanResult[] = [
      {
        file: 'src/Vuln.java',
        vulnerabilities: [
          vuln({ fix: 'Use a parameterised query', tags: ['library-api-surface'] }),
          vuln({ type: 'Path Traversal', cwe: undefined, severity: 'low' }),
        ],
      },
    ];
    expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
  });

  test('cross-file taint paths produce valid relatedLocations', () => {
    const crossFile = {
      taintPaths: [
        {
          source: { file: 'src/Controller.java', line: 10, type: 'http-param' },
          sink: { file: 'src/Repo.java', line: 88, type: 'sql-injection', cwe: 'CWE-89' },
          confidence: 0.9,
        },
      ],
      crossFileCalls: [],
    } as unknown as CrossFileData;

    expect(validate(JSON.parse(formatSARIF([], crossFile)))).toEqual([]);
  });

  test('a scan error on one file still yields a valid document', () => {
    const results: ScanResult[] = [
      { file: 'src/Broken.java', vulnerabilities: [], error: 'parse failed' },
      { file: 'src/Vuln.java', vulnerabilities: [vuln()] },
    ];
    expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
  });

  // The schema puts `minimum: 1` on region.startLine. A finding reported at
  // line 0 — or with the line missing entirely — therefore invalidates the
  // whole run, not just that result, and code scanning drops every finding in
  // the upload. The formatter passes `vuln.line` through unguarded, so this is
  // the regression this file exists to catch.
  test('a finding at line 0 does not produce an invalid document', () => {
    const results: ScanResult[] = [
      { file: 'src/Vuln.java', vulnerabilities: [vuln({ line: 0 })] },
    ];
    expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
  });

  test('a finding with a missing line does not produce an invalid document', () => {
    const results: ScanResult[] = [
      { file: 'src/Vuln.java', vulnerabilities: [vuln({ line: undefined as unknown as number })] },
    ];
    expect(validate(JSON.parse(formatSARIF(results)))).toEqual([]);
  });

  // #615 — text output already says the ceiling was hit. SARIF must too,
  // or a CI consumer treats a truncated scan as a complete successful run.
  test('a project size ceiling is a warning and marks the run unsuccessful', () => {
    const doc = JSON.parse(formatSARIF([], {
      taintPaths: [],
      crossFileCalls: [],
      projectSizeBudgetExceeded: true,
      filesAnalysed: 7,
      filesTotal: 18,
    }));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolExecutionNotifications).toEqual([
      {
        level: 'warning',
        message: {
          text: 'Project size ceiling reached — analysed 7 of 18 files.',
        },
        properties: { reason: 'project-size-ceiling' },
      },
    ]);
    expect(validate(doc)).toEqual([]);
  });

  // #1306 — a file with no result at all (never read past the ceiling, or
  // left out by analyzeProject) was absent from SARIF, which reads as clean.
  test('a file never read past the project size ceiling is its own warning at that file', () => {
    const doc = JSON.parse(formatSARIF([{ file: 'src/A.java', vulnerabilities: [] }], {
      taintPaths: [],
      crossFileCalls: [],
      projectSizeBudgetExceeded: true,
      filesAnalysed: 1,
      filesTotal: 3,
      unanalysedFiles: [
        { file: 'src/B.java', reason: 'project-size-ceiling' },
        { file: 'src/C.java', reason: 'project-size-ceiling' },
      ],
    }));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(false);
    const perFile = invocation.toolExecutionNotifications.filter((n: { locations?: unknown }) => n.locations);
    expect(perFile).toEqual(['src/B.java', 'src/C.java'].map(uri => ({
      level: 'warning',
      message: { text: 'File not analysed: the project size ceiling was reached before it was read. Raise it with --max-project-source-chars <n> (0 = unlimited).' },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
      properties: { reason: 'project-size-ceiling' },
    })));
    expect(validate(doc)).toEqual([]);
  });

  test('a file the analyser returned no result for is an error at that file, and the run is unsuccessful', () => {
    const doc = JSON.parse(formatSARIF([{ file: 'src/A.java', vulnerabilities: [] }], {
      taintPaths: [],
      crossFileCalls: [],
      unanalysedFiles: [{ file: 'src/Gone.java', reason: 'no-result' }],
    }));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolExecutionNotifications).toEqual([
      {
        level: 'error',
        message: { text: 'File not analysed: the analyser returned no result for it.' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'src/Gone.java' } } }],
        properties: { reason: 'analysis-error' },
      },
    ]);
    expect(validate(doc)).toEqual([]);
  });

  test('a complete scan says so and carries no notification', () => {
    const doc = JSON.parse(formatSARIF([{ file: 'src/Clean.java', vulnerabilities: [] }]));
    expect(doc.runs[0].invocations).toEqual([{ executionSuccessful: true }]);
    expect(validate(doc)).toEqual([]);
  });

  // A file skipped by --file-timeout-ms (or one whose analysis threw) has no
  // results. Before, SARIF had nothing else either, so it read as clean.
  test('a file that was not analysed is an error notification at that file, and the run is unsuccessful', () => {
    const results: ScanResult[] = [
      { file: 'src/Slow.java', vulnerabilities: [], error: 'analysis timed out after 12ms (at parse); file skipped', errorKind: 'timeout' },
      { file: 'src/Broken.java', vulnerabilities: [], error: 'boom' },
      { file: 'src/Vuln.java', vulnerabilities: [vuln()] },
    ];
    const doc = JSON.parse(formatSARIF(results));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolExecutionNotifications).toEqual([
      {
        level: 'error',
        message: { text: 'File not analysed: analysis timed out after 12ms (at parse); file skipped' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'src/Slow.java' } } }],
        properties: { reason: 'file-timeout' },
      },
      {
        level: 'error',
        message: { text: 'File not analysed: boom' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'src/Broken.java' } } }],
        properties: { reason: 'analysis-error' },
      },
    ]);
    expect(doc.runs[0].results).toHaveLength(1);
    expect(validate(doc)).toEqual([]);
  });

  test('a partly parsed file is a warning at its first error line; the run still completed', () => {
    const results: ScanResult[] = [
      { file: 'src/A.java', vulnerabilities: [], parseErrors: { count: 2, lines: [3, 9] } },
    ];
    const doc = JSON.parse(formatSARIF(results));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.toolExecutionNotifications).toHaveLength(1);
    const n = invocation.toolExecutionNotifications[0];
    expect(n.level).toBe('warning');
    expect(n.properties).toEqual({ reason: 'parse-error' });
    expect(n.locations).toEqual([{ physicalLocation: { artifactLocation: { uri: 'src/A.java' }, region: { startLine: 3 } } }]);
    expect(n.message.text).toContain('2 syntax error(s) (first at line 3)');
    expect(validate(doc)).toEqual([]);
  });

  test('findings dropped by the entry-path gate are a note naming the flag; the run is still complete', () => {
    const doc = JSON.parse(formatSARIF([], { taintPaths: [], crossFileCalls: [], entryPathDropped: 3 }));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.toolExecutionNotifications).toHaveLength(1);
    const n = invocation.toolExecutionNotifications[0];
    expect(n.level).toBe('note');
    expect(n.properties).toEqual({ reason: 'entry-path-gate' });
    expect(n.message.text).toContain('3 high/critical security finding(s)');
    expect(n.message.text).toContain('--disable-pass require-entry-path');
    expect(validate(doc)).toEqual([]);
  });

  test('an exceeded cross-file budget is a warning and marks the run unsuccessful', () => {
    const doc = JSON.parse(formatSARIF([], { taintPaths: [], crossFileCalls: [], budgetExceeded: true }));
    const invocation = doc.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolExecutionNotifications).toHaveLength(1);
    expect(invocation.toolExecutionNotifications[0].level).toBe('warning');
    expect(invocation.toolExecutionNotifications[0].properties).toEqual({ reason: 'cross-file-budget' });
    expect(invocation.toolExecutionNotifications[0].message.text).toContain('--cross-file-budget-ms');
    expect(validate(doc)).toEqual([]);
  });
});

describe('GitHub code scanning requirements', () => {
  // Stricter than the spec: code scanning resolves artifact URIs against the
  // repository root, so an absolute path matches no tracked file and the
  // finding is accepted but never displayed.
  test('artifact URIs are repository-relative', () => {
    const results: ScanResult[] = [{ file: 'src/Vuln.java', vulnerabilities: [vuln()] }];
    const doc = JSON.parse(formatSARIF(results));

    for (const r of doc.runs[0].results) {
      const uri = r.locations[0].physicalLocation.artifactLocation.uri;
      expect(uri.startsWith('/')).toBe(false);
      expect(/^[a-zA-Z]:[\\/]/.test(uri)).toBe(false);
    }
  });

  // Every ruleId must resolve to a rule in tool.driver.rules, or code scanning
  // shows the finding with no name, severity or description.
  test('every result ruleId resolves to a declared rule', () => {
    const results: ScanResult[] = [
      {
        file: 'src/Vuln.java',
        vulnerabilities: [vuln(), vuln({ type: 'Path Traversal', cwe: 'CWE-22' })],
      },
    ];
    const crossFile = {
      taintPaths: [
        {
          source: { file: 'src/Controller.java', line: 10, type: 'http-param' },
          sink: { file: 'src/Repo.java', line: 88, type: 'sql-injection', cwe: 'CWE-89' },
          confidence: 0.9,
        },
      ],
      crossFileCalls: [],
    } as unknown as CrossFileData;

    const doc = JSON.parse(formatSARIF(results, crossFile));
    const declared = new Set(doc.runs[0].tool.driver.rules.map((r: { id: string }) => r.id));

    for (const r of doc.runs[0].results) {
      expect(declared.has(r.ruleId)).toBe(true);
    }
  });

  test('the document declares version 2.1.0', () => {
    expect(JSON.parse(formatSARIF([])).version).toBe('2.1.0');
  });
});
