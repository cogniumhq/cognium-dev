import { describe, test, expect } from 'bun:test';
import {
  applySuppressionsToResults,
  applySuppressionsToTaintPaths,
  type Suppression,
} from '../src/cli.js';
import type { ScanResult } from '../src/formatters.js';
import type { TaintPath } from 'circle-ir';

function makeResult(file: string, vulns: Array<{ type: string; line: number }>): ScanResult {
  return {
    file,
    vulnerabilities: vulns.map(v => ({
      type: v.type,
      severity: 'high',
      message: `${v.type} at line ${v.line}`,
      line: v.line,
      category: 'security',
    })),
  };
}

describe('applySuppressionsToResults', () => {
  test('returns results unchanged when no suppressions', () => {
    const results = [makeResult('/app/src/Foo.java', [{ type: 'sql_injection', line: 10 }])];
    const out = applySuppressionsToResults(results, [], '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('suppresses by pass name (all files)', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'naming-convention', line: 5 }]),
      makeResult('/app/src/B.java', [{ type: 'naming-convention', line: 12 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'naming-convention' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(0);
    expect(out[1].vulnerabilities).toHaveLength(0);
  });

  test('suppresses by pass + file', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'dead-code', line: 5 }]),
      makeResult('/app/src/B.java', [{ type: 'dead-code', line: 10 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'dead-code', file: 'src/A.java' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(0); // suppressed
    expect(out[1].vulnerabilities).toHaveLength(1); // not suppressed
  });

  test('suppresses by pass + file + line', () => {
    const results = [
      makeResult('/app/src/A.java', [
        { type: 'dead-code', line: 5 },
        { type: 'dead-code', line: 20 },
      ]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code', file: 'src/A.java', line: 5 },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
    expect(out[0].vulnerabilities[0].line).toBe(20);
  });

  test('does not suppress when pass name does not match', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'sql_injection', line: 10 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'xss' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('does not suppress when file does not match', () => {
    const results = [
      makeResult('/app/src/B.java', [{ type: 'dead-code', line: 5 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'dead-code', file: 'src/A.java' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('does not suppress when line does not match', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'dead-code', line: 20 }]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code', file: 'src/A.java', line: 5 },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('multiple suppressions can stack', () => {
    const results = [
      makeResult('/app/src/A.java', [
        { type: 'dead-code', line: 5 },
        { type: 'naming-convention', line: 10 },
        { type: 'sql_injection', line: 15 },
      ]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code' },
      { pass: 'naming-convention' },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
    expect(out[0].vulnerabilities[0].type).toBe('sql_injection');
  });

  test('handles file with ./prefix in suppression', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'dead-code', line: 5 }]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code', file: './src/A.java' },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(0);
  });
});

function makePath(sinkFile: string, sinkLine: number, sinkType: TaintPath['sink']['type'] = 'sql_injection'): TaintPath {
  return {
    id: `tp-${sinkFile}-${sinkLine}`,
    source: { file: 'src/A.java', line: 5, type: 'http_param', code: 'req.getParameter("q")' },
    sink: { file: sinkFile, line: sinkLine, type: sinkType, cwe: 'CWE-89', code: 'stmt.execute(q)' },
    hops: [],
    sanitizers_in_path: [],
    path_exists: true,
    confidence: 0.9,
  };
}

describe('applySuppressionsToTaintPaths (#412)', () => {
  test('returns paths unchanged when no suppressions', () => {
    const paths = [makePath('/app/src/B.java', 20)];
    expect(applySuppressionsToTaintPaths(paths, [], '/app')).toHaveLength(1);
  });

  test('suppresses by sink type across all files', () => {
    const paths = [
      makePath('/app/src/B.java', 20, 'sql_injection'),
      makePath('/app/src/C.java', 8, 'xss'),
    ];
    const out = applySuppressionsToTaintPaths(paths, [{ pass: 'sql_injection' }], '/app');
    expect(out).toHaveLength(1);
    expect(out[0].sink.type).toBe('xss');
  });

  test('also matches the cross-file-<type> SARIF rule id', () => {
    const paths = [makePath('/app/src/B.java', 20)];
    const out = applySuppressionsToTaintPaths(
      paths,
      [{ pass: 'cross-file-sql_injection' }],
      '/app',
    );
    expect(out).toHaveLength(0);
  });

  test('suppresses by sink file + line', () => {
    const paths = [
      makePath('/app/src/B.java', 20),
      makePath('/app/src/B.java', 40),
    ];
    const out = applySuppressionsToTaintPaths(
      paths,
      [{ pass: 'sql_injection', file: 'src/B.java', line: 20 }],
      '/app',
    );
    expect(out).toHaveLength(1);
    expect(out[0].sink.line).toBe(40);
  });

  test('does not suppress when file or line does not match', () => {
    const paths = [makePath('/app/src/B.java', 20)];
    expect(applySuppressionsToTaintPaths(
      paths,
      [{ pass: 'sql_injection', file: 'src/C.java' }],
      '/app',
    )).toHaveLength(1);
    expect(applySuppressionsToTaintPaths(
      paths,
      [{ pass: 'sql_injection', file: 'src/B.java', line: 99 }],
      '/app',
    )).toHaveLength(1);
  });

  test('does not suppress a different sink type', () => {
    const paths = [makePath('/app/src/B.java', 20, 'ssrf')];
    const out = applySuppressionsToTaintPaths(paths, [{ pass: 'sql_injection' }], '/app');
    expect(out).toHaveLength(1);
  });
});
