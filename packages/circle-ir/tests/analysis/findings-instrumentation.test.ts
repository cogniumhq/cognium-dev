/**
 * Tests for #145 PR B — opt-in per-file findings instrumentation hook.
 * Verifies the flag toggle, the per-finding + summary stderr payload
 * shapes, and that the emission is read-only (no mutation of pipeline
 * outputs).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  setFindingsInstrumentation,
  isFindingsInstrumentationEnabled,
  emitFindingsInstrumentation,
} from '../../src/analysis/findings-instrumentation.js';
import type { SastFinding, TaintSource, TaintSink } from '../../src/types/index.js';

function makeFinding(over: Partial<SastFinding> = {}): SastFinding {
  return {
    id: 'rule-x-app.js-10',
    pass: 'taint-matcher',
    category: 'security',
    rule_id: 'sql-injection',
    cwe: 'CWE-89',
    severity: 'high',
    level: 'error',
    message: 'SQL injection',
    file: 'app.js',
    line: 50,
    ...over,
  };
}

function makeSink(line = 50, type: TaintSink['type'] = 'sql_injection'): TaintSink {
  return {
    type,
    cwe: 'CWE-89',
    location: `query_${line}`,
    line,
    confidence: 0.87,
  };
}

function makeSource(line = 10, type: TaintSource['type'] = 'http_param'): TaintSource {
  return {
    type,
    location: `param_${line}`,
    line,
    severity: 'high',
    confidence: 0.9,
  };
}

const emptyTaint = { sources: [] as TaintSource[], sinks: [] as TaintSink[] };

describe('findings instrumentation (#145 PR B, re-scoped)', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    setFindingsInstrumentation(false);
  });

  afterEach(() => {
    setFindingsInstrumentation(false);
    errorSpy.mockRestore();
  });

  it('flag defaults to off', () => {
    expect(isFindingsInstrumentationEnabled()).toBe(false);
  });

  it('emits nothing when flag is off', () => {
    emitFindingsInstrumentation('app.js', [makeFinding()], emptyTaint);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it('toggle round-trip', () => {
    setFindingsInstrumentation(true);
    expect(isFindingsInstrumentationEnabled()).toBe(true);
    setFindingsInstrumentation(false);
    expect(isFindingsInstrumentationEnabled()).toBe(false);
  });

  it('emits one [finding] line per finding plus one [findings-summary]', () => {
    setFindingsInstrumentation(true);
    const findings = [makeFinding({ line: 50 }), makeFinding({ line: 60, rule_id: 'xss', cwe: 'CWE-79' })];
    emitFindingsInstrumentation('app.js', findings, emptyTaint);

    expect(errorSpy).toHaveBeenCalledTimes(3);
    const lines = errorSpy.mock.calls.map(c => c[0] as string);
    expect(lines.filter(l => l.startsWith('[finding] '))).toHaveLength(2);
    expect(lines.filter(l => l.startsWith('[findings-summary] '))).toHaveLength(1);
  });

  it('per-finding payload carries required coalesce fields', () => {
    setFindingsInstrumentation(true);
    const f = makeFinding({ line: 50, rule_id: 'sql-injection', severity: 'critical', cwe: 'CWE-89' });
    emitFindingsInstrumentation('app.js', [f], {
      sources: [makeSource(10, 'http_param')],
      sinks: [makeSink(50, 'sql_injection')],
    });

    const line = errorSpy.mock.calls.find(c => (c[0] as string).startsWith('[finding] '))![0] as string;
    const payload = JSON.parse(line.replace('[finding] ', ''));

    expect(payload).toMatchObject({
      file: 'app.js',
      line: 50,
      rule_id: 'sql-injection',
      pass: 'taint-matcher',
      category: 'security',
      severity: 'critical',
      cwe: 'CWE-89',
      sink_type: 'sql_injection',
      confidence: 0.87,
      dedup_group_id: 'app.js:50:sql-injection',
    });
  });

  it('source_type populated when no sink matches the finding line', () => {
    setFindingsInstrumentation(true);
    const f = makeFinding({ line: 10, rule_id: 'tainted-input' });
    emitFindingsInstrumentation('app.js', [f], {
      sources: [makeSource(10, 'http_header')],
      sinks: [makeSink(99)],
    });

    const line = errorSpy.mock.calls.find(c => (c[0] as string).startsWith('[finding] '))![0] as string;
    const payload = JSON.parse(line.replace('[finding] ', ''));
    expect(payload.source_type).toBe('http_header');
    expect(payload.sink_type).toBeUndefined();
  });

  it('summary aggregates total, by_rule, by_severity, group cardinality', () => {
    setFindingsInstrumentation(true);
    const findings = [
      makeFinding({ line: 50, rule_id: 'sql-injection', severity: 'high' }),
      makeFinding({ line: 50, rule_id: 'sql-injection', severity: 'high' }), // duplicate group
      makeFinding({ line: 60, rule_id: 'xss', severity: 'medium' }),
    ];
    emitFindingsInstrumentation('app.js', findings, {
      sources: [makeSource(10)],
      sinks: [makeSink(50), makeSink(60, 'xss')],
    });

    const sumLine = errorSpy.mock.calls.find(c => (c[0] as string).startsWith('[findings-summary] '))![0] as string;
    const summary = JSON.parse(sumLine.replace('[findings-summary] ', ''));
    expect(summary).toMatchObject({
      file: 'app.js',
      total: 3,
      unique_groups: 2,
      max_findings_per_group: 2,
      sources_count: 1,
      sinks_count: 2,
      by_rule: { 'sql-injection': 2, xss: 1 },
      by_severity: { high: 2, medium: 1 },
    });
  });

  it('zero findings → only summary line, no [finding] lines', () => {
    setFindingsInstrumentation(true);
    emitFindingsInstrumentation('app.js', [], emptyTaint);

    expect(errorSpy).toHaveBeenCalledTimes(1);
    const line = errorSpy.mock.calls[0][0] as string;
    expect(line.startsWith('[findings-summary] ')).toBe(true);
    const summary = JSON.parse(line.replace('[findings-summary] ', ''));
    expect(summary.total).toBe(0);
    expect(summary.unique_groups).toBe(0);
    expect(summary.max_findings_per_group).toBe(0);
  });

  it('does not mutate the findings array', () => {
    setFindingsInstrumentation(true);
    const findings = [makeFinding()];
    const snapshot = JSON.stringify(findings);
    emitFindingsInstrumentation('app.js', findings, emptyTaint);
    expect(JSON.stringify(findings)).toBe(snapshot);
  });
});
