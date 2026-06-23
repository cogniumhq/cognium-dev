/**
 * Tests for #142 defensive per-file finding cap.
 *
 * Verifies the cap behaves as a hard threshold: under-cap inputs pass
 * through unchanged; over-cap inputs collapse to a single `saturated-file`
 * advisory carrying the suppressed count + by_rule / by_severity rollup.
 */

import { describe, it, expect } from 'vitest';
import {
  applyPerFileFindingCap,
  DEFAULT_PER_FILE_FINDING_CAP,
  SATURATED_FILE_RULE_ID,
} from '../../src/analysis/per-file-finding-cap.js';
import type { SastFinding } from '../../src/types/index.js';

function makeFinding(over: Partial<SastFinding> = {}): SastFinding {
  return {
    id: `rule-x-app.java-${over.line ?? 1}`,
    pass: 'taint-matcher',
    category: 'security',
    rule_id: 'sql-injection',
    cwe: 'CWE-89',
    severity: 'high',
    level: 'error',
    message: 'SQL injection',
    file: 'app.java',
    line: 1,
    ...over,
  };
}

function makeFindings(count: number, overrides?: (i: number) => Partial<SastFinding>): SastFinding[] {
  return Array.from({ length: count }, (_, i) => makeFinding({ line: i + 1, ...overrides?.(i) }));
}

describe('#142 per-file finding cap', () => {
  it('passes through findings unchanged when count <= cap', () => {
    const findings = makeFindings(50);
    const result = applyPerFileFindingCap('app.java', findings, 100);
    expect(result).toBe(findings);
    expect(result).toHaveLength(50);
  });

  it('passes through findings unchanged when count === cap (boundary)', () => {
    const findings = makeFindings(100);
    const result = applyPerFileFindingCap('app.java', findings, 100);
    expect(result).toBe(findings);
    expect(result).toHaveLength(100);
  });

  it('collapses to a single saturated-file advisory when count > cap', () => {
    const findings = makeFindings(101);
    const result = applyPerFileFindingCap('app.java', findings, 100);

    expect(result).toHaveLength(1);
    const advisory = result[0]!;
    expect(advisory.rule_id).toBe(SATURATED_FILE_RULE_ID);
    expect(advisory.pass).toBe(SATURATED_FILE_RULE_ID);
    expect(advisory.category).toBe('maintainability');
    expect(advisory.severity).toBe('low');
    expect(advisory.level).toBe('note');
    expect(advisory.file).toBe('app.java');
    expect(advisory.line).toBe(1);
    expect(advisory.evidence?.suppressed_count).toBe(101);
    expect(advisory.evidence?.cap).toBe(100);
  });

  it('aggregates by_rule and by_severity in the advisory evidence', () => {
    const findings = [
      ...makeFindings(60, () => ({ rule_id: 'sql-injection', severity: 'high' })),
      ...makeFindings(50, () => ({ rule_id: 'xss', severity: 'medium' })),
    ];
    const result = applyPerFileFindingCap('app.java', findings, 100);

    expect(result).toHaveLength(1);
    const evidence = result[0]!.evidence as {
      suppressed_count: number;
      cap: number;
      by_rule: Record<string, number>;
      by_severity: Record<string, number>;
    };
    expect(evidence.suppressed_count).toBe(110);
    expect(evidence.by_rule).toEqual({ 'sql-injection': 60, xss: 50 });
    expect(evidence.by_severity).toEqual({ high: 60, medium: 50 });
  });

  it('disables the cap when cap === 0', () => {
    const findings = makeFindings(5000);
    const result = applyPerFileFindingCap('app.java', findings, 0);
    expect(result).toBe(findings);
    expect(result).toHaveLength(5000);
  });

  it('disables the cap for negative values (defensive)', () => {
    const findings = makeFindings(2000);
    const result = applyPerFileFindingCap('app.java', findings, -1);
    expect(result).toBe(findings);
    expect(result).toHaveLength(2000);
  });

  it('exposes a default cap of 1000', () => {
    expect(DEFAULT_PER_FILE_FINDING_CAP).toBe(1000);
  });

  it('handles an empty findings array', () => {
    const result = applyPerFileFindingCap('app.java', [], 100);
    expect(result).toEqual([]);
  });
});
