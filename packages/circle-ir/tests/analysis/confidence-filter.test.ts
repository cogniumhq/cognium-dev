/**
 * Tests for #153 pre-req confidence-based finding filter (3.94.0).
 *
 * Verifies that:
 *   - findings without `confidence` (the pre-3.94.0 default) always pass through
 *   - `'high'` confidence always passes through
 *   - `'medium'` / `'low'` are dropped unless `includeSpeculative` is true
 */

import { describe, it, expect } from 'vitest';
import {
  applyConfidenceFilter,
  isHighConfidence,
} from '../../src/analysis/confidence-filter.js';
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

describe('applyConfidenceFilter (#153 pre-req)', () => {
  it('passes through findings with no confidence field (pre-3.94.0 default)', () => {
    const findings = [makeFinding({ line: 1 }), makeFinding({ line: 2 })];
    expect(applyConfidenceFilter(findings, false)).toEqual(findings);
    expect(applyConfidenceFilter(findings, true)).toEqual(findings);
  });

  it('passes through high-confidence findings in both modes', () => {
    const findings = [
      makeFinding({ line: 1, confidence: 'high' }),
      makeFinding({ line: 2, confidence: 'high' }),
    ];
    expect(applyConfidenceFilter(findings, false)).toEqual(findings);
    expect(applyConfidenceFilter(findings, true)).toEqual(findings);
  });

  it('drops medium-confidence findings when includeSpeculative=false', () => {
    const findings = [
      makeFinding({ line: 1, confidence: 'high' }),
      makeFinding({ line: 2, confidence: 'medium' }),
      makeFinding({ line: 3 }),
    ];
    const result = applyConfidenceFilter(findings, false);
    expect(result).toHaveLength(2);
    expect(result.map(f => f.line)).toEqual([1, 3]);
  });

  it('drops low-confidence findings when includeSpeculative=false', () => {
    const findings = [
      makeFinding({ line: 1, confidence: 'low' }),
      makeFinding({ line: 2, confidence: 'high' }),
    ];
    const result = applyConfidenceFilter(findings, false);
    expect(result).toHaveLength(1);
    expect(result[0].line).toBe(2);
  });

  it('preserves all confidences when includeSpeculative=true', () => {
    const findings = [
      makeFinding({ line: 1, confidence: 'low' }),
      makeFinding({ line: 2, confidence: 'medium' }),
      makeFinding({ line: 3, confidence: 'high' }),
      makeFinding({ line: 4 }),
    ];
    expect(applyConfidenceFilter(findings, true)).toEqual(findings);
  });

  it('returns empty array for empty input in both modes', () => {
    expect(applyConfidenceFilter([], false)).toEqual([]);
    expect(applyConfidenceFilter([], true)).toEqual([]);
  });

  it('does not mutate the input array', () => {
    const findings = [
      makeFinding({ line: 1, confidence: 'medium' }),
      makeFinding({ line: 2 }),
    ];
    const snapshot = [...findings];
    applyConfidenceFilter(findings, false);
    expect(findings).toEqual(snapshot);
  });
});

describe('isHighConfidence (#153 pre-req)', () => {
  it('returns true for undefined confidence', () => {
    expect(isHighConfidence(makeFinding())).toBe(true);
  });

  it('returns true for explicit high confidence', () => {
    expect(isHighConfidence(makeFinding({ confidence: 'high' }))).toBe(true);
  });

  it('returns false for medium confidence', () => {
    expect(isHighConfidence(makeFinding({ confidence: 'medium' }))).toBe(false);
  });

  it('returns false for low confidence', () => {
    expect(isHighConfidence(makeFinding({ confidence: 'low' }))).toBe(false);
  });
});
