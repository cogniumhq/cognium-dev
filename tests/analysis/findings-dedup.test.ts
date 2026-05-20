/**
 * Tests for generateFindings() cross-product deduplication.
 *
 * When multiple taint sources reach the same sink, the N×M cross-product
 * should collapse into one finding per (sink.line, type), aggregating
 * contributing sources in `evidence.sources`.
 */

import { describe, it, expect } from 'vitest';
import { generateFindings } from '../../src/analysis/findings.js';
import type { TaintSource, TaintSink, DFG } from '../../src/types/index.js';

function makeSource(line: number, type = 'http_param'): TaintSource {
  return {
    type,
    location: `param_${line}`,
    line,
    confidence: 0.9,
    method: `getParam${line}`,
  };
}

function makeSink(line: number, type: 'sql_injection' | 'xss' = 'sql_injection'): TaintSink {
  return {
    type,
    cwe: type === 'sql_injection' ? 'CWE-89' : 'CWE-79',
    location: `query_${line}`,
    line,
    confidence: 0.9,
    method: `exec${line}`,
  };
}

const emptyDfg: DFG = { defs: [], uses: [], chains: [] };

describe('generateFindings deduplication', () => {
  it('3 sources × 1 sink → 1 finding with 3 evidence sources', () => {
    const sources = [makeSource(10), makeSource(20), makeSource(30)];
    const sinks = [makeSink(50)];

    const findings = generateFindings(sources, sinks, emptyDfg, 'app.js');

    expect(findings).toHaveLength(1);
    expect(findings[0].sink.line).toBe(50);
    expect(findings[0].type).toBe('sql_injection');

    const evidenceSources = findings[0].evidence?.sources as Array<{ line: number }>;
    expect(evidenceSources).toHaveLength(3);
    expect(evidenceSources.map(s => s.line).sort((a, b) => a - b)).toEqual([10, 20, 30]);
  });

  it('2 sources × 2 sinks → 2 findings', () => {
    const sources = [makeSource(10), makeSource(20)];
    const sinks = [makeSink(50), makeSink(60)];

    const findings = generateFindings(sources, sinks, emptyDfg, 'app.js');

    expect(findings).toHaveLength(2);
    const lines = findings.map(f => f.sink.line).sort((a, b) => a - b);
    expect(lines).toEqual([50, 60]);
  });

  it('1 source × 1 sink → 1 finding (no change)', () => {
    const sources = [makeSource(10)];
    const sinks = [makeSink(50)];

    const findings = generateFindings(sources, sinks, emptyDfg, 'app.js');

    expect(findings).toHaveLength(1);
    const evidenceSources = findings[0].evidence?.sources as Array<{ line: number }>;
    expect(evidenceSources).toHaveLength(1);
  });

  it('keeps highest confidence source as primary', () => {
    const sources = [
      { ...makeSource(10), confidence: 0.5 },
      { ...makeSource(20), confidence: 0.95 },
    ];
    const sinks = [makeSink(50)];

    const findings = generateFindings(sources, sinks, emptyDfg, 'app.js');

    expect(findings).toHaveLength(1);
    // The highest-confidence source (line 20) should be the primary
    expect(findings[0].source.line).toBe(20);
  });

  it('deduplicates by (sink.line, type) — different types remain separate', () => {
    const sources = [makeSource(10)];
    // Same sink line but different types
    const sinks = [makeSink(50, 'sql_injection'), makeSink(50, 'xss')];

    const findings = generateFindings(sources, sinks, emptyDfg, 'app.js');

    // sql_injection and xss at the same line should be separate findings
    expect(findings).toHaveLength(2);
    const types = findings.map(f => f.type).sort();
    expect(types).toEqual(['sql_injection', 'xss']);
  });
});
