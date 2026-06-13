/**
 * Tests for the `discoveryMethod` provenance plumbing on
 * `generateFindings` (#26).
 *
 * The static path of consumers like cognium-ai's `runReport` already
 * delegates to `generateFindings`, which applies a DFG-reachability
 * gate. The LLM path historically emitted an N×M cross-product instead
 * of calling `generateFindings`, because the function didn't carry
 * any provenance signal that the LLM path needs (downstream reporters
 * filter/weight LLM-discovered vulnerabilities differently).
 *
 * 3.45.0 widens `TaintSource`, `TaintSink`, and `Finding.verification`
 * to carry an optional `discoveryMethod` of `'static' | 'llm'`
 * (`'static' | 'llm' | 'mixed'` on the finding). The DFG gate, the
 * dedup behavior, the severity rules, and the confidence math are
 * unchanged — this is pure metadata plumbing.
 */

import { describe, it, expect } from 'vitest';
import { generateFindings } from '../../src/analysis/findings.js';
import type { TaintSource, TaintSink, DFG } from '../../src/types/index.js';

// Empty DFG forces the proximity fallback path inside `generateFindings`,
// which is sufficient to exercise the provenance plumbing without
// having to parse real code.
const emptyDfg: DFG = { defs: [], uses: [], chains: [] };

function makeSource(over: Partial<TaintSource> = {}): TaintSource {
  return {
    type: 'http_param',
    location: 'request.getParameter("q")',
    severity: 'high',
    line: 10,
    confidence: 0.9,
    ...over,
  };
}

function makeSink(over: Partial<TaintSink> = {}): TaintSink {
  return {
    type: 'sql_injection',
    cwe: 'CWE-89',
    location: 'stmt.execute(q)',
    line: 12,
    confidence: 0.9,
    ...over,
  };
}

describe('generateFindings: discoveryMethod plumbing (#26)', () => {
  describe('finding-level provenance', () => {
    it('static source + static sink → discoveryMethod: "static"', () => {
      const findings = generateFindings(
        [makeSource({ discoveryMethod: 'static' })],
        [makeSink({ discoveryMethod: 'static' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('static');
    });

    it('absent discoveryMethod on both inputs → "static" (back-compat)', () => {
      const findings = generateFindings(
        [makeSource()],
        [makeSink()],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('static');
    });

    it('llm source + llm sink → discoveryMethod: "llm"', () => {
      const findings = generateFindings(
        [makeSource({ discoveryMethod: 'llm' })],
        [makeSink({ discoveryMethod: 'llm' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('llm');
    });

    it('llm source + static sink → discoveryMethod: "mixed"', () => {
      const findings = generateFindings(
        [makeSource({ discoveryMethod: 'llm' })],
        [makeSink({ discoveryMethod: 'static' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('mixed');
    });

    it('static source + llm sink → discoveryMethod: "mixed"', () => {
      const findings = generateFindings(
        [makeSource({ discoveryMethod: 'static' })],
        [makeSink({ discoveryMethod: 'llm' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('mixed');
    });

    it('llm source + absent sink → discoveryMethod: "mixed" (absent === static)', () => {
      const findings = generateFindings(
        [makeSource({ discoveryMethod: 'llm' })],
        [makeSink()],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('mixed');
    });
  });

  describe('dedup merges provenance correctly', () => {
    it('two static sources reaching same sink → "static"', () => {
      const findings = generateFindings(
        [
          makeSource({ discoveryMethod: 'static', line: 8 }),
          makeSource({ discoveryMethod: 'static', line: 9 }),
        ],
        [makeSink({ discoveryMethod: 'static' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('static');
      const sources = findings[0].evidence?.sources as Array<{ file: string; line: number }>;
      expect(sources.length).toBe(2);
    });

    it('two llm sources reaching same sink → "llm"', () => {
      const findings = generateFindings(
        [
          makeSource({ discoveryMethod: 'llm', line: 8 }),
          makeSource({ discoveryMethod: 'llm', line: 9 }),
        ],
        [makeSink({ discoveryMethod: 'llm' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('llm');
    });

    it('one static + one llm source reaching same sink → "mixed"', () => {
      const findings = generateFindings(
        [
          makeSource({ discoveryMethod: 'static', line: 8 }),
          makeSource({ discoveryMethod: 'llm', line: 9 }),
        ],
        [makeSink({ discoveryMethod: 'static' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('mixed');
      const sources = findings[0].evidence?.sources as Array<{ file: string; line: number }>;
      expect(sources.length).toBe(2);
    });

    it('merged provenance survives a higher-confidence overwrite', () => {
      // The lower-confidence source comes first; the higher-confidence one
      // overwrites the primary fields. The merged discoveryMethod must
      // not be silently lost when verification is replaced.
      const findings = generateFindings(
        [
          makeSource({ discoveryMethod: 'llm', line: 8, confidence: 0.4 }),
          makeSource({ discoveryMethod: 'static', line: 9, confidence: 0.95 }),
        ],
        [makeSink({ discoveryMethod: 'static' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].verification.discoveryMethod).toBe('mixed');
    });
  });

  describe('DFG-reachability gate is unchanged', () => {
    it('llm-discovered source + sink far apart with empty DFG → no finding', () => {
      // 1000 lines apart, no DFG path, no proximity → must be dropped
      // regardless of provenance. (This is the architectural invariant
      // the LLM-path adoption depends on.)
      const findings = generateFindings(
        [makeSource({ discoveryMethod: 'llm', line: 10 })],
        [makeSink({ discoveryMethod: 'llm', line: 1010 })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(0);
    });

    it('source type that cannot reach sink type → no finding even when llm', () => {
      // env_input cannot reach sql_injection per the canSourceReachSink
      // mapping; widening must not bypass that gate.
      const findings = generateFindings(
        [makeSource({ type: 'env_input', discoveryMethod: 'llm' })],
        [makeSink({ discoveryMethod: 'llm' })],
        emptyDfg,
        'test.java',
      );
      expect(findings).toHaveLength(0);
    });
  });
});
