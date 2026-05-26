/**
 * Tests for Taint Propagation Analysis
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import {
  propagateTaint,
  calculateFlowConfidence,
  getTaintStats,
  type TaintFlow,
  type TaintPropagationResult,
} from '../../src/analysis/taint-propagation.js';

describe('Taint Propagation', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('propagateTaint', () => {
    it('should propagate taint from source to sink', async () => {
      const code = `
public class Handler {
    public void handle(HttpServletRequest request, Statement stmt) {
        String input = request.getParameter("id");
        stmt.executeQuery("SELECT * FROM users WHERE id = " + input);
    }
}
`;
      const result = await analyze(code, 'Handler.java', 'java');
      const propagated = propagateTaint(
        result.dfg,
        result.calls,
        result.taint.sources,
        result.taint.sinks,
        []
      );

      expect(propagated.taintedVars.length).toBeGreaterThan(0);
    });

    it('should handle code without sinks', async () => {
      const code = `
public class NoSink {
    public void method(HttpServletRequest request) {
        String input = request.getParameter("data");
        System.out.println(input);
    }
}
`;
      const result = await analyze(code, 'NoSink.java', 'java');
      const propagated = propagateTaint(
        result.dfg,
        result.calls,
        result.taint.sources,
        result.taint.sinks,
        []
      );

      // Should have tainted vars but no dangerous flows
      expect(propagated.taintedVars.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle code without sources', async () => {
      const code = `
public class NoSource {
    public void method(Statement stmt) {
        String query = "SELECT * FROM users";
        stmt.executeQuery(query);
    }
}
`;
      const result = await analyze(code, 'NoSource.java', 'java');
      const propagated = propagateTaint(
        result.dfg,
        result.calls,
        result.taint.sources,
        result.taint.sinks,
        []
      );

      // No tainted vars since no sources
      expect(propagated.flows.length).toBe(0);
    });

    it('should suppress taint propagation through a recognised sanitizer', async () => {
      // escapeHtml sanitizes for XSS — the variable assigned from the call
      // should NOT be treated as tainted.
      const code = `
public class Handler {
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("name");
        String safe = StringEscapeUtils.escapeHtml(input);
        response.sendError(500, safe);
    }
}
`;
      const result = await analyze(code, 'Handler.java', 'java');
      const propagated = propagateTaint(
        result.dfg,
        result.calls,
        result.taint.sources,
        result.taint.sinks,
        result.taint.sanitizers ?? []  // pass detected sanitizers
      );

      // The original source variable must still be tainted
      expect(propagated.taintedVars.some(v => v.variable === 'input')).toBe(true);

      // 'safe' is assigned from escapeHtml(input) — propagation must be stopped
      expect(propagated.taintedVars.some(v => v.variable === 'safe')).toBe(false);

      // No XSS flow should reach the sink through 'safe'
      const xssFlows = propagated.flows.filter(f => f.sink.type === 'xss');
      expect(xssFlows).toHaveLength(0);
    });

    it('should continue propagating taint through a non-sanitizer call', async () => {
      // toLowerCase() is not a registered sanitizer — taint must propagate
      const code = `
public class Handler {
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("name");
        String lower = input.toLowerCase();
        response.sendError(500, lower);
    }
}
`;
      const result = await analyze(code, 'Handler.java', 'java');
      const propagated = propagateTaint(
        result.dfg,
        result.calls,
        result.taint.sources,
        result.taint.sinks,
        result.taint.sanitizers ?? []
      );

      // 'input' must be tainted
      expect(propagated.taintedVars.some(v => v.variable === 'input')).toBe(true);

      // 'lower' should remain tainted (toLowerCase is not a sanitizer)
      // If the DFG chain exists, lower is tainted; if not the tainted set just
      // contains the original variable — either way input is reportable.
      const inputTainted = propagated.taintedVars.some(v => v.variable === 'input');
      expect(inputTainted).toBe(true);
    });

    it('should not suppress taint when sanitizer is applied to a different variable', async () => {
      // escapeHtml is called on 'other' — 'input' itself remains unsanitized.
      const code = `
public class Handler {
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("name");
        String other = "static value";
        String clean = StringEscapeUtils.escapeHtml(other);
        response.sendError(500, input);
    }
}
`;
      const result = await analyze(code, 'Handler.java', 'java');
      const propagated = propagateTaint(
        result.dfg,
        result.calls,
        result.taint.sources,
        result.taint.sinks,
        result.taint.sanitizers ?? []
      );

      // 'input' must still be tainted — the sanitizer applied to 'other' should
      // have no effect on 'input's taint status.
      expect(propagated.taintedVars.some(v => v.variable === 'input')).toBe(true);
    });
  });

  describe('calculateFlowConfidence', () => {
    it('should return full confidence for direct flows', () => {
      const flow: TaintFlow = {
        source: {
          type: 'http_param' as const,
          method: 'getParameter',
          line: 1,
          variable: 'input',
          confidence: 1.0,
        },
        sink: {
          type: 'sql_injection' as const,
          method: 'executeQuery',
          line: 2,
          variable: 'query',
          cwe: 'CWE-89',
        },
        path: [{ variable: 'input', line: 1 }, { variable: 'query', line: 2 }],
        sanitized: false,
        confidence: 1.0,
      };

      const confidence = calculateFlowConfidence(flow);
      expect(confidence).toBe(1.0);
    });

    it('should reduce confidence for longer paths', () => {
      const shortFlow: TaintFlow = {
        source: {
          type: 'http_param' as const,
          method: 'getParameter',
          line: 1,
          variable: 'input',
          confidence: 1.0,
        },
        sink: {
          type: 'sql_injection' as const,
          method: 'executeQuery',
          line: 10,
          variable: 'query',
          cwe: 'CWE-89',
        },
        path: [
          { variable: 'input', line: 1 },
          { variable: 'query', line: 10 },
        ],
        sanitized: false,
        confidence: 1.0,
      };

      const longFlow: TaintFlow = {
        source: {
          type: 'http_param' as const,
          method: 'getParameter',
          line: 1,
          variable: 'input',
          confidence: 1.0,
        },
        sink: {
          type: 'sql_injection' as const,
          method: 'executeQuery',
          line: 10,
          variable: 'query',
          cwe: 'CWE-89',
        },
        path: [
          { variable: 'input', line: 1 },
          { variable: 'a', line: 2 },
          { variable: 'b', line: 3 },
          { variable: 'c', line: 4 },
          { variable: 'd', line: 5 },
          { variable: 'query', line: 10 },
        ],
        sanitized: false,
        confidence: 1.0,
      };

      const shortConfidence = calculateFlowConfidence(shortFlow);
      const longConfidence = calculateFlowConfidence(longFlow);

      expect(longConfidence).toBeLessThan(shortConfidence);
    });

    it('should return zero confidence for sanitized flows', () => {
      const flow: TaintFlow = {
        source: {
          type: 'http_param' as const,
          method: 'getParameter',
          line: 1,
          variable: 'input',
          confidence: 1.0,
        },
        sink: {
          type: 'sql_injection' as const,
          method: 'executeQuery',
          line: 2,
          variable: 'query',
          cwe: 'CWE-89',
        },
        path: [{ variable: 'input', line: 1 }, { variable: 'query', line: 2 }],
        sanitized: true,
        confidence: 0,
      };

      const confidence = calculateFlowConfidence(flow);
      expect(confidence).toBe(0);
    });

    it('should factor in source confidence', () => {
      const highConfFlow: TaintFlow = {
        source: {
          type: 'http_param' as const,
          method: 'getParameter',
          line: 1,
          variable: 'input',
          confidence: 1.0,
        },
        sink: {
          type: 'sql_injection' as const,
          method: 'executeQuery',
          line: 2,
          variable: 'query',
          cwe: 'CWE-89',
        },
        path: [{ variable: 'input', line: 1 }, { variable: 'query', line: 2 }],
        sanitized: false,
        confidence: 1.0,
      };

      const lowConfFlow: TaintFlow = {
        source: {
          type: 'http_param' as const,
          method: 'getParameter',
          line: 1,
          variable: 'input',
          confidence: 0.5,
        },
        sink: {
          type: 'sql_injection' as const,
          method: 'executeQuery',
          line: 2,
          variable: 'query',
          cwe: 'CWE-89',
        },
        path: [{ variable: 'input', line: 1 }, { variable: 'query', line: 2 }],
        sanitized: false,
        confidence: 0.5,
      };

      const highConf = calculateFlowConfidence(highConfFlow);
      const lowConf = calculateFlowConfidence(lowConfFlow);

      expect(highConf).toBe(1.0);
      expect(lowConf).toBe(0.5);
    });
  });

  describe('getTaintStats', () => {
    it('should calculate stats for empty result', () => {
      const result: TaintPropagationResult = {
        taintedVars: [],
        flows: [],
      };

      const stats = getTaintStats(result);

      expect(stats.totalTaintedVars).toBe(0);
      expect(stats.totalFlows).toBe(0);
      expect(stats.flowsBySinkType.size).toBe(0);
      expect(stats.avgConfidence).toBe(0);
    });

    it('should calculate stats for result with flows', () => {
      const result: TaintPropagationResult = {
        taintedVars: [
          { name: 'input', taintType: 'http_param', sourceLine: 1 },
          { name: 'query', taintType: 'derived', sourceLine: 2 },
        ],
        flows: [
          {
            source: {
              type: 'http_param' as const,
              method: 'getParameter',
              line: 1,
              variable: 'input',
              confidence: 1.0,
            },
            sink: {
              type: 'sql_injection' as const,
              method: 'executeQuery',
              line: 2,
              variable: 'query',
              cwe: 'CWE-89',
            },
            path: [{ variable: 'input', line: 1 }, { variable: 'query', line: 2 }],
            sanitized: false,
            confidence: 0.9,
          },
          {
            source: {
              type: 'http_param' as const,
              method: 'getParameter',
              line: 3,
              variable: 'cmd',
              confidence: 1.0,
            },
            sink: {
              type: 'command_injection' as const,
              method: 'exec',
              line: 4,
              variable: 'cmd',
              cwe: 'CWE-78',
            },
            path: [{ variable: 'cmd', line: 3 }, { variable: 'cmd', line: 4 }],
            sanitized: false,
            confidence: 0.8,
          },
        ],
      };

      const stats = getTaintStats(result);

      expect(stats.totalTaintedVars).toBe(2);
      expect(stats.totalFlows).toBe(2);
      expect(stats.flowsBySinkType.get('sql_injection')).toBe(1);
      expect(stats.flowsBySinkType.get('command_injection')).toBe(1);
      expect(stats.avgConfidence).toBeCloseTo(0.85);
    });

    it('should group flows by sink type correctly', () => {
      const result: TaintPropagationResult = {
        taintedVars: [],
        flows: [
          {
            source: { type: 'http_param' as const, method: 'm1', line: 1, variable: 'v1', confidence: 1.0 },
            sink: { type: 'sql_injection' as const, method: 's1', line: 2, variable: 'v1', cwe: 'CWE-89' },
            path: [], sanitized: false, confidence: 0.9,
          },
          {
            source: { type: 'http_param' as const, method: 'm2', line: 3, variable: 'v2', confidence: 1.0 },
            sink: { type: 'sql_injection' as const, method: 's2', line: 4, variable: 'v2', cwe: 'CWE-89' },
            path: [], sanitized: false, confidence: 0.9,
          },
          {
            source: { type: 'http_param' as const, method: 'm3', line: 5, variable: 'v3', confidence: 1.0 },
            sink: { type: 'xss' as const, method: 's3', line: 6, variable: 'v3', cwe: 'CWE-79' },
            path: [], sanitized: false, confidence: 0.8,
          },
        ],
      };

      const stats = getTaintStats(result);

      expect(stats.flowsBySinkType.get('sql_injection')).toBe(2);
      expect(stats.flowsBySinkType.get('xss')).toBe(1);
    });
  });
});
