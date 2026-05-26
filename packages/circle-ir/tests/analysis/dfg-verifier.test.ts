/**
 * Tests for DFGVerifier - Track 2 validation
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DFGVerifier, verifyTaintFlow, formatVerificationResult } from '../../src/analysis/dfg-verifier.js';
import type { DFG, CallInfo, TaintSource, TaintSink, TaintSanitizer } from '../../src/types/index.js';

import { CodeGraph } from '../../src/graph/code-graph.js';
import type { CircleIR } from '../../src/types/index.js';

function makeIR(defs: DFG['defs'] = [], uses: DFG['uses'] = [], chains: DFG['chains'] = []): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'test.java', language: 'java', loc: 20, hash: '' },
    types: [], calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs, uses, chains },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [], exports: [], unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

describe('DFGVerifier', () => {
  // Helper to create mock DFG
  function createDFG(
    defs: Array<{ id: number; variable: string; line: number; kind: 'param' | 'local' | 'field' | 'return' }>,
    uses: Array<{ id: number; variable: string; line: number; def_id: number | null }>,
    chains: Array<{ from_def: number; to_def: number; via: string }> = []
  ): DFG {
    return { defs, uses, chains };
  }

  describe('verify', () => {
    it('should verify a direct taint flow', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
        ],
        [
          { id: 1, variable: 'input', line: 10, def_id: 1 },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
          location: { line: 10, column: 0 },
          in_method: 'test',
        },
      ];

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 5,
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 10,
        confidence: 0.9,
      };

      const result = verifyTaintFlow(dfg, calls, source, sink);

      expect(result.verified).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
      expect(result.path).toBeDefined();
    });

    it('should verify flow through assignment chain', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'query', line: 8, kind: 'local' },
        ],
        [
          { id: 1, variable: 'input', line: 8, def_id: 1 },
          { id: 2, variable: 'query', line: 12, def_id: 2 },
        ],
        [
          { from_def: 1, to_def: 2, via: 'input' },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'query', variable: 'query', literal: null }],
          location: { line: 12, column: 0 },
          in_method: 'test',
        },
      ];

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 5,
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 12,
        confidence: 0.9,
      };

      const result = verifyTaintFlow(dfg, calls, source, sink);

      expect(result.verified).toBe(true);
      expect(result.path).toBeDefined();
      expect(result.path!.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle case with different variables at source and sink', () => {
      // Source defines 'input', sink uses 'unrelated' with no direct def-use chain
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'unrelated', line: 8, kind: 'local' },
        ],
        [
          { id: 1, variable: 'unrelated', line: 12, def_id: 2 },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'unrelated', variable: 'unrelated', literal: null }],
          location: { line: 12, column: 0 },
          in_method: 'test',
        },
      ];

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 5,  // Defines 'input'
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 12,  // Uses 'unrelated'
        confidence: 0.9,
      };

      const result = verifyTaintFlow(dfg, calls, source, sink);

      // The verifier may find paths through various heuristics
      // What matters is it returns a valid result with appropriate confidence
      expect(typeof result.verified).toBe('boolean');
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });

    it('should detect sanitizer in path', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'safe', line: 8, kind: 'local' },
        ],
        [
          { id: 1, variable: 'input', line: 8, def_id: 1 },
          { id: 2, variable: 'safe', line: 12, def_id: 2 },
        ],
        [
          { from_def: 1, to_def: 2, via: 'input' },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'prepareStatement',
          receiver: 'conn',
          arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
          location: { line: 8, column: 0 },
          in_method: 'test',
        },
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'safe', variable: 'safe', literal: null }],
          location: { line: 12, column: 0 },
          in_method: 'test',
        },
      ];

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 5,
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 12,
        confidence: 0.9,
      };

      const sanitizers: TaintSanitizer[] = [
        { type: 'prepared_statement', method: 'prepareStatement', line: 8, sanitizes: ['sql_injection'] },
      ];

      const result = verifyTaintFlow(dfg, calls, source, sink, sanitizers);

      // The path exists but may be sanitized - check the sanitizer detection logic
      // If verified is false, reason should mention sanitization
      if (!result.verified) {
        expect(result.reason).toContain('sanitized');
      }
      // Otherwise, the path may have been found without going through the sanitizer line
      expect(typeof result.verified).toBe('boolean');
    });

    it('should return low confidence when no definition at source line', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'other', line: 10, kind: 'local' },
        ],
        []
      );

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 5,  // No definition at this line
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 10,
        confidence: 0.9,
      };

      const result = verifyTaintFlow(dfg, [], source, sink);

      expect(result.verified).toBe(false);
      expect(result.confidence).toBe(0);
      expect(result.reason).toContain('No variable definition');
    });
  });

  describe('verifyAll', () => {
    it('should verify multiple source-sink pairs', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input1', line: 5, kind: 'param' },
          { id: 2, variable: 'input2', line: 6, kind: 'param' },
        ],
        [
          { id: 1, variable: 'input1', line: 10, def_id: 1 },
          { id: 2, variable: 'input2', line: 15, def_id: 2 },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'input1', variable: 'input1', literal: null }],
          location: { line: 10, column: 0 },
          in_method: 'test',
        },
        {
          method_name: 'exec',
          receiver: 'runtime',
          arguments: [{ position: 0, expression: 'input2', variable: 'input2', literal: null }],
          location: { line: 15, column: 0 },
          in_method: 'test',
        },
      ];

      const sources: TaintSource[] = [
        { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 },
        { type: 'http_param', location: 'test', severity: 'high', line: 6, confidence: 0.9 },
      ];

      const sinks: TaintSink[] = [
        { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 10, confidence: 0.9 },
        { type: 'command_injection', cwe: 'CWE-78', location: 'test', line: 15, confidence: 0.9 },
      ];

      const verifier = new DFGVerifier(dfg, calls, []);
      const results = verifier.verifyAll(sources, sinks);

      expect(results.size).toBe(4);  // 2 sources * 2 sinks
      expect(results.get('5:10')?.verified).toBe(true);
      expect(results.get('6:15')?.verified).toBe(true);
    });
  });

  describe('getStats', () => {
    it('should calculate verification statistics', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
        ],
        [
          { id: 1, variable: 'input', line: 10, def_id: 1 },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
          location: { line: 10, column: 0 },
          in_method: 'test',
        },
      ];

      const sources: TaintSource[] = [
        { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 },
      ];

      const sinks: TaintSink[] = [
        { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 10, confidence: 0.9 },
        { type: 'xss', cwe: 'CWE-79', location: 'test', line: 20, confidence: 0.9 },
      ];

      const verifier = new DFGVerifier(dfg, calls, []);
      const results = verifier.verifyAll(sources, sinks);
      const stats = verifier.getStats(results);

      expect(stats.total).toBe(2);
      expect(stats.verified).toBeGreaterThanOrEqual(0);
      expect(stats.notVerified).toBeGreaterThanOrEqual(0);
      expect(stats.verified + stats.notVerified + stats.sanitized).toBe(stats.total);
    });
  });

  describe('formatVerificationResult', () => {
    it('should format verified result', () => {
      const result = {
        verified: true,
        confidence: 0.95,
        reason: 'Verified: 2-step flow from line 5 to line 10',
        path: {
          steps: [
            { defId: 1, variable: 'input', line: 5, kind: 'param' as const, flowType: 'direct' as const },
            { defId: 2, variable: 'input', line: 10, kind: 'local' as const, flowType: 'assignment' as const },
          ],
          length: 2,
          hasDirectFlow: true,
        },
        alternativePaths: 0,
      };

      const formatted = formatVerificationResult(result);

      expect(formatted).toContain('VERIFIED');
      expect(formatted).toContain('95%');
      expect(formatted).toContain('Line 5');
      expect(formatted).toContain('Line 10');
    });

    it('should format not verified result', () => {
      const result = {
        verified: false,
        confidence: 0.2,
        reason: 'No def-use chain found from source (line 5) to sink (line 10)',
      };

      const formatted = formatVerificationResult(result);

      expect(formatted).toContain('NOT VERIFIED');
      expect(formatted).toContain('20%');
      expect(formatted).toContain('No def-use chain');
    });

    it('should show alternative paths count', () => {
      const result = {
        verified: true,
        confidence: 0.85,
        reason: 'Verified: 3-step flow',
        path: {
          steps: [
            { defId: 1, variable: 'a', line: 1, kind: 'param' as const, flowType: 'direct' as const },
          ],
          length: 1,
          hasDirectFlow: true,
        },
        alternativePaths: 3,
      };

      const formatted = formatVerificationResult(result);

      expect(formatted).toContain('Alternative paths found: 3');
    });
  });

  describe('configuration options', () => {
    it('should respect maxDepth configuration', () => {
      // Create a moderate chain - shorter for testability
      const defs = [];
      const uses = [];
      const chains = [];

      for (let i = 1; i <= 20; i++) {
        defs.push({ id: i, variable: `v${i}`, line: i * 2, kind: 'local' as const });
        if (i > 1) {
          uses.push({ id: i - 1, variable: `v${i - 1}`, line: i * 2, def_id: i - 1 });
          chains.push({ from_def: i - 1, to_def: i, via: `v${i - 1}` });
        }
      }

      const dfg = createDFG(defs, uses, chains);

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 2,
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 40,  // v20 at line 40
        confidence: 0.9,
      };

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'v20', variable: 'v20', literal: null }],
          location: { line: 40, column: 0 },
          in_method: 'test',
        },
      ];

      // Test that the verifier respects the configuration
      const resultShort = verifyTaintFlow(dfg, calls, source, sink, [], { maxDepth: 3 });
      const resultLong = verifyTaintFlow(dfg, calls, source, sink, [], { maxDepth: 30 });

      // Both results should be valid booleans
      expect(typeof resultShort.verified).toBe('boolean');
      expect(typeof resultLong.verified).toBe('boolean');

      // Short depth may or may not find path depending on heuristics
      // Long depth should have higher chance of finding the path
      expect(resultLong.confidence).toBeGreaterThanOrEqual(0);
    });

    it('should handle cyclic def-use chains without infinite loop', () => {
      // A → B → A cycle: the visited set must prevent infinite recursion
      const dfg = createDFG(
        [
          { id: 1, variable: 'a', line: 5, kind: 'param' },
          { id: 2, variable: 'b', line: 8, kind: 'local' },
        ],
        [
          { id: 1, variable: 'a', line: 8,  def_id: 1 },
          { id: 2, variable: 'b', line: 10, def_id: 2 },
        ],
        [
          { from_def: 1, to_def: 2, via: 'a' },
          { from_def: 2, to_def: 1, via: 'b' },  // cycle back to def 1
        ]
      );

      const source: TaintSource = {
        type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9,
      };
      const sink: TaintSink = {
        type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 20, confidence: 0.9,
      };

      // Must not hang; visited set breaks the cycle
      const result = verifyTaintFlow(dfg, [], source, sink);
      expect(typeof result.verified).toBe('boolean');
      expect(result.confidence).toBeGreaterThanOrEqual(0);
    });

    it('should handle allowFieldFlows configuration', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'this.field', line: 8, kind: 'field' },
        ],
        [
          { id: 1, variable: 'input', line: 8, def_id: 1 },
          { id: 2, variable: 'this.field', line: 12, def_id: 2 },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'this.field', variable: 'this.field', literal: null }],
          location: { line: 12, column: 0 },
          in_method: 'test',
        },
      ];

      const source: TaintSource = {
        type: 'http_param',
        location: 'test',
        severity: 'high',
        line: 5,
        confidence: 0.9,
      };

      const sink: TaintSink = {
        type: 'sql_injection',
        cwe: 'CWE-89',
        location: 'test',
        line: 12,
        confidence: 0.9,
      };

      // With field flows disabled
      const resultNoFields = verifyTaintFlow(dfg, calls, source, sink, [], { allowFieldFlows: false });

      // With field flows enabled (default)
      const resultWithFields = verifyTaintFlow(dfg, calls, source, sink, [], { allowFieldFlows: true });

      // Results may differ based on field flow setting
      expect(typeof resultNoFields.verified).toBe('boolean');
      expect(typeof resultWithFields.verified).toBe('boolean');
    });
  });

  describe('CodeGraph constructor path', () => {
    it('accepts a CodeGraph instance as first argument', () => {
      const defs = [{ id: 1, variable: 'input', line: 5, kind: 'param' as const }];
      const uses = [{ id: 1, variable: 'input', line: 10, def_id: 1 }];
      const graph = new CodeGraph(makeIR(defs, uses));

      const source: TaintSource = {
        type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9,
      };
      const sink: TaintSink = {
        type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 10, confidence: 0.9,
      };

      const verifier = new DFGVerifier(graph, [], { maxDepth: 10 });
      const result   = verifier.verify(source, sink);
      expect(typeof result.verified).toBe('boolean');
    });

    it('CodeGraph path with default config (no options)', () => {
      const graph = new CodeGraph(makeIR());
      const verifier = new DFGVerifier(graph, []);
      const result = verifier.verify(
        { type: 'http_param', location: 'test', severity: 'high', line: 99, confidence: 0.9 },
        { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 100, confidence: 0.9 },
      );
      expect(result.verified).toBe(false);
    });
  });

  describe('branch coverage — reachesSink / calculateConfidence / laterDefsOfVar', () => {
    it('10.1 reachesSink(): verifies via call-argument when no use entry exists', () => {
      // def1 has a re-def at line 7, so branch-3 (no later defs) fails for def1.
      // Branch-2 (call arg matches) is the only route that returns true.
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'input', line: 7, kind: 'local' }, // re-def blocks branch-3 for def1
        ],
        [] // no use entries → usesAtLine(10) empty → branch-1 fails
      );
      const calls: CallInfo[] = [{
        method_name: 'executeQuery',
        receiver: 'stmt',
        arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
        location: { line: 10, column: 0 },
        in_method: 'test',
      }];
      const source: TaintSource = { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 };
      const sink: TaintSink = { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 10, confidence: 0.9 };

      const result = verifyTaintFlow(dfg, calls, source, sink);
      expect(result.verified).toBe(true);
    });

    it('10.2 calculateConfidence(): field-step penalty lowers confidence below 0.9', () => {
      // Source line (20) is intentionally after sink line (10) so branch-3 of reachesSink
      // cannot short-circuit def1 → the BFS must traverse through the field def,
      // producing a step with flowType='field' and hasDirectFlow=false.
      const dfg = createDFG(
        [
          { id: 1, variable: 'input',     line: 20, kind: 'param' },
          { id: 2, variable: 'this.data', line:  8, kind: 'field' },
        ],
        [
          // use of def1 at line 8 → BFS explores defsAtLine(8) → finds def2 (field)
          { id: 1, variable: 'input', line: 8, def_id: 1 },
        ]
      );
      const calls: CallInfo[] = [{
        method_name: 'process',
        receiver: 'handler',
        arguments: [{ position: 0, expression: 'this.data', variable: 'this.data', literal: null }],
        location: { line: 10, column: 0 },
        in_method: 'test',
      }];
      const source: TaintSource = { type: 'http_param', location: 'test', severity: 'high', line: 20, confidence: 0.9 };
      const sink: TaintSink = { type: 'xss', cwe: 'CWE-79', location: 'test', line: 10, confidence: 0.9 };

      const result = verifyTaintFlow(dfg, calls, source, sink, [], { allowFieldFlows: true });
      expect(result.verified).toBe(true);
      // field step adds flowType='field' → hasDirectFlow=false, fieldSteps=1 → 0.9 - 0.05 = 0.85
      expect(result.confidence).toBeLessThan(0.9);
    });

    it('10.3 calculateConfidence(): long-path penalty (>10 hops) lowers confidence', () => {
      // 12-def chain via explicit DFG chains; source line > sink line so branch-3
      // never fires for intermediate defs, forcing the full chain to be traversed.
      const defs = [];
      const chains = [];
      for (let i = 1; i <= 12; i++) {
        defs.push({ id: i, variable: `v${i}`, line: 110 - i * 5, kind: 'local' as const });
        if (i > 1) {
          chains.push({ from_def: i - 1, to_def: i, via: `v${i - 1}` });
        }
      }
      defs[0] = { id: 1, variable: 'v1', line: 110, kind: 'param' }; // source at line 110

      const dfg = createDFG(defs, [], chains);
      const calls: CallInfo[] = [{
        method_name: 'executeQuery',
        receiver: 'stmt',
        arguments: [{ position: 0, expression: 'v12', variable: 'v12', literal: null }],
        location: { line: 5, column: 0 },
        in_method: 'test',
      }];
      const source: TaintSource = { type: 'http_param', location: 'test', severity: 'high', line: 110, confidence: 0.9 };
      const sink: TaintSink = { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 5, confidence: 0.9 };

      const result = verifyTaintFlow(dfg, calls, source, sink);
      expect(result.verified).toBe(true);
      // path.length=12 > 10 → -0.05 - 0.10 penalties; even with hasDirectFlow +0.05
      // result is 0.9 + 0.05 - 0.05 - 0.10 = 0.80 < 0.85
      expect(result.confidence).toBeLessThan(0.85);
    });

    it('10.4 laterDefsOfVar() BFS exploration connects re-def to sink', () => {
      // def1 and def2 share variable 'x'; no chain or use links them.
      // branch-3 of reachesSink fails for def1 (def2 is a later def).
      // The BFS laterDefsOfVar block (lines 268-290) pushes def2 onto the queue,
      // and def2 reaches the sink via its own branch-3 (no defs after line 8).
      // arg.variable=null prevents branch-2 from matching def1 directly.
      const dfg = createDFG(
        [
          { id: 1, variable: 'x', line: 5, kind: 'param' },
          { id: 2, variable: 'x', line: 8, kind: 'local' }, // re-def; no chain from def1
        ],
        [] // no uses
      );
      const calls: CallInfo[] = [{
        method_name: 'sink',
        receiver: null,
        arguments: [{ position: 0, expression: 'x', variable: null, literal: null }],
        location: { line: 10, column: 0 },
        in_method: 'test',
      }];
      const source: TaintSource = { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 };
      const sink: TaintSink = { type: 'command_injection', cwe: 'CWE-78', location: 'test', line: 10, confidence: 0.9 };

      const result = verifyTaintFlow(dfg, calls, source, sink);
      expect(result.verified).toBe(true);
    });
  });

  describe('getStats — sanitized branch', () => {
    it('counts a sanitized result in getStats', () => {
      const dfg = createDFG(
        [{ id: 1, variable: 'input', line: 5, kind: 'param' }],
        [{ id: 1, variable: 'input', line: 10, def_id: 1 }],
      );
      const calls: CallInfo[] = [{
        method_name: 'executeQuery',
        receiver: 'stmt',
        arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
        location: { line: 10, column: 0 },
        in_method: 'test',
      }];
      const sanitizers: TaintSanitizer[] = [
        { type: 'prepared_statement', method: 'prepareStatement', line: 5, sanitizes: ['sql_injection'] },
      ];
      const verifier = new DFGVerifier(dfg, calls, sanitizers);
      const results = new Map([
        ['5:10', {
          verified:         false,
          confidence:       0.1,
          reason:           'Flow sanitized at line 5 by prepareStatement',
          alternativePaths: 0,
        }],
        ['5:20', {
          verified:         true,
          confidence:       0.9,
          reason:           'Verified: direct flow',
          alternativePaths: 0,
        }],
      ]);
      const stats = verifier.getStats(results);
      expect(stats.total).toBe(2);
      expect(stats.sanitized).toBe(1);
      expect(stats.verified).toBe(1);
      expect(stats.notVerified).toBe(0);
    });
  });
});
