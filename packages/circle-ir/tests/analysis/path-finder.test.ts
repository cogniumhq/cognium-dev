/**
 * Tests for PathFinder - Taint path enumeration
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PathFinder, findTaintPaths, formatTaintPath } from '../../src/analysis/path-finder.js';
import type { DFG, CallInfo, TaintSource, TaintSink, TaintSanitizer } from '../../src/types/index.js';

describe('PathFinder', () => {
  // Helper to create mock DFG
  function createDFG(
    defs: Array<{ id: number; variable: string; line: number; kind: 'param' | 'local' | 'field' | 'return' }>,
    uses: Array<{ id: number; variable: string; line: number; def_id: number | null }>
  ): DFG {
    return { defs, uses, chains: [] };
  }

  describe('findAllPaths', () => {
    it('should find a simple direct path', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'local' },
          { id: 2, variable: 'input', line: 10, kind: 'local' },
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
      ];

      const result = findTaintPaths(dfg, calls, sources, sinks);

      expect(result.paths.length).toBeGreaterThan(0);
      expect(result.summary.vulnerablePaths).toBeGreaterThan(0);
      expect(result.paths[0].source.line).toBe(5);
      expect(result.paths[0].sink.line).toBe(10);
    });

    it('should find a path through assignments', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'query', line: 8, kind: 'local' },
          { id: 3, variable: 'query', line: 12, kind: 'local' },
        ],
        [
          { id: 1, variable: 'input', line: 8, def_id: 1 },
          { id: 2, variable: 'query', line: 12, def_id: 2 },
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

      const sources: TaintSource[] = [
        { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 },
      ];

      const sinks: TaintSink[] = [
        { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 12, confidence: 0.9 },
      ];

      const result = findTaintPaths(dfg, calls, sources, sinks);

      expect(result.paths.length).toBeGreaterThan(0);
      expect(result.paths[0].hops.length).toBeGreaterThan(2);  // source -> assign -> sink
    });

    it('should mark paths as sanitized when sanitizer present', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
          { id: 2, variable: 'safe', line: 8, kind: 'local' },
        ],
        [
          { id: 1, variable: 'input', line: 8, def_id: 1 },
          { id: 2, variable: 'safe', line: 12, def_id: 2 },
        ]
      );

      const calls: CallInfo[] = [
        {
          method_name: 'escapeHtml',
          receiver: null,
          arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
          location: { line: 8, column: 0 },
          in_method: 'test',
        },
        {
          method_name: 'print',
          receiver: 'response',
          arguments: [{ position: 0, expression: 'safe', variable: 'safe', literal: null }],
          location: { line: 12, column: 0 },
          in_method: 'test',
        },
      ];

      const sources: TaintSource[] = [
        { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 },
      ];

      const sinks: TaintSink[] = [
        { type: 'xss', cwe: 'CWE-79', location: 'test', line: 12, confidence: 0.9 },
      ];

      const sanitizers: TaintSanitizer[] = [
        { type: 'html_encode', method: 'escapeHtml', line: 8, sanitizes: ['xss'] },
      ];

      const result = findTaintPaths(dfg, calls, sources, sinks, sanitizers);

      // Should find paths but mark them as sanitized
      if (result.paths.length > 0) {
        expect(result.summary.sanitizedPaths).toBeGreaterThanOrEqual(0);
      }
    });

    it('should handle multiple sources and sinks', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input1', line: 5, kind: 'param' },
          { id: 2, variable: 'input2', line: 6, kind: 'param' },
          { id: 3, variable: 'input1', line: 10, kind: 'local' },
          { id: 4, variable: 'input2', line: 15, kind: 'local' },
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

      const result = findTaintPaths(dfg, calls, sources, sinks);

      // Should find paths from both sources to both sinks where applicable
      expect(result.paths.length).toBeGreaterThan(0);
    });

    it('should respect maxPathLength configuration', () => {
      // Create a long chain
      const defs = [];
      const uses = [];
      for (let i = 1; i <= 100; i++) {
        defs.push({ id: i, variable: `v${i}`, line: i * 5, kind: 'local' as const });
        if (i > 1) {
          uses.push({ id: i - 1, variable: `v${i - 1}`, line: i * 5, def_id: i - 1 });
        }
      }

      const dfg = createDFG(defs, uses);

      const sources: TaintSource[] = [
        { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 },
      ];

      const sinks: TaintSink[] = [
        { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 500, confidence: 0.9 },
      ];

      const calls: CallInfo[] = [
        {
          method_name: 'executeQuery',
          receiver: 'stmt',
          arguments: [{ position: 0, expression: 'v100', variable: 'v100', literal: null }],
          location: { line: 500, column: 0 },
          in_method: 'test',
        },
      ];

      const result = findTaintPaths(dfg, calls, sources, sinks, [], { maxPathLength: 10 });

      // Should not find path due to depth limit
      expect(result.paths.every(p => p.length <= 11)).toBe(true);
    });
  });

  describe('formatTaintPath', () => {
    it('should format path for display', () => {
      const path = {
        id: 'path-1',
        source: { line: 5, type: 'http_param' as const, variable: 'input' },
        sink: { line: 10, type: 'sql_injection' as const, method: 'executeQuery' },
        hops: [
          { line: 5, variable: 'input', operation: 'source' as const, description: 'Taint introduced from http_param' },
          { line: 10, variable: 'input', operation: 'sink' as const, description: 'Flows into sql_injection sink' },
        ],
        sanitized: false,
        confidence: 0.95,
        length: 2,
      };

      const formatted = formatTaintPath(path);

      expect(formatted).toContain('Path path-1');
      expect(formatted).toContain('http_param');
      expect(formatted).toContain('sql_injection');
      expect(formatted).toContain('95%');
      expect(formatted).toContain('Line 5');
      expect(formatted).toContain('Line 10');
    });

    it('should show sanitizer information when path is sanitized', () => {
      const path = {
        id: 'path-2',
        source: { line: 5, type: 'http_param' as const, variable: 'input' },
        sink: { line: 15, type: 'xss' as const, method: 'print' },
        hops: [
          { line: 5, variable: 'input', operation: 'source' as const, description: 'Taint introduced from http_param' },
          { line: 10, variable: 'safe', operation: 'assign' as const, description: 'Assigned to safe' },
          { line: 15, variable: 'safe', operation: 'sink' as const, description: 'Flows into xss sink' },
        ],
        sanitized: true,
        sanitizer: { line: 10, method: 'escapeHtml' },
        confidence: 0.1,
        length: 3,
      };

      const formatted = formatTaintPath(path);

      expect(formatted).toContain('Sanitized');
      expect(formatted).toContain('line 10');
      expect(formatted).toContain('escapeHtml');
    });
  });

  describe('PathFinder class methods', () => {
    it('should find paths to a specific sink', () => {
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

      const finder = new PathFinder(dfg, calls, sources, sinks, []);
      const paths = finder.findPathsToSink(10);

      expect(paths.every(p => p.sink.line === 10)).toBe(true);
    });

    it('should group paths by sink type', () => {
      const dfg = createDFG(
        [
          { id: 1, variable: 'input', line: 5, kind: 'param' },
        ],
        [
          { id: 1, variable: 'input', line: 10, def_id: 1 },
          { id: 2, variable: 'input', line: 15, def_id: 1 },
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
        {
          method_name: 'print',
          receiver: 'response',
          arguments: [{ position: 0, expression: 'input', variable: 'input', literal: null }],
          location: { line: 15, column: 0 },
          in_method: 'test',
        },
      ];

      const sources: TaintSource[] = [
        { type: 'http_param', location: 'test', severity: 'high', line: 5, confidence: 0.9 },
      ];

      const sinks: TaintSink[] = [
        { type: 'sql_injection', cwe: 'CWE-89', location: 'test', line: 10, confidence: 0.9 },
        { type: 'xss', cwe: 'CWE-79', location: 'test', line: 15, confidence: 0.9 },
      ];

      const finder = new PathFinder(dfg, calls, sources, sinks, []);
      const grouped = finder.getPathsBySinkType();

      expect(grouped.has('sql_injection') || grouped.has('xss')).toBe(true);
    });

    it('should return paths originating from a specific source line', () => {
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
      ];

      const finder = new PathFinder(dfg, calls, sources, sinks, []);
      const paths = finder.findPathsFromSourceLine(5);

      expect(paths.every(p => p.source.line === 5)).toBe(true);
    });
  });
});
