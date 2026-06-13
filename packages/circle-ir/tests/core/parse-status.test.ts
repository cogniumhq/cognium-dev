/**
 * Parse-status regression tests (issue #27).
 *
 * Previously tree-sitter parse failures were silently swallowed: extractors
 * ran on partial trees and produced an IR indistinguishable from a clean
 * parse. With #27 wired, every analyze() return now carries a structured
 * `parse_status` field so callers (CLI, circle-ir-ai) can surface dropped
 * files instead of treating them as 0-finding scans.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { extractParseStatus, parse, disposeTree } from '../../src/core/index.js';

describe('parse_status (issue #27)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('extractParseStatus helper', () => {
    it('returns success=true with empty locations for a clean parse', async () => {
      const tree = await parse('package com.example; public class Foo {}', 'java');
      try {
        const status = extractParseStatus(tree);
        expect(status.success).toBe(true);
        expect(status.has_errors).toBe(false);
        expect(status.error_count).toBe(0);
        expect(status.error_locations).toEqual([]);
      } finally {
        disposeTree(tree);
      }
    });

    it('reports has_errors=true for malformed Java with a missing brace', async () => {
      const broken = `
package com.example;
public class Broken {
    public void method() {
        int x = 1;
    // missing closing brace for method
}
`;
      const tree = await parse(broken, 'java');
      try {
        const status = extractParseStatus(tree);
        expect(status.success).toBe(false);
        expect(status.has_errors).toBe(true);
        expect(status.error_count).toBeGreaterThan(0);
        expect(status.error_locations.length).toBeGreaterThan(0);
        expect(status.error_locations[0]).toHaveProperty('line');
        expect(status.error_locations[0]).toHaveProperty('column');
      } finally {
        disposeTree(tree);
      }
    });

    it('caps error_locations at 50 even when error_count is higher', async () => {
      // Generate many syntactically broken statements
      const lines: string[] = ['public class Many {'];
      for (let i = 0; i < 120; i++) {
        lines.push(`    int x${i} = ( ;`); // unterminated parenthesis
      }
      lines.push('}');
      const tree = await parse(lines.join('\n'), 'java');
      try {
        const status = extractParseStatus(tree);
        expect(status.has_errors).toBe(true);
        expect(status.error_locations.length).toBeLessThanOrEqual(50);
      } finally {
        disposeTree(tree);
      }
    });

    it('reports stray-token errors at the lexer level', async () => {
      // Stray characters that tree-sitter cannot reduce
      const tree = await parse('public class @@@', 'java');
      try {
        const status = extractParseStatus(tree);
        expect(status.has_errors).toBe(true);
        expect(status.error_count).toBeGreaterThan(0);
      } finally {
        disposeTree(tree);
      }
    });
  });

  describe('analyze() integration', () => {
    it('attaches parse_status with success=true on clean Java', async () => {
      const ir = await analyze(
        'package com.example; public class Foo { public void bar() {} }',
        'Foo.java',
        'java',
      );
      expect(ir.parse_status).toBeDefined();
      expect(ir.parse_status?.success).toBe(true);
      expect(ir.parse_status?.has_errors).toBe(false);
      expect(ir.parse_status?.error_count).toBe(0);
    });

    it('attaches parse_status with has_errors=true on malformed Java', async () => {
      const broken = `
package com.example;
public class Broken {
    public void method() {
        int x = 1
    }
`;
      const ir = await analyze(broken, 'Broken.java', 'java');
      expect(ir.parse_status).toBeDefined();
      expect(ir.parse_status?.has_errors).toBe(true);
      expect(ir.parse_status?.error_count).toBeGreaterThan(0);
      expect(ir.parse_status?.error_locations.length).toBeGreaterThan(0);
    });

    it('attaches parse_status with success=true on clean JavaScript', async () => {
      const ir = await analyze(
        'function add(a, b) { return a + b; }',
        'add.js',
        'javascript',
      );
      expect(ir.parse_status?.success).toBe(true);
    });

    it('attaches parse_status with has_errors=true on malformed JavaScript', async () => {
      const ir = await analyze(
        'function broken( { return 1; }',
        'broken.js',
        'javascript',
      );
      expect(ir.parse_status?.has_errors).toBe(true);
      expect(ir.parse_status?.error_count).toBeGreaterThan(0);
    });

    it('attaches parse_status with success=true on clean Python', async () => {
      const ir = await analyze(
        'def add(a, b):\n    return a + b\n',
        'add.py',
        'python',
      );
      expect(ir.parse_status?.success).toBe(true);
    });

    it('parse_status.error_locations have 1-based lines', async () => {
      // Force a syntax error on a known line
      const code = 'class Foo {\n    int x = (\n}';
      const ir = await analyze(code, 'Foo.java', 'java');
      expect(ir.parse_status?.has_errors).toBe(true);
      const lines = ir.parse_status?.error_locations.map(loc => loc.line) ?? [];
      // No location should ever be 0 (1-based per spec)
      for (const line of lines) {
        expect(line).toBeGreaterThanOrEqual(1);
      }
    });
  });

  describe('HTML preprocessor', () => {
    it('attaches parse_status on clean HTML', async () => {
      const html = `<!DOCTYPE html>
<html>
  <body>
    <script>var x = 1;</script>
  </body>
</html>`;
      const ir = await analyze(html, 'page.html', 'html');
      expect(ir.parse_status).toBeDefined();
      // Tree-sitter HTML grammar is permissive, but the field should exist
      expect(ir.parse_status?.success).toBe(true);
    });
  });
});
