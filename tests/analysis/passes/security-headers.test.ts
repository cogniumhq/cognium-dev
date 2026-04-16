/**
 * Tests for Pass #89: security-headers (category: security)
 */

import { describe, it, expect } from 'vitest';
import { CodeGraph } from '../../../src/graph/code-graph.js';
import { SecurityHeadersPass } from '../../../src/analysis/passes/security-headers-pass.js';
import type {
  CircleIR, SastFinding, TypeInfo, MethodInfo, CallInfo, ArgumentInfo,
} from '../../../src/types/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { TaintConfig } from '../../../src/types/config.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeArg(
  position: number,
  expression: string,
  literal?: string | null,
): ArgumentInfo {
  return { position, expression, literal: literal ?? null };
}

function makeCall(
  method_name: string,
  receiver: string | null,
  line: number,
  args: ArgumentInfo[],
): CallInfo {
  return {
    method_name,
    receiver,
    arguments: args,
    location: { line, column: 0 },
  };
}

function makeMethod(
  name: string,
  start_line: number,
  end_line: number,
  annotations: string[] = [],
): MethodInfo {
  return { name, return_type: null, parameters: [], annotations, modifiers: [], start_line, end_line };
}

function makeType(
  name: string,
  annotations: string[] = [],
  methods: MethodInfo[] = [],
): TypeInfo {
  return {
    name, kind: 'class', package: null, extends: null, implements: [],
    annotations, methods, fields: [], start_line: 1, end_line: 50,
  };
}

function makeIR(
  language: CircleIR['meta']['language'],
  options: { types?: TypeInfo[]; calls?: CallInfo[]; file?: string } = {},
): CircleIR {
  return {
    meta: {
      circle_ir: '3.0',
      file: options.file ?? 'app.ts',
      language,
      loc: 50,
      hash: '',
    },
    types: options.types ?? [],
    calls: options.calls ?? [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {} as CircleIR['enriched'],
  };
}

function runPass(ir: CircleIR): SastFinding[] {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const ctx: PassContext = {
    graph,
    code: '',
    language: ir.meta.language,
    config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
    getResult: () => { throw new Error('not used'); },
    hasResult: () => false,
    addFinding: (f) => findings.push(f),
  };
  new SecurityHeadersPass().run(ctx);
  return findings;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SecurityHeadersPass', () => {
  // ========================================================================
  // Clickjacking rules (CWE-1021)
  // ========================================================================

  describe('missing-x-frame-options', () => {
    it('fires on Java @Controller with no X-Frame-Options set', () => {
      const ir = makeIR('java', {
        types: [makeType('HomeController', ['@RestController'], [
          makeMethod('index', 10, 20, ['@GetMapping']),
        ])],
      });
      const findings = runPass(ir);
      const xframe = findings.filter(f => f.rule_id === 'missing-x-frame-options');
      expect(xframe).toHaveLength(1);
      expect(xframe[0].cwe).toBe('CWE-1021');
      expect(xframe[0].level).toBe('warning');
      expect(xframe[0].line).toBe(1);
    });

    it('fires on Express app.get() route with no X-Frame-Options', () => {
      const ir = makeIR('javascript', {
        calls: [makeCall('get', 'app', 5, [
          makeArg(0, "'/home'", "'/home'"),
          makeArg(1, 'handler'),
        ])],
      });
      const findings = runPass(ir);
      const xframe = findings.filter(f => f.rule_id === 'missing-x-frame-options');
      expect(xframe).toHaveLength(1);
    });

    it('does NOT fire when X-Frame-Options IS set', () => {
      const ir = makeIR('java', {
        types: [makeType('HomeController', ['@RestController'], [
          makeMethod('index', 10, 20, ['@GetMapping']),
        ])],
        calls: [makeCall('setHeader', 'response', 12, [
          makeArg(0, '"X-Frame-Options"', '"X-Frame-Options"'),
          makeArg(1, '"DENY"', '"DENY"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'missing-x-frame-options')).toHaveLength(0);
    });

    it('does NOT fire on library code without HTTP handlers', () => {
      // Plain class, no controller annotations, no route calls.
      const ir = makeIR('java', {
        types: [makeType('UserService', [], [
          makeMethod('getUser', 5, 15),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'missing-x-frame-options')).toHaveLength(0);
    });

    it('matches header name case-insensitively', () => {
      const ir = makeIR('java', {
        types: [makeType('HomeController', ['@Controller'], [
          makeMethod('index', 10, 20, ['@GetMapping']),
        ])],
        calls: [makeCall('setHeader', 'response', 12, [
          makeArg(0, '"x-frame-options"', '"x-frame-options"'),
          makeArg(1, '"DENY"', '"DENY"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'missing-x-frame-options')).toHaveLength(0);
    });
  });

  describe('x-frame-options-allow-from', () => {
    it('fires on X-Frame-Options: ALLOW-FROM example.com', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 15, [
          makeArg(0, '"X-Frame-Options"', '"X-Frame-Options"'),
          makeArg(1, '"ALLOW-FROM https://example.com"', '"ALLOW-FROM https://example.com"'),
        ])],
      });
      const findings = runPass(ir);
      const match = findings.filter(f => f.rule_id === 'x-frame-options-allow-from');
      expect(match).toHaveLength(1);
      expect(match[0].cwe).toBe('CWE-1021');
      expect(match[0].line).toBe(15);
    });

    it('does NOT fire on X-Frame-Options: DENY', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 15, [
          makeArg(0, '"X-Frame-Options"', '"X-Frame-Options"'),
          makeArg(1, '"DENY"', '"DENY"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'x-frame-options-allow-from')).toHaveLength(0);
    });
  });

  describe('missing-csp-frame-ancestors', () => {
    it('fires when CSP is absent on a handler', () => {
      const ir = makeIR('javascript', {
        calls: [makeCall('get', 'app', 5, [
          makeArg(0, "'/home'", "'/home'"),
          makeArg(1, 'handler'),
        ])],
      });
      const findings = runPass(ir);
      const csp = findings.filter(f => f.rule_id === 'missing-csp-frame-ancestors');
      expect(csp).toHaveLength(1);
      expect(csp[0].level).toBe('note');
    });

    it('does NOT fire when Content-Security-Policy IS set', () => {
      const ir = makeIR('javascript', {
        calls: [
          makeCall('get', 'app', 5, [
            makeArg(0, "'/home'", "'/home'"),
            makeArg(1, 'handler'),
          ]),
          makeCall('setHeader', 'res', 8, [
            makeArg(0, '"Content-Security-Policy"', '"Content-Security-Policy"'),
            makeArg(1, "\"frame-ancestors 'self'\"", "\"frame-ancestors 'self'\""),
          ]),
        ],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'missing-csp-frame-ancestors')).toHaveLength(0);
    });
  });

  // ========================================================================
  // CORS rules (CWE-346, CWE-942)
  // ========================================================================

  describe('cors-wildcard-origin', () => {
    it('fires on Access-Control-Allow-Origin: *', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 20, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"*"', '"*"'),
        ])],
      });
      const findings = runPass(ir);
      const wc = findings.filter(f => f.rule_id === 'cors-wildcard-origin');
      expect(wc).toHaveLength(1);
      expect(wc[0].level).toBe('error');
      expect(wc[0].severity).toBe('high');
      expect(wc[0].cwe).toBe('CWE-942');
    });

    it('does NOT fire on a specific origin', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 20, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"https://trusted.example.com"', '"https://trusted.example.com"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'cors-wildcard-origin')).toHaveLength(0);
    });
  });

  describe('cors-null-origin', () => {
    it('fires on Access-Control-Allow-Origin: null', () => {
      const ir = makeIR('javascript', {
        calls: [makeCall('setHeader', 'res', 42, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"null"', '"null"'),
        ])],
      });
      const findings = runPass(ir);
      const nulo = findings.filter(f => f.rule_id === 'cors-null-origin');
      expect(nulo).toHaveLength(1);
      expect(nulo[0].cwe).toBe('CWE-346');
    });
  });

  describe('cors-http-origin', () => {
    it('fires on http:// origin', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 30, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"http://example.com"', '"http://example.com"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'cors-http-origin')).toHaveLength(1);
    });

    it('does NOT fire on https:// origin', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 30, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"https://example.com"', '"https://example.com"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'cors-http-origin')).toHaveLength(0);
    });
  });

  describe('cors-reflected-origin', () => {
    it('fires when value is a dynamic expression (no literal)', () => {
      const ir = makeIR('javascript', {
        calls: [makeCall('setHeader', 'res', 50, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, 'req.headers.origin', null),   // NO literal → reflected
        ])],
      });
      const findings = runPass(ir);
      const refl = findings.filter(f => f.rule_id === 'cors-reflected-origin');
      expect(refl).toHaveLength(1);
      expect(refl[0].level).toBe('error');
      expect(refl[0].evidence).toMatchObject({
        header: 'Access-Control-Allow-Origin',
        value: null,
        kind: 'unsafe-value',
      });
    });

    it('does NOT fire when value is a string literal', () => {
      const ir = makeIR('javascript', {
        calls: [makeCall('setHeader', 'res', 50, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"https://safe.example.com"', '"https://safe.example.com"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'cors-reflected-origin')).toHaveLength(0);
    });
  });

  // ========================================================================
  // Structural behavior
  // ========================================================================

  describe('pass structure', () => {
    it('has correct name and category', () => {
      const pass = new SecurityHeadersPass();
      expect(pass.name).toBe('security-headers');
      expect(pass.category).toBe('security');
    });

    it('returns result with writtenHeaders and hasHandler', () => {
      const ir = makeIR('java', {
        types: [makeType('HomeController', ['@RestController'], [
          makeMethod('index', 10, 20, ['@GetMapping']),
        ])],
        calls: [makeCall('setHeader', 'response', 12, [
          makeArg(0, '"X-Frame-Options"', '"X-Frame-Options"'),
          makeArg(1, '"DENY"', '"DENY"'),
        ])],
      });
      const graph = new CodeGraph(ir);
      const ctx: PassContext = {
        graph,
        code: '',
        language: 'java',
        config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
        getResult: () => { throw new Error('not used'); },
        hasResult: () => false,
        addFinding: () => {},
      };
      const result = new SecurityHeadersPass().run(ctx);
      expect(result.hasHandler).toBe(true);
      expect(result.writtenHeaders.has('x-frame-options')).toBe(true);
    });

    it('accepts custom rule tables via options', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 5, [
          makeArg(0, '"X-Custom"', '"X-Custom"'),
          makeArg(1, '"bad"', '"bad"'),
        ])],
      });
      const graph = new CodeGraph(ir);
      const findings: SastFinding[] = [];
      const ctx: PassContext = {
        graph,
        code: '',
        language: 'java',
        config: { sources: [], sinks: [], sanitizers: [] } as TaintConfig,
        getResult: () => { throw new Error('not used'); },
        hasResult: () => false,
        addFinding: (f) => findings.push(f),
      };
      new SecurityHeadersPass({
        rules: [{
          rule_id: 'custom-bad-header',
          cwe: 'CWE-0000',
          level: 'error',
          severity: 'critical',
          header: 'X-Custom',
          kind: 'weak-value',
          valuePattern: /^bad$/,
          message: 'Bad custom header value',
        }],
      }).run(ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].rule_id).toBe('custom-bad-header');
    });

    it('emits stable finding IDs', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 20, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"*"', '"*"'),
        ])],
        file: 'src/MyController.java',
      });
      const findings = runPass(ir);
      expect(findings[0].id).toBe('cors-wildcard-origin-src/MyController.java-20');
    });

    it('still fires value-based rules even without a handler', () => {
      // cors-wildcard-origin has no requiresHandler → should fire anywhere
      // a setHeader call appears.
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 20, [
          makeArg(0, '"Access-Control-Allow-Origin"', '"Access-Control-Allow-Origin"'),
          makeArg(1, '"*"', '"*"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'cors-wildcard-origin')).toHaveLength(1);
    });
  });

  // ========================================================================
  // Java constant resolution (HttpHeaders.X_FRAME_OPTIONS etc.)
  // ========================================================================

  describe('constant resolution', () => {
    it('resolves HttpHeaders.X_FRAME_OPTIONS to X-Frame-Options', () => {
      const ir = makeIR('java', {
        types: [makeType('FramingConfigServlet', ['@Controller'], [
          makeMethod('doGet', 10, 30, ['@RequestMapping']),
        ])],
        calls: [makeCall('setHeader', 'response', 15, [
          makeArg(0, 'HttpHeaders.X_FRAME_OPTIONS'),  // constant, no literal
          makeArg(1, '"ALLOW-FROM https://evil.com"', '"ALLOW-FROM https://evil.com"'),
        ])],
      });
      const findings = runPass(ir);
      // Should fire x-frame-options-allow-from (weak-value)
      const af = findings.filter(f => f.rule_id === 'x-frame-options-allow-from');
      expect(af).toHaveLength(1);
      expect(af[0].line).toBe(15);
      // Should NOT fire missing-x-frame-options (the header was set)
      expect(findings.filter(f => f.rule_id === 'missing-x-frame-options')).toHaveLength(0);
    });

    it('resolves HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN to Access-Control-Allow-Origin', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 22, [
          makeArg(0, 'HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN'),  // constant
          makeArg(1, '"*"', '"*"'),
        ])],
      });
      const findings = runPass(ir);
      expect(findings.filter(f => f.rule_id === 'cors-wildcard-origin')).toHaveLength(1);
    });

    it('resolves bare SCREAMING_SNAKE_CASE constant (no class prefix)', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 8, [
          makeArg(0, 'X_FRAME_OPTIONS'),  // bare constant
          makeArg(1, '"DENY"', '"DENY"'),
        ])],
      });
      const findings = runPass(ir);
      // X-Frame-Options is set with DENY → missing rule should NOT fire
      // and ALLOW-FROM should NOT fire
      expect(findings.filter(f => f.rule_id === 'x-frame-options-allow-from')).toHaveLength(0);
    });

    it('resolves CONTENT_SECURITY_POLICY constant', () => {
      const ir = makeIR('java', {
        types: [makeType('MyController', ['@RestController'], [
          makeMethod('index', 10, 20, ['@GetMapping']),
        ])],
        calls: [makeCall('addHeader', 'response', 14, [
          makeArg(0, 'HttpHeaders.CONTENT_SECURITY_POLICY'),
          makeArg(1, '"frame-ancestors \'self\'"', '"frame-ancestors \'self\'"'),
        ])],
      });
      const findings = runPass(ir);
      // CSP is set → missing-csp-frame-ancestors should NOT fire
      expect(findings.filter(f => f.rule_id === 'missing-csp-frame-ancestors')).toHaveLength(0);
    });

    it('does NOT resolve single-word identifiers (not SCREAMING_SNAKE_CASE)', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 10, [
          makeArg(0, 'headerName'),  // variable, not constant
          makeArg(1, '"*"', '"*"'),
        ])],
      });
      const findings = runPass(ir);
      // headerName is not resolvable → call is skipped → no cors-wildcard finding
      expect(findings.filter(f => f.rule_id === 'cors-wildcard-origin')).toHaveLength(0);
    });

    it('detects reflected origin via constant header name', () => {
      const ir = makeIR('java', {
        calls: [makeCall('setHeader', 'response', 25, [
          makeArg(0, 'HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN'),
          makeArg(1, 'request.getHeader("Origin")'),  // dynamic → reflected
        ])],
      });
      const findings = runPass(ir);
      const refl = findings.filter(f => f.rule_id === 'cors-reflected-origin');
      expect(refl).toHaveLength(1);
      expect(refl[0].line).toBe(25);
    });
  });
});
