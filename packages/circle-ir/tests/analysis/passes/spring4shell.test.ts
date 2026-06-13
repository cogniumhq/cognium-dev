/**
 * Tests for Spring4ShellPass — CVE-2022-22965 implicit form-data binding RCE.
 *
 * Uses minimal IR fixtures (no WASM parsing) so the matching predicates are
 * exercised in isolation. End-to-end tests run via the wider analyze() path
 * are covered by the integration smoke tests at the bottom of this file.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { CodeGraph } from '../../../src/graph/index.js';
import type { PassContext } from '../../../src/graph/analysis-pass.js';
import type { CircleIR, SastFinding } from '../../../src/types/index.js';
import { Spring4ShellPass } from '../../../src/analysis/passes/spring4shell-pass.js';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeIR(overrides: Partial<CircleIR> = {}): CircleIR {
  return {
    meta: { circle_ir: '3.0', file: 'FooController.java', language: 'java', loc: 40, hash: '' },
    types: [],
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: {},
    ...overrides,
  };
}

function makeCtx(ir: CircleIR, language?: string): PassContext & { findings: SastFinding[] } {
  const graph = new CodeGraph(ir);
  const findings: SastFinding[] = [];
  const results = new Map<string, unknown>();
  return {
    graph,
    code: '',
    language: language ?? ir.meta.language,
    config: { sources: [], sinks: [] } as unknown as PassContext['config'],
    getResult: <T>(name: string) => results.get(name) as T,
    hasResult: (name: string) => results.has(name),
    addFinding: (f: SastFinding) => { findings.push(f); },
    findings,
  };
}

function param(
  name: string,
  type: string | null,
  annotations: string[] = [],
  line?: number,
) {
  return { name, type, annotations, line };
}

function method(
  name: string,
  parameters: ReturnType<typeof param>[],
  annotations: string[] = [],
  startLine = 10,
) {
  return {
    name,
    return_type: 'String' as const,
    parameters,
    annotations,
    modifiers: ['public'],
    start_line: startLine,
    end_line: startLine + 5,
  };
}

function controllerClass(
  className: string,
  methods: ReturnType<typeof method>[],
  classAnnotations: string[] = ['Controller'],
) {
  return {
    name: className,
    kind: 'class' as const,
    package: null,
    extends: null,
    implements: [] as string[],
    annotations: classAnnotations,
    methods,
    fields: [] as never[],
    start_line: 1,
    end_line: 40,
  };
}

// ---------------------------------------------------------------------------
// Positive cases (vulnerable shapes)
// ---------------------------------------------------------------------------

describe('Spring4ShellPass — positive cases', () => {
  it('fires on @Controller + @RequestMapping with naked POJO param', () => {
    const ir = makeIR({
      types: [
        controllerClass('Foo', [
          method('bar', [param('bean', 'MyBean', [], 12)], ['RequestMapping("/bar")'], 11),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);

    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].rule_id).toBe('spring4shell');
    expect(ctx.findings[0].cwe).toBe('CWE-94');
    expect(ctx.findings[0].severity).toBe('high');
    expect(ctx.findings[0].level).toBe('error');
    expect(ctx.findings[0].line).toBe(12);
    expect(ctx.findings[0].message).toContain('Foo.bar');
    expect(ctx.findings[0].message).toContain('MyBean');
  });

  it('fires on @RestController + @PostMapping with naked POJO param', () => {
    const ir = makeIR({
      types: [
        controllerClass('UserApi', [
          method('create', [param('user', 'UserDto')], ['PostMapping("/users")']),
        ], ['RestController']),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].message).toContain('UserApi.create');
  });

  it.each([
    ['GetMapping'],
    ['PostMapping'],
    ['PutMapping'],
    ['DeleteMapping'],
    ['PatchMapping'],
    ['RequestMapping'],
  ])('fires for route annotation @%s', (route) => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('bean', 'MyBean')], [route]),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
  });

  it('fires when only ONE of multiple parameters is naked', () => {
    const ir = makeIR({
      types: [
        controllerClass('Mixed', [
          method('handler', [
            param('id', 'String', ['RequestParam']),       // safe
            param('user', 'UserDto'),                       // VULNERABLE
            param('req', 'HttpServletRequest'),             // framework-resolved
          ], ['RequestMapping("/m")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].evidence?.parameter_name).toBe('user');
  });

  it('fires on @ControllerAdvice (also data-binds)', () => {
    const ir = makeIR({
      types: [
        controllerClass('GlobalAdvice', [
          method('handle', [param('bean', 'MyBean')], ['RequestMapping("/x")']),
        ], ['ControllerAdvice']),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
  });

  it('produces one finding per vulnerable parameter in same method', () => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [
            param('a', 'AaaDto'),
            param('b', 'BbbDto'),
          ], ['PostMapping("/m")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(2);
  });

  it('fires on POJO array params (e.g. UserDto[])', () => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('users', 'UserDto[]')], ['PostMapping("/u")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
  });

  it('strips generics on parameter type', () => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('bean', 'GenericBean<String, Integer>')], ['PostMapping("/g")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].evidence?.parameter_type).toBe('GenericBean<String, Integer>');
  });
});

// ---------------------------------------------------------------------------
// Negative cases (FP regression — must not fire on benign shapes)
// ---------------------------------------------------------------------------

describe('Spring4ShellPass — FP regression', () => {
  it.each([
    ['RequestBody'],
    ['RequestParam'],
    ['PathVariable'],
    ['RequestHeader'],
    ['CookieValue'],
    ['MatrixVariable'],
    ['ModelAttribute'],
    ['Valid'],
    ['Validated'],
    ['RequestPart'],
    ['SessionAttribute'],
    ['RequestAttribute'],
  ])('does NOT fire when parameter has @%s', (binding) => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('bean', 'UserDto', [binding])], ['PostMapping("/m")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT fire on @RequestBody with arguments e.g. @RequestBody(required = false)', () => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('bean', 'UserDto', ['RequestBody(required = false)'])], ['PostMapping("/m")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it.each([
    'String', 'CharSequence',
    'int', 'long', 'boolean', 'double',
    'Integer', 'Long', 'Boolean', 'Double',
    'BigInteger', 'BigDecimal',
    'UUID',
    'Date', 'LocalDate', 'LocalDateTime', 'Instant',
    'List', 'Set', 'Optional', 'Collection',
  ])('does NOT fire on scalar/simple type %s', (type) => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('p', type)], ['GetMapping("/p")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it.each([
    'HttpServletRequest',
    'HttpServletResponse',
    'HttpSession',
    'Model',
    'ModelMap',
    'BindingResult',
    'Principal',
    'Authentication',
    'Locale',
    'MultipartFile',
    'RedirectAttributes',
    'WebRequest',
    'UriComponentsBuilder',
    'HttpEntity',
    'ServerWebExchange',
  ])('does NOT fire on Spring framework type %s', (type) => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('p', type)], ['PostMapping("/p")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT fire when class is not a controller', () => {
    const ir = makeIR({
      types: [
        controllerClass('Service', [
          method('m', [param('bean', 'UserDto')], ['RequestMapping("/m")']),
        ], ['Service']),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT fire when method has no route annotation', () => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('helper', [param('bean', 'UserDto')], ['Transactional']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT fire when parameter type is unknown (null)', () => {
    const ir = makeIR({
      types: [
        controllerClass('C', [
          method('m', [param('p', null)], ['PostMapping("/p")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT fire on non-Java languages', () => {
    const ir = makeIR({
      meta: { circle_ir: '3.0', file: 'foo.py', language: 'python', loc: 40, hash: '' },
      types: [
        controllerClass('C', [
          method('m', [param('bean', 'UserDto')], ['PostMapping("/m")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir, 'python');
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does NOT fire on primitive-only handlers (OWASP Benchmark-style scalar controllers)', () => {
    const ir = makeIR({
      types: [
        controllerClass('BenchmarkTest', [
          method('handle', [
            param('req', 'HttpServletRequest'),
            param('res', 'HttpServletResponse'),
          ], ['RequestMapping("/BenchmarkTest00001")']),
        ]),
      ],
    });
    const ctx = makeCtx(ir);
    new Spring4ShellPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Integration via analyze() — exercises the WASM parser + analyzer pipeline
// ---------------------------------------------------------------------------

describe('Spring4ShellPass — analyze() integration', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports finding on the canonical Spring4Shell controller shape', async () => {
    const code = `
package com.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class FooController {

    @RequestMapping("/bar")
    public String bar(MyBean bean) {
        return "ok";
    }
}
`;
    const ir = await analyze(code, 'FooController.java', 'java');
    const findings = ir.findings?.filter(f => f.rule_id === 'spring4shell') ?? [];
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].cwe).toBe('CWE-94');
    expect(findings[0].severity).toBe('high');
  });

  it('does NOT report on Spring REST controller that uses @RequestBody (JSON)', async () => {
    const code = `
package com.example;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserApi {

    @PostMapping("/users")
    public String create(@RequestBody UserDto user) {
        return user.toString();
    }
}
`;
    const ir = await analyze(code, 'UserApi.java', 'java');
    const findings = ir.findings?.filter(f => f.rule_id === 'spring4shell') ?? [];
    expect(findings).toHaveLength(0);
  });

  it('does NOT report on scalar @RequestParam handler', async () => {
    const code = `
package com.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ScalarController {

    @GetMapping("/echo")
    public String echo(@RequestParam String name) {
        return name;
    }
}
`;
    const ir = await analyze(code, 'ScalarController.java', 'java');
    const findings = ir.findings?.filter(f => f.rule_id === 'spring4shell') ?? [];
    expect(findings).toHaveLength(0);
  });

  it('does NOT report on classic Java servlet (no Spring annotations)', async () => {
    const code = `
package com.example;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LegacyServlet extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse res) {
        String name = req.getParameter("name");
    }
}
`;
    const ir = await analyze(code, 'LegacyServlet.java', 'java');
    const findings = ir.findings?.filter(f => f.rule_id === 'spring4shell') ?? [];
    expect(findings).toHaveLength(0);
  });
});
