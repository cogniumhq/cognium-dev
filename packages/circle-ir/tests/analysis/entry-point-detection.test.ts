/**
 * Tests for the entry-point tier classifier (cognium-dev#128).
 *
 * Ship 1 scope: Java-only Tier 1 detection (annotation-driven), with
 * Tier 2 (call-graph reachability) deferred and every non-Tier-1 Java
 * method classified as Tier 3. Non-Java languages return TIER_UNKNOWN
 * so the gate is pass-through.
 *
 * Ported verbatim from
 * `cognium-ai/circle-ir-ai/tests/analysis/entry-point-detection.test.ts`
 * with fixture helpers adapted to construct full `MethodInfo` /
 * `TypeInfo` records (the AI-side `MethodShape` / `TypeShape` aliases
 * omitted a few circle-ir-required fields like `modifiers`,
 * `return_type`, `package`, `methods`, `fields`).
 *
 * Reference: cognium-dev#128 implementation plan §7.1.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyEntryPointTier,
  shouldGateInterproceduralParam,
  type EntryPointContext,
} from '../../src/analysis/entry-point-detection.js';
import type { TypeInfo, MethodInfo, ParameterInfo } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const javaCtx: EntryPointContext = { language: 'java' };
const pythonCtx: EntryPointContext = { language: 'python' };

function param(opts: Partial<ParameterInfo> & { name: string }): ParameterInfo {
  return {
    name: opts.name,
    type: opts.type ?? null,
    annotations: opts.annotations ?? [],
  };
}

function method(name: string, opts: Partial<MethodInfo> = {}): MethodInfo {
  return {
    name,
    return_type: opts.return_type ?? null,
    parameters: opts.parameters ?? [],
    annotations: opts.annotations ?? [],
    modifiers: opts.modifiers ?? [],
    start_line: opts.start_line ?? 10,
    end_line: opts.end_line ?? 20,
  };
}

function type(name: string, opts: Partial<TypeInfo> = {}): TypeInfo {
  return {
    name,
    kind: opts.kind ?? 'class',
    package: opts.package ?? null,
    extends: opts.extends ?? null,
    implements: opts.implements ?? [],
    annotations: opts.annotations ?? [],
    methods: opts.methods ?? [],
    fields: opts.fields ?? [],
    start_line: opts.start_line ?? 1,
    end_line: opts.end_line ?? 100,
  };
}

// ---------------------------------------------------------------------------
// TIER_1 — method-level annotations
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — TIER_1 by method annotation', () => {
  it.each([
    '@GetMapping("/x")',
    '@PostMapping',
    '@PutMapping("/y")',
    '@DeleteMapping',
    '@PatchMapping',
    '@RequestMapping(value = "/x", method = RequestMethod.GET)',
    '@KafkaListener(topics = "t")',
    '@RabbitListener(queues = "q")',
    '@JmsListener(destination = "d")',
    '@SqsListener("queue")',
    '@StreamListener("input")',
    '@MessageMapping("/m")',
    '@SubscribeMapping("/topic/x")',
    '@KafkaHandler',
    '@RabbitHandler',
    '@SqsHandler',
    '@Scheduled(cron = "0 * * * * *")',
    '@EventListener',
    '@Path("/r")',
    '@GET',
    '@POST',
  ])('returns TIER_1 for method annotated %s', (ann) => {
    const m = method('handle', { annotations: [ann] });
    const t = type('Service', { annotations: ['@Service'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — class-level annotations
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — TIER_1 by class annotation', () => {
  it.each([
    '@RestController',
    '@Controller',
    '@Path("/api")',
    '@WebServlet("/foo")',
    '@ServerEndpoint("/ws")',
    '@FeignClient(name = "x")',
  ])('returns TIER_1 for any method of class annotated %s', (ann) => {
    const m = method('anyHandler');
    const t = type('UserController', { annotations: [ann] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  // ---- cognium-dev#136: Spring stereotype beans are Tier 1 ----
  // Library-jar audit: stereotypes are the visible trust boundary when
  // the @RestController seam is not in the scanned scope.

  it('returns TIER_1 for @Service class methods (#136)', () => {
    const m = method('process');
    const t = type('UserService', { annotations: ['@Service'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for @Repository class methods (#136)', () => {
    const m = method('findById');
    const t = type('UserRepository', { annotations: ['@Repository'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for @Component class methods (#136)', () => {
    const m = method('execute');
    const t = type('AuditComponent', { annotations: ['@Component'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for stereotype annotation with arguments (#136)', () => {
    const m = method('process');
    const t = type('UserService', { annotations: ['@Service("userBean")'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('library-facade short-circuit still trumps stereotype (#136 precision lock)', () => {
    // A `*Util` class accidentally carrying @Service must stay TIER_3
    // because the library-facade override runs before annotation
    // detection — see classShapeIsLibraryFacade rationale.
    const m = method('exec', { parameters: [param({ name: 'cmd', type: 'String' })] });
    const t = type('RuntimeUtil', { annotations: ['@Service'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — supertype lifecycle methods
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — TIER_1 by supertype lifecycle', () => {
  it('returns TIER_1 for doGet of an HttpServlet subclass', () => {
    const m = method('doGet');
    const t = type('UserServlet', { extends: 'HttpServlet' });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_3 for a non-lifecycle helper on an HttpServlet subclass', () => {
    const m = method('formatResponse');
    const t = type('UserServlet', { extends: 'HttpServlet' });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });

  it('returns TIER_1 for doFilter of a Filter implementer', () => {
    const m = method('doFilter');
    const t = type('AuthFilter', { implements: ['Filter'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for preHandle of HandlerInterceptor', () => {
    const m = method('preHandle');
    const t = type('AuthInterceptor', { implements: ['HandlerInterceptor'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for run() of CommandLineRunner', () => {
    const m = method('run', { parameters: [param({ name: 'args', type: 'String...' })] });
    const t = type('Bootstrap', { implements: ['CommandLineRunner'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  // #154 — Netty handler classes. Pre-fix dolphinscheduler shape
  // (LoggerRequestProcessor implements NettyRequestProcessor) +
  // standard Netty handler shapes.
  it.each([
    { supertype: 'NettyRequestProcessor', kind: 'implements', method: 'process' },
    { supertype: 'SimpleChannelInboundHandler', kind: 'extends',   method: 'channelRead0' },
    { supertype: 'SimpleChannelInboundHandler', kind: 'extends',   method: 'messageReceived' },
    { supertype: 'ChannelInboundHandler',       kind: 'implements', method: 'channelRead' },
    { supertype: 'ChannelInboundHandlerAdapter', kind: 'extends',  method: 'channelRead' },
    { supertype: 'ChannelDuplexHandler',         kind: 'extends',  method: 'channelRead' },
  ] as const)('returns TIER_1 for $method on a $supertype $kind', ({ supertype, kind, method: mname }) => {
    const m = method(mname);
    const t = kind === 'extends'
      ? type('MyHandler', { extends: supertype })
      : type('MyHandler', { implements: [supertype] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for SimpleChannelInboundHandler<MyCommand>.channelRead0 (generic erasure)', () => {
    // Verifies `simpleTypeName` strips `<MyCommand>` before supertype lookup.
    const m = method('channelRead0', {
      parameters: [
        param({ name: 'ctx', type: 'ChannelHandlerContext' }),
        param({ name: 'msg', type: 'MyCommand' }),
      ],
    });
    const t = type('CommandHandler', { extends: 'SimpleChannelInboundHandler<MyCommand>' });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_3 for a non-lifecycle helper on a Netty handler', () => {
    // Negative control: only the named lifecycle methods are TIER_1.
    const m = method('parseHeader');
    const t = type('CommandHandler', { extends: 'SimpleChannelInboundHandler' });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });

  it('CVE-2022-26884 dolphinscheduler shape: LoggerRequestProcessor.process gates correctly', () => {
    // End-to-end shape from the #154 issue: command parameter on a
    // NettyRequestProcessor.process() handler must NOT be dropped by
    // the interprocedural_param gate (would otherwise lose the
    // command.getBody() → path-traversal flow).
    const m = method('process', {
      parameters: [
        param({ name: 'channel', type: 'Channel' }),
        param({ name: 'command', type: 'Command' }),
      ],
    });
    const t = type('LoggerRequestProcessor', { implements: ['NettyRequestProcessor'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    // The gate should NOT drop a speculative source on this method's
    // params — TIER_1 means the source is preserved through verification.
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — main(String[])
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — TIER_1 by main signature', () => {
  it('returns TIER_1 for main(String[])', () => {
    const m = method('main', { parameters: [param({ name: 'args', type: 'String[]' })] });
    const t = type('App');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for main(String...)', () => {
    const m = method('main', { parameters: [param({ name: 'args', type: 'String...' })] });
    const t = type('App');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_1 for main(java.lang.String[])', () => {
    const m = method('main', { parameters: [param({ name: 'args', type: 'java.lang.String[]' })] });
    const t = type('App');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('returns TIER_3 for a method named main with wrong signature', () => {
    const m = method('main', { parameters: [param({ name: 'x', type: 'int' })] });
    const t = type('App');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — fallback
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — TIER_3 fallback', () => {
  it('returns TIER_3 for a plain public utility method', () => {
    const m = method('encode', { parameters: [param({ name: 's', type: 'String' })] });
    const t = type('Encoder');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });

  it('returns TIER_3 for the jedis amplification shape (public X y(String key))', () => {
    const m = method('get', { parameters: [param({ name: 'key', type: 'String' })] });
    const t = type('UnifiedJedis');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });

  it('returns TIER_3 for a MyBatis Interceptor lifecycle method', () => {
    // SPI plumbing — classifier confirms it's not an entry point; any
    // downstream framework-internal severity rubric handles it elsewhere.
    const m = method('intercept');
    const t = type('PageInterceptor', { implements: ['Interceptor'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });
});

// ---------------------------------------------------------------------------
// TIER_UNKNOWN — languages without a classifier / missing language
// ---------------------------------------------------------------------------
//
// Python / JS / Go / Bash all gained dedicated classifiers in 3.166.0
// (cognium-dev#237). The previous "TIER_UNKNOWN for non-Java" batch
// was tightened to only cover languages that still fall through
// (rust / html / unrecognized) and the missing-language case.

describe('classifyEntryPointTier — TIER_UNKNOWN for unsupported languages', () => {
  it('returns TIER_UNKNOWN for a python function with no Tier-1 signal', () => {
    // Plain util method, no framework decorator, in a src/ path — Python
    // classifier returns TIER_UNKNOWN so caller's safety guard preserves
    // recall.
    const m = method('get_user');
    expect(classifyEntryPointTier(m, undefined, pythonCtx)).toBe('TIER_UNKNOWN');
  });

  it('returns TIER_UNKNOWN when language is missing', () => {
    const m = method('handle');
    const t = type('Foo');
    expect(classifyEntryPointTier(m, t, {})).toBe('TIER_UNKNOWN');
  });

  it('returns TIER_UNKNOWN for an unsupported language (rust)', () => {
    const m = method('handle', { annotations: ['#[get("/x")]'] });
    const t = type('Foo');
    expect(classifyEntryPointTier(m, t, { language: 'rust' })).toBe('TIER_UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// shouldGateInterproceduralParam — the gate predicate
// ---------------------------------------------------------------------------

describe('shouldGateInterproceduralParam — gate predicate', () => {
  const jedisLike = type('UnifiedJedis');
  const jedisMethod = method('get', { parameters: [param({ name: 'key', type: 'String' })] });

  const controller = type('UserController', { annotations: ['@RestController'] });
  const handler = method('createUser', {
    annotations: ['@PostMapping'],
    parameters: [param({ name: 'payload', type: 'String', annotations: ['@RequestBody'] })],
  });

  it('drops interprocedural_param on a TIER_3 method (jedis shape)', () => {
    expect(
      shouldGateInterproceduralParam('interprocedural_param', jedisMethod, jedisLike, javaCtx),
    ).toBe(true);
  });

  it('keeps interprocedural_param on a TIER_1 method (controller handler)', () => {
    expect(
      shouldGateInterproceduralParam('interprocedural_param', handler, controller, javaCtx),
    ).toBe(false);
  });

  it('never gates non-interprocedural_param sources', () => {
    expect(
      shouldGateInterproceduralParam('http_param', jedisMethod, jedisLike, javaCtx),
    ).toBe(false);
    expect(
      shouldGateInterproceduralParam('user_input', jedisMethod, jedisLike, javaCtx),
    ).toBe(false);
  });

  it('preserves recall when enclosing method is missing', () => {
    expect(
      shouldGateInterproceduralParam('interprocedural_param', undefined, jedisLike, javaCtx),
    ).toBe(false);
  });

  it('does not gate non-Java sources (TIER_UNKNOWN = pass-through)', () => {
    expect(
      shouldGateInterproceduralParam('interprocedural_param', jedisMethod, jedisLike, pythonCtx),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// TIER_3 strengthening — library-facade shape heuristics (#128 step 2)
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — TIER_3 by library-facade shape (#128 step 2)', () => {
  describe('class-name suffix override', () => {
    it.each([
      ['RuntimeUtil', 'exec'],
      ['StringUtils', 'isEmpty'],
      ['UrlHelper', 'encode'],
      ['DateHelpers', 'parse'],
    ])('returns TIER_3 for %s.%s on suffix match', (cls, mth) => {
      const m = method(mth, { parameters: [param({ name: 'arg', type: 'String' })] });
      const t = type(cls);
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('overrides spurious @RestController on a *Util class (the four post-gate misses cluster)', () => {
      const m = method('exec', { parameters: [param({ name: 'cmd', type: 'String' })] });
      const t = type('RuntimeUtil', { annotations: ['@RestController'] });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('does NOT downgrade real entry points named without utility suffix', () => {
      const m = method('createUser');
      const t = type('UserController', { annotations: ['@RestController'] });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    });

    it('length guard: class named bare "Util" alone is not caught', () => {
      const m = method('encode');
      const t = type('Util');
      // length guard: 'Util' (4) is not > 'Util' suffix (4) → not flagged
      // Falls through to plain TIER_3 fallback (same observable tier, different path)
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('case-sensitive: lowercase "util" suffix is NOT caught (only canonical PascalCase)', () => {
      const m = method('parse', { annotations: ['@GetMapping'] });
      const t = type('myutil');
      // 'myutil' does not end with 'Util' (case sensitive); Tier-1 method
      // annotation still applies.
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    });
  });

  describe('package fragment override', () => {
    it.each([
      ['freemarker.template', 'FreemarkerEngine', 'render'],
      ['org.apache.velocity.template', 'VelocityEngine', 'evaluate'],
      ['com.acme.engine', 'CustomEngine', 'process'],
      ['org.app.engines.audio', 'AudioEngine', 'play'],
    ])('returns TIER_3 for %s.%s.%s on package fragment match', (pkg, cls, mth) => {
      const m = method(mth, { parameters: [param({ name: 'in', type: 'String' })] });
      const t = type(cls, { package: pkg });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('overrides spurious @KafkaListener on a template-package class', () => {
      const m = method('render', {
        annotations: ['@KafkaListener(topics = "t")'],
        parameters: [param({ name: 'tpl', type: 'String' })],
      });
      const t = type('FreemarkerEngine', { package: 'freemarker.template' });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('does NOT match similar but distinct fragments (templatemap, enginepool)', () => {
      const m = method('handle', { annotations: ['@GetMapping'] });
      const t = type('Foo', { package: 'app.templatemap' });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    });

    it('does NOT match fragment as suffix without trailing dot (template at end of package)', () => {
      const m = method('handle', { annotations: ['@GetMapping'] });
      const t = type('Foo', { package: 'app.notatemplate' });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    });
  });

  describe('JDK facade interface-implements override', () => {
    it.each([
      ['List', 'CustomList', 'get'],
      ['Map', 'CustomMap', 'put'],
      ['Iterator', 'StreamingIterator', 'next'],
      ['Comparable', 'OrderedThing', 'compareTo'],
      ['Serializable', 'EventPayload', 'readObject'],
    ])('returns TIER_3 for a class implementing %s', (iface, cls, mth) => {
      const m = method(mth, { parameters: [param({ name: 'x', type: 'Object' })] });
      const t = type(cls, { implements: [iface] });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('overrides spurious @WebServlet on a JDK-collection-implementing class', () => {
      const m = method('add', { parameters: [param({ name: 'item', type: 'Object' })] });
      const t = type('TaintedList', {
        implements: ['List'],
        annotations: ['@WebServlet("/bad")'],
      });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('tolerates generic parameters on the implements clause (List<String>)', () => {
      const m = method('add');
      const t = type('StringList', { implements: ['List<String>'] });
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });
  });

  describe('combined / boundary', () => {
    it('does NOT trigger on a plain unannotated class (negative control)', () => {
      // Plain business class with no stereotype, no controller annotation,
      // and no library-facade shape — falls through to the TIER_3 fallback
      // via step 8, not via the library-facade short-circuit.
      const m = method('createOrder', { parameters: [param({ name: 'req', type: 'OrderReq' })] });
      const t = type('OrderProcessor');
      expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
    });

    it('shouldGateInterproceduralParam drops sources on heuristic-flagged TIER_3 classes', () => {
      const m = method('exec', { parameters: [param({ name: 'cmd', type: 'String' })] });
      const t = type('RuntimeUtil');
      expect(
        shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx),
      ).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// #224 — XStream Converter + Jenkins Stapler seed extensions
// ---------------------------------------------------------------------------

describe('classifyEntryPointTier — #224 XStream Converter supertype', () => {
  it.each([
    { supertype: 'Converter',                    kind: 'implements', method: 'unmarshal' },
    { supertype: 'Converter',                    kind: 'implements', method: 'marshal'   },
    { supertype: 'SingleValueConverter',         kind: 'implements', method: 'fromString' },
    { supertype: 'ConverterMatcher',             kind: 'implements', method: 'unmarshal' },
    { supertype: 'AbstractReflectionConverter',  kind: 'extends',    method: 'unmarshal' },
    { supertype: 'AbstractReflectionConverter',  kind: 'extends',    method: 'doUnmarshal' },
    { supertype: 'AbstractSingleValueConverter', kind: 'extends',    method: 'fromString' },
    { supertype: 'AbstractCollectionConverter',  kind: 'extends',    method: 'unmarshal' },
  ] as const)('returns TIER_1 for $method on a $supertype $kind', ({ supertype, kind, method: mname }) => {
    const m = method(mname, {
      parameters: [
        param({ name: 'reader', type: 'HierarchicalStreamReader' }),
        param({ name: 'ctx',    type: 'UnmarshallingContext' }),
      ],
    });
    const t = kind === 'extends'
      ? type('MyConverter', { extends: supertype })
      : type('MyConverter', { implements: [supertype] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('CVE-2020-26217 shape: unmarshal on a class implementing Converter is not gated', () => {
    // End-to-end: the interprocedural_param source on the unmarshal
    // parameter must survive so the reader.getAttribute → exec flow
    // fires. Pre-fix (3.144.x) this was silently dropped by the #128
    // entry-point gate because the class carries no framework
    // annotation.
    const m = method('unmarshal', {
      parameters: [
        param({ name: 'reader', type: 'HierarchicalStreamReader' }),
        param({ name: 'ctx',    type: 'UnmarshallingContext' }),
      ],
    });
    const t = type('DynamicProxyConverter', { implements: ['Converter'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('returns TIER_3 for a non-lifecycle helper on a Converter class', () => {
    // Only the named lifecycle methods (marshal/unmarshal/fromString/
    // toString/doMarshal/doUnmarshal) are TIER_1. A helper method on
    // the same class stays TIER_3.
    const m = method('formatEntry');
    const t = type('MyConverter', { implements: ['Converter'] });
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });
});

describe('classifyEntryPointTier — #224 Jenkins Stapler form-binding annotations', () => {
  it.each([
    '@DataBoundConstructor',
    '@DataBoundSetter',
  ])('returns TIER_1 for a method annotated %s', (ann) => {
    const m = method('setCredentialsId', {
      annotations: [ann],
      parameters: [param({ name: 'credentialsId', type: 'String' })],
    });
    const t = type('DockerRegistryEndpoint');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('CVE-2022-20617 shape: @DataBoundConstructor is not gated', () => {
    // End-to-end: the DockerRegistryEndpoint constructor parameter is
    // a Jenkins Stapler-bound user input source; the interprocedural_param
    // source must survive the entry-point gate so the credentialsId
    // → subprocess flow fires.
    const m = method('DockerRegistryEndpoint', {
      annotations: ['@DataBoundConstructor'],
      parameters: [
        param({ name: 'url',           type: 'String' }),
        param({ name: 'credentialsId', type: 'String' }),
      ],
    });
    const t = type('DockerRegistryEndpoint');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('returns TIER_3 for an unannotated helper on the same class', () => {
    // Only the @DataBoundConstructor / @DataBoundSetter methods are
    // TIER_1. A helper method with no annotation stays TIER_3.
    const m = method('getEffectiveUrl');
    const t = type('DockerRegistryEndpoint');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });

  it('library-facade short-circuit still trumps @DataBoundConstructor', () => {
    // Precision lock: an accidental `*Util` class carrying
    // @DataBoundConstructor stays TIER_3 (facade override runs first).
    const m = method('CredentialsUtil', { annotations: ['@DataBoundConstructor'] });
    const t = type('CredentialsUtil');
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });
});
