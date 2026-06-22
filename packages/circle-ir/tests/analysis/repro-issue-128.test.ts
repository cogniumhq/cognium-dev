/**
 * Repro for issue #128 — entry-point-anchored taint sources (Sprint 35 / 3.88.0).
 *
 * `taint-matcher.ts:218-237` emits an `interprocedural_param` source for
 * every parameter of every Java method in a file, regardless of whether
 * the method is reachable from a program entry point. On the top-25 Java
 * OSS harness this produced ~1,768 of 1,968 high CWE-78 findings against
 * `redis/jedis`'s facade methods — pure signature amplification on a
 * library that is *called by* users, never *invoked at* a network
 * boundary.
 *
 * 3.88.0 wires `shouldGateInterproceduralParam()` from the verbatim port
 * of cognium-ai's classifier (PR #135) into `interprocedural-pass.ts`
 * Scenario A. The gate drops speculative `interprocedural_param` sources
 * whose enclosing method classifies as `TIER_3_LIBRARY_API` (utility /
 * helper classes via `*Util` / `*Utils` / `*Helper(s)` suffix, template
 * / engine packages via `*.template.*` / `*.engine.*`, direct JDK-facade
 * `implements`, or any non-entry-point Java method).
 *
 * Critical-miss cluster anchoring this test: `RuntimeUtil.exec` ×3 +
 * `FreemarkerEngine.render` — TIER_3 surfaces that were slipping
 * through the downstream cognium-ai gate. Recall locks anchor the six
 * primary entry-point shapes (Spring `@RestController` / `@RequestMapping`,
 * Servlet `HttpServlet.doGet`, JAX-RS `@GET`, `main(String[])`,
 * non-Java pass-through).
 */

import { describe, it, expect } from 'vitest';
import {
  shouldGateInterproceduralParam,
  classifyEntryPointTier,
  type EntryPointContext,
} from '../../src/analysis/entry-point-detection.js';
import type { TypeInfo, MethodInfo, ParameterInfo } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixture helpers (mirrors entry-point-detection.test.ts)
// ---------------------------------------------------------------------------

const javaCtx: EntryPointContext = { language: 'java' };
const pythonCtx: EntryPointContext = { language: 'python' };
const jsCtx: EntryPointContext     = { language: 'javascript' };

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
// Critical-miss locks (must GATE — return true)
//
// These are the four FP-cluster shapes that slipped through the
// downstream cognium-ai gate and motivated the upstream port.
// ---------------------------------------------------------------------------

describe('Issue #128 — critical-miss FP cluster (must gate interprocedural_param)', () => {
  it('RuntimeUtil.exec — hutool-style command facade, *Util suffix', () => {
    // Hutool's cn.hutool.core.util.RuntimeUtil.exec(cmd) — wraps
    // Runtime.getRuntime().exec under a static utility surface.
    // Called by user code, never by a network boundary.
    const m = method('exec', {
      modifiers: ['public', 'static'],
      parameters: [param({ name: 'cmd', type: 'String' })],
    });
    const t = type('RuntimeUtil', { package: 'cn.hutool.core.util' });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(true);
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_3_LIBRARY_API');
  });

  it('RuntimeUtil.execForStr — second method on the same facade', () => {
    const m = method('execForStr', {
      modifiers: ['public', 'static'],
      parameters: [param({ name: 'cmds', type: 'String[]' })],
    });
    const t = type('RuntimeUtil', { package: 'cn.hutool.core.util' });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(true);
  });

  it('RuntimeUtil.execForLines — third method on the same facade', () => {
    const m = method('execForLines', {
      modifiers: ['public', 'static'],
      parameters: [param({ name: 'cmd', type: 'String' })],
    });
    const t = type('RuntimeUtil', { package: 'cn.hutool.core.util' });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(true);
  });

  it('FreemarkerEngine.render — engine-package facade', () => {
    // freemarker.template.* / org.apache.freemarker.engine.* — template
    // rendering libraries operating on user-supplied template content.
    // Library API surface, not a network entry point.
    const m = method('render', {
      modifiers: ['public'],
      parameters: [
        param({ name: 'template', type: 'String' }),
        param({ name: 'context',  type: 'Map<String,Object>' }),
      ],
    });
    const t = type('FreemarkerEngine', { package: 'org.apache.freemarker.engine.impl' });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(true);
  });

  it('Plain non-entry-point Java method (no annotation, no entry-point class) — gates', () => {
    // The bulk of #128's signal: any public Java method that isn't
    // explicitly an entry point falls through to TIER_3.
    const m = method('processQuery', {
      modifiers: ['public'],
      parameters: [param({ name: 'q', type: 'String' })],
    });
    const t = type('SomeService');  // no annotations, no facade shape
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(true);
  });

  it('Class implementing JDK Map facade — gates', () => {
    // Custom map implementations are library data structures; their
    // put/get/remove parameters are not entry-point taint.
    const m = method('put', {
      parameters: [
        param({ name: 'k', type: 'String' }),
        param({ name: 'v', type: 'Object' }),
      ],
    });
    const t = type('LinkedCaseInsensitiveMap', {
      implements: ['Map<String,Object>'],
    });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Recall locks (must NOT gate — return false)
//
// Real entry-point methods must continue to anchor `interprocedural_param`
// sources so legitimate cross-method flows still surface.
// ---------------------------------------------------------------------------

describe('Issue #128 — recall locks (must not gate interprocedural_param)', () => {
  it('@RestController + @GetMapping — Spring web entry point', () => {
    const m = method('getUser', {
      annotations: ['@GetMapping("/users/{id}")'],
      parameters:  [param({ name: 'id', type: 'String', annotations: ['@PathVariable'] })],
    });
    const t = type('UserController', { annotations: ['@RestController'] });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
    expect(classifyEntryPointTier(m, t, javaCtx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('@RequestMapping on a plain Controller class — fires', () => {
    const m = method('handle', {
      annotations: ['@RequestMapping("/api")'],
      parameters:  [param({ name: 'body', type: 'String', annotations: ['@RequestBody'] })],
    });
    const t = type('ApiController', { annotations: ['@Controller'] });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('HttpServlet.doGet — lifecycle entry point', () => {
    const m = method('doGet', {
      parameters: [
        param({ name: 'req', type: 'HttpServletRequest' }),
        param({ name: 'res', type: 'HttpServletResponse' }),
      ],
    });
    const t = type('MyServlet', { extends: 'HttpServlet' });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('JAX-RS @GET on a @Path resource class — fires', () => {
    const m = method('list', {
      annotations: ['@GET'],
      parameters:  [param({ name: 'q', type: 'String', annotations: ['@QueryParam("q")'] })],
    });
    const t = type('UsersResource', { annotations: ['@Path("/users")'] });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('public static void main(String[] args) — CLI entry point', () => {
    const m = method('main', {
      modifiers:  ['public', 'static'],
      return_type: 'void',
      parameters: [param({ name: 'args', type: 'String[]' })],
    });
    const t = type('App');
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('@KafkaListener — message-queue entry point', () => {
    const m = method('consume', {
      annotations: ['@KafkaListener(topics = "events")'],
      parameters:  [param({ name: 'payload', type: 'String' })],
    });
    const t = type('EventConsumer', { annotations: ['@Service'] });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('CommandLineRunner.run — Spring boot lifecycle entry point', () => {
    const m = method('run', {
      parameters: [param({ name: 'args', type: 'String...' })],
    });
    const t = type('Bootstrap', { implements: ['CommandLineRunner'] });
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, javaCtx)).toBe(false);
  });

  it('non-Java (Python) — UNKNOWN tier, pass-through', () => {
    // Python calls do not carry Java annotation surface; the gate
    // must not engage outside ship-1 scope.
    const m = method('handler', {
      parameters: [param({ name: 'event' })],
    });
    const t = type('Handler');
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, pythonCtx)).toBe(false);
    expect(classifyEntryPointTier(m, t, pythonCtx)).toBe('TIER_UNKNOWN');
  });

  it('non-Java (JavaScript) — UNKNOWN tier, pass-through', () => {
    const m = method('handler', {
      parameters: [param({ name: 'req' })],
    });
    const t = type('Handler');
    expect(shouldGateInterproceduralParam('interprocedural_param', m, t, jsCtx)).toBe(false);
  });

  it('non-interprocedural_param source type — never gated', () => {
    // Sanity check: even if enclosing method classifies as TIER_3,
    // other source types (http_param, env_var, etc.) are never gated.
    const m = method('process', {
      parameters: [param({ name: 'p', type: 'String' })],
    });
    const t = type('SomeUtil');  // TIER_3 by *Util suffix
    expect(shouldGateInterproceduralParam('http_param',         m, t, javaCtx)).toBe(false);
    expect(shouldGateInterproceduralParam('env_var',            m, t, javaCtx)).toBe(false);
    expect(shouldGateInterproceduralParam('constructor_field',  m, t, javaCtx)).toBe(false);
    expect(shouldGateInterproceduralParam(null,                 m, t, javaCtx)).toBe(false);
    expect(shouldGateInterproceduralParam(undefined,            m, t, javaCtx)).toBe(false);
  });

  it('unresolved enclosing method — preserves recall', () => {
    // If the source's `in_method` doesn't resolve to a known method
    // in the file, the gate falls through (returns false) rather than
    // dropping the source.
    expect(shouldGateInterproceduralParam('interprocedural_param', undefined, undefined, javaCtx)).toBe(false);
  });
});
