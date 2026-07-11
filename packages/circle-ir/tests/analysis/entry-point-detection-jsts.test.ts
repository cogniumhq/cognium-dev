/**
 * JavaScript / TypeScript entry-point classifier tests
 * (cognium-dev#237 — 3.166.0).
 *
 * Locks in Tier 1 detection for NestJS decorators (method + class),
 * Express-family `RuntimeRegistration` handlers, Lambda / Next.js
 * App Router named module exports, and the library-path TIER_3
 * heuristic. Non-signal cases fall through to TIER_UNKNOWN.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyEntryPointTier,
  type EntryPointContext,
} from '../../src/analysis/entry-point-detection.js';
import type {
  TypeInfo,
  MethodInfo,
  ParameterInfo,
  RuntimeRegistration,
} from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function param(opts: Partial<ParameterInfo> & { name: string }): ParameterInfo {
  return { name: opts.name, type: opts.type ?? null, annotations: opts.annotations ?? [] };
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

function moduleType(opts: Partial<TypeInfo> = {}): TypeInfo {
  return type('__module__', opts);
}

const CTX = (
  filePath: string,
  language: 'javascript' | 'typescript' | 'tsx' | 'jsx' = 'typescript',
  extra: Partial<EntryPointContext> = {},
): EntryPointContext => ({ language, filePath, ...extra });

// ---------------------------------------------------------------------------
// TIER_1 — NestJS method decorators
// ---------------------------------------------------------------------------

describe('classifyJsTsEntryPoint — TIER_1 by NestJS method decorator', () => {
  it.each([
    '@Get()',
    '@Post("/users")',
    '@Put(":id")',
    '@Delete(":id")',
    '@Patch()',
    '@All()',
    '@Head()',
    '@Options()',
    '@SubscribeMessage("chat")',
    '@MessagePattern({ cmd: "sum" })',
    '@EventPattern("user.created")',
    '@GrpcMethod("UserService")',
  ])('returns TIER_1 for a method annotated %s', (ann) => {
    const m = method('handle', { annotations: [ann] });
    const t = type('UserController');
    expect(classifyEntryPointTier(m, t, CTX('src/users.controller.ts'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — NestJS class decorators
// ---------------------------------------------------------------------------

describe('classifyJsTsEntryPoint — TIER_1 by NestJS class decorator', () => {
  it.each(['@Controller()', '@Controller("users")', '@RestController()', '@Resolver()', '@WebSocketGateway()'])(
    'returns TIER_1 for any method of a class annotated %s',
    (ann) => {
      const m = method('list');
      const t = type('UserController', { annotations: [ann] });
      expect(classifyEntryPointTier(m, t, CTX('src/users.controller.ts'))).toBe(
        'TIER_1_ENTRY_POINT',
      );
    },
  );
});

// ---------------------------------------------------------------------------
// TIER_1 — RuntimeRegistration handler (Express, Fastify, Koa)
// ---------------------------------------------------------------------------

describe('classifyJsTsEntryPoint — TIER_1 by runtime registration', () => {
  it('Express handler resolved via RuntimeRegistration → TIER_1', () => {
    const m = method('handleUsers');
    const regs: RuntimeRegistration[] = [
      {
        kind: 'http_route',
        framework: 'express',
        registrar: { method: 'get', receiver: 'app', line: 5, column: 0 },
        path: '/users',
        handler: { name: 'handleUsers', line: 10, column: 0 },
      },
    ];
    expect(
      classifyEntryPointTier(m, undefined, CTX('src/app.ts', 'typescript', { runtimeRegistrations: regs })),
    ).toBe('TIER_1_ENTRY_POINT');
  });

  it('Anonymous inline handler does not attach TIER_1 to any named method', () => {
    const m = method('somethingElse');
    const regs: RuntimeRegistration[] = [
      {
        kind: 'http_route',
        framework: 'express',
        registrar: { method: 'get', receiver: 'app', line: 5, column: 0 },
        path: '/users',
        handler: { name: null, line: 5, column: 15 },
      },
    ];
    expect(
      classifyEntryPointTier(m, undefined, CTX('src/app.ts', 'typescript', { runtimeRegistrations: regs })),
    ).toBe('TIER_UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — module-level named exports
// ---------------------------------------------------------------------------

describe('classifyJsTsEntryPoint — TIER_1 by named module export', () => {
  it.each(['handler', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'load', 'action', 'middleware'])(
    'returns TIER_1 for module-level export named %s',
    (name) => {
      const m = method(name);
      // No enclosing type = module scope.
      expect(classifyEntryPointTier(m, undefined, CTX('src/route.ts'))).toBe(
        'TIER_1_ENTRY_POINT',
      );
    },
  );

  it('module-level `main` → TIER_1', () => {
    const m = method('main');
    expect(classifyEntryPointTier(m, undefined, CTX('src/cli.ts'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — library / test paths
// ---------------------------------------------------------------------------

describe('classifyJsTsEntryPoint — TIER_3 by library / test path', () => {
  it.each([
    'src/libapi/http.ts',
    'src/lib/parser.ts',
    'src/utils/strings.ts',
    'src/helpers/format.ts',
    'node_modules/left-pad/index.js',
    'dist/bundle.js',
    'build/output.js',
    '__tests__/example.test.ts',
    'src/foo.spec.ts',
    'tests/foo.test.js',
  ])('returns TIER_3 for file %s', (filePath) => {
    const m = method('handler', { annotations: ['@Get()'] });
    const t = type('X', { annotations: ['@Controller()'] });
    expect(classifyEntryPointTier(m, t, CTX(filePath))).toBe('TIER_3_LIBRARY_API');
  });
});

// ---------------------------------------------------------------------------
// TIER_UNKNOWN — fallback
// ---------------------------------------------------------------------------

describe('classifyJsTsEntryPoint — TIER_UNKNOWN fallback', () => {
  it('plain unannotated method with no signal → TIER_UNKNOWN', () => {
    const m = method('privateHelper', {
      parameters: [param({ name: 'x', type: 'string' })],
    });
    const t = type('SomeService');
    expect(classifyEntryPointTier(m, t, CTX('src/app.ts'))).toBe('TIER_UNKNOWN');
  });

  it('handler named at module level but inside a real class does not fire module-export rule', () => {
    const m = method('handler');
    const t = type('SomeClass', {
      annotations: ['@SomethingUnrelated'],
      extends: 'BaseClass',
    });
    // Class has annotation + extends → does not look like module scope.
    expect(classifyEntryPointTier(m, t, CTX('src/app.ts'))).toBe('TIER_UNKNOWN');
  });
});
