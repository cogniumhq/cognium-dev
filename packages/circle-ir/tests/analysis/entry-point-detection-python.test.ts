/**
 * Python entry-point classifier tests (cognium-dev#237 — 3.166.0).
 *
 * Locks in Tier 1 detection for Flask / FastAPI / Django / Click /
 * Celery decorator patterns, `main()` at module scope, and the
 * library-path + `_private_helper` TIER_3 heuristics. Non-signal
 * cases fall through to TIER_UNKNOWN (safety guard on caller side).
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

function moduleType(opts: Partial<TypeInfo> = {}): TypeInfo {
  return {
    name: opts.name ?? '__module__',
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

const CTX = (filePath: string, extra: Partial<EntryPointContext> = {}): EntryPointContext => ({
  language: 'python',
  filePath,
  ...extra,
});

// ---------------------------------------------------------------------------
// TIER_1 — decorator match
// ---------------------------------------------------------------------------

describe('classifyPythonEntryPoint — TIER_1 by decorator', () => {
  it.each([
    '@app.route("/users")',
    '@blueprint.route("/api/v1/users")',
    '@app.get("/users/<id>")',
    '@app.post("/users")',
    '@app.put("/users/<id>")',
    '@app.delete("/users/<id>")',
    '@app.patch("/users/<id>")',
    '@router.get("/items/{id}")',
    '@router.websocket("/ws")',
    '@router.api_route("/items", methods=["GET"])',
    '@click.command()',
    '@click.group()',
    '@celery.task',
    '@shared_task(bind=True)',
    '@app.task(name="do_work")',
    '@login_required',
    '@csrf_exempt',
    '@api_view(["GET"])',
    '@require_http_methods(["POST"])',
    '@fixture',
  ])('returns TIER_1 for a function annotated %s', (ann) => {
    const m = method('handle', { annotations: [ann] });
    expect(classifyEntryPointTier(m, undefined, CTX('src/app.py'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('tolerates dotted receivers (last segment is the decorator name)', () => {
    const m = method('list_items', {
      annotations: ['@some.nested.receiver.get("/items")'],
    });
    expect(classifyEntryPointTier(m, undefined, CTX('src/api.py'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('bare @task (no parens) is picked up', () => {
    const m = method('nightly_job', { annotations: ['@task'] });
    expect(classifyEntryPointTier(m, undefined, CTX('src/jobs.py'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — RuntimeRegistration handler match
// ---------------------------------------------------------------------------

describe('classifyPythonEntryPoint — TIER_1 by runtime registration', () => {
  it('marks a handler as TIER_1 when RuntimeRegistration names it', () => {
    const m = method('list_users');
    const regs: RuntimeRegistration[] = [
      {
        kind: 'decorator',
        framework: 'flask',
        registrar: { method: 'route', receiver: 'app', line: 5, column: 0 },
        path: '/users',
        handler: { name: 'list_users', line: 6, column: 0 },
      },
    ];
    expect(
      classifyEntryPointTier(m, undefined, CTX('src/app.py', { runtimeRegistrations: regs })),
    ).toBe('TIER_1_ENTRY_POINT');
  });

  it('does not fire when the registration handler is anonymous', () => {
    const m = method('unrelated_helper');
    const regs: RuntimeRegistration[] = [
      {
        kind: 'decorator',
        framework: 'flask',
        registrar: { method: 'route', receiver: 'app', line: 5, column: 0 },
        path: '/users',
        handler: { name: null, line: 6, column: 0 },
      },
    ];
    expect(
      classifyEntryPointTier(m, undefined, CTX('src/app.py', { runtimeRegistrations: regs })),
    ).toBe('TIER_UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — main() at module scope
// ---------------------------------------------------------------------------

describe('classifyPythonEntryPoint — TIER_1 by main convention', () => {
  it('main() at module top-level (no enclosing type) → TIER_1', () => {
    const m = method('main');
    expect(classifyEntryPointTier(m, undefined, CTX('src/cli.py'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('main() inside a synthesized module-scope container → TIER_1', () => {
    const m = method('main');
    const t = moduleType();
    expect(classifyEntryPointTier(m, t, CTX('src/cli.py'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — library / helper paths
// ---------------------------------------------------------------------------

describe('classifyPythonEntryPoint — TIER_3 by library path', () => {
  it.each([
    'src/libapi/http.py',
    'src/lib/parser.py',
    'src/utils/strings.py',
    'src/helpers/format.py',
    'src/interop/ctypes_bridge.py',
    'vendor/thirdparty/x.py',
    'tests/test_util.py',
    '__tests__/fake.py',
  ])('returns TIER_3 for file %s', (filePath) => {
    // Even with a Flask decorator, path override wins — utility helper
    // that happens to be `@app.route`-decorated in a lib dir stays TIER_3.
    const m = method('helper', { annotations: ['@app.route("/x")'] });
    expect(classifyEntryPointTier(m, undefined, CTX(filePath))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — convention-private helper
// ---------------------------------------------------------------------------

describe('classifyPythonEntryPoint — TIER_3 by _private convention', () => {
  it('returns TIER_3 for _helper (single-underscore) with no framework signal', () => {
    const m = method('_helper');
    expect(classifyEntryPointTier(m, undefined, CTX('src/app.py'))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });

  it('dunder methods (__init__) do NOT get downgraded', () => {
    const m = method('__init__');
    // No positive signal → TIER_UNKNOWN (not TIER_3) — the caller's
    // safety guard preserves the finding.
    expect(classifyEntryPointTier(m, undefined, CTX('src/app.py'))).toBe(
      'TIER_UNKNOWN',
    );
  });

  it('_private helper with a route decorator is still TIER_1 (decorator wins over convention)', () => {
    const m = method('_route_impl', { annotations: ['@app.route("/x")'] });
    expect(classifyEntryPointTier(m, undefined, CTX('src/app.py'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_UNKNOWN — fallback (recall preserved via caller safety guard)
// ---------------------------------------------------------------------------

describe('classifyPythonEntryPoint — TIER_UNKNOWN fallback', () => {
  it('plain public function with no signal → TIER_UNKNOWN', () => {
    const m = method('do_thing', {
      parameters: [param({ name: 'x', type: 'str' })],
    });
    expect(classifyEntryPointTier(m, undefined, CTX('src/app.py'))).toBe(
      'TIER_UNKNOWN',
    );
  });
});
