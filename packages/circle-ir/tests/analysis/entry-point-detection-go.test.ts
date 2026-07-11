/**
 * Go entry-point classifier tests (cognium-dev#237 — 3.166.0).
 *
 * Locks in Tier 1 detection for `net/http.HandleFunc` / gin / chi
 * registrations (via `ir.calls` walk), `http.ResponseWriter` +
 * `*http.Request` handler signatures, gRPC `Server`-suffixed
 * receivers, `main` in package `main`, and the library-path TIER_3
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
  CallInfo,
  ArgumentInfo,
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

function arg(expression: string, position = 0): ArgumentInfo {
  return { position, expression };
}

function call(opts: {
  method_name: string;
  receiver: string | null;
  arguments: ArgumentInfo[];
  line?: number;
}): CallInfo {
  return {
    method_name: opts.method_name,
    receiver: opts.receiver,
    arguments: opts.arguments,
    location: { line: opts.line ?? 5, column: 0 },
  };
}

const CTX = (filePath: string, extra: Partial<EntryPointContext> = {}): EntryPointContext => ({
  language: 'go',
  filePath,
  ...extra,
});

// ---------------------------------------------------------------------------
// TIER_1 — main() in package main
// ---------------------------------------------------------------------------

describe('classifyGoEntryPoint — TIER_1 by main package', () => {
  it('main() in `package main` → TIER_1', () => {
    const m = method('main');
    const t = type('__module__', { package: 'main' });
    expect(classifyEntryPointTier(m, t, CTX('cmd/serve/main.go'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('main() in a non-main package does not fire this rule alone', () => {
    const m = method('main');
    const t = type('__module__', { package: 'server' });
    // No other signal → TIER_UNKNOWN.
    expect(classifyEntryPointTier(m, t, CTX('server/impl.go'))).toBe('TIER_UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — net/http handler signature
// ---------------------------------------------------------------------------

describe('classifyGoEntryPoint — TIER_1 by handler signature', () => {
  it('func(w http.ResponseWriter, r *http.Request) → TIER_1', () => {
    const m = method('serveHTTP', {
      parameters: [
        param({ name: 'w', type: 'http.ResponseWriter' }),
        param({ name: 'r', type: '*http.Request' }),
      ],
    });
    expect(classifyEntryPointTier(m, undefined, CTX('server/handler.go'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('func(w ResponseWriter, r *Request) (unqualified type) also matches', () => {
    const m = method('handle', {
      parameters: [
        param({ name: 'w', type: 'ResponseWriter' }),
        param({ name: 'r', type: '*Request' }),
      ],
    });
    expect(classifyEntryPointTier(m, undefined, CTX('server/handler.go'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('func with only one param does not match', () => {
    const m = method('helper', {
      parameters: [param({ name: 'r', type: '*http.Request' })],
    });
    expect(classifyEntryPointTier(m, undefined, CTX('server/handler.go'))).toBe(
      'TIER_UNKNOWN',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — gRPC handler shape
// ---------------------------------------------------------------------------

describe('classifyGoEntryPoint — TIER_1 by gRPC handler shape', () => {
  it('receiver *UserServer + first param context.Context → TIER_1', () => {
    const m = method('GetUser', {
      parameters: [
        param({ name: 'ctx', type: 'context.Context' }),
        param({ name: 'req', type: '*pb.GetUserRequest' }),
      ],
    });
    const t = type('UserServer');
    expect(classifyEntryPointTier(m, t, CTX('grpc/user.go'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('receiver named ChatService (Service suffix) also fires', () => {
    const m = method('Send', {
      parameters: [
        param({ name: 'ctx', type: 'context.Context' }),
        param({ name: 'req', type: '*pb.SendReq' }),
      ],
    });
    const t = type('ChatService');
    expect(classifyEntryPointTier(m, t, CTX('grpc/chat.go'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('receiver without Server/Service/Handler suffix does not fire', () => {
    const m = method('DoStuff', {
      parameters: [
        param({ name: 'ctx', type: 'context.Context' }),
        param({ name: 'req', type: '*pb.Req' }),
      ],
    });
    const t = type('BusinessLogic');
    expect(classifyEntryPointTier(m, t, CTX('svc/logic.go'))).toBe('TIER_UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — ir.calls registration walk
// ---------------------------------------------------------------------------

describe('classifyGoEntryPoint — TIER_1 by ir.calls registration walk', () => {
  it('handler registered via http.HandleFunc("/x", handleX) → TIER_1', () => {
    const m = method('handleX');
    const calls: CallInfo[] = [
      call({
        method_name: 'HandleFunc',
        receiver: 'http',
        arguments: [arg('"/x"', 0), arg('handleX', 1)],
      }),
    ];
    expect(classifyEntryPointTier(m, undefined, CTX('main.go', { calls }))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('handler registered via router.GET(path, handler) (chi/gin) → TIER_1', () => {
    const m = method('listItems');
    const calls: CallInfo[] = [
      call({
        method_name: 'GET',
        receiver: 'router',
        arguments: [arg('"/items"', 0), arg('listItems', 1)],
      }),
    ];
    expect(classifyEntryPointTier(m, undefined, CTX('server.go', { calls }))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('registrar with package-qualified handler `pkg.MyHandler` matches on last segment', () => {
    const m = method('MyHandler');
    const calls: CallInfo[] = [
      call({
        method_name: 'HandleFunc',
        receiver: 'http',
        arguments: [arg('"/x"', 0), arg('pkg.MyHandler', 1)],
      }),
    ];
    expect(classifyEntryPointTier(m, undefined, CTX('main.go', { calls }))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('registrar on unrelated receiver does not fire', () => {
    const m = method('handleX');
    const calls: CallInfo[] = [
      call({
        method_name: 'HandleFunc',
        receiver: 'unrelatedThing',
        arguments: [arg('"/x"', 0), arg('handleX', 1)],
      }),
    ];
    expect(classifyEntryPointTier(m, undefined, CTX('main.go', { calls }))).toBe(
      'TIER_UNKNOWN',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — library / test paths
// ---------------------------------------------------------------------------

describe('classifyGoEntryPoint — TIER_3 by path', () => {
  it.each([
    'pkg/lib/helper.go',
    'internal/utils/parse.go',
    'vendor/github.com/x/y/z.go',
    'internal/helpers/format.go',
  ])('returns TIER_3 for %s', (filePath) => {
    const m = method('serveHTTP', {
      parameters: [
        param({ name: 'w', type: 'http.ResponseWriter' }),
        param({ name: 'r', type: '*http.Request' }),
      ],
    });
    expect(classifyEntryPointTier(m, undefined, CTX(filePath))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });

  it('returns TIER_3 for `*_test.go` files (Go convention)', () => {
    const m = method('serveHTTP', {
      parameters: [
        param({ name: 'w', type: 'http.ResponseWriter' }),
        param({ name: 'r', type: '*http.Request' }),
      ],
    });
    expect(classifyEntryPointTier(m, undefined, CTX('server/handler_test.go'))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });
});
