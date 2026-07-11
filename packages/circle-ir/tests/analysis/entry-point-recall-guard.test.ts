/**
 * Polyglot entry-point recall-guard tests (cognium-dev#237 — 3.166.0).
 *
 * The 3.166.0 polyglot expansion widened the `require-entry-path` gate
 * from Java-only to Python / JS-TS / Go / Bash. These tests lock in
 * that classic must-fire framework patterns per language are still
 * classified TIER_1 by the entry-point classifier — i.e. findings on
 * their handlers are annotated (not dropped) by `applyRequireEntryPath`.
 *
 * If a future refactor accidentally shrinks the Tier-1 admission table
 * for any of these languages, this test file breaks before any
 * benchmark-harness rerun.
 *
 * Note: this file exercises the *classifier* (via
 * `classifyEntryPointTier`) — the same admission that feeds
 * `applyRequireEntryPath`. Full end-to-end coverage lives in
 * `require-entry-path-polyglot.test.ts`.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyEntryPointTier,
  type EntryPointContext,
} from '../../src/analysis/entry-point-detection.js';
import type {
  ArgumentInfo,
  CallInfo,
  MethodInfo,
  ParameterInfo,
  RuntimeRegistration,
  TypeInfo,
} from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Shared fixtures
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

function makeType(name: string, opts: Partial<TypeInfo> = {}): TypeInfo {
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
  receiver?: string | null;
  arguments: ArgumentInfo[];
  line?: number;
}): CallInfo {
  return {
    method_name: opts.method_name,
    receiver: opts.receiver ?? null,
    arguments: opts.arguments,
    location: { line: opts.line ?? 5, column: 0 },
  };
}

// ---------------------------------------------------------------------------
// Python — Flask / FastAPI must-fire patterns
// ---------------------------------------------------------------------------

describe('recall-guard — Python framework entry points', () => {
  it('Flask @app.route view fires', () => {
    const m = method('list_users', { annotations: ['@app.route("/users")'] });
    const ctx: EntryPointContext = { language: 'python', filePath: 'src/app.py' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('FastAPI @router.get fires', () => {
    const m = method('get_item', { annotations: ['@router.get("/items/{id}")'] });
    const ctx: EntryPointContext = { language: 'python', filePath: 'src/api.py' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('Django @api_view fires', () => {
    const m = method('user_list', { annotations: ['@api_view(["GET"])'] });
    const ctx: EntryPointContext = { language: 'python', filePath: 'src/views.py' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('Celery @shared_task fires', () => {
    const m = method('do_work', { annotations: ['@shared_task'] });
    const ctx: EntryPointContext = { language: 'python', filePath: 'src/tasks.py' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('Flask handler via RuntimeRegistration fires (decorator resolution reuse)', () => {
    const m = method('handle_login');
    const regs: RuntimeRegistration[] = [
      {
        kind: 'decorator',
        framework: 'flask',
        registrar: { method: 'route', receiver: 'app', line: 4, column: 0 },
        path: '/login',
        handler: { name: 'handle_login', line: 5, column: 0 },
      },
    ];
    const ctx: EntryPointContext = {
      language: 'python',
      filePath: 'src/app.py',
      runtimeRegistrations: regs,
    };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });
});

// ---------------------------------------------------------------------------
// JS/TS — Express / NestJS / Lambda must-fire patterns
// ---------------------------------------------------------------------------

describe('recall-guard — JS/TS framework entry points', () => {
  it('Express handler via RuntimeRegistration fires', () => {
    const m = method('handleUsers');
    const regs: RuntimeRegistration[] = [
      {
        kind: 'http_route',
        framework: 'express',
        registrar: { method: 'post', receiver: 'app', line: 3, column: 0 },
        path: '/users',
        handler: { name: 'handleUsers', line: 3, column: 20 },
      },
    ];
    const ctx: EntryPointContext = {
      language: 'javascript',
      filePath: 'src/app.js',
      runtimeRegistrations: regs,
    };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('NestJS @Post method fires', () => {
    const m = method('createUser', {
      annotations: ['@Post()'],
      parameters: [param({ name: 'body', type: 'CreateUserDto' })],
    });
    const t = makeType('UserController', { annotations: ['@Controller("users")'] });
    const ctx: EntryPointContext = { language: 'typescript', filePath: 'src/users.controller.ts' };
    expect(classifyEntryPointTier(m, t, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('AWS Lambda `exports.handler` fires', () => {
    const m = method('handler');
    const ctx: EntryPointContext = { language: 'javascript', filePath: 'lambda.js' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('Next.js App Router `export function GET` fires', () => {
    const m = method('GET');
    const ctx: EntryPointContext = { language: 'typescript', filePath: 'src/app/api/route.ts' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });
});

// ---------------------------------------------------------------------------
// Go — net/http + gin/chi must-fire patterns
// ---------------------------------------------------------------------------

describe('recall-guard — Go framework entry points', () => {
  it('net/http handler via signature shape fires', () => {
    const m = method('serveHTTP', {
      parameters: [
        param({ name: 'w', type: 'http.ResponseWriter' }),
        param({ name: 'r', type: '*http.Request' }),
      ],
    });
    const ctx: EntryPointContext = { language: 'go', filePath: 'server/handler.go' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('http.HandleFunc("/users", listUsers) via ir.calls walk fires', () => {
    const m = method('listUsers');
    const calls: CallInfo[] = [
      call({
        method_name: 'HandleFunc',
        receiver: 'http',
        arguments: [arg('"/users"', 0), arg('listUsers', 1)],
      }),
    ];
    const ctx: EntryPointContext = { language: 'go', filePath: 'main.go', calls };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('gin router.POST(path, handler) fires', () => {
    const m = method('CreateUser');
    const calls: CallInfo[] = [
      call({
        method_name: 'POST',
        receiver: 'router',
        arguments: [arg('"/users"', 0), arg('CreateUser', 1)],
      }),
    ];
    const ctx: EntryPointContext = { language: 'go', filePath: 'main.go', calls };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('main() in package main fires', () => {
    const m = method('main');
    const t = makeType('__module__', { package: 'main' });
    const ctx: EntryPointContext = { language: 'go', filePath: 'cmd/serve/main.go' };
    expect(classifyEntryPointTier(m, t, ctx)).toBe('TIER_1_ENTRY_POINT');
  });
});

// ---------------------------------------------------------------------------
// Bash — positional-arg + main() must-fire patterns
// ---------------------------------------------------------------------------

describe('recall-guard — Bash framework entry points', () => {
  it('main() function fires', () => {
    const m = method('main');
    const ctx: EntryPointContext = { language: 'bash', filePath: 'deploy.sh' };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('script-body $1 use in module-scope fires', () => {
    const m = method('__script_body__', { start_line: 1, end_line: 50 });
    const t = makeType('__module__');
    const calls: CallInfo[] = [
      call({ method_name: 'echo', arguments: [arg('$1', 0)], line: 3 }),
    ];
    const ctx: EntryPointContext = { language: 'bash', filePath: 'deploy.sh', calls };
    expect(classifyEntryPointTier(m, t, ctx)).toBe('TIER_1_ENTRY_POINT');
  });

  it('function using getopts fires', () => {
    const m = method('parse_flags', { start_line: 5, end_line: 25 });
    const calls: CallInfo[] = [
      call({ method_name: 'getopts', arguments: [arg('"h:v"', 0), arg('opt', 1)], line: 10 }),
    ];
    const ctx: EntryPointContext = { language: 'bash', filePath: 'deploy.sh', calls };
    expect(classifyEntryPointTier(m, undefined, ctx)).toBe('TIER_1_ENTRY_POINT');
  });
});

// ---------------------------------------------------------------------------
// Java — pre-existing recall targets (regression sentinels)
// ---------------------------------------------------------------------------

describe('recall-guard — Java framework entry points (regression sentinels)', () => {
  it('Spring @RestController handler fires', () => {
    const m = method('createUser', {
      annotations: ['@PostMapping'],
      parameters: [
        param({ name: 'payload', type: 'String', annotations: ['@RequestBody'] }),
      ],
    });
    const t = makeType('UserController', { annotations: ['@RestController'] });
    expect(
      classifyEntryPointTier(m, t, { language: 'java' }),
    ).toBe('TIER_1_ENTRY_POINT');
  });

  it('main(String[]) fires', () => {
    const m = method('main', {
      parameters: [param({ name: 'args', type: 'String[]' })],
    });
    const t = makeType('App');
    expect(
      classifyEntryPointTier(m, t, { language: 'java' }),
    ).toBe('TIER_1_ENTRY_POINT');
  });

  it('HttpServlet.doGet fires', () => {
    const m = method('doGet');
    const t = makeType('UserServlet', { extends: 'HttpServlet' });
    expect(
      classifyEntryPointTier(m, t, { language: 'java' }),
    ).toBe('TIER_1_ENTRY_POINT');
  });
});
