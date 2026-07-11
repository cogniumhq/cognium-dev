/**
 * Bash entry-point classifier tests (cognium-dev#237 — 3.166.0).
 *
 * Locks in Tier 1 detection for `main()` functions, positional
 * parameter (`$1`, `$@`, `getopts`) consumption, and the
 * `benign_` / `lib_` / `_helpers_` filename-prefix TIER_3 heuristic.
 * Non-signal cases fall through to TIER_UNKNOWN.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyEntryPointTier,
  type EntryPointContext,
} from '../../src/analysis/entry-point-detection.js';
import type {
  TypeInfo,
  MethodInfo,
  CallInfo,
  ArgumentInfo,
} from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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
    location: { line: opts.line ?? 15, column: 0 },
  };
}

const CTX = (filePath: string, extra: Partial<EntryPointContext> = {}): EntryPointContext => ({
  language: 'bash',
  filePath,
  ...extra,
});

// ---------------------------------------------------------------------------
// TIER_1 — main() function
// ---------------------------------------------------------------------------

describe('classifyBashEntryPoint — TIER_1 by main function', () => {
  it('main() function → TIER_1', () => {
    const m = method('main');
    expect(classifyEntryPointTier(m, undefined, CTX('deploy.sh'))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_1 — positional-parameter consumption
// ---------------------------------------------------------------------------

describe('classifyBashEntryPoint — TIER_1 by positional-arg use', () => {
  it.each(['$1', '$2', '$@', '$*', '$#', 'getopts'])(
    'method consuming %s in an argument → TIER_1',
    (tok) => {
      const m = method('parse_args', { start_line: 10, end_line: 30 });
      const calls: CallInfo[] = [
        call({ method_name: 'echo', arguments: [arg(tok, 0)], line: 15 }),
      ];
      expect(classifyEntryPointTier(m, undefined, CTX('deploy.sh', { calls }))).toBe(
        'TIER_1_ENTRY_POINT',
      );
    },
  );

  it('getopts call site fires even without a $-token argument', () => {
    const m = method('parse_args', { start_line: 10, end_line: 30 });
    const calls: CallInfo[] = [
      call({ method_name: 'getopts', arguments: [arg('"h:v"', 0), arg('opt', 1)], line: 15 }),
    ];
    expect(classifyEntryPointTier(m, undefined, CTX('deploy.sh', { calls }))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });

  it('calls OUTSIDE the method line range do not fire (attribution stays local)', () => {
    const m = method('helper', { start_line: 10, end_line: 20 });
    const calls: CallInfo[] = [
      // $1 in a call at line 5 — before method start.
      call({ method_name: 'echo', arguments: [arg('$1', 0)], line: 5 }),
    ];
    // Per the classifier's design: fileHasPositionalArgUse is only
    // consulted for module-scope containers. A regular function's
    // classification only counts positional uses within its own range.
    expect(classifyEntryPointTier(m, undefined, CTX('deploy.sh', { calls }))).toBe(
      'TIER_UNKNOWN',
    );
  });

  it('module-scope container + file-level $1 use → TIER_1', () => {
    const m = method('__script_body__', { start_line: 1, end_line: 50 });
    const t = moduleType();
    const calls: CallInfo[] = [
      call({ method_name: 'echo', arguments: [arg('$1', 0)], line: 3 }),
    ];
    expect(classifyEntryPointTier(m, t, CTX('deploy.sh', { calls }))).toBe(
      'TIER_1_ENTRY_POINT',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — library/benign filename prefixes
// ---------------------------------------------------------------------------

describe('classifyBashEntryPoint — TIER_3 by filename prefix', () => {
  it.each([
    'scripts/benign_path_join.sh',
    'scripts/benign_sqlite_param.sh',
    'scripts/safe_helpers.sh',
    'scripts/lib_common.sh',
    'scripts/common_utils.sh',
    'scripts/_internal.sh',
  ])('returns TIER_3 for filename %s', (filePath) => {
    const m = method('do_it');
    expect(classifyEntryPointTier(m, undefined, CTX(filePath))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });

  it.each([
    'scripts/deploy.test.sh',
    'scripts/deploy_test.sh',
  ])('returns TIER_3 for test-suffixed script %s', (filePath) => {
    const m = method('do_it');
    expect(classifyEntryPointTier(m, undefined, CTX(filePath))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });

  it('filename-prefix override wins over main() convention', () => {
    // A helper with `main` function in a `benign_` script is still TIER_3
    // — the file signals library/benign explicitly, so no entry-point.
    const m = method('main');
    expect(classifyEntryPointTier(m, undefined, CTX('scripts/benign_helper.sh'))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_3 — library path fragments
// ---------------------------------------------------------------------------

describe('classifyBashEntryPoint — TIER_3 by library path', () => {
  it.each([
    'lib/common.sh',
    'scripts/helpers/format.sh',
    'vendor/thirdparty/tool.sh',
  ])('returns TIER_3 for %s', (filePath) => {
    const m = method('main');
    expect(classifyEntryPointTier(m, undefined, CTX(filePath))).toBe(
      'TIER_3_LIBRARY_API',
    );
  });
});

// ---------------------------------------------------------------------------
// TIER_UNKNOWN — fallback
// ---------------------------------------------------------------------------

describe('classifyBashEntryPoint — TIER_UNKNOWN fallback', () => {
  it('plain function, no positional args, no library markers → TIER_UNKNOWN', () => {
    const m = method('helper');
    expect(classifyEntryPointTier(m, undefined, CTX('deploy.sh'))).toBe(
      'TIER_UNKNOWN',
    );
  });
});
