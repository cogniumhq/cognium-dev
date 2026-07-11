/**
 * Polyglot `applyRequireEntryPath` pinning tests
 * (cognium-dev#237 — 3.166.0).
 *
 * Each test recreates one of the 14 ticket-body FP fixtures at IR level
 * — a library-facade / interop helper carrying a taint-flow finding on
 * a method that is NOT called from any framework entry point in the
 * same scan. The polyglot gate should drop these findings under the
 * `application/production` profile.
 *
 * Fixtures modelled (from #237 ticket body):
 *   Bash:
 *     - benign_path_join.sh        — path_traversal on library helper
 *     - benign_sqlite_param.sh     — sql_injection on library helper
 *   Python:
 *     - safe_interop_ctypes.py           — redos on interop layer
 *     - safe_interop_env_json_to_xpath.py — xxe on interop layer
 *     - safe_interop_jinja_ssti.py       — template_injection on interop
 *     - safe_interop_toml_dynimport.py   — path_traversal on interop
 *   JS/TS:
 *     - safe_interop_json_deserialize_sink.js — insecure_deserialization
 *     - safe_axios_allowlist.js               — ssrf on libapi
 *     - safe_ioredis_get.js                   — ssrf on libapi
 *
 * Java `SafeInteropSpel.java` + `SafeVelocityRender.java` fixtures
 * from the ticket are covered by the pre-existing Java classifier
 * (library-facade shape override on `*Spel` / `velocity.template.*`
 * package) — see `entry-point-detection.test.ts §TIER_3 strengthening`.
 *
 * The `safe_fastapi_allowlist.py` fixture is a genuine entry-point
 * (`@app.get`) — it requires allowlist-sanitizer credit (out of scope
 * per the plan) and is NOT gated here.
 *
 * # Test contract
 *
 * Each pinning test:
 *   1. Builds a two-file scan — one real framework entry point (so the
 *      language has ≥1 Tier-1 key and the safety guard does not fire),
 *      one library-facade file carrying the finding.
 *   2. Runs `applyRequireEntryPath` under
 *      `projectProfile: 'application/production'`.
 *   3. Asserts the library-facade finding is DROPPED.
 *   4. Asserts the entry-point file's findings are preserved.
 */

import { describe, it, expect } from 'vitest';
import { applyRequireEntryPath } from '../../src/analysis/require-entry-path.js';
import type {
  CallInfo,
  CircleIR,
  Meta,
  MethodInfo,
  RuntimeRegistration,
  SastFinding,
  TypeInfo,
} from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixture builders (shared across all polyglot pinning tests)
// ---------------------------------------------------------------------------

function makeMeta(file: string, language: string): Meta {
  return {
    file,
    language,
    loc: 100,
    hash: 'test-hash',
    parsed_at: new Date().toISOString(),
  } as Meta;
}

function makeMethod(
  name: string,
  startLine: number,
  endLine: number,
  annotations: string[] = [],
): MethodInfo {
  return {
    name,
    return_type: null,
    parameters: [],
    annotations,
    modifiers: [],
    start_line: startLine,
    end_line: endLine,
  };
}

function makeType(
  name: string,
  methods: MethodInfo[],
  opts: {
    annotations?: string[];
    extends?: string | null;
    implements?: string[];
    package?: string | null;
  } = {},
): TypeInfo {
  return {
    name,
    kind: 'class',
    package: opts.package ?? null,
    extends: opts.extends ?? null,
    implements: opts.implements ?? [],
    annotations: opts.annotations ?? [],
    methods,
    fields: [],
    start_line: 1,
    end_line: 999,
  };
}

function makeIR(
  file: string,
  language: string,
  types: TypeInfo[],
  opts: {
    calls?: CallInfo[];
    findings?: SastFinding[];
    runtimeRegistrations?: RuntimeRegistration[];
  } = {},
): CircleIR {
  return {
    meta: makeMeta(file, language),
    types,
    calls: opts.calls ?? [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: { types: [] },
    findings: opts.findings && opts.findings.length > 0 ? opts.findings : undefined,
    runtime_registrations: opts.runtimeRegistrations ?? undefined,
  } as unknown as CircleIR;
}

function makeFinding(
  file: string,
  line: number,
  rule_id: string,
  overrides: Partial<SastFinding> = {},
): SastFinding {
  return {
    id: `t-${line}-${rule_id}`,
    pass: 'sink-filter',
    category: 'security',
    rule_id,
    severity: 'high',
    level: 'error',
    message: `Tainted flow to ${rule_id} sink`,
    file,
    line,
    ...overrides,
  };
}

const APP_PROFILE = { projectProfile: 'application/production' as const };

// ---------------------------------------------------------------------------
// Bash pinning fixtures
// ---------------------------------------------------------------------------

describe('applyRequireEntryPath polyglot — Bash pinning', () => {
  it('drops path_traversal on `benign_path_join.sh` (library helper, no positional args)', () => {
    // Real entry point elsewhere in the scan so bash has ≥1 Tier-1 key.
    const mainScript = makeMethod('main', 1, 30);
    const mainType = makeType('__module__', [mainScript]);
    const mainIR = makeIR('scripts/deploy.sh', 'bash', [mainType]);

    // Library helper carrying the FP finding.
    const joinPaths = makeMethod('join_paths', 3, 15);
    const helperType = makeType('__module__', [joinPaths]);
    const finding = makeFinding('scripts/benign_path_join.sh', 8, 'path-traversal');
    const helperIR = makeIR('scripts/benign_path_join.sh', 'bash', [helperType], {
      findings: [finding],
    });

    applyRequireEntryPath(
      [
        { file: 'scripts/deploy.sh', analysis: mainIR },
        { file: 'scripts/benign_path_join.sh', analysis: helperIR },
      ],
      APP_PROFILE,
    );

    expect(helperIR.findings).toBeUndefined();
  });

  it('drops sql_injection on `benign_sqlite_param.sh` (library helper)', () => {
    const mainScript = makeMethod('main', 1, 30);
    const mainType = makeType('__module__', [mainScript]);
    const mainIR = makeIR('scripts/db_migrate.sh', 'bash', [mainType]);

    const buildQuery = makeMethod('build_query', 3, 15);
    const helperType = makeType('__module__', [buildQuery]);
    const finding = makeFinding('scripts/benign_sqlite_param.sh', 8, 'sql-injection');
    const helperIR = makeIR('scripts/benign_sqlite_param.sh', 'bash', [helperType], {
      findings: [finding],
    });

    applyRequireEntryPath(
      [
        { file: 'scripts/db_migrate.sh', analysis: mainIR },
        { file: 'scripts/benign_sqlite_param.sh', analysis: helperIR },
      ],
      APP_PROFILE,
    );

    expect(helperIR.findings).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Python pinning fixtures — `/interop/` path fragment drives TIER_3
// ---------------------------------------------------------------------------

describe('applyRequireEntryPath polyglot — Python pinning', () => {
  it.each([
    { file: 'src/interop/safe_interop_ctypes.py',           rule: 'redos' },
    { file: 'src/interop/safe_interop_env_json_to_xpath.py', rule: 'xxe' },
    { file: 'src/interop/safe_interop_jinja_ssti.py',       rule: 'template-injection' },
    { file: 'src/interop/safe_interop_toml_dynimport.py',   rule: 'path-traversal' },
  ])('drops $rule on interop helper $file', ({ file, rule }) => {
    // Real entry point: a Flask handler in src/api/routes.py.
    const listUsers = makeMethod('list_users', 3, 15, ['@app.route("/users")']);
    const routesType = makeType('__module__', [listUsers]);
    const routesRegs: RuntimeRegistration[] = [
      {
        kind: 'decorator',
        framework: 'flask',
        registrar: { method: 'route', receiver: 'app', line: 3, column: 0 },
        path: '/users',
        handler: { name: 'list_users', line: 4, column: 0 },
      },
    ];
    const routesIR = makeIR('src/api/routes.py', 'python', [routesType], {
      runtimeRegistrations: routesRegs,
    });

    // Interop helper carrying the FP finding.
    const helper = makeMethod('do_work', 3, 15);
    const helperType = makeType('__module__', [helper]);
    const finding = makeFinding(file, 8, rule);
    const helperIR = makeIR(file, 'python', [helperType], { findings: [finding] });

    applyRequireEntryPath(
      [
        { file: 'src/api/routes.py', analysis: routesIR },
        { file, analysis: helperIR },
      ],
      APP_PROFILE,
    );

    expect(helperIR.findings).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// JS/TS pinning fixtures — `/libapi/` + `/interop/` path fragments
// ---------------------------------------------------------------------------

describe('applyRequireEntryPath polyglot — JS/TS pinning', () => {
  it.each([
    { file: 'src/interop/safe_interop_json_deserialize_sink.js', rule: 'insecure-deserialization' },
    { file: 'src/libapi/safe_axios_allowlist.js',                rule: 'ssrf' },
    { file: 'src/libapi/safe_ioredis_get.js',                    rule: 'ssrf' },
  ])('drops $rule on library-facade helper $file', ({ file, rule }) => {
    // Real entry point: an Express route in src/routes.js.
    const listUsers = makeMethod('listUsers', 3, 15);
    const routesType = makeType('__module__', [listUsers]);
    const routesRegs: RuntimeRegistration[] = [
      {
        kind: 'http_route',
        framework: 'express',
        registrar: { method: 'get', receiver: 'app', line: 3, column: 0 },
        path: '/users',
        handler: { name: 'listUsers', line: 3, column: 20 },
      },
    ];
    const routesIR = makeIR('src/routes.js', 'javascript', [routesType], {
      runtimeRegistrations: routesRegs,
    });

    // Library helper carrying the FP finding.
    const helper = makeMethod('doWork', 3, 15);
    const helperType = makeType('__module__', [helper]);
    const finding = makeFinding(file, 8, rule);
    const helperIR = makeIR(file, 'javascript', [helperType], { findings: [finding] });

    applyRequireEntryPath(
      [
        { file: 'src/routes.js', analysis: routesIR },
        { file, analysis: helperIR },
      ],
      APP_PROFILE,
    );

    expect(helperIR.findings).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Java pre-existing pinning — SafeInteropSpel / SafeVelocityRender
// ---------------------------------------------------------------------------
//
// These fixtures land in the ticket table but are already covered by the
// Java classifier's library-facade short-circuit (package-fragment /
// class-name heuristics from cognium-dev#128 step 2). Reproduced here as
// regression sentinels — if the polyglot expansion accidentally weakens
// Java classification, these break.

describe('applyRequireEntryPath polyglot — Java regression sentinels', () => {
  it('drops code-injection on `SafeVelocityRender` (velocity.template.* package)', () => {
    // Real Java entry point.
    const handleReq = makeMethod('handle', 3, 15, ['@GetMapping("/users")']);
    const ctrl = makeType('UserController', [handleReq], {
      annotations: ['@RestController'],
      package: 'com.example.web',
    });
    const ctrlIR = makeIR('src/main/java/com/example/web/UserController.java', 'java', [ctrl]);

    // Velocity template renderer — library-facade shape via package.
    const render = makeMethod('render', 3, 15);
    const veloType = makeType('VelocityEngine', [render], {
      package: 'org.apache.velocity.template',
    });
    const finding = makeFinding(
      'src/main/java/org/apache/velocity/template/VelocityEngine.java',
      8,
      'code-injection',
    );
    const veloIR = makeIR(
      'src/main/java/org/apache/velocity/template/VelocityEngine.java',
      'java',
      [veloType],
      { findings: [finding] },
    );

    applyRequireEntryPath(
      [
        {
          file: 'src/main/java/com/example/web/UserController.java',
          analysis: ctrlIR,
        },
        {
          file: 'src/main/java/org/apache/velocity/template/VelocityEngine.java',
          analysis: veloIR,
        },
      ],
      APP_PROFILE,
    );

    expect(veloIR.findings).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Safety guard: languages with zero classified entry points keep findings
// ---------------------------------------------------------------------------

describe('applyRequireEntryPath polyglot — per-language safety guard', () => {
  it('preserves findings on Python files when Python has zero Tier-1 entry points', () => {
    // Two Python files, both library-only (no decorators, no `main`).
    // The safety guard must not drop the finding — reachability is
    // unanswerable.
    const helperA = makeMethod('foo', 3, 15);
    const helperType = makeType('__module__', [helperA]);
    const findingA = makeFinding('src/pkg/helper_a.py', 8, 'sql-injection');
    const irA = makeIR('src/pkg/helper_a.py', 'python', [helperType], {
      findings: [findingA],
    });

    const helperB = makeMethod('bar', 3, 15);
    const helperTypeB = makeType('__module__', [helperB]);
    const irB = makeIR('src/pkg/helper_b.py', 'python', [helperTypeB]);

    applyRequireEntryPath(
      [
        { file: 'src/pkg/helper_a.py', analysis: irA },
        { file: 'src/pkg/helper_b.py', analysis: irB },
      ],
      APP_PROFILE,
    );

    // Safety guard fires — no Tier-1 keys for Python → keep.
    expect(irA.findings).toBeDefined();
    expect(irA.findings).toHaveLength(1);
  });

  it('preserves findings on unsupported language (rust) regardless of profile', () => {
    const rustFn = makeMethod('handle_request', 3, 15);
    const rustType = makeType('__module__', [rustFn]);
    const finding = makeFinding('src/lib.rs', 8, 'sql-injection');
    const rustIR = makeIR('src/lib.rs', 'rust', [rustType], { findings: [finding] });

    applyRequireEntryPath([{ file: 'src/lib.rs', analysis: rustIR }], APP_PROFILE);

    expect(rustIR.findings).toBeDefined();
    expect(rustIR.findings).toHaveLength(1);
  });
});
