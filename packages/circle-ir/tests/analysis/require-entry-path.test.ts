/**
 * Tests for `applyRequireEntryPath` (cognium-dev#234, ships 3.153.0).
 *
 * Focused on the helper's decision contract:
 *   1. H+C security findings on methods reachable from a Tier-1 entry
 *      point are annotated with `entryPath[]` + `entryPathTier`.
 *   2. H+C security findings on methods NOT reachable from any Tier-1
 *      entry point are DROPPED, unless the file's profile is
 *      `library/*` (already handled by #236 / #232) or the containing
 *      method cannot be resolved.
 *   3. Non-H+C findings and non-security findings are never dropped.
 *   4. `disabledPasses` fully disables the helper.
 *   5. Non-Java files never drop (classifier returns TIER_UNKNOWN, so
 *      the entry-point set is empty and reachability is meaningless).
 */

import { describe, it, expect } from 'vitest';
import { applyRequireEntryPath } from '../../src/analysis/require-entry-path.js';
import type {
  CallInfo,
  CircleIR,
  Meta,
  MethodInfo,
  SastFinding,
  TypeInfo,
} from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

function makeMeta(file: string, language = 'java'): Meta {
  return {
    file,
    language,
    loc: 100,
    hash: 'test-hash',
    parsed_at: new Date().toISOString(),
  } as Meta;
}

function makeMethod(name: string, startLine: number, endLine: number, annotations: string[] = []): MethodInfo {
  return {
    name,
    return_type: 'void',
    parameters: [],
    annotations,
    modifiers: ['public'],
    start_line: startLine,
    end_line: endLine,
  };
}

function makeType(name: string, methods: MethodInfo[], annotations: string[] = [], extendsClass: string | null = null): TypeInfo {
  return {
    name,
    kind: 'class',
    package: 'com.example',
    extends: extendsClass,
    implements: [],
    annotations,
    methods,
    fields: [],
    start_line: 1,
    end_line: 999,
  };
}

function makeCall(methodName: string, inMethod: string, line: number, receiverType: string | null = null): CallInfo {
  return {
    method_name: methodName,
    receiver: receiverType,
    receiver_type: receiverType,
    arguments: [],
    location: { line, column: 0 },
    in_method: inMethod,
  };
}

function makeIR(file: string, types: TypeInfo[], calls: CallInfo[], findings: SastFinding[] = []): CircleIR {
  return {
    meta: makeMeta(file),
    types,
    calls,
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: [],
    exports: [],
    unresolved: [],
    enriched: { types: [] },
    findings: findings.length > 0 ? findings : undefined,
  } as unknown as CircleIR;
}

function makeFinding(file: string, line: number, overrides: Partial<SastFinding> = {}): SastFinding {
  return {
    id: `t-${line}`,
    pass: 'sink-filter',
    category: 'security',
    rule_id: 'sql-injection',
    severity: 'high',
    level: 'error',
    message: 'Tainted flow to sink',
    file,
    line,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Drop tests
// ---------------------------------------------------------------------------

describe('applyRequireEntryPath — drop policy', () => {
  it('drops H+C finding on utility class with no callers', () => {
    // Foo.util() has a finding at line 5 but no caller anywhere.
    const util = makeMethod('doStuff', 3, 10);
    const type = makeType('Helper', [util]); // no framework annotations
    const finding = makeFinding('/src/Helper.java', 5);
    const ir = makeIR('/src/Helper.java', [type], [], [finding]);

    applyRequireEntryPath([{ file: '/src/Helper.java', analysis: ir }]);

    expect(ir.findings).toBeUndefined();
  });

  it('preserves reachable H+C finding via @RestController', () => {
    // Controller.handle() calls Service.doStuff() which contains the sink.
    const handle = makeMethod('handle', 3, 10, ['@GetMapping']);
    const controller = makeType('Controller', [handle], ['@RestController']);
    const doStuff = makeMethod('doStuff', 3, 20);
    const service = makeType('Service', [doStuff]);
    const call = makeCall('doStuff', 'handle', 7, 'Service');
    const finding = makeFinding('/src/Service.java', 12);

    const controllerIR = makeIR('/src/Controller.java', [controller], [call]);
    const serviceIR = makeIR('/src/Service.java', [service], [], [finding]);

    applyRequireEntryPath([
      { file: '/src/Controller.java', analysis: controllerIR },
      { file: '/src/Service.java', analysis: serviceIR },
    ]);

    expect(serviceIR.findings).toBeDefined();
    expect(serviceIR.findings).toHaveLength(1);
    const annotated = serviceIR.findings![0];
    expect(annotated.entryPathTier).toBe('tier1-entry-point');
    expect(annotated.entryPath).toBeDefined();
    expect(annotated.entryPath!.length).toBeGreaterThanOrEqual(2);
  });

  it('preserves reachable H+C finding via HttpServlet supertype', () => {
    const doGet = makeMethod('doGet', 3, 20);
    const servlet = makeType('MyServlet', [doGet], [], 'HttpServlet');
    const finding = makeFinding('/src/MyServlet.java', 10);
    const ir = makeIR('/src/MyServlet.java', [servlet], [], [finding]);

    applyRequireEntryPath([{ file: '/src/MyServlet.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
    expect(ir.findings![0].entryPathTier).toBe('tier1-entry-point');
    expect(ir.findings![0].entryPath).toHaveLength(1);
  });

  it('preserves H+C finding on `main(String[])`', () => {
    const main = makeMethod('main', 3, 20);
    main.parameters = [{ name: 'args', type: 'String[]', annotations: [] }];
    main.modifiers = ['public', 'static'];
    const app = makeType('App', [main]);
    const finding = makeFinding('/src/App.java', 10);
    const ir = makeIR('/src/App.java', [app], [], [finding]);

    applyRequireEntryPath([{ file: '/src/App.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
    expect(ir.findings![0].entryPathTier).toBe('tier1-entry-point');
  });

  it('does NOT drop under library/production profile', () => {
    const doStuff = makeMethod('doStuff', 3, 10);
    const helper = makeType('Helper', [doStuff]);
    const finding = makeFinding('/src/Helper.java', 5);
    const ir = makeIR('/src/Helper.java', [helper], [], [finding]);

    applyRequireEntryPath(
      [{ file: '/src/Helper.java', analysis: ir }],
      { projectProfile: 'library/production' },
    );

    expect(ir.findings).toHaveLength(1);
  });

  it('drops under application/production profile', () => {
    const doStuff = makeMethod('doStuff', 3, 10);
    const helper = makeType('Helper', [doStuff]);
    const finding = makeFinding('/src/Helper.java', 5);
    const ir = makeIR('/src/Helper.java', [helper], [], [finding]);

    applyRequireEntryPath(
      [{ file: '/src/Helper.java', analysis: ir }],
      { projectProfile: 'application/production' },
    );

    expect(ir.findings).toBeUndefined();
  });
});

describe('applyRequireEntryPath — preserve policy', () => {
  it('preserves medium-severity finding on unreachable method', () => {
    const doStuff = makeMethod('doStuff', 3, 10);
    const helper = makeType('Helper', [doStuff]);
    const finding = makeFinding('/src/Helper.java', 5, { severity: 'medium', level: 'warning' });
    const ir = makeIR('/src/Helper.java', [helper], [], [finding]);

    applyRequireEntryPath([{ file: '/src/Helper.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
  });

  it('preserves non-security finding on unreachable method', () => {
    const doStuff = makeMethod('doStuff', 3, 10);
    const helper = makeType('Helper', [doStuff]);
    const finding = makeFinding('/src/Helper.java', 5, {
      category: 'reliability',
      rule_id: 'dead-code',
    });
    const ir = makeIR('/src/Helper.java', [helper], [], [finding]);

    applyRequireEntryPath([{ file: '/src/Helper.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
  });

  // cognium-dev #246 REG-155-02 — rule-based crypto/config findings must
  // survive even under `unknown` / `application` profile with no
  // reachable entry point.
  it('preserves rule-based weak-crypto finding on unreachable method', () => {
    const doStuff = makeMethod('encrypt', 3, 10);
    const helper = makeType('EcbCipherTp', [doStuff]);
    const finding = makeFinding('/src/EcbCipherTp.java', 5, {
      rule_id: 'weak-crypto',
      cwe: 'CWE-327',
    });
    const ir = makeIR('/src/EcbCipherTp.java', [helper], [], [finding]);

    applyRequireEntryPath([{ file: '/src/EcbCipherTp.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
    expect(ir.findings![0].rule_id).toBe('weak-crypto');
  });

  it('preserves rule-based tls-verify-disabled finding on unreachable method', () => {
    const doStuff = makeMethod('setup', 3, 10);
    const helper = makeType('InsecureTls', [doStuff]);
    const finding = makeFinding('/src/InsecureTls.java', 5, {
      rule_id: 'tls-verify-disabled',
      cwe: 'CWE-295',
      severity: 'critical',
    });
    const ir = makeIR('/src/InsecureTls.java', [helper], [], [finding]);

    applyRequireEntryPath([{ file: '/src/InsecureTls.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
  });

  it('preserves finding whose containing method cannot be resolved (field initializer)', () => {
    const helper = makeType('Helper', []); // no methods
    const finding = makeFinding('/src/Helper.java', 2); // in field-init at line 2
    const ir = makeIR('/src/Helper.java', [helper], [], [finding]);

    applyRequireEntryPath([{ file: '/src/Helper.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
  });

  it('is a full no-op when disabled via disabledPasses', () => {
    const doStuff = makeMethod('doStuff', 3, 10);
    const helper = makeType('Helper', [doStuff]);
    const finding = makeFinding('/src/Helper.java', 5);
    const ir = makeIR('/src/Helper.java', [helper], [], [finding]);

    applyRequireEntryPath(
      [{ file: '/src/Helper.java', analysis: ir }],
      { disabledPasses: ['require-entry-path'] },
    );

    expect(ir.findings).toHaveLength(1);
    expect(ir.findings![0].entryPath).toBeUndefined();
    expect(ir.findings![0].entryPathTier).toBeUndefined();
  });

  it('preserves finding in non-Java file (classifier is Java-primary)', () => {
    const doStuff = makeMethod('do_stuff', 3, 10);
    const helper = makeType('Helper', [doStuff]);
    const finding = makeFinding('/src/helper.py', 5);
    const ir = makeIR('/src/helper.py', [helper], [], [finding]);
    ir.meta = makeMeta('/src/helper.py', 'python');

    applyRequireEntryPath([{ file: '/src/helper.py', analysis: ir }]);

    // TIER_UNKNOWN → no entry points classified → no drop under our
    // conservative "insufficient evidence" rule. Note: because we
    // additionally treat non-Java as language-partial, no annotation
    // is produced either.
    expect(ir.findings).toHaveLength(1);
  });
});

describe('applyRequireEntryPath — reachability edge cases', () => {
  it('handles the case where the sink method IS the entry point', () => {
    const handle = makeMethod('handle', 3, 20, ['@PostMapping']);
    const controller = makeType('Controller', [handle], ['@RestController']);
    const finding = makeFinding('/src/Controller.java', 10);
    const ir = makeIR('/src/Controller.java', [controller], [], [finding]);

    applyRequireEntryPath([{ file: '/src/Controller.java', analysis: ir }]);

    expect(ir.findings).toHaveLength(1);
    expect(ir.findings![0].entryPathTier).toBe('tier1-entry-point');
    // Path length 1 = sink method itself is the terminal hop.
    expect(ir.findings![0].entryPath).toHaveLength(1);
  });

  it('multi-hop chain: Controller → Service → Dao', () => {
    const handle = makeMethod('handle', 3, 20, ['@GetMapping']);
    const controller = makeType('Controller', [handle], ['@RestController']);
    const query = makeMethod('query', 3, 20);
    const service = makeType('Service', [query]);
    const runSql = makeMethod('runSql', 3, 20);
    const dao = makeType('Dao', [runSql]);

    const c1 = makeCall('query', 'handle', 10, 'Service');
    const c2 = makeCall('runSql', 'query', 10, 'Dao');
    const finding = makeFinding('/src/Dao.java', 12);

    const ctrlIR = makeIR('/src/Controller.java', [controller], [c1]);
    const svcIR = makeIR('/src/Service.java', [service], [c2]);
    const daoIR = makeIR('/src/Dao.java', [dao], [], [finding]);

    applyRequireEntryPath([
      { file: '/src/Controller.java', analysis: ctrlIR },
      { file: '/src/Service.java', analysis: svcIR },
      { file: '/src/Dao.java', analysis: daoIR },
    ]);

    expect(daoIR.findings).toHaveLength(1);
    expect(daoIR.findings![0].entryPath!.length).toBe(3); // Controller.handle → Service.query → Dao.runSql
  });
});
