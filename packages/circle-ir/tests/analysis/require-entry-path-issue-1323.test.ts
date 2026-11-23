/**
 * cognium-dev#1323 — imported Express handlers must be entry points for
 * require-entry-path even when the route registration lives in another file.
 */

import { describe, it, expect } from 'vitest';
import { applyRequireEntryPath } from '../../src/analysis/require-entry-path.js';
import type {
  CircleIR,
  ImportInfo,
  Meta,
  MethodInfo,
  RuntimeRegistration,
  SastFinding,
  TypeInfo,
} from '../../src/types/index.js';

function makeMeta(file: string, language: string): Meta {
  return {
    file,
    language,
    loc: 50,
    hash: 'test',
    parsed_at: new Date().toISOString(),
  } as Meta;
}

function makeMethod(name: string, startLine: number, endLine: number): MethodInfo {
  return {
    name,
    return_type: 'void',
    parameters: [],
    annotations: [],
    modifiers: [],
    start_line: startLine,
    end_line: endLine,
  };
}

function makeType(name: string, methods: MethodInfo[]): TypeInfo {
  return {
    name,
    kind: 'class',
    package: null,
    extends: null,
    implements: [],
    annotations: [],
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
    imports?: ImportInfo[];
    runtimeRegistrations?: RuntimeRegistration[];
    findings?: SastFinding[];
  } = {},
): CircleIR {
  return {
    meta: makeMeta(file, language),
    types,
    calls: [],
    cfg: { blocks: [], edges: [] },
    dfg: { defs: [], uses: [], chains: [] },
    taint: { sources: [], sinks: [], sanitizers: [] },
    imports: opts.imports ?? [],
    exports: [],
    unresolved: [],
    enriched: { types: [] },
    findings: opts.findings,
    runtime_registrations: opts.runtimeRegistrations,
  } as unknown as CircleIR;
}

describe('require-entry-path #1323 imported Express handler', () => {
  it('keeps command_injection on handler.ts when routes.ts registers imported run', () => {
    const run = makeMethod('run', 4, 8);
    const headers = makeMethod('headers', 10, 13);
    const routesRegs: RuntimeRegistration[] = [
      {
        kind: 'http_route',
        framework: 'express',
        registrar: { method: 'get', receiver: 'router', line: 12, column: 0 },
        path: '/run',
        handler: { name: 'run', line: 12, column: 16 },
      },
    ];
    const routesIR = makeIR('routes.ts', 'typescript', [makeType('__module__', [headers])], {
      imports: [
        {
          imported_name: 'run',
          from_package: './handler',
          alias: null,
          is_wildcard: false,
          line_number: 2,
        },
      ],
      runtimeRegistrations: routesRegs,
    });

    const finding: SastFinding = {
      id: 'cmd-1',
      pass: 'sink-filter',
      category: 'security',
      rule_id: 'command_injection',
      severity: 'high',
      level: 'error',
      message: 'cmdi',
      file: 'handler.ts',
      line: 5,
    };
    const handlerIR = makeIR('handler.ts', 'typescript', [makeType('__module__', [run])], {
      findings: [finding],
    });

    applyRequireEntryPath(
      [
        { file: 'routes.ts', analysis: routesIR },
        { file: 'handler.ts', analysis: handlerIR },
      ],
      { projectProfile: 'application/production' },
    );

    expect(handlerIR.findings).toHaveLength(1);
    expect(handlerIR.findings![0].entryPath).toBeDefined();
    expect(handlerIR.findings![0].entryPathTier).toBe('tier1-entry-point');
  });
});