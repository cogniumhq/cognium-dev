/**
 * The package entry point exports the runtime values we tell consumers to
 * import.
 *
 * 3.197.0's release notes said `SOURCE_TYPES` was available for building an
 * exhaustive map. It was not: `src/index.ts` re-exports `SourceType` under
 * `export type`, so the union's runtime array never reached the entry point
 * and the built module carried no such symbol. The claim was verified against
 * the source file rather than against what the package actually exports —
 * cognium-ai caught it by checking the built module.
 *
 * This asserts the property that was actually wrong: importing from the entry
 * point yields a *value*, not just a type. A `export type` regression makes
 * these fail, because a type-only export is `undefined` at runtime.
 */

import { describe, it, expect } from 'vitest';
import * as publicApi from '../src/index.js';
import { SOURCE_TYPES, SINK_TYPES } from '../src/index.js';
import { RULE_DEFINITIONS } from '../src/analysis/rules.js';

describe('package entry exports runtime values', () => {
  it('SOURCE_TYPES is an array at runtime, reachable from the entry point', () => {
    expect(Array.isArray(SOURCE_TYPES)).toBe(true);
    expect(SOURCE_TYPES.length).toBeGreaterThan(0);
    expect(publicApi.SOURCE_TYPES).toBe(SOURCE_TYPES);
  });

  it('SINK_TYPES is an array at runtime, reachable from the entry point', () => {
    expect(Array.isArray(SINK_TYPES)).toBe(true);
    expect(SINK_TYPES.length).toBeGreaterThan(0);
    expect(publicApi.SINK_TYPES).toBe(SINK_TYPES);
  });

  it('SINK_TYPES agrees with the rule table', () => {
    // `RULE_DEFINITIONS` is `Record<SinkType, RuleInfo>`, so the two must
    // describe the same set — a drift here means a consumer building a map
    // from one and looking up in the other gets an undefined.
    expect([...SINK_TYPES].sort()).toEqual(Object.keys(RULE_DEFINITIONS).sort());
  });

  it('both arrays are free of duplicates', () => {
    expect(new Set(SOURCE_TYPES).size).toBe(SOURCE_TYPES.length);
    expect(new Set(SINK_TYPES).size).toBe(SINK_TYPES.length);
  });

  it('SBOM generators are callable functions at the entry point', () => {
    for (const name of [
      'collectDependencies',
      'parseNpmDependencies',
      'parseNpmLockDependencies',
      'parsePypiDependencies',
      'parsePyprojectDependencies',
      'parseMavenDependencies',
      'parseGradleDependencies',
      'parseCargoDependencies',
      'parseCargoLockDependencies',
      'parsePoetryLockDependencies',
      'parseGoDependencies',
      'toCycloneDx',
      'toSpdx',
    ] as const) {
      expect(typeof (publicApi as Record<string, unknown>)[name]).toBe('function');
    }
  });
});
