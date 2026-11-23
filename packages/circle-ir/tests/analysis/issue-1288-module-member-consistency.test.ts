/**
 * #1288 S2: module / field verdicts must not contradict member may-be-live (#952 repro).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser } from '../../src/core/parser.js';
import { buildTsCallGraph } from '../../src/navigation/index.js';
import { deadCode, deadCodeConsistencyViolations } from '../../src/graph-facts/index.js';

beforeAll(async () => {
  await initParser();
});

const root = 'expo-app';
const pkg = JSON.stringify({
  main: 'expo-router/entry',
  dependencies: { expo: '52.0.0', 'expo-router': '4.0.0', react: '18.0.0' },
});

const expoFiles = [
  {
    path: `${root}/app/_layout.tsx`,
    code: 'export default function Layout() { return null; }',
    ids: { packageName: 'app' },
  },
  {
    path: `${root}/app/settings/index.tsx`,
    code: [
      "import * as handlers from '../../src/lib/handlers';",
      'export default function Settings(p: { k: string }) { return (handlers as any)[p.k](); }',
    ].join('\n'),
    ids: { packageName: 'app' },
  },
  {
    path: `${root}/src/lib/handlers.ts`,
    code: [
      'export const VERSION = 3;',
      "export function onA() { return 'a'; }",
      "export function onB() { return 'b'; }",
    ].join('\n'),
    ids: { packageName: 'app' },
  },
  {
    path: `${root}/src/lib/plugins.ts`,
    code: [
      'export class Registry {',
      '  count = 0;',
      '  run(n: string) { return (this as any)[n](); }',
      '  helper() { return 1; }',
      '}',
    ].join('\n'),
    ids: { packageName: 'app' },
  },
  {
    path: `${root}/src/lib/orphan.ts`,
    code: 'export function neverCalled() { return 42; }',
    ids: { packageName: 'app' },
  },
];

describe('issue #1288 module/field verdict consistency', () => {
  it('lifts module and field containers when members are may-be-live (synthetic #952)', async () => {
    const g = await buildTsCallGraph(expoFiles, { packages: [{ root, packageJson: pkg, appJson: '{}' }] });
    const r = deadCode(g);
    const v = Object.fromEntries(r.facts.map(f => [f.qualified_name, f.verdict]));

    expect(v['app/expo-app/src/lib/handlers:onA']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/handlers:onB']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/handlers']).not.toBe('dead');

    expect(v['app/expo-app/src/lib/plugins:Registry.run']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/plugins']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/plugins:Registry.count']).toBe('may-be-live');

    expect(v['app/expo-app/src/lib/orphan:neverCalled']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/orphan']).toBe('may-be-live');

    expect(deadCodeConsistencyViolations(r.facts, g)).toEqual([]);
    expect(v['app/expo-app/src/lib/plugins:Registry.helper']).toBe('may-be-live');
  });
});