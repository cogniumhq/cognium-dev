/**
 * #1288 (partial): Jest manual mocks under `__mocks__/` are analysis entries when
 * Jest is configured, even on an Expo app whose package.json omits `jest` but
 * ships `jest.config.*` (jest-expo preset).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser } from '../../src/core/parser.js';
import { buildTsCallGraph } from '../../src/navigation/index.js';
import { deadCode } from '../../src/graph-facts/index.js';

beforeAll(async () => {
  await initParser();
});

const root = 'expo-app';
const expoDeps = {
  main: 'expo-router/entry',
  dependencies: { expo: '52.0.0', 'expo-router': '4.0.0', react: '18.0.0' },
  devDependencies: { 'jest-expo': '52.0.0' },
};

describe('issue #1288 jest manual mock entries', () => {
  it('treats package-root __mocks__ as test entries when jest.config is present', async () => {
    const packageJson = JSON.stringify(expoDeps);
    const files = [
      { path: `${root}/app/_layout.tsx`, code: 'export default function Layout() { return null; }', ids: { packageName: 'app' } },
      { path: `${root}/jest.config.js`, code: "module.exports = { preset: 'jest-expo' };", ids: { packageName: 'app' } },
      { path: `${root}/__mocks__/expo-haptics.ts`, code: 'export const impactAsync = () => 1;', ids: { packageName: 'app' } },
      { path: `${root}/src/lib/orphan.ts`, code: 'export function neverCalled() { return 42; }', ids: { packageName: 'app' } },
    ];
    const g = await buildTsCallGraph(files, { packages: [{ root, packageJson, appJson: '{}' }] });
    const mockEntries = g.entries.filter(e => e.file.includes('__mocks__/expo-haptics'));
    expect(mockEntries.length).toBeGreaterThan(0);
    expect(mockEntries.every(e => e.kind === 'test' && e.framework === 'jest')).toBe(true);
    const verdicts = Object.fromEntries(
      deadCode(g).facts
        .filter(f => f.file.includes('__mocks__'))
        .map(f => [f.qualified_name.replace(/^.*:/, ''), f.verdict]),
    );
    expect(verdicts.impactAsync).toBeUndefined();
    expect(deadCode(g).facts.find(f => f.file.includes('orphan') && f.qualified_name.endsWith('neverCalled'))?.verdict).toBe('dead');
  });
});