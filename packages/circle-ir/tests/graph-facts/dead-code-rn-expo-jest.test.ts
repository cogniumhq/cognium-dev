/**
 * React Native, Expo and Jest load files by name or place: expo-router
 * screens under `app/`, config plugins, Metro/Babel/Jest configs, Jest setup
 * files, `__mocks__` and test files. They are entries only when the package
 * depends on the tool.
 */

import { describe, it, expect } from 'vitest';
import { buildTsCallGraph, DEFAULT_ENTRY_TABLES, type TsCallGraph } from '../../src/navigation/index.js';
import { deadCode } from '../../src/graph-facts/index.js';

const root = 'apps/mobile';
const files = Object.entries({
  'app/_layout.tsx': 'export default function RootLayout() { return null; }',
  'app/+html.tsx': 'export default function Root() { return null; }',
  'app/+not-found.tsx': 'export default function NotFound() { return null; }',
  'app/(tabs)/index.tsx': 'export default function Home() { return null; }',
  'app/(tabs)/settings.tsx': 'export default function Settings() { return null; }\nexport function ErrorBoundary() { return null; }',
  'app/user/[id].tsx': 'export default function User() { return null; }',
  'app/docs/[...rest].tsx': 'export default function Docs() { return null; }',
  'app/hello+api.ts': 'export function GET() { return 1; }\nexport function helper() { return 2; }',
  'app.config.ts': "export default { name: 'x', plugins: ['expo-router', './plugins/withThing', ['./plugins/withOpts', { a: 1 }]] };",
  'plugins/withThing.js': 'function withThing(c) { return c; }\nmodule.exports = withThing;',
  'plugins/withOpts.ts': 'export default function withOpts(c: unknown) { return c; }',
  'plugins/withJson.ts': 'export default function withJson(c: unknown) { return c; }',
  'plugins/unused.ts': 'export default function unusedPlugin(c: unknown) { return c; }',
  'metro.config.js': 'function metro() { return {}; }\nmodule.exports = metro();',
  'babel.config.js': 'module.exports = function babel(api) { return {}; };',
  'jest.config.ts': 'export default { preset: "jest-expo" };',
  'jest-setup.ts': 'export function setupMocks() { return 1; }\nsetupMocks();',
  '__mocks__/expo-haptics.ts': 'export function impactAsync() { return 1; }',
  'src/thing.test.ts': 'function fixture() { return 1; }\nfixture();',
  'src/lib/idle.ts': 'export function idle() { return 3; }',
}).map(([p, code]) => ({ path: `${root}/${p}`, code, ids: { packageName: 'm' } }));

const deps = { dependencies: { expo: '52.0.0', 'expo-router': '4.0.0', 'react-native': '0.76.0' }, devDependencies: { jest: '29.0.0' } };
const appJson = JSON.stringify({ expo: { plugins: ['./plugins/withJson'] } });

const verdicts = (g: TsCallGraph): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const f of deadCode(g).facts) out[f.qualified_name.replace(/^.*:/, '')] = f.verdict;
  return out;
};

describe('React Native / Expo / Jest entry points', () => {
  it('expo-router routes, config plugins and tool files are entries', async () => {
    const g = await buildTsCallGraph(files, { packages: [{ root, packageJson: JSON.stringify(deps), appJson }] });
    const q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name.replace(/^.*:/, '')] as const)));
    const routes = g.entries
      .filter(e => e.framework === 'expo-router')
      .map(e => `${e.kind} ${e.method ?? ''} ${e.path ?? ''} ${q.get(e.id)}${e.surface ? ` [${e.surface}]` : ''}`.replace(/\s+/g, ' '))
      .sort();
    expect(routes).toEqual([
      'lifecycle / Root',
      'lifecycle /settings ErrorBoundary',
      'route GET / Home [page]',
      'route GET / NotFound [page]',
      'route GET / RootLayout [layout]',
      'route GET /docs/{rest} Docs [page]',
      'route GET /hello GET [api]',
      'route GET /settings Settings [page]',
      'route GET /user/{id} User [page]',
    ]);
    const v = verdicts(g);
    for (const name of ['RootLayout', 'Home', 'Settings', 'User', 'Docs', 'GET', 'withThing', 'withOpts', 'withJson', 'metro']) {
      expect([name, v[name]]).toEqual([name, 'live']);
    }
    // Jest setup, mocks and tests are test files: their declarations are not reported.
    for (const name of ['setupMocks', 'impactAsync', 'fixture']) expect([name, v[name]]).toEqual([name, undefined]);
    expect(v.unusedPlugin).toBe('dead');
    expect(v.idle).toBe('dead');
    expect(v.helper).toBe('dead');
    const tools = [...new Set(g.entries.map(e => e.framework).filter(f => f && f !== 'expo-router'))].sort();
    expect(tools).toEqual(['babel', 'expo', 'jest', 'metro']);
  });

  it('nothing without the dependencies', async () => {
    const g = await buildTsCallGraph(files, { packages: [{ root, packageJson: '{}', appJson }] });
    expect(g.entries.filter(e => ['expo-router', 'expo', 'metro', 'babel', 'jest'].includes(e.framework ?? ''))).toEqual([]);
    const v = verdicts(g);
    expect(v.RootLayout).toBe('dead');
    expect(v.withJson).toBe('dead');
    expect(v.impactAsync).toBe('dead');
    expect(v.setupMocks).toBe('dead');
    // The runner-agnostic test-file rule is unchanged: `*.test.ts` is still a test file.
    expect(v.fixture).toBeUndefined();
  });

  it('jest alone turns on the Jest rows only', async () => {
    const g = await buildTsCallGraph(files, { packages: [{ root, packageJson: JSON.stringify({ devDependencies: { jest: '29.0.0' } }) }] });
    const v = verdicts(g);
    expect(v.impactAsync).toBeUndefined();
    expect(v.setupMocks).toBeUndefined();
    expect(v.RootLayout).toBe('dead');
    expect(v.metro).toBe('dead');
  });

  it('the tables can turn it off', async () => {
    const g = await buildTsCallGraph(files, {
      packages: [{ root, packageJson: JSON.stringify(deps), appJson }],
      entryTables: { ...DEFAULT_ENTRY_TABLES, toolFiles: undefined, expo: undefined },
    });
    expect(verdicts(g).RootLayout).toBe('dead');
  });
});
