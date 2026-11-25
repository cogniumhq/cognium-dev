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

/**
 * #1311: the React Native app entry (`index.js` registering the root
 * component, Expo's `App.tsx`) and platform files (`Button.ios.tsx`,
 * `Button.android.tsx`) that Metro picks for `import './Button'`.
 */
describe('React Native entry and platform files', () => {
  const rnRoot = 'apps/rn';
  const rnFiles = Object.entries({
    'index.js': "import { AppRegistry } from 'react-native';\nimport { boot } from './src/boot';\nboot();\nAppRegistry.registerComponent('rn', () => null);",
    'src/boot.ts': "import Button from './Button';\nimport { haptic } from './haptics';\nimport { Store } from './store';\nexport function boot() { haptic(); new Store().load(); return Button(); }",
    'src/Button.ios.tsx': 'export default function IosButton() { return iosShadow(); }\nfunction iosShadow() { return null; }',
    'src/Button.android.tsx': 'export default function AndroidButton() { return elevation(); }\nfunction elevation() { return null; }',
    'src/haptics.ts': 'export function haptic() { return 0; }',
    'src/haptics.native.ts': 'export function haptic() { return 1; }',
    'src/haptics.web.ts': 'export function haptic() { return 2; }\nexport function webOnly() { return 3; }',
    'src/store/index.ios.ts': 'export class Store { load() { return 1; } save() { return 2; } }',
    'src/store/index.android.ts': 'export class Store { load() { return 1; } save() { return 2; } }',
    'src/idle.ios.ts': 'export function idleIos() { return 4; }',
    'src/idle.android.ts': 'export function idleAndroid() { return 5; }',
  }).map(([p, code]) => ({ path: `${rnRoot}/${p}`, code, ids: { packageName: 'rn' } }));
  const rnDeps = JSON.stringify({ dependencies: { 'react-native': '0.76.0' } });

  it('index.js is the app entry and every platform variant is as live as the import', async () => {
    const g = await buildTsCallGraph(rnFiles, { packages: [{ root: rnRoot, packageJson: rnDeps }] });
    const v = verdicts(g);
    for (const name of ['boot', 'IosButton', 'iosShadow', 'AndroidButton', 'elevation', 'haptic', 'Store.load']) {
      expect([name, v[name]]).toEqual([name, 'live']);
    }
    const facts = deadCode(g).facts;
    const byFile = (suffix: string) => facts.filter(f => f.file.endsWith(suffix)).map(f => `${f.qualified_name.replace(/^.*:/, '')} ${f.verdict}`);
    // Each variant of `haptic` is reached, not only the one the import resolved to.
    for (const f of ['src/haptics.ts', 'src/haptics.native.ts']) expect(byFile(f)).toContain('haptic live');
    expect(byFile('src/haptics.web.ts')).toEqual(expect.arrayContaining(['haptic live', 'webOnly dead']));
    for (const f of ['src/store/index.ios.ts', 'src/store/index.android.ts']) expect(byFile(f)).toEqual(expect.arrayContaining(['Store.load live', 'Store.save dead']));
    // Variants nothing imports are still dead.
    expect(v.idleIos).toBe('dead');
    expect(v.idleAndroid).toBe('dead');
    expect(g.entries.some(e => e.framework === 'react-native' && e.file === `${rnRoot}/index.js`)).toBe(true);
  });

  it("Expo's App.tsx is the app entry", async () => {
    const g = await buildTsCallGraph(
      [{ path: `${rnRoot}/App.tsx`, code: "import Button from './src/Button';\nexport default function App() { return Button(); }", ids: { packageName: 'rn' } }, ...rnFiles.filter(f => !f.path.endsWith('index.js'))],
      { packages: [{ root: rnRoot, packageJson: JSON.stringify({ main: 'node_modules/expo/AppEntry.js', dependencies: { expo: '52.0.0', 'react-native': '0.76.0' } }) }] },
    );
    const v = verdicts(g);
    for (const name of ['App', 'IosButton', 'AndroidButton']) expect([name, v[name]]).toEqual([name, 'live']);
  });

  it('nothing without react-native or expo', async () => {
    const g = await buildTsCallGraph(rnFiles, { packages: [{ root: rnRoot, packageJson: '{}' }] });
    const v = verdicts(g);
    expect(v.boot).toBe('dead');
    expect(v.IosButton).toBe('dead');
    expect(g.entries.filter(e => e.framework === 'react-native')).toEqual([]);
  });

  it('a package without react-native inside an app does not resolve platform files', async () => {
    const g = await buildTsCallGraph(
      [...rnFiles, { path: `${rnRoot}/lib/main.ts`, code: "import Button from '../src/Button';\nexport function main() { return Button(); }", ids: { packageName: 'rn' } }],
      { packages: [{ root: rnRoot, packageJson: rnDeps }, { root: `${rnRoot}/lib`, packageJson: JSON.stringify({ main: 'main.ts' }) }] },
    );
    const moduleOf = (suffix: string) => g.files.find(f => f.file.endsWith(suffix))!.decls[0].id;
    const imported = (from: string, to: string) => g.imports.some(i => i.from === moduleOf(from) && i.to === moduleOf(to));
    expect(imported('src/boot.ts', 'src/Button.ios.tsx')).toBe(true);
    expect(imported('lib/main.ts', 'src/Button.ios.tsx')).toBe(false);
  });

  // react-native-windows / react-native-macos resolve `.windows` / `.macos` like the core platforms (same list as the test-file gate).
  it('windows and macos variants are platform files too, and index.windows.js is an entry', async () => {
    const files = [
      ...rnFiles,
      { path: `${rnRoot}/src/Button.windows.tsx`, code: 'export default function WinButton() { return winChrome(); }\nfunction winChrome() { return null; }', ids: { packageName: 'rn' } },
      { path: `${rnRoot}/src/Button.macos.tsx`, code: 'export default function MacButton() { return null; }', ids: { packageName: 'rn' } },
      { path: `${rnRoot}/index.windows.js`, code: "import { winBoot } from './src/winBoot';\nwinBoot();", ids: { packageName: 'rn' } },
      { path: `${rnRoot}/src/winBoot.ts`, code: 'export function winBoot() { return 7; }', ids: { packageName: 'rn' } },
    ];
    const g = await buildTsCallGraph(files, { packages: [{ root: rnRoot, packageJson: rnDeps }] });
    const v = verdicts(g);
    for (const name of ['WinButton', 'winChrome', 'MacButton', 'winBoot']) expect([name, v[name]]).toEqual([name, 'live']);
    expect(g.entries.some(e => e.framework === 'react-native' && e.file === `${rnRoot}/index.windows.js`)).toBe(true);
  });

  it('the tables can turn platform files off', async () => {
    const g = await buildTsCallGraph(rnFiles, {
      packages: [{ root: rnRoot, packageJson: rnDeps }],
      entryTables: { ...DEFAULT_ENTRY_TABLES, platformFiles: undefined },
    });
    const v = verdicts(g);
    expect(v.boot).toBe('live');
    expect(v.IosButton).toBe('dead');
    expect(v.AndroidButton).toBe('dead');
  });
});
