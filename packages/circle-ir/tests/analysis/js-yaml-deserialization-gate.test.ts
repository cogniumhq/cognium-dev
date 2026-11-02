/**
 * Deserialization gate E — js-yaml (conformis' SAST gate on 4.18.1:
 * `yaml.load(readFileSync(...))` was a critical CWE-502). js-yaml 4 removed
 * the code-building `!!js/*` types, so `load` on js-yaml ≥ 4, or with an
 * explicit schema that builds no code, is not a deserialization sink.
 * js-yaml 3's `load` (DEFAULT_FULL_SCHEMA), an unknown version, the full
 * schema, and other libraries' `load` stay sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { resolveJsYamlMajor, jsYamlBindings } from '../../src/analysis/dependency-versions.js';

const lock = (v: string) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/js-yaml': { version: v } } });
const pkg = (range: string) => JSON.stringify({ dependencies: { 'js-yaml': range } });

const deser = async (code: string, js?: { packageJson?: string; packageLock?: string }) =>
  (await analyze(code, 'c.ts', 'typescript', js ? { dependencyContext: { js } } : {})).taint.sinks
    .filter(s => s.type === 'deserialization');

const IMPORT = `import yaml from 'js-yaml';\nimport { readFileSync } from 'fs';\n`;
const LOAD = `${IMPORT}export function cfg(req: any) {\n  return yaml.load(req.body);\n}\n`;

describe('resolveJsYamlMajor', () => {
  it('reads the lockfile first, then a single-major package.json range', () => {
    expect(resolveJsYamlMajor({ packageLock: lock('4.1.0'), packageJson: pkg('^3.14.1') })).toEqual({ major: 4, from: 'lockfile' });
    expect(resolveJsYamlMajor({ packageLock: JSON.stringify({ dependencies: { 'js-yaml': { version: '3.14.1' } } }) })).toEqual({ major: 3, from: 'lockfile' });
    expect(resolveJsYamlMajor({ packageJson: pkg('^5.4.2') })).toEqual({ major: 5, from: 'package.json' });
    expect(resolveJsYamlMajor({ packageJson: pkg('~3.14.1') })).toEqual({ major: 3, from: 'package.json' });
    expect(resolveJsYamlMajor({ packageJson: pkg('4.x') })).toEqual({ major: 4, from: 'package.json' });
  });
  it('is null when nothing names one major', () => {
    expect(resolveJsYamlMajor(undefined)).toBeNull();
    expect(resolveJsYamlMajor({ packageJson: pkg('>=3') })).toBeNull();
    expect(resolveJsYamlMajor({ packageJson: pkg('*') })).toBeNull();
    expect(resolveJsYamlMajor({ packageJson: JSON.stringify({ dependencies: { yaml: '^2.0.0' } }) })).toBeNull();
    expect(resolveJsYamlMajor({ packageLock: 'not json' })).toBeNull();
  });
});

describe('jsYamlBindings', () => {
  it('finds default, namespace, require and named bindings, and the full schema', () => {
    expect([...jsYamlBindings(`import * as Y from "js-yaml";`).namespaces]).toEqual(['Y']);
    expect([...jsYamlBindings(`const jsyaml = require('js-yaml');`).namespaces]).toEqual(['jsyaml']);
    expect([...jsYamlBindings(`import { load, dump } from 'js-yaml';`).functions]).toEqual(['load']);
    expect([...jsYamlBindings(`const { loadAll } = require('js-yaml');`).functions]).toEqual(['loadAll']);
    expect(jsYamlBindings(`import yaml from 'js-yaml';\nyaml.load(x, { schema: yaml.DEFAULT_FULL_SCHEMA });`).full).toBe(true);
    expect(jsYamlBindings(`const y = require('js-yaml/lib/js-yaml');`).full).toBe(true);
  });
});

describe('deserialization gate E — js-yaml', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('js-yaml ≥ 4 from the lockfile or package.json: load is not a sink', async () => {
    expect(await deser(LOAD, { packageLock: lock('4.1.0') })).toHaveLength(0);
    expect(await deser(LOAD, { packageJson: pkg('^5.4.2') })).toHaveLength(0);
    expect(await deser(`${IMPORT}export const c = (p: string) => yaml.load(readFileSync(p, 'utf8'));\n`, { packageJson: pkg('^4.1.0') })).toHaveLength(0);
  });

  it('an explicit schema that builds no code: not a sink whatever the version', async () => {
    const code = `${IMPORT}export function cfg(req: any) {\n  return yaml.load(req.body, {\n    schema: yaml.CORE_SCHEMA,\n  });\n}\n`;
    expect(await deser(code)).toHaveLength(0);
    expect(await deser(code, { packageJson: pkg('^3.14.1') })).toHaveLength(0);
    expect(await deser(`import { load, FAILSAFE_SCHEMA } from 'js-yaml';\nexport const c = (s: string) => load(s, { schema: FAILSAFE_SCHEMA });\n`)).toHaveLength(0);
  });

  it('stays a sink: js-yaml 3, unknown version, the full schema, js-yaml/lib, another library', async () => {
    expect((await deser(LOAD, { packageJson: pkg('^3.14.1') })).length).toBeGreaterThan(0);
    expect((await deser(LOAD)).length).toBeGreaterThan(0);
    expect((await deser(LOAD, { packageJson: pkg('>=3') })).length).toBeGreaterThan(0);
    const full = `${IMPORT}export function cfg(req: any) {\n  return yaml.load(req.body, { schema: yaml.DEFAULT_FULL_SCHEMA });\n}\n`;
    expect((await deser(full, { packageLock: lock('4.1.0') })).length).toBeGreaterThan(0);
    const lib = `const yaml = require('js-yaml/lib/js-yaml');\nexport function cfg(req) {\n  return yaml.load(req.body);\n}\n`;
    expect((await deser(lib, { packageLock: lock('4.1.0') })).length).toBeGreaterThan(0);
  });

  it('the flow from a request body goes with the sink', async () => {
    const flows = async (js?: { packageLock?: string }) =>
      (await analyze(LOAD, 'c.ts', 'typescript', js ? { dependencyContext: { js } } : {})).taint.flows.filter(f => f.sink_type === 'deserialization');
    expect((await flows()).length).toBeGreaterThan(0);
    expect(await flows({ packageLock: lock('4.1.0') })).toHaveLength(0);
  });
});
