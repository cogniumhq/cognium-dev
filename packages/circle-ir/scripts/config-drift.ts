#!/usr/bin/env npx tsx
/**
 * configs/ drift report (cognium-dev #4 follow-up — source-of-truth
 * consolidation).
 *
 * The YAML/JSON files under `configs/` are documentation and an export
 * surface for downstream consumers — nothing in `src/` reads them (circle-ir
 * must run in the browser, so it cannot read files at all). The runtime
 * registries are `DEFAULT_SOURCES` / `DEFAULT_SINKS` in
 * `src/analysis/config-loader.ts` plus the per-language
 * `LanguagePlugin.getBuiltinSinks()` / `getBuiltinSources()` supplements.
 *
 * That split is exactly what made Issue #4 (`yaml.safe_load` mis-registered
 * as a CWE-502 sink) expensive to diagnose: the YAML said one thing and the
 * code did another, with no signal that they had diverged. This script prints
 * that divergence so it can be reviewed deliberately.
 *
 * It is a *report*, not a gate — configs/ is allowed to lag. Run it before
 * publishing if you care about what consumers of the shipped `configs/`
 * directory will see:
 *
 *     npm run config:drift
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { parse as parseYaml } from 'yaml';
import { DEFAULT_SINKS } from '../src/analysis/config-loader.js';
import { getLanguagePlugin, registerBuiltinPlugins } from '../src/languages/index.js';
import type { SupportedLanguage } from '../src/types/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SINK_DIR = path.join(__dirname, '..', 'configs', 'sinks');

/** Config files whose contents are specific to one language. */
const FILE_LANGUAGE: Record<string, SupportedLanguage | undefined> = {
  'python.json': 'python',
  'golang.json': 'go',
  'nodejs.json': 'javascript',
  'rust.json': 'rust',
};

interface ConfigSink {
  method: string;
  class?: string;
  type: string;
  cwe?: string;
}

function runtimeSinkIndex(language?: SupportedLanguage): Map<string, string> {
  registerBuiltinPlugins();
  const index = new Map<string, string>();
  const key = (cls: string | undefined, method: string) => `${cls ?? '*'}.${method}`;

  for (const sink of DEFAULT_SINKS) {
    if (language && sink.languages && !sink.languages.includes(language)) continue;
    index.set(key(sink.class, sink.method), sink.type);
  }
  if (language) {
    const plugin = getLanguagePlugin(language);
    if (plugin) {
      for (const sink of plugin.getBuiltinSinks()) {
        index.set(key(sink.class, sink.method), sink.type);
      }
    }
  }
  return index;
}

let totalEntries = 0;
let totalMissing = 0;
let totalMismatch = 0;

for (const file of fs.readdirSync(SINK_DIR).sort()) {
  const raw = fs.readFileSync(path.join(SINK_DIR, file), 'utf8');
  const doc = file.endsWith('.json') ? JSON.parse(raw) : parseYaml(raw);
  const sinks: ConfigSink[] = doc?.sinks ?? [];
  if (sinks.length === 0) continue;

  const language = FILE_LANGUAGE[file];
  const runtime = runtimeSinkIndex(language);

  const missing: string[] = [];
  const mismatched: string[] = [];
  for (const sink of sinks) {
    const name = `${sink.class ?? '*'}.${sink.method}`;
    const runtimeType = runtime.get(name);
    if (runtimeType === undefined) missing.push(`${name} (${sink.type})`);
    else if (runtimeType !== sink.type) mismatched.push(`${name}: config=${sink.type} runtime=${runtimeType}`);
  }

  totalEntries += sinks.length;
  totalMissing += missing.length;
  totalMismatch += mismatched.length;

  const status = missing.length === 0 && mismatched.length === 0 ? 'in sync' : 'DRIFT';
  console.log(
    `\n${file} (language: ${language ?? 'any'}) — ${sinks.length} documented, ${status}`,
  );
  for (const entry of missing) console.log(`  not registered at runtime: ${entry}`);
  for (const entry of mismatched) console.log(`  type disagreement:        ${entry}`);
}

console.log(
  `\nTotal: ${totalEntries} documented sinks · ${totalMissing} absent from the runtime registries · ${totalMismatch} typed differently.`,
);
console.log(
  'configs/ is documentation / export only (ADR-004) — this report never fails the build.',
);
