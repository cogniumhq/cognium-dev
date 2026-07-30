/**
 * Sink-registry contract (cognium-dev #4 follow-up — source-of-truth
 * consolidation).
 *
 * ADR-004: `DEFAULT_SINKS` in `src/analysis/config-loader.ts` is the canonical
 * taint-sink registry. `LanguagePlugin.getBuiltinSinks()` is a supplement for
 * language-specific patterns that have no `DEFAULT_SINKS` counterpart, and the
 * YAML/JSON files under `configs/` are documentation / export only — nothing
 * reads them at runtime.
 *
 * These tests lock the invariant that made the Issue #4 `yaml.safe_load` fix
 * hard to land: the same `(class, method, cwe)` triple registered in BOTH
 * runtime surfaces. A duplicate is invisible — `findSinks` dedupes by
 * `location:line:cwe` and keeps the higher-confidence match — so the copy that
 * loses is dead weight that silently absorbs edits (fix one, the other still
 * wins).
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_SINKS, DEFAULT_SOURCES } from '../../src/analysis/config-loader.js';
import { getLanguagePlugin, registerBuiltinPlugins } from '../../src/languages/index.js';
import type { SupportedLanguage } from '../../src/types/index.js';

const LANGUAGES: SupportedLanguage[] = [
  'java',
  'javascript',
  'typescript',
  'python',
  'go',
  'rust',
  'bash',
];

const c_label = (
  cls: string | undefined,
  method: string,
  pluginCwe: string,
  configCwe: string,
  configType: string,
  pluginType: string,
) =>
  pluginCwe === configCwe
    ? `${cls ?? '*'}.${method} [${pluginCwe}] — same CWE in both surfaces`
    : `${cls ?? '*'}.${method} — config=${configType}/${configCwe} vs plugin=${pluginType}/${pluginCwe} (both fire)`;

describe('sink registry — plugin builtins do not duplicate DEFAULT_SINKS', () => {
  registerBuiltinPlugins();

  for (const language of LANGUAGES) {
    it(`${language}: no (class, method, cwe) is registered in both surfaces`, () => {
      const plugin = getLanguagePlugin(language);
      if (!plugin) return;

      const configForLanguage = DEFAULT_SINKS.filter(
        p => !p.languages || p.languages.length === 0 || p.languages.includes(language),
      );

      // Deliberate, documented dual classifications — each carries a note on
      // its DEFAULT_SINKS entry and a test that locks both halves:
      //   fmt.Fprintf  — CWE-134 (any writer) + CWE-79 (ResponseWriter shape)
      //   log.Printf/Fatalf/Panicf — CWE-134 (tainted Go format string, #264)
      //                              + CWE-117 (forged log line)
      const ALLOWED_OVERLAP = new Set([
        'fmt.Fprintf',
        'log.Printf',
        'log.Fatalf',
        'log.Panicf',
      ]);

      const duplicates: string[] = [];
      for (const pluginSink of plugin.getBuiltinSinks()) {
        if (ALLOWED_OVERLAP.has(`${pluginSink.class ?? '*'}.${pluginSink.method}`)) continue;
        const clash = configForLanguage.find(
          c =>
            (c.class ?? undefined) === (pluginSink.class ?? undefined) &&
            c.method === pluginSink.method &&
            (c.cwe === pluginSink.cwe || c.type !== pluginSink.type),
        );
        if (clash) {
          duplicates.push(
            c_label(pluginSink.class, pluginSink.method, pluginSink.cwe, clash.cwe, clash.type, pluginSink.type),
          );
        }
      }

      expect(
        duplicates,
        `These patterns exist in DEFAULT_SINKS *and* the ${language} plugin. ` +
          'Keep the DEFAULT_SINKS entry (add `languages` scoping if the pattern ' +
          'is language-specific) and delete the plugin copy — see ADR-004.',
      ).toEqual([]);
    });
  }
});

describe('source registry — plugin builtins do not duplicate DEFAULT_SOURCES', () => {
  registerBuiltinPlugins();

  for (const language of LANGUAGES) {
    it(`${language}: no identical (class, method, type) pair in both surfaces`, () => {
      const plugin = getLanguagePlugin(language);
      if (!plugin) return;

      const configForLanguage = DEFAULT_SOURCES.filter(
        p => !p.languages || p.languages.length === 0 || p.languages.includes(language),
      );

      // `findSources` pushes one TaintSource per matching pattern with no
      // dedup, so any overlap emits two sources for one call site — identical
      // ones are pure noise, and ones that disagree on `type` are worse: the
      // same read is reported under two different SourceType values.
      const duplicates: string[] = [];
      for (const pluginSource of plugin.getBuiltinSources()) {
        if (!pluginSource.method) continue;
        const clash = configForLanguage.find(
          c =>
            (c.class ?? undefined) === (pluginSource.class ?? undefined) &&
            c.method === pluginSource.method,
        );
        if (clash) {
          duplicates.push(
            `${pluginSource.class ?? '*'}.${pluginSource.method} ` +
              `[config=${clash.type}, plugin=${pluginSource.type}]`,
          );
        }
      }

      expect(
        duplicates,
        `These sources exist in DEFAULT_SOURCES *and* the ${language} plugin, ` +
          'so every matching call emits two identical TaintSource entries. ' +
          'Keep the DEFAULT_SOURCES entry and delete the plugin copy — see ADR-004.',
      ).toEqual([]);
    });
  }
});

describe('sink registry — configs/ is not a runtime surface', () => {
  it('no library module imports or reads the configs/ directory', async () => {
    // Guard for the ADR-004 claim. circle-ir must run in the browser, so the
    // library cannot read files at all; this asserts nobody re-introduces a
    // loader that makes `configs/` look authoritative.
    const { readdirSync, readFileSync, statSync } = await import('node:fs');
    const { join } = await import('node:path');

    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) {
          walk(full);
          continue;
        }
        if (!entry.endsWith('.ts')) continue;
        const text = readFileSync(full, 'utf8');
        for (const line of text.split('\n')) {
          // Comments referencing configs/ are fine (and plentiful); a real
          // read would be an import or an fs call naming the path.
          const trimmed = line.trim();
          if (trimmed.startsWith('*') || trimmed.startsWith('//')) continue;
          if (/(?:import|require|readFile|readFileSync|fetch)\s*\(?[^\n]*configs\//.test(line)) {
            offenders.push(`${full}: ${trimmed}`);
          }
        }
      }
    };
    walk(new URL('../../src', import.meta.url).pathname);

    expect(offenders).toEqual([]);
  });
});
