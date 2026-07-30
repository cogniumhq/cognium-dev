/**
 * Test helper: the *effective* taint-sink registry for a language.
 *
 * Two TypeScript surfaces are consulted at runtime (ADR-004):
 *   1. `DEFAULT_SINKS` (`src/analysis/config-loader.ts`) — canonical; entries
 *      may be language-scoped via `languages: [...]`.
 *   2. `LanguagePlugin.getBuiltinSinks()` — language-specific supplements for
 *      patterns that have no `DEFAULT_SINKS` counterpart.
 *
 * `TaintMatcherPass` merges them as `[...config, ...plugin]` and
 * `findSinks` filters the config half by `languages` before matching. This
 * helper reproduces that merge so tests can assert "language L registers sink
 * X" without hard-coding *which* surface holds it — the split is an
 * implementation detail, and moving an entry between the two must not break
 * a coverage test.
 */

import { DEFAULT_SINKS, DEFAULT_SOURCES } from '../../src/analysis/config-loader.js';
import { getLanguagePlugin, registerBuiltinPlugins } from '../../src/languages/index.js';
import type { SupportedLanguage } from '../../src/types/index.js';

export interface RuntimeSink {
  method: string;
  class?: string;
  type: string;
  cwe: string;
  severity: string;
  argPositions: number[];
  /** Which surface the entry came from. */
  surface: 'config' | 'plugin';
}

/**
 * All sink patterns that can match a call in `language`, in the same order
 * `findSinks` iterates them (config first, then plugin builtins).
 */
export function runtimeSinks(language: SupportedLanguage): RuntimeSink[] {
  registerBuiltinPlugins();

  const out: RuntimeSink[] = DEFAULT_SINKS.filter(
    p => !p.languages || p.languages.length === 0 || p.languages.includes(language),
  ).map(p => ({
    method: p.method,
    class: p.class,
    type: p.type,
    cwe: p.cwe,
    severity: p.severity,
    argPositions: p.arg_positions,
    surface: 'config' as const,
  }));

  const plugin = getLanguagePlugin(language);
  if (plugin) {
    for (const p of plugin.getBuiltinSinks()) {
      out.push({
        method: p.method,
        class: p.class,
        type: p.type,
        cwe: p.cwe,
        severity: p.severity,
        argPositions: p.argPositions,
        surface: 'plugin',
      });
    }
  }

  return out;
}

export interface RuntimeSource {
  method?: string;
  class?: string;
  annotation?: string;
  type: string;
  severity: string;
  returnTainted: boolean;
  surface: 'config' | 'plugin';
}

/**
 * All source patterns that can match a call in `language`, in the same order
 * `findSources` iterates them (config first, then plugin builtins).
 */
export function runtimeSources(language: SupportedLanguage): RuntimeSource[] {
  registerBuiltinPlugins();

  const out: RuntimeSource[] = DEFAULT_SOURCES.filter(
    p => !p.languages || p.languages.length === 0 || p.languages.includes(language),
  ).map(p => ({
    method: p.method,
    class: p.class,
    annotation: p.annotation,
    type: p.type,
    severity: p.severity,
    returnTainted: p.return_tainted ?? false,
    surface: 'config' as const,
  }));

  const plugin = getLanguagePlugin(language);
  if (plugin) {
    for (const p of plugin.getBuiltinSources()) {
      out.push({
        method: p.method,
        class: p.class,
        annotation: p.annotation,
        type: p.type,
        severity: p.severity,
        returnTainted: p.returnTainted ?? false,
        surface: 'plugin',
      });
    }
  }

  return out;
}

/**
 * First sink matching `method` (and `class`, when given) — i.e. the entry that
 * wins the `findSinks` dedup slot on a confidence tie, since the map keeps the
 * first writer unless a later pattern scores strictly higher.
 */
export function findRuntimeSink(
  language: SupportedLanguage,
  method: string,
  cls?: string | null,
): RuntimeSink | undefined {
  return runtimeSinks(language).find(
    s => s.method === method && (cls === undefined || (cls === null ? !s.class : s.class === cls)),
  );
}
