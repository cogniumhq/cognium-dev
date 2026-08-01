/**
 * Emitted taint types conform to the published unions (cognium-dev #4
 * follow-up).
 *
 * Language-plugin builtins used to declare `type` as a bare `string`, which
 * `TaintMatcherPass` cast to `SourceType` / `SinkType` when merging them into
 * the config. A typo or an unlisted category therefore compiled cleanly and
 * shipped to consumers as a value the exported type said was impossible.
 *
 * That failure mode is *silent* on the consumer side: an unmatched source type
 * does not throw or log, it falls through to a default branch — and when that
 * branch is a severity gate, real findings get quietly demoted rather than
 * dropped. cognium-ai hit exactly this when the Python `user_input` /
 * `env_var` duplicates were removed in 3.195.0.
 *
 * The plugin interfaces are typed against the unions now, so the compiler is
 * the primary guard. These tests are the runtime backstop for anything that
 * reaches the arrays through a cast or a plugin registered at runtime by a
 * third party.
 */

import { describe, it, expect } from 'vitest';
import { DEFAULT_SINKS } from '../../src/analysis/config-loader.js';
import { RULE_DEFINITIONS } from '../../src/analysis/rules.js';
import { getLanguagePlugin, registerBuiltinPlugins } from '../../src/languages/index.js';
import { SOURCE_TYPES } from '../../src/types/index.js';
import type { SupportedLanguage } from '../../src/types/index.js';

const LANGUAGES: SupportedLanguage[] = [
  'java',
  'javascript',
  'typescript',
  'python',
  'go',
  'rust',
  'bash',
  'html',
  'vue',
];

// `SOURCE_TYPES` is the union itself, exported as a runtime array so this can
// be checked at all. Sink types are covered by RULE_DEFINITIONS, which is
// `Record<SinkType, RuleInfo>` and therefore exhaustive by construction.
const SINK_TYPE_SET = new Set<string>([
  ...DEFAULT_SINKS.map(s => s.type),
  ...Object.keys(RULE_DEFINITIONS),
]);
const SOURCE_TYPE_SET = new Set<string>(SOURCE_TYPES);

describe('plugin builtins emit only published union members', () => {
  registerBuiltinPlugins();

  for (const language of LANGUAGES) {
    it(`${language}: every builtin sink type is a known SinkType`, () => {
      const plugin = getLanguagePlugin(language);
      if (!plugin) return;
      const unknown = plugin
        .getBuiltinSinks()
        .map(s => s.type)
        .filter(t => !SINK_TYPE_SET.has(t));
      expect([...new Set(unknown)]).toEqual([]);
    });

    it(`${language}: every builtin source type is a known SourceType`, () => {
      const plugin = getLanguagePlugin(language);
      if (!plugin) return;
      const unknown = plugin
        .getBuiltinSources()
        .map(s => s.type)
        .filter(t => !SOURCE_TYPE_SET.has(t));
      expect([...new Set(unknown)]).toEqual([]);
    });
  }
});

describe('every emitted sink type has rule metadata', () => {
  it('no sink type reaches a consumer without a name and remediation', () => {
    registerBuiltinPlugins();

    const emitted = new Set<string>(DEFAULT_SINKS.map(s => s.type));
    for (const language of LANGUAGES) {
      getLanguagePlugin(language)?.getBuiltinSinks().forEach(s => emitted.add(s.type));
    }

    // `insecure_storage`, `prototype_pollution`, `regex_dos` and
    // `unsafe_memory` were emitted for a long time with no entry here, so
    // consumers rendering those findings had nothing to display. The cast is
    // what let that pass unnoticed.
    const missing = [...emitted].filter(t => !(t in RULE_DEFINITIONS)).sort();
    expect(missing).toEqual([]);
  });
});
