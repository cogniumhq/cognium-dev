/**
 * TaintMatcherPass
 *
 * First pass in the analysis pipeline. Merges language-plugin built-in
 * sources/sinks into the config, runs config-based taint matching, and
 * extracts @sanitizer-annotated method names from type declarations.
 */

import type { TaintSource, TaintSink, TaintSanitizer, SourceType, SinkType } from '../../types/index.js';
import type { TaintConfig } from '../../types/config.js';
import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import { analyzeTaint } from '../taint-matcher.js';
import { getLanguagePlugin } from '../../languages/index.js';
import { createWithJdkTypes } from '../../resolution/type-hierarchy.js';

export interface TaintMatcherResult {
  sources: TaintSource[];
  sinks: TaintSink[];
  sanitizers: TaintSanitizer[];
  /** Method names annotated with @sanitizer (for ConstantPropagationPass). */
  sanitizerMethods: string[];
  /** Final merged config (with plugin extensions applied). */
  config: TaintConfig;
}

export class TaintMatcherPass implements AnalysisPass<TaintMatcherResult> {
  readonly name = 'taint-matcher';
  readonly category = 'security' as const;

  run(ctx: PassContext): TaintMatcherResult {
    const { graph, language, config } = ctx;
    const { calls, types } = graph.ir;

    // Merge language-plugin built-in sources/sinks.
    // Plugins (e.g. Bash) define patterns directly on the plugin rather than
    // in YAML config files; splice them in here so they behave identically.
    let mergedConfig = config;
    const plugin = getLanguagePlugin(language as import('../../types/index.js').SupportedLanguage);
    if (plugin) {
      const pluginSources = plugin.getBuiltinSources();
      const pluginSinks = plugin.getBuiltinSinks();
      if (pluginSources.length > 0 || pluginSinks.length > 0) {
        mergedConfig = {
          ...config,
          sources: [
            ...config.sources,
            ...pluginSources.map(s => ({
              method: s.method,
              class: s.class,
              annotation: s.annotation,
              type: s.type as SourceType,
              severity: s.severity,
              return_tainted: s.returnTainted ?? false,
            })),
          ],
          sinks: [
            ...config.sinks,
            ...pluginSinks.map(s => ({
              method: s.method,
              class: s.class,
              type: s.type as SinkType,
              cwe: s.cwe,
              severity: s.severity,
              arg_positions: s.argPositions,
            })),
          ],
        };
      }
    }

    // Build a local TypeHierarchyResolver so that sink patterns match subtype
    // receivers (e.g. PreparedStatement.executeQuery() matches Statement sink).
    const hierarchy = createWithJdkTypes();
    hierarchy.addFromIR(graph.ir, graph.ir.meta.file);

    const taint = analyzeTaint(calls, types, mergedConfig, hierarchy);

    // Extract method names annotated with @sanitizer (Javadoc comments).
    const sanitizerMethods: string[] = [];
    for (const type of types) {
      for (const method of type.methods) {
        if (method.annotations.includes('sanitizer')) {
          sanitizerMethods.push(method.name);
        }
      }
    }

    return {
      sources: taint.sources,
      sinks: taint.sinks,
      sanitizers: taint.sanitizers ?? [],
      sanitizerMethods,
      config: mergedConfig,
    };
  }
}
