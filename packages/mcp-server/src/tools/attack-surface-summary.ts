/**
 * `attack_surface_summary` tool — high-level roll-up of a project's
 * attack surface: entry points × sinks × cross-file taint paths, grouped
 * by language / framework / vulnerability category.
 *
 * Designed as the first tool an LLM calls when a user asks
 * "give me a security posture summary of this codebase".
 */

import { z } from 'zod';
import { resolve } from 'path';
import { RULE_DEFINITIONS, type SinkType } from 'circle-ir';
import type { ToolContext, ToolResult } from './types.js';
import { textResult } from './types.js';

export const attackSurfaceSummaryInputShape = {
  project_root: z.string().describe('Absolute path to the project root.'),
} as const;

export const attackSurfaceSummaryConfig = {
  title: 'Attack surface summary',
  description:
    'Compute a security-posture roll-up for a previously-scanned project: total entry points by framework, ' +
    'total sinks by category, cross-file taint-path totals per sink type, and the top 10 files by finding ' +
    'count. Use as the entry-level tool for "what does this codebase look like from a security angle?"',
  inputSchema: attackSurfaceSummaryInputShape,
} as const;

export function makeAttackSurfaceSummaryHandler(ctx: ToolContext) {
  return async (args: { project_root: string }): Promise<ToolResult> => {
    const root = resolve(args.project_root);
    const { analysis, cacheHit } = await ctx.cache.getOrCompute(root, {});

    const entryPointsByFramework: Record<string, number> = {};
    const entryPointsByLanguage: Record<string, number> = {};
    const entryPointsByKind: Record<string, number> = {};
    const sinksByType: Record<string, number> = {};
    const sinksByLanguage: Record<string, number> = {};
    const findingsBySeverity: Record<string, number> = {};
    const findingsByCategory: Record<string, number> = {};
    const findingsByRule: Record<string, number> = {};
    const findingsPerFile: Record<string, number> = {};

    let totalEntryPoints = 0;
    let totalSinks = 0;
    let totalSources = 0;
    let totalFindings = 0;

    for (const fa of analysis.files) {
      const lang = fa.analysis.meta.language;
      for (const reg of fa.analysis.runtime_registrations ?? []) {
        totalEntryPoints++;
        const fw = reg.framework ?? 'unknown';
        entryPointsByFramework[fw] = (entryPointsByFramework[fw] ?? 0) + 1;
        entryPointsByLanguage[lang] = (entryPointsByLanguage[lang] ?? 0) + 1;
        entryPointsByKind[reg.kind] = (entryPointsByKind[reg.kind] ?? 0) + 1;
      }
      for (const s of fa.analysis.taint?.sinks ?? []) {
        totalSinks++;
        sinksByType[s.type] = (sinksByType[s.type] ?? 0) + 1;
        sinksByLanguage[lang] = (sinksByLanguage[lang] ?? 0) + 1;
      }
      totalSources += fa.analysis.taint?.sources?.length ?? 0;
      for (const f of fa.analysis.findings ?? []) {
        totalFindings++;
        findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] ?? 0) + 1;
        findingsByCategory[f.category] = (findingsByCategory[f.category] ?? 0) + 1;
        findingsByRule[f.rule_id] = (findingsByRule[f.rule_id] ?? 0) + 1;
        findingsPerFile[fa.file] = (findingsPerFile[fa.file] ?? 0) + 1;
      }
    }

    const crossFilePathsBySinkType: Record<string, number> = {};
    for (const p of analysis.taint_paths) {
      const t = p.sink.type ?? 'unknown';
      crossFilePathsBySinkType[t] = (crossFilePathsBySinkType[t] ?? 0) + 1;
    }

    const topFiles = Object.entries(findingsPerFile)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([file, count]) => ({ file, findings: count }));

    const criticalCategories = Object.entries(sinksByType)
      .map(([type, count]) => ({
        type,
        count,
        cwe: (RULE_DEFINITIONS as Record<string, { cwe?: string; severityLevel?: string } | undefined>)[type]?.cwe,
        severity: (RULE_DEFINITIONS as Record<string, { cwe?: string; severityLevel?: string } | undefined>)[type as SinkType]?.severityLevel,
      }))
      .sort((a, b) => b.count - a.count);

    return textResult({
      projectRoot: root,
      cacheHit,
      totals: {
        files: analysis.files.length,
        entryPoints: totalEntryPoints,
        sources: totalSources,
        sinks: totalSinks,
        findings: totalFindings,
        crossFileTaintPaths: analysis.taint_paths.length,
      },
      entryPoints: {
        byFramework: entryPointsByFramework,
        byLanguage: entryPointsByLanguage,
        byKind: entryPointsByKind,
      },
      sinks: {
        byLanguage: sinksByLanguage,
        byCategory: criticalCategories,
      },
      findings: {
        bySeverity: findingsBySeverity,
        byCategory: findingsByCategory,
        topRules: Object.entries(findingsByRule)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([rule_id, count]) => ({ rule_id, count })),
      },
      crossFileTaintPaths: {
        bySinkType: crossFilePathsBySinkType,
        budgetExceeded: analysis.cross_file_budget_exceeded === true,
      },
      topFiles,
    });
  };
}
