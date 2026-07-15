/**
 * `scan` tool — run circle-ir on a file or directory.
 *
 * The workhorse tool. Every other tool that needs analysis data pulls
 * from the same `ProjectCache`, so calling `scan` first is the fastest
 * path for a session (subsequent tool calls are cache hits).
 */

import { z } from 'zod';
import type {
  SastFinding, TaintPath, SupportedLanguage, SinkType,
} from 'circle-ir';
import { RULE_DEFINITIONS } from 'circle-ir';

/**
 * Local shape for a per-file taint flow, mirroring circle-ir's internal
 * `TaintFlowInfo` (not exported from the public entry point).
 */
interface TaintFlowInfo {
  source_line: number;
  sink_line: number;
  source_type: string;
  sink_type: string;
  confidence: number;
  sanitized: boolean;
  tags?: string[];
}
import { resolve } from 'path';
import { existsSync, statSync } from 'fs';
import type { ToolContext, ToolResult } from './types.js';
import { textResult, errorResult } from './types.js';
import {
  truncateArray, truncateString, MAX_FINDINGS, MAX_TAINT_PATHS, MAX_STRING_LEN,
} from '../util/serialize.js';

export const scanInputShape = {
  path: z.string().describe('Absolute path to a file or directory to scan.'),
  language: z.enum(['java', 'javascript', 'typescript', 'python', 'go', 'rust', 'bash', 'html'])
    .optional()
    .describe('Restrict analysis to a single language.'),
  severity: z.array(z.enum(['critical', 'high', 'medium', 'low']))
    .optional()
    .describe('Filter findings to these severity levels.'),
  categories: z.array(z.enum(['security', 'reliability', 'performance', 'maintainability', 'architecture']))
    .optional()
    .describe('Filter findings to these ISO-25010 categories.'),
  disabledPasses: z.array(z.string())
    .optional()
    .describe('circle-ir rule_ids to disable, e.g. ["naming-convention", "todo-in-prod"].'),
  forceRefresh: z.boolean()
    .optional()
    .describe('Skip the cache and re-analyze from disk.'),
  crossFileBudgetMs: z.number().int().min(0)
    .optional()
    .describe('Wall-time cap for the cross-file phase in ms. 0 = unlimited.'),
} as const;

export const scanConfig = {
  title: 'Scan project',
  description:
    'Run circle-ir static analysis (polyglot SAST pipeline) on a file or directory. ' +
    'Returns SastFindings covering security, reliability, performance, maintainability, and architecture, ' +
    'plus per-file taint flows and (for directory scans) cross-file taint paths. Results are cached per ' +
    'project + option-set and invalidated by file mtime, so subsequent tool calls are effectively free.',
  inputSchema: scanInputShape,
} as const;

function compactFinding(f: SastFinding): Record<string, unknown> {
  return {
    id: f.id,
    rule_id: f.rule_id,
    category: f.category,
    severity: f.severity,
    level: f.level,
    cwe: f.cwe,
    message: truncateString(f.message),
    file: f.file,
    line: f.line,
    end_line: f.end_line,
    column: f.column,
    snippet: truncateString(f.snippet),
    fix: truncateString(f.fix),
    confidence: f.confidence,
  };
}

function compactFlow(file: string, flow: TaintFlowInfo): Record<string, unknown> {
  const rule = RULE_DEFINITIONS[flow.sink_type as SinkType];
  return {
    file,
    source_type: flow.source_type,
    source_line: flow.source_line,
    sink_type: flow.sink_type,
    sink_line: flow.sink_line,
    cwe: rule?.cwe,
    severity: rule?.severityLevel ?? 'high',
    confidence: flow.confidence,
    sanitized: flow.sanitized,
    tags: flow.tags,
  };
}

function compactTaintPath(p: TaintPath): Record<string, unknown> {
  return {
    id: p.id,
    source: {
      file: p.source.file,
      line: p.source.line,
      type: p.source.type,
      code: truncateString(p.source.code, 512),
    },
    sink: {
      file: p.sink.file,
      line: p.sink.line,
      type: p.sink.type,
      cwe: p.sink.cwe,
      code: truncateString(p.sink.code, 512),
    },
    hops: p.hops.map(h => ({
      file: h.file,
      line: h.line,
      variable: h.variable,
      code: truncateString(h.code, 256),
    })),
    sanitizers_in_path: p.sanitizers_in_path,
    confidence: p.confidence,
  };
}

export function makeScanHandler(ctx: ToolContext) {
  return async (args: {
    path: string;
    language?: SupportedLanguage;
    severity?: Array<'critical' | 'high' | 'medium' | 'low'>;
    categories?: Array<'security' | 'reliability' | 'performance' | 'maintainability' | 'architecture'>;
    disabledPasses?: string[];
    forceRefresh?: boolean;
    crossFileBudgetMs?: number;
  }): Promise<ToolResult> => {
    const absPath = resolve(args.path);
    if (!existsSync(absPath)) {
      return errorResult(`Path not found: ${absPath}`);
    }
    const isDir = statSync(absPath).isDirectory();
    const projectRoot = isDir ? absPath : resolve(absPath, '..');

    if (args.forceRefresh) {
      ctx.cache.invalidate(projectRoot);
    }

    const scanOpts = {
      ...(args.language ? { language: args.language } : {}),
      ...(args.disabledPasses ? { disabledPasses: args.disabledPasses } : {}),
      ...(args.crossFileBudgetMs !== undefined ? { crossFileBudgetMs: args.crossFileBudgetMs } : {}),
    };

    const { analysis, cacheHit, analysisMs, fileCount } = await ctx.cache.getOrCompute(projectRoot, scanOpts);

    const findings: SastFinding[] = [];
    const flows: Array<{ file: string; flow: TaintFlowInfo }> = [];
    for (const fa of analysis.files) {
      if (!isDir && fa.file !== absPath) continue;
      for (const f of fa.analysis.findings ?? []) findings.push(f);
      for (const fl of fa.analysis.taint.flows ?? []) flows.push({ file: fa.file, flow: fl });
    }

    // Filter findings.
    let filteredFindings = findings;
    if (args.severity && args.severity.length > 0) {
      const set = new Set(args.severity);
      filteredFindings = filteredFindings.filter(f => set.has(f.severity as never));
    }
    if (args.categories && args.categories.length > 0) {
      const set = new Set(args.categories);
      filteredFindings = filteredFindings.filter(f => set.has(f.category as never));
    }
    // Filter flows: flows are always 'security'; drop if categories filter excludes 'security'.
    let filteredFlows = flows;
    if (args.categories && !args.categories.includes('security')) {
      filteredFlows = [];
    }
    if (args.severity && args.severity.length > 0) {
      const set = new Set(args.severity);
      filteredFlows = filteredFlows.filter(({ flow }) => {
        const sev = RULE_DEFINITIONS[flow.sink_type as SinkType]?.severityLevel ?? 'high';
        return set.has(sev);
      });
    }

    const taintPaths = isDir ? analysis.taint_paths : [];

    const { items: findingsSlice, truncated: fTrunc, totalCount: fTotal } =
      truncateArray(filteredFindings.map(compactFinding), MAX_FINDINGS);
    const { items: flowsSlice, truncated: flTrunc, totalCount: flTotal } =
      truncateArray(filteredFlows.map(({ file, flow }) => compactFlow(file, flow)), MAX_FINDINGS);
    const { items: pathsSlice, truncated: pTrunc, totalCount: pTotal } =
      truncateArray(taintPaths.map(compactTaintPath), MAX_TAINT_PATHS);

    const summary = {
      totalFindings: fTotal,
      totalTaintFlows: flTotal,
      totalCrossFileTaintPaths: pTotal,
      byCategory: countBy(filteredFindings, f => f.category),
      bySeverity: countBy(filteredFindings, f => f.severity),
      byRuleId: topN(countBy(filteredFindings, f => f.rule_id), 10),
      byTaintSinkType: countBy(filteredFlows.map(x => x.flow), f => f.sink_type),
    };

    return textResult({
      projectRoot,
      scannedPath: absPath,
      fileCount,
      cacheHit,
      analysisMs,
      crossFileBudgetExceeded: analysis.cross_file_budget_exceeded === true,
      summary,
      findings: findingsSlice,
      findingsTruncated: fTrunc,
      taintFlows: flowsSlice,
      taintFlowsTruncated: flTrunc,
      crossFileTaintPaths: pathsSlice,
      crossFileTaintPathsTruncated: pTrunc,
      note: (fTrunc || flTrunc || pTrunc)
        ? `Response truncated (${MAX_FINDINGS} findings / ${MAX_FINDINGS} flows / ${MAX_TAINT_PATHS} paths max). Narrow via 'severity' / 'categories' or query 'find_similar' / 'list_reachable_sinks'.`
        : undefined,
      _limits: { maxStringLen: MAX_STRING_LEN, maxFindings: MAX_FINDINGS, maxTaintPaths: MAX_TAINT_PATHS },
    });
  };
}

function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const i of items) {
    const k = key(i);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function topN(map: Record<string, number>, n: number): Record<string, number> {
  const entries = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, n);
  return Object.fromEntries(entries);
}
