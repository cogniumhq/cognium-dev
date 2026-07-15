/**
 * Project-scoped analysis cache.
 *
 * A long-lived MCP process holds one `ProjectAnalysis` per active project
 * root. Invalidation is mtime-based: on each request we re-index file
 * mtimes and re-run `analyzeProject` only if any file changed. LRU
 * eviction keeps memory bounded when the LLM hops between projects.
 */

import { resolve } from 'path';
import { analyzeProject, type ProjectAnalysis } from 'circle-ir';
import { collectFiles, indexMtimes, mtimesEqual } from './util/files.js';
import { ensureAnalyzer } from './util/wasm.js';

/**
 * Per-project analysis options that participate in the cache key. Two
 * scans with different profiles / disabled passes must not share a cache
 * entry.
 */
export interface ProjectScanOptions {
  /** Force analysis of a single language. */
  language?: string;
  /** Circle-IR disabled passes (e.g. ['naming-convention']). */
  disabledPasses?: string[];
  /** Cross-file phase wall-time budget in ms. 0 = unlimited. */
  crossFileBudgetMs?: number;
}

interface CacheEntry {
  key: string;
  analysis: ProjectAnalysis;
  mtimes: Map<string, number>;
  computedAt: number;
  analysisMs: number;
}

function optionsKey(opts: ProjectScanOptions): string {
  const parts = [
    `lang=${opts.language ?? '*'}`,
    `disabled=${(opts.disabledPasses ?? []).slice().sort().join(',')}`,
    `budget=${opts.crossFileBudgetMs ?? 'default'}`,
  ];
  return parts.join('|');
}

export class ProjectCache {
  private entries = new Map<string, CacheEntry>();
  private readonly capacity: number;

  constructor(capacity = 3) {
    this.capacity = capacity;
  }

  private cacheKey(projectRoot: string, opts: ProjectScanOptions): string {
    return `${resolve(projectRoot)}::${optionsKey(opts)}`;
  }

  /**
   * Return a cached analysis if fresh, else run `analyzeProject`. The
   * boolean `cacheHit` in the return value lets tools surface cache
   * behaviour to callers.
   */
  async getOrCompute(
    projectRoot: string,
    opts: ProjectScanOptions,
  ): Promise<{ analysis: ProjectAnalysis; cacheHit: boolean; analysisMs: number; fileCount: number }> {
    await ensureAnalyzer();
    const absRoot = resolve(projectRoot);
    const key = this.cacheKey(absRoot, opts);
    const existing = this.entries.get(key);

    const langOpt = opts.language as ProjectScanOptions['language'];
    const currentMtimes = indexMtimes(absRoot, langOpt ? { language: langOpt as never } : {});

    if (existing && mtimesEqual(existing.mtimes, currentMtimes)) {
      // Touch for LRU: re-insert to move to the end of the Map's iteration order.
      this.entries.delete(key);
      this.entries.set(key, existing);
      return {
        analysis: existing.analysis,
        cacheHit: true,
        analysisMs: existing.analysisMs,
        fileCount: currentMtimes.size,
      };
    }

    const files = collectFiles(absRoot, langOpt ? { language: langOpt as never } : {});
    const t0 = Date.now();
    const analysis = await analyzeProject(
      files.map(f => ({ code: f.code, filePath: f.filePath, language: f.language })),
      {
        ...(opts.disabledPasses ? { disabledPasses: opts.disabledPasses } : {}),
        ...(opts.crossFileBudgetMs !== undefined ? { crossFileBudgetMs: opts.crossFileBudgetMs } : {}),
      },
    );
    const analysisMs = Date.now() - t0;

    const entry: CacheEntry = {
      key,
      analysis,
      mtimes: currentMtimes,
      computedAt: Date.now(),
      analysisMs,
    };
    this.entries.set(key, entry);
    this.evictLRU();

    return { analysis, cacheHit: false, analysisMs, fileCount: files.length };
  }

  /** Invalidate one specific project (all option-keys) or one specific key. */
  invalidate(projectRoot: string, opts?: ProjectScanOptions): number {
    const abs = resolve(projectRoot);
    let removed = 0;
    if (opts) {
      if (this.entries.delete(this.cacheKey(abs, opts))) removed++;
      return removed;
    }
    for (const key of [...this.entries.keys()]) {
      if (key.startsWith(abs + '::')) {
        this.entries.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /** Invalidate every cached project. */
  clear(): number {
    const n = this.entries.size;
    this.entries.clear();
    return n;
  }

  size(): number {
    return this.entries.size;
  }

  private evictLRU(): void {
    while (this.entries.size > this.capacity) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey === undefined) break;
      this.entries.delete(oldestKey);
    }
  }
}
