/**
 * File collection + language detection utilities.
 *
 * A small standalone reimplementation so the MCP server does not depend on
 * the CLI package. Mirrors the extension → language mapping from
 * `packages/cli/src/cli.ts`.
 */

import { statSync, readdirSync, readFileSync } from 'fs';
import { extname, join, resolve } from 'path';
import type { SupportedLanguage } from 'circle-ir';

const LANG_MAP: Record<string, SupportedLanguage> = {
  '.java': 'java',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.go': 'go',
  '.rs': 'rust',
  '.sh': 'bash',
  '.bash': 'bash',
  '.html': 'html',
  '.htm': 'html',
};

/** Directories skipped during recursive collection. */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  'target',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  '.pytest_cache',
]);

export function detectLanguage(filePath: string): SupportedLanguage | null {
  const ext = extname(filePath).toLowerCase();
  return LANG_MAP[ext] ?? null;
}

export interface CollectedFile {
  filePath: string;
  language: SupportedLanguage;
  code: string;
  mtimeMs: number;
}

export interface CollectOptions {
  /** Restrict to a single language, e.g. 'java'. */
  language?: SupportedLanguage;
  /** Absolute max number of files to collect (safety cap). */
  maxFiles?: number;
}

/**
 * Recursively collect source files under `root`. Skips hidden dirs,
 * `node_modules`, build outputs, and language-mismatched files.
 */
export function collectFiles(root: string, opts: CollectOptions = {}): CollectedFile[] {
  const absRoot = resolve(root);
  const out: CollectedFile[] = [];
  const maxFiles = opts.maxFiles ?? 10_000;

  const st = statSync(absRoot);
  if (st.isFile()) {
    const lang = detectLanguage(absRoot);
    if (lang && (!opts.language || lang === opts.language)) {
      out.push({
        filePath: absRoot,
        language: lang,
        code: readFileSync(absRoot, 'utf8'),
        mtimeMs: st.mtimeMs,
      });
    }
    return out;
  }

  const stack: string[] = [absRoot];
  while (stack.length > 0 && out.length < maxFiles) {
    const dir = stack.pop()!;
    let entries: import('fs').Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      const p = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(p);
      } else if (entry.isFile()) {
        const lang = detectLanguage(p);
        if (!lang) continue;
        if (opts.language && lang !== opts.language) continue;
        let stf: import('fs').Stats;
        try {
          stf = statSync(p);
        } catch {
          continue;
        }
        try {
          out.push({
            filePath: p,
            language: lang,
            code: readFileSync(p, 'utf8'),
            mtimeMs: stf.mtimeMs,
          });
        } catch {
          // unreadable — skip
        }
        if (out.length >= maxFiles) break;
      }
    }
  }
  return out;
}

/**
 * Cheap mtime index used for cache invalidation. Same walking logic as
 * `collectFiles` but skips reading file contents.
 */
export function indexMtimes(root: string, opts: CollectOptions = {}): Map<string, number> {
  const absRoot = resolve(root);
  const out = new Map<string, number>();
  const maxFiles = opts.maxFiles ?? 10_000;

  let st: import('fs').Stats;
  try {
    st = statSync(absRoot);
  } catch {
    return out;
  }

  if (st.isFile()) {
    if (detectLanguage(absRoot)) out.set(absRoot, st.mtimeMs);
    return out;
  }

  const stack: string[] = [absRoot];
  while (stack.length > 0 && out.size < maxFiles) {
    const dir = stack.pop()!;
    let entries: import('fs').Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      const p = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(p);
      } else if (entry.isFile()) {
        const lang = detectLanguage(p);
        if (!lang) continue;
        if (opts.language && lang !== opts.language) continue;
        try {
          out.set(p, statSync(p).mtimeMs);
        } catch {
          // ignore
        }
        if (out.size >= maxFiles) break;
      }
    }
  }
  return out;
}

export function mtimesEqual(a: Map<string, number>, b: Map<string, number>): boolean {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) {
    if (b.get(k) !== v) return false;
  }
  return true;
}
