/**
 * Reading one version of a tree: the source files of a language under a root,
 * by repository-relative path, with their bytes' digest.
 */
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

export type CodeLanguage = 'java' | 'javascript' | 'typescript' | 'python';

/** File extensions read for each language. */
export const EXTENSIONS: Record<CodeLanguage, readonly string[]> = {
  java: ['.java'],
  javascript: ['.js', '.jsx', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx', '.mts', '.cts'],
  python: ['.py'],
};

/** Directories never read: tool and build output, dependencies, version control. */
export const DEFAULT_EXCLUDED_DIRS: readonly string[] = [
  '.git', 'node_modules', 'target', 'build', 'dist', 'out', '.gradle', '.idea', '__pycache__', '.venv', 'venv',
];

/** Server-side template files read beside a language's sources (Thymeleaf HTML, JSP). */
export const TEMPLATE_EXTENSIONS: Partial<Record<CodeLanguage, readonly string[]>> = {
  java: ['.html', '.htm', '.jsp', '.jspx', '.tag', '.tagx'],
};

export interface TreeFile {
  /** Repository-relative, `/`-separated. */
  path: string;
  code: string;
  /** `sha256:<hex>` of the file's bytes. */
  digest: string;
}

export const sha = (s: string | Buffer): string => `sha256:${createHash('sha256').update(s).digest('hex')}`;

/**
 * Every file of `language` under `root`, sorted by path. Symbolic links are not
 * followed (a link out of the tree would read files that are not the subject's).
 */
export function readTree(
  root: string,
  language: CodeLanguage,
  excludedDirs: readonly string[] = DEFAULT_EXCLUDED_DIRS,
  exts: readonly string[] = EXTENSIONS[language],
): TreeFile[] {
  const out: TreeFile[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      const st = lstatSync(full);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (!excludedDirs.includes(name)) walk(full);
        continue;
      }
      if (!st.isFile() || !exts.some(e => name.endsWith(e))) continue;
      // test sources are part of the tree: excluding them is the caller's choice
      const bytes = readFileSync(full);
      out.push({ path: relative(root, full).split(sep).join('/'), code: bytes.toString('utf8'), digest: sha(bytes) });
    }
  };
  walk(root);
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
