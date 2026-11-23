/**
 * Workarounds for tree-sitter-typescript 0.23.2 recoveries that hide
 * declarations when later exports appear in the same file (cognium-dev#1193).
 */
import type { Node, Tree } from './parser.js';
import { parse, disposeTree } from './parser.js';

/** Parenthesize unparenthesized conditional type defaults in type-parameter lists. */
export function stabilizeTypeScriptConditionalDefaults(code: string): string {
  return code.replace(
    /(=\s*)([A-Za-z_$][\w$.]*)\s+extends\s+((?:[^{}]|\{[^{}]*\})*)\?\s*([^:]+):\s*([^,>\n]+)/g,
    '$1($2 extends $3 ? $4 : $5)',
  );
}

/** Split a module into top-level `export …` statement sources (order preserved). */
export function splitTopLevelExportStatements(code: string): string[] {
  return code
    .split(/(?=^export )/m)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** True when the grammar grouped one or more trailing exports into a program-level ERROR. */
export function hasExportTailProgramError(root: Node): boolean {
  return root.type === 'program' && root.namedChildren.some((c) => c?.type === 'ERROR');
}

/**
 * Parse each top-level export in isolation. Used when a full-file parse leaves a
 * program-level ERROR so later declarations never appear in the combined tree.
 */
export async function parseTypeScriptExportChunkTrees(
  code: string,
  language: 'typescript' | 'javascript' = 'typescript',
): Promise<Tree[]> {
  const stabilized = stabilizeTypeScriptConditionalDefaults(code);
  const chunks = splitTopLevelExportStatements(stabilized);
  const trees: Tree[] = [];
  for (const chunk of chunks) {
    trees.push(await parse(chunk, language));
  }
  return trees;
}

export async function withTypeScriptExportChunkTrees<T>(
  code: string,
  language: 'typescript' | 'javascript',
  fn: (trees: Tree[]) => T,
): Promise<T> {
  const trees = await parseTypeScriptExportChunkTrees(code, language);
  try {
    return fn(trees);
  } finally {
    for (const t of trees) disposeTree(t);
  }
}
