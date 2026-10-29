/**
 * Stable code ids (`ids@0.1`) — experimental, opt-in.
 *
 * Nothing in `analyze()` calls this module; a consumer that wants ids calls
 * `deriveStableIds` (or `deriveTypeScriptIds` on a tree it already holds) and
 * `assignNodeIds` on the IR it already has. TypeScript and JavaScript only in
 * this version.
 */

import { disposeTree, parse, type SupportedLanguage } from '../core/parser.js';
import { deriveTypeScriptIds } from './typescript.js';
import type { StableIdFile, StableIdOptions } from './types.js';

export { STABLE_ID_SCHEME } from './types.js';
export type {
  StableIdScheme,
  StableDecl,
  StableDeclKind,
  StableIdFlag,
  StableIdFile,
  StableIdOptions,
  StableNodeIds,
} from './types.js';
export { deriveTypeScriptIds, moduleNameFor } from './typescript.js';
export { assignNodeIds, type NodeIdSource } from './nodes.js';
export { diffStableIds, type StableIdDiff } from './diff.js';
export { blake3, base32, digest128 } from './hash.js';

/** True when `ids@0.1` covers the language. */
export function stableIdsSupport(language: SupportedLanguage): boolean {
  return language === 'typescript' || language === 'javascript' || language === 'tsx';
}

/**
 * Parse `code` and derive its `ids@0.1` declaration and body ids.
 * `.tsx`/`.jsx` files (or `language: 'tsx'`) parse with the JSX-aware
 * grammar; ids record the language as `typescript` or `javascript`.
 */
export async function deriveStableIds(
  code: string,
  filePath: string,
  language: SupportedLanguage,
  options: StableIdOptions = {},
): Promise<StableIdFile> {
  if (!stableIdsSupport(language)) {
    throw new Error(`stable-ids: ${language} is not covered by ids@0.1 (TypeScript/JavaScript only)`);
  }
  const lower = filePath.toLowerCase();
  const jsx = language === 'tsx' || lower.endsWith('.tsx') || lower.endsWith('.jsx');
  const idLanguage: 'javascript' | 'typescript' = language === 'javascript' ? 'javascript' : 'typescript';
  const tree = await parse(code, jsx ? 'tsx' : idLanguage);
  try {
    return deriveTypeScriptIds(tree, filePath, idLanguage, options);
  } finally {
    disposeTree(tree);
  }
}
