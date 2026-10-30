/**
 * Stable code ids (scheme `ids@0.1`).
 *
 * A declaration's id is derived from what names it — language, kind,
 * qualified name and signature — never from its position in a file, so an
 * edit elsewhere in the file (or a move of the whole declaration inside the
 * file) leaves it unchanged. A body id adds a hash of the normalized body, so
 * it changes when, and only when, the body changes. Node ids (CFG blocks, DFG
 * defs and uses, call sites) are local indexes inside one body version.
 *
 * The scheme is versioned: every id-bearing record carries `scheme`, and the
 * scheme string is part of every hash, so ids of two scheme versions can never
 * collide or be mixed silently.
 */

export const STABLE_ID_SCHEME = 'ids@0.1' as const;
export type StableIdScheme = typeof STABLE_ID_SCHEME;

export type StableDeclKind = 'function' | 'method' | 'type' | 'field' | 'module';

/**
 * - `unstable:duplicate` — another declaration in the same scope has the same
 *   kind, qualified name and signature; the second and later ones carry a
 *   `#n` suffix in source order, so inserting one before another re-keys it.
 * - `unstable:anonymous` — an anonymous or nested function, keyed by its
 *   enclosing declaration plus its structural position there; an edit to the
 *   enclosing body may re-key it.
 */
export type StableIdFlag = 'unstable:duplicate' | 'unstable:anonymous';

export interface StableDecl {
  /** 128-bit declaration id, 26 lowercase base32 characters. */
  id: string;
  /** `<id>.<body_hash>` — changes when and only when the body changes. */
  body_id: string;
  /** 128-bit hash of the normalized body (whitespace, comments and formatting removed). */
  body_hash: string;
  kind: StableDeclKind;
  /** The declaration's own name (`default` for an anonymous default export). */
  name: string;
  /**
   * `<module>:<Outer>.<member>` for declarations; nested and anonymous
   * functions append `/<name>@<path>` to their enclosing declaration's name.
   */
  qualified_name: string;
  /** Canonical signature; parameter names never take part. */
  signature: string;
  /** The enclosing declaration's id (`null` only for the module itself). */
  parent: string | null;
  /** 1-based, inclusive. */
  start_line: number;
  end_line: number;
  /** 0-based. */
  start_column: number;
  end_column: number;
  flags: StableIdFlag[];
  /** Number of normalized body tokens. Small bodies are weak evidence of a move. */
  token_count: number;
  /** The normalized body tokens; present only under `keepBodyTokens`. */
  body_tokens?: string[];
}

export interface StableIdFile {
  scheme: StableIdScheme;
  file: string;
  /** `typescript` for `.ts`/`.tsx`, `javascript` for `.js`/`.jsx`, `java` for `.java`, `python` for `.py`. */
  language: 'javascript' | 'typescript' | 'java' | 'python';
  /** The module path every qualified name in this file starts with. */
  module: string;
  /** Source order, a parent before its members. The first entry is the module. */
  decls: StableDecl[];
  /** `true` when the parse had errors; ids under an error region may be missing. */
  partial: boolean;
}

export interface StableIdOptions {
  /**
   * The module path to use as-is. Otherwise it is derived by
   * `moduleNameFor(filePath, options)`.
   */
  module?: string;
  /** The package name (from the nearest `package.json`). */
  packageName?: string;
  /**
   * The package's directory, relative to the repository root (`''` or absent
   * for the root). `filePath` is expected repository-relative.
   */
  packageRoot?: string;
  /** Keep `body_tokens` on each declaration (needed for similarity candidates). */
  keepBodyTokens?: boolean;
}

/** Stable node ids parallel to the IR arrays they key; `null` where no body encloses the node. */
export interface StableNodeIds {
  cfg_blocks: (string | null)[];
  dfg_defs: (string | null)[];
  dfg_uses: (string | null)[];
  calls: (string | null)[];
}
