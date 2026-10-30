/**
 * Shared id construction for every language's `ids@0.1` extractor: the
 * declaration id from (scheme, language, kind, qualified name, signature),
 * the `#n` suffix and `unstable:duplicate` flag for same-key duplicates, and
 * the body hash.
 */

import type { Node } from '../core/parser.js';
import { digest128 } from './hash.js';
import { STABLE_ID_SCHEME, type StableDecl, type StableDeclKind, type StableIdFlag } from './types.js';

export function placeholder(kind: StableDeclKind, name: string, signature: string): string {
  return `⟦${kind} ${name} ${signature}⟧`;
}

export class Builder {
  readonly decls: StableDecl[] = [];
  private readonly first = new Map<string, StableDecl>();
  private readonly count = new Map<string, number>();

  constructor(
    private readonly language: string,
    private readonly keepTokens: boolean,
  ) {}

  add(
    kind: StableDeclKind,
    name: string,
    qualifiedName: string,
    signature: string,
    at: Node,
    parent: string | null,
    flags: StableIdFlag[] = [],
  ): StableDecl {
    const key = `${kind}\u0000${qualifiedName}\u0000${signature}`;
    const n = (this.count.get(key) ?? 0) + 1;
    this.count.set(key, n);
    let qname = qualifiedName;
    const ownFlags = [...flags];
    if (n > 1) {
      qname = `${qualifiedName}#${n}`;
      ownFlags.push('unstable:duplicate');
      const first = this.first.get(key);
      if (first && !first.flags.includes('unstable:duplicate')) first.flags.push('unstable:duplicate');
    }
    const id = digest128([STABLE_ID_SCHEME, this.language, kind, qname, signature]);
    const decl: StableDecl = {
      id,
      body_id: id,
      body_hash: '',
      kind,
      name,
      qualified_name: qname,
      signature,
      parent,
      start_line: at.startPosition.row + 1,
      end_line: at.endPosition.row + 1,
      start_column: at.startPosition.column,
      end_column: at.endPosition.column,
      flags: ownFlags,
      token_count: 0,
    };
    if (n === 1) this.first.set(key, decl);
    this.decls.push(decl);
    return decl;
  }

  setBody(decl: StableDecl, tokens: string[]): void {
    decl.body_hash = digest128([STABLE_ID_SCHEME, ...tokens]);
    decl.body_id = `${decl.id}.${decl.body_hash}`;
    decl.token_count = tokens.length;
    if (this.keepTokens) decl.body_tokens = tokens;
  }
}

