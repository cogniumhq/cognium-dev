/**
 * Body normalization for `ids@0.1`: the leaf tokens of a syntax subtree with
 * whitespace, comments and formatting removed, identifiers and literals kept.
 *
 * Formatting a formatter may change and that cannot change meaning is
 * dropped: statement-terminating `;`, a trailing `,` before a closing bracket,
 * the quote style of a plain string, the parentheses around a lone untyped
 * arrow-function parameter, and whitespace inside JSX text.
 */

import type { Node } from '../core/parser.js';

export interface EmitOptions {
  /** Subtrees left out entirely (by `node.id`). */
  skip?: ReadonlySet<number>;
  /** Subtrees replaced by one placeholder token (`''` drops the subtree). */
  replace?: ReadonlyMap<number, string>;
}

const CLOSERS = new Set([')', ']', '}', '>']);

/** True for a parenthesised parameter list that holds one bare, untyped identifier. */
function isLoneArrowParam(node: Node): Node | null {
  if (node.type !== 'formal_parameters' || node.parent?.type !== 'arrow_function') return null;
  const params = namedChildren(node);
  if (params.length !== 1) return null;
  const p = params[0];
  if (p.type === 'identifier') return p;
  if (p.type === 'required_parameter' && p.namedChildCount === 1) {
    const pattern = p.childForFieldName('pattern');
    if (pattern?.type === 'identifier') return pattern;
  }
  return null;
}

/** Named children, comments excluded. */
export function namedChildren(node: Node): Node[] {
  const out: Node[] = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c && c.type !== 'comment') out.push(c);
  }
  return out;
}

function emit(node: Node, opts: EmitOptions, out: string[]): void {
  const replaced = opts.replace?.get(node.id);
  if (replaced !== undefined) {
    if (replaced !== '') out.push(replaced);
    return;
  }
  if (opts.skip?.has(node.id)) return;
  const type = node.type;
  if (type === 'comment' || type === 'hash_bang_line') return;

  const lone = isLoneArrowParam(node);
  if (lone) {
    emit(lone, opts, out);
    return;
  }

  if (node.childCount === 0) {
    let text = node.text;
    if (type === 'jsx_text') text = text.replace(/\s+/g, ' ').trim();
    if (text === '') return;
    if ((text === "'" || text === '"') && node.parent?.type === 'string') text = '"';
    out.push(text);
    return;
  }
  for (let i = 0; i < node.childCount; i++) {
    const c = node.child(i);
    if (c) emit(c, opts, out);
  }
}

/** The normalized token stream of `nodes`, in order. */
export function bodyTokens(nodes: readonly Node[], opts: EmitOptions = {}): string[] {
  const raw: string[] = [];
  for (const n of nodes) emit(n, opts, raw);
  const out: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    const t = raw[i];
    if (t === ';') continue;
    if (t === ',') {
      let j = i + 1;
      while (j < raw.length && raw[j] === ';') j++;
      if (j < raw.length && CLOSERS.has(raw[j])) continue;
    }
    out.push(t);
  }
  return out;
}

const WORD_END = /[\w$#]$/;
const WORD_START = /^[\w$#]/;

/** Concatenate tokens, keeping a space only where two words would fuse. */
export function joinTokens(parts: readonly string[]): string {
  let s = '';
  for (const p of parts) {
    if (p === '') continue;
    if (s !== '' && WORD_END.test(s) && WORD_START.test(p)) s += ' ';
    s += p;
  }
  return s;
}

function flatten(node: Node, type: string, acc: Node[]): void {
  for (const c of namedChildren(node)) {
    if (c.type === type) flatten(c, type, acc);
    else acc.push(c);
  }
}

/**
 * A type annotation serialized canonically: object-type members and the arms
 * of a union or intersection are sorted, so `{b: string; a: number}` and
 * `{a: number, b: string}` — or `A | B` and `B | A` — serialize the same.
 */
export function canonicalType(node: Node): string {
  switch (node.type) {
    case 'type_annotation':
    case 'opting_type_annotation':
    case 'omitting_type_annotation': {
      const inner = namedChildren(node);
      return inner.length === 1 ? canonicalType(inner[0]) : joinTokens(bodyTokens([node]));
    }
    case 'formal_parameters': {
      // Parameters of a function or constructor type: types only, never names.
      const params = namedChildren(node).map(p => {
        const type = p.childForFieldName('type');
        const pattern = p.childForFieldName('pattern');
        const rest = pattern?.type === 'rest_pattern' || p.type === 'rest_pattern' ? '...' : '';
        const optional = p.type === 'optional_parameter' ? '?' : '';
        return rest + (type ? canonicalType(type) : '_') + optional;
      });
      return '(' + params.join(',') + ')';
    }
    case 'object_type': {
      const members = namedChildren(node).map(canonicalType);
      members.sort();
      return '{' + members.join(';') + '}';
    }
    case 'union_type':
    case 'intersection_type': {
      const arms: Node[] = [];
      flatten(node, node.type, arms);
      const parts = arms.map(canonicalType).sort();
      return parts.join(node.type === 'union_type' ? '|' : '&');
    }
    default: {
      if (node.childCount === 0) return node.text;
      const parts: string[] = [];
      for (let i = 0; i < node.childCount; i++) {
        const c = node.child(i);
        if (!c || c.type === 'comment') continue;
        parts.push(c.isNamed ? canonicalType(c) : c.text);
      }
      // A trailing comma before a closer is formatting.
      const kept = parts.filter((p, i) => !(p === ',' && CLOSERS.has(parts[i + 1] ?? '')));
      return joinTokens(kept);
    }
  }
}
