// Provider: ids computed from the labeller's own view of a declaration
// (identity = file module, enclosing names, kind, name and signature; body =
// the declaration's tokens without whitespace and comments). It implements
// the labelling rule as ids, so on the sealed set it scores 100% precision and
// recall: a check of the harness and the labels, not of any engine.

import { createHash } from 'node:crypto';
import { declarationsOf } from '../label.mjs';

export const name = 'reference';

const h = s => createHash('sha256').update(s).digest('hex').slice(0, 26);

export async function describe() {
  return { provider: name, scheme: 'reference' };
}

export async function derive(code, file) {
  const r = declarationsOf(file, code);
  const decls = r.decls.map(d => ({
    id: h(d.key),
    body_id: h(d.key) + '.' + h(d.full.w.join('\u0001')),
    name: d.name,
    kind: d.kind,
    start_line: d.start,
    end_line: d.end,
    parent: d.parentKey === null ? null : h(d.parentKey),
  }));
  return { scheme: 'reference', file, decls, partial: r.partial };
}
