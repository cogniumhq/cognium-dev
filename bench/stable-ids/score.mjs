// Score a provider's ids against the sealed labels.
//
// A provider derives ids per file. For each labelled declaration of the
// earlier commit, the harness finds the provider's declaration for it (the
// join), looks for a declaration with the same `id` in the later commit, and
// predicts:
//   stable   — same id and same body_id;
//   body     — same id, different body_id;
//   identity — no declaration with that id in the later commit;
//   none     — the provider has no declaration for it at all.
// A `stable` prediction counts as correct only when the later declaration it
// found is the one the label pairs it with.

/**
 * The provider's declaration for a labelled one: a file's root module for the
 * file itself; otherwise the innermost declaration with the same name whose
 * line range holds the label's name line; failing that, the innermost one that
 * starts on the label's first line or name line.
 */
export function joinDecl(engineDecls, at) {
  if (!engineDecls || engineDecls.length === 0) return null;
  if (at.isFile) return engineDecls.find(d => d.parent === null || d.parent === undefined) ?? null;
  const span = d => d.end_line - d.start_line;
  const pick = list => {
    if (list.length === 0) return null;
    const sorted = [...list].sort((a, b) => span(a) - span(b) || (a.kind === at.kind ? 0 : 1) - (b.kind === at.kind ? 0 : 1) || a.start_line - b.start_line);
    return sorted[0];
  };
  const inner = engineDecls.filter(d => d.parent !== null && d.parent !== undefined);
  const byName = inner.filter(d => d.name === at.name && d.start_line <= at.line && at.line <= d.end_line);
  if (byName.length > 0) return pick(byName);
  return pick(inner.filter(d => d.start_line === at.start || d.start_line === at.line));
}

function isFileRecord(r) {
  return r.kind === 'module' && r.chain === '' && r.name === '';
}

const PRED = ['stable', 'body', 'identity', 'none'];
const LABELS = ['stable', 'body', 'identity'];

function emptyCounts() {
  const confusion = {};
  for (const l of LABELS) confusion[l] = Object.fromEntries(PRED.map(p => [p, 0]));
  return { scored: 0, tp: 0, fp: 0, fn: 0, wrong_partner: 0, judgement: {}, unjoined: 0, confusion, nodes: { checked: 0, kept: 0 } };
}

function labelClass(r) {
  return r.label === 'stable' ? 'stable' : r.change;
}

/**
 * Score one pair. `engine.before` / `engine.after` map a file path to the
 * provider's declarations for it; `engine.nodes`, when present, maps
 * `before|after` → file → body_id → node ids.
 */
export function scorePair(records, engine) {
  const counts = emptyCounts();
  const misses = [];
  const afterById = new Map();
  for (const decls of engine.after.values()) {
    for (const d of decls) if (!afterById.has(d.id)) afterById.set(d.id, d);
  }
  for (const r of records) {
    if (r.judgement) {
      counts.judgement[r.judgement] = (counts.judgement[r.judgement] ?? 0) + 1;
      continue;
    }
    const isFile = isFileRecord(r);
    const eb = joinDecl(engine.before.get(r.file), { isFile, name: r.name, kind: r.kind, line: r.line, start: r.start });
    let pred;
    let partnerOk = true;
    let ea = null;
    if (!eb) {
      pred = 'none';
      counts.unjoined++;
    } else {
      ea = afterById.get(eb.id) ?? null;
      if (!ea) pred = 'identity';
      else pred = ea.body_id === eb.body_id ? 'stable' : 'body';
      if (pred === 'stable' && r.after) {
        const want = joinDecl(engine.after.get(r.after.file), { isFile, name: r.name, kind: r.kind, line: r.after.line, start: r.after.start });
        partnerOk = want === ea;
      }
    }
    const label = labelClass(r);
    counts.scored++;
    counts.confusion[label][pred]++;
    const engineStable = pred === 'stable';
    if (engineStable && r.after && !partnerOk) counts.wrong_partner++;
    if (label === 'stable') {
      if (engineStable && partnerOk) {
        counts.tp++;
        if (engine.nodes) {
          const nb = [...(engine.nodes.before.get(r.file)?.get(eb.body_id) ?? [])].sort();
          const na = [...(engine.nodes.after.get(r.after.file)?.get(ea.body_id) ?? [])].sort();
          counts.nodes.checked++;
          if (nb.length === na.length && nb.every((x, i) => x === na[i])) counts.nodes.kept++;
          else misses.push({ ...where(r), label, pred, note: 'node ids changed' });
        }
      } else {
        // A stable claim matched to the wrong declaration is wrong twice: a miss and a false stable.
        counts.fn++;
        if (engineStable) counts.fp++;
        misses.push({ ...where(r), label, pred: engineStable ? 'stable (wrong partner)' : pred });
      }
    } else if (engineStable) {
      counts.fp++;
      misses.push({ ...where(r), label, pred });
    } else if (label !== pred) {
      misses.push({ ...where(r), label, pred });
    }
  }
  return { counts, misses };
}

function where(r) {
  return { file: r.file, line: r.line, kind: r.kind, name: (r.chain ? r.chain + '.' : '') + r.name };
}

/** Add `b`'s counts into `a`. */
export function addCounts(a, b) {
  for (const k of ['scored', 'tp', 'fp', 'fn', 'wrong_partner', 'unjoined']) a[k] += b[k];
  for (const [k, v] of Object.entries(b.judgement)) a.judgement[k] = (a.judgement[k] ?? 0) + v;
  for (const l of LABELS) for (const p of PRED) a.confusion[l][p] += b.confusion[l][p];
  a.nodes.checked += b.nodes.checked;
  a.nodes.kept += b.nodes.kept;
  return a;
}

export function totals() {
  return emptyCounts();
}

/** `{ value, num, den }`; value is null when the denominator is zero. */
export function ratio(num, den) {
  return { value: den === 0 ? null : num / den, num, den };
}

/** Precision and recall of `stable`, and the two clauses of the acceptance line, from counts. */
export function metrics(c) {
  const bodyRow = c.confusion.body;
  const idRow = c.confusion.identity;
  return {
    precision: ratio(c.tp, c.tp + c.fp),
    recall: ratio(c.tp, c.tp + c.fn),
    // A changed body gets a new body id and keeps its declaration id.
    body_keeps_decl: ratio(bodyRow.body, PRED.reduce((s, p) => s + bodyRow[p], 0)),
    // A changed identity (signature, name, enclosing type, file) gets a new declaration id.
    identity_new_decl: ratio(idRow.identity + idRow.none, PRED.reduce((s, p) => s + idRow[p], 0)),
  };
}

export function formatRatio(r) {
  return r.value === null ? `n/a (0/0)` : `${(r.value * 100).toFixed(1)}% (${r.num}/${r.den})`;
}
