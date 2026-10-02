// nav.mjs — the navigation index over a real repository: per-tier counts for
// the bench targets, the unresolved reasons, and the build/query timings.
//
//   CIRCLE_IR=$PWD/packages/circle-ir/dist/index.js node bench/nav.mjs <repo>
//
// Java only, like the rest of bench/.
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
const { initAnalyzer, analyze, buildNavigationIndex } = await import(process.env.CIRCLE_IR);
const ROOT = process.argv[2];

function walk(d, out = []) {
  for (const e of readdirSync(d).sort()) {
    const p = join(d, e), s = statSync(p);
    if (s.isDirectory()) { if (!['node_modules', '.git', 'target'].includes(e)) walk(p, out); }
    else if (p.endsWith('.java')) out.push(p);
  }
  return out;
}

const files = walk(ROOT);
await initAnalyzer();
let t = performance.now();
const entries = [];
for (const f of files) {
  const source = readFileSync(f, 'utf8');
  entries.push({
    path: relative(ROOT, f), language: 'java', source,
    ir: await analyze(source, f, 'java', { navigationTypes: true }),
  });
}
const parseMs = performance.now() - t;
t = performance.now();
const idx = buildNavigationIndex(entries, { parseMs, cache: true });
console.log('files', files.length, '| parse ms', parseMs.toFixed(0), '| index ms', (performance.now() - t).toFixed(1));

const targets = [
  'org.owasp.webgoat.container.users.WebGoatUser.equals',
  'org.owasp.webgoat.container.assignments.AttackResultBuilder.failed',
  'org.owasp.webgoat.container.assignments.AttackResultBuilder.output',
  'org.owasp.webgoat.container.i18n.Messages.getMessage',
  'org.owasp.webgoat.container.LessonDataSource.getConnection',
  'org.owasp.webgoat.lessons.challenges.challenge7.MD5.decode',
  'org.owasp.webgoat.lessons.clientsidefiltering.CheckoutCodes.get',
  'org.owasp.webgoat.container.lessons.Lesson.getName',
  'org.owasp.webgoat.container.session.LessonSession.getValue',
  'org.owasp.webgoat.ServerUrlConfig.url',
];
const rows = [];
for (const sym of targets) {
  const t0 = performance.now();
  const a = idx.resolveCallers({ symbol: sym });
  const byTier = { exact: 0, polymorphic: 0, inferred: 0 };
  for (const x of a.answers) byTier[x.tier]++;
  const reasons = {};
  for (const u of a.unresolved) reasons[u.reason] = (reasons[u.reason] || 0) + 1;
  rows.push({
    target: sym.split('.').slice(-2).join('.'),
    answers: a.answers.length, ...byTier,
    unresolved: a.unresolved.length,
    reasons: Object.entries(reasons).map(([k, v]) => `${k}:${v}`).join(' ') || '—',
    ms: (performance.now() - t0).toFixed(1),
  });
}
console.table(rows);

// Whole-repository tier census, one entry per distinct call site, so the
// number is comparable with `probe.mjs`'s resolve-all over `ir.calls`.
// Overloads share a widened line range, so a site can be visited twice; the
// site key dedupes it. Sites inside no declared method body (a field
// initialiser, a static block) are not reachable by a callee query and are
// counted separately rather than silently dropped.
const census = { exact: 0, polymorphic: 0, inferred: 0 };
const reasons = {};
const seen = new Set();
for (const e of entries) {
  for (const t of e.ir.types ?? []) {
    for (const m of t.methods ?? []) {
      // Mirror the index's own FQN: a nested type's `package` can be null, and
      // the file's `meta.package` is the fallback the index uses.
      const tpkg = t.package ?? e.ir.meta?.package ?? '';
      const fqn = [tpkg, t.enclosing_type, t.name, m.name].filter(Boolean).join('.');
      const a = idx.resolveCallees({ symbol: fqn });
      // A (file, line, col) triple is NOT unique: a chained expression reports
      // several calls at the start of the expression. The target or the method
      // name completes the key.
      for (const x of a.answers) {
        const k = `${x.site.file}:${x.site.line}:${x.site.col}:${x.target}`;
        if (seen.has(k)) continue; seen.add(k); census[x.tier]++;
      }
      for (const u of a.unresolved) {
        const k = `${u.site.file}:${u.site.line}:${u.site.col}:${u.methodName}`;
        if (seen.has(k)) continue; seen.add(k); reasons[u.reason] = (reasons[u.reason] || 0) + 1;
      }
    }
  }
}
const allSites = entries.reduce((n, e) => n + (e.ir.calls?.length ?? 0), 0);
const answered = census.exact + census.polymorphic + census.inferred;
const unresolvedTotal = Object.values(reasons).reduce((a, b) => a + b, 0);
console.log('\ntier census, one entry per distinct call site:');
console.log(JSON.stringify({
  call_sites_in_ir: allSites,
  visited: answered + unresolvedTotal,
  not_reached_by_a_callee_query: allSites - (answered + unresolvedTotal),
  answered, ...census,
  unresolved: unresolvedTotal, reasons,
}, null, 1));
