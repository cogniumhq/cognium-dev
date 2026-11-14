#!/usr/bin/env node
// release-readiness — the release-readiness skill's review (skills/release-readiness/SKILL.md).
//
// Runs on one release candidate (an rc tag) and writes a verdict: every check pass, fail, waived
// or abstain with its evidence, overall GO or NO-GO, and each failure as a ready-to-file task.
// Node 22, no dependencies, no network of its own. Re-runnable; writes only the files it is told to.
//
//   node readiness.mjs [--config .release-readiness.json] [--tag <rc tag>] [--sha <commit>]
//                      [--out-md verdict.md] [--out-json verdict.json] [--only ci,benchmark,...]
//                      [--today YYYY-MM-DD]   (--only also takes "goal")
//                      [--gate-from <dir>]    the base branch's gate files (0.4.0): config, figure of
//                                             record, waivers, goals read from <dir>, not the candidate
//                      [--final]              an open waiver is NO-GO (the review before a final release)
//   env BRANCH_CHECK_BASE  the base branch a failure's task is fixed on (0.4.4; default main; the
//                          git-branching setting, which the CI template passes from its BASE)
//
// Exit 0 = GO, 1 = NO-GO, 2 = usage or config error.
//
// The checks, in order:
//   ci:<id>           each command in config "ci", run at the candidate's checkout; exit 0 = pass
//   benchmark:...     the benchmark gate: the candidate's results file against the figure-of-record
//                     file; one check per suite and metric (see benchmarkGate below)
//   security, sbom-licence, customer:<id>
//                     hooks; exit 0 = pass, 3 = abstain, anything else = fail. Not configured = abstain.
//   figure:<check>:<metric>
//                     figures a check reports on its output ("release-readiness:figure <metric> <value>"),
//                     a count or a pass/fail, against the rows of record that name that check (figureGate)
//   goal:<suite>      benchmark goals from .loop/benchmarks.json (optional): the suite's command prints
//                     "release-readiness:figure <metric> <value>"; met = pass, below the goal = warn
//                     (shown, does not change the verdict), or fail when mode is block and the
//                     figure-of-record file holds a number of record for that metric (judgeGoal)
//   figure-of-record  fails when a command changed the figure-of-record file during the review
//   waivers           fails when a command changed the waiver file during the review
//   goals-file        fails when a command changed .loop/benchmarks.json during the review
// The three files are read once, before any command of the candidate runs; only those copies are used.
// A waiver file can turn one named failing check into "waived", in the verdict, never silently; only a
// person's answer with a confirming check counts, and a waiver stays open until that check passes.
// With --gate-from the gate is the base branch's, so a candidate cannot weaken its own gate.
// The review never writes the figure of record; a person records a new figure in a reviewed PR.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

export const VERSION = "0.4.4";
export const ABSTAIN_EXIT = 3;
/** At most this many invalid figure names are named in a check's summary; the rest are counted. */
export const MAX_LISTED = 20;
/** The verdict Markdown (written into the release notes) is cut to at most this many bytes. */
export const MAX_SUMMARY_BYTES = 60 * 1024;
const NO_RECORD = "no record yet";
const EPS = 1e-9;

// ---------- the benchmark gate ----------

const num = (x) => typeof x === "number" && Number.isFinite(x);
const fmt = (x) => (num(x) ? String(Math.round(x * 1e6) / 1e6) : String(x));

// A row's kind: "number" (the default, every 0.2.0 row), "count" (a whole number ≥ 0 with a
// direction, e.g. open must-fix findings, lower is better) or "passfail" (pass is better).
export const KINDS = ["number", "count", "passfail"];
const isCount = (x) => Number.isInteger(x) && x >= 0;
/** "pass" or "fail" for a pass/fail value (true/false accepted), else null. */
export function passfail(x) {
  if (x === true || x === "pass") return "pass";
  if (x === false || x === "fail") return "fail";
  return null;
}

/** Why a figure-of-record row is not of record, or null when it is. */
export function notOfRecord(row) {
  if (row.status && String(row.status).toLowerCase() === NO_RECORD) return "no figure of record yet";
  const kind = row.kind ?? "number";
  if (!KINDS.includes(kind)) return `not of record: kind must be one of ${KINDS.join(", ")}, not ${JSON.stringify(row.kind)}`;
  if (kind === "passfail") {
    if (!passfail(row.value)) return 'not of record: a passfail value must be "pass" or "fail"';
  } else if (!num(row.value)) return "not of record: no numeric value";
  else if (kind === "count" && !isCount(row.value)) return "not of record: a count must be a whole number ≥ 0";
  const missing = ["version", "date", "method"].filter((k) => !row[k] || !String(row[k]).trim());
  if (missing.length) return `not of record: no ${missing.join(", ")}`;
  if (kind === "passfail") return null;
  if (row.direction !== "higher" && row.direction !== "lower")
    return `not of record: direction must be "higher" or "lower", not ${JSON.stringify(row.direction)}`;
  if (row.tolerance !== undefined && !(num(row.tolerance) && row.tolerance >= 0))
    return "not of record: tolerance must be a number ≥ 0";
  return null;
}

/** The record's own words: value, version, date, method, direction and tolerance. */
function recordLabel(row) {
  const kind = row.kind ?? "number";
  if (kind === "passfail") return `record ${passfail(row.value)} (${row.version}, ${row.date}, ${row.method}); pass/fail, pass is better`;
  return `record ${fmt(row.value)} (${row.version}, ${row.date}, ${row.method}); ${kind === "count" ? "count, " : ""}${row.direction} is better, tolerance ${fmt(row.tolerance ?? 0)}`;
}

/**
 * Compare one value with a row of record (the row is of record). Returns { status, summary }:
 * fail on a regression beyond tolerance or on a value of the wrong kind, else pass with what moved.
 */
export function compareWithRecord(row, value) {
  const kind = row.kind ?? "number";
  if (kind === "passfail") {
    const rec = passfail(row.value), now = passfail(value);
    if (!now) return { status: "fail", summary: `candidate value ${JSON.stringify(value)} is not pass or fail` };
    if (rec === "pass" && now === "fail") return { status: "fail", summary: "regressed: pass of record, fail on the candidate" };
    if (rec === "fail" && now === "pass") return { status: "pass", summary: "improved: fail of record, pass on the candidate (the figure of record is not changed by this review)" };
    return { status: "pass", summary: `same as the figure of record (${now})` };
  }
  if (!num(value)) return { status: "fail", summary: "candidate value is not a number" };
  if (kind === "count" && !isCount(value)) return { status: "fail", summary: `candidate value ${fmt(value)} is not a count (a whole number ≥ 0)` };
  const tol = row.tolerance ?? 0;
  const drop = row.direction === "higher" ? row.value - value : value - row.value;
  if (kind === "count") {
    const moved = `${fmt(row.value)} → ${fmt(value)}`;
    if (drop > tol + EPS) return { status: "fail", summary: `worse by ${fmt(drop)} (${moved}), beyond tolerance ${fmt(tol)}` };
    if (drop > EPS) return { status: "pass", summary: `worse by ${fmt(drop)} (${moved}), within tolerance ${fmt(tol)}` };
    if (drop < -EPS) return { status: "pass", summary: `better by ${fmt(-drop)} (${moved}; the figure of record is not changed by this review)` };
    return { status: "pass", summary: `same as the figure of record (${fmt(value)})` };
  }
  if (drop > tol + EPS) return { status: "fail", summary: `dropped ${fmt(drop)}, beyond tolerance ${fmt(tol)}` };
  if (drop > EPS) return { status: "pass", summary: `dropped ${fmt(drop)}, within tolerance ${fmt(tol)}` };
  if (drop < -EPS) return { status: "pass", summary: `improved by ${fmt(-drop)} (the figure of record is not changed by this review)` };
  return { status: "pass", summary: "same as the figure of record" };
}

/**
 * Compare a candidate's results with the figure of record.
 * record:    { records: [{ suite, metric, value, direction: "higher"|"lower", tolerance, version, date, method, status? }] }
 * candidate: { tag | sha, version, date, method, results: [{ suite, metric, value }] } or null (none of this candidate's)
 * Returns one check per suite and metric: fail on a drop beyond tolerance or on a metric of record
 * the candidate did not measure; abstain on a row that is not of record (never pass).
 */
export function benchmarkGate(record, candidate) {
  const checks = [];
  // Rows that name a "check" are that check's figures (figureGate), not benchmark rows.
  const rows = (Array.isArray(record?.records) ? record.records : []).filter((r) => !r?.check);
  const results = Array.isArray(candidate?.results) ? candidate.results : [];
  const key = (r) => `${r.suite}:${r.metric}`;
  const byKey = new Map();
  for (const r of results) byKey.set(key(r), [...(byKey.get(key(r)) || []), r]);
  const twice = (k) => {
    const all = byKey.get(k) || [];
    return all.length > 1 ? { id: `benchmark:${k}`, group: "benchmark", status: "fail",
      summary: `measured ${all.length} times: ${all.map((r) => fmt(r.value)).join(", ")}`,
      evidence: [`the candidate results file has ${all.length} rows for ${k}; one result per suite and metric`] } : null;
  };
  const seen = new Set();
  const candLabel = candidate
    ? `candidate ${[candidate.version, candidate.date, candidate.method].filter(Boolean).join(", ") || "(unlabelled)"}`
    : "no candidate results file";

  for (const row of rows) {
    const k = key(row);
    if (seen.has(k)) {
      checks.push({ id: `benchmark:${k}`, group: "benchmark", status: "abstain",
        summary: "duplicate figure-of-record row", evidence: [`${k} appears more than once in the figure-of-record file`] });
      continue;
    }
    seen.add(k);
    const id = `benchmark:${k}`;
    const dup = twice(k);
    if (dup) { checks.push(dup); continue; }
    const cand = byKey.get(k)?.[0];
    const why = notOfRecord(row);
    if (why) {
      checks.push({ id, group: "benchmark", status: "abstain", summary: why,
        evidence: [cand && num(cand.value) ? `candidate measured ${fmt(cand.value)}; nothing of record to compare it with` : "nothing to compare"] });
      continue;
    }
    const rec = recordLabel(row);
    if (!cand) {
      checks.push({ id, group: "benchmark", status: "fail", summary: "not measured on the candidate",
        evidence: [rec, `${candLabel}: no result for ${k}`] });
      continue;
    }
    const ev = [rec, `${candLabel}: ${num(cand.value) ? fmt(cand.value) : JSON.stringify(cand.value)}`];
    checks.push({ id, group: "benchmark", ...compareWithRecord(row, cand.value), evidence: ev });
  }
  for (const r of results) {
    const k = key(r);
    if (seen.has(k)) continue;
    seen.add(k);
    const dup = twice(k);
    if (dup) { checks.push(dup); continue; }
    checks.push({ id: `benchmark:${k}`, group: "benchmark", status: "abstain", summary: "no figure of record yet",
      evidence: [`candidate measured ${fmt(r.value)}; no row in the figure-of-record file`] });
  }
  if (!checks.length)
    checks.push({ id: "benchmark", group: "benchmark", status: "abstain", summary: "no figure of record and no candidate results",
      evidence: ["the figure-of-record file has no benchmark rows"] });
  return checks;
}

// ---------- figures a check reports ----------

/** One figure line on a command's output: "release-readiness:figure <metric> <value>". */
const FIGURE_LINE = /^release-readiness:figure[ \t]+(\S+)[ \t]+(\S+)[ \t]*$/;
/** A figure's metric name: lower-case letter, then lower-case letters, digits and "_", 64 at most. */
export const METRIC = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * The figures a command printed: { figures: { metric: [value, ...] }, invalid: [name, ...] }.
 * figures has no prototype, so a name like "__proto__" or "constructor" is never an inherited key;
 * a name that does not match METRIC is not kept but listed in invalid (the check then fails).
 * Values: "pass"/"fail", numbers, or the raw text.
 */
export function parseFigures(out) {
  const figures = Object.create(null);
  const invalid = [];
  for (const line of String(out || "").split(/\r?\n/)) {
    const m = FIGURE_LINE.exec(line.trim());
    if (!m) continue;
    if (!METRIC.test(m[1])) { invalid.push(m[1].slice(0, 80)); continue; }
    const raw = m[2];
    const v = raw === "pass" || raw === "fail" ? raw : /^-?\d+(\.\d+)?$/.test(raw) ? Number(raw) : raw;
    if (!Object.hasOwn(figures, m[1])) figures[m[1]] = [];
    figures[m[1]].push(v);
  }
  return { figures, invalid };
}

/** A goal check that only warns (mode warn, or block without a number of record): a doubled figure with no row of record warns too. */
const warnOnly = (c) => c?.group === "goal" && c.status === "warn";

/** The values a check reported for one metric (own keys only), or []. */
const reported = (c, metric) => (c?.figures && Object.hasOwn(c.figures, metric) ? c.figures[metric] : []);

/**
 * Compare the figures checks reported in this review with the rows of record that name a check.
 * record: { records: [{ check: "<check id>", metric, kind: "count"|"passfail"|"number", value,
 *           direction (not for passfail), tolerance, version, date, method, status? }] }
 * checks: the checks this review ran, each with the "figures" its command printed.
 * One check per row, id figure:<check>:<metric>: fail on a regression beyond tolerance, on a figure
 * of record the check did not report (it ran but printed nothing, abstained without a figure, timed
 * out, or was not run at all), or reported twice; abstain only when the row is not of record. A check
 * with a figure of record cannot abstain its way out: if it abstained, a figure it printed is still
 * compared, and a figure it did not print fails as not reported (only a pre-run waiver for that
 * figure can cover it). A figure a check reported with no row abstains ("no figure of record yet"),
 * so a person can record it. Never writes.
 * wanted(group) says whether this review ran a check group (--only); rows of other groups are skipped.
 */
export function figureGate(record, checks, { wanted = () => true } = {}) {
  const out = [];
  const rows = (Array.isArray(record?.records) ? record.records : []).filter((r) => r?.check);
  const groupOf = (id) => String(id).split(":")[0];
  const seen = new Set();
  for (const row of rows) {
    if (!wanted(groupOf(row.check))) continue;
    const k = `${row.check}:${row.metric}`;
    const id = `figure:${k}`;
    if (seen.has(k)) {
      out.push({ id, group: "figure", status: "abstain", summary: "duplicate figure-of-record row",
        evidence: [`${k} appears more than once in the figure-of-record file`] });
      continue;
    }
    seen.add(k);
    const c = checks.find((x) => x.id === row.check);
    const vals = reported(c, row.metric);
    const why = METRIC.test(String(row.metric)) ? notOfRecord(row)
      : `not of record: metric ${JSON.stringify(row.metric)} is not a figure name (${METRIC.source})`;
    if (why) {
      out.push({ id, group: "figure", status: "abstain", summary: why,
        evidence: [vals.length ? `${row.check} reported ${vals.map(fmt).join(", ")}; nothing of record to compare it with` : "nothing to compare"] });
      continue;
    }
    const rec = recordLabel(row);
    if (!c) {
      out.push({ id, group: "figure", status: "fail", summary: "the check of record did not run in this review",
        evidence: [rec, `no check ${row.check} in this review (not configured?)`] });
      continue;
    }
    if (!vals.length) {
      const why = c.status === "abstain" ? "abstained" : c.status === "fail" ? "failed" : "passed";
      out.push({ id, group: "figure", status: "fail", summary: `not reported by ${row.check} (it ${why})`,
        evidence: [rec, `${row.check} (${c.status}: ${c.summary}) printed no "release-readiness:figure ${row.metric} <value>" line`,
          ...(c.status === "abstain" ? ["a check with a figure of record cannot abstain its way out; only a pre-run waiver for this figure covers it"] : [])] });
      continue;
    }
    if (vals.length > 1) {
      // A row of record fails closed on a doubled figure, whatever the goal's mode.
      out.push({ id, group: "figure", status: "fail", summary: `reported ${vals.length} times: ${vals.map(fmt).join(", ")}`,
        evidence: [rec, `${row.check} printed ${vals.length} figure lines for ${row.metric}; one per metric`] });
      continue;
    }
    out.push({ id, group: "figure", ...compareWithRecord(row, vals[0]),
      evidence: [rec, `${row.check} on the candidate (${c.status}): ${fmt(vals[0])}`] });
  }
  for (const c of checks) {
    for (const [metric, vals] of Object.entries(c.figures || Object.create(null))) {
      const k = `${c.id}:${metric}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ id: `figure:${k}`, group: "figure", status: vals.length > 1 ? (warnOnly(c) ? "warn" : "fail") : "abstain",
        summary: vals.length > 1 ? `reported ${vals.length} times: ${vals.map(fmt).join(", ")}${warnOnly(c) ? " (the goal warns, so this warns too)" : ""}` : "no figure of record yet",
        evidence: [`${c.id} reported ${vals.map(fmt).join(", ")}; no row in the figure-of-record file names this check and metric`] });
    }
  }
  return out;
}

// ---------- benchmark goals (.loop/benchmarks.json, 0.3.2) ----------

/** Where a repository lists its benchmark goals, relative to the repository root. Optional. */
export const GOALS_FILE = ".loop/benchmarks.json";
export const GOAL_MODES = ["warn", "block"];
const COMPARISONS = { ">=": ">=", "≥": ">=", "<=": "<=", "≤": "<=" };
/** A suite name in a goal: letters, digits, ".", "_", "/" and "-", 128 at most. */
export const SUITE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;

/**
 * Parse the goals file's text. Returns { goals: [...], problems: [...] }: each well-formed entry is
 * { suite, metric, goal, comparison: ">="|"<=", run, mode }, mode defaulting to "warn"; each malformed
 * entry is { entry, index, why, mode } (mode "block" only when the entry asked for it in so many words).
 * A file that is not JSON, or has no "goals" array, gives one problem with index -1.
 */
export function parseGoals(text) {
  let doc;
  // A file we cannot read as goals fails when its text asks for block anywhere, else warns.
  const asksBlock = /"mode"\s*:\s*"block"/.test(String(text).slice(0, 1 << 20)) ? "block" : "warn";
  try { doc = JSON.parse(text); } catch (e) { return { goals: [], problems: [{ index: -1, why: `not JSON: ${e.message}`, mode: asksBlock }] }; }
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.goals))
    return { goals: [], problems: [{ index: -1, why: 'no "goals" array', mode: asksBlock }] };
  const goals = [], problems = [];
  doc.goals.forEach((g, index) => {
    const asked = g && typeof g === "object" && g.mode === "block" ? "block" : "warn";
    const bad = (why) => problems.push({ index, entry: g, why, mode: asked });
    if (!g || typeof g !== "object" || Array.isArray(g)) return bad("an entry must be an object");
    if (typeof g.suite !== "string" || !SUITE.test(g.suite)) return bad(`suite ${JSON.stringify(g.suite)} must match ${SUITE.source}`);
    if (typeof g.metric !== "string" || !METRIC.test(g.metric)) return bad(`metric ${JSON.stringify(g.metric)} must match ${METRIC.source}`);
    if (!num(g.goal)) return bad(`goal ${JSON.stringify(g.goal)} must be a number`);
    if (!Object.hasOwn(COMPARISONS, String(g.comparison))) return bad(`comparison ${JSON.stringify(g.comparison)} must be ">=" or "<="`);
    if (typeof g.run !== "string" || !g.run.trim()) return bad("no command (run)");
    if (g.mode !== undefined && !GOAL_MODES.includes(g.mode)) return bad(`mode ${JSON.stringify(g.mode)} must be "warn" or "block"`);
    goals.push({ suite: g.suite, metric: g.metric, goal: g.goal, comparison: COMPARISONS[g.comparison], run: g.run, mode: g.mode ?? "warn" });
  });
  // One entry per suite: the check is goal:<suite>, and a figure row of record names it.
  const n = new Map();
  for (const g of goals) n.set(g.suite, (n.get(g.suite) || 0) + 1);
  return {
    goals: goals.filter((g) => n.get(g.suite) === 1),
    problems: [...problems, ...goals.filter((g) => n.get(g.suite) > 1)
      .map((g) => ({ index: -1, entry: g, why: `suite ${g.suite} listed more than once (one goal per suite)`, mode: g.mode }))],
  };
}

/**
 * Read the goals file without ever throwing: { state: "none"|"file"|"unreadable", text, why, key }.
 * A dangling symlink is "none"; a directory (or a link to one), or a file that cannot be read, is
 * "unreadable" (one goal warning). key is what the integrity check compares before and after the run.
 */
export function snapshotGoals(path) {
  let st;
  try { st = statSync(path); } catch (e) {
    if (e.code === "ENOENT" || e.code === "ENOTDIR") return { state: "none", text: null, key: null };
    return { state: "unreadable", text: null, why: `cannot read: ${e.code || e.message}`, key: `\0unreadable:${e.code}` };
  }
  if (!st.isFile()) return { state: "unreadable", text: null, why: `not a file (${st.isDirectory() ? "a directory" : "not a regular file"})`, key: `\0notfile:${st.isDirectory() ? "dir" : "other"}` };
  try { const text = readFileSync(path, "utf8"); return { state: "file", text, key: text }; }
  catch (e) { return { state: "unreadable", text: null, why: `cannot read: ${e.code || e.message}`, key: `\0unreadable:${e.code}` }; }
}

/**
 * The number of record a goal can block on: a row of record (value, version, date and method, and
 * not "no record yet") for the goal's metric, either the goal command's own figure
 * ({ "check": "goal:<suite>", "metric" }) or a benchmark row ({ "suite", "metric" }). Null when none.
 */
export function goalRecord(record, g) {
  const rows = Array.isArray(record?.records) ? record.records : [];
  return rows.find((r) => r && r.metric === g.metric && (r.check === `goal:${g.suite}` || (!r.check && r.suite === g.suite))
    && (r.kind ?? "number") !== "passfail" && notOfRecord(r) === null) || null;
}

/**
 * Judge one goal from its command's check (commandCheck output, which carries the figures it printed).
 * Met: pass. Below the goal, or no usable figure: "warn" (does not change the verdict), or "fail"
 * when the goal's mode is block and a number of record exists for its metric; mode block without
 * one is treated as warn and the check says why.
 */
export function judgeGoal(g, c, record) {
  const rec = goalRecord(record, g);
  const blocking = g.mode === "block" && !!rec;
  const id = `goal:${g.suite}`;
  const want = `goal ${g.comparison === ">=" ? "≥" : "≤"} ${fmt(g.goal)}`;
  const ev = [`${want}; mode ${g.mode}${g.mode === "block" ? (rec ? ` (number of record ${fmt(rec.value)}, ${rec.version}, ${rec.date}, ${rec.method})`
    : ": treated as warn, the figure-of-record file has no number of record for this metric (value, version, date and method)") : ""}`,
    ...c.evidence];
  const vals = reported(c, g.metric);
  let short = null, value;
  if (c.status === "fail" && /invalid figure name|timed out/.test(c.summary)) short = `the command ${c.summary}`;
  else if (vals.length > 1) short = `reported ${vals.length} times: ${vals.map(fmt).join(", ")}`;
  else if (!vals.length) short = `no "release-readiness:figure ${g.metric} <value>" line (the command ${c.status === "pass" ? "passed" : c.status === "abstain" ? "abstained" : c.summary})`;
  else if (!num(vals[0])) short = `value ${JSON.stringify(vals[0])} is not a number`;
  else {
    value = vals[0];
    const met = g.comparison === ">=" ? value >= g.goal - EPS : value <= g.goal + EPS;
    if (!met) short = `below goal: ${fmt(value)}, ${want}`;
  }
  const figures = c.figures ? { figures: c.figures } : {};
  if (!short) return { id, group: "goal", status: "pass", summary: `met: ${fmt(value)}, ${want}`, evidence: ev, ...figures };
  const status = blocking ? "fail" : "warn";
  const note = blocking ? "" : g.mode === "block" ? " (warns: mode block needs a number of record)" : " (warns, does not block)";
  return { id, group: "goal", status, summary: short + note, evidence: ev, ...figures };
}

// ---------- whose results ----------

const sameSha = (a, b) => !!a && !!b && a.length >= 7 && b.length >= 7 && (a.startsWith(b) || b.startsWith(a));

/**
 * The candidate results file must name the candidate it was measured on: "tag" equal to the rc tag
 * under review, or "sha" equal to its commit (7+ hex digits, prefix match). Returns the check that
 * says so and the results to compare, or null results when they are not this candidate's: then every
 * row of record fails as not measured, and the check itself fails, so stale numbers never pass.
 */
export function candidateFor(candidate, { tag, sha } = {}) {
  const id = "benchmark:results";
  if (!candidate) return { check: null, results: null };
  const named = [candidate.tag && `tag ${candidate.tag}`, candidate.sha && `sha ${candidate.sha}`].filter(Boolean).join(", ") || "neither a tag nor a sha";
  const under = [tag && `tag ${tag}`, sha && `sha ${sha}`].filter(Boolean).join(", ");
  if (!tag && !sha)
    return { results: null, check: { id, group: "benchmark-input", status: "abstain", summary: "no --tag or --sha to tie the results to",
      evidence: [`the results file names ${named}; run the review with --tag and --sha`] } };
  if ((tag && candidate.tag === tag) || sameSha(String(candidate.sha || ""), String(sha || "")))
    return { results: candidate, check: { id, group: "benchmark-input", status: "pass", summary: "the results are this candidate's",
      evidence: [`the results file names ${named}; under review: ${under}`] } };
  return { results: null, check: { id, group: "benchmark-input", status: "fail", summary: "the results are not this candidate's",
    evidence: [`the results file names ${named}; under review: ${under}`, "re-measure on the candidate and record its tag or sha in the results file"] } };
}

// ---------- waivers ----------

const DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * waivers: { waivers: [{ check, who, why, until: "YYYY-MM-DD", answer, confirm, tag? }] }
 * A valid waiver (who, why, until, answer and confirm set, until not past, tag matching when given,
 * `who` a person) turns its one named check from fail into waived. `answer` is the https link to the
 * person's own answer to the waiver question; `confirm` names the check that confirms the waiver can
 * close (often the waived check itself, on a later candidate). Agent-written text never counts: a
 * `who` that ends in [bot] or is in the config's `agents` list is ignored. An applied waiver is
 * "open" until its confirming check passes in a review; open waivers block a final release.
 * Every waiver, used or not, is reported.
 */
// Integrity checks a waiver can never turn into "waived": they say the review's own inputs were tampered with.
export const UNWAIVABLE = ["figure-of-record", "waivers", "goals-file"];

const ANSWER = /^https:\/\/[^\s]+$/;

/** True when `who` names an agent: a GitHub App's [bot] login, or a login in the config's `agents`. */
export function isAgent(who, agents = []) {
  const w = String(who ?? "").trim().toLowerCase();
  return w.endsWith("[bot]") || agents.some((a) => String(a).trim().toLowerCase() === w);
}

export function applyWaivers(checks, waivers, { today, tag, agents = [] } = {}) {
  const report = [];
  const list = Array.isArray(waivers?.waivers) ? waivers.waivers : [];
  for (const w of list) {
    const name = w?.check ? String(w.check) : "(no check named)";
    const missing = ["check", "who", "why", "until", "answer", "confirm"].filter((k) => !w?.[k] || !String(w[k]).trim());
    if (missing.length) { report.push({ check: name, state: "ignored", note: `invalid: no ${missing.join(", ")}`, waiver: w }); continue; }
    if (!DATE.test(String(w.until))) { report.push({ check: name, state: "ignored", note: `invalid: until ${JSON.stringify(w.until)} is not YYYY-MM-DD`, waiver: w }); continue; }
    if (today && w.until < today) { report.push({ check: name, state: "ignored", note: `expired on ${w.until}`, waiver: w }); continue; }
    if (w.tag && w.tag !== tag) { report.push({ check: name, state: "ignored", note: `for ${w.tag}, not ${tag || "a review without --tag"}`, waiver: w }); continue; }
    if (UNWAIVABLE.includes(name)) { report.push({ check: name, state: "ignored", note: "an integrity check cannot be waived", waiver: w }); continue; }
    if (isAgent(w.who, agents)) { report.push({ check: name, state: "ignored", note: `${w.who} is an agent: only a person's answer waives a check`, waiver: w }); continue; }
    if (!ANSWER.test(String(w.answer).trim())) { report.push({ check: name, state: "ignored", note: "invalid: answer is not an https link to the person's answer", waiver: w }); continue; }
    const c = checks.find((x) => x.id === name);
    if (!c) { report.push({ check: name, state: "unused", note: "no such check in this review", waiver: w }); continue; }
    if (c.status !== "fail") { report.push({ check: name, state: "unused", note: `the check is ${c.status}`, waiver: w }); continue; }
    c.status = "waived";
    c.evidence = [...c.evidence, `WAIVED by ${w.who} until ${w.until}: ${w.why} (answer ${w.answer}; confirmed by ${w.confirm})`];
    report.push({ check: name, state: "applied", note: `by ${w.who} until ${w.until}: ${w.why}`, waiver: w });
  }
  // Open or closed: a waiver closes when its confirming check passed in this review.
  for (const r of report) {
    if (r.state !== "applied") continue;
    const conf = checks.find((x) => x.id === String(r.waiver.confirm).trim());
    r.open = !(conf && conf.status === "pass");
    r.note += r.open ? ` · open: ${r.waiver.confirm} ${conf ? `is ${conf.status}` : "did not run in this review"}` : ` · closed: ${r.waiver.confirm} passed`;
  }
  return report;
}

/** A pass or fail is a claim; without evidence it is a fail (approvals quote the evidence). */
export function requireEvidence(checks) {
  for (const c of checks) {
    if (c.status !== "pass" && c.status !== "fail") continue;
    const ev = (Array.isArray(c.evidence) ? c.evidence : []).filter((e) => String(e ?? "").trim());
    if (!ev.length) {
      c.status = "fail";
      c.summary = `no evidence recorded${c.summary ? ` (was: ${c.summary})` : ""}`;
      c.evidence = ["a result without evidence cannot be approved: the check recorded none"];
    }
  }
}

// ---------- verdict ----------

/** GO or NO-GO, with the reasons. */
export function decide(checks, required = []) {
  const reasons = [];
  for (const c of checks) if (c.status === "fail") reasons.push(`${c.id} failed: ${c.summary}`);
  for (const r of required) {
    // A group is its checks' "group"; the inputs of a gate (benchmark:run, benchmark:results) are
    // group "benchmark-input" and never satisfy "benchmark" on their own.
    const mine = checks.filter((c) => c.id === r || (c.group ?? c.id.split(":")[0]) === r);
    if (!mine.length || mine.every((c) => c.status === "abstain"))
      reasons.push(`required check ${r} abstained${mine[0] ? `: ${mine[0].summary}` : ""}`);
  }
  if (!checks.some((c) => c.status === "pass" || c.status === "waived")) reasons.push("no check passed");
  return { verdict: reasons.length ? "NO-GO" : "GO", reasons };
}

/** A ready-to-file task (for the release's epic) for one failed check. */
export function taskFor(check, meta) {
  const title = `release-readiness: ${check.id} failed on ${meta.tag || "the candidate"}`;
  const body = [
    `The release-readiness review of \`${meta.tag || "?"}\` at \`${meta.sha || "?"}\` failed **${check.id}**: ${check.summary}.`,
    "",
    "Evidence:",
    ...check.evidence.map((e) => `- ${e}`),
    "",
    `Done when: fixed on ${meta.base || "main"} and the check passes on the next candidate (rc.N+1). A waiver instead needs a person's entry in the waiver file (who, why, until).`,
  ].join("\n");
  return { check: check.id, title, body, labels: ["release-readiness"] };
}

const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>");

export function renderMarkdown(v) {
  const n = (s) => v.checks.filter((c) => c.status === s).length;
  const out = [
    "<!-- release-readiness:start -->",
    `## Release readiness: ${v.verdict}`,
    "",
    `Candidate \`${v.tag || "?"}\` at \`${v.sha || "?"}\` · reviewed ${v.at} · release-readiness ${v.tool}`,
    "",
    `${n("pass")} pass · ${n("fail")} fail · ${n("waived")} waived · ${n("warn")} warn · ${n("abstain")} abstain`,
    "",
    `Gate: ${v.gate === "base" ? "the base branch's (the candidate's own gate files were not used)" : "the candidate's checkout (no --gate-from)"} · final release: **${v.final_release ?? "allowed"}**${v.open_waivers?.length ? ` (open waivers: ${v.open_waivers.map((w) => `\`${cell(w)}\``).join(", ")})` : ""}`,
    "",
  ];
  if (v.reasons.length) out.push("**Why NO-GO**", "", ...v.reasons.map((r) => `- ${r}`), "");
  const warns = v.warnings ?? v.checks.filter((c) => c.status === "warn").map((c) => `${c.id}: ${c.summary}`);
  if (warns.length) out.push(`**Warnings** (${warns.length}; below a benchmark goal, not measured, or the candidate's gate differs from the base's; they do not change the verdict)`, "", ...warns.map((w) => `- ${cell(w)}`), "");
  out.push("| Check | Result | Evidence |", "|---|---|---|");
  for (const c of v.checks) out.push(`| \`${cell(c.id)}\` | **${c.status}**: ${cell(c.summary)} | ${cell(c.evidence.join("\n"))} |`);
  out.push("");
  if (v.waivers.length) {
    out.push("**Waivers**", "");
    for (const w of v.waivers) out.push(`- \`${w.check}\`: ${w.state} (${w.note})`);
    out.push("");
  }
  if (v.tasks.length) {
    out.push(`**Tasks for the epic** (${v.tasks.length}, one per failure)`, "");
    for (const t of v.tasks) out.push("<details><summary>" + cell(t.title) + "</summary>", "", t.body, "", "</details>", "");
  }
  out.push("<!-- release-readiness:end -->");
  return capMarkdown(out, MAX_SUMMARY_BYTES);
}

const bytes = (s) => Buffer.byteLength(s, "utf8");

/**
 * Join the verdict's lines, cut to at most max bytes (UTF-8), whole lines first. When cut, a marker
 * says how much was left out and where the rest is, an open <details> is closed, and the end marker
 * stays, so the release notes always hold one complete, bounded verdict block.
 */
export function capMarkdown(lines, max = MAX_SUMMARY_BYTES) {
  const full = lines.join("\n") + "\n";
  if (bytes(full) <= max) return full;
  const end = "<!-- release-readiness:end -->";
  const body = lines[lines.length - 1] === end ? lines.slice(0, -1) : lines;
  const marker = (n) => `\n**Truncated:** ${n} bytes of this verdict are not shown (the notes are kept under ${max} bytes); the full verdict is verdict.md and verdict.json of the review run.\n`;
  // Room for the marker (with a generous byte count), a closing </details> and the end marker.
  const reserve = bytes(marker(bytes(full))) + bytes("</details>\n") + bytes(end + "\n") + 2;
  const budget = Math.max(0, max - reserve);
  const kept = [];
  let used = 0;
  for (const l of body) {
    const need = bytes(l) + 1;
    if (used + need <= budget) { kept.push(l); used += need; continue; }
    const room = budget - used - 1 - bytes("…");
    if (room > 0) kept.push(Buffer.from(l, "utf8").subarray(0, room).toString("utf8").replace(/\uFFFD+$/, "") + "…");
    break;
  }
  const open = kept.filter((l) => l.startsWith("<details>")).length - kept.filter((l) => l === "</details>").length;
  const shown = kept.join("\n");
  const out = [shown, ...(open > 0 ? ["</details>"] : []), marker(bytes(full) - bytes(shown)), end].join("\n") + "\n";
  return out;
}

// ---------- running commands ----------

function tail(text, lines = 15, width = 300) {
  return String(text || "").trimEnd().split(/\r?\n/).slice(-lines).map((l) => (l.length > width ? l.slice(0, width) + "…" : l));
}

/** Run one shell command; returns { code, out, timedOut }. */
export function run(command, { cwd, timeoutSeconds = 900 } = {}) {
  const r = spawnSync("bash", ["-c", command], { cwd, encoding: "utf8", timeout: timeoutSeconds * 1000, maxBuffer: 64 << 20 });
  const timedOut = r.error?.code === "ETIMEDOUT" || r.signal === "SIGTERM";
  return { code: r.status ?? (r.error ? 127 : 1), out: `${r.stdout || ""}${r.stderr || ""}${r.error && !timedOut ? r.error.message : ""}`, timedOut };
}

/** The first MAX_LISTED items joined with ", ", then "and N more". */
export function listCapped(items, max = MAX_LISTED) {
  const shown = items.slice(0, max).join(", ");
  return items.length > max ? `${shown} and ${items.length - max} more` : shown;
}

function commandCheck(id, group, command, opts, { hook }) {
  const r = run(command, opts);
  const ev = [`\`${command}\` exit ${r.timedOut ? "timeout" : r.code}`, ...tail(r.out)];
  // Figures come only from this run's own output, so they are this candidate's; a timed-out run reports none.
  const { figures, invalid } = r.timedOut ? { figures: {}, invalid: [] } : parseFigures(r.out);
  const f = Object.keys(figures).length ? { figures } : {};
  if (r.timedOut) return { id, group, status: "fail", summary: `timed out after ${opts.timeoutSeconds}s`, evidence: ev };
  if (invalid.length)
    return { id, group, status: "fail", summary: `invalid figure name${invalid.length > 1 ? "s" : ""}: ${listCapped(invalid.map((n) => JSON.stringify(n)))}`,
      evidence: [...ev, `a figure name must match ${METRIC.source}; the command exited ${r.code}`], ...f };
  if (r.code === 0) return { id, group, status: "pass", summary: "passed", evidence: ev, ...f };
  if (hook && r.code === ABSTAIN_EXIT) return { id, group, status: "abstain", summary: "the hook abstained", evidence: ev, ...f };
  return { id, group, status: "fail", summary: `exit ${r.code}`, evidence: ev, ...f };
}

const HOOKS = ["security", "sbom-licence"];

function readJson(path, what) {
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (e) { throw new UsageError(`${what} ${path}: ${e.message}`); }
}
class UsageError extends Error {}

/** The whole review. Returns the verdict object. */
/** The gate files a review reads: the config, and the files it names (figure of record, waivers) plus the goals file. */
function gateFiles(config, configName) {
  const b = config?.benchmark || {};
  return [configName, b.record, config?.waivers, GOALS_FILE].filter(Boolean);
}

/**
 * With a base gate (--gate-from), the candidate's own copies of the gate files are compared with the
 * base's: a difference never changes the verdict (the base's copy is the one applied) and is shown as a
 * warning, so a candidate that edits its gate is seen, not obeyed.
 */
export function gateDiff(candidateRoot, gateRoot, files) {
  const changed = [];
  for (const f of files) {
    const a = resolve(candidateRoot, f), g = resolve(gateRoot, f);
    const ta = existsSync(a) ? readFileSync(a, "utf8") : null, tg = existsSync(g) ? readFileSync(g, "utf8") : null;
    if (ta !== tg) changed.push(`${f}: ${tg === null ? "not on the base" : ta === null ? "deleted by the candidate" : "differs from the base"}`);
  }
  return changed.length
    ? [{ id: "gate-definition", group: "gate-definition", status: "warn",
        summary: `the candidate's gate differs from the base's in ${changed.length} file(s); the base's applies`,
        evidence: [...changed, "a gate changes only once its PR is merged to the base"] }]
    : [];
}

export function review(config, { root, tag, sha, today, only, at = new Date(), gateRoot, configName = ".release-readiness.json", final = false, base } = {}) {
  // The gate's own files (figure of record, waivers, goals) are read from gateRoot: the base branch's
  // copy when --gate-from is given, else the candidate's checkout (before 0.4.0's behaviour).
  gateRoot ??= root;
  // Without an explicit date, waivers are judged against the review's own date: an expired waiver
  // never applies because a caller forgot to pass one. Tests pass a fixed date.
  today ??= at.toISOString().slice(0, 10);
  if (!DATE.test(String(today))) throw new UsageError("today must be YYYY-MM-DD");
  const opts = { cwd: root, timeoutSeconds: config.timeoutSeconds ?? 900 };
  const want = (g) => !only || only.includes(g);
  const checks = [];
  const abstain = (id, group, summary) => checks.push({ id, group, status: "abstain", summary, evidence: ["not configured in .release-readiness.json"] });
  // The figure of record is read once, before any command of the candidate runs, and never written:
  // a candidate's command cannot raise the bar it is measured against.
  const b = config.benchmark || {};
  const recPath = b.record ? resolve(gateRoot, b.record) : null;
  const recText = recPath && existsSync(recPath) ? readFileSync(recPath, "utf8") : null;
  let record = { records: [] };
  if (recText !== null) {
    try { record = JSON.parse(recText); } catch (e) { throw new UsageError(`figure-of-record file ${recPath}: ${e.message}`); }
  }
  // The waiver file likewise: only a waiver present before the candidate ran can apply, so a command
  // of the candidate cannot waive its own failure.
  const wPath = config.waivers ? resolve(gateRoot, config.waivers) : null;
  const wText = wPath && existsSync(wPath) ? readFileSync(wPath, "utf8") : null;
  let waiverFile = null;
  if (wText !== null) {
    try { waiverFile = JSON.parse(wText); } catch (e) { throw new UsageError(`waiver file ${wPath}: ${e.message}`); }
  }

  // The goals file likewise: the candidate cannot lower its own goal while it runs.
  const gPath = gateRoot !== undefined ? resolve(gateRoot, GOALS_FILE) : resolve(GOALS_FILE);
  // The candidate's own gate files, compared before any of its commands runs.
  const gateCheck = gateRoot !== root && root !== undefined ? gateDiff(root, gateRoot, gateFiles(config, configName)) : [];
  const gSnap = snapshotGoals(gPath);
  const gText = gSnap.text;
  const goalFile = gSnap.state === "none" ? null : gSnap.state === "file" ? parseGoals(gText)
    : { goals: [], problems: [{ index: -1, why: gSnap.why, mode: "warn" }] };

  if (want("ci")) {
    const ci = Array.isArray(config.ci) ? config.ci : [];
    if (!ci.length) abstain("ci", "ci", "no CI commands configured");
    for (const c of ci) checks.push(commandCheck(`ci:${c.id}`, "ci", c.run, opts, { hook: false }));
  }
  if (want("benchmark")) {
    if (!b.record) abstain("benchmark", "benchmark", "no figure-of-record file configured");
    else {
      // A measuring command that did not pass leaves no results of this candidate: the file on disk
      // is not read, so a stale one cannot pass the gate.
      let ran = true;
      if (b.run) {
        const r = commandCheck("benchmark:run", "benchmark-input", b.run, opts, { hook: true });
        checks.push(r);
        ran = r.status === "pass";
      }
      const candPath = b.candidate ? resolve(root, b.candidate) : null;
      const candidate = ran && candPath && existsSync(candPath) ? readJson(candPath, "candidate results file") : null;
      const { check: tie, results } = candidateFor(candidate, { tag, sha });
      if (tie) checks.push(tie);
      if (recText === null) abstain("benchmark", "benchmark", `figure-of-record file ${b.record} not found`);
      else checks.push(...benchmarkGate(record, results));
    }
  }
  const hooks = config.hooks || {};
  for (const h of HOOKS) {
    if (!want(h)) continue;
    if (hooks[h]?.run) checks.push(commandCheck(h, h, hooks[h].run, opts, { hook: true }));
    else abstain(h, h, "not configured");
  }
  if (want("customer")) {
    const cs = Array.isArray(hooks.customer) ? hooks.customer : [];
    if (!cs.length) abstain("customer", "customer", "no customer skills configured");
    for (const c of cs) checks.push(commandCheck(`customer:${c.id}`, "customer", c.run, opts, { hook: true }));
  }
  if (want("goal") && goalFile) {
    for (const p of goalFile.problems) {
      const where = p.index >= 0 ? `entry ${p.index + 1}` : GOALS_FILE;
      const id = p.index === -1 && !p.entry ? "goal" : `goal:${p.entry?.suite && SUITE.test(String(p.entry.suite)) ? p.entry.suite : `#${p.index + 1}`}`;
      // A malformed entry that asked to block fails (a declared block is never weakened silently);
      // anything else malformed warns, since the default is warn.
      checks.push({ id, group: "goal", status: p.mode === "block" ? "fail" : "warn",
        summary: `malformed goal (${where}): ${p.why}${p.mode === "block" ? "" : " (warns, does not block)"}`,
        evidence: [`${GOALS_FILE}: ${p.why}`] });
    }
    for (const g of goalFile.goals)
      checks.push(judgeGoal(g, commandCheck(`goal:${g.suite}`, "goal", g.run, opts, { hook: true }), record));
  }
  // Figures the checks reported, against the rows of record that name them (after every check ran).
  checks.push(...figureGate(record, checks, { wanted: want }));
  if (recPath) {
    const now = existsSync(recPath) ? readFileSync(recPath, "utf8") : null;
    if (now !== recText)
      checks.push({ id: "figure-of-record", group: "figure-of-record", status: "fail",
        summary: "the figure-of-record file changed during the review",
        evidence: [`${b.record} was ${recText === null ? "created" : now === null ? "deleted" : "rewritten"} by a command of the candidate`,
          "the review compared against the file as it was before any command ran; a figure is recorded only by a person, in a reviewed PR"] });
  }
  if (wPath) {
    const now = existsSync(wPath) ? readFileSync(wPath, "utf8") : null;
    if (now !== wText)
      checks.push({ id: "waivers", group: "waivers", status: "fail",
        summary: "the waiver file changed during the review",
        evidence: [`${config.waivers} was ${wText === null ? "created" : now === null ? "deleted" : "rewritten"} by a command of the candidate`,
          "only the waivers present before any command ran were applied; a waiver is written only by a person, in a reviewed PR"] });
  }

  {
    const after = snapshotGoals(gPath);
    const now = after.key;
    if (now !== gSnap.key)
      checks.push({ id: "goals-file", group: "goals-file", status: "fail",
        summary: "the goals file changed during the review",
        evidence: [`${GOALS_FILE} was ${gSnap.state === "none" ? "created" : after.state === "none" ? "deleted" : "rewritten"} by a command of the candidate`,
          "the goals were judged as they were before any command ran; a goal changes only in a reviewed PR"] });
  }

  checks.push(...gateCheck);
  requireEvidence(checks);
  const agents = Array.isArray(config.agents) ? config.agents : [];
  const waivers = waiverFile ? applyWaivers(checks, waiverFile, { today, tag, agents }) : [];
  const required = (config.required ?? ["ci"]).filter((r) => want(r.split(":")[0]));
  const decided = decide(checks, required);
  const openWaivers = waivers.filter((w) => w.state === "applied" && w.open).map((w) => w.check);
  // An open waiver blocks a final release; with --final it is a NO-GO of this review.
  if (final) for (const w of openWaivers) decided.reasons.push(`open waiver on ${w}: a final release needs its confirming check to pass`);
  const verdict = decided.reasons.length ? "NO-GO" : "GO";
  const reasons = decided.reasons;
  const finalRelease = openWaivers.length ? "blocked" : "allowed";
  const meta = { tag, sha, base };
  const tasks = checks.filter((c) => c.status === "fail").map((c) => taskFor(c, meta));
  const warnings = checks.filter((c) => c.status === "warn").map((c) => `${c.id}: ${c.summary}`);
  return { tool: VERSION, verdict, reasons, warnings, tag, sha, at: at.toISOString().replace(/\.\d+Z$/, "Z"),
    gate: gateRoot !== root ? "base" : "candidate", final_release: finalRelease, open_waivers: openWaivers, checks, waivers, tasks };
}

// ---------- CLI ----------

function parseArgs(argv) {
  const a = { config: ".release-readiness.json" };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i], v = () => { if (i + 1 >= argv.length) throw new UsageError(`${k} needs a value`); return argv[++i]; };
    if (k === "--config") a.config = v();
    else if (k === "--tag") a.tag = v();
    else if (k === "--sha") a.sha = v();
    else if (k === "--out-md") a.outMd = v();
    else if (k === "--out-json") a.outJson = v();
    else if (k === "--only") a.only = v().split(",").map((s) => s.trim()).filter(Boolean);
    else if (k === "--today") a.today = v();
    else if (k === "--gate-from") a.gateFrom = v();
    else if (k === "--final") a.final = true;
    else if (k === "-h" || k === "--help") a.help = true;
    else throw new UsageError(`unknown argument ${k}`);
  }
  return a;
}

function main(argv) {
  let a;
  try {
    a = parseArgs(argv);
    if (a.help) { console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 24).map((l) => l.replace(/^\/\/ ?/, "")).join("\n")); return 0; }
    if (a.today && !DATE.test(a.today)) throw new UsageError("--today must be YYYY-MM-DD");
    // 0.4.4: the base branch, as git-branching's check.sh reads it (empty or unset: main)
    const base = process.env.BRANCH_CHECK_BASE || "main";
    if (!/^[A-Za-z0-9_][A-Za-z0-9._/-]*$/.test(base) || base.includes("..") || base.endsWith("/") || /^(refs|rc|release|hotfix)\//.test(base))
      throw new UsageError(`BRANCH_CHECK_BASE ${JSON.stringify(base)} is not a base branch name`);
    const cfgPath = resolve(a.config);
    const root = dirname(cfgPath);
    let gateRoot = root, config;
    if (a.gateFrom) {
      // The base's gate: its config and the files it names, from a directory outside the candidate
      // (a command of the candidate must not be able to reach it through its own tree).
      gateRoot = resolve(a.gateFrom);
      const rel = relative(root, gateRoot);
      if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) throw new UsageError("--gate-from must be outside the candidate's checkout");
      const baseCfg = resolve(gateRoot, a.config.startsWith("/") ? relative(root, cfgPath) : a.config);
      if (!existsSync(baseCfg)) throw new UsageError(`the base has no ${relative(gateRoot, baseCfg)}: adopt the review on the base first`);
      config = readJson(baseCfg, "base config");
    } else {
      if (!existsSync(cfgPath)) throw new UsageError(`config ${a.config} not found`);
      config = readJson(cfgPath, "config");
    }
    const today = a.today || new Date().toISOString().slice(0, 10);
    const v = review(config, { root, tag: a.tag, sha: a.sha, today, only: a.only, gateRoot, configName: relative(root, cfgPath), final: !!a.final, base });
    const md = renderMarkdown(v);
    if (a.outMd) writeFileSync(a.outMd, md);
    if (a.outJson) writeFileSync(a.outJson, JSON.stringify(v, null, 2) + "\n");
    process.stdout.write(md);
    return v.verdict === "GO" ? 0 : 1;
  } catch (e) {
    if (e instanceof UsageError) { console.error(`release-readiness: ${e.message}`); return 2; }
    throw e;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
