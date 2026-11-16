// Tests for readiness.mjs. No network; temp folders only.
//   node --test scripts/release-readiness.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { benchmarkGate, applyWaivers, decide, review, renderMarkdown, notOfRecord, candidateFor,
  figureGate, parseFigures, compareWithRecord, parseGoals, goalRecord, judgeGoal, GOALS_FILE, VERSION, METRIC, MAX_SUMMARY_BYTES, capMarkdown, listCapped,
  isAgent, requireEvidence, gateDiff } from "./release-readiness.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "release-readiness.mjs");
const row = (o = {}) => ({ suite: "lighthouse/index", metric: "performance", value: 90, direction: "higher",
  tolerance: 2, version: "1.1.0", date: "2026-11-01", method: "lighthouse 12, mobile, median of 3", ...o });
const cand = (value, o = {}) => ({ tag: "site-v1.2.0-rc.1", version: "1.2.0-rc.1", date: "2026-11-12", method: "same",
  results: [{ suite: "lighthouse/index", metric: "performance", value, ...o }] });
const one = (record, candidate) => {
  const c = benchmarkGate({ records: [record] }, candidate);
  assert.equal(c.length, 1);
  return c[0];
};

// --- the benchmark gate: pass, drop, within tolerance, missing record, waived ---

test("pass: candidate equal to or better than the record", () => {
  assert.equal(one(row(), cand(90)).status, "pass");
  const better = one(row(), cand(95));
  assert.equal(better.status, "pass");
  assert.match(better.summary, /improved by 5/);
});

test("drop beyond tolerance fails", () => {
  const c = one(row(), cand(87));
  assert.equal(c.status, "fail");
  assert.equal(c.id, "benchmark:lighthouse/index:performance");
  assert.match(c.summary, /dropped 3, beyond tolerance 2/);
  assert.ok(c.evidence.some((e) => /record 90 \(1\.1\.0, 2026-11-01/.test(e)));
});

test("drop within tolerance passes, and says so", () => {
  const c = one(row(), cand(88));
  assert.equal(c.status, "pass");
  assert.match(c.summary, /dropped 2, within tolerance 2/);
});

test("direction lower: a rise is a drop", () => {
  const r = row({ metric: "page-weight-kb", value: 500, direction: "lower", tolerance: 10 });
  const c = (v) => ({ results: [{ suite: r.suite, metric: r.metric, value: v }] });
  assert.equal(one(r, c(505)).status, "pass");
  assert.equal(one(r, c(511)).status, "fail");
  assert.equal(one(r, c(400)).status, "pass");
});

test("tolerance defaults to 0: any drop fails", () => {
  const r = row(); delete r.tolerance;
  assert.equal(one(r, cand(89.9)).status, "fail");
});

test("missing figure of record abstains, never passes", () => {
  const noRec = one({ suite: "lighthouse/index", metric: "performance", status: "no record yet", direction: "higher" }, cand(99));
  assert.equal(noRec.status, "abstain");
  assert.match(noRec.summary, /no figure of record yet/);
  for (const k of ["version", "date", "method", "value"]) {
    const r = row(); delete r[k];
    assert.equal(one(r, cand(99)).status, "abstain", `no ${k}`);
  }
  assert.equal(one(row({ direction: "up" }), cand(99)).status, "abstain");
  // a candidate result with no row at all
  const extra = benchmarkGate({ records: [] }, cand(99));
  assert.deepEqual(extra.map((c) => c.status), ["abstain"]);
  // nothing at all
  assert.equal(benchmarkGate({ records: [] }, null)[0].status, "abstain");
});

test("a metric of record not measured on the candidate fails", () => {
  assert.equal(one(row(), null).status, "fail");
  assert.equal(one(row(), { results: [] }).status, "fail");
  assert.equal(one(row(), cand("n/a")).status, "fail");
});

test("waived: one named failure becomes waived, with who, why and until in the evidence", () => {
  const checks = benchmarkGate({ records: [row(), row({ metric: "seo" })] },
    { results: [{ suite: "lighthouse/index", metric: "performance", value: 80 }, { suite: "lighthouse/index", metric: "seo", value: 70 }] });
  const rep = applyWaivers(checks, { waivers: [{ check: "benchmark:lighthouse/index:performance", who: "owner", why: "new hero video, tracked in #12", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] }, { today: "2026-11-12" });
  assert.equal(rep[0].state, "applied");
  assert.equal(checks[0].status, "waived");
  assert.ok(checks[0].evidence.at(-1).includes("WAIVED by owner until 2026-12-01"));
  assert.equal(checks[1].status, "fail", "only the named check is waived");
  assert.equal(decide(checks).verdict, "NO-GO");
  applyWaivers(checks, { waivers: [{ check: "benchmark:lighthouse/index:seo", who: "owner", why: "x", until: "2026-11-12", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] }, { today: "2026-11-12" });
  assert.equal(decide(checks).verdict, "GO");
});

test("a waiver never applies silently: invalid, expired, other tag, unused", () => {
  const fresh = () => benchmarkGate({ records: [row()] }, cand(80));
  const base = { check: "benchmark:lighthouse/index:performance", who: "owner", why: "because", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" };
  for (const [w, note] of [
    [{ ...base, who: "" }, /invalid: no who/],
    [{ ...base, why: undefined }, /invalid: no why/],
    [{ ...base, until: "soon" }, /not YYYY-MM-DD/],
    [{ ...base, until: "2026-11-11" }, /expired/],
    [{ ...base, tag: "site-v1.0.0-rc.1" }, /for site-v1\.0\.0-rc\.1/],
  ]) {
    const c = fresh();
    const rep = applyWaivers(c, { waivers: [w] }, { today: "2026-11-12", tag: "site-v1.2.0-rc.1" });
    assert.equal(c[0].status, "fail");
    assert.equal(rep[0].state, "ignored");
    assert.match(rep[0].note, note);
  }
  // a waiver limited to a tag never applies to a review run without --tag
  const notag = fresh();
  assert.equal(applyWaivers(notag, { waivers: [{ ...base, tag: "site-v1.2.0-rc.1" }] }, { today: "2026-11-12" })[0].state, "ignored");
  assert.equal(notag[0].status, "fail");
  const passing = benchmarkGate({ records: [row()] }, cand(95));
  assert.equal(applyWaivers(passing, { waivers: [base] }, { today: "2026-11-12" })[0].state, "unused");
  assert.equal(passing[0].status, "pass");
});

// --- B1: the results must be this candidate's ---

test("candidateFor: results tied by tag or sha pass; another candidate's fail; no tag or sha abstains", () => {
  const c = cand(95);
  assert.equal(candidateFor(c, { tag: "site-v1.2.0-rc.1" }).check.status, "pass");
  assert.equal(candidateFor({ ...c, tag: undefined, sha: "abcdef1234567" }, { tag: "x", sha: "abcdef1234567890" }).check.status, "pass");
  const stale = candidateFor({ ...c, tag: "site-v1.1.0-rc.2" }, { tag: "site-v1.2.0-rc.1", sha: "1234567890" });
  assert.equal(stale.check.status, "fail");
  assert.equal(stale.results, null);
  assert.match(stale.check.evidence[0], /names tag site-v1\.1\.0-rc\.2; under review: tag site-v1\.2\.0-rc\.1/);
  assert.equal(candidateFor({ ...c, tag: undefined }, { tag: "site-v1.2.0-rc.1" }).check.status, "fail", "a file naming neither");
  assert.equal(candidateFor({ ...c, tag: undefined, sha: "abc" }, { sha: "abcdef0" }).check.status, "fail", "short sha never matches");
  assert.equal(candidateFor(c, {}).check.status, "abstain");
  assert.deepEqual(candidateFor(null, { tag: "t" }), { check: null, results: null });
});

function rrRepo(cfg, files) {
  const d = mkdtempSync(join(tmpdir(), "rr-"));
  writeFileSync(join(d, ".release-readiness.json"), JSON.stringify(cfg));
  for (const [p, c] of Object.entries(files)) writeFileSync(join(d, p), JSON.stringify(c));
  return d;
}

test("B1: stale results (last release's numbers, better than the record) are NO-GO, not a pass", () => {
  const cfg = { ci: [{ id: "ok", run: "true" }], benchmark: { record: "for.json", candidate: "cand.json" } };
  const d = rrRepo(cfg, { "for.json": { records: [row()] }, "cand.json": { ...cand(95), tag: "site-v1.1.0-rc.3" } });
  try {
    const v = review(cfg, { root: d, tag: "site-v1.2.0-rc.1", sha: "0123456789abcdef", today: "2026-11-12" });
    assert.equal(v.verdict, "NO-GO");
    assert.equal(v.checks.find((c) => c.id === "benchmark:results").status, "fail");
    const row1 = v.checks.find((c) => c.id === "benchmark:lighthouse/index:performance");
    assert.equal(row1.status, "fail");
    assert.match(row1.summary, /not measured on the candidate/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("B1: results of this candidate are compared; a benchmark run that does not pass leaves the file unread", () => {
  const cfg = (run) => ({ ci: [{ id: "ok", run: "true" }], benchmark: { record: "for.json", candidate: "cand.json", run } });
  const files = { "for.json": { records: [row()] }, "cand.json": cand(95) };
  const opts = { tag: "site-v1.2.0-rc.1", sha: "0123456789abcdef", today: "2026-11-12" };
  for (const [run, want, runStatus] of [[undefined, "GO", null], ["true", "GO", "pass"], ["exit 3", "NO-GO", "abstain"], ["exit 1", "NO-GO", "fail"]]) {
    const d = rrRepo(cfg(run), files);
    try {
      const v = review(cfg(run), { root: d, ...opts });
      assert.equal(v.verdict, want, `run ${run}`);
      if (runStatus) assert.equal(v.checks.find((c) => c.id === "benchmark:run").status, runStatus);
      const r = v.checks.find((c) => c.id === "benchmark:lighthouse/index:performance");
      assert.equal(r.status, want === "GO" ? "pass" : "fail", `row on run ${run}`);
      if (want === "NO-GO") assert.equal(v.checks.find((c) => c.id === "benchmark:results"), undefined, "file not read");
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

// --- B2: a metric measured twice is an error ---

test("B2: duplicate candidate rows fail, with every value shown", () => {
  const dup = { results: [{ suite: "lighthouse/index", metric: "performance", value: 50 }, { suite: "lighthouse/index", metric: "performance", value: 95 }] };
  const c = one(row(), dup);
  assert.equal(c.status, "fail");
  assert.match(c.summary, /measured 2 times: 50, 95/);
  const noRec = benchmarkGate({ records: [] }, dup);
  assert.equal(noRec.length, 1);
  assert.equal(noRec[0].status, "fail");
  assert.equal(decide([{ id: "ci:a", status: "pass", summary: "", evidence: [] }, c]).verdict, "NO-GO");
});

// --- the verdict ---

test("decide: fail is NO-GO; abstain alone is not GO unless something passed; required abstain blocks", () => {
  const p = { id: "ci:checks", group: "ci", status: "pass", summary: "", evidence: [] };
  const a = { id: "benchmark:x:y", group: "benchmark", status: "abstain", summary: "no figure of record yet", evidence: [] };
  assert.equal(decide([p, a], ["ci"]).verdict, "GO");
  assert.equal(decide([a], []).verdict, "NO-GO");
  const r = decide([p, a], ["ci", "benchmark"]);
  assert.equal(r.verdict, "NO-GO");
  assert.match(r.reasons.join(), /required check benchmark abstained/);
  // the gate's inputs alone never satisfy a required benchmark
  const tie = { id: "benchmark:results", group: "benchmark-input", status: "pass", summary: "", evidence: [] };
  assert.equal(decide([p, tie, a], ["benchmark"]).verdict, "NO-GO");
});

test("notOfRecord accepts a complete row", () => assert.equal(notOfRecord(row()), null));

// --- the whole review, end to end through the CLI ---

function repo(files) {
  const d = mkdtempSync(join(tmpdir(), "rr-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(d, p)), { recursive: true });
    writeFileSync(join(d, p), typeof c === "string" ? c : JSON.stringify(c));
  }
  return d;
}
const cli = (d, ...args) => spawnSync(process.execPath, [SCRIPT, "--config", join(d, ".release-readiness.json"), "--today", "2026-11-12", ...args], { encoding: "utf8" });

test("CLI: GO with abstentions, verdict files written; hooks not configured abstain", () => {
  const d = repo({
    ".release-readiness.json": { ci: [{ id: "checks", run: "echo all good" }], benchmark: { record: "for.json", candidate: "cand.json" } },
    "for.json": { records: [row({ status: "no record yet", value: undefined })] },
  });
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abc", "--out-json", join(d, "v.json"), "--out-md", join(d, "v.md"));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /## Release readiness: GO/);
    assert.match(r.stdout, /`security` \| \*\*abstain\*\*/);
    assert.match(r.stdout, /`customer` \| \*\*abstain\*\*/);
    assert.match(r.stdout, /benchmark:lighthouse\/index:performance` \| \*\*abstain\*\*: no figure of record yet/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("CLI: a CI failure and a benchmark drop are NO-GO, each with a task; a hook exit 3 abstains", () => {
  const d = repo({
    ".release-readiness.json": {
      ci: [{ id: "checks", run: "echo broken >&2; exit 1" }],
      benchmark: { record: "for.json", candidate: "cand.json" },
      hooks: { security: { run: "echo scanner not reachable; exit 3" }, "sbom-licence": { run: "true" } },
      waivers: "waivers.json",
    },
    "for.json": { records: [row()] },
    "cand.json": cand(80),
    "waivers.json": { waivers: [] },
  });
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abc", "--out-json", join(d, "v.json"));
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    assert.equal(v.verdict, "NO-GO");
    assert.deepEqual(v.tasks.map((t) => t.check).sort(), ["benchmark:lighthouse/index:performance", "ci:checks"]);
    assert.match(v.tasks[0].title, /failed on site-v1\.2\.0-rc\.1/);
    assert.equal(v.checks.find((c) => c.id === "security").status, "abstain");
    assert.equal(v.checks.find((c) => c.id === "sbom-licence").status, "pass");
    assert.ok(v.checks.find((c) => c.id === "ci:checks").evidence.some((e) => e.includes("broken")));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("CLI: missing config is a usage error (exit 2)", () => {
  const d = mkdtempSync(join(tmpdir(), "rr-"));
  try { assert.equal(cli(d).status, 2); } finally { rmSync(d, { recursive: true, force: true }); }
});

test("renderMarkdown escapes table pipes and keeps the markers", () => {
  const md = renderMarkdown({ verdict: "GO", reasons: [], tag: "t", sha: "s", at: "now", tool: "0", waivers: [], tasks: [],
    checks: [{ id: "ci:a", status: "pass", summary: "a | b", evidence: ["x|y"] }] });
  assert.match(md, /^<!-- release-readiness:start -->/);
  assert.match(md, /a \\\| b/);
  assert.match(md, /<!-- release-readiness:end -->\n$/);
});

// --- 0.3.0: figures of record a check reports (a count with a direction, or a pass/fail) ---

const fig = (o = {}) => ({ check: "customer:a11y", metric: "open_must_fix", kind: "count", value: 2, direction: "lower",
  tolerance: 0, version: "0.3.0", date: "2026-11-12", method: "a11y-recheck, dist/", ...o });
const ran = (figures, o = {}) => ({ id: "customer:a11y", group: "customer", status: "fail", summary: "exit 1", evidence: [], figures, ...o });
const fone = (row, checks) => {
  const c = figureGate({ records: [row] }, checks);
  assert.equal(c.length, 1, JSON.stringify(c));
  return c[0];
};

test("version is 0.4.4", () => assert.equal(VERSION, "0.4.4"));

test("parseFigures: one line per figure; pass/fail, counts, raw text; other lines ignored", () => {
  const p = parseFigures("checking 11 pages\nrelease-readiness:figure open_must_fix 2\n  release-readiness:figure keyboard pass  \nrelease-readiness:figure x n/a\nrelease-readiness:figure open_must_fix 3\nnot release-readiness:figure y 1");
  assert.deepEqual({ ...p.figures }, { open_must_fix: [2, 3], keyboard: ["pass"], x: ["n/a"] });
  assert.deepEqual(p.invalid, []);
  assert.deepEqual({ ...parseFigures("").figures }, {});
});

test("count figure, lower is better, tolerance 0: same passes, one more fails, fewer passes", () => {
  const same = fone(fig(), [ran({ open_must_fix: [2] })]);
  assert.equal(same.id, "figure:customer:a11y:open_must_fix");
  assert.equal(same.group, "figure");
  assert.equal(same.status, "pass");
  assert.match(same.summary, /same as the figure of record \(2\)/);
  const worse = fone(fig(), [ran({ open_must_fix: [3] })]);
  assert.equal(worse.status, "fail");
  assert.match(worse.summary, /worse by 1 \(2 → 3\), beyond tolerance 0/);
  assert.ok(worse.evidence[0].includes("record 2 (0.3.0, 2026-11-12, a11y-recheck, dist/); count, lower is better, tolerance 0"));
  const better = fone(fig(), [ran({ open_must_fix: [0] })]);
  assert.equal(better.status, "pass");
  assert.match(better.summary, /better by 2 \(2 → 0/);
  assert.equal(fone(fig({ tolerance: 1 }), [ran({ open_must_fix: [3] })]).status, "pass", "within tolerance");
  assert.equal(fone(fig({ direction: "higher", value: 10 }), [ran({ open_must_fix: [9] })]).status, "fail", "higher is better");
  assert.equal(fone(fig(), [ran({ open_must_fix: [2.5] })]).status, "fail", "not a count");
  assert.equal(fone(fig(), [ran({ open_must_fix: ["many"] })]).status, "fail", "not a number");
});

test("pass/fail figure: a pass of record that fails is a regression; fail stays fail is not", () => {
  const pf = (value) => fig({ metric: "keyboard", kind: "passfail", value, direction: undefined, tolerance: undefined });
  const r = fone(pf("pass"), [ran({ keyboard: ["fail"] })]);
  assert.equal(r.status, "fail");
  assert.match(r.summary, /regressed: pass of record, fail on the candidate/);
  assert.equal(fone(pf("pass"), [ran({ keyboard: ["pass"] })]).status, "pass");
  assert.equal(fone(pf("fail"), [ran({ keyboard: ["fail"] })]).status, "pass");
  assert.match(fone(pf(false), [ran({ keyboard: ["pass"] })]).summary, /improved/);
  assert.equal(fone(pf("pass"), [ran({ keyboard: [1] })]).status, "fail", "not pass or fail");
  assert.equal(notOfRecord(pf("pass")), null, "no direction needed");
  assert.match(notOfRecord(pf("maybe")), /passfail value must be "pass" or "fail"/);
});

test("figure rows not of record abstain; a reported figure with no row abstains so a person can record it", () => {
  assert.equal(fone(fig({ status: "no record yet", value: undefined }), [ran({ open_must_fix: [2] })]).status, "abstain");
  assert.match(notOfRecord(fig({ value: 2.5 })), /a count must be a whole number/);
  assert.match(notOfRecord(fig({ kind: "percent" })), /kind must be one of number, count, passfail/);
  for (const k of ["version", "date", "method"]) assert.equal(fone(fig({ [k]: "" }), [ran({ open_must_fix: [2] })]).status, "abstain", `no ${k}`);
  const extra = figureGate({ records: [] }, [ran({ open_must_fix: [2] })]);
  assert.deepEqual(extra.map((c) => [c.id, c.status, c.summary]), [["figure:customer:a11y:open_must_fix", "abstain", "no figure of record yet"]]);
});

test("figure of record not reported fails; check abstained is still compared; check not run fails; reported twice fails", () => {
  const silent = fone(fig(), [ran(undefined, { status: "pass", summary: "passed" })]);
  assert.equal(silent.status, "fail");
  assert.match(silent.summary, /not reported by customer:a11y/);
  assert.equal(fone(fig(), [ran({ open_must_fix: [9] }, { status: "abstain", summary: "needs Docker" })]).status, "fail", "0.3.1: compared anyway");
  const missing = fone(fig(), [{ id: "customer", group: "customer", status: "abstain", summary: "no customer skills configured", evidence: [] }]);
  assert.equal(missing.status, "fail");
  assert.match(missing.summary, /did not run in this review/);
  const twice = fone(fig(), [ran({ open_must_fix: [2, 3] })]);
  assert.equal(twice.status, "fail");
  assert.match(twice.summary, /reported 2 times: 2, 3/);
  // --only without the check's group: the row is not judged at all
  assert.deepEqual(figureGate({ records: [fig()] }, [], { wanted: (g) => g === "benchmark" }), []);
});

test("backward compatible: rows naming a check stay out of the benchmark gate; kind defaults to number", () => {
  assert.deepEqual(benchmarkGate({ records: [fig()] }, null).map((c) => c.id), ["benchmark"]);
  assert.equal(notOfRecord({ ...row(), kind: "number" }), null);
  assert.deepEqual(compareWithRecord(row(), 87), { status: "fail", summary: "dropped 3, beyond tolerance 2" });
  // a benchmark row may itself be a count
  const cnt = one(row({ metric: "broken-links", kind: "count", value: 0, direction: "lower", tolerance: 0 }),
    { results: [{ suite: "lighthouse/index", metric: "broken-links", value: 1 }] });
  assert.equal(cnt.status, "fail");
  assert.match(cnt.summary, /worse by 1 \(0 → 1\)/);
});

const hookRepo = (print, exit, extra = {}) => repo({
  ".release-readiness.json": { ci: [{ id: "checks", run: "true" }], benchmark: { record: "for.json" },
    hooks: { customer: [{ id: "a11y", run: `echo "11 pages"; ${print}; exit ${exit}` }] }, waivers: "waivers.json" },
  "for.json": { records: [fig()] },
  "waivers.json": { waivers: [{ check: "customer:a11y", who: "owner", why: "two known findings, tracked in #31", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] },
  ...extra,
});

test("CLI: a hook that reports the same count as the record, waived, is GO; one more is NO-GO even with the hook waived", () => {
  for (const [n, want, status] of [[2, 0, "pass"], [3, 1, "fail"]]) {
    const d = hookRepo(`echo "release-readiness:figure open_must_fix ${n}"`, 1);
    try {
      const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
      assert.equal(r.status, want, r.stdout + r.stderr);
      const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
      assert.equal(v.checks.find((c) => c.id === "customer:a11y").status, "waived");
      const f = v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix");
      assert.equal(f.status, status);
      if (status === "fail") assert.deepEqual(v.tasks.map((t) => t.check), ["figure:customer:a11y:open_must_fix"]);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

test("CLI: the candidate cannot record its own figure: a command that rewrites the record is NO-GO, compared with the old record", () => {
  const rewritten = JSON.stringify({ records: [fig({ value: 5 })] }).replace(/"/g, '\\"');
  const d = hookRepo(`echo "${rewritten}" > for.json; echo "release-readiness:figure open_must_fix 5"`, 0);
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    const guard = v.checks.find((c) => c.id === "figure-of-record");
    assert.equal(guard.status, "fail");
    assert.match(guard.evidence[0], /rewritten by a command of the candidate/);
    const f = v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix");
    assert.equal(f.status, "fail", "compared with the record as it was before the run (2), not the rewritten 5");
    assert.match(f.summary, /worse by 3 \(2 → 5\)/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("review never writes the figure-of-record file", () => {
  const d = hookRepo('echo "release-readiness:figure open_must_fix 0"', 0);
  try {
    const before = spawnSync("cat", [join(d, "for.json")], { encoding: "utf8" }).stdout;
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1");
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /better by 2 \(2 → 0; the figure of record is not changed by this review\)/);
    assert.equal(spawnSync("cat", [join(d, "for.json")], { encoding: "utf8" }).stdout, before);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

// --- 0.3.0 review round 2 ---

const PROTO = ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"];

test("R2: prototype-key and invalid metric names never crash; they are listed as invalid", () => {
  for (const name of ["__proto__", "toString", "hasOwnProperty", "valueOf", "Open", "open-must", "a".repeat(65), "1x", "émoji"]) {
    const p = parseFigures(`release-readiness:figure ${name} 1`);
    assert.deepEqual(p.invalid, [name.slice(0, 80)], name);
    assert.deepEqual(Object.keys(p.figures), [], name);
  }
  for (const name of ["constructor", "prototype"]) {
    // valid by the pattern, so kept as an own key, never an inherited one
    const p = parseFigures(`release-readiness:figure ${name} 1\nrelease-readiness:figure ${name} 2`);
    assert.deepEqual(p.figures[name], [1, 2], name);
    assert.equal(Object.getPrototypeOf(p.figures), null);
  }
  assert.ok(METRIC.test("open_must_fix") && !METRIC.test("open.must"));
});

test("R2: a row of record named like a prototype key, not reported, fails as not reported (not an inherited value)", () => {
  const c = fone(fig({ metric: "constructor" }), [ran(parseFigures("").figures, { status: "pass", summary: "passed" })]);
  assert.equal(c.status, "fail");
  assert.match(c.summary, /not reported by customer:a11y/);
  for (const metric of ["__proto__", "toString", "hasOwnProperty"])
    assert.match(fone(fig({ metric }), [ran(parseFigures("").figures)]).summary, /is not a figure name/, metric);
});

test("R2: CLI gives a verdict, not a crash, on prototype-key figure lines; the check fails", () => {
  for (const name of PROTO) {
    const d = hookRepo(`echo "release-readiness:figure ${name} 1"; echo "release-readiness:figure open_must_fix 2"`, 0);
    try {
      const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
      assert.ok(r.status === 0 || r.status === 1, `${name}: exit ${r.status} ${r.stderr}`);
      assert.match(r.stdout, /## Release readiness:/, name);
      const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
      assert.equal(v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix").status, "pass", name);
      if (name === "__proto__") {
        const h = v.checks.find((c) => c.id === "customer:a11y");
        assert.ok(h.evidence.some((e) => /must match/.test(e)), JSON.stringify(h));
      }
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
  const d = hookRepo('echo "release-readiness:figure Open_Must 1"', 0);
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    const h = v.checks.find((c) => c.id === "customer:a11y");
    assert.equal(h.status, "waived", "exit 0, failed by the invalid name (the fixture's person waiver then applies)");
    assert.match(h.summary, /invalid figure name: "Open_Must"/);
    assert.equal(v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix").status, "fail");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("R2: a command that writes a waiver for its own regression is NO-GO; nothing it wrote is applied", () => {
  const forged = JSON.stringify({ waivers: ["figure:customer:a11y:open_must_fix", "customer:a11y", "figure-of-record", "waivers"]
    .map((check) => ({ check, who: "candidate", why: "self", until: "2026-12-31", answer: "https://example.invalid/answers/1", confirm: "ci:later" })) }).replace(/"/g, '\\"');
  for (const pre of [undefined, { waivers: [] }]) {
    const extra = pre ? { "waivers.json": pre } : {};
    const d = hookRepo(`echo "${forged}" > waivers.json; echo "release-readiness:figure open_must_fix 5"`, 1, extra);
    if (!pre) rmSync(join(d, "waivers.json"));
    try {
      const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
      assert.equal(r.status, 1, r.stdout + r.stderr);
      const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
      const w = v.checks.find((c) => c.id === "waivers");
      assert.equal(w.status, "fail");
      assert.match(w.evidence[0], pre ? /rewritten/ : /created/);
      assert.equal(v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix").status, "fail");
      assert.equal(v.checks.find((c) => c.id === "customer:a11y").status, "fail");
      assert.ok(!v.checks.some((c) => c.status === "waived"));
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

test("R2: the pre-run waiver copy is applied even if a command deletes the file; integrity checks are never waivable", () => {
  const d = hookRepo('rm waivers.json; echo "release-readiness:figure open_must_fix 2"', 1);
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
    assert.equal(r.status, 1);
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    assert.equal(v.checks.find((c) => c.id === "customer:a11y").status, "waived", "the pre-run waiver");
    assert.match(v.checks.find((c) => c.id === "waivers").evidence[0], /deleted/);
  } finally { rmSync(d, { recursive: true, force: true }); }
  const checks = [{ id: "figure-of-record", status: "fail", summary: "", evidence: [] }, { id: "waivers", status: "fail", summary: "", evidence: [] }];
  const rep = applyWaivers(checks, { waivers: checks.map((c) => ({ check: c.id, who: "owner", why: "x", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" })) }, { today: "2026-11-12" });
  assert.deepEqual(rep.map((x) => [x.state, x.note]), [["ignored", "an integrity check cannot be waived"], ["ignored", "an integrity check cannot be waived"]]);
  assert.deepEqual(checks.map((c) => c.status), ["fail", "fail"]);
});

test("R2: a person's waiver for a figure regression, present before the run with who, why and until, applies", () => {
  const d = hookRepo('echo "release-readiness:figure open_must_fix 3"', 1, { "waivers.json": { waivers: [
    { check: "customer:a11y", who: "owner", why: "known findings, #31", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" },
    { check: "figure:customer:a11y:open_must_fix", who: "owner", why: "third finding, #32", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] } });
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    assert.equal(v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix").status, "waived");
    assert.equal(v.checks.find((c) => c.id === "waivers"), undefined, "unchanged file, no integrity failure listed");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

// --- 0.3.1: the three non-blocking points of the 0.3.0 review ---

test("0.3.1: a check with a figure of record cannot abstain its way out (figureGate)", () => {
  const abst = { status: "abstain", summary: "the hook abstained" };
  const regressed = fone(fig(), [ran({ open_must_fix: [3] }, abst)]);
  assert.equal(regressed.status, "fail", "printed a regressed figure, then abstained: compared anyway");
  assert.match(regressed.summary, /worse by 1 \(2 → 3\)/);
  assert.ok(regressed.evidence.some((e) => /customer:a11y on the candidate \(abstain\): 3/.test(e)));
  assert.equal(fone(fig(), [ran({ open_must_fix: [2] }, abst)]).status, "pass", "printed the same figure, then abstained");
  const silent = fone(fig(), [ran(undefined, abst)]);
  assert.equal(silent.status, "fail");
  assert.match(silent.summary, /not reported by customer:a11y \(it abstained\)/);
  assert.ok(silent.evidence.some((e) => /cannot abstain its way out/.test(e)));
  // a row not of record still abstains, whatever the check did
  assert.equal(fone(fig({ status: "no record yet" }), [ran(undefined, abst)]).status, "abstain");
});

test("0.3.1 CLI: a hook that prints a regressed figure and exits 3 is NO-GO, not GO", () => {
  const d = hookRepo('echo "release-readiness:figure open_must_fix 3"', 3);
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    assert.equal(v.checks.find((c) => c.id === "customer:a11y").status, "abstain");
    const f = v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix");
    assert.equal(f.status, "fail");
    assert.deepEqual(v.tasks.map((t) => t.check), ["figure:customer:a11y:open_must_fix"]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("0.3.1 CLI: a hook that abstains without its figure is NO-GO; a pre-run waiver for that figure makes it GO", () => {
  for (const [waiveFigure, want, status] of [[false, 1, "fail"], [true, 0, "waived"]]) {
    const extra = waiveFigure ? { "waivers.json": { waivers: [
      { check: "figure:customer:a11y:open_must_fix", who: "owner", why: "no preview this week, #40", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] } } : {};
    const d = hookRepo('echo "no preview, cannot judge"', 3, extra);
    try {
      const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
      assert.equal(r.status, want, r.stdout + r.stderr);
      const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
      const f = v.checks.find((c) => c.id === "figure:customer:a11y:open_must_fix");
      assert.equal(f.status, status);
      assert.match(f.summary, /not reported by customer:a11y \(it abstained\)/);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

test("0.3.1: the invalid figure-name list in a summary is capped at 20 with \"and N more\"", () => {
  const names = Array.from({ length: 25 }, (_, i) => `Bad${i}`);
  const d = hookRepo(names.map((n) => `echo "release-readiness:figure ${n} 1"`).join("; ") + '; echo "release-readiness:figure open_must_fix 2"', 0);
  try {
    const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"));
    const v = JSON.parse(spawnSync("cat", [join(d, "v.json")], { encoding: "utf8" }).stdout);
    const h = v.checks.find((c) => c.id === "customer:a11y");
    assert.match(h.summary, /^invalid figure names: "Bad0", .*"Bad19" and 5 more$/, h.summary);
    assert.ok(!h.summary.includes("Bad20"), h.summary);
    assert.ok(r.status === 1 || r.status === 0);
  } finally { rmSync(d, { recursive: true, force: true }); }
  assert.equal(listCapped(["a", "b"]), "a, b");
  assert.equal(listCapped(["a", "b", "c"], 2), "a, b and 1 more");
});

test("0.3.1: the verdict Markdown written to the notes is at most 60 KB, with a truncation marker and both markers", () => {
  const big = "x".repeat(300);
  const checks = Array.from({ length: 400 }, (_, i) => ({ id: `ci:c${i}`, group: "ci", status: "fail", summary: `exit 1 é ${i}`,
    evidence: Array.from({ length: 15 }, () => big) }));
  const v = { tool: VERSION, verdict: "NO-GO", reasons: checks.map((c) => `${c.id} failed: ${c.summary}`), tag: "t", sha: "s", at: "2026-11-12T00:00:00Z",
    checks, waivers: [], tasks: checks.map((c) => ({ check: c.id, title: `release-readiness: ${c.id} failed on t`, body: c.evidence.join("\n"), labels: [] })) };
  const md = renderMarkdown(v);
  assert.equal(MAX_SUMMARY_BYTES, 60 * 1024);
  assert.ok(Buffer.byteLength(md, "utf8") <= MAX_SUMMARY_BYTES, `${Buffer.byteLength(md, "utf8")} bytes`);
  assert.match(md, /^<!-- release-readiness:start -->\n## Release readiness: NO-GO/);
  assert.match(md, /\*\*Truncated:\*\* \d+ bytes of this verdict are not shown/);
  assert.match(md, /<!-- release-readiness:end -->\n$/);
  assert.equal((md.match(/<details>/g) || []).length, (md.match(/<\/details>/g) || []).length, "every <details> closed");
  // one giant line is cut too, never left whole
  const one = capMarkdown(["<!-- release-readiness:start -->", "y".repeat(200000), "<!-- release-readiness:end -->"], 1000);
  assert.ok(Buffer.byteLength(one, "utf8") <= 1000, `${Buffer.byteLength(one, "utf8")}`);
  assert.match(one, /<!-- release-readiness:end -->\n$/);
  // a small verdict is unchanged
  const small = { ...v, checks: checks.slice(0, 1), reasons: v.reasons.slice(0, 1), tasks: [] };
  assert.ok(!renderMarkdown(small).includes("Truncated"));
});

test("0.3.1: review() without a date judges waivers against today, so an expired waiver is not applied", () => {
  const files = { ".release-readiness.json": { ci: [{ id: "ok", run: "true" }, { id: "bad", run: "false" }], waivers: "waivers.json" },
    "waivers.json": { waivers: [{ check: "ci:bad", who: "owner", why: "old", until: "2000-01-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] } };
  const d = repo(files);
  try {
    const cfg = JSON.parse(spawnSync("cat", [join(d, ".release-readiness.json")], { encoding: "utf8" }).stdout);
    const v = review(cfg, { root: d });
    assert.equal(v.verdict, "NO-GO");
    assert.equal(v.checks.find((c) => c.id === "ci:bad").status, "fail");
    assert.deepEqual(v.waivers.map((w) => [w.state, w.note]), [["ignored", "expired on 2000-01-01"]]);
    // an explicit date is still honoured (tests), and the review's own `at` sets the default
    assert.equal(review(cfg, { root: d, today: "1999-12-31" }).verdict, "GO");
    assert.equal(review(cfg, { root: d, at: new Date("1999-06-01T00:00:00Z") }).verdict, "GO");
    assert.throws(() => review(cfg, { root: d, today: "12/11/2026" }), /YYYY-MM-DD/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

// --- 0.3.2: benchmark goals (.loop/benchmarks.json): warn by default, block only on a number of record ---

const goal = (o = {}) => ({ suite: "cwe-bench-java", metric: "tp_rate", goal: 80, comparison: ">=",
  run: 'echo "release-readiness:figure tp_rate 72"', ...o });
const goalRow = (o = {}) => ({ check: "goal:cwe-bench-java", metric: "tp_rate", value: 75, direction: "higher", tolerance: 5,
  version: "4.31.0", date: "2026-11-08", method: "CWE-Bench-Java, static, 120 CVEs", ...o });
const goalRepo = (goals, records = [], extra = {}) => repo({
  ".release-readiness.json": { ci: [{ id: "checks", run: "true" }], benchmark: { record: "for.json" }, waivers: "waivers.json" },
  "for.json": { records },
  "waivers.json": { waivers: [] },
  [GOALS_FILE]: typeof goals === "string" ? goals : { goals },
  ...extra,
});
const reviewOf = (d) => {
  const r = cli(d, "--tag", "site-v1.2.0-rc.1", "--sha", "abcdef1", "--out-json", join(d, "v.json"), "--out-md", join(d, "v.md"));
  return { r, v: JSON.parse(readFileSync(join(d, "v.json"), "utf8")), md: readFileSync(join(d, "v.md"), "utf8") };
};
const goalCheck = (v, suite = "cwe-bench-java") => v.checks.find((c) => c.id === `goal:${suite}`);

test("0.3.2 goals: met is pass; ≤ goals compare the other way; ≥ and ≤ spellings both accepted", () => {
  const { goals, problems } = parseGoals(JSON.stringify({ goals: [goal({ comparison: "≥" }), goal({ suite: "fpr", metric: "fpr", comparison: "≤", goal: 5 })] }));
  assert.deepEqual(problems, []);
  assert.deepEqual(goals.map((g) => [g.comparison, g.mode]), [[">=", "warn"], ["<=", "warn"]]);
  const c = (v, m = "tp_rate") => ({ id: "goal:x", status: "pass", summary: "passed", evidence: [], figures: { [m]: [v] } });
  assert.equal(judgeGoal(goals[0], c(80), {}).status, "pass");
  assert.equal(judgeGoal(goals[0], c(79.5), {}).status, "warn");
  assert.equal(judgeGoal(goals[1], c(5, "fpr"), {}).status, "pass");
  assert.equal(judgeGoal(goals[1], c(6, "fpr"), {}).status, "warn");
});

test("0.3.2 CLI warn: below goal is shown in the verdict and the notes, and the verdict stays GO", () => {
  const d = goalRepo([goal()]);
  try {
    const { r, v, md } = reviewOf(d);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(v.verdict, "GO");
    const g = goalCheck(v);
    assert.equal(g.status, "warn");
    assert.match(g.summary, /below goal: 72, goal ≥ 80 \(warns, does not block\)/);
    assert.deepEqual(v.warnings, [`goal:cwe-bench-java: ${g.summary}`]);
    assert.match(md, /1 warn/);
    assert.match(md, /\*\*Warnings\*\* \(1;/);
    assert.match(md, /- goal:cwe-bench-java: below goal: 72/);
    assert.equal(v.tasks.length, 0, "a warning is not a task");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("0.3.2 CLI block with a number of record: below goal fails (NO-GO, a task); met passes", () => {
  for (const [printed, exit, status] of [[72, 1, "fail"], [81, 0, "pass"]]) {
    const d = goalRepo([goal({ mode: "block", run: `echo "release-readiness:figure tp_rate ${printed}"` })], [goalRow()]);
    try {
      const { r, v } = reviewOf(d);
      assert.equal(r.status, exit, r.stdout + r.stderr);
      const g = goalCheck(v);
      assert.equal(g.status, status);
      assert.match(g.evidence[0], /mode block \(number of record 75, 4\.31\.0, 2026-11-08, CWE-Bench-Java/);
      if (status === "fail") {
        assert.match(g.summary, /^below goal: 72, goal ≥ 80$/);
        assert.ok(v.tasks.some((t) => t.check === "goal:cwe-bench-java"));
        assert.ok(v.reasons.some((x) => x.startsWith("goal:cwe-bench-java failed")));
      }
      // the goal command's figure is also compared with its row of record (75, tolerance 5)
      assert.equal(v.checks.find((c) => c.id === "figure:goal:cwe-bench-java:tp_rate").status, "pass");
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
  // a benchmark row of record (suite + metric) also allows block
  assert.ok(goalRecord({ records: [{ ...goalRow(), check: undefined, suite: "cwe-bench-java" }] }, goal()));
});

test("0.3.2 CLI block without a number of record falls back to warn, and the verdict says why", () => {
  const incomplete = [[], [goalRow({ status: "no record yet" })], [goalRow({ version: "" })], [goalRow({ date: undefined })],
    [goalRow({ method: " " })]];
  for (const records of incomplete) {
    const d = goalRepo([goal({ mode: "block" })], records);
    try {
      const { r, v, md } = reviewOf(d);
      assert.equal(r.status, 0, JSON.stringify(records) + r.stdout + r.stderr);
      const g = goalCheck(v);
      assert.equal(g.status, "warn");
      assert.match(g.summary, /warns: mode block needs a number of record/);
      assert.match(g.evidence[0], /treated as warn, the figure-of-record file has no number of record for this metric/);
      assert.match(md, /goal:cwe-bench-java: below goal: 72/);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

test("0.3.2 CLI: a command that rewrites the goals file mid-run is judged on the old goal, and the goals-file check fails (unwaivable)", () => {
  const lowered = JSON.stringify({ goals: [goal({ goal: 10 })] }).replace(/"/g, '\\"');
  const d = goalRepo([goal({ run: `echo "${lowered}" > ${GOALS_FILE}; echo "release-readiness:figure tp_rate 72"` })], [],
    { "waivers.json": { waivers: [{ check: "goals-file", who: "owner", why: "x", until: "2026-12-01", answer: "https://example.invalid/answers/1", confirm: "ci:later" }] } });
  try {
    const { r, v } = reviewOf(d);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.equal(goalCheck(v).status, "warn", "judged against goal 80 as read before the run, not the rewritten 10");
    assert.match(goalCheck(v).summary, /goal ≥ 80/);
    const guard = v.checks.find((c) => c.id === "goals-file");
    assert.equal(guard.status, "fail");
    assert.match(guard.evidence[0], /rewritten by a command of the candidate/);
    assert.equal(v.waivers[0].state, "ignored");
  } finally { rmSync(d, { recursive: true, force: true }); }
  // a command that creates the goals file during the review fails the same way
  const d2 = repo({ ".release-readiness.json": { ci: [{ id: "checks", run: `mkdir -p .loop && echo '{"goals":[]}' > ${GOALS_FILE}` }] } });
  try {
    const { r, v } = reviewOf(d2);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(v.checks.find((c) => c.id === "goals-file").evidence[0], /created/);
  } finally { rmSync(d2, { recursive: true, force: true }); }
});

test("0.3.2 CLI: a malformed goals file warns and never crashes; a malformed entry that asked to block fails", () => {
  for (const text of ["{ not json", '{"goals": 3}', "[]"]) {
    const d = goalRepo(text);
    try {
      const { r, v } = reviewOf(d);
      assert.equal(r.status, 0, text + r.stdout + r.stderr);
      const g = v.checks.find((c) => c.id === "goal");
      assert.equal(g.status, "warn", text);
      assert.match(g.summary, /^malformed goal \(\.loop\/benchmarks\.json\)/);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
  const { goals, problems } = parseGoals(JSON.stringify({ goals: [
    goal({ metric: "__proto__" }), goal({ suite: "a:b" }), goal({ goal: "80" }), goal({ comparison: ">" }), goal({ mode: "strict" }),
    goal({ suite: "dup" }), goal({ suite: "dup", metric: "fpr" }), null] }));
  assert.equal(goals.length, 0);
  assert.deepEqual(problems.map((p) => p.why.split(" ")[0]), ["metric", "suite", "goal", "comparison", "mode", "an", "suite", "suite"]);
  const d = goalRepo([goal({ metric: "Not-A-Name", mode: "block" }), goal({ suite: "other", goal: "x" })], [goalRow()]);
  try {
    const { r, v } = reviewOf(d);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.equal(goalCheck(v).status, "fail");
    assert.match(goalCheck(v).summary, /malformed goal \(entry 1\): metric "Not-A-Name" must match/);
    assert.equal(goalCheck(v, "other").status, "warn");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("0.3.2 CLI: a missing command (no run, or not on PATH) warns in warn mode and fails in block mode with a record", () => {
  const d = goalRepo([goal({ run: undefined }), goal({ suite: "gone", run: "no-such-benchmark-command-xyz" }),
    goal({ suite: "silent", run: "echo measured nothing" })]);
  try {
    const { r, v } = reviewOf(d);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(goalCheck(v).summary, /malformed goal \(entry 1\): no command \(run\)/);
    assert.equal(goalCheck(v).status, "warn");
    assert.equal(goalCheck(v, "gone").status, "warn");
    assert.match(goalCheck(v, "gone").summary, /no "release-readiness:figure tp_rate <value>" line \(the command exit 127\)/);
    assert.equal(goalCheck(v, "silent").status, "warn");
  } finally { rmSync(d, { recursive: true, force: true }); }
  const d2 = goalRepo([goal({ mode: "block", run: "no-such-benchmark-command-xyz" })], [goalRow()]);
  try {
    const { r, v } = reviewOf(d2);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.equal(goalCheck(v).status, "fail");
  } finally { rmSync(d2, { recursive: true, force: true }); }
});

test("0.3.2: goal command output stays capped; an abstaining or doubly-reporting command does not meet its goal; no goals file changes nothing", () => {
  const d = goalRepo([goal({ run: `for i in $(seq 1 200); do head -c 5000 /dev/zero | tr '\\0' x; echo; done; echo "release-readiness:figure tp_rate 90"` }),
    goal({ suite: "abst", run: 'echo "release-readiness:figure tp_rate 90"; exit 3', mode: "block" }),
    goal({ suite: "twice", run: 'echo "release-readiness:figure tp_rate 90"; echo "release-readiness:figure tp_rate 91"' })],
    [goalRow({ check: "goal:abst" })]);
  try {
    const { r, v } = reviewOf(d);
    const g = goalCheck(v);
    assert.equal(g.status, "pass");
    assert.ok(g.evidence.length <= 17 && g.evidence.every((e) => e.length <= 400), "evidence is the capped tail");
    assert.equal(goalCheck(v, "abst").status, "pass", "a figure printed before exit 3 is still judged");
    assert.equal(goalCheck(v, "twice").status, "warn");
    assert.match(goalCheck(v, "twice").summary, /reported 2 times/);
    assert.equal(v.checks.find((c) => c.id === "figure:goal:twice:tp_rate").status, "warn", "a warn goal's doubled figure warns");
    assert.equal(r.status, 0, "warn mode: a doubled figure does not block (round 1 fix)");
  } finally { rmSync(d, { recursive: true, force: true }); }
  const d2 = repo({ ".release-readiness.json": { ci: [{ id: "checks", run: "true" }] } });
  try {
    const { r, v } = reviewOf(d2);
    assert.equal(r.status, 0);
    assert.ok(!v.checks.some((c) => c.group === "goal" || c.id === "goals-file"));
    assert.deepEqual(v.warnings, []);
  } finally { rmSync(d2, { recursive: true, force: true }); }
});

// --- 0.3.2 fix round 1 ---

test("0.3.2 r1: a doubled figure warns in warn mode without a row of record; with a row of record its figure fails closed", () => {
  const twice = 'echo "release-readiness:figure tp_rate 90"; echo "release-readiness:figure tp_rate 70"';
  for (const [mode, records, exit, status, figStatus = status] of [["warn", [], 0, "warn"], ["warn", [goalRow()], 1, "warn", "fail"],
    ["block", [goalRow({ version: "" })], 0, "warn", "abstain"], ["block", [goalRow()], 1, "fail"]]) {
    const d = goalRepo([goal({ mode, run: twice })], records);
    try {
      const { r, v, md } = reviewOf(d);
      const label = `${mode} ${JSON.stringify(records)}`;
      assert.equal(r.status, exit, label + r.stdout + r.stderr);
      assert.equal(goalCheck(v).status, status, label);
      assert.equal(v.checks.find((c) => c.id === "figure:goal:cwe-bench-java:tp_rate").status, figStatus, label);
      if (status === "warn") assert.match(md, /reported 2 times: 90, 70/);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

test("0.3.2 r1: a goals file that is a directory, or a symlink to one, warns and never crashes", () => {
  for (const kind of ["dir", "link"]) {
    const d = repo({ ".release-readiness.json": { ci: [{ id: "checks", run: "true" }] } });
    try {
      mkdirSync(join(d, ".loop"), { recursive: true });
      if (kind === "dir") mkdirSync(join(d, GOALS_FILE));
      else { mkdirSync(join(d, "elsewhere")); symlinkSync(join(d, "elsewhere"), join(d, GOALS_FILE)); }
      const { r, v } = reviewOf(d);
      assert.equal(r.status, 0, kind + r.stdout + r.stderr);
      const g = v.checks.find((c) => c.id === "goal");
      assert.equal(g.status, "warn", kind);
      assert.match(g.summary, /not a file \(a directory\)/);
      assert.ok(!v.checks.some((c) => c.id === "goals-file"), "unchanged across the run");
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
  // a candidate that turns the file into a directory mid-run fails goals-file (and does not crash)
  const d = goalRepo([goal({ run: `rm ${GOALS_FILE} && mkdir ${GOALS_FILE}; echo "release-readiness:figure tp_rate 90"` })]);
  try {
    const { r, v } = reviewOf(d);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(v.checks.find((c) => c.id === "goals-file").evidence[0], /rewritten/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("0.3.2 r1: an unparseable goals file whose text asks for block fails; without block it warns", () => {
  for (const [text, exit, status] of [['{"goals":[{"suite":"s","mode":"block",', 1, "fail"], ['{"goals":{"mode": "block"}}', 1, "fail"], ["{ nope", 0, "warn"]]) {
    const d = goalRepo(text);
    try {
      const { r, v } = reviewOf(d);
      assert.equal(r.status, exit, text + r.stdout + r.stderr);
      assert.equal(v.checks.find((c) => c.id === "goal").status, status, text);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

test("0.3.2 r2: a figure of record (85) printed twice as 10 is NO-GO, whatever the goal's mode", () => {
  for (const mode of ["warn", "block"]) {
    const d = goalRepo([goal({ mode, goal: 80, run: 'echo "release-readiness:figure tp_rate 10"; echo "release-readiness:figure tp_rate 10"' })],
      [goalRow({ value: 85 })]);
    try {
      const { r, v } = reviewOf(d);
      assert.equal(r.status, 1, mode + r.stdout + r.stderr);
      assert.equal(v.verdict, "NO-GO");
      const f = v.checks.find((c) => c.id === "figure:goal:cwe-bench-java:tp_rate");
      assert.equal(f.status, "fail", mode);
      assert.match(f.summary, /reported 2 times: 10, 10/);
      assert.ok(v.reasons.some((x) => x.startsWith("figure:goal:cwe-bench-java:tp_rate failed")), mode);
    } finally { rmSync(d, { recursive: true, force: true }); }
  }
});

// --- 0.4.0: the base's gate, evidence, waivers that count, open waivers ---

const W = (o = {}) => ({ check: "ci:bad", who: "owner", why: "known, #50", until: "2026-12-01",
  answer: "https://example.invalid/answers/7", confirm: "ci:bad", ...o });
const failing = () => [{ id: "ci:bad", group: "ci", status: "fail", summary: "exit 1", evidence: ["$ false", "exit 1"] },
  { id: "ci:good", group: "ci", status: "pass", summary: "exit 0", evidence: ["$ true", "exit 0"] }];

test("0.4.0: an agent is a [bot] login or a configured agent, case-insensitive", () => {
  assert.equal(isAgent("cursor[bot]"), true);
  assert.equal(isAgent("Review-Agent", ["review-agent"]), true);
  assert.equal(isAgent("owner", ["review-agent"]), false);
});

test("0.4.0: a waiver counts only with a person's answer and a confirming check", () => {
  for (const [w, why] of [
    [W({ answer: undefined }), /invalid: no answer/],
    [W({ confirm: "" }), /invalid: no confirm/],
    [W({ answer: "http://example.invalid/a" }), /not an https link/],
    [W({ answer: "see thread" }), /not an https link/],
    [W({ who: "cursor[bot]" }), /is an agent/],
    [W({ who: "review-agent" }), /is an agent/],
  ]) {
    const checks = failing();
    const [r] = applyWaivers(checks, { waivers: [w] }, { today: "2026-11-12", agents: ["review-agent"] });
    assert.equal(r.state, "ignored", JSON.stringify(w));
    assert.match(r.note, why);
    assert.equal(checks[0].status, "fail", "the check stays failed");
  }
  const checks = failing();
  const [r] = applyWaivers(checks, { waivers: [W()] }, { today: "2026-11-12" });
  assert.equal(r.state, "applied");
  assert.equal(checks[0].status, "waived");
  assert.match(checks[0].evidence.join("\n"), /answer https:\/\/example\.invalid\/answers\/7; confirmed by ci:bad/);
});

test("0.4.0: a waiver is open until its confirming check passes", () => {
  const open = applyWaivers(failing(), { waivers: [W()] }, { today: "2026-11-12" })[0];
  assert.equal(open.open, true);
  assert.match(open.note, /open: ci:bad is waived/);
  const closed = applyWaivers(failing(), { waivers: [W({ confirm: "ci:good" })] }, { today: "2026-11-12" })[0];
  assert.equal(closed.open, false);
  assert.match(closed.note, /closed: ci:good passed/);
  const absent = applyWaivers(failing(), { waivers: [W({ confirm: "measure:bench" })] }, { today: "2026-11-12" })[0];
  assert.equal(absent.open, true);
  assert.match(absent.note, /did not run in this review/);
});

test("0.4.0: a pass or a fail without evidence is a fail; abstain and warn are untouched", () => {
  const checks = [{ id: "a", status: "pass", summary: "ok", evidence: [] }, { id: "b", status: "pass", summary: "ok", evidence: ["", "  "] },
    { id: "c", status: "abstain", summary: "n/a", evidence: [] }, { id: "d", status: "pass", summary: "ok", evidence: ["exit 0"] }];
  requireEvidence(checks);
  assert.deepEqual(checks.map((c) => c.status), ["fail", "fail", "abstain", "pass"]);
  assert.match(checks[0].summary, /no evidence recorded \(was: ok\)/);
});

/** A candidate checkout and a base gate directory, side by side in one temp folder. */
function twoTrees(candidate, base) {
  const top = mkdtempSync(join(tmpdir(), "rr-gate-"));
  const mk = (dir, files) => { for (const [f, c] of Object.entries(files)) { const p = join(top, dir, f); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, typeof c === "string" ? c : JSON.stringify(c)); } };
  mkdirSync(join(top, "cand"), { recursive: true }); mkdirSync(join(top, "base"), { recursive: true });
  mk("cand", candidate); mk("base", base);
  return top;
}
const gcli = (top, ...args) => spawnSync(process.execPath, [SCRIPT, "--config", join(top, "cand", ".release-readiness.json"), "--today", "2026-11-12", ...args], { encoding: "utf8" });

test("0.4.0 CLI --gate-from: the base's gate applies; the candidate's own waiver and weaker config are seen, not obeyed", () => {
  const baseCfg = { required: ["ci"], ci: [{ id: "bad", run: "false" }, { id: "good", run: "true" }], waivers: "waivers.json", agents: ["review-agent"] };
  const top = twoTrees({
    // The candidate drops the failing command and waives it anyway.
    ".release-readiness.json": { ci: [{ id: "good", run: "true" }], waivers: "waivers.json" },
    "waivers.json": { waivers: [W()] },
  }, { ".release-readiness.json": baseCfg, "waivers.json": { waivers: [] } });
  try {
    const r = gcli(top, "--gate-from", join(top, "base"), "--out-json", join(top, "v.json"));
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const v = JSON.parse(readFileSync(join(top, "v.json"), "utf8"));
    assert.equal(v.gate, "base");
    assert.equal(v.checks.find((c) => c.id === "ci:bad").status, "fail", "the base's command ran; the candidate's waiver did not apply");
    const g = v.checks.find((c) => c.id === "gate-definition");
    assert.equal(g.status, "warn");
    assert.match(g.evidence.join("\n"), /\.release-readiness\.json: differs from the base/);
    assert.match(g.evidence.join("\n"), /waivers\.json: differs from the base/);
    assert.match(r.stdout, /Gate: the base branch's/);
  } finally { rmSync(top, { recursive: true, force: true }); }
});

test("0.4.0 CLI --gate-from: the same gate gives no gate-definition warning; a gate inside the candidate or a base with no config is refused", () => {
  const cfg = { ci: [{ id: "good", run: "true" }] };
  const top = twoTrees({ ".release-readiness.json": cfg }, { ".release-readiness.json": cfg });
  try {
    const r = gcli(top, "--gate-from", join(top, "base"), "--out-json", join(top, "v.json"));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(JSON.parse(readFileSync(join(top, "v.json"), "utf8")).checks.some((c) => c.id === "gate-definition"), false);
    assert.equal(gcli(top, "--gate-from", join(top, "cand")).status, 2);
    mkdirSync(join(top, "cand", "sub"), { recursive: true });
    assert.equal(gcli(top, "--gate-from", join(top, "cand", "sub")).status, 2);
    mkdirSync(join(top, "empty"));
    const e = gcli(top, "--gate-from", join(top, "empty"));
    assert.equal(e.status, 2);
    assert.match(e.stderr, /the base has no/);
  } finally { rmSync(top, { recursive: true, force: true }); }
});

test("0.4.0 CLI: an open waiver keeps an rc GO but blocks the final release; --final makes it NO-GO", () => {
  const cfg = { ci: [{ id: "bad", run: "false" }, { id: "good", run: "true" }], waivers: "waivers.json" };
  const top = twoTrees({ ".release-readiness.json": cfg, "waivers.json": { waivers: [W()] } }, {});
  try {
    const rc = gcli(top, "--out-json", join(top, "v.json"));
    assert.equal(rc.status, 0, rc.stdout + rc.stderr);
    const v = JSON.parse(readFileSync(join(top, "v.json"), "utf8"));
    assert.equal(v.final_release, "blocked");
    assert.deepEqual(v.open_waivers, ["ci:bad"]);
    assert.match(rc.stdout, /final release: \*\*blocked\*\* \(open waivers: `ci:bad`\)/);
    const fin = gcli(top, "--final");
    assert.equal(fin.status, 1);
    assert.match(fin.stdout, /open waiver on ci:bad: a final release needs its confirming check to pass/);
  } finally { rmSync(top, { recursive: true, force: true }); }
});

test("0.4.0: gateDiff names a file only the candidate has as not on the base", () => {
  const top = twoTrees({ "a.json": "{}", "b.json": "1" }, { "b.json": "1" });
  try {
    const [g] = gateDiff(join(top, "cand"), join(top, "base"), ["a.json", "b.json"]);
    assert.deepEqual(g.evidence.slice(0, 1), ["a.json: not on the base"]);
    assert.deepEqual(gateDiff(join(top, "cand"), join(top, "base"), ["b.json"]), []);
  } finally { rmSync(top, { recursive: true, force: true }); }
});

// --- 0.4.4: the base branch a failure's task is fixed on (git-branching's BRANCH_CHECK_BASE, default main) ---

test("0.4.4: a failure's task is fixed on main by default, on the base branch when one is given", () => {
  const cfg = { ci: [{ id: "bad", run: "exit 1" }] };
  const d = rrRepo(cfg, {});
  try {
    const opts = { root: d, tag: "site-v1.2.0-rc.1", sha: "0123456789abcdef", today: "2026-11-12" };
    const dflt = review(cfg, opts).tasks[0].body;
    assert.match(dflt, /Done when: fixed on main and the check passes on the next candidate/);
    const master = review(cfg, { ...opts, base: "master" }).tasks[0].body;
    assert.match(master, /Done when: fixed on master and the check passes on the next candidate/);
    assert.doesNotMatch(master, /fixed on main/);
    assert.equal(master.replace("fixed on master", "fixed on main"), dflt, "only the branch name differs");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("0.4.4: the CLI reads BRANCH_CHECK_BASE (unset or empty: main) and refuses a name that is not a base branch", () => {
  const cfg = { ci: [{ id: "bad", run: "exit 1" }] };
  const d = rrRepo(cfg, {});
  const run = (env) => spawnSync(process.execPath, [SCRIPT, "--config", join(d, ".release-readiness.json"), "--today", "2026-11-12",
    "--tag", "site-v1.2.0-rc.1", "--sha", "abc", "--out-json", join(d, "v.json")], { encoding: "utf8", env: { PATH: process.env.PATH, ...env } });
  const body = () => JSON.parse(readFileSync(join(d, "v.json"), "utf8")).tasks[0].body;
  try {
    assert.equal(run({}).status, 1);
    assert.match(body(), /fixed on main and/);
    assert.equal(run({ BRANCH_CHECK_BASE: "" }).status, 1);
    assert.match(body(), /fixed on main and/);
    assert.equal(run({ BRANCH_CHECK_BASE: "master" }).status, 1);
    assert.match(body(), /fixed on master and/);
    for (const bad of ["m$(touch PWNED)", "../main", "refs/heads/master", "release/site-1.2.0", "rc/site-1.2.0-rc.1", "a b", "main/"]) {
      const r = run({ BRANCH_CHECK_BASE: bad });
      assert.equal(r.status, 2, bad);
      assert.match(r.stderr, /not a base branch name/, bad);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});
