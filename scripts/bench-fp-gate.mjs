#!/usr/bin/env node
/**
 * Judge `bench-diff diff` output on false-positive gain: findings ADDED on
 * benchmark cases the expected-results CSV marks as not vulnerable.
 *
 * Usage:
 *   node scripts/bench-fp-gate.mjs parse <file|->
 *       Judge saved `bench-diff diff --expected <csv>` output (a file, or stdin
 *       with `-`).
 *
 * Environment:
 *   FP_GAIN_MAX  the most ADDED rows on expected=false cases that still pass
 *                (default 0).
 *   FP_WAIVERS   path to the reviewed waiver list (default
 *                scripts/bench-fp-waivers.json next to this script). An ADDED
 *                expected=false row that matches a waiver is counted as
 *                `waived`, not as fp_gain. A waiver is {file, signature, cwe,
 *                reason, ref}; it matches on file + signature as printed, but
 *                when the waiver's signature carries a line number it matches on
 *                file + category (the rule before `@`) so a line shift does not
 *                break it. Waivers only ever suppress expected=false additions.
 *
 * Exit codes:
 *   0  fp_gain is at most FP_GAIN_MAX
 *   1  fp_gain is above FP_GAIN_MAX
 *   3  cannot judge (no or duplicate `summary:` line, a malformed ADDED row,
 *      more ADDED rows than the summary's `added`, a bad FP_GAIN_MAX, an
 *      unreadable or malformed waiver file, missing input, usage error)
 *
 * bench-diff prints one tab-separated row per changed signature; an addition is
 *   ADDED\t<file>\t<signature>\texpected=<true|false|?>[/<category>]
 * and the partner of a re-attribution is not printed as ADDED. Only rows with
 * `expected=false` count. `expected=true` additions are new detections on real
 * vulnerabilities, and `expected=?` files are not scored by the CSV; both are
 * reported as evidence and never change the exit code.
 *
 * On 0 or 1 it prints:
 *   bench-fp-gate: fp_gain=<N> max=<M> waived=<N> added_on_real=<N> added_unscored=<N>
 *   bench-fp-gate: waived <file> <signature>        (one per waived row)
 *   bench-fp-gate: offending <file> <signature>     (the first 20 only)
 * On 3 it prints `bench-fp-gate: cannot judge: <reason>`. Offending and waived
 * rows are reduced to a safe character set, as their paths come from the
 * scanned corpus.
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const DIGITS = /^\d+$/;
const MAX_LISTED = 20;
const EXPECTED = /^expected=(true|false|\?)(\/.*)?$/;
const HAS_LINE_NUMBER = /@\d/;

/** The default waiver list, resolved next to this script (not the cwd). */
export function defaultWaiversPath() {
  return join(dirname(fileURLToPath(import.meta.url)), 'bench-fp-waivers.json');
}

/**
 * Read and validate the waiver list at `path`. Returns `{ ok: true, waivers }`,
 * or `{ ok: false, reason }` when the file is unreadable, not valid JSON, not an
 * array, or holds an entry without a string `file` and `signature`.
 */
export function loadWaivers(path) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return { ok: false, reason: `cannot read waiver file ${path}` };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return { ok: false, reason: `waiver file ${path} is not valid JSON` };
  }
  if (!Array.isArray(data)) return { ok: false, reason: `waiver file ${path} is not a JSON array` };
  for (let i = 0; i < data.length; i++) {
    const w = data[i];
    if (!w || typeof w !== 'object' || typeof w.file !== 'string' || typeof w.signature !== 'string') {
      return { ok: false, reason: `waiver ${i} in ${path} needs string file and signature` };
    }
  }
  return { ok: true, waivers: data };
}

/** The rule category of a signature: everything before the first `@`. */
function category(signature) {
  return signature.split('@')[0];
}

/**
 * True when `{ file, signature }` (an ADDED row, as printed) matches any waiver.
 * A waiver matches on file plus its signature as printed, except that a waiver
 * whose own signature carries a line number matches on category only, so a line
 * shift in the corpus does not break it. Waivers are applied by the caller only
 * to expected=false rows.
 */
function isWaived(file, signature, waivers) {
  return waivers.some(w =>
    w.file === file &&
    (HAS_LINE_NUMBER.test(w.signature)
      ? category(w.signature) === category(signature)
      : w.signature === signature));
}

/**
 * Judge bench-diff `diff` output against `max` (a digit string, or undefined
 * for the default 0). `waivers` suppress matching expected=false additions.
 * Returns `{ code: 0|1, fpGain, waived, addedOnReal, addedUnscored, offending,
 * waivedRows, lines }` on a judgement, or `{ code: 3, reason }`.
 */
export function judge(text, max = '0', waivers = []) {
  if (!DIGITS.test(max)) return cannot(`FP_GAIN_MAX must be a whole number, got '${max}'`);
  const lines = text.split('\n').map(l => l.replace(/\r$/, ''));
  const summaries = lines.filter(l => l.startsWith('summary: '));
  if (summaries.length !== 1) return cannot(`expected one summary line, found ${summaries.length}`);
  const added = /(?:^| )added=(\d+)(?: |$)/.exec(summaries[0].slice('summary: '.length));
  if (!added) return cannot('summary has no numeric added');

  let fpGain = 0, waived = 0, addedOnReal = 0, addedUnscored = 0, rows = 0;
  const offending = [];
  const waivedRows = [];
  for (const l of lines) {
    if (!l.startsWith('ADDED\t')) continue;
    const fields = l.split('\t');
    if (fields.length !== 4) return cannot(`malformed ADDED row (${fields.length} fields)`);
    const m = EXPECTED.exec(fields[3]);
    if (!m) return cannot('ADDED row has no expected= field');
    rows++;
    if (m[1] === 'false') {
      if (isWaived(fields[1], fields[2], waivers)) {
        waived++;
        waivedRows.push(`${safe(fields[1])} ${safe(fields[2])}`);
      } else {
        fpGain++;
        if (offending.length < MAX_LISTED) offending.push(`${safe(fields[1])} ${safe(fields[2])}`);
      }
    } else if (m[1] === 'true') addedOnReal++;
    else addedUnscored++;
  }
  // Each ADDED row is one counted addition; re-attribution partners are
  // counted in `added` but not printed. More rows than `added` is not
  // bench-diff output.
  if (rows > Number(added[1])) return cannot(`${rows} ADDED rows but summary added=${added[1]}`);

  const limit = Number(max);
  return {
    code: fpGain <= limit ? 0 : 1,
    fpGain,
    waived,
    addedOnReal,
    addedUnscored,
    offending,
    waivedRows,
    lines: [
      `bench-fp-gate: fp_gain=${fpGain} max=${limit} waived=${waived} added_on_real=${addedOnReal} added_unscored=${addedUnscored}`,
      ...waivedRows.map(w => `bench-fp-gate: waived ${w}`),
      ...offending.map(o => `bench-fp-gate: offending ${o}`),
    ],
  };
}

function safe(s) {
  return s.replace(/[^A-Za-z0-9._/@:>=+-]/g, '?').slice(0, 200);
}

function cannot(reason) {
  return { code: 3, reason };
}

function main(argv, env) {
  const [cmd, ...rest] = argv;
  if (cmd !== 'parse' || rest.length !== 1) return cannot('usage: parse <file|->');
  const waiversPath = env.FP_WAIVERS ? env.FP_WAIVERS : defaultWaiversPath();
  const loaded = loadWaivers(waiversPath);
  if (!loaded.ok) return cannot(loaded.reason);
  let text;
  if (rest[0] === '-') text = readFileSync(0, 'utf8');
  else if (existsSync(rest[0])) text = readFileSync(rest[0], 'utf8');
  else return cannot(`missing input ${rest[0]}`);
  return judge(
    text,
    env.FP_GAIN_MAX === undefined || env.FP_GAIN_MAX === '' ? '0' : env.FP_GAIN_MAX,
    loaded.waivers,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const result = main(process.argv.slice(2), process.env);
  if (result.code === 3) console.log(`bench-fp-gate: cannot judge: ${result.reason}`);
  else console.log(result.lines.join('\n'));
  process.exitCode = result.code;
}
