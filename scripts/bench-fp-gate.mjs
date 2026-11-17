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
 *
 * Exit codes:
 *   0  fp_gain is at most FP_GAIN_MAX
 *   1  fp_gain is above FP_GAIN_MAX
 *   3  cannot judge (no or duplicate `summary:` line, a malformed ADDED row,
 *      more ADDED rows than the summary's `added`, a bad FP_GAIN_MAX, missing
 *      input, usage error)
 *
 * bench-diff prints one tab-separated row per changed signature; an addition is
 *   ADDED\t<file>\t<signature>\texpected=<true|false|?>[/<category>]
 * and the partner of a re-attribution is not printed as ADDED. Only rows with
 * `expected=false` count. `expected=true` additions are new detections on real
 * vulnerabilities, and `expected=?` files are not scored by the CSV; both are
 * reported as evidence and never change the exit code.
 *
 * On 0 or 1 it prints:
 *   bench-fp-gate: fp_gain=<N> max=<M> added_on_real=<N> added_unscored=<N>
 *   bench-fp-gate: offending <file> <signature>     (the first 20 only)
 * On 3 it prints `bench-fp-gate: cannot judge: <reason>`. Offending rows are
 * reduced to a safe character set, as their paths come from the scanned corpus.
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DIGITS = /^\d+$/;
const MAX_LISTED = 20;
const EXPECTED = /^expected=(true|false|\?)(\/.*)?$/;

/**
 * Judge bench-diff `diff` output against `max` (a digit string, or undefined
 * for the default 0). Returns `{ code: 0|1, fpGain, addedOnReal, addedUnscored,
 * offending, lines }` on a judgement, or `{ code: 3, reason }`.
 */
export function judge(text, max = '0') {
  if (!DIGITS.test(max)) return cannot(`FP_GAIN_MAX must be a whole number, got '${max}'`);
  const lines = text.split('\n').map(l => l.replace(/\r$/, ''));
  const summaries = lines.filter(l => l.startsWith('summary: '));
  if (summaries.length !== 1) return cannot(`expected one summary line, found ${summaries.length}`);
  const added = /(?:^| )added=(\d+)(?: |$)/.exec(summaries[0].slice('summary: '.length));
  if (!added) return cannot('summary has no numeric added');

  let fpGain = 0, addedOnReal = 0, addedUnscored = 0, rows = 0;
  const offending = [];
  for (const l of lines) {
    if (!l.startsWith('ADDED\t')) continue;
    const fields = l.split('\t');
    if (fields.length !== 4) return cannot(`malformed ADDED row (${fields.length} fields)`);
    const m = EXPECTED.exec(fields[3]);
    if (!m) return cannot('ADDED row has no expected= field');
    rows++;
    if (m[1] === 'false') {
      fpGain++;
      if (offending.length < MAX_LISTED) offending.push(`${safe(fields[1])} ${safe(fields[2])}`);
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
    addedOnReal,
    addedUnscored,
    offending,
    lines: [
      `bench-fp-gate: fp_gain=${fpGain} max=${limit} added_on_real=${addedOnReal} added_unscored=${addedUnscored}`,
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
  let text;
  if (rest[0] === '-') text = readFileSync(0, 'utf8');
  else if (existsSync(rest[0])) text = readFileSync(rest[0], 'utf8');
  else return cannot(`missing input ${rest[0]}`);
  return judge(text, env.FP_GAIN_MAX === undefined || env.FP_GAIN_MAX === '' ? '0' : env.FP_GAIN_MAX);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const result = main(process.argv.slice(2), process.env);
  if (result.code === 3) console.log(`bench-fp-gate: cannot judge: ${result.reason}`);
  else console.log(result.lines.join('\n'));
  process.exitCode = result.code;
}
