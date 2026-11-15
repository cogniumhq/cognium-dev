#!/usr/bin/env node
/**
 * Judge `bench-diff diff` output on true-positive loss alone, and print one
 * machine-readable figure line for a release gate.
 *
 * Usage:
 *   node scripts/bench-gate.mjs parse <file|->
 *       Judge saved `bench-diff diff` output (a file, or stdin with `-`).
 *   node scripts/bench-gate.mjs diff <before.json> <after.json>
 *       [--expected <csv>] [--allow <regex>] [--runtime <bin>] [--bench-diff <path>]
 *       Run `<runtime> <bench-diff> diff <before> <after> [...]` and judge its
 *       output. Defaults: runtime `bun`, bench-diff
 *       `.claude/skills/autofix-issues/bench-diff.mts` in this repo.
 *
 * Exit codes:
 *   0  tp_loss is 0
 *   1  tp_loss is above 0
 *   3  cannot judge (no or duplicate `summary:` line, bench-diff usage error,
 *      crash or timeout, counts that disagree with `GATE:` or the exit code,
 *      missing input, wrapper usage error)
 *
 * On 0 or 1 it prints, in this order:
 *   bench-gate: <the summary line, verbatim>
 *   bench-gate: removed_outside_allow=<N> (evidence; not gated)
 *   release-readiness:figure tp_loss <N>
 * On 3 it prints `bench-gate: cannot judge: <reason>` and no figure line.
 *
 * bench-diff's own GATE fails on removed_outside_allow too; this gate does
 * not. That count is printed as evidence and never changes the exit code. No
 * other line of bench-diff's output is echoed: its rows carry file paths, and
 * a crafted path must not be able to print a second figure line.
 */
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BENCH_DIFF = join(ROOT, '.claude', 'skills', 'autofix-issues', 'bench-diff.mts');
const TIMEOUT_MS = 30 * 60 * 1000;
const DIGITS = /^\d+$/;

/**
 * Judge bench-diff `diff` output. `exitCode` is bench-diff's own exit code in
 * diff mode, or undefined when judging saved output.
 * Returns `{ code: 0|1, lines }` on a judgement, or `{ code: 3, reason }`.
 */
export function judge(text, exitCode) {
  const lines = text.split('\n').map(l => l.replace(/\r$/, ''));
  const summaries = lines.filter(l => l.startsWith('summary: '));
  if (summaries.length !== 1) return cannot(`expected one summary line, found ${summaries.length}`);
  const summary = summaries[0];

  // `key=value` tokens of the summary line; a repeated key cannot be judged.
  const counts = new Map();
  for (const token of summary.slice('summary: '.length).split(' ')) {
    const eq = token.indexOf('=');
    if (eq <= 0) continue;
    const key = token.slice(0, eq);
    if (counts.has(key)) return cannot(`summary repeats ${key}`);
    counts.set(key, token.slice(eq + 1));
  }
  const tpLoss = counts.get('tp_loss');
  if (tpLoss === undefined || !DIGITS.test(tpLoss)) return cannot('summary has no numeric tp_loss');
  const outside = counts.get('removed_outside_allow');
  if (outside === undefined || !DIGITS.test(outside)) return cannot('summary has no numeric removed_outside_allow');

  // bench-diff passes only when both counts are 0. Its GATE line and exit
  // code must agree with that, or the output is not what it seems.
  const pass = Number(tpLoss) === 0 && Number(outside) === 0;
  for (const l of lines) {
    if (l === 'GATE: PASS' || l === 'GATE: FAIL') {
      if ((l === 'GATE: PASS') !== pass) return cannot(`${l} disagrees with the summary counts`);
    }
  }
  if (exitCode !== undefined && exitCode !== (pass ? 0 : 1)) {
    return cannot(`bench-diff exit code ${exitCode} disagrees with the summary counts`);
  }

  return {
    code: Number(tpLoss) === 0 ? 0 : 1,
    lines: [
      `bench-gate: ${summary}`,
      `bench-gate: removed_outside_allow=${Number(outside)} (evidence; not gated)`,
      `release-readiness:figure tp_loss ${Number(tpLoss)}`,
    ],
  };
}

function cannot(reason) {
  return { code: 3, reason };
}

/** Run bench-diff in diff mode and judge what it printed. */
function runDiff(args) {
  const positional = [];
  const passOn = [];
  let runtime = 'bun';
  let benchDiff = BENCH_DIFF;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--expected' || a === '--allow' || a === '--runtime' || a === '--bench-diff') {
      const v = args[++i];
      if (v === undefined) return cannot(`${a} needs a value`);
      if (a === '--runtime') runtime = v;
      else if (a === '--bench-diff') benchDiff = v;
      else passOn.push(a, v);
    } else if (a.startsWith('--')) {
      return cannot(`unknown option ${a}`);
    } else {
      positional.push(a);
    }
  }
  if (positional.length !== 2) return cannot('usage: diff <before.json> <after.json>');
  for (const f of positional) {
    if (!existsSync(f)) return cannot(`missing input ${f}`);
  }

  const r = spawnSync(runtime, [benchDiff, 'diff', ...positional, ...passOn], {
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (r.error) return cannot(`bench-diff did not run: ${r.error.code ?? r.error.message}`);
  if (r.status !== 0 && r.status !== 1) {
    return cannot(r.status === null ? `bench-diff ended by ${r.signal}` : `bench-diff exited ${r.status}`);
  }
  return judge(`${r.stdout}\n${r.stderr}`, r.status);
}

function readInput(src) {
  if (src === '-') return readFileSync(0, 'utf8');
  if (!existsSync(src)) return undefined;
  return readFileSync(src, 'utf8');
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === 'parse') {
    if (rest.length !== 1) return cannot('usage: parse <file|->');
    const text = readInput(rest[0]);
    if (text === undefined) return cannot(`missing input ${rest[0]}`);
    return judge(text);
  }
  if (cmd === 'diff') return runDiff(rest);
  return cannot('commands: parse | diff');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const result = main(process.argv.slice(2));
  if (result.code === 3) console.log(`bench-gate: cannot judge: ${result.reason}`);
  else console.log(result.lines.join('\n'));
  process.exitCode = result.code;
}
