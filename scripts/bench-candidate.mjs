#!/usr/bin/env node
/**
 * The candidate results file of the release review: the bench-diff tp_loss a
 * release candidate was measured at, naming the candidate and the commit.
 *
 * Usage:
 *   node scripts/bench-candidate.mjs write --tag <rc tag> --measured <sha> --reference <tag>
 *       --suite <suite> [--date YYYY-MM-DD] [--out <path>] <saved bench-diff diff output|->
 *       Judge saved `bench-diff diff` output with scripts/bench-gate.mjs and record its
 *       tp_loss for <suite> in the results file (default .release/candidate-results.json).
 *       The number is recorded whatever it is; the release review judges it.
 *   node scripts/bench-candidate.mjs check [--file <path>]
 *       Pass when the results file was measured on this code: its sha is an ancestor of
 *       HEAD and nothing but the results file changed since.
 *
 * Exit codes:
 *   write  0 written, 2 bad arguments (nothing written), 3 cannot judge (nothing written)
 *   check  0 measured on this code, 1 not (or the file is unreadable), 3 no results file
 *
 * A file that names the same tag and sha keeps its other suites and gets this
 * suite's entry replaced. A file for another tag or sha is started afresh:
 * numbers never carry over from one candidate to another.
 */
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { judge } from './bench-gate.mjs';

const DEFAULT_FILE = '.release/candidate-results.json';
const TAG = /^[a-z][a-z0-9.-]*-v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*$/;
const SHA = /^[0-9a-f]{40}$/;
const SUITE = /^[a-z0-9][a-z0-9._/-]{0,127}$/;
const REF_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const FIGURE = /^release-readiness:figure tp_loss (\d+)$/;
const MAX_LISTED = 20;

/** `--name value` options and positionals; an unknown or valueless option is an error. */
function parseArgs(args, names) {
  const opts = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--') && a !== '-') {
      const name = a.slice(2);
      if (!names.includes(name)) return { error: `unknown option ${a}` };
      const v = args[++i];
      if (v === undefined) return { error: `${a} needs a value` };
      if (name in opts) return { error: `${a} given twice` };
      opts[name] = v;
    } else {
      positional.push(a);
    }
  }
  return { opts, positional };
}

function validDate(s) {
  if (!DATE.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

function readJson(path) {
  try {
    return { value: JSON.parse(readFileSync(path, 'utf8')) };
  } catch (e) {
    return { error: e.message };
  }
}

/** Write through a temp file in the same directory, then rename over the target. */
function writeAtomic(path, value) {
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(tmp, path);
}

export function write(args, { today = new Date().toISOString().slice(0, 10), stdin = () => readFileSync(0, 'utf8') } = {}) {
  const usage = reason => ({ code: 2, lines: [`bench-candidate: ${reason}`] });
  const p = parseArgs(args, ['tag', 'measured', 'reference', 'suite', 'date', 'out']);
  if (p.error) return usage(p.error);
  const { tag, measured, reference, suite } = p.opts;
  const date = p.opts.date ?? today;
  const out = p.opts.out ?? DEFAULT_FILE;
  if (!tag || !TAG.test(tag)) return usage(`--tag must be <track>-v<X.Y.Z>-rc.<N>, not ${JSON.stringify(tag ?? '')}`);
  if (!measured || !SHA.test(measured)) return usage('--measured must be a 40-hex lower-case commit sha');
  if (!reference || !REF_TAG.test(reference) || reference.includes('..')) return usage('--reference must be a plain tag name');
  if (!suite || !SUITE.test(suite)) return usage(`--suite must match ${SUITE.source}`);
  if (!validDate(date)) return usage('--date must be YYYY-MM-DD');
  if (p.positional.length !== 1) return usage('one input: the saved bench-diff diff output, or - for stdin');

  const src = p.positional[0];
  let text;
  if (src === '-') text = stdin();
  else if (!existsSync(src)) return usage(`missing input ${src}`);
  else text = readFileSync(src, 'utf8');

  const judged = judge(text);
  if (judged.code === 3) return { code: 3, lines: [`bench-candidate: cannot judge: ${judged.reason}`] };
  const figure = judged.lines.map(l => FIGURE.exec(l)).find(Boolean);
  if (!figure) return { code: 3, lines: ['bench-candidate: cannot judge: no tp_loss figure'] };
  const value = Number(figure[1]);

  // Same candidate: keep the other suites. Anything else: a fresh file.
  let results = [];
  if (existsSync(out)) {
    const prev = readJson(out).value;
    if (prev && prev.tag === tag && prev.sha === measured && Array.isArray(prev.results)) {
      results = prev.results.filter(r => r?.suite !== suite);
    }
  }
  results.push({ suite, metric: 'tp_loss', value });
  writeAtomic(out, {
    tag,
    sha: measured,
    version: `${measured.slice(0, 12)} vs ${reference}`,
    date,
    method: `bench-diff diff via scripts/bench-gate.mjs vs ${reference}`,
    results,
  });
  return {
    code: 0,
    lines: [
      ...judged.lines.filter(l => !FIGURE.test(l)),
      `bench-candidate: wrote ${out}: ${suite} tp_loss ${value} (${tag} at ${measured})`,
    ],
  };
}

function git(args) {
  const r = spawnSync('git', args, { encoding: 'utf8', maxBuffer: 64 << 20 });
  return { status: r.error ? null : r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

export function check(args) {
  const p = parseArgs(args, ['file']);
  if (p.error || p.positional.length) return { code: 1, lines: [`bench-candidate: ${p.error ?? 'check takes no positional arguments'}`] };
  const file = p.opts.file ?? DEFAULT_FILE;
  if (!existsSync(file)) return { code: 3, lines: ['bench-candidate: no candidate results file'] };

  const parsed = readJson(file);
  if (parsed.error) return { code: 1, lines: [`bench-candidate: ${file} is not JSON: ${parsed.error}`] };
  const { sha, tag } = parsed.value ?? {};
  if (typeof sha !== 'string' || !SHA.test(sha)) return { code: 1, lines: [`bench-candidate: ${file} has no 40-hex sha`] };

  const top = git(['rev-parse', '--show-toplevel']);
  if (top.status !== 0) return { code: 1, lines: ['bench-candidate: not in a git repository'] };
  const self = relative(top.stdout.trim(), resolve(file)).split('\\').join('/');

  const anc = git(['merge-base', '--is-ancestor', sha, 'HEAD']);
  if (anc.status !== 0) {
    return { code: 1, lines: [`bench-candidate: measured at ${sha}, which is not an ancestor of HEAD; re-measure`] };
  }
  const diff = git(['-C', top.stdout.trim(), 'diff', '--name-only', '--no-renames', '-z', sha, 'HEAD']);
  if (diff.status !== 0) return { code: 1, lines: [`bench-candidate: cannot diff ${sha} with HEAD`] };
  const changed = diff.stdout.split('\0').filter(f => f && f !== self);
  if (changed.length) {
    const shown = changed.slice(0, MAX_LISTED).join(', ');
    const more = changed.length > MAX_LISTED ? ` and ${changed.length - MAX_LISTED} more` : '';
    return { code: 1, lines: [`bench-candidate: measured at ${sha}; changed since: ${shown}${more}; re-measure`] };
  }
  return { code: 0, lines: [`bench-candidate: measured at ${sha} (${tag}); nothing but the results file changed since`] };
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === 'write') return write(rest);
  if (cmd === 'check') return check(rest);
  return { code: 2, lines: ['bench-candidate: commands: write | check'] };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const result = main(process.argv.slice(2));
  console.log(result.lines.join('\n'));
  process.exitCode = result.code;
}
