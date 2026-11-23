#!/usr/bin/env node
// Regex lint gate (S3). Lints `packages/*/src` with `eslint.regex.config.mjs`
// and fails when:
//   - any regex is reported as certain to backtrack exponentially, or
//   - a file has more super-linear regex reports than
//     `scripts/regex-lint-baseline.json` allows.
// The baseline records what main had when the gate landed; it may only go
// down. After fixing regexes, run `node scripts/regex-lint.mjs --update`.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = join(ROOT, 'scripts', 'regex-lint-baseline.json');
const EXPONENTIAL = /is going to cause exponential backtracking/;

/** `{ file: count }` of super-linear reports, and the certain-exponential ones. */
export function summarize(results, root = ROOT) {
  const counts = {};
  const exponential = [];
  for (const r of results) {
    const file = relative(root, r.filePath).split('\\').join('/');
    for (const m of r.messages) {
      if (!m.ruleId?.startsWith('regexp/')) continue;
      counts[file] = (counts[file] ?? 0) + 1;
      if (EXPONENTIAL.test(m.message)) exponential.push(`${file}:${m.line}:${m.column} ${m.message}`);
    }
  }
  return { counts: Object.fromEntries(Object.entries(counts).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))), exponential };
}

/** Files above their baseline, and files below it (the baseline can be lowered). */
export function compare(baseline, counts) {
  const over = [];
  const under = [];
  for (const file of new Set([...Object.keys(baseline), ...Object.keys(counts)])) {
    const was = baseline[file] ?? 0;
    const now = counts[file] ?? 0;
    if (now > was) over.push({ file, was, now });
    else if (now < was) under.push({ file, was, now });
  }
  const byFile = (a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0);
  return { over: over.sort(byFile), under: under.sort(byFile) };
}

async function main() {
  const { ESLint } = await import('eslint');
  const eslint = new ESLint({ cwd: ROOT, overrideConfigFile: join(ROOT, 'eslint.regex.config.mjs') });
  const { counts, exponential } = summarize(await eslint.lintFiles(['packages/*/src/**/*.ts']));
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (process.argv.includes('--update')) {
    writeFileSync(BASELINE, JSON.stringify(counts, null, 2) + '\n');
    console.log(`regex-lint: baseline written (${total} reports in ${Object.keys(counts).length} files)`);
    return exponential.length ? 1 : 0;
  }
  const baseline = JSON.parse(readFileSync(BASELINE, 'utf8'));
  const { over, under } = compare(baseline, counts);
  for (const e of exponential) console.error(`regex-lint: exponential backtracking: ${e}`);
  for (const o of over) console.error(`regex-lint: ${o.file}: ${o.now} super-linear regex reports, baseline ${o.was}`);
  if (under.length) console.log(`regex-lint: ${under.length} file(s) below baseline; lower it with --update`);
  console.log(`regex-lint: ${total} super-linear reports in ${Object.keys(counts).length} files (baseline ${Object.values(baseline).reduce((a, b) => a + b, 0)}); ${exponential.length} exponential`);
  return exponential.length || over.length ? 1 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = await main();
}
