/**
 * Check that a release's changelog sections list every merged PR.
 *
 * Usage: node scripts/changelog-prs.mjs <since-tag> <version> <changelog>...
 *
 * Reads the first-parent commits in `<since-tag>..HEAD`, takes the PR number
 * a squash merge appends (`… (#1234)`), and checks that each changelog's
 * `## [<version>]` section mentions `#1234`. A PR that changed shipped code
 * without a changelog line is easy to miss in review; this lists them.
 *
 * Exit 0: every PR listed. 1: some missing (named on stderr). 2: usage error,
 * or a changelog has no section for the version.
 */
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** The PR number GitHub appends to a squash-merge subject, or null. */
export function prNumber(subject) {
  const m = /\(#(\d+)\)\s*$/.exec(subject);
  return m ? Number(m[1]) : null;
}

/** The body of `## [version]`, up to the next `## [` heading, or null. */
export function changelogSection(text, version) {
  const lines = text.split('\n');
  const start = lines.findIndex(l => l.startsWith(`## [${version}]`));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && l.startsWith('## ['));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join('\n');
}

/** The PR numbers that `section` does not mention as `#N`. */
export function missingPrs(section, prs) {
  return prs.filter(n => !new RegExp(`#${n}(?!\\d)`).test(section));
}

function main(args) {
  const [since, version, ...files] = args;
  if (!since || !version || files.length === 0) {
    console.error('usage: changelog-prs.mjs <since-tag> <version> <changelog>...');
    return 2;
  }
  const subjects = execFileSync('git', ['log', '--first-parent', '--format=%s', `${since}..HEAD`], { encoding: 'utf8' })
    .split('\n').filter(Boolean);
  const prs = subjects.map(prNumber).filter(n => n !== null);
  let code = 0;
  for (const file of files) {
    const section = changelogSection(readFileSync(file, 'utf8'), version);
    if (section === null) {
      console.error(`${file}: no ## [${version}] section`);
      return 2;
    }
    const missing = missingPrs(section, prs);
    if (missing.length) {
      console.error(`${file}: [${version}] does not list ${missing.length} of ${prs.length} PRs: ${missing.map(n => `#${n}`).join(' ')}`);
      code = 1;
    } else {
      console.log(`${file}: [${version}] lists all ${prs.length} PRs since ${since}`);
    }
  }
  return code;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exit(main(process.argv.slice(2)));
