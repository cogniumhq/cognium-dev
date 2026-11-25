/**
 * #1305 R1, the rest of the text paths: every place a scanned file or folder
 * name reaches the terminal goes through `termSafe`, so a hostile name can't
 * recolour the terminal, move the cursor or forge an output line. JSON and
 * SARIF keep the raw name (covered in formatters.test.ts).
 */
import { describe, test, expect, spyOn } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, copyFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { spinnerFileLabel, termSafe } from '../src/utils/term-safe';
import { formatResults } from '../src/formatters';
import { deadCodeText, depCallsText, entriesText, reachText, registrationFiles } from '../src/graph-facts';

const CLI = resolve(import.meta.dir, '../src/cli.ts');
const WATCHDOG = resolve(import.meta.dir, '../src/file-watchdog.ts');
const VULN_FILE = resolve(import.meta.dir, 'fixtures', 'VulnController.java');

/** A name that tries to set the window title, ring the bell and forge a line. */
const EVIL = 'src/a\x1b]0;pwned\x07\n[OK] forged.java';
const EVIL_SHOWN = 'src/a\\x1b]0;pwned\\x07\\x0a[OK] forged.java';

/** Nothing raw from the name: no ESC, no BEL, no forged line. */
function expectSafe(text: string): void {
  expect(text).not.toContain('\x1b]0;');
  expect(text).not.toContain('\x07');
  expect(text.split('\n').some(l => l.startsWith('[OK] forged'))).toBe(false);
}

describe('termSafe: the added marks (review nit)', () => {
  test('direction marks and the line and paragraph separators are escaped too', () => {
    expect(termSafe('a‎b‏c؜d')).toBe('a\\u{200e}b\\u{200f}c\\u{61c}d');
    expect(termSafe('a b c')).toBe('a\\u{2028}b\\u{2029}c');
    expect(termSafe('src\\win\\Ünï.ts')).toBe('src\\win\\Ünï.ts');
  });
});

describe('scan and metrics spinners', () => {
  test('the label is escaped', () => {
    const label = spinnerFileLabel(EVIL);
    expectSafe(label);
    expect(label).toBe(EVIL_SHOWN);
  });

  test('a long name is escaped before it is cut, so the cut never splits an escape', () => {
    const long = `${'d/'.repeat(60)}x\x1by.java`;
    const label = spinnerFileLabel(long);
    expect(label.length).toBe(80);
    expect(label.startsWith('...')).toBe(true);
    expect(label.endsWith('x\\x1by.java')).toBe(true);
    expect(label).not.toContain('\x1b');
  });
});

describe('graph-facts text reports', () => {
  const engine = { package: 'circle-ir' as const, version: '0.0.0' };
  const partialFiles = [{ file: EVIL, line: 3, column: 1, nodeKind: 'ERROR', parent: 'class_body' }];

  test('dep-calls: call sites, the covering test and unattributed sites', () => {
    const text = depCallsText({
      root: '/r', language: 'java', engine, artifact: 'g:a', packages: ['p'], packageSource: 'jar',
      calls: [{ site: { file: EVIL, line: 4 }, receiver: 'r', methodName: 'm', tests: [{ class: 'strong', file: EVIL, line: 9 }] }],
      unattributedSites: [{ site: { file: EVIL, line: 5 }, receiver: 'r', methodName: 'n' }],
      uncovered: 0, unattributed: 1, covered: true, partial: [],
    } as never);
    expectSafe(text);
    expect(text).toContain(`${EVIL_SHOWN}:4`);
    expect(text).toContain(`← ${EVIL_SHOWN}:9`);
    expect(text).toContain(`unattributed ${EVIL_SHOWN}:5`);
  });

  test('dep-calls: the partial list', () => {
    const text = depCallsText({
      root: '/r', language: 'java', engine, artifact: 'g:a', packages: ['p'], packageSource: 'jar',
      calls: [], unattributedSites: [],
      uncovered: 0, unattributed: 0, covered: true, partial: ['ok.java', EVIL],
    } as never);
    expectSafe(text);
    expect(text).toContain(`partial: ok.java, ${EVIL_SHOWN}`);
  });

  test('dead code: facts and the files that did not parse', () => {
    const text = deadCodeText({
      root: '/r', language: 'java', engine, scheme: 's', rootKinds: ['main'], partialFiles,
      summary: { live: 0, 'may-be-live': 0, dead: 1, reachedByTestOnly: 0 }, verdicts: ['dead'],
      facts: [{ id: 'd1', verdict: 'dead', file: EVIL, qualified_name: 'A.b', kind: 'method', reasons: [], reachedByTest: false }],
      locations: { d1: [7, 1] },
    } as never);
    expectSafe(text);
    expect(text).toContain(`dead        ${EVIL_SHOWN}:7`);
    expect(text).toContain(`${EVIL_SHOWN}:3:1  ERROR in class_body`);
  });

  test('removal reach: removed and moved files', () => {
    const text = reachText({
      root: '/r', base: 'main', language: 'java', engine, scheme: 's', partialFiles: [],
      removed: [{ file: EVIL, qualified_name: 'A.b', id: 'x', kind: 'method', strong: null, weak: null, unresolvedCount: 0, moveCandidates: [] }],
      moved: [{ from: EVIL, to: `${EVIL}2`, relation: 'rename' }],
      locations: {},
    } as never);
    expectSafe(text);
    expect(text).toContain(`removed  ${EVIL_SHOWN}  A.b`);
    expect(text).toContain(`moved    ${EVIL_SHOWN} → ${EVIL_SHOWN}2`);
  });

  test('entry points', () => {
    const text = entriesText({
      root: '/r', language: 'java', engine, entryIndexDigest: 'x', unresolvedRegistrations: [], partial: [], partialFiles: [],
      summary: { http: 1 }, entries: [{ kind: 'http', certainty: 'certain', file: EVIL, line: 2, method: 'GET', path: '/x' }],
    } as never);
    expectSafe(text);
    expect(text).toContain(`${EVIL_SHOWN}:2 GET /x`);
  });
});

/** A route path from a string literal in the scanned source, with the same payload. */
const EVIL_ROUTE = '/a\x1b]0;pwned\x07\n[OK] forged';
const EVIL_ROUTE_SHOWN = '/a\\x1b]0;pwned\\x07\\x0a[OK] forged';

describe('graph-facts route paths (#1394 follow-up)', () => {
  const engine = { package: 'circle-ir' as const, version: '0.0.0' };

  test('entry points: the route method and path are escaped', () => {
    const text = entriesText({
      root: '/r', language: 'java', engine, entryIndexDigest: 'x', unresolvedRegistrations: [], partial: [], partialFiles: [],
      summary: { http: 2 }, entries: [
        { kind: 'http', certainty: 'certain', file: 'A.java', line: 2, method: 'GET', path: EVIL_ROUTE },
        { kind: 'http', certainty: 'certain', file: 'B.java', line: 3, path: EVIL_ROUTE },
      ],
    } as never);
    expectSafe(text);
    expect(text).toContain(`A.java:2 GET ${EVIL_ROUTE_SHOWN}`);
    expect(text).toContain(`B.java:3 ${EVIL_ROUTE_SHOWN}`);
  });

  test('removal reach: the path of the entry a removed declaration is reached from is escaped', () => {
    const text = reachText({
      root: '/r', base: 'main', language: 'java', engine, scheme: 's', partialFiles: [], moved: [], locations: {},
      removed: [{ file: 'A.java', qualified_name: 'A.b', id: 'x', kind: 'method', strong: { entry: { kind: 'http', path: EVIL_ROUTE } }, weak: null, unresolvedCount: 0, moveCandidates: [] }],
    } as never);
    expectSafe(text);
    expect(text).toContain(`strong from http ${EVIL_ROUTE_SHOWN}`);
  });

  test('an ordinary route is unchanged', () => {
    const text = entriesText({
      root: '/r', language: 'java', engine, entryIndexDigest: 'x', unresolvedRegistrations: [], partial: [], partialFiles: [],
      summary: { http: 1 }, entries: [{ kind: 'http', certainty: 'certain', file: 'A.java', line: 2, method: 'POST', path: '/api/v1/users/{id}' }],
    } as never);
    expect(text).toContain('A.java:2 POST /api/v1/users/{id}');
  });
});

describe('project profile folder names', () => {
  test('the profile block in text results escapes a module folder', () => {
    const prev = process.env.NO_COLOR;
    process.env.NO_COLOR = '1';
    try {
      const out = formatResults([], false, undefined, {
        modules: [{ root: EVIL, profile: 'web-app', reasons: ['pom'] }], unknownFileCount: 0,
      } as never);
      expectSafe(out);
      expect(out).toContain(`${EVIL_SHOWN}  →  web-app`);
    } finally {
      if (prev === undefined) delete process.env.NO_COLOR; else process.env.NO_COLOR = prev;
    }
  });
});

async function runCli(cwd: string, ...args: string[]): Promise<{ stdout: string; stderr: string }> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], { stdout: 'pipe', stderr: 'pipe', env: { ...process.env, NO_COLOR: '1' }, cwd });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  await proc.exited;
  return { stdout, stderr };
}

/** A scan root holding one Java file in a folder named with ESC, BEL and a newline. */
function hostileTree(): { root: string; dirShown: string } {
  const root = mkdtempSync(join(tmpdir(), 'termsafe-'));
  const dir = 'mod\x1b]0;pwned\x07\n[OK] forged';
  mkdirSync(join(root, dir));
  copyFileSync(VULN_FILE, join(root, dir, 'VulnController.java'));
  writeFileSync(join(root, dir, 'pom.xml'), '<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>');
  return { root, dirShown: 'mod\\x1b]0;pwned\\x07\\x0a[OK] forged' };
}

describe('graph-facts oversized registering file warning', () => {
  test('the skipped file is named escaped', () => {
    const { root, dirShown } = hostileTree();
    const warn = spyOn(console, 'error').mockImplementation(() => {});
    try {
      writeFileSync(join(root, 'mod\x1b]0;pwned\x07\n[OK] forged', 'plugin.xml'), `<plugin>${' '.repeat(200)}</plugin>`);
      expect(registrationFiles(root, 80).map(f => f.path)).toEqual([]);
      expect(warn).toHaveBeenCalledTimes(1);
      const msg = String(warn.mock.calls[0][0]);
      expectSafe(msg);
      expect(msg).toContain(`Warning: ${dirShown}/plugin.xml is `);
    } finally {
      warn.mockRestore();
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('metrics text output', () => {
  test('each file name line is escaped', async () => {
    const { root, dirShown } = hostileTree();
    try {
      const { stdout } = await runCli(root, 'metrics', root, '-q');
      expectSafe(stdout);
      expect(stdout).toContain(`${dirShown}/VulnController.java`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);
});

describe('--project-profile-explain', () => {
  test('module folders and build files are escaped', async () => {
    const { root, dirShown } = hostileTree();
    try {
      const { stderr } = await runCli(root, 'scan', root, '-q', '--project-profile-explain');
      expectSafe(stderr);
      expect(stderr).toContain(`${dirShown}/pom.xml`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);
});

describe('file watchdog timeout message', () => {
  test('the stopped file is named escaped on stderr', async () => {
    const block = 'const until = Date.now() + 15000; while (Date.now() < until) {}';
    const script = `
      const { startFileWatchdog } = await import(${JSON.stringify(WATCHDOG)});
      const w = startFileWatchdog(300);
      await new Promise(r => setTimeout(r, 200));
      w.onFileStart(${JSON.stringify(EVIL)});
      ${block}
    `;
    const proc = Bun.spawn(['bun', '-e', script], { stdout: 'pipe', stderr: 'pipe' });
    const stderr = await new Response(proc.stderr).text();
    await proc.exited;
    expectSafe(stderr);
    expect(stderr).toContain(`Error: analysis of ${EVIL_SHOWN} ran past --file-timeout-ms 300`);
  }, 20_000);
});
