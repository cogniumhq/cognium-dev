/**
 * `.vue` single-file components are scanned: a folder holding only `.vue`
 * files is collected, and a `v-html` binding fed by the script's URL input is
 * reported as XSS at the template line.
 */
import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { collectFiles } from '../src/cli';

const CLI = resolve(import.meta.dir, '../src/cli.ts');

const BANNER = [
  '<template>',
  '  <div v-html="message"></div>',
  '</template>',
  '',
  '<script setup>',
  'const params = new URLSearchParams(window.location.search);',
  "const message = params.get('msg');",
  '</script>',
  '',
].join('\n');

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'cog-vue-'));
  writeFileSync(join(root, 'Banner.vue'), BANNER);
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('Vue single-file components', () => {
  test('a folder of .vue files is collected', async () => {
    expect(await collectFiles(root)).toEqual([join(root, 'Banner.vue')]);
    expect(await collectFiles(root, { language: 'vue' })).toEqual([join(root, 'Banner.vue')]);
  });

  test('v-html bound to URL input is reported at the template line', async () => {
    const out = join(root, 'report.json');
    const proc = Bun.spawn(['bun', 'run', CLI, 'scan', root, '-f', 'json', '--category', 'security', '-q', '-o', out], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env, NO_COLOR: '1' },
      cwd: root,
    });
    expect(await proc.exited).toBe(1);
    const report = JSON.parse(await Bun.file(out).text()) as {
      results: Array<{ file: string; vulnerabilities: Array<{ type: string; line: number; cwe?: string; message: string }> }>;
    };
    const vulns = report.results.flatMap((r) => r.vulnerabilities.map((v) => ({ ...v, file: r.file })));
    expect(vulns).toEqual([
      expect.objectContaining({
        file: join(root, 'Banner.vue'),
        type: 'xss',
        line: 2,
        cwe: 'CWE-79',
        message: expect.stringContaining('from line 7 to line 2'),
      }),
    ]);
  }, 60_000);
});
