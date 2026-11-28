/**
 * Go cross-file taint through a helper that forwards to another helper.
 *
 * A handler passed a request value to a helper in another file, and that
 * helper handed it unchanged to a second helper holding the sink
 * (`Continue` → `nav.Back` → `redirectTo` → `http.Redirect`). The cross-file
 * flow stopped at the first helper because it holds no sink itself. The
 * forwarding chain is now followed, in the same file or another file of the
 * same package (directory).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

type Project = Awaited<ReturnType<typeof analyzeProject>>;

const redirectPaths = (r: Project) =>
  (r.taint_paths ?? []).filter(p => p.sink?.type === 'open_redirect' && p.source?.file !== p.sink?.file);

const handler = (importLine: string, call: string) => ({
  filePath: 'internal/web/controllers/x/controller.go',
  language: 'go' as const,
  code: [
    'package x',
    '',
    'import (',
    '\t"net/http"',
    '',
    `\t${importLine}`,
    ')',
    '',
    'func Continue(w http.ResponseWriter, r *http.Request) {',
    '\ttarget := r.URL.Query().Get("next")',
    `\t${call}`,
    '}',
  ].join('\n'),
});

const helper = (filePath: string, body: string[]) => ({
  filePath,
  language: 'go' as const,
  code: ['package x', '', 'import "net/http"', '', ...body].join('\n'),
});

beforeAll(async () => {
  await initAnalyzer();
});

describe('Go cross-file flow through a forwarding helper', () => {
  it('nested package: handler → exported helper → unexported helper with the sink', async () => {
    const r = await analyzeProject([
      handler('nav "example.com/app/internal/web/x"', 'nav.Back(w, r, target)'),
      helper('internal/web/x/nav.go', [
        'func Back(w http.ResponseWriter, r *http.Request, target string) {',
        '\tredirectTo(w, r, target)',
        '}',
        '',
        'func redirectTo(w http.ResponseWriter, r *http.Request, target string) {',
        '\thttp.Redirect(w, r, target, http.StatusFound)',
        '}',
      ]),
    ]);
    const paths = redirectPaths(r);
    expect(paths).toHaveLength(1);
    expect(paths[0]).toMatchObject({
      source: { file: 'internal/web/controllers/x/controller.go', line: 10, type: 'http_param' },
      sink: { file: 'internal/web/x/nav.go', line: 10 },
    });
  });

  it('the second hop may sit in another file of the same package', async () => {
    const r = await analyzeProject([
      handler('nav "example.com/app/internal/web/x"', 'nav.Back(w, r, target)'),
      helper('internal/web/x/back.go', [
        'func Back(w http.ResponseWriter, r *http.Request, target string) {',
        '\tredirectTo(w, r, target)',
        '}',
      ]),
      helper('internal/web/x/redirect.go', [
        'func redirectTo(w http.ResponseWriter, r *http.Request, target string) {',
        '\thttp.Redirect(w, r, target, http.StatusFound)',
        '}',
      ]),
    ]);
    expect(redirectPaths(r).map(p => p.sink?.file)).toEqual(['internal/web/x/redirect.go']);
  });

  // ---------------------------------------------------------------------
  // Negatives
  // ---------------------------------------------------------------------

  it('negative: the helper forwards a constant, not the parameter', async () => {
    const r = await analyzeProject([
      handler('nav "example.com/app/internal/web/x"', 'nav.Back(w, r, target)'),
      helper('internal/web/x/nav.go', [
        'func Back(w http.ResponseWriter, r *http.Request, target string) {',
        '\t_ = target',
        '\tredirectTo(w, r, "/home")',
        '}',
        '',
        'func redirectTo(w http.ResponseWriter, r *http.Request, to string) {',
        '\thttp.Redirect(w, r, to, http.StatusFound)',
        '}',
      ]),
    ]);
    expect(redirectPaths(r)).toHaveLength(0);
  });

  it('negative: the helper forwards a different parameter than the tainted one', async () => {
    const r = await analyzeProject([
      handler('nav "example.com/app/internal/web/x"', 'nav.Back(w, r, target, "/home")'),
      helper('internal/web/x/nav.go', [
        'func Back(w http.ResponseWriter, r *http.Request, target string, fallback string) {',
        '\t_ = target',
        '\tredirectTo(w, r, fallback)',
        '}',
        '',
        'func redirectTo(w http.ResponseWriter, r *http.Request, to string) {',
        '\thttp.Redirect(w, r, to, http.StatusFound)',
        '}',
      ]),
    ]);
    expect(redirectPaths(r)).toHaveLength(0);
  });

  it('negative: a same-named function in another package is not the forwarder target', async () => {
    const r = await analyzeProject([
      handler('nav "example.com/app/internal/web/x"', 'nav.Back(w, r, target)'),
      helper('internal/web/x/nav.go', [
        'func Back(w http.ResponseWriter, r *http.Request, target string) {',
        '\tlogVisit(w, r, target)',
        '}',
      ]),
      helper('internal/other/y/visit.go', [
        'func logVisit(w http.ResponseWriter, r *http.Request, target string) {',
        '\thttp.Redirect(w, r, target, http.StatusFound)',
        '}',
      ]),
    ]);
    expect(redirectPaths(r)).toHaveLength(0);
  });
});
