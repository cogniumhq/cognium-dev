/**
 * An `external_taint_escape` at a call into another project file is dropped
 * when a resolved path from the same source follows the value through that
 * call to a real sink. An escape with no such path is kept.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';
import { dropEscapesExplainedByTaintPaths } from '../../src/analysis/explained-escape-gate.js';
import type { CircleIR, TaintPath } from '../../src/types/index.js';

const ESCAPE = 'external_taint_escape';

const redirectHelper = {
  filePath: 'redirect.go', language: 'go' as const, code: [
    'package main',
    '',
    'import "net/http"',
    '',
    'func redirectTo(w http.ResponseWriter, r *http.Request, target string) {',
    '\thttp.Redirect(w, r, target, http.StatusFound)',
    '}',
  ].join('\n'),
};

const handler = (body: string[]) => ({
  filePath: 'main.go', language: 'go' as const, code: [
    'package main',
    '',
    'import "net/http"',
    '',
    'func next(w http.ResponseWriter, r *http.Request) {',
    ...body,
    '}',
  ].join('\n'),
});

type Project = Awaited<ReturnType<typeof analyzeProject>>;
const flowsOf = (r: Project, file: string, type: string) =>
  (r.files.find(f => f.file === file)?.analysis.taint.flows ?? []).filter(f => f.sink_type === type);
const sinksOf = (r: Project, file: string, type: string) =>
  (r.files.find(f => f.file === file)?.analysis.taint.sinks ?? []).filter(s => s.type === type);

describe('explained escapes (project scan)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('Go: a redirect helper in another file is reported as the open redirect only', async () => {
    const r = await analyzeProject([
      handler(['\ttarget := r.URL.Query().Get("next")', '\tredirectTo(w, r, target)']),
      redirectHelper,
    ]);
    expect(flowsOf(r, 'main.go', ESCAPE)).toEqual([]);
    expect(sinksOf(r, 'main.go', ESCAPE)).toEqual([]);
    expect(r.taint_paths.map(p => p.sink.type)).toEqual(['open_redirect']);
    const path = r.taint_paths[0];
    expect(path.hops.map(h => `${h.file}:${h.line}`)).toEqual(['main.go:6', 'main.go:7', 'redirect.go:6']);
    // The sink file's own finding names the file its source is in.
    expect(flowsOf(r, 'redirect.go', 'open_redirect')).toEqual([
      expect.objectContaining({ source_file: 'main.go', source_line: 6, sink_line: 6 }),
    ]);
  });

  it('Go (gin): the same through a gin handler method', async () => {
    const r = await analyzeProject([
      {
        filePath: 'controller.go', language: 'go', code: [
          'package web',
          '',
          'import "github.com/gin-gonic/gin"',
          '',
          'type Controller struct{}',
          '',
          'func (ctrl *Controller) Continue(ctx *gin.Context) {',
          '\ttarget := ctx.Query("next")',
          '\tredirectTo(ctx.Writer, ctx.Request, target)',
          '}',
        ].join('\n'),
      },
      { ...redirectHelper, filePath: 'navigation.go', code: redirectHelper.code.replace('package main', 'package web') },
    ]);
    expect(flowsOf(r, 'controller.go', ESCAPE)).toEqual([]);
    expect(r.taint_paths.map(p => p.sink.type)).toEqual(['open_redirect']);
  });

  it('keeps an escape into a function no project file defines', async () => {
    const r = await analyzeProject([
      handler([
        '\ttarget := r.URL.Query().Get("next")',
        '\tredirectTo(w, r, target)',
        '\taudit := r.Header.Get("X-Audit")',
        '\trecordAudit(audit)',
      ]),
      redirectHelper,
    ]);
    expect(flowsOf(r, 'main.go', ESCAPE).map(f => f.sink_line)).toEqual([9]);
    expect(sinksOf(r, 'main.go', ESCAPE).map(s => s.line)).toEqual([9]);
    expect(r.taint_paths.some(p => p.sink.type === 'open_redirect')).toBe(true);
  });

  it('keeps an escape into a project function whose body has no sink', async () => {
    const r = await analyzeProject([
      handler(['\ttarget := r.URL.Query().Get("next")', '\tremember(target)']),
      {
        filePath: 'store.go', language: 'go', code: [
          'package main',
          '',
          'var saved string',
          '',
          'func remember(v string) {',
          '\tsaved = v',
          '}',
        ].join('\n'),
      },
    ]);
    expect(flowsOf(r, 'main.go', ESCAPE).map(f => f.sink_line)).toEqual([7]);
  });

  it('a single-file scan still reports the escape: it cannot see the helper', async () => {
    const h = handler(['\ttarget := r.URL.Query().Get("next")', '\tredirectTo(w, r, target)']);
    const ir = await analyze(h.code, h.filePath, h.language);
    expect((ir.taint.flows ?? []).filter(f => f.sink_type === ESCAPE).map(f => f.sink_line)).toEqual([7]);
  });
});

describe('dropEscapesExplainedByTaintPaths', () => {
  const ir = (flows: Array<{ source_line: number; sink_line: number; sink_type: string }>): CircleIR => ({
    taint: {
      sources: [],
      sinks: [...new Set(flows.map(f => f.sink_line))].map(line => ({ type: ESCAPE, cwe: 'CWE-668', location: '', line, confidence: 1 })),
      sanitizers: [],
      flows: flows.map(f => ({ ...f, source_type: 'http_param', path: [], confidence: 1, sanitized: false })),
    },
  }) as unknown as CircleIR;
  const hop = (file: string, line: number) => ({ file, line, method: '', code: '', variable: '' });
  const path = (sinkType: string, hops: Array<ReturnType<typeof hop>>): TaintPath => ({
    id: 'p',
    source: { file: hops[0].file, line: hops[0].line, type: 'http_param', code: '' },
    sink: { file: hops[hops.length - 1].file, line: hops[hops.length - 1].line, type: sinkType, cwe: '', code: '' },
    hops, sanitizers_in_path: [], path_exists: true, confidence: 1,
  }) as unknown as TaintPath;

  it('drops only the escape at the line where the path hands the value to another file', () => {
    const fa = [{
      file: 'a.go', analysis: ir([
        { source_line: 6, sink_line: 6, sink_type: ESCAPE },   // on the source line, but the path leaves at 7
        { source_line: 6, sink_line: 7, sink_type: ESCAPE },   // the hand-off: explained
        { source_line: 3, sink_line: 7, sink_type: ESCAPE },   // another source: kept
      ]),
    }];
    const kept = dropEscapesExplainedByTaintPaths(fa, [
      path('open_redirect', [hop('a.go', 6), hop('a.go', 7), hop('b.go', 2)]),
      path(ESCAPE, [hop('a.go', 6), hop('a.go', 7)]),
      path(ESCAPE, [hop('a.go', 3), hop('a.go', 7)]),
    ]);
    expect(fa[0].analysis.taint.flows!.map(f => `${f.source_line}->${f.sink_line}`)).toEqual(['6->6', '3->7']);
    // the sink at 7 stays: the flow from line 3 still reaches it
    expect(fa[0].analysis.taint.sinks.map(s => s.line).sort()).toEqual([6, 7]);
    expect(kept.map(p => `${p.sink.type}@${p.source.line}->${p.sink.line}`)).toEqual([
      'open_redirect@6->2', `${ESCAPE}@3->7`,
    ]);
  });

  it('a path that never leaves its file explains nothing', () => {
    const fa = [{ file: 'a.go', analysis: ir([{ source_line: 6, sink_line: 7, sink_type: ESCAPE }]) }];
    dropEscapesExplainedByTaintPaths(fa, [path('sql_injection', [hop('a.go', 6), hop('a.go', 7), hop('a.go', 9)])]);
    expect(fa[0].analysis.taint.flows).toHaveLength(1);
  });
});
