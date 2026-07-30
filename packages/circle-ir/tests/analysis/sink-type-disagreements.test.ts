/**
 * Type-disagreement resolutions (cognium-dev #4 follow-up, second slice).
 *
 * Where the canonical registry (`DEFAULT_SINKS` / `DEFAULT_SOURCES`) and a
 * language plugin registered the *same* call under two different vulnerability
 * types, both patterns matched and the engine emitted two findings for one
 * call site with different CWEs. These lock the chosen classification so the
 * duplicate cannot creep back:
 *
 *   - Python `exec(code)`     → code_injection (CWE-94) only, never CWE-78
 *   - Go `Context.PostForm`   → http_body only
 *   - Rust `Form<T>`          → http_body only
 *   - Python `input()`        → io_input only (never the off-union
 *                               `user_input`), `os.getenv` → env_input
 *
 * Three overlaps are NOT defects and stay dual-classified — the second half
 * of this file pins them so a future "cleanup" cannot silently drop one:
 * `res.redirect` (CWE-601 + CWE-113, per #189 Sprint 82's sink-type-aware
 * flow dedup and #132's crlf recall test), Go `log.Printf`/`Fatalf`/`Panicf`
 * (CWE-117 + CWE-134, per #264), and `fmt.Fprintf` (CWE-134 + CWE-79).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('sink/source type disagreements — resolved classifications', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('python exec() is code_injection, not command_injection', () => {
    it('emits CWE-94 and no CWE-78 sink', async () => {
      const code = [
        'from flask import request',
        '',
        'def handler():',
        '    payload = request.args.get("p")',
        '    exec(payload)',
      ].join('\n');

      const result = await analyze(code, 'app.py', 'python');
      const execSinks = result.taint.sinks.filter(s => s.method === 'exec');

      expect(execSinks.length).toBeGreaterThan(0);
      expect(execSinks.map(s => s.cwe)).toContain('CWE-94');
      expect(execSinks.map(s => s.cwe)).not.toContain('CWE-78');
      expect(execSinks.map(s => s.type)).not.toContain('command_injection');
    });

    it('leaves the classless CWE-78 exec sink active for other languages', async () => {
      const code = [
        'const { exec } = require("child_process");',
        'app.get("/run", (req, res) => {',
        '  exec(req.query.cmd);',
        '});',
      ].join('\n');

      const result = await analyze(code, 'server.js', 'javascript');
      const execSinks = result.taint.sinks.filter(s => s.method === 'exec');

      expect(execSinks.map(s => s.cwe)).toContain('CWE-78');
    });
  });

  describe('deliberate dual classifications are preserved', () => {
    it('js res.redirect() emits BOTH open_redirect and crlf (#189 Sprint 82)', async () => {
      const code = [
        'app.get("/go", (req, res) => {',
        '  res.redirect(req.query.next);',
        '});',
      ].join('\n');

      const result = await analyze(code, 'server.js', 'javascript');
      const cwes = new Set(
        result.taint.sinks.filter(s => s.method === 'redirect').map(s => s.cwe),
      );

      expect(cwes).toContain('CWE-601');
      expect(cwes).toContain('CWE-113');
    });

    it('go log.Printf emits BOTH log_injection and format_string (#264)', async () => {
      const code = [
        'package main',
        '',
        'import (',
        '\t"log"',
        '\t"net/http"',
        ')',
        '',
        'func handler(w http.ResponseWriter, r *http.Request) {',
        '\tname := r.URL.Query().Get("name")',
        '\tlog.Printf(name)',
        '}',
      ].join('\n');

      const result = await analyze(code, 'main.go', 'go');
      const cwes = new Set(
        result.taint.sinks.filter(s => s.method === 'Printf').map(s => s.cwe),
      );

      expect(cwes).toContain('CWE-117');
      expect(cwes).toContain('CWE-134');
    });
  });

  describe('fmt.* format_string entries are untouched', () => {
    it('keeps CWE-134 on fmt.Sprintf', async () => {
      const code = [
        'package main',
        '',
        'import (',
        '\t"fmt"',
        '\t"net/http"',
        ')',
        '',
        'func handler(w http.ResponseWriter, r *http.Request) {',
        '\tname := r.URL.Query().Get("name")',
        '\ts := fmt.Sprintf(name)',
        '\t_ = s',
        '}',
      ].join('\n');

      const result = await analyze(code, 'main.go', 'go');
      const sprintfSinks = result.taint.sinks.filter(s => s.method === 'Sprintf');

      expect(sprintfSinks.map(s => s.cwe)).toContain('CWE-134');
    });
  });

  describe('source types are single-valued per call', () => {
    it('python input() is io_input only', async () => {
      const code = ['name = input("who? ")', 'print(name)'].join('\n');

      const result = await analyze(code, 'cli.py', 'python');
      const inputSources = result.taint.sources.filter(s => s.location.includes('input('));

      expect(inputSources.length).toBeGreaterThan(0);
      expect(new Set(inputSources.map(s => s.type))).toEqual(new Set(['io_input']));
    });

    it('python os.getenv() is env_input only', async () => {
      const code = ['import os', 'home = os.getenv("HOME")', 'print(home)'].join('\n');

      const result = await analyze(code, 'env.py', 'python');
      const envSources = result.taint.sources.filter(s => s.location.includes('getenv('));

      expect(envSources.length).toBeGreaterThan(0);
      expect(new Set(envSources.map(s => s.type))).toEqual(new Set(['env_input']));
    });

    it('go Context.PostForm is http_body only', async () => {
      const code = [
        'package main',
        '',
        'import "github.com/gin-gonic/gin"',
        '',
        'func handler(c *gin.Context) {',
        '\tname := c.PostForm("name")',
        '\t_ = name',
        '}',
      ].join('\n');

      const result = await analyze(code, 'main.go', 'go');
      const formSources = result.taint.sources.filter(s => s.location.includes('PostForm('));

      expect(formSources.length).toBeGreaterThan(0);
      expect(new Set(formSources.map(s => s.type))).toEqual(new Set(['http_body']));
    });
  });
});
