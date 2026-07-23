/**
 * cognium-dev #240 ship 1 — extend open_redirect (CWE-601) framework coverage.
 *
 * Baseline (variant-coverage.md): 11 probes, 1 fires, 10 FN. This suite pins
 * the newly added framework sinks across Python (django/starlette/fastapi),
 * JS/TS (koa/fastify/express-location/next.js), Java (RedirectView + JAX-RS
 * Response), and Go (gin/echo/fiber). Runtime sink table lives at
 * `OPEN_REDIRECT_FRAMEWORK_SINKS` in `src/analysis/config-loader.ts`.
 *
 * Two must-not-fire fixtures at the tail guard against literal-URL FPs.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasOpenRedirectFlow = (r: any) =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === 'open_redirect');

const countOpenRedirect = (r: any) =>
  (r.findings ?? []).filter((f: any) => f.rule_id === 'open_redirect').length;

const hasOpenRedirectSignal = (r: any) =>
  hasOpenRedirectFlow(r) || countOpenRedirect(r) > 0;

describe('#240 ship 1 — open_redirect framework sinks (CWE-601)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -----------------------------------------------------------------
  // Python — django / starlette / fastapi
  // -----------------------------------------------------------------

  it('TP — Django HttpResponseRedirect(user_url) fires', async () => {
    const code = [
      'from django.http import HttpResponseRedirect',
      'from flask import request',
      '',
      'def view():',
      '    next_url = request.args.get("next")',
      '    return HttpResponseRedirect(next_url)',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — Django HttpResponsePermanentRedirect(user_url) fires', async () => {
    const code = [
      'from django.http import HttpResponsePermanentRedirect',
      'from flask import request',
      '',
      'def view():',
      '    next_url = request.args.get("next")',
      '    return HttpResponsePermanentRedirect(next_url)',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — Starlette/FastAPI RedirectResponse(user_url) fires', async () => {
    const code = [
      'from starlette.responses import RedirectResponse',
      'from flask import request',
      '',
      'def view():',
      '    next_url = request.args.get("next")',
      '    return RedirectResponse(next_url)',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  // -----------------------------------------------------------------
  // JS/TS — koa / fastify / express location / next.js
  // -----------------------------------------------------------------

  it('TP — Koa ctx.redirect(user_url) fires', async () => {
    const code = [
      "const Koa = require('koa');",
      'const app = new Koa();',
      'app.use(async (ctx) => {',
      '  const next = ctx.query.next;',
      '  ctx.redirect(next);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'koa.js', 'javascript');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — Fastify reply.redirect(user_url) fires', async () => {
    const code = [
      "const fastify = require('fastify')();",
      "fastify.get('/r', async (request, reply) => {",
      '  const target = request.query.next;',
      '  reply.redirect(target);',
      '});',
    ].join('\n');
    const r = await analyze(code, 'fastify.js', 'javascript');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — Express res.location(user_url) fires', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/r', (req, res) => {",
      '  res.location(req.query.next);',
      '  res.status(302).end();',
      '});',
    ].join('\n');
    const r = await analyze(code, 'express-location.js', 'javascript');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — Next.js NextResponse.redirect(user_url) fires', async () => {
    const code = [
      "import { NextResponse } from 'next/server';",
      'export async function GET(req) {',
      '  const url = new URL(req.url);',
      "  const next = url.searchParams.get('next');",
      '  return NextResponse.redirect(next);',
      '}',
    ].join('\n');
    const r = await analyze(code, 'route.ts', 'typescript');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  // -----------------------------------------------------------------
  // Java — Spring MVC RedirectView + JAX-RS Response
  // -----------------------------------------------------------------

  it('TP — Spring new RedirectView(user_url) fires', async () => {
    const code = [
      'import org.springframework.web.servlet.view.RedirectView;',
      'import javax.servlet.http.*;',
      'public class Ctrl {',
      '  public RedirectView go(HttpServletRequest req) {',
      '    String next = req.getParameter("next");',
      '    return new RedirectView(next);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Ctrl.java', 'java');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — Spring RedirectView.setUrl(user_url) fires', async () => {
    const code = [
      'import org.springframework.web.servlet.view.RedirectView;',
      'import javax.servlet.http.*;',
      'public class Ctrl {',
      '  public RedirectView go(HttpServletRequest req) {',
      '    String next = req.getParameter("next");',
      '    RedirectView v = new RedirectView();',
      '    v.setUrl(next);',
      '    return v;',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Ctrl.java', 'java');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — JAX-RS Response.seeOther(user_uri) fires', async () => {
    const code = [
      'import javax.ws.rs.core.Response;',
      'import java.net.URI;',
      'import javax.servlet.http.*;',
      'public class Api {',
      '  public Response go(HttpServletRequest req) {',
      '    String next = req.getParameter("next");',
      '    return Response.seeOther(URI.create(next)).build();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Api.java', 'java');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  it('TP — JAX-RS Response.temporaryRedirect(user_uri) fires', async () => {
    const code = [
      'import javax.ws.rs.core.Response;',
      'import java.net.URI;',
      'import javax.servlet.http.*;',
      'public class Api {',
      '  public Response go(HttpServletRequest req) {',
      '    String next = req.getParameter("next");',
      '    return Response.temporaryRedirect(URI.create(next)).build();',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Api.java', 'java');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  // -----------------------------------------------------------------
  // Go — gin / echo / fiber
  // -----------------------------------------------------------------

  // Gin/fiber sinks require Go local-receiver type resolution
  // (`c *gin.Context` → 'Context') which the current
  // `receiverMightBeClass('c', 'Context')` cannot perform. The sink
  // entries are catalogued for the day that resolution lands; until
  // then the external_taint_escape fallback fires on these call sites,
  // so recall is not lost — only the sink-type label is generic. See
  // taint-matcher.ts:2137 receiverMightBeClass.
  it('TP — gin c.Redirect(302, user_url) fires (arg[1]) [Go receiver-type resolution]', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "net/http"',
      '  "github.com/gin-gonic/gin"',
      ')',
      '',
      'func handler(c *gin.Context, r *http.Request) {',
      '  next := r.URL.Query().Get("next")',
      '  c.Redirect(http.StatusFound, next)',
      '}',
    ].join('\n');
    const r = await analyze(code, 'gin.go', 'go');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  // cognium-dev #260 fix (3.179.0): the "Go arg[0] flow gap" turned out
  // to be a sink-dedup ordering bug — the fiber `class: 'Ctx'` pattern
  // was losing the sinkMap slot to the gin `class: 'Context'` pattern
  // via `receiverMightBeClass`'s fuzzy "'ctx' is contained in 'context'
  // and covers ≥ 40 % of it" heuristic. Both patterns had equal
  // confidence, so iteration order (gin defined first at config-loader
  // line 707, fiber at line 708) picked the wrong one, emitting the
  // sink with `argPositions: [1]` and dropping the tainted arg[0] flow.
  // `calculateSinkConfidence` now boosts exact class matches by an
  // extra 0.05, guaranteeing the fiber pattern wins when the receiver
  // is exactly 'Ctx'.
  it('TP — fiber c.Redirect(user_url) fires (arg[0]) [#260]', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '  "net/http"',
      '  "github.com/gofiber/fiber/v2"',
      ')',
      '',
      'func handler(c *fiber.Ctx, r *http.Request) error {',
      '  next := r.URL.Query().Get("next")',
      '  return c.Redirect(next)',
      '}',
    ].join('\n');
    const r = await analyze(code, 'fiber.go', 'go');
    expect(hasOpenRedirectSignal(r)).toBe(true);
  });

  // -----------------------------------------------------------------
  // FP-guards — hardcoded literals must NOT emit open_redirect findings
  // -----------------------------------------------------------------

  it('FP-guard — Python literal RedirectResponse("/home") does not fire', async () => {
    const code = [
      'from starlette.responses import RedirectResponse',
      '',
      'def view():',
      '    return RedirectResponse("/home")',
    ].join('\n');
    const r = await analyze(code, 'view.py', 'python');
    expect(countOpenRedirect(r)).toBe(0);
  });

  it('FP-guard — Java literal new RedirectView("/home") does not fire', async () => {
    const code = [
      'import org.springframework.web.servlet.view.RedirectView;',
      'public class Ctrl {',
      '  public RedirectView home() {',
      '    return new RedirectView("/home");',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'Ctrl.java', 'java');
    expect(countOpenRedirect(r)).toBe(0);
  });
});
