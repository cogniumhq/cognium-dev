/**
 * Tests for cognium-dev #213 — tenth slice: modern JS/TS framework
 * request sources.
 *
 * Covers the four major frameworks whose request-URL / route-args
 * shapes were previously invisible to the engine:
 *
 *   - NextJS App Router — `req.nextUrl.searchParams.get('id')`
 *   - Angular            — `route.snapshot.params['id']` /
 *                          `queryParams` / `paramMap.get(id)`
 *   - Remix              — `({ params, request })` destructure +
 *                          `new URL(request.url).searchParams`
 *   - SvelteKit          — `({ params, url })` destructure +
 *                          `url.searchParams.get('q')` +
 *                          `event.request`
 *
 * Coverage is via a mix of property-source patterns (in config-loader)
 * and regex entries in JS_TAINTED_PATTERNS. The regex layer is scoped
 * enough (searchParams.get / event.url / route.snapshot.*) to avoid
 * unrelated code, but keep an eye on FP reports for the URL-based
 * matches — WHATWG URL is broadly used outside request handlers.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 tenth slice — modern JS/TS framework sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows?.length ?? 0) > 0;

  it('NextJS App Router — `req.nextUrl.searchParams.get(...)` flows', async () => {
    const code = `import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';

export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get('id');
  exec('ls /users/' + id);
  return NextResponse.json({});
}`;
    const r = await analyze(code, 'route.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('Angular — `route.snapshot.params[\'id\']` flows', async () => {
    const code = `import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({ selector: 'user' })
export class UserComponent {
  constructor(private route: ActivatedRoute) {}
  loadUser() {
    const id = this.route.snapshot.params['id'];
    fetch('/api/user/' + id);
  }
}`;
    const r = await analyze(code, 'user.component.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('Remix loader — `params.id` + `URL.searchParams` flow to command exec', async () => {
    const code = `import type { LoaderArgs } from '@remix-run/node';
import { exec } from 'child_process';

export async function loader({ params, request }: LoaderArgs) {
  const id = params.id;
  const url = new URL(request.url);
  const q = url.searchParams.get('q');
  exec('grep ' + q + ' /var/log/user-' + id);
  return {};
}`;
    const r = await analyze(code, 'route.tsx', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('SvelteKit — `event.params.id` + `event.url.searchParams.get(...)` flow', async () => {
    const code = `import type { RequestHandler } from '@sveltejs/kit';
import { exec } from 'child_process';

export const GET: RequestHandler = async ({ params, url }) => {
  const id = params.id;
  const q = url.searchParams.get('q');
  exec('grep ' + q + ' /var/log/user-' + id);
  return new Response();
};`;
    const r = await analyze(code, 'route.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('SvelteKit — `event.request.formData()` flows', async () => {
    const code = `import type { RequestHandler } from '@sveltejs/kit';
import { exec } from 'child_process';

export const POST: RequestHandler = async ({ request }) => {
  const form = await request.formData();
  const name = form.get('name') as string;
  exec('echo ' + name);
  return new Response();
};`;
    const r = await analyze(code, 'route.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });
});
