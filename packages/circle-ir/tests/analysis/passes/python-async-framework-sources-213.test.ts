/**
 * Tests for cognium-dev #213 — eleventh slice: async Python framework
 * source parity.
 *
 * Prior aiohttp coverage was `.json/.post/.text` methods and
 * `request.query / match_info` properties. This slice extends:
 *
 *   - aiohttp — `request.rel_url` (parsed URL — modern query-param
 *               idiom `request.rel_url.query.get('q')`),
 *               `request.remote` (client IP), `request.raw_headers`,
 *               `request.transport` (peer_name).
 *   - Quart (async Flask) — `Request.get_json` / `get_data` / `form` /
 *               `files` return-tainted method sources. Regex layer for
 *               `data = await request.get_json()` so `data` is
 *               added to pyTaintedVars for downstream sinks.
 *
 * Starlette `request.path_params` was already covered.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 eleventh slice — async Python framework sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows?.length ?? 0) > 0;

  it('aiohttp — `request.rel_url.query.get(...)` flows', async () => {
    const code = `from aiohttp import web
import subprocess

async def handler(request):
    q = request.rel_url.query.get('q')
    subprocess.run(q, shell=True)
`;
    const r = await analyze(code, 'rel_url.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('aiohttp — `request.match_info[...]` flows', async () => {
    const code = `from aiohttp import web
import subprocess

async def handler(request):
    uid = request.match_info['id']
    subprocess.run('grep user-' + uid + ' /log', shell=True)
`;
    const r = await analyze(code, 'mi.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('aiohttp — `request.remote` (client IP) flows', async () => {
    const code = `from aiohttp import web
import subprocess

async def handler(request):
    ip = request.remote
    subprocess.run('echo ' + ip + ' >> /log', shell=True)
`;
    const r = await analyze(code, 'remote.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('Quart — `await request.get_json()` flows', async () => {
    const code = `from quart import request
import subprocess

async def h():
    data = await request.get_json()
    subprocess.run(data['cmd'], shell=True)
`;
    const r = await analyze(code, 'quart-json.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('Quart — `request.args.get(...)` flows (shared Flask idiom)', async () => {
    const code = `from quart import Quart, request
import subprocess

app = Quart(__name__)

@app.route('/')
async def h():
    q = request.args.get('q')
    subprocess.run(q, shell=True)
`;
    const r = await analyze(code, 'quart-args.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });
});
