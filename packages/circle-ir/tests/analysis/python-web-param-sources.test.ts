/**
 * Python web-framework parameters as taint sources.
 *
 * FastAPI route handlers and webargs-decorated views receive request values
 * as plain function parameters. Those parameters are sources; framework
 * objects (`Request`, `BackgroundTasks`, …) and `Depends(...)`-injected
 * values are not. Also covers the FastAPI / Starlette `FileResponse` and
 * `RedirectResponse` sinks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { findPythonWebParamSources, isPythonWebParamSource } from '../../src/analysis/python-web-params.js';
import type { TypeInfo } from '../../src/types/index.js';

type Result = Awaited<ReturnType<typeof analyze>>;

const run = (lines: string[], file = 'app.py'): Promise<Result> => analyze(lines.join('\n'), file, 'python');

const flowsOf = (r: Result, sinkType: string) => (r.taint.flows ?? []).filter(f => f.sink_type === sinkType);
const hasFlow = (r: Result, sinkType: string, from: number, to: number) =>
  flowsOf(r, sinkType).some(f => f.source_line === from && f.sink_line === to);
const paramSources = (r: Result) => r.taint.sources.filter(s => isPythonWebParamSource(s));

beforeAll(async () => {
  await initAnalyzer();
});

describe('FastAPI route parameters are taint sources', () => {
  it('Annotated[str, Query()] and a plain str parameter reach a shell command', async () => {
    const r = await run([
      'import subprocess',
      'from typing import Annotated',
      'from fastapi import FastAPI, Query',
      '',
      'app = FastAPI()',
      '',
      '@app.get("/ping")',
      'def ping(host: Annotated[str, Query()]):',
      '    return {"rc": subprocess.run(f"ping -c 1 {host}", shell=True).returncode}',
      '',
      '@app.get("/ping2")',
      'def ping2(host: str):',
      '    return {"rc": subprocess.run(f"ping -c 1 {host}", shell=True).returncode}',
    ]);
    expect(hasFlow(r, 'command_injection', 8, 9)).toBe(true);
    expect(hasFlow(r, 'command_injection', 12, 13)).toBe(true);
    const src = paramSources(r).find(s => s.line === 8);
    expect(src).toMatchObject({ type: 'http_param', variable: 'host', in_method: 'ping' });
  });

  it('APIRouter routes, default-value markers and a multi-line signature', async () => {
    const r = await run([
      'import os',
      'from typing import Annotated, Optional',
      'from fastapi import APIRouter, Cookie, Header, Query',
      '',
      'router = APIRouter(prefix="/x")',
      '',
      '@router.post(',
      '    "/run",',
      '    status_code=202,',
      ')',
      'async def run(',
      '    cmd: str = Query(..., max_length=64),',
      '    agent: Annotated[Optional[str], Header()] = None,',
      '    session: str | None = Cookie(default=None),',
      '    limit: int = 10,',
      '):',
      '    os.system(cmd)',
    ]);
    expect(hasFlow(r, 'command_injection', 12, 17)).toBe(true);
    const byVar = new Map(paramSources(r).map(s => [s.variable, s]));
    expect(byVar.get('cmd')).toMatchObject({ type: 'http_param', line: 12 });
    expect(byVar.get('agent')).toMatchObject({ type: 'http_header', line: 13 });
    expect(byVar.get('session')).toMatchObject({ type: 'http_cookie', line: 14 });
    expect(byVar.get('limit')).toMatchObject({ type: 'http_param', line: 15 });
  });

  it('a Pydantic body model: its attributes are request input', async () => {
    const r = await run([
      'from fastapi import FastAPI',
      'from pydantic import BaseModel',
      '',
      'app = FastAPI()',
      '',
      'class Lookup(BaseModel):',
      '    name: str',
      '',
      '@app.post("/lookup")',
      'def lookup(body: Lookup):',
      '    q = "SELECT * FROM users WHERE name = \'" + body.name + "\'"',
      '    return cursor.execute(q)',
    ]);
    expect(paramSources(r).find(s => s.variable === 'body')?.type).toBe('http_body');
    expect(flowsOf(r, 'sql_injection').some(f => f.source_line === 10 && f.sink_line === 12)).toBe(true);
  });

  it('UploadFile: the client-supplied filename reaches open()', async () => {
    const r = await run([
      'from fastapi import FastAPI, File, UploadFile',
      '',
      'app = FastAPI()',
      '',
      '@app.post("/upload")',
      'async def upload(file: UploadFile = File(...)):',
      '    with open("/srv/uploads/" + file.filename, "wb") as fh:',
      '        fh.write(await file.read())',
    ]);
    expect(paramSources(r).find(s => s.variable === 'file')?.type).toBe('file_input');
    expect(hasFlow(r, 'path_traversal', 6, 7)).toBe(true);
  });

  it('request: Request — query_params, json(), form(), headers and cookies are sources', async () => {
    const r = await run([
      'import os',
      'from fastapi import FastAPI, Request',
      '',
      'app = FastAPI()',
      '',
      '@app.post("/req")',
      'async def req(request: Request):',
      '    a = request.query_params.get("a")',
      '    os.system(a)',
      '    body = await request.json()',
      '    os.system(body["cmd"])',
      '    form = await request.form()',
      '    os.system(form["x"])',
      '    h = request.headers.get("x-cmd")',
      '    cursor.execute("SELECT " + h)',
      '    c = request.cookies.get("c")',
      '    cursor.execute("SELECT " + c)',
    ]);
    expect(hasFlow(r, 'command_injection', 8, 9)).toBe(true);
    expect(hasFlow(r, 'command_injection', 10, 11)).toBe(true);
    expect(hasFlow(r, 'command_injection', 12, 13)).toBe(true);
    expect(hasFlow(r, 'sql_injection', 14, 15)).toBe(true);
    expect(hasFlow(r, 'sql_injection', 16, 17)).toBe(true);
    // The Request object itself is not a parameter source.
    expect(paramSources(r)).toHaveLength(0);
  });

  it('FileResponse(path) is a path traversal sink, RedirectResponse(url) an open redirect', async () => {
    const r = await run([
      'from fastapi import FastAPI',
      'from fastapi.responses import FileResponse, RedirectResponse',
      '',
      'app = FastAPI()',
      '',
      '@app.get("/dl")',
      'def dl(name: str):',
      '    return FileResponse(path="/srv/files/" + name)',
      '',
      '@app.get("/go")',
      'def go(next: str):',
      '    return RedirectResponse(url=next)',
    ]);
    expect(hasFlow(r, 'path_traversal', 7, 8)).toBe(true);
    expect(hasFlow(r, 'open_redirect', 11, 12)).toBe(true);
  });

  it('Starlette FileResponse / RedirectResponse are the same sinks', async () => {
    const r = await run([
      'from fastapi import FastAPI',
      'from starlette.responses import FileResponse, RedirectResponse',
      '',
      'app = FastAPI()',
      '',
      '@app.get("/dl")',
      'def dl(name: str):',
      '    return FileResponse("/srv/files/" + name)',
      '',
      '@app.get("/go")',
      'def go(next: str):',
      '    return RedirectResponse(next)',
    ]);
    expect(hasFlow(r, 'path_traversal', 7, 8)).toBe(true);
    expect(hasFlow(r, 'open_redirect', 11, 12)).toBe(true);
  });

  // ---------------------------------------------------------------------
  // Negatives
  // ---------------------------------------------------------------------

  it('negative: a constant passed to the same sink does not fire', async () => {
    const r = await run([
      'import subprocess',
      'from fastapi import FastAPI',
      'from fastapi.responses import FileResponse, RedirectResponse',
      '',
      'app = FastAPI()',
      '',
      '@app.get("/ping")',
      'def ping(host: str):',
      '    return {"rc": subprocess.run("ping -c 1 localhost", shell=True).returncode}',
      '',
      '@app.get("/dl")',
      'def dl(name: str):',
      '    return FileResponse("/srv/files/report.pdf")',
      '',
      '@app.get("/go")',
      'def go(next: str):',
      '    return RedirectResponse("/home")',
    ]);
    expect(paramSources(r).length).toBe(3);
    expect(flowsOf(r, 'command_injection')).toHaveLength(0);
    expect(flowsOf(r, 'path_traversal')).toHaveLength(0);
    expect(flowsOf(r, 'open_redirect')).toHaveLength(0);
  });

  it('negative: Depends()-injected parameters are not sources, even beside a real one', async () => {
    const r = await run([
      'import os',
      'from typing import Annotated',
      'from fastapi import BackgroundTasks, Depends, FastAPI, Request, Security',
      '',
      'app = FastAPI()',
      '',
      'def get_settings():',
      '    return {"cmd": "uptime"}',
      '',
      '@app.get("/a")',
      'def a(host: str, db=Depends(get_settings), s: dict = Depends(get_settings)):',
      '    os.system(db)',
      '    os.system(s["cmd"])',
      '',
      '@app.get("/b")',
      'def b(settings: Annotated[dict, Depends(get_settings)], user=Security(get_settings)):',
      '    os.system(settings["cmd"])',
      '    os.system(user)',
      '',
      '@app.get("/c")',
      'def c(host: str, request: Request, tasks: BackgroundTasks):',
      '    os.system(request)',
      '    os.system(tasks)',
    ]);
    expect(paramSources(r).map(s => s.variable).sort()).toEqual(['host', 'host']);
    expect(flowsOf(r, 'command_injection')).toHaveLength(0);
  });

  it('negative: plain parameters outside a FastAPI route are not sources', async () => {
    const r = await run([
      'import os',
      'from fastapi import FastAPI',
      '',
      'app = FastAPI()',
      'cache = make_cache()',
      '',
      'def helper(host: str):',
      '    os.system(host)',
      '',
      '@cache.get("k")',
      'def cached(host: str):',
      '    os.system(host)',
    ]);
    // Neither function is a route of `app`; `cache` is not a FastAPI app.
    expect(paramSources(r)).toHaveLength(0);
    expect(flowsOf(r, 'command_injection').some(f => f.sink_line === 8)).toBe(false);
  });

  it('aliases of a parameter flow inside its handler only', async () => {
    const r = await run([
      'import os',
      'import shlex',
      'from fastapi import FastAPI',
      '',
      'app = FastAPI()',
      '',
      '@app.get("/a")',
      'def a(host: str):',
      '    cmd = "ping " + host',
      '    os.system(cmd)',
      '',
      'def other():',
      '    cmd = "uptime"',
      '    os.system(cmd)',
      '',
      '@app.get("/b")',
      'def b(host: str):',
      '    cmd = "ping " + shlex.quote(host)',
      '    os.system(cmd)',
    ]);
    expect(hasFlow(r, 'command_injection', 8, 10)).toBe(true);
    // `other`'s `cmd` is a constant; `b` quotes the parameter for the shell.
    expect(flowsOf(r, 'command_injection').some(f => f.sink_line === 14 || f.sink_line === 19)).toBe(false);
  });

  it('negative: without a fastapi import, an app.get decorator binds nothing', async () => {
    const r = await run([
      'import os',
      'from myframework import FastAPI',
      '',
      'app = FastAPI()',
      '',
      '@app.get("/x")',
      'def x(host: str):',
      '    os.system("ls")',
    ]);
    expect(paramSources(r)).toHaveLength(0);
  });

  it('negative: Django FileResponse(file object) is not the FastAPI sink', async () => {
    const r = await run([
      'from django.http import FileResponse',
      '',
      'def view(request):',
      '    f = get_file()',
      '    return FileResponse(f)',
    ], 'views.py');
    expect(r.taint.sinks.some(s => s.method === 'FileResponse')).toBe(false);
  });
});

describe('FastAPI marker parameters outside a route', () => {
  it('a dependency function that declares Header() reads request input', async () => {
    const r = await run([
      'import os',
      'from fastapi import Header',
      '',
      'def verify(x_token: str = Header()):',
      '    os.system("check " + x_token)',
    ], 'deps.py');
    expect(paramSources(r)).toHaveLength(1);
    expect(paramSources(r)[0]).toMatchObject({ type: 'http_header', variable: 'x_token', line: 4 });
  });
});

describe('webargs parameters are taint sources', () => {
  it('use_kwargs field dict: the named keyword argument reaches a shell command', async () => {
    const r = await run([
      'import subprocess',
      'from flask import Flask',
      'from webargs import fields',
      'from webargs.flaskparser import use_kwargs',
      '',
      'app = Flask(__name__)',
      '',
      '@app.route("/ping")',
      '@use_kwargs({"host": fields.Str(required=True)}, location="query")',
      'def ping(host):',
      '    return str(subprocess.run(f"ping -c 1 {host}", shell=True).returncode)',
    ]);
    expect(hasFlow(r, 'command_injection', 10, 11)).toBe(true);
    expect(paramSources(r)[0]).toMatchObject({ type: 'http_param', variable: 'host', in_method: 'ping' });
  });

  it('use_args with a schema: the parsed-arguments parameter is a source', async () => {
    const r = await run([
      'import os',
      'from flask import Flask',
      'from webargs import fields',
      'from webargs.flaskparser import parser',
      '',
      'app = Flask(__name__)',
      'user_args = {"name": fields.Str(required=True)}',
      '',
      '@app.route("/a")',
      '@parser.use_args(user_args, location="json")',
      'def a(args):',
      '    os.system("echo " + args["name"])',
    ]);
    expect(paramSources(r)[0]).toMatchObject({ type: 'http_body', variable: 'args' });
    expect(hasFlow(r, 'command_injection', 11, 12)).toBe(true);
  });

  it('aiohttp parser: the parsed values are sources, the request object is not', async () => {
    const r = await run([
      'import os',
      'from aiohttp import web',
      'from webargs import fields',
      'from webargs.aiohttpparser import use_kwargs',
      '',
      '@use_kwargs({"name": fields.Str()}, location="query")',
      'async def index(request, name):',
      '    os.system("echo " + name)',
      '    os.system(request.app["cmd"])',
      '    return web.Response(text="ok")',
    ]);
    expect(paramSources(r).map(s => s.variable)).toEqual(['name']);
    expect(hasFlow(r, 'command_injection', 7, 8)).toBe(true);
    expect(flowsOf(r, 'command_injection').some(f => f.sink_line === 9)).toBe(false);
  });

  it('negative: a constant passed to the same sink does not fire', async () => {
    const r = await run([
      'import subprocess',
      'from flask import Flask',
      'from webargs import fields',
      'from webargs.flaskparser import use_kwargs',
      '',
      'app = Flask(__name__)',
      '',
      '@app.route("/ping")',
      '@use_kwargs({"host": fields.Str(required=True)}, location="query")',
      'def ping(host):',
      '    return str(subprocess.run("ping -c 1 localhost", shell=True).returncode)',
    ]);
    expect(paramSources(r)).toHaveLength(1);
    expect(flowsOf(r, 'command_injection')).toHaveLength(0);
  });

  it('negative: a parameter use_kwargs does not bind, and an undecorated helper, are not sources', async () => {
    const r = await run([
      'import os',
      'from flask import Flask',
      'from webargs import fields',
      'from webargs.flaskparser import use_kwargs',
      '',
      'app = Flask(__name__)',
      '',
      '@use_kwargs({"host": fields.Str()}, location="query")',
      'def ping(host, request=None):',
      '    os.system(request)',
      '',
      'def helper(host):',
      '    os.system(host)',
    ]);
    expect(paramSources(r).map(s => `${s.in_method}:${s.variable}`)).toEqual(['ping:host']);
    expect(flowsOf(r, 'command_injection')).toHaveLength(0);
  });
});

describe('findPythonWebParamSources (signature reading)', () => {
  const fn = (name: string, line: number, annotations: string[]): TypeInfo => ({
    name: '<module>',
    kind: 'class',
    package: null,
    extends: null,
    implements: [],
    annotations: [],
    methods: [{
      name,
      return_type: null,
      parameters: [],
      annotations,
      modifiers: [],
      start_line: line,
      end_line: line + 5,
    }],
    fields: [],
    start_line: 1,
    end_line: 100,
  });

  it('reads positional-only, keyword-only and splat markers, commas in strings and comments', () => {
    const code = [
      'from fastapi import FastAPI, Query',
      'app = FastAPI()',
      '@app.get("/x")',
      'def x(a: str, /, b: str = Query(",", alias="b,c"),  # a comment, with a comma',
      '      *, c: int = 3, **extra) -> dict:',
      '    return {}',
    ].join('\n');
    const sources = findPythonWebParamSources(code, [fn('x', 4, ['app.get("/x")'])]);
    expect(sources.map(s => [s.variable, s.line])).toEqual([['a', 4], ['b', 4], ['c', 5]]);
  });

  it('no sources from a file that imports neither framework', () => {
    const code = ['@app.get("/x")', 'def x(a: str):', '    pass'].join('\n');
    expect(findPythonWebParamSources(code, [fn('x', 2, ['app.get("/x")'])])).toEqual([]);
  });
});
