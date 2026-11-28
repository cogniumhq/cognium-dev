/**
 * Python web-framework parameter sources.
 *
 * Some Python frameworks hand request input to a handler as ordinary function
 * parameters instead of through a `request` object, so no call or property
 * read marks the value as a source:
 *
 * - **FastAPI.** A function decorated with `@<app>.get(...)` (also `post`,
 *   `put`, `patch`, `delete`, `head`, `options`, `trace`, `api_route`,
 *   `websocket`), where `<app>` is bound in the same file to `FastAPI()` or
 *   `APIRouter()`, receives its path, query, header, cookie, form, file and
 *   body values as parameters. Each parameter is a source unless it is a
 *   framework object (`Request`, `Response`, `BackgroundTasks`, `WebSocket`,
 *   …) or is injected with `Depends(...)` / `Security(...)`.
 *   A parameter that carries a FastAPI marker — `Annotated[T, Query()]` or a
 *   default of `Query(...)` (also `Path`, `Body`, `Form`, `Header`, `Cookie`,
 *   `File`) — is a source in any function, since the marker only means
 *   something when FastAPI binds it from the request (a dependency function
 *   declares its inputs the same way).
 * - **webargs.** A function decorated with `@use_kwargs(...)` or
 *   `@use_args(...)` from a `webargs` parser (`webargs.flaskparser`,
 *   `aiohttpparser`, `djangoparser`, `tornadoparser`, …) receives the parsed
 *   request values as parameters. For `use_kwargs` with a literal field
 *   dictionary only the parameters named by its keys are sources; otherwise
 *   every parameter except `self`, `cls` and the framework request object.
 *
 * Every source names its parameter (`variable`) and enclosing function
 * (`in_method`), so the data-flow seed covers that binding only.
 *
 * Text-based, like the other Python source detectors: the signature is read
 * from the source starting at the function's `def` line.
 */

import type { SourceType, TaintSource, TypeInfo, MethodInfo } from '../types/index.js';

// ---------------------------------------------------------------------------
// Signature parsing
// ---------------------------------------------------------------------------

interface PyParam {
  name: string;
  /** Annotation text, trimmed; '' when absent. */
  annotation: string;
  /** Default-value text, trimmed; '' when absent. */
  defaultValue: string;
  /** `*args` / `**kwargs` / bare `*` / `/`. */
  special: boolean;
  /** 0-based offset of the entry inside the signature text. */
  offset: number;
}

/**
 * Index of the bracket that closes the one at `open`, skipping string
 * literals. -1 when it does not close.
 */
function closeBracket(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'") {
      i = skipString(text, i);
      continue;
    }
    if (ch === '#') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return -1;
      i = nl;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Index of the closing quote of the string literal opening at `start`. */
function skipString(text: string, start: number): number {
  const q = text[start];
  const triple = text.startsWith(q.repeat(3), start);
  if (triple) {
    const end = text.indexOf(q.repeat(3), start + 3);
    return end < 0 ? text.length : end + 2;
  }
  for (let i = start + 1; i < text.length; i++) {
    if (text[i] === '\\') { i++; continue; }
    if (text[i] === q || text[i] === '\n') return i;
  }
  return text.length;
}

/**
 * Split `text` at top-level occurrences of `sep` (outside brackets and
 * strings). Returns each piece with its offset.
 */
function splitTopLevel(text: string, sep: string): Array<{ text: string; offset: number }> {
  const out: Array<{ text: string; offset: number }> = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'") { i = skipString(text, i); continue; }
    if (ch === '#') {
      const nl = text.indexOf('\n', i);
      i = nl < 0 ? text.length : nl;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (depth === 0 && text.startsWith(sep, i)) {
      out.push({ text: text.slice(start, i), offset: start });
      start = i + sep.length;
      i += sep.length - 1;
    }
  }
  out.push({ text: text.slice(start), offset: start });
  return out;
}

/** Index of the first top-level `=` that is an assignment (not `==`, `<=`, …). */
function topLevelEquals(text: string): number {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'") { i = skipString(text, i); continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === '=' && depth === 0) {
      const prev = text[i - 1];
      const next = text[i + 1];
      if (next === '=' || prev === '=' || prev === '!' || prev === '<' || prev === '>') continue;
      return i;
    }
  }
  return -1;
}

/** Index of the first top-level `:`. */
function topLevelColon(text: string): number {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'") { i = skipString(text, i); continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ':' && depth === 0) return i;
  }
  return -1;
}

/**
 * The parameter list of the function whose `def` sits on 1-based `defLine`.
 * Returns null when the signature cannot be read.
 */
function readSignature(lines: string[], defLine: number): { params: PyParam[]; startLine: number; text: string } | null {
  const idx = defLine - 1;
  if (idx < 0 || idx >= lines.length) return null;
  // A signature rarely spans more than a few dozen lines.
  const text = lines.slice(idx, Math.min(lines.length, idx + 60)).join('\n');
  const m = /\bdef\s+[\p{L}\p{N}_]+\s*\(/u.exec(text);
  if (!m) return null;
  const open = m.index + m[0].length - 1;
  const close = closeBracket(text, open);
  if (close < 0) return null;
  const inner = text.slice(open + 1, close);
  const params: PyParam[] = [];
  for (const piece of splitTopLevel(inner, ',')) {
    const raw = piece.text;
    const lead = raw.length - raw.trimStart().length;
    const entry = raw.trim();
    if (entry === '') continue;
    const offset = open + 1 + piece.offset + lead;
    if (entry === '*' || entry === '/' || entry.startsWith('*')) {
      params.push({ name: entry.replace(/^\*+/, '').split(/[:=]/)[0].trim(), annotation: '', defaultValue: '', special: true, offset });
      continue;
    }
    const eq = topLevelEquals(entry);
    const head = eq >= 0 ? entry.slice(0, eq) : entry;
    const defaultValue = eq >= 0 ? entry.slice(eq + 1).trim() : '';
    const colon = topLevelColon(head);
    const name = (colon >= 0 ? head.slice(0, colon) : head).trim();
    const annotation = colon >= 0 ? head.slice(colon + 1).trim() : '';
    if (!/^[\p{L}_][\p{L}\p{N}_]*$/u.test(name)) continue;
    params.push({ name, annotation, defaultValue, special: false, offset });
  }
  return { params, startLine: defLine, text };
}

/** 1-based line of `offset` inside a signature text that starts at `startLine`. */
function lineOfOffset(text: string, offset: number, startLine: number): number {
  let line = startLine;
  for (let i = 0; i < offset && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

// ---------------------------------------------------------------------------
// FastAPI
// ---------------------------------------------------------------------------

const FASTAPI_IMPORT_RE = /^[ \t]*(?:from[ \t]+fastapi(?:\.[\w.]+)?[ \t]+import\b|import[ \t]+fastapi\b)/m;

/** Names bound in the file to `FastAPI(...)` or `APIRouter(...)`. */
function fastApiReceivers(code: string): Set<string> {
  const names = new Set<string>();
  const re = /^[ \t]*([\p{L}_][\p{L}\p{N}_]*)\s*(?::\s*[\w.]+\s*)?=\s*(?:fastapi\s*\.\s*)?(?:FastAPI|APIRouter)\s*\(/gmu;
  for (const m of code.matchAll(re)) names.add(m[1]);
  return names;
}

const FASTAPI_ROUTE_DECORATOR_RE =
  /^\s*([\p{L}_][\p{L}\p{N}_]*)\s*\.\s*(?:get|post|put|patch|delete|head|options|trace|api_route|websocket)\s*\(/u;

/**
 * FastAPI parameter markers and the source type each one binds. `Path` is a
 * URL segment and `Form` an urlencoded field: both are plain request strings,
 * typed `http_param` so every string sink is in reach.
 */
const FASTAPI_MARKERS: Record<string, SourceType> = {
  Query: 'http_param',
  Path: 'http_param',
  Form: 'http_param',
  Body: 'http_body',
  Header: 'http_header',
  Cookie: 'http_cookie',
  File: 'file_input',
};

/** Injected (not request-bound) parameters. */
const FASTAPI_INJECTION_MARKER_RE = /^(?:fastapi\s*\.\s*|params\s*\.\s*)?(?:Depends|Security)\s*\(/;

/** Framework objects FastAPI passes in by type. These are not request values themselves. */
const FASTAPI_FRAMEWORK_TYPES = new Set([
  'Request', 'Response', 'BackgroundTasks', 'WebSocket', 'HTTPConnection',
  'SecurityScopes', 'JSONResponse', 'HTMLResponse', 'PlainTextResponse',
  'StreamingResponse', 'FileResponse', 'RedirectResponse',
]);

/** Scalar annotations FastAPI binds from the path or query string. */
const SCALAR_TYPE_RE =
  /^(?:str|int|float|bool|bytes|complex|Decimal|UUID|uuid\.UUID|date|datetime|time|timedelta|datetime\.\w+|EmailStr|HttpUrl|AnyUrl|AnyHttpUrl|constr\b.*|conint\b.*|confloat\b.*|Literal\[.*\]|None)$/;

/** `Annotated[T, m1, m2]` → { inner: 'T', metadata: ['m1', 'm2'] }; otherwise null. */
function splitAnnotated(annotation: string): { inner: string; metadata: string[] } | null {
  const m = /^(?:typing\s*\.\s*|typing_extensions\s*\.\s*)?Annotated\s*\[/.exec(annotation);
  if (!m) return null;
  const open = m[0].length - 1;
  const close = closeBracket(annotation, open);
  if (close < 0) return null;
  const parts = splitTopLevel(annotation.slice(open + 1, close), ',').map(p => p.text.trim()).filter(Boolean);
  if (parts.length === 0) return null;
  return { inner: parts[0], metadata: parts.slice(1) };
}

/** The FastAPI marker a `Query(...)`-style expression names, if any. */
function markerOf(expr: string): string | undefined {
  const m = /^(?:fastapi\s*\.\s*|params\s*\.\s*)?([A-Z]\w*)\s*\(/.exec(expr.trim());
  if (!m) return undefined;
  return Object.hasOwn(FASTAPI_MARKERS, m[1]) ? m[1] : undefined;
}

/** Peel `Optional[T]`, `T | None`, `Union[T, None]`, `list[T]`, `List[T]` down to the base names. */
function baseTypeNames(annotation: string): string[] {
  const t = annotation.trim();
  if (t === '') return [];
  const union = splitTopLevel(t, '|');
  if (union.length > 1) return union.flatMap(u => baseTypeNames(u.text));
  const generic = /^(?:typing\s*\.\s*)?(Optional|Union|List|list|Set|set|Sequence|FrozenSet|frozenset|Tuple|tuple)\s*\[/.exec(t);
  if (generic) {
    const open = generic[0].length - 1;
    const close = closeBracket(t, open);
    if (close > 0) {
      return splitTopLevel(t.slice(open + 1, close), ',').flatMap(p => baseTypeNames(p.text));
    }
  }
  return [t.replace(/^["']|["']$/g, '')];
}

/** Last dotted segment: `fastapi.Request` → `Request`. */
const lastSegment = (name: string): string => name.split('.').pop()!.trim();

/** Classes this file declares as Pydantic models (`class Item(BaseModel):`). */
function pydanticModels(code: string): Set<string> {
  const models = new Set<string>();
  const re = /^[ \t]*class\s+([\p{L}_][\p{L}\p{N}_]*)\s*\(([^)]*)\)\s*:/gmu;
  const declared: Array<[string, string[]]> = [];
  for (const m of code.matchAll(re)) {
    declared.push([m[1], m[2].split(',').map(b => lastSegment(b.trim()))]);
  }
  // Fixed point so `class B(A)` with `class A(BaseModel)` counts as well.
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, bases] of declared) {
      if (models.has(name)) continue;
      if (bases.some(b => b === 'BaseModel' || models.has(b))) {
        models.add(name);
        changed = true;
      }
    }
  }
  return models;
}

/**
 * Source type for one FastAPI parameter, or null when it is not request
 * input. `route` is true when the function is a route handler of a FastAPI
 * app or router in this file.
 */
function fastApiParamSource(p: PyParam, route: boolean, models: ReadonlySet<string>): SourceType | null {
  if (p.special) return null;
  if (p.name === 'self' || p.name === 'cls') return null;

  let annotation = p.annotation;
  let marker: string | undefined;
  const annotated = splitAnnotated(annotation);
  if (annotated) {
    if (annotated.metadata.some(md => FASTAPI_INJECTION_MARKER_RE.test(md))) return null;
    for (const md of annotated.metadata) {
      marker = markerOf(md);
      if (marker) break;
    }
    annotation = annotated.inner;
  }
  if (FASTAPI_INJECTION_MARKER_RE.test(p.defaultValue)) return null;
  if (!marker && p.defaultValue) marker = markerOf(p.defaultValue);

  const bases = baseTypeNames(annotation).map(lastSegment);
  if (bases.some(b => FASTAPI_FRAMEWORK_TYPES.has(b))) return null;

  const isUpload = bases.some(b => b === 'UploadFile');
  if (marker) return isUpload ? 'file_input' : FASTAPI_MARKERS[marker];
  if (!route) return null;
  if (isUpload) return 'file_input';
  // No marker: scalars come from the path or query string, a model from the
  // JSON body.
  if (bases.length > 0 && bases.every(b => !SCALAR_TYPE_RE.test(b)) &&
      bases.some(b => models.has(b) || /^[A-Z]/.test(b))) {
    return 'http_body';
  }
  return 'http_param';
}

function findFastApiFunctions(code: string, lines: string[], types: TypeInfo[]): PythonWebFunction[] {
  if (!FASTAPI_IMPORT_RE.test(code)) return [];
  const receivers = fastApiReceivers(code);
  const models = pydanticModels(code);
  const out: PythonWebFunction[] = [];
  for (const method of allFunctions(types)) {
    const route = method.annotations.some(a => {
      const m = FASTAPI_ROUTE_DECORATOR_RE.exec(a);
      return !!m && receivers.has(m[1]);
    });
    const sig = readSignature(lines, method.start_line);
    if (!sig) continue;
    const sources: TaintSource[] = [];
    for (const p of sig.params) {
      const type = fastApiParamSource(p, route, models);
      if (!type) continue;
      sources.push(paramSource(type, `${FASTAPI_LOCATION} '${p.name}' in ${method.name}`, p, method, sig));
    }
    if (route || sources.length > 0) out.push({ method, handler: route, sources });
  }
  return out;
}

// ---------------------------------------------------------------------------
// webargs
// ---------------------------------------------------------------------------

const WEBARGS_IMPORT_RE = /^[ \t]*(?:from[ \t]+webargs(?:\.[\w.]+)?[ \t]+import\b|import[ \t]+webargs\b)/m;
const WEBARGS_DECORATOR_RE = /^\s*(?:[\p{L}_][\p{L}\p{N}_]*\s*\.\s*)*(use_kwargs|use_args)\s*\(/u;
/** The handler's own request / view objects, passed positionally ahead of the parsed values. */
const WEBARGS_NON_INPUT = new Set(['self', 'cls', 'request', 'req']);

/** webargs `location=` → source type. The webargs default location is the JSON body. */
const WEBARGS_LOCATIONS: Record<string, SourceType> = {
  json: 'http_body',
  json_or_form: 'http_body',
  form: 'http_param',
  query: 'http_param',
  querystring: 'http_param',
  headers: 'http_header',
  cookies: 'http_cookie',
  files: 'file_input',
  view_args: 'http_param',
  match_info: 'http_param',
  path: 'http_param',
};

function findWebargsFunctions(code: string, lines: string[], types: TypeInfo[]): PythonWebFunction[] {
  if (!WEBARGS_IMPORT_RE.test(code)) return [];
  const out: PythonWebFunction[] = [];
  for (const method of allFunctions(types)) {
    const decorators = method.annotations
      .map(a => ({ text: a, m: WEBARGS_DECORATOR_RE.exec(a) }))
      .filter((d): d is { text: string; m: RegExpExecArray } => d.m !== null);
    if (decorators.length === 0) continue;
    const sig = readSignature(lines, method.start_line);
    if (!sig) continue;

    // Names a literal `use_kwargs({...})` binds; null = any parameter.
    let kwargNames: Set<string> | null = new Set();
    let type: SourceType = 'http_body';
    for (const d of decorators) {
      const open = d.m[0].length - 1;
      const close = closeBracket(d.text, open);
      const args = close > 0 ? splitTopLevel(d.text.slice(open + 1, close), ',').map(a => a.text.trim()) : [];
      const loc = args.map(a => /^location\s*=\s*(['"])(\w+)\1$/.exec(a)).find(x => x);
      if (loc && Object.hasOwn(WEBARGS_LOCATIONS, loc[2])) type = WEBARGS_LOCATIONS[loc[2]];
      const first = args[0] ?? '';
      if (d.m[1] === 'use_kwargs' && first.startsWith('{') && kwargNames) {
        for (const entry of splitTopLevel(first.slice(1, -1), ',')) {
          const key = /^\s*(['"])([\p{L}_][\p{L}\p{N}_]*)\1\s*:/u.exec(entry.text);
          if (key) kwargNames.add(key[2]);
        }
      } else {
        kwargNames = null;
      }
    }

    const sources: TaintSource[] = [];
    for (const p of sig.params) {
      if (p.special || WEBARGS_NON_INPUT.has(p.name)) continue;
      if (kwargNames && !kwargNames.has(p.name)) continue;
      sources.push(paramSource(type, `${WEBARGS_LOCATION} '${p.name}' in ${method.name}`, p, method, sig));
    }
    out.push({ method, handler: true, sources });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

const FASTAPI_LOCATION = 'FastAPI parameter';
const WEBARGS_LOCATION = 'webargs parameter';

/**
 * True for a source this module emitted. Such a source names exactly one
 * parameter (`variable`); the other parameters on its signature line —
 * `request`, a `Depends(...)` value — must not share its seed.
 */
export function isPythonWebParamSource(source: { location?: string; variable?: string }): boolean {
  const loc = source.location ?? '';
  return source.variable !== undefined &&
    (loc.startsWith(`${FASTAPI_LOCATION} '`) || loc.startsWith(`${WEBARGS_LOCATION} '`));
}

function* allFunctions(types: TypeInfo[]): Generator<MethodInfo> {
  for (const t of types) for (const m of t.methods) yield m;
}

function paramSource(
  type: SourceType,
  location: string,
  p: PyParam,
  method: MethodInfo,
  sig: { startLine: number; text: string },
): TaintSource {
  const line = method.parameters.find(mp => mp.name === p.name)?.line
    ?? lineOfOffset(sig.text, p.offset, sig.startLine);
  return {
    type,
    location,
    severity: 'high',
    line,
    confidence: 0.95,
    variable: p.name,
    in_method: method.name,
  };
}

/** A function whose parameters this module models. */
export interface PythonWebFunction {
  method: MethodInfo;
  /**
   * True for a FastAPI route handler or a webargs-decorated view: every
   * parameter that is request input is in `sources`, so a parameter that is
   * not (`request`, a `Depends(...)` value) carries no request data.
   */
  handler: boolean;
  /** One source per request-bound parameter. */
  sources: TaintSource[];
}

/**
 * FastAPI route handlers, functions with FastAPI parameter markers, and
 * webargs-decorated views in one Python file.
 */
export function findPythonWebFunctions(code: string, types: TypeInfo[]): PythonWebFunction[] {
  const lines = code.split('\n');
  return [
    ...findFastApiFunctions(code, lines, types),
    ...findWebargsFunctions(code, lines, types),
  ];
}

/**
 * Parameter sources for FastAPI route handlers and webargs-decorated views in
 * one Python file. See the module comment for what counts.
 */
export function findPythonWebParamSources(code: string, types: TypeInfo[]): TaintSource[] {
  return findPythonWebFunctions(code, types).flatMap(f => f.sources);
}
