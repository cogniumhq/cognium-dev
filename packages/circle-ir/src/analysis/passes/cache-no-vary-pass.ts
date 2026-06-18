/**
 * Pass: cache-no-vary (CWE-524, category: security)
 *
 * Pattern pass — flags HTTP handlers that set a *shared-cacheable*
 * `Cache-Control` directive (`public` or implicit-public + positive `max-age`)
 * **AND** read authenticated or user-scoped state (cookies / Authorization
 * header / session), **AND** do not set `Vary: Cookie` / `Vary: Authorization`.
 *
 * In that configuration a shared cache (CDN, reverse proxy, ISP cache) keys
 * the response by URL only and is free to serve user A's body to user B —
 * the canonical CWE-524 leak.
 *
 * Languages: JavaScript / TypeScript (Express-style `res.setHeader` etc.),
 * Python (Flask / Django / FastAPI), Go (`net/http`, gin), Java (Servlet /
 * Spring).
 *
 * Trigger mode: strict + auth-qualifier. Skips:
 *   - `Cache-Control: private` / `no-store` / `no-cache`
 *   - `max-age=0` (effectively non-cacheable)
 *   - Handlers with no auth/session/cookie read
 *   - Handlers that set `Vary: Cookie|Authorization|*`
 *   - Test files (`*.test.*`, `*.spec.*`, `__tests__/`, `tests/`)
 *
 * Closes: cognium-dev #96 L91.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// Header value parsing -------------------------------------------------------

function isSharedCacheable(value: string): boolean {
  const v = value.toLowerCase();
  if (/\b(private|no-store|no-cache)\b/.test(v)) return false;
  const pub = /\bpublic\b/.test(v);
  const maxMatch = /\b(?:s-maxage|max-age)\s*=\s*(\d+)/.exec(v);
  const positiveMax = maxMatch ? Number(maxMatch[1]) > 0 : false;
  return pub || positiveMax;
}

function isVaryCovering(value: string): boolean {
  const v = value.toLowerCase();
  return /\b(cookie|authorization|\*)\b/.test(v);
}

// Source-text auth-signal regexes (per-language) -----------------------------

const JS_AUTH_SIGNAL_RE =
  /\b(?:req|request)\s*\.\s*(?:cookies|session|user(?:Id|Name)?)\b|\b(?:req|request)\s*\.\s*headers\s*\.\s*(?:cookie|authorization)\b|\bres(?:ponse)?\s*\.\s*cookie\s*\(/i;
const PY_AUTH_SIGNAL_RE =
  /\brequest\s*\.\s*cookies\b|\brequest\s*\.\s*headers\s*\.\s*get\s*\(\s*['"]Authorization['"]|\brequest\s*\.\s*authorization\b|\bsession\s*\[|\b(?:g\.user|current_user)\b|\bset_cookie\s*\(/i;
const GO_AUTH_SIGNAL_RE =
  /\br\s*\.\s*Cookie\s*\(|\br\s*\.\s*Header\s*(?:\(\)|\.)\s*\.?\s*Get\s*\(\s*"(?:Cookie|Authorization)"|\br\s*\.\s*BasicAuth\s*\(|\bhttp\s*\.\s*SetCookie\s*\(|\bc\s*\.\s*(?:GetHeader|Cookie|SetCookie)\s*\(/;
const JAVA_AUTH_SIGNAL_RE =
  /@CookieValue\b|@RequestHeader\s*\(\s*"(?:Cookie|Authorization)"|\brequest\s*\.\s*getCookies\s*\(|\brequest\s*\.\s*getHeader\s*\(\s*"(?:Cookie|Authorization)"|\bresponse\s*\.\s*addCookie\s*\(|\bSecurityContextHolder\b|\bPrincipal\s+\w+|\bAuthentication\s+\w+/;

// Source-text cache/vary patterns (for shapes that are not extracted as IR
// calls — Python subscript assignments + decorators).

const PY_CACHE_HEADER_ASSIGN_RE =
  /\w+(?:\s*\.\s*\w+)*\s*\.\s*headers\s*\[\s*['"]Cache-Control['"]\s*\]\s*=\s*(['"])([^'"]*)\1/i;
const PY_VARY_HEADER_ASSIGN_RE =
  /\w+(?:\s*\.\s*\w+)*\s*\.\s*headers\s*\[\s*['"]Vary['"]\s*\]\s*=\s*(['"])([^'"]*)\1/i;
const PY_VARY_DECORATOR_RE = /^\s*@\s*(?:vary_on_cookie|vary_on_headers)\b/;
const PY_CACHE_CONTROL_DECORATOR_RE = /^\s*@\s*cache_control\s*\(([^)]*)\)/;

// Per-language header-setting method tables ----------------------------------

const JS_HEADER_METHODS = new Set(['setHeader', 'set', 'header']);
const GO_HEADER_METHODS = new Set(['Set', 'Add']);
const JAVA_HEADER_METHODS = new Set(['setHeader', 'addHeader']);

// JS receivers we treat as response objects.
const JS_RES_RECEIVERS = new Set(['res', 'response', 'ctx']);

// Public result --------------------------------------------------------------

export interface CacheNoVaryResult {
  findings: Array<{
    line: number;
    language: string;
    handler: string | null;
    cacheValue: string;
  }>;
}

type Signal = 'cache-public' | 'vary' | 'auth';

interface ClassifyResult {
  kind: Signal;
  value?: string;
}

function classifyCall(
  call: CallInfo,
  language: string,
): ClassifyResult | null {
  const method = call.method_name;
  const receiver = (call.receiver ?? '').trim();
  const arg0 = call.arguments[0]?.literal ?? null;
  const arg1 = call.arguments[1]?.literal ?? null;

  if (language === 'javascript' || language === 'typescript') {
    if (JS_RES_RECEIVERS.has(receiver) && JS_HEADER_METHODS.has(method)) {
      const header = (arg0 ?? '').toLowerCase();
      if (header === 'cache-control' && arg1 && isSharedCacheable(arg1)) {
        return { kind: 'cache-public', value: arg1 };
      }
      if (header === 'vary' && arg1 && isVaryCovering(arg1)) {
        return { kind: 'vary' };
      }
    }
    if (JS_RES_RECEIVERS.has(receiver) && method === 'vary') {
      const v = arg0 ?? '';
      if (isVaryCovering(v) || v === '') return { kind: 'vary' };
    }
    if (JS_RES_RECEIVERS.has(receiver) && method === 'cookie') {
      // Set-Cookie — auth-bearing response.
      return { kind: 'auth' };
    }
    return null;
  }

  if (language === 'python') {
    // Auth signals via call.
    if (receiver === 'request.cookies' || receiver === 'request.session') {
      return { kind: 'auth' };
    }
    if (receiver === 'request.headers' && method === 'get') {
      const v = (arg0 ?? '').toLowerCase();
      if (v === 'authorization' || v === 'cookie') return { kind: 'auth' };
    }
    if (
      (receiver === 'response' || receiver === 'resp') &&
      method === 'set_cookie'
    ) {
      return { kind: 'auth' };
    }
    // Vary / cache via call.
    if (method === 'patch_vary_headers') return { kind: 'vary' };
    if (method === 'patch_cache_control') {
      const argTxt = call.arguments.map((a) => a.expression ?? '').join(',');
      if (/\bpublic\s*=\s*True\b/.test(argTxt)) {
        return { kind: 'cache-public', value: argTxt };
      }
    }
    return null;
  }

  if (language === 'go') {
    // Cache / Vary header via w.Header().Set/Add or c.Header (gin).
    if (
      (receiver === 'w.Header()' || receiver === 'rw.Header()') &&
      GO_HEADER_METHODS.has(method)
    ) {
      const header = (arg0 ?? '').toLowerCase();
      if (header === 'cache-control' && arg1 && isSharedCacheable(arg1)) {
        return { kind: 'cache-public', value: arg1 };
      }
      if (header === 'vary' && arg1 && isVaryCovering(arg1)) {
        return { kind: 'vary' };
      }
    }
    if (receiver === 'c' && method === 'Header') {
      const header = (arg0 ?? '').toLowerCase();
      if (header === 'cache-control' && arg1 && isSharedCacheable(arg1)) {
        return { kind: 'cache-public', value: arg1 };
      }
      if (header === 'vary' && arg1 && isVaryCovering(arg1)) {
        return { kind: 'vary' };
      }
    }
    // Auth signals.
    if (receiver === 'r' && (method === 'Cookie' || method === 'BasicAuth')) {
      return { kind: 'auth' };
    }
    if (
      (receiver === 'r.Header' || receiver === 'r.Header()') &&
      method === 'Get'
    ) {
      const v = (arg0 ?? '').toLowerCase();
      if (v === 'cookie' || v === 'authorization') return { kind: 'auth' };
    }
    if (receiver === 'http' && method === 'SetCookie') return { kind: 'auth' };
    if (
      receiver === 'c' &&
      (method === 'Cookie' || method === 'GetHeader' || method === 'SetCookie')
    ) {
      return { kind: 'auth' };
    }
    return null;
  }

  if (language === 'java') {
    if (
      (receiver === 'response' || receiver === 'resp') &&
      JAVA_HEADER_METHODS.has(method)
    ) {
      const header = (arg0 ?? '').toLowerCase();
      if (header === 'cache-control' && arg1 && isSharedCacheable(arg1)) {
        return { kind: 'cache-public', value: arg1 };
      }
      if (header === 'vary' && arg1 && isVaryCovering(arg1)) {
        return { kind: 'vary' };
      }
    }
    if (
      (receiver === 'headers' || receiver === 'httpHeaders') &&
      method === 'setCacheControl'
    ) {
      return { kind: 'cache-public', value: 'HttpHeaders.setCacheControl(...)' };
    }
    if (
      (receiver === 'headers' || receiver === 'httpHeaders') &&
      method === 'setVary'
    ) {
      return { kind: 'vary' };
    }
    // Auth signals.
    if (receiver === 'request' && method === 'getCookies') {
      return { kind: 'auth' };
    }
    if (receiver === 'request' && method === 'getHeader') {
      const v = (arg0 ?? '').toLowerCase();
      if (v === 'cookie' || v === 'authorization') return { kind: 'auth' };
    }
    if (
      (receiver === 'response' || receiver === 'resp') &&
      method === 'addCookie'
    ) {
      return { kind: 'auth' };
    }
    return null;
  }

  return null;
}

function authSignalRegex(language: string): RegExp | null {
  switch (language) {
    case 'javascript':
    case 'typescript':
      return JS_AUTH_SIGNAL_RE;
    case 'python':
      return PY_AUTH_SIGNAL_RE;
    case 'go':
      return GO_AUTH_SIGNAL_RE;
    case 'java':
      return JAVA_AUTH_SIGNAL_RE;
    default:
      return null;
  }
}

interface WindowScan {
  cachePublic?: { line: number; value: string };
  vary: boolean;
  auth: boolean;
}

function scanWindow(
  code: string,
  language: string,
  startLine: number,
  endLine: number,
): WindowScan {
  const lines = code.split('\n');
  const lo = Math.max(0, startLine - 1);
  const hi = Math.min(lines.length, endLine);
  const out: WindowScan = { vary: false, auth: false };
  const authRe = authSignalRegex(language);
  for (let i = lo; i < hi; i++) {
    const ln = lines[i];
    if (authRe && authRe.test(ln)) out.auth = true;
    if (language === 'python') {
      if (!out.cachePublic) {
        const mc = PY_CACHE_HEADER_ASSIGN_RE.exec(ln);
        if (mc && isSharedCacheable(mc[2])) {
          out.cachePublic = { line: i + 1, value: mc[2] };
        }
      }
      if (!out.cachePublic) {
        const md = PY_CACHE_CONTROL_DECORATOR_RE.exec(ln);
        if (md) {
          const argTxt = md[1];
          if (
            /\bpublic\s*=\s*True\b/.test(argTxt) &&
            (/\bmax_age\s*=\s*[1-9]\d*\b/.test(argTxt) || !/max_age/.test(argTxt))
          ) {
            out.cachePublic = { line: i + 1, value: argTxt };
          }
        }
      }
      if (!out.vary) {
        const mv = PY_VARY_HEADER_ASSIGN_RE.exec(ln);
        if (mv && isVaryCovering(mv[2])) out.vary = true;
        if (PY_VARY_DECORATOR_RE.test(ln)) out.vary = true;
      }
    }
  }
  return out;
}

export class CacheNoVaryPass implements AnalysisPass<CacheNoVaryResult> {
  readonly name = 'cache-no-vary';
  readonly category = 'security' as const;

  run(ctx: PassContext): CacheNoVaryResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const findings: CacheNoVaryResult['findings'] = [];

    const isSupported =
      language === 'javascript' ||
      language === 'typescript' ||
      language === 'python' ||
      language === 'go' ||
      language === 'java';
    if (!isSupported) return { findings };

    // Skip test / spec files — low-FP guardrail.
    if (
      /(?:\.test|\.spec)\.[jt]sx?$/i.test(file) ||
      /__tests__\/|\/tests?\//i.test(file)
    ) {
      return { findings };
    }

    // Group calls by handler.
    const callsByHandler = new Map<string, CallInfo[]>();
    for (const call of graph.ir.calls) {
      const key = call.in_method ?? '<top>';
      let arr = callsByHandler.get(key);
      if (!arr) {
        arr = [];
        callsByHandler.set(key, arr);
      }
      arr.push(call);
    }

    const emit = (line: number, handler: string | null, cacheValue: string) => {
      if (findings.some((f) => f.line === line && f.handler === handler)) return;
      findings.push({ line, language, handler, cacheValue });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-524',
        severity: 'medium',
        level: 'warning',
        message:
          `Response sets a shared-cacheable Cache-Control ('${cacheValue}') in ` +
          `a handler that reads authenticated or user-scoped state, but does ` +
          `not set 'Vary: Cookie' or 'Vary: Authorization'. A shared cache ` +
          `(CDN, reverse proxy, ISP cache) keys the response by URL only and ` +
          `may serve one user's body to another. (CWE-524)`,
        file,
        line,
        fix:
          `Either add 'Vary: Cookie' (or 'Vary: Authorization') so caches key ` +
          `on the user identity, or change the directive to 'private' / ` +
          `'no-store' so the response is never shared-cached.`,
        evidence: {
          language,
          handler: handler ?? '<top>',
          cacheValue,
        },
      });
    };

    for (const [handlerKey, calls] of callsByHandler) {
      const handler = handlerKey === '<top>' ? null : handlerKey;

      const cachePublicHits: Array<{ line: number; value: string }> = [];
      let varyFromCalls = false;
      let authFromCalls = false;

      for (const call of calls) {
        const cls = classifyCall(call, language);
        if (!cls) continue;
        if (cls.kind === 'cache-public') {
          cachePublicHits.push({
            line: call.location.line,
            value: cls.value ?? '',
          });
        } else if (cls.kind === 'vary') {
          varyFromCalls = true;
        } else if (cls.kind === 'auth') {
          authFromCalls = true;
        }
      }

      // Compute a widened source-text window around this handler's calls.
      let minLine = Infinity;
      let maxLine = -Infinity;
      for (const c of calls) {
        if (c.location?.line) {
          minLine = Math.min(minLine, c.location.line);
          maxLine = Math.max(maxLine, c.location.line);
        }
      }
      if (minLine === Infinity) continue;
      const winStart = Math.max(1, minLine - 5);
      const winEnd = maxLine + 5;

      const winScan = scanWindow(code, language, winStart, winEnd);
      if (winScan.cachePublic) cachePublicHits.push(winScan.cachePublic);
      const vary = varyFromCalls || winScan.vary;
      const auth = authFromCalls || winScan.auth;

      if (cachePublicHits.length === 0) continue;
      if (vary) continue;
      if (!auth) continue;

      // Emit one finding per handler (use first cache-public location).
      emit(cachePublicHits[0].line, handler, cachePublicHits[0].value);
    }

    return { findings };
  }
}
