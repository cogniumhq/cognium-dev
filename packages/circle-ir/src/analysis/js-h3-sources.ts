/**
 * h3 / Nitro / Nuxt server request inputs.
 *
 * An h3 event handler (`defineEventHandler((event) => …)`,
 * `eventHandler(async (event) => …)`, or the object form
 * `defineEventHandler({ handler: (event) => … })`) reads the request through
 * utility functions that take the handler's `event`:
 *
 *   getQuery, getValidatedQuery                        → http_param
 *   readBody, readRawBody, readFormData,
 *   readMultipartFormData, readValidatedBody           → http_body
 *   getRouterParam, getRouterParams,
 *   getValidatedRouterParams                           → http_path
 *   getHeader, getHeaders,
 *   getRequestHeader, getRequestHeaders                → http_header
 *   getCookie, parseCookies                            → http_cookie
 *
 * The validated readers check the shape of the input, not its content, so
 * their result is still attacker-controlled text for injection purposes.
 *
 * Only a call whose first argument is the enclosing handler's own event
 * parameter is a source: a project helper that happens to be named
 * `getQuery`, or a call outside an event handler, is not. Nuxt auto-imports
 * these utilities, so no import is required.
 */

import type { SourceType, TaintSource } from '../types/index.js';
import { maskLiterals } from './passes/prototype-pollution-pass.js';

const H3_INPUTS: Readonly<Record<string, SourceType>> = {
  getQuery: 'http_param',
  getValidatedQuery: 'http_param',
  readBody: 'http_body',
  readRawBody: 'http_body',
  readFormData: 'http_body',
  readMultipartFormData: 'http_body',
  readValidatedBody: 'http_body',
  getRouterParam: 'http_path',
  getRouterParams: 'http_path',
  getValidatedRouterParams: 'http_path',
  getHeader: 'http_header',
  getHeaders: 'http_header',
  getRequestHeader: 'http_header',
  getRequestHeaders: 'http_header',
  getCookie: 'http_cookie',
  parseCookies: 'http_cookie',
};

const HANDLER_CALL_RE = /(?<![\w$.])(?:defineEventHandler|eventHandler)\s*\(/g;
const IDENT = String.raw`[A-Za-z_$][\w$]*`;
/** A function expression's head up to its first parameter: `(event`, `event =>`, `function name(event`. */
const FN_HEAD = String.raw`(?:async\s+)?(?:\(\s*(${IDENT})|(${IDENT})\s*=>|function[\s*]*(?:${IDENT}\s*)?\(\s*(${IDENT}))`;
/** First parameter of a function expression at the start of `text`. */
const FN_HEAD_RE = new RegExp(String.raw`^\s*${FN_HEAD}`);
/** `handler: (event) =>`, `handler: function (event)`, `handler(event) {`, `async handler(event)`. */
const OBJECT_HANDLER_RE = new RegExp(
  String.raw`(?<![\w$])(?:async\s+)?handler(?:\s*:\s*${FN_HEAD}|\s*\(\s*(${IDENT}))`,
);
const INPUT_CALL_RE = new RegExp(String.raw`(?<![\w$.])(${Object.keys(H3_INPUTS).join('|')})\s*(?:<[^<>()]*>\s*)?\(\s*(${IDENT})\s*[,)]`, 'g');

/** Index of the `)` matching the `(` at `open` in masked code, or -1. */
function matchParen(masked: string, open: number): number {
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return i;
  }
  return -1;
}

/** Names bound by `const x = `, `x = ` or `const { a, b: c } = ` ending right before a call. */
function boundNames(before: string): string[] {
  const stmt = before.replace(/\bawait\s*$/, '').trimEnd();
  const plain = new RegExp(String.raw`(?:^|[^\w$.])(?:(?:const|let|var)\s+)?(${IDENT})\s*(?::[^=;]+)?=$`).exec(stmt);
  if (plain && !/^(?:return|typeof|case)$/.test(plain[1])) return [plain[1]];
  const destructure = /(?:const|let|var)\s*\{([^{}]*)\}\s*(?::[^=;]+)?=$/.exec(stmt);
  if (!destructure) return [];
  const names: string[] = [];
  for (const part of destructure[1].split(',')) {
    const m = new RegExp(String.raw`^\s*(?:\.\.\.)?(?:${IDENT}\s*:\s*)?(${IDENT})\s*(?:=.*)?$`).exec(part);
    if (m) names.push(m[1]);
  }
  return names;
}

export function findH3EventHandlerSources(code: string, language: string): TaintSource[] {
  if (language !== 'javascript' && language !== 'typescript') return [];
  if (!/(?<![\w$.])(?:defineEventHandler|eventHandler)\s*\(/.test(code)) return [];
  const masked = maskLiterals(code);
  const lineStarts: number[] = [0];
  for (let i = 0; i < masked.length; i++) if (masked[i] === '\n') lineStarts.push(i + 1);
  const lineOf = (offset: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };

  const sources: TaintSource[] = [];
  const seen = new Set<string>();
  for (const m of masked.matchAll(HANDLER_CALL_RE)) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(masked, open);
    if (close < 0) continue;
    const span = masked.slice(open + 1, close);
    const head = FN_HEAD_RE.exec(span)
      ?? (/^\s*\{/.test(span) ? OBJECT_HANDLER_RE.exec(span) : null);
    const event = head?.slice(1).find(Boolean);
    if (!event) continue;

    for (const c of span.matchAll(INPUT_CALL_RE)) {
      if (c[2] !== event) continue;
      const at = open + 1 + c.index;
      const line = lineOf(at);
      const before = masked.slice(lineStarts[line - 1], at);
      const names = boundNames(before);
      const type = H3_INPUTS[c[1]];
      for (const variable of names.length > 0 ? names : [undefined]) {
        const key = `${line}:${variable ?? ''}`;
        if (seen.has(key)) continue;
        seen.add(key);
        sources.push({
          type,
          location: `h3 ${c[1]}(${event})${variable ? ` -> ${variable}` : ''}`,
          severity: 'high',
          line,
          confidence: 0.95,
          method: c[1],
          ...(variable ? { variable } : {}),
        });
      }
    }
  }
  return sources;
}
