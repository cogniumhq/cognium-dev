/**
 * NestJS controller handler return values as sinks.
 *
 * With the default Express adapter, a route handler's return value is the
 * response body, and a `string` is sent as `text/html`. A handler that
 * returns a string built from request input is reflected XSS:
 *
 *   @Controller('greet')
 *   export class GreetController {
 *     @Get()
 *     hello(@Query('name') name: string) {
 *       return `<h1>Hello ${name}</h1>`;          // xss
 *     }
 *   }
 *
 * A handler decorated `@Redirect()` redirects to the `url` of the object it
 * returns, so `return { url: next }` with request input is an open redirect.
 *
 * Positive evidence only:
 *   - the class carries `@Controller(...)` and the method an HTTP-method
 *     decorator (`@Get`, `@Post`, `@Put`, `@Delete`, `@Patch`, `@Options`,
 *     `@Head`, `@All`, `@Search`);
 *   - the returned expression reads a request-bound parameter (`@Query`,
 *     `@Param`, `@Body`, `@Headers`), an in-method source (a `@Req()` read),
 *     or a local assigned from one;
 *   - for xss, the expression builds a string (a template literal with a
 *     substitution, or a concatenation with a string literal), or it is a
 *     carrier whose value is text: a `string` parameter, a keyed
 *     `@Query('name')` / `@Param('id')` / `@Headers('h')` parameter, a local
 *     assigned such a string, or any read of a carrier when the handler is
 *     declared to return `string`.
 *
 * Not a sink: a returned object or array (sent as JSON), a constant, a
 * redirect `url` that starts with a fixed `https://host/` origin, a call
 * whose result is not known to be text, a handler with
 * `@Header('Content-Type', …)` naming a non-HTML type, a handler that takes
 * `@Res()` / `@Response()` without `passthrough` (it writes the response
 * itself), a `@Render(...)` or `@Sse()` handler, a carrier only passed
 * through an HTML encoder or a numeric conversion, a parameter declared
 * `number`, `boolean` or `Date`, and a `return` inside a nested function.
 */

import type { TypeInfo } from '../types/index.js';
import { maskLiterals } from './passes/prototype-pollution-pass.js';

export interface NestReturnSink {
  sinkLine: number;
  sourceLine: number;
  type: 'xss' | 'open_redirect';
  /** The request-bound names the returned expression reads. */
  carriers: string[];
}

const IDENT = String.raw`[A-Za-z_$][\w$]*`;
const HTTP_METHOD_DECORATOR = /^(?:Get|Post|Put|Delete|Patch|Options|Head|All|Search)$/;
const REQUEST_PARAM_DECORATOR = /^(?:Query|Param|Body|Headers)$/;
const NON_TEXT_TYPE = /^(?:number|bigint|boolean|Date)(?:\s*\|\s*(?:undefined|null))*$/;
/** Calls whose result carries no markup from their argument. */
const NEUTRALISING_CALL = new RegExp(
  String.raw`(?<![\w$.])(?:(?:DOMPurify|validator|he|entities|xssFilters|Math)\s*\.\s*${IDENT}|sanitizeHtml|sanitize|escapeHtml|escapeHTML|htmlEscape|escape|encode|xss|encodeURIComponent|encodeURI|Number|parseInt|parseFloat|Boolean)\s*\(`,
);

const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * `expr` with string literal text blanked (a template literal keeps only its
 * `${…}` substitutions) and the argument lists of neutralising calls dropped:
 * what remains is the code whose value can reach the output unchanged.
 */
function rawValueCode(expr: string): string {
  let out = '';
  for (let k = 0; k < expr.length; k++) {
    const ch = expr[k];
    if (ch === "'" || ch === '"') {
      let e = k + 1;
      while (e < expr.length && expr[e] !== ch) e += expr[e] === '\\' ? 2 : 1;
      out += "''";
      k = e;
    } else if (ch === '`') {
      let e = k + 1;
      let subs = '';
      while (e < expr.length && expr[e] !== '`') {
        if (expr[e] === '\\') { e += 2; continue; }
        if (expr[e] === '$' && expr[e + 1] === '{') {
          let depth = 0;
          let close = e + 1;
          for (; close < expr.length; close++) {
            if (expr[close] === '{') depth++;
            else if (expr[close] === '}' && --depth === 0) break;
          }
          subs += ` (${expr.slice(e + 2, close)})`;
          e = close + 1;
          continue;
        }
        e++;
      }
      out += `''${subs}`;
      k = e;
    } else {
      out += ch;
    }
  }
  for (let guard = 0; guard < 32; guard++) {
    const m = NEUTRALISING_CALL.exec(out);
    if (!m) break;
    let depth = 0;
    let close = out.length - 1;
    for (let i = m.index + m[0].length - 1; i < out.length; i++) {
      if (out[i] === '(') depth++;
      else if (out[i] === ')' && --depth === 0) { close = i; break; }
    }
    out = `${out.slice(0, m.index)}0${out.slice(close + 1)}`;
  }
  return out;
}

/** Decorator texts written on the lines directly above `line` (1-based). */
function decoratorsAbove(lines: readonly string[], line: number): string[] {
  const out: string[] = [];
  let buf = '';
  for (let i = line - 2; i >= 0; i--) {
    const t = (lines[i] ?? '').trim();
    if (t === '' || t.startsWith('//')) continue;
    buf = buf ? `${t} ${buf}` : t;
    if (t.startsWith('@')) {
      out.unshift(buf);
      buf = '';
      continue;
    }
    // A decorator whose arguments wrap over several lines.
    if (/^[)\]},'"`\w]/.test(t) && !/[;{]$/.test(t) && !/^(?:export|class|public|private|protected|static|async)\b/.test(t)) continue;
    break;
  }
  return out;
}

/** The statement starting at offset `from` of `text`, up to a top-level `;` or an unmatched closer. */
function readStatement(text: string, from: number): string {
  let depth = 0;
  for (let i = from; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      for (i++; i < text.length && text[i] !== ch; i++) {
        if (text[i] === '\\') { i++; continue; }
        if (ch === '`' && text[i] === '$' && text[i + 1] === '{') {
          let d = 0;
          for (; i < text.length; i++) {
            if (text[i] === '{') d++;
            else if (text[i] === '}' && --d === 0) break;
          }
        }
      }
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      if (--depth < 0) return text.slice(from, i);
    } else if (ch === ';' && depth === 0) return text.slice(from, i);
  }
  return text.slice(from);
}

/**
 * Whether the `{` at `at` of masked `text` opens a function body (an arrow
 * function, a function expression, or an object-literal / class method)
 * rather than a block or an object literal.
 */
function opensFunction(masked: string, at: number): boolean {
  const before = masked.slice(0, at).trimEnd();
  if (before.endsWith('=>')) return true;
  if (!before.endsWith(')')) {
    // A return type annotation between `)` and `{`: `(x): string {`.
    return /\)\s*:\s*[^;{}()=\s][^;{}()=]*$/.test(before)
      && !/(?:^|[^\w$.])(?:if|for|while|switch|catch|with)\s*\([^)]*\)\s*:/.test(before);
  }
  let depth = 0;
  for (let k = before.length - 1; k >= 0; k--) {
    if (before[k] === ')') depth++;
    else if (before[k] === '(' && --depth === 0) {
      return !/(?:^|[^\w$.])(?:if|for|while|switch|catch|with)$/.test(before.slice(0, k).trimEnd());
    }
  }
  return false;
}

/**
 * The method body of `text` (a method's source, from its first line to the
 * line of its closing brace): the offset of the `{` matching the last `}`,
 * and the offsets of the `return` keywords that belong to it rather than to
 * a nested function. Null when the braces do not balance.
 */
function methodBody(text: string): { open: number; returns: number[] } | null {
  const masked = maskLiterals(text);
  const close = masked.lastIndexOf('}');
  if (close < 0) return null;
  let depth = 0;
  let open = -1;
  for (let i = close; i >= 0; i--) {
    if (masked[i] === '}') depth++;
    else if (masked[i] === '{' && --depth === 0) { open = i; break; }
  }
  if (open < 0) return null;
  const stack: boolean[] = [];
  const returns: number[] = [];
  for (let i = open + 1; i < close; i++) {
    const ch = masked[i];
    if (ch === '{') stack.push(opensFunction(masked, i));
    else if (ch === '}') stack.pop();
    else if (ch === 'r' && masked.startsWith('return', i) && !/[\w$.]/.test(masked[i - 1] ?? '')
      && !/[\w$]/.test(masked[i + 6] ?? '') && !stack.some(Boolean)) {
      returns.push(i);
    }
  }
  return { open, returns };
}

/** `expr` with everything inside brackets dropped; top-level string literals are kept. */
function topLevelText(expr: string): string {
  let out = '';
  let depth = 0;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      while (j < expr.length && expr[j] !== ch) j += expr[j] === '\\' ? 2 : 1;
      if (depth === 0) out += expr.slice(i, j + 1);
      i = j;
    } else if (ch === '(' || ch === '[' || ch === '{') {
      if (depth++ === 0) out += ch;
    } else if (ch === ')' || ch === ']' || ch === '}') {
      if (--depth === 0) out += ch;
    } else if (depth === 0) {
      out += ch;
    }
  }
  return out;
}

/**
 * The value text of property `key` of the object literal `expr` (the key
 * itself for a shorthand `{ key }`), or undefined when `expr` is not an
 * object literal with that property at its top level.
 */
function objectProperty(expr: string, key: string): string | undefined {
  const text = expr.trim();
  if (!text.startsWith('{') || !text.endsWith('}')) return undefined;
  const entries: string[] = [];
  let depth = 0;
  let start = 1;
  for (let i = 1; i < text.length - 1; i++) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      for (i++; i < text.length && text[i] !== ch; i++) if (text[i] === '\\') i++;
    } else if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) { entries.push(text.slice(start, i)); start = i + 1; }
  }
  entries.push(text.slice(start, text.length - 1));
  for (const raw of entries) {
    const entry = raw.trim();
    if (entry === key) return key;
    const colon = entry.indexOf(':');
    if (colon > 0 && entry.slice(0, colon).trim().replace(/^(['"])(.*)\1$/, '$2') === key) {
      return entry.slice(colon + 1).trim();
    }
  }
  return undefined;
}

function isClassController(lines: readonly string[], t: TypeInfo): boolean {
  if ((t.annotations ?? []).includes('Controller')) return true;
  const own = lines[t.start_line - 1] ?? '';
  const cls = own.search(/\bclass\b/);
  if (cls > 0 && /@Controller\s*\(/.test(own.slice(0, cls))) return true;
  return decoratorsAbove(lines, t.start_line).some(d => /^@Controller\s*\(/.test(d));
}

export function findJsNestReturnSinks(
  code: string,
  language: string,
  types: ReadonlyArray<TypeInfo>,
  sources: ReadonlyArray<{ line: number; type: string; variable?: string }>,
): NestReturnSink[] {
  if (language !== 'javascript' && language !== 'typescript') return [];
  if (!/@Controller\s*\(/.test(code)) return [];
  const lines = code.split('\n');
  const out: NestReturnSink[] = [];

  for (const t of types) {
    if (t.kind !== 'class' || !isClassController(lines, t)) continue;
    for (const m of t.methods) {
      const decorators = decoratorsAbove(lines, m.start_line);
      const names = new Set([
        ...m.annotations,
        ...decorators.map(d => /^@([A-Za-z_$][\w$]*)/.exec(d)?.[1] ?? ''),
      ]);
      if (![...names].some(n => HTTP_METHOD_DECORATOR.test(n))) continue;
      if (names.has('Render') || names.has('Sse')) continue;
      const body = lines.slice(m.start_line - 1, m.end_line).join('\n');
      const parsed = methodBody(body);
      if (!parsed) continue;
      const signature = body.slice(0, parsed.open);
      // `@Res()` without `{ passthrough: true }`: the handler writes the response itself.
      if (/@(?:Res|Response)\s*\(\s*\)/.test(signature)) continue;
      const redirect = names.has('Redirect');
      const contentType = decorators
        .map(d => /^@Header\s*\(\s*(['"`])content-type\1\s*,\s*(['"`])([^'"`]*)\2/i.exec(d)?.[3])
        .find((v): v is string => v !== undefined);
      if (!redirect && contentType !== undefined && !/html/i.test(contentType)) continue;
      const declaredString = /\)\s*:\s*(?:Promise\s*<\s*string\s*>|string)\s*$/.test(signature);

      // Seeds: request-bound parameters, then in-method sources with a variable.
      const seeds = new Map<string, { line: number; text: boolean }>();
      for (const p of m.parameters) {
        if (!p.annotations.some(a => REQUEST_PARAM_DECORATOR.test(a))) continue;
        if (!new RegExp(`^${IDENT}$`).test(p.name)) continue;
        const type = (p.type ?? '').trim();
        if (NON_TEXT_TYPE.test(type)) continue;
        const keyed = new RegExp(String.raw`@(?:Query|Param|Headers)\s*\(\s*(['"\`])[^'"\`]*\1\s*(?:,[^)]*)?\)\s*${esc(p.name)}(?![\w$])`).test(signature);
        seeds.set(p.name, { line: p.line ?? m.start_line, text: /^string\b/.test(type) || (type === '' && keyed) });
      }
      for (const s of sources) {
        if (s.type === 'interprocedural_param' || !s.variable) continue;
        if (!new RegExp(`^${IDENT}$`).test(s.variable)) continue;
        if (s.line < m.start_line || s.line > m.end_line || seeds.has(s.variable)) continue;
        seeds.set(s.variable, { line: s.line, text: false });
      }
      if (seeds.size === 0) continue;

      const refersTo = (expr: string, name: string): boolean =>
        new RegExp(`(?<![\\w$.])${esc(name)}(?![\\w$])`).test(rawValueCode(expr));
      // The value itself is text built here: a template literal, or a
      // top-level concatenation with a string literal (not one inside a
      // call's arguments, as in `execSync('ls ' + dir).toString()`).
      const buildsString = (expr: string): boolean => {
        const e = expr.trim();
        if (/^`[\s\S]*\$\{[\s\S]*`$/.test(e)) return true;
        return /(?:['"`]\s*\+|\+\s*['"`])/.test(topLevelText(e));
      };

      // Locals assigned from a carrier, in line order; a reassignment from
      // anything else ends the carrier.
      const carriers = new Map<string, { sourceLine: number; text: boolean }>();
      for (const [n, s] of seeds) carriers.set(n, { sourceLine: s.line, text: s.text });
      const assignRe = new RegExp(String.raw`^\s*(?:(?:const|let|var)\s+)?(${IDENT})\s*(?::[^=;]+)?=(?![=>])\s*`);
      for (let i = m.start_line; i < Math.min(m.end_line, lines.length); i++) {
        const am = assignRe.exec(lines[i] ?? '');
        if (!am) continue;
        const rhs = readStatement(lines.slice(i, m.end_line).join('\n'), am[0].length);
        const from = [...carriers].find(([c]) => refersTo(rhs, c));
        if (from) carriers.set(am[1], { sourceLine: from[1].sourceLine, text: buildsString(rhs) || from[1].text });
        else if (seeds.get(am[1])?.line !== i + 1) carriers.delete(am[1]);
      }

      for (const at of parsed.returns) {
        const sinkLine = m.start_line + body.slice(0, at).split('\n').length - 1;
        const expr = readStatement(body, at + 'return'.length).trim().replace(/^await\s+/, '');
        if (expr === '') continue;
        let hit: Array<[string, { sourceLine: number; text: boolean }]>;
        let type: NestReturnSink['type'];
        if (redirect) {
          const value = objectProperty(expr, 'url');
          if (value === undefined) continue;
          // A fixed origin (`https://docs.example.com/${v}`) keeps the redirect on that host.
          if (/^(['"`])https?:\/\/[^/'"`$\s]+\//i.test(value)) continue;
          hit = [...carriers].filter(([c]) => refersTo(value, c));
          type = 'open_redirect';
        } else {
          if (/^[{[]/.test(expr)) continue;
          hit = [...carriers].filter(([c]) => refersTo(expr, c));
          if (hit.length === 0) continue;
          const read = new RegExp(String.raw`^${IDENT}(?:\s*\??\.\s*${IDENT}|\s*\[\s*(?:'[^']*'|"[^"]*"|\d+)\s*\])*$`).test(expr);
          const bare = new RegExp(`^${IDENT}$`).test(expr);
          const text = buildsString(expr)
            || (bare && hit.some(([, info]) => info.text))
            || (declaredString && read);
          if (!text) continue;
          type = 'xss';
        }
        if (hit.length === 0) continue;
        out.push({
          sinkLine,
          sourceLine: Math.min(...hit.map(([, info]) => info.sourceLine)),
          type,
          carriers: hit.map(([c]) => c),
        });
      }
    }
  }
  return out;
}
