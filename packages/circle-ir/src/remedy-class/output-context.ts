/**
 * Output context: where in an HTML document a value lands, read from the
 * markup written before it. A small state scan over the literal text: element
 * content, a quoted or unquoted attribute value (URL-valued attributes apart),
 * or a script block (inside a string literal or not).
 *
 * The scan follows HTML's tokenizer only as far as these states need; which
 * encoder suits which context is not decided here — a caller's table says
 * that, with its rows' `context`.
 */

export type OutputContext =
  | 'html-content'
  | 'html-attribute-quoted'
  | 'html-attribute-unquoted'
  | 'url'
  | 'js-string'
  | 'js'
  | 'unknown';

/** Attributes whose value HTML parses as a URL. */
const URL_ATTRIBUTES = new Set([
  'href', 'src', 'action', 'formaction', 'cite', 'poster', 'data', 'background',
  'longdesc', 'codebase', 'manifest', 'icon', 'srcset', 'xlink:href',
]);

/**
 * The context at the end of `markup`: where the next written value lands.
 * Event-handler attributes (`on*`) are JavaScript and come out `unknown`, as
 * does a position inside a tag outside any attribute value.
 */
export function htmlContextAt(markup: string): OutputContext {
  type State =
    | { k: 'text' }
    | { k: 'tag'; name: string; attr: string; afterEq: boolean }
    | { k: 'value'; tag: string; attr: string; quote: string }
    | { k: 'unquoted'; tag: string; attr: string }
    | { k: 'script'; quote: string | null };
  let st: State = { k: 'text' };
  const lower = markup.toLowerCase();
  let i = 0;
  while (i < markup.length) {
    const c = markup[i];
    switch (st.k) {
      case 'text': {
        if (c === '<') {
          const m = /^<\/?([a-z][a-z0-9:-]*)/.exec(lower.slice(i));
          if (m) {
            const closing = lower[i + 1] === '/';
            st = closing ? { k: 'tag', name: '/', attr: '', afterEq: false } : { k: 'tag', name: m[1], attr: '', afterEq: false };
            i += m[0].length;
            continue;
          }
        }
        break;
      }
      case 'tag': {
        if (c === '>') {
          st = st.name === 'script' ? { k: 'script', quote: null } : { k: 'text' };
        } else if (c === '=') {
          st = { ...st, afterEq: true };
        } else if (c === '"' || c === "'") {
          st = st.afterEq ? { k: 'value', tag: st.name, attr: st.attr, quote: c } : st;
        } else if (/\s/.test(c)) {
          // whitespace between attributes
        } else if (st.afterEq) {
          st = { k: 'unquoted', tag: st.name, attr: st.attr };
          continue;
        } else {
          const m = /^[^\s=>/"']+/.exec(lower.slice(i));
          if (m) {
            st = { ...st, attr: m[0], afterEq: false };
            i += m[0].length;
            continue;
          }
        }
        break;
      }
      case 'value': {
        if (c === st.quote) st = { k: 'tag', name: st.tag, attr: '', afterEq: false };
        break;
      }
      case 'unquoted': {
        if (/\s/.test(c)) st = { k: 'tag', name: st.tag, attr: '', afterEq: false };
        else if (c === '>') st = st.tag === 'script' ? { k: 'script', quote: null } : { k: 'text' };
        break;
      }
      case 'script': {
        if (st.quote === null && lower.startsWith('</script', i)) {
          st = { k: 'tag', name: '/', attr: '', afterEq: false };
          i += '</script'.length;
          continue;
        }
        if (st.quote !== null && c === '\\') {
          i += 2;
          continue;
        }
        if (c === '"' || c === "'" || c === '`') {
          st = { k: 'script', quote: st.quote === null ? c : st.quote === c ? null : st.quote };
        }
        break;
      }
    }
    i++;
  }
  switch (st.k) {
    case 'text':
      return 'html-content';
    case 'value':
      if (st.attr.startsWith('on') || st.attr === 'style') return 'unknown';
      return URL_ATTRIBUTES.has(st.attr) ? 'url' : 'html-attribute-quoted';
    case 'unquoted':
      if (st.attr.startsWith('on') || st.attr === 'style') return 'unknown';
      return URL_ATTRIBUTES.has(st.attr) ? 'url' : 'html-attribute-unquoted';
    case 'script':
      return st.quote !== null ? 'js-string' : 'js';
    case 'tag':
      // right after `attr=`: the value starts here, unquoted
      if (st.afterEq && st.attr) {
        if (st.attr.startsWith('on') || st.attr === 'style') return 'unknown';
        return URL_ATTRIBUTES.has(st.attr) ? 'url' : 'html-attribute-unquoted';
      }
      return 'unknown';
  }
}

/** The string literals of a Java expression, in order, unescaped. */
export function javaStringLiterals(expr: string): string[] {
  const out: string[] = [];
  for (const m of expr.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    out.push(m[1].replace(/\\(u[0-9a-fA-F]{4}|.)/g, (_, e: string) => {
      if (e.length === 5) return String.fromCharCode(parseInt(e.slice(1), 16));
      return ({ n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '0': '\0' } as Record<string, string>)[e] ?? e;
    }));
  }
  return out;
}

/**
 * The markup a Java expression writes before the first of `names` (a tainted
 * identifier): its string literals up to that point, concatenated.
 */
export function markupBefore(expr: string, names: ReadonlySet<string>): string | null {
  // mask string literals so an identifier inside one is not taken for the value
  const masked = expr.replace(/"(?:[^"\\]|\\.)*"/g, m => '"' + ' '.repeat(m.length - 2) + '"');
  let at = -1;
  for (const m of masked.matchAll(/[A-Za-z_$][\w$]*/g)) {
    if (names.has(m[0]) && masked[(m.index ?? 0) - 1] !== '.') {
      at = m.index ?? -1;
      break;
    }
  }
  if (at < 0) return null;
  return javaStringLiterals(expr.slice(0, at)).join('');
}
