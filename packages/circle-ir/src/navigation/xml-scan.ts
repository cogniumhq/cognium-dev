/**
 * A small, tolerant XML reader for registering files passed in as text
 * (deployment descriptors, plug-in manifests, component descriptions).
 *
 * It builds an element tree with attributes, direct text and the 1-based
 * line / 0-based column of each start tag. Comments, processing
 * instructions, `DOCTYPE` declarations (with an internal subset) and CDATA
 * sections are understood; the five predefined entities and character
 * references are decoded. Namespaces are not resolved: `name` is the local
 * part of a tag (`scr:component` → `component`). It never throws and is
 * linear in the input: malformed input yields whatever was read up to the
 * point it stops making sense, and nesting past `XML_MAX_DEPTH` stops it.
 * Tolerated beyond XML: unquoted attribute values, `/ >`, and junk inside a
 * tag (the tag closes at the next `>`).
 */

export interface XmlElement {
  /** The tag's local name (any `prefix:` removed). */
  name: string;
  /** Attributes as written (prefixes kept), values decoded. */
  attrs: ReadonlyMap<string, string>;
  children: XmlElement[];
  /** The element's own text (not its children's), decoded, untrimmed. */
  text: string;
  /** 1-based line of the start tag. */
  line: number;
  /** 0-based column of the start tag. */
  col: number;
}

const ENTITIES: Readonly<Record<string, string>> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decode(s: string): string {
  if (!s.includes('&')) return s;
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[A-Za-z]+);/g, (whole, ref: string) => {
    if (ref[0] === '#') {
      const code = ref[1] === 'x' ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[ref] ?? whole;
  });
}

function localName(qname: string): string {
  const i = qname.indexOf(':');
  return i >= 0 ? qname.slice(i + 1) : qname;
}

const NAME = /[A-Za-z_:][\w.:-]*/y;
const SPACE = /\s*/y;
// An unquoted value runs to a space or `>`; a `/` right before `>` closes the tag instead.
const UNQUOTED = /(?:[^\s>"'=<`/]|\/(?!\s*>))+/y;

/**
 * The deepest element kept. Registering files nest a handful of levels; past
 * this the input is not one, and reading stops with what was built so far.
 */
export const XML_MAX_DEPTH = 256;

/** The top-level elements of `text` (normally one, the document element). Linear in the input. */
export function parseXml(text: string): XmlElement[] {
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const at = (offset: number): { line: number; col: number } => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return { line: lo + 1, col: offset - lineStarts[lo] };
  };

  const top: XmlElement[] = [];
  const stack: XmlElement[] = [];
  // How many elements of each name are open: an end tag naming none is skipped without a scan.
  const open = new Map<string, number>();
  const popTo = (k: number): void => {
    for (let x = stack.length - 1; x >= k; x--) {
      const name = stack[x].name;
      open.set(name, (open.get(name) ?? 1) - 1);
    }
    stack.length = k;
  };
  const addText = (s: string): void => {
    if (stack.length > 0) stack[stack.length - 1].text += s;
  };
  let i = 0;
  const n = text.length;
  while (i < n) {
    const lt = text.indexOf('<', i);
    if (lt < 0) {
      addText(decode(text.slice(i)));
      break;
    }
    if (lt > i) addText(decode(text.slice(i, lt)));
    if (text.startsWith('<!--', lt)) {
      const end = text.indexOf('-->', lt + 4);
      if (end < 0) break;
      i = end + 3;
    } else if (text.startsWith('<![CDATA[', lt)) {
      const end = text.indexOf(']]>', lt + 9);
      if (end < 0) break;
      addText(text.slice(lt + 9, end));
      i = end + 3;
    } else if (text.startsWith('<?', lt)) {
      const end = text.indexOf('?>', lt + 2);
      if (end < 0) break;
      i = end + 2;
    } else if (text.startsWith('<!', lt)) {
      // DOCTYPE and other declarations. An internal subset `[ … ]` may hold `>`, quoted
      // literals, comments and processing instructions; a quote inside a comment is text.
      let j = lt + 2;
      let depth = 0;
      while (j < n) {
        const c = text[j];
        if (c === '<' && text.startsWith('<!--', j)) {
          const end = text.indexOf('-->', j + 4);
          if (end < 0) { j = n; break; }
          j = end + 3;
          continue;
        }
        if (c === '<' && text.startsWith('<?', j)) {
          const end = text.indexOf('?>', j + 2);
          if (end < 0) { j = n; break; }
          j = end + 2;
          continue;
        }
        if (c === '[') depth++;
        else if (c === ']') depth--;
        else if (c === '>' && depth <= 0) break;
        else if (c === '"' || c === "'") {
          const close = text.indexOf(c, j + 1);
          if (close < 0) { j = n; break; }
          j = close;
        }
        j++;
      }
      if (j >= n) break;
      i = j + 1;
    } else if (text[lt + 1] === '/') {
      const close = text.indexOf('>', lt + 2);
      if (close < 0) break;
      const name = localName(text.slice(lt + 2, close).trim());
      // Pop to the matching element; an end tag that matches nothing open is ignored.
      if ((open.get(name) ?? 0) > 0) {
        for (let k = stack.length - 1; k >= 0; k--) {
          if (stack[k].name === name) {
            popTo(k);
            break;
          }
        }
      }
      i = close + 1;
    } else {
      NAME.lastIndex = lt + 1;
      const m = NAME.exec(text);
      if (!m) {
        addText('<');
        i = lt + 1;
        continue;
      }
      const pos = at(lt);
      const el: XmlElement = { name: localName(m[0]), attrs: new Map(), children: [], text: '', line: pos.line, col: pos.col };
      const attrs = el.attrs as Map<string, string>;
      let j = NAME.lastIndex;
      let selfClosing = false;
      let ok = false;
      while (j < n) {
        SPACE.lastIndex = j;
        SPACE.exec(text);
        j = SPACE.lastIndex;
        if (text[j] === '/') {
          // `/>`, also written `/ >`
          SPACE.lastIndex = j + 1;
          SPACE.exec(text);
          if (text[SPACE.lastIndex] === '>') { selfClosing = true; j = SPACE.lastIndex + 1; ok = true; break; }
        }
        if (text[j] === '>') { j += 1; ok = true; break; }
        NAME.lastIndex = j;
        const a = NAME.exec(text);
        if (!a) {
          // Junk in the tag: close it at the next `>` with the attributes read so far.
          const close = text.indexOf('>', j);
          if (close < 0) break;
          selfClosing = text[close - 1] === '/';
          j = close + 1;
          ok = true;
          break;
        }
        j = NAME.lastIndex;
        SPACE.lastIndex = j;
        SPACE.exec(text);
        j = SPACE.lastIndex;
        if (text[j] !== '=') { attrs.set(a[0], ''); continue; }
        SPACE.lastIndex = j + 1;
        SPACE.exec(text);
        j = SPACE.lastIndex;
        const q = text[j];
        if (q !== '"' && q !== "'") {
          // An unquoted value (not XML, but written): up to the next space or `>`.
          UNQUOTED.lastIndex = j;
          const u = UNQUOTED.exec(text);
          attrs.set(a[0], u ? decode(u[0]) : '');
          if (u) j = UNQUOTED.lastIndex;
          continue;
        }
        const end = text.indexOf(q, j + 1);
        if (end < 0) break;
        attrs.set(a[0], decode(text.slice(j + 1, end)));
        j = end + 1;
      }
      if (!ok) break;
      if (!selfClosing && stack.length >= XML_MAX_DEPTH) break;
      if (stack.length > 0) stack[stack.length - 1].children.push(el);
      else top.push(el);
      if (!selfClosing) {
        stack.push(el);
        open.set(el.name, (open.get(el.name) ?? 0) + 1);
      }
      i = j;
    }
  }
  return top;
}

/** Every element of the trees in document order (each element before its children). */
export function* xmlElements(roots: readonly XmlElement[]): Generator<XmlElement> {
  const stack = [...roots].reverse();
  while (stack.length > 0) {
    const el = stack.pop() as XmlElement;
    yield el;
    for (let k = el.children.length - 1; k >= 0; k--) stack.push(el.children[k]);
  }
}

/** The trimmed text of the first child named `name`, or `undefined`. */
export function childText(el: XmlElement, name: string): string | undefined {
  const c = el.children.find(x => x.name === name);
  return c ? c.text.trim() : undefined;
}
