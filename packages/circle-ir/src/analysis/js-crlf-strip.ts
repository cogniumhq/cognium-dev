/**
 * Whether a JavaScript / TypeScript `String.replace` chain strips CR and LF
 * (cognium-dev#562, the JS half of the Java rule in `java-crlf-strip.ts`).
 *
 * The decision is made by running the chain's own literal patterns against a
 * short probe string, so a regex is judged by what it matches rather than by how
 * it is spelled (`/[\r\n]/g`, `/\r|\n/g`, `/\s+/g` and `/[\x00-\x1f]/g` all
 * strip both). Only literal arguments are understood: a pattern held in a
 * variable, a `new RegExp(...)`, or a replacement that is a function or a
 * non-literal makes the whole chain `undecided`, and the caller keeps the credit
 * the class-less `replace` row gave before.
 */

export type JsReplaceVerdict = 'strips-crlf' | 'leaves-crlf' | 'undecided';

interface ReplaceStep {
  /** `replace` / `replaceAll`. */
  kind: 'replace' | 'replaceAll';
  pattern: RegExp | string;
  replacement: string;
}

const MAX_PATTERN_LENGTH = 200;

/** String methods that may follow a replace in a judged chain without changing its CR / LF coverage. */
const NEUTRAL_AFTER_REPLACE = new Set([
  'replace', 'replaceAll', 'trim', 'trimStart', 'trimEnd', 'toString',
  'toLowerCase', 'toUpperCase', 'slice', 'substring',
]);

/** Probe text: lone and doubled CR / LF, a CRLF pair and neutral characters. */
const PROBE = 'a\r\rb\n\nc\r\nd\n\re x\t';

function readQuoted(s: string, i: number): { value: string; end: number } | null {
  const q = s[i]!;
  if (q !== '"' && q !== "'" && q !== '`') return null;
  let out = '';
  for (let j = i + 1; j < s.length; j++) {
    const c = s[j]!;
    if (c === q) return { value: out, end: j + 1 };
    if (q === '`' && c === '$' && s[j + 1] === '{') return null;
    if (c === '\\') {
      const n = s[j + 1];
      if (n === undefined) return null;
      switch (n) {
        case 'n': out += '\n'; j++; continue;
        case 'r': out += '\r'; j++; continue;
        case 't': out += '\t'; j++; continue;
        case '0': out += '\0'; j++; continue;
        case 'x': {
          const h = /^[0-9a-fA-F]{2}/.exec(s.slice(j + 2, j + 4));
          if (!h) return null;
          out += String.fromCharCode(parseInt(h[0], 16)); j += 3; continue;
        }
        case 'u': {
          const h = /^[0-9a-fA-F]{4}/.exec(s.slice(j + 2, j + 6));
          if (!h) return null;
          out += String.fromCharCode(parseInt(h[0], 16)); j += 5; continue;
        }
        default:
          out += n; j++; continue;
      }
    }
    if (c === '\n' && q !== '`') return null;
    out += c;
  }
  return null;
}

function readRegexLiteral(s: string, i: number): { source: string; flags: string; end: number } | null {
  if (s[i] !== '/') return null;
  let inClass = false;
  for (let j = i + 1; j < s.length; j++) {
    const c = s[j]!;
    if (c === '\n') return null;
    if (c === '\\') { j++; continue; }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; continue; }
    if (c === '/') {
      const flags = /^[dgimsuvy]*/.exec(s.slice(j + 1))![0];
      return { source: s.slice(i + 1, j), flags, end: j + 1 + flags.length };
    }
  }
  return null;
}

const skipWs = (s: string, i: number): number => {
  while (i < s.length && /\s/.test(s[i]!)) i++;
  return i;
};

/**
 * Parse every `.replace(<literal>, <string literal>)` / `.replaceAll(...)` step
 * of a chain, in source order. Returns null when any step is not literal.
 */
function parseSteps(chainText: string): ReplaceStep[] | null {
  const steps: ReplaceStep[] = [];
  const callRe = /\.\s*(replaceAll|replace)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(chainText)) !== null) {
    const kind = m[1] as 'replace' | 'replaceAll';
    let i = skipWs(chainText, m.index + m[0].length);
    let pattern: RegExp | string;
    const rx = readRegexLiteral(chainText, i);
    if (rx) {
      if (rx.source.length > MAX_PATTERN_LENGTH) return null;
      try { pattern = new RegExp(rx.source, rx.flags); } catch { return null; }
      i = rx.end;
    } else {
      const str = readQuoted(chainText, i);
      if (!str) return null;
      pattern = str.value;
      i = str.end;
    }
    i = skipWs(chainText, i);
    if (chainText[i] !== ',') return null;
    i = skipWs(chainText, i + 1);
    const rep = readQuoted(chainText, i);
    if (!rep) return null;
    i = skipWs(chainText, rep.end);
    if (chainText[i] !== ')') return null;
    steps.push({ kind, pattern, replacement: rep.value });
    callRe.lastIndex = i + 1;
  }
  return steps;
}

function run(steps: ReplaceStep[], input: string): string | null {
  let s = input;
  try {
    for (const st of steps) {
      if (st.kind === 'replaceAll' && st.pattern instanceof RegExp && !st.pattern.global) return null;
      s = st.kind === 'replaceAll'
        ? s.replaceAll(st.pattern, st.replacement)
        : s.replace(st.pattern, st.replacement);
    }
  } catch {
    return null;
  }
  return s;
}

/**
 * Verdict for the replace chain whose text is `chainText` (the receiver plus the
 * `.method(...)` segments after it).
 */
export function jsReplaceChainVerdict(chainText: string): JsReplaceVerdict {
  const steps = parseSteps(chainText);
  if (!steps || steps.length === 0) return 'undecided';
  // Another transform after the first replace may strip CR / LF on its own
  // (`.split("\r").join("")`): the chain is only judged when every later
  // segment is a replace or a harmless string method.
  const first = chainText.search(/\.\s*(?:replaceAll|replace)\s*\(/);
  for (const seg of chainText.slice(first + 1).matchAll(/\.\s*([A-Za-z_$][\w$]*)\s*\(/g)) {
    if (!NEUTRAL_AFTER_REPLACE.has(seg[1]!)) return 'undecided';
  }
  const out = run(steps, PROBE);
  if (out === null) return 'undecided';
  return out.includes('\r') || out.includes('\n') ? 'leaves-crlf' : 'strips-crlf';
}

/**
 * The text of the call chain that starts at (line, column): the receiver
 * expression plus the `.method(...)` segments after it, up to the first
 * character that cannot continue the chain at nesting depth 0. String and regex
 * literals are skipped as units. The chain may continue over following lines.
 */
export function jsChainTextAt(sourceLines: string[], line: number, column: number): string {
  const text = [(sourceLines[line - 1] ?? '').slice(column), ...sourceLines.slice(line, line + 7)].join('\n');
  let depth = 0;
  let prevSig = '';
  let i = 0;
  for (; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++;
      prevSig = c;
      continue;
    }
    if (c === '/' && depth > 0 && (prevSig === '(' || prevSig === ',')) {
      const rx = readRegexLiteral(text, i);
      if (rx) { i = rx.end - 1; prevSig = '/'; continue; }
    }
    if (c === '(' || c === '[' || c === '{') { depth++; prevSig = c; continue; }
    if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
      prevSig = c;
      continue;
    }
    if (depth === 0 && !/[\w$.\s]/.test(c)) break;
    if (!/\s/.test(c)) prevSig = c;
  }
  return text.slice(0, i);
}
