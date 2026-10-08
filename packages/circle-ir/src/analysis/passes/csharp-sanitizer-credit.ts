/**
 * C# sanitizer and guard credit (cognium-dev C#/.NET Phase-1, #518).
 *
 * C# rides the text-scan propagation, which knows nothing about sanitizers, so
 * `SinkFilterPass` Stage 15k drops a sink when the value reaching it has been
 * made safe. This module answers that question for one sink at a time, inside
 * the method that contains it:
 *
 *   - `sanitizedVarsAt`   the value passed through a sanitizer for the sink's
 *                         type, directly or through a same-file helper;
 *   - `guardedVarsAt`     a check that dominates the sink proves the value
 *                         inert (allowlist, numeric parse, host allowlist);
 *   - `fixedHostRequest`  the request URL has a constant host.
 *
 * Everything is matched on source text and is deliberately narrow: when a
 * shape is not recognised the sink stays, so a miss here is a false positive,
 * never a silently dropped finding.
 */

/**
 * `Regex.Replace(x, "[^<allowlist>]", "")` — an allowlist character strip
 * (cognium-dev#272, the LDAP-strip cluster).
 *
 * A **negated** class is the whole point: `[^a-zA-Z0-9]` deletes everything
 * *not* in the set, so the surviving characters are exactly the set. That makes
 * the result provably inert for the metacharacter-driven injection families
 * below. A blacklist replace (`"[<>]"`) proves nothing — it enumerates what to
 * remove and silently misses the rest — and must not match.
 *
 * Two conditions, both load-bearing:
 *
 *  (a) the pattern is a string literal beginning `[^`. A computed pattern could
 *      be anything, including attacker-influenced.
 *  (b) the surviving set contains **no metacharacters**. `[^a-zA-Z0-9']` would
 *      keep the single quote alive, which breaks SQL and LDAP escaping outright
 *      — so the class body is restricted to alphanumerics, `\w`, `\d`, `\s`,
 *      underscore, hyphen and spaces. Anything else (quote, paren, backslash,
 *      dot, asterisk, semicolon) fails the match and the sink still fires.
 *
 * The replacement must be empty or a single safe character, so
 * `Regex.Replace(x, "[^a-z]", "';DROP")` cannot qualify.
 */
export const CSHARP_ALLOWLIST_STRIP_RE =
  /\bRegex\s*\.\s*Replace\s*\([^,]*,\s*@?"\[\^(?:[A-Za-z0-9_\- ]|\\w|\\d|\\s)+\]"\s*,\s*@?"[A-Za-z0-9_]?"\s*\)/;

/**
 * `new string(x.Where(char.IsLetterOrDigit).ToArray())` — the LINQ spelling of
 * the same allowlist strip: only letters and digits survive.
 */
const CSHARP_ALLOWLIST_FILTER_RE =
  /\bnew\s+string\s*\(\s*[A-Za-z_]\w*\s*\.\s*Where\s*\(\s*char\s*\.\s*Is(?:LetterOrDigit|Digit|Letter)\s*\)\s*\.\s*ToArray\s*\(\s*\)\s*\)/;

// C# sanitizers and the sink types each neutralises. A tainted value that
// flows through one of these before reaching a sink of the matching type is
// safe. Method names are C#-distinctive (see config-loader C# sanitizers).
export const CSHARP_SANITIZER_RES: Array<{ re: RegExp; type: string }> = [
  { re: /\b(?:HtmlEncode|JavaScriptStringEncode)\s*\(/, type: 'xss' },
  // `HtmlEncoder.Default.Encode(x)` is the ASP.NET Core spelling (#520).
  { re: /\bHtmlEncoder\s*\.\s*(?:Default\s*\.\s*)?Encode\s*\(/, type: 'xss' },
  { re: /\bPath\s*\.\s*GetFileName\s*\(/, type: 'path_traversal' },
  // XML-escapes `< > & " '`. A value escaped this way cannot close the quoted
  // literal it is placed in, which is what XPath injection needs.
  { re: /\bSecurityElement\s*\.\s*Escape\s*\(/, type: 'xpath_injection' },
  // An allowlist strip leaves only inert characters, so it covers every family
  // whose exploitation needs a metacharacter. Each has a fixture; see
  // `issue-272-csharp-allowlist-strip.test.ts`.
  { re: CSHARP_ALLOWLIST_STRIP_RE, type: 'ldap_injection' },
  { re: CSHARP_ALLOWLIST_STRIP_RE, type: 'xpath_injection' },
  { re: CSHARP_ALLOWLIST_STRIP_RE, type: 'command_injection' },
  { re: CSHARP_ALLOWLIST_STRIP_RE, type: 'sql_injection' },
  { re: CSHARP_ALLOWLIST_STRIP_RE, type: 'crlf' },
  { re: CSHARP_ALLOWLIST_FILTER_RE, type: 'ldap_injection' },
  { re: CSHARP_ALLOWLIST_FILTER_RE, type: 'xpath_injection' },
  { re: CSHARP_ALLOWLIST_FILTER_RE, type: 'command_injection' },
  { re: CSHARP_ALLOWLIST_FILTER_RE, type: 'sql_injection' },
  { re: CSHARP_ALLOWLIST_FILTER_RE, type: 'crlf' },
];

/**
 * Sink types for which a value made only of letters, digits, `_` and `-` is
 * inert: each needs a metacharacter (quote, paren, slash, angle bracket, CR/LF)
 * to be exploited.
 */
const INERT_WHEN_ALPHANUMERIC: ReadonlySet<string> = new Set([
  'ldap_injection', 'xpath_injection', 'command_injection', 'sql_injection',
  'crlf', 'xss', 'path_traversal', 'code_injection',
]);

export interface CsMethodRange {
  name: string;
  start_line: number;
  end_line: number;
}

const IDENT = '[A-Za-z_]\\w*';
const ASSIGN_RE = new RegExp(`^\\s*(?:var\\s+|[A-Za-z_][\\w.<>\\[\\]?]*\\s+)?(${IDENT})\\s*=(?!=)\\s*(.+?);?\\s*$`);
const ENDS_STATEMENT_RE = /[;{}]\s*(?:\/\/.*)?$/;

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function withoutStringLiterals(text: string): string {
  return text.replace(/@"(?:[^"]|"")*"|"(?:[^"\\]|\\.)*"/g, '""');
}

function mentions(text: string, name: string): boolean {
  return new RegExp(`(?<![\\w])${escapeRegex(name)}(?![\\w])`).test(text);
}

/** Text inside the parentheses opening at `open`, or null when unbalanced. */
function insideParens(text: string, open: number): string | null {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return text.slice(open + 1, i);
  }
  return null;
}

/** The argument text of the last call on a line: `a.B(c).D(e + f);` gives `e + f`. */
function lastCallArguments(text: string): string | null {
  const close = text.lastIndexOf(')');
  if (close < 0) return null;
  let depth = 0;
  for (let i = close; i >= 0; i--) {
    if (text[i] === ')') depth++;
    else if (text[i] === '(' && --depth === 0) return text.slice(i + 1, close);
  }
  return null;
}

/** `if (COND) rest` at the start of `text`. */
function leadingIf(text: string): { cond: string; rest: string } | null {
  const m = /^\s*(?:\}\s*)?(?:else\s+)?if\s*\(/.exec(text);
  if (!m) return null;
  const open = m[0].length - 1;
  const cond = insideParens(text, open);
  if (cond === null) return null;
  return { cond: cond.trim(), rest: text.slice(open + cond.length + 2).trim() };
}

const EXITS_RE = /^(?:\{\s*)?(?:return\b|throw\b|continue\b|break\b)/;

type GuardKind = 'allowlist' | 'numeric' | 'host';

export class CSharpCredit {
  private readonly lines: string[];
  private readonly helperCache = new Map<string, Set<string>>();
  private readonly guardHelperCache = new Map<GuardKind, Map<string, number>>();

  constructor(code: string, private readonly methods: ReadonlyArray<CsMethodRange>) {
    // CRLF files leave `\r` on every line, which `.` and `$` will not cross.
    this.lines = code.split(/\r?\n/);
  }

  /** The innermost method containing `line`, or null. */
  private methodAt(line: number): CsMethodRange | null {
    let best: CsMethodRange | null = null;
    for (const m of this.methods) {
      if (line < m.start_line || line > m.end_line) continue;
      if (!best || m.end_line - m.start_line < best.end_line - best.start_line) best = m;
    }
    return best;
  }

  /**
   * Statements of lines `[from, to)`, 1-based, with a statement wrapped over
   * several lines joined up to its `;`. `line` is where the statement starts.
   */
  private statements(from: number, to: number): Array<{ line: number; text: string }> {
    const out: Array<{ line: number; text: string }> = [];
    for (let i = Math.max(from, 1); i < to; i++) {
      let text = (this.lines[i - 1] ?? '').trimEnd();
      const first = i;
      if (/^\s*(?:[\w.<>[\]?]+\s+)?[A-Za-z_]\w*\s*=(?!=)/.test(text) && !ENDS_STATEMENT_RE.test(text)) {
        while (i < to - 1 && i < first + 12) {
          i++;
          text += ' ' + (this.lines[i - 1] ?? '').trim();
          if (ENDS_STATEMENT_RE.test(this.lines[i - 1] ?? '')) break;
        }
      }
      out.push({ line: first, text });
    }
    return out;
  }

  /** Does `text` apply a built-in sanitizer for `type`? */
  private builtinSanitizes(type: string, text: string): boolean {
    for (const { re, type: t } of CSHARP_SANITIZER_RES) {
      if (t === type && re.test(text)) return true;
    }
    if (type === 'ldap_injection') {
      // RFC 4515 escaping, or stripping, of the filter metacharacters. Both
      // parentheses must be handled: they are what lets input restructure a
      // filter. `x.Replace("(", "\\28").Replace(")", "\\29")`.
      if (/\.\s*Replace\s*\(\s*"\("\s*,/.test(text) && /\.\s*Replace\s*\(\s*"\)"\s*,/.test(text)) return true;
    }
    if (type === 'path_traversal') {
      // `full.StartsWith(prefix) ? full : null` — the value is handed back
      // only when it is under the prefix.
      if (/\b([A-Za-z_]\w*)\s*\.\s*StartsWith\s*\([^)]*\)\s*\?\s*\1\s*:\s*null\b/.test(text)) return true;
    }
    return false;
  }

  /**
   * Same-file methods that sanitize for `type`: every `return` hands back a
   * sanitized expression. `static string Clean(string x) { return HtmlEncode(x); }`
   * makes `Clean(input)` an xss sanitizer at its call sites.
   */
  private helpers(type: string): Set<string> {
    const cached = this.helperCache.get(type);
    if (cached) return cached;
    const set = new Set<string>();
    this.helperCache.set(type, set);
    for (const m of this.methods) {
      const returns = this.returnExprs(m);
      if (returns.length === 0) continue;
      const ok = returns.every(r => {
        if (this.builtinSanitizes(type, r.expr)) return true;
        const v = /^([A-Za-z_]\w*)$/.exec(r.expr.trim());
        return !!v && this.sanitizedVarsIn(type, m.start_line, r.line, false).has(v[1]);
      });
      if (ok) set.add(m.name);
    }
    return set;
  }

  /** Every returned expression of a method: `return e;` and expression bodies. */
  private returnExprs(m: CsMethodRange): Array<{ line: number; expr: string }> {
    const out: Array<{ line: number; expr: string }> = [];
    for (const st of this.statements(m.start_line, m.end_line + 1)) {
      for (const r of st.text.matchAll(/\breturn\s+([^;]+);/g)) out.push({ line: st.line, expr: r[1] });
      if (st.line === m.start_line) {
        const body = /\)\s*=>\s*(.+?);\s*$/.exec(st.text);
        if (body) out.push({ line: st.line, expr: body[1] });
      }
    }
    return out;
  }

  /** Does `text` apply a sanitizer for `type`, built in or a same-file helper? */
  sanitizes(type: string, text: string): boolean {
    if (this.builtinSanitizes(type, text)) return true;
    for (const name of this.helpers(type)) {
      if (new RegExp(`(?<![\\w.])${escapeRegex(name)}\\s*\\(`).test(text)) return true;
    }
    return false;
  }

  private sanitizedVarsIn(type: string, from: number, to: number, withHelpers: boolean): Set<string> {
    const sanitized = new Set<string>();
    for (const st of this.statements(from, to)) {
      const m = ASSIGN_RE.exec(st.text);
      if (!m) continue;
      const [, lhs, rhs] = m;
      const credited =
        (withHelpers ? this.sanitizes(type, rhs) : this.builtinSanitizes(type, rhs)) ||
        [...sanitized].some(v => mentions(rhs, v));
      if (credited) sanitized.add(lhs);
      else sanitized.delete(lhs);
    }
    return sanitized;
  }

  /**
   * The variables sanitized for `type` at `sinkLine`, judged inside the method
   * that contains the sink (cognium-dev#579). The body is read top to bottom up
   * to the sink and the last assignment to a name decides: a sanitizer call or
   * a derivation from a sanitized name credits it, anything else removes it.
   * Class fields are the caller's concern: they can be sanitized in one method
   * and read in another.
   */
  sanitizedVarsAt(type: string, sinkLine: number): Set<string> {
    return this.sanitizedVarsIn(type, this.methodAt(sinkLine)?.start_line ?? 1, sinkLine, true);
  }

  /**
   * True when the sink on `sinkLine` also receives a tainted value that no
   * sanitizer covers. In `Write(HtmlEncode(a) + b)` the encoder covers `a`
   * only: `b` arrives raw, so the sanitizer on the line must not clear the
   * sink. `credited` are the names already known safe for `type` there;
   * `seeds` are the taint sources that name a variable.
   *
   * Taint is followed through the sink's method top to bottom, last
   * assignment wins. The sink text is then read without its string literals
   * and without the sanitizer calls for `type`; a tainted, uncredited name
   * left over is a raw operand.
   */
  rawTaintReaches(
    type: string,
    sinkLine: number,
    credited: ReadonlySet<string>,
    seeds: ReadonlyArray<{ variable: string; line: number }>,
  ): boolean {
    if (seeds.length === 0) return false;
    const method = this.methodAt(sinkLine);
    const from = method?.start_line ?? 1;
    const tainted = new Set<string>();
    const stmts = this.statements(from, sinkLine);
    for (let i = 0; i < stmts.length; i++) {
      const st = stmts[i];
      const end = i + 1 < stmts.length ? stmts[i + 1].line : sinkLine;
      const m = ASSIGN_RE.exec(st.text);
      if (m) {
        const rhs = withoutStringLiterals(m[2]);
        if ([...tainted].some(v => mentions(rhs, v))) tainted.add(m[1]);
        else tainted.delete(m[1]);
      }
      for (const s of seeds) if (s.line >= st.line && s.line < end) tainted.add(s.variable);
    }
    if (tainted.size === 0) return false;
    // Only what the call is given counts: a tainted receiver or cast target
    // (`((XmlDocument)ctx).SelectSingleNode(q)`) is not an operand.
    const call = withoutStringLiterals(this.sinkText(sinkLine));
    const rest = this.withoutSanitizerCalls(type, lastCallArguments(call) ?? call);
    // A sanitizer spelled as a chain or a ternary on the name itself
    // (`x.Replace("(", …)`, `p.StartsWith(root) ? p : null`) is not a call
    // that can be cut out; it covers the name it is written on.
    if (this.builtinSanitizes(type, rest)) return false;
    for (const v of tainted) if (!credited.has(v) && mentions(rest, v)) return true;
    return false;
  }

  /** `text` with every sanitizer call for `type`, arguments included, removed. */
  private withoutSanitizerCalls(type: string, text: string): string {
    const res: RegExp[] = [];
    for (const { re, type: t } of CSHARP_SANITIZER_RES) if (t === type) res.push(re);
    for (const name of this.helpers(type)) res.push(new RegExp(`(?<![\\w.])${escapeRegex(name)}\\s*\\(`));
    let out = text;
    for (const re of res) {
      for (let guard = 0; guard < 16; guard++) {
        const m = re.exec(out);
        if (!m) break;
        if (!m[0].endsWith('(')) {
          // The pattern matched the whole call.
          out = out.slice(0, m.index) + out.slice(m.index + m[0].length);
          continue;
        }
        const open = m.index + m[0].length - 1;
        const inner = insideParens(out, open);
        if (inner === null) break;
        out = out.slice(0, m.index) + out.slice(open + inner.length + 2);
      }
    }
    return out;
  }

  /**
   * The text of the statement at `line` that a sink call can be in: for
   * `if (COND) sink(x);` that is `sink(x);`, without the condition. A name
   * that only appears in the condition is not something the sink receives.
   */
  sinkText(line: number): string {
    const text = this.lines[line - 1] ?? '';
    const guarded = leadingIf(text);
    return guarded && guarded.rest !== '' ? guarded.rest : text;
  }

  // -------------------------------------------------------------------------
  // Guards
  // -------------------------------------------------------------------------

  /** Variables a condition proves to hold only letters, digits, `_` and `-`. */
  private allowlistVars(cond: string): string[] {
    const out: string[] = [];
    const anchored = new RegExp(
      `\\bRegex\\s*\\.\\s*IsMatch\\s*\\(\\s*(${IDENT})\\s*,\\s*@?"\\^\\[(?:[A-Za-z0-9_\\- ]|\\\\w|\\\\d)+\\](?:[+*]|\\{\\d+(?:,\\d*)?\\})\\$"`, 'g');
    for (const m of cond.matchAll(anchored)) out.push(m[1]);
    const methodGroup = new RegExp(`(${IDENT})\\s*\\.\\s*All\\s*\\(\\s*char\\s*\\.\\s*Is(?:LetterOrDigit|Digit|Letter)\\s*\\)`, 'g');
    for (const m of cond.matchAll(methodGroup)) out.push(m[1]);
    const lambda = new RegExp(`(${IDENT})\\s*\\.\\s*All\\s*\\(\\s*(${IDENT})\\s*=>`, 'g');
    for (const m of cond.matchAll(lambda)) {
      const open = cond.indexOf('(', m.index + m[1].length);
      const body = insideParens(cond, open)?.replace(new RegExp(`^\\s*${m[2]}\\s*=>`), '') ?? '';
      const c = escapeRegex(m[2]);
      const residue = body
        .replace(new RegExp(`char\\s*\\.\\s*Is(?:LetterOrDigit|Digit|Letter)\\s*\\(\\s*${c}\\s*\\)`, 'g'), '')
        .replace(new RegExp(`${c}\\s*==\\s*'[_\\-]'`, 'g'), '')
        .replace(/\|\||\s/g, '');
      if (residue === '') out.push(m[1]);
    }
    return out;
  }

  /** Variables a condition proves to be numeric (`int.TryParse(x, out _)`). */
  private numericVars(cond: string, parsedFrom: Map<string, string>): string[] {
    const out: string[] = [];
    const tryParse = new RegExp(
      `\\b(?:int|long|short|byte|uint|ulong|decimal|double|float|Int32|Int64|Guid)\\s*\\.\\s*TryParse\\s*\\(\\s*(${IDENT})\\s*,`, 'g');
    for (const m of cond.matchAll(tryParse)) out.push(m[1]);
    for (const [parsed, from] of parsedFrom) {
      if (new RegExp(`(?<![\\w])${escapeRegex(parsed)}\\s*(?:!=\\s*null|\\.\\s*HasValue)\\b`).test(cond)) out.push(from);
    }
    return out;
  }

  /** Variables whose host a condition compares against a constant or an allowlist. */
  private hostVars(cond: string, hostOf: Map<string, string>): string[] {
    const out: string[] = [];
    const compares = (expr: string): boolean => {
      const e = escapeRegex(expr).replace(/\\ /g, '\\s*');
      return (
        new RegExp(`${e}\\s*==\\s*@?"[^"]+"`).test(cond) ||
        new RegExp(`@?"[^"]+"\\s*==\\s*${e}`).test(cond) ||
        new RegExp(`${e}\\s*\\.\\s*Equals\\s*\\(`).test(cond) ||
        new RegExp(`\\.\\s*Contains\\s*\\(\\s*${e}\\s*[),]`).test(cond) ||
        new RegExp(`\\bIndexOf\\s*\\([^()]*,\\s*${e}\\s*\\)\\s*>=\\s*0`).test(cond)
      );
    };
    const direct = new RegExp(`new\\s+(?:System\\s*\\.\\s*)?Uri\\s*\\(\\s*(${IDENT})\\s*\\)\\s*\\.\\s*Host\\b`, 'g');
    for (const m of cond.matchAll(direct)) {
      if (compares(m[0])) out.push(m[1]);
    }
    for (const [hostVar, from] of hostOf) {
      if (mentions(cond, hostVar) && compares(hostVar)) out.push(from);
    }
    return out;
  }

  /**
   * Same-file methods that are guards of `kind` on one of their parameters:
   * `static bool IsAllowed(string c) { return Array.IndexOf(Allowed, new Uri(c).Host) >= 0; }`.
   * Maps the method name to the position of the validated parameter.
   */
  private guardHelpers(kind: GuardKind): Map<string, number> {
    const cached = this.guardHelperCache.get(kind);
    if (cached) return cached;
    const map = new Map<string, number>();
    this.guardHelperCache.set(kind, map);
    for (const m of this.methods) {
      const signature = this.lines[m.start_line - 1] ?? '';
      const open = signature.indexOf('(', signature.indexOf(m.name));
      const params = open === -1 ? null : insideParens(signature, open);
      if (!params) continue;
      const names = params.split(',').map(p => p.trim().split(/\s+/).pop() ?? '');
      const returns = this.returnExprs(m);
      if (returns.length !== 1) continue;
      const proven = this.provenBy(kind, returns[0].expr, new Map(), new Map(), false);
      const pos = names.findIndex(n => proven.includes(n));
      if (pos !== -1) map.set(m.name, pos);
    }
    return map;
  }

  private provenBy(
    kind: GuardKind,
    cond: string,
    parsedFrom: Map<string, string>,
    hostOf: Map<string, string>,
    withHelpers: boolean,
  ): string[] {
    const out =
      kind === 'allowlist' ? this.allowlistVars(cond)
      : kind === 'numeric' ? this.numericVars(cond, parsedFrom)
      : this.hostVars(cond, hostOf);
    if (withHelpers) {
      for (const [name, pos] of this.guardHelpers(kind)) {
        for (const call of cond.matchAll(new RegExp(`(?<![\\w.])${escapeRegex(name)}\\s*\\(`, 'g'))) {
          const args = insideParens(cond, call.index + call[0].length - 1)?.split(',') ?? [];
          const arg = args[pos]?.trim();
          if (arg && new RegExp(`^${IDENT}$`).test(arg)) out.push(arg);
        }
      }
    }
    return out;
  }

  /**
   * The variables a check dominating `sinkLine` proves safe for `type`.
   *
   * Recognised checks:
   *   - allowlist: anchored `Regex.IsMatch(x, "^[A-Za-z0-9_]+$")`, `x.All(char.IsLetterOrDigit)`;
   *   - numeric:   `int.TryParse(x, out _)`, or `p != null` where `p = int.Parse(x)`;
   *   - host (ssrf only): `new Uri(x).Host == "api.example.com"`, an allowlist
   *     `Contains` / `IndexOf` of that host.
   * directly, through a `bool` or host variable, or through a same-file helper.
   *
   * A check dominates the sink when the sink is the body of the `if`, is
   * inside its block, or follows an early exit on the negated check
   * (`if (!ok) return;`).
   */
  guardedVarsAt(type: string, sinkLine: number): Set<string> {
    const kinds: GuardKind[] = [];
    if (INERT_WHEN_ALPHANUMERIC.has(type)) kinds.push('allowlist', 'numeric');
    if (type === 'ssrf') kinds.push('host');
    const proven = new Set<string>();
    if (kinds.length === 0) return proven;

    const scopeStart = this.methodAt(sinkLine)?.start_line ?? 1;
    const before = this.statements(scopeStart, sinkLine);
    const boolOf = new Map<string, string>();     // b = <condition>
    const parsedFrom = new Map<string, string>(); // p = int.Parse(x)
    const hostOf = new Map<string, string>();     // h = new Uri(x).Host
    const parseAnywhere = new RegExp(
      `(${IDENT})\\s*=\\s*(?:\\([^)]*\\)\\s*)?(?:int|long|short|byte|uint|ulong|decimal|double|float|Int32|Int64)\\s*\\.\\s*Parse\\s*\\(\\s*(${IDENT})\\s*[,)]`, 'g');
    for (const st of before) {
      // `try { p = int.Parse(x); }` keeps the assignment off the line start.
      for (const p of st.text.matchAll(parseAnywhere)) parsedFrom.set(p[1], p[2]);
      const m = ASSIGN_RE.exec(st.text);
      if (!m) continue;
      const [, lhs, rhs] = m;
      const parse = new RegExp(`^(?:\\([^)]*\\)\\s*)?(?:int|long|short|byte|uint|ulong|decimal|double|float|Int32|Int64)\\s*\\.\\s*Parse\\s*\\(\\s*(${IDENT})\\s*[,)]`).exec(rhs);
      if (parse) parsedFrom.set(lhs, parse[1]);
      const host = new RegExp(`^new\\s+(?:System\\s*\\.\\s*)?Uri\\s*\\(\\s*(${IDENT})\\s*\\)\\s*\\.\\s*Host$`).exec(rhs.trim());
      if (host) hostOf.set(lhs, host[1]);
      boolOf.set(lhs, rhs);
    }

    const credit = (cond: string): void => {
      // A bare variable stands for the condition it was assigned.
      const resolved = new RegExp(`^${IDENT}$`).test(cond) ? boolOf.get(cond) ?? cond : cond;
      for (const kind of kinds) {
        for (const v of this.provenBy(kind, resolved, parsedFrom, hostOf, true)) proven.add(v);
      }
    };

    // (i) the sink is the body of an `if` on its own line.
    const own = leadingIf(this.lines[sinkLine - 1] ?? '');
    if (own && !own.cond.startsWith('!')) credit(own.cond);

    // (ii) the sink is inside the block of an `if`.
    let depth = 0;
    for (let i = sinkLine - 1; i >= scopeStart; i--) {
      const text = this.lines[i - 1] ?? '';
      for (let c = text.length - 1; c >= 0; c--) {
        if (text[c] === '}') depth++;
        else if (text[c] === '{') {
          if (depth > 0) { depth--; continue; }
          let header = text.slice(0, c);
          for (let h = i - 1; header.trim() === '' && h >= scopeStart; h--) header = this.lines[h - 1] ?? '';
          const enclosing = leadingIf(header);
          if (enclosing && !enclosing.cond.startsWith('!')) credit(enclosing.cond);
        }
      }
    }

    // (iii) an early exit on the negated check, earlier in the method.
    for (let i = scopeStart; i < sinkLine; i++) {
      const guard = leadingIf(this.lines[i - 1] ?? '');
      if (!guard) continue;
      let rest = guard.rest;
      for (let n = i + 1; rest === '' && n < sinkLine; n++) rest = (this.lines[n - 1] ?? '').trim();
      if (!EXITS_RE.test(rest)) continue;
      if (guard.cond.startsWith('!')) {
        // `!(a == b)` drops the wrapping parentheses with the `!`; `!F(x)` keeps its call.
        const inner = guard.cond.slice(1).trim();
        const wrapped = inner.startsWith('(') && insideParens(inner, 0)?.length === inner.length - 2;
        credit(wrapped ? inner.slice(1, -1) : inner);
      }
      else if (/!=/.test(guard.cond) && !/[|&]/.test(guard.cond)) credit(guard.cond.replace('!=', '=='));
    }
    return proven;
  }

  /**
   * `StringBuilder`s that hold only safe text at `sinkLine`: every write to
   * the builder before the sink is made of string literals and `credited`
   * names. One write with anything else and the builder is not credited, so
   * `sb.Append(validated); sb.Append(raw);` stays tainted.
   *
   * This is how a guard on a value reaches a sink that receives the builder
   * the value was appended to (`if (parsed != null) { sb.Append(data); Compile(sb.ToString()); }`).
   */
  safeBuilders(credited: ReadonlySet<string>, sinkLine: number): Set<string> {
    const scopeStart = this.methodAt(sinkLine)?.start_line ?? 1;
    const onlySafe = (expr: string): boolean => {
      const idents = expr
        .replace(/\$?@?"(?:[^"\\]|\\.)*"/g, ' ')
        .replace(/'(?:[^'\\]|\\.)'/g, ' ')
        .replace(/\.\s*[A-Za-z_]\w*\s*\(\s*\)/g, ' ')   // x.ToString()
        .match(/[A-Za-z_]\w*/g) ?? [];
      return idents.every(id => credited.has(id));
    };
    const state = new Map<string, boolean>();   // builder -> still safe
    const declRe = new RegExp(`\\b(?:StringBuilder|var)\\s+(${IDENT})\\s*=\\s*new\\s+(?:System\\s*\\.\\s*Text\\s*\\.\\s*)?StringBuilder\\s*\\(`);
    const writeRe = new RegExp(`^\\s*(${IDENT})\\s*\\.\\s*(?:Append|AppendLine|AppendFormat|Insert)\\s*\\(`);
    for (const st of this.statements(scopeStart, sinkLine)) {
      const decl = declRe.exec(st.text);
      if (decl) {
        const args = insideParens(st.text, decl.index + decl[0].length - 1) ?? '';
        state.set(decl[1], onlySafe(args));
        continue;
      }
      const write = writeRe.exec(st.text);
      if (write && state.has(write[1])) {
        const args = insideParens(st.text, write[0].length - 1);
        if (args === null || !onlySafe(args)) state.set(write[1], false);
      }
    }
    return new Set([...state].filter(([, safe]) => safe).map(([name]) => name));
  }

  /**
   * True when what leaves on `line` has been sanitized or validated for some
   * sink type. Used for the untyped "tainted data reaches an external call"
   * fallback, which has no sink type of its own to ask about.
   */
  creditedOnLine(line: number, seeds: ReadonlyArray<{ variable: string; line: number }> = []): boolean {
    const text = this.sinkText(line);
    const types = new Set(CSHARP_SANITIZER_RES.map(r => r.type));
    for (const t of INERT_WHEN_ALPHANUMERIC) types.add(t);
    types.add('ssrf');
    for (const type of types) {
      const credited = new Set([...this.sanitizedVarsAt(type, line), ...this.guardedVarsAt(type, line)]);
      for (const v of this.safeBuilders(credited, line)) credited.add(v);
      const covered = this.sanitizes(type, text) || [...credited].some(v => mentions(text, v));
      if (covered && !this.rawTaintReaches(type, line, credited, seeds)) return true;
    }
    return this.fixedHostRequest(line);
  }

  // -------------------------------------------------------------------------
  // SSRF: constant host
  // -------------------------------------------------------------------------

  /**
   * True when the request on `sinkLine` goes to a constant host: the URL
   * argument starts with a string literal holding the whole authority, as in
   * `GetAsync("https://api.internal.example.com/?x=" + v)`. Input can then only
   * extend the path or query. The literal must be the first operand of the
   * argument, and must end the authority (`/`, `?` or `#` after the host), or
   * `"https://api.example.com" + x` would let `x = ".evil.org"` move the host.
   */
  fixedHostRequest(sinkLine: number): boolean {
    const fixedLiteral = '\\$?@?"https?:\\/\\/[A-Za-z0-9.\\-]+(?::\\d+)?[\\/?#][^"]*"';
    const text = this.lines[sinkLine - 1] ?? '';
    const argStart = `\\(\\s*(?:new\\s+(?:System\\s*\\.\\s*)?Uri\\s*\\(\\s*)?`;
    if (new RegExp(argStart + fixedLiteral).test(text)) return true;
    // The URL was built into a variable first.
    const scopeStart = this.methodAt(sinkLine)?.start_line ?? 1;
    const fixed = new Set<string>();
    for (const st of this.statements(scopeStart, sinkLine)) {
      const m = ASSIGN_RE.exec(st.text);
      if (!m) continue;
      if (new RegExp('^(?:new\\s+(?:System\\s*\\.\\s*)?Uri\\s*\\(\\s*)?' + fixedLiteral).test(m[2].trim())) fixed.add(m[1]);
      else fixed.delete(m[1]);
    }
    for (const v of fixed) {
      if (new RegExp(argStart + escapeRegex(v) + '\\s*[,)]').test(text)) return true;
    }
    return false;
  }
}
