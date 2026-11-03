// Expected labels for the stable-ids conformance set.
//
// Given the two versions of the TypeScript files one commit touched, label
// every declaration of the earlier version `stable` or `changed`, or set it
// aside with a judgement reason. The rule is written out in README.md
// ("The labelling rule"); this file is its only implementation. It parses with
// the TypeScript compiler, not with the engine's parser, and never calls the
// engine, so the labels do not depend on what is being measured.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** Version of the labelling rule. Bump it when any label could change. */
export const LABEL_RULE = 'stable-labels@1';

let tsCache = null;

/** The TypeScript compiler (the classic JavaScript API) from the repo's dev dependencies. */
export function loadTypeScript() {
  if (tsCache) return tsCache;
  let ts;
  try {
    ts = require('typescript');
  } catch {
    throw new Error('stable-ids labels: the `typescript` package is not installed; run `npm ci` at the repo root');
  }
  if (typeof ts.createSourceFile !== 'function') {
    throw new Error(`stable-ids labels: typescript ${ts.version ?? '?'} has no createSourceFile (the labeller needs the JavaScript compiler API)`);
  }
  tsCache = ts;
  return ts;
}

/** Files the set labels: TypeScript sources, declaration files included. */
export function isLabelledPath(path) {
  return /\.(?:ts|tsx|mts|cts)$/.test(path) && !/(^|\/)node_modules\//.test(path);
}

/** The module path of a file: its repository-relative path without the extension. */
export function modulePath(path) {
  return path.replace(/\\/g, '/').replace(/\.d\.(?:m|c)?ts$/, '').replace(/\.(?:m|c)?tsx?$/, '');
}

function scriptKind(ts, path) {
  return path.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
}

const IDENT = /^[A-Za-z_$][\w$]*$/;

// ---------------------------------------------------------------------------
// Tokens. Every leaf of the syntax tree is one token; comments and whitespace
// are trivia and never appear. Each token has two spellings:
//   w — as written (the whitespace-and-comments view);
//   f — with formatting choices also removed (quote style, statement
//       semicolons, trailing commas, type-member separators, the parentheses
//       of a single bare arrow parameter and those wrapping JSX).
// A null spelling means the token is dropped in that view. A third spelling,
//   r — the token with the comments and whitespace before it,
// is used only to tell whether a stable declaration's text changed at all
// (the "whitespace and comments" edit kind); it never decides a label.

class Tokenizer {
  constructor(ts, sf) {
    this.ts = ts;
    this.sf = sf;
    const K = ts.SyntaxKind;
    this.K = K;
    this.typeElements = new Set([K.PropertySignature, K.MethodSignature, K.IndexSignature, K.CallSignature, K.ConstructSignature]);
    this.nameParents = new Set([
      K.PropertyAssignment, K.PropertySignature, K.PropertyDeclaration, K.MethodDeclaration, K.MethodSignature,
      K.GetAccessor, K.SetAccessor, K.EnumMember,
    ]);
    this.jsx = new Set([K.JsxElement, K.JsxSelfClosingElement, K.JsxFragment]);
  }

  isJSDoc(node) {
    return node.kind >= this.K.FirstJSDocNode && node.kind <= this.K.LastJSDocNode;
  }

  simpleArrowParam(node) {
    if (node.typeParameters || node.type || node.parameters.length !== 1) return false;
    const p = node.parameters[0];
    return !p.type && !p.initializer && !p.dotDotDotToken && !p.questionToken
      && !(p.modifiers && p.modifiers.length) && p.name.kind === this.K.Identifier;
  }

  leaf(node, out) {
    const K = this.K;
    switch (node.kind) {
      case K.EndOfFileToken:
        out.push({ w: null, f: null, r: this.sf.text.slice(node.pos, node.end) });
        return;
      case K.JsxText: {
        const r = this.sf.text.slice(node.pos, node.end);
        if (node.containsOnlyTriviaWhiteSpaces) { out.push({ w: null, f: null, r }); return; }
        const t = node.text.replace(/\s+/g, ' ').trim();
        out.push({ w: t === '' ? null : t, f: t === '' ? null : t, r });
        return;
      }
      case K.StringLiteral: {
        const w = node.getText(this.sf);
        const p = node.parent;
        const isName = p && this.nameParents.has(p.kind) && p.name === node;
        const f = isName && IDENT.test(node.text) ? node.text : JSON.stringify(node.text);
        out.push({ w, f, r: this.sf.text.slice(node.pos, node.end) });
        return;
      }
      case K.SemicolonToken:
        out.push({ w: ';', f: node.parent && node.parent.kind === K.ForStatement ? ';' : null, r: this.sf.text.slice(node.pos, node.end) });
        return;
      case K.CommaToken:
        out.push({ w: ',', f: node.parent && this.typeElements.has(node.parent.kind) ? null : ',', r: this.sf.text.slice(node.pos, node.end) });
        return;
      default:
        out.push({ w: node.getText(this.sf), f: node.getText(this.sf), r: this.sf.text.slice(node.pos, node.end) });
    }
  }

  walk(node, ctx, out) {
    if (ctx.exclude.has(node)) return;
    const ph = ctx.replace.get(node);
    if (ph !== undefined) {
      out.push({ w: ph, f: ph, r: ph });
      return;
    }
    if (this.isJSDoc(node)) return;
    const kids = node.getChildren(this.sf);
    if (kids.length === 0) {
      this.leaf(node, out);
      return;
    }
    const K = this.K;
    const dropParens = (node.kind === K.ArrowFunction && this.simpleArrowParam(node))
      || (node.kind === K.ParenthesizedExpression && this.jsx.has(node.expression.kind));
    for (const k of kids) {
      if (dropParens && (k.kind === K.OpenParenToken || k.kind === K.CloseParenToken)) {
        out.push({ w: k.getText(this.sf), f: null, r: this.sf.text.slice(k.pos, k.end) });
        continue;
      }
      this.walk(k, ctx, out);
    }
  }

  /** Token spellings of `nodes`, skipping `exclude` and replacing `replace` keys by their placeholder. */
  tokens(nodes, exclude = new Set(), replace = new Map()) {
    const out = [];
    for (const n of nodes) this.walk(n, { exclude, replace }, out);
    const w = [];
    const f0 = [];
    const r = [];
    for (const t of out) {
      if (t.w !== null) w.push(t.w);
      if (t.f !== null) f0.push(t.f);
      r.push(t.r);
    }
    // A comma right before a closer is a trailing comma: formatting.
    const f = [];
    for (let i = 0; i < f0.length; i++) {
      if (f0[i] === ',' && i + 1 < f0.length && /^[)\]}>]$/.test(f0[i + 1])) continue;
      f.push(f0[i]);
    }
    return { w, f, r: r.join('') };
  }

  /** One string for a type or other signature part (the formatting-free view). */
  text(node) {
    if (!node) return '_';
    return joinTokens(this.tokens([node]).f);
  }
}

/** Tokens as one string, with a space only where two word characters would touch. */
function joinTokens(tokens) {
  let out = '';
  for (const t of tokens) {
    if (out !== '' && /[\w$]$/.test(out) && /^[\w$]/.test(t)) out += ' ';
    out += t;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Declarations.

function propName(tk, name) {
  const K = tk.K;
  if (!name) return null;
  switch (name.kind) {
    case K.Identifier:
    case K.PrivateIdentifier:
      return name.text;
    case K.StringLiteral:
    case K.NumericLiteral:
    case K.NoSubstitutionTemplateLiteral:
      return name.text;
    case K.ComputedPropertyName: {
      const e = name.expression;
      if (e.kind === K.StringLiteral || e.kind === K.NumericLiteral || e.kind === K.NoSubstitutionTemplateLiteral) return e.text;
      return '[' + joinTokens(tk.tokens([e]).f) + ']';
    }
    default:
      return null;
  }
}

function hasModifier(node, kind) {
  return !!(node.modifiers && node.modifiers.some(m => m.kind === kind));
}

function paramSig(tk, p) {
  const K = tk.K;
  if (p.name.kind === K.Identifier && p.name.text === 'this') return 'this:' + tk.text(p.type);
  return (p.dotDotDotToken ? '...' : '') + (p.type ? tk.text(p.type) : '_') + (p.questionToken || p.initializer ? '?' : '');
}

function typeParamsSig(tk, node) {
  const tps = node.typeParameters;
  if (!tps || tps.length === 0) return '';
  return '<' + tps.map(tp => tk.text(tp)).join(',') + '>';
}

function fnSig(tk, fn) {
  return typeParamsSig(tk, fn) + '(' + fn.parameters.map(p => paramSig(tk, p)).join(',') + ')' + (fn.type ? ':' + tk.text(fn.type) : '');
}

/** Children of `node` from its first `{` to the end (the braces of a class, interface or enum). */
function braceChildren(tk, node) {
  const kids = node.getChildren(tk.sf);
  const i = kids.findIndex(k => k.kind === tk.K.OpenBraceToken);
  return i < 0 ? [] : kids.slice(i);
}

function isFunctionValue(tk, e) {
  return !!e && (e.kind === tk.K.ArrowFunction || e.kind === tk.K.FunctionExpression);
}

class Collector {
  constructor(tk, file) {
    this.tk = tk;
    this.file = file;
    this.module = modulePath(file);
    this.decls = [];
  }

  line(pos) {
    return this.tk.sf.getLineAndCharacterOfPosition(pos).line + 1;
  }

  add(parent, d) {
    const sf = this.tk.sf;
    const span = d.span;
    d.chain = parent && parent.kind !== 'module-file' ? [...parent.chain, parent.name] : [];
    d.key = [this.module, d.chain.join('.'), d.kind === 'module-file' ? 'module' : d.kind, d.name, d.signature].join('\u0000');
    d.parent = parent;
    d.members = [];
    d.start = this.line(span.getStart(sf));
    d.end = this.line(span.getEnd());
    d.line = d.nameNode ? this.line(d.nameNode.getStart(sf)) : d.start;
    d.file = this.file;
    if (parent) parent.members.push(d);
    this.decls.push(d);
    return d;
  }

  scope(parent, statements) {
    const tk = this.tk;
    const K = tk.K;
    for (const s of statements) {
      switch (s.kind) {
        case K.FunctionDeclaration: {
          const name = s.name ? s.name.text : (hasModifier(s, K.DefaultKeyword) ? 'default' : null);
          if (name === null) break;
          this.add(parent, { kind: 'function', name, signature: fnSig(tk, s), span: s, nameNode: s.name ?? null, inner: s.body ? [s.body] : [] });
          break;
        }
        case K.ClassDeclaration: {
          const name = s.name ? s.name.text : 'default';
          const d = this.add(parent, { kind: 'type', name, signature: typeParamsSig(tk, s), span: s, nameNode: s.name ?? null, inner: braceChildren(tk, s), container: true });
          this.classMembers(d, s.members);
          break;
        }
        case K.InterfaceDeclaration: {
          const d = this.add(parent, { kind: 'type', name: s.name.text, signature: typeParamsSig(tk, s), span: s, nameNode: s.name, inner: braceChildren(tk, s), container: true });
          this.typeMembers(d, s.members);
          break;
        }
        case K.TypeAliasDeclaration:
          this.add(parent, { kind: 'type', name: s.name.text, signature: typeParamsSig(tk, s), span: s, nameNode: s.name, inner: [s.type] });
          break;
        case K.EnumDeclaration:
          this.add(parent, { kind: 'type', name: s.name.text, signature: '', span: s, nameNode: s.name, inner: braceChildren(tk, s) });
          break;
        case K.ModuleDeclaration: {
          let name = s.name.text;
          let body = s.body;
          while (body && body.kind === K.ModuleDeclaration) {
            name += '.' + body.name.text;
            body = body.body;
          }
          const d = this.add(parent, { kind: 'module', name, signature: '', span: s, nameNode: s.name, inner: body ? [body] : [], container: !!body });
          if (body && body.kind === K.ModuleBlock) this.scope(d, body.statements);
          break;
        }
        case K.VariableStatement: {
          const list = s.declarationList.declarations;
          for (const v of list) {
            if (v.name.kind !== K.Identifier) continue; // destructuring stays in the enclosing body
            const span = list.length === 1 ? s : v;
            const init = v.initializer;
            if (isFunctionValue(tk, init)) {
              this.add(parent, { kind: 'function', name: v.name.text, signature: fnSig(tk, init), span, nameNode: v.name, inner: [init.body] });
            } else if (init && init.kind === K.ClassExpression) {
              const d = this.add(parent, { kind: 'type', name: v.name.text, signature: typeParamsSig(tk, init), span, nameNode: v.name, inner: braceChildren(tk, init), container: true });
              this.classMembers(d, init.members);
            } else {
              this.add(parent, { kind: 'field', name: v.name.text, signature: v.type ? tk.text(v.type) : '_', span, nameNode: v.name, inner: init ? [init] : [] });
            }
          }
          break;
        }
        default:
          break; // imports, exports, statements: part of the enclosing body
      }
    }
  }

  classMembers(parent, members) {
    const tk = this.tk;
    const K = tk.K;
    for (const m of members) {
      const stat = hasModifier(m, K.StaticKeyword) ? 'static ' : '';
      const q = m.questionToken ? '?' : '';
      switch (m.kind) {
        case K.Constructor:
          this.add(parent, { kind: 'method', name: 'constructor', signature: fnSig(tk, m), span: m, nameNode: null, inner: m.body ? [m.body] : [] });
          break;
        case K.MethodDeclaration: {
          const name = propName(tk, m.name);
          if (name === null) break;
          this.add(parent, { kind: 'method', name, signature: stat + q + fnSig(tk, m), span: m, nameNode: m.name, inner: m.body ? [m.body] : [] });
          break;
        }
        case K.GetAccessor:
        case K.SetAccessor: {
          const name = propName(tk, m.name);
          if (name === null) break;
          const pre = m.kind === K.GetAccessor ? 'get ' : 'set ';
          this.add(parent, { kind: 'method', name, signature: stat + pre + fnSig(tk, m), span: m, nameNode: m.name, inner: m.body ? [m.body] : [] });
          break;
        }
        case K.PropertyDeclaration: {
          const name = propName(tk, m.name);
          if (name === null) break;
          this.add(parent, { kind: 'field', name, signature: stat + q + (m.type ? tk.text(m.type) : '_'), span: m, nameNode: m.name, inner: m.initializer ? [m.initializer] : [] });
          break;
        }
        default:
          break; // index signatures, static blocks: part of the class body
      }
    }
  }

  typeMembers(parent, members) {
    const tk = this.tk;
    const K = tk.K;
    for (const m of members) {
      const q = m.questionToken ? '?' : '';
      if (m.kind === K.PropertySignature) {
        const name = propName(tk, m.name);
        if (name !== null) this.add(parent, { kind: 'field', name, signature: q + (m.type ? tk.text(m.type) : '_'), span: m, nameNode: m.name, inner: [] });
      } else if (m.kind === K.MethodSignature) {
        const name = propName(tk, m.name);
        if (name !== null) this.add(parent, { kind: 'method', name, signature: q + fnSig(tk, m), span: m, nameNode: m.name, inner: [] });
      }
    }
  }
}

function placeholder(d) {
  return `@@${d.kind} ${d.name} ${d.signature}@@`;
}

/**
 * Parse one file version and return its declarations with their token views.
 * `partial` is true when the parser reported syntax errors.
 */
export function declarationsOf(path, text) {
  const ts = loadTypeScript();
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, scriptKind(ts, path));
  const tk = new Tokenizer(ts, sf);
  const c = new Collector(tk, path);
  const mod = c.add(null, { kind: 'module-file', name: '', signature: '', span: sf, nameNode: null, inner: [sf], container: true });
  c.scope(mod, sf.statements);
  for (const d of c.decls) {
    const replace = new Map();
    for (const m of d.members) replace.set(m.span, placeholder(m));
    const exclude = new Set(d.nameNode ? [d.nameNode] : []);
    d.full = tk.tokens([d.span], exclude, replace);
    d.innerTokens = tk.tokens(d.inner, exclude, replace);
    if (d.container) {
      const phs = new Set(d.members.map(placeholder));
      d.innerNoMembers = d.innerTokens.f.filter(t => !phs.has(t));
      d.memberOrder = d.innerTokens.f.filter(t => phs.has(t));
    }
  }
  // Drop syntax-tree references: callers get plain data.
  const decls = c.decls.map(d => ({
    file: d.file, module: c.module, kind: d.kind === 'module-file' ? 'module' : d.kind, isFile: d.kind === 'module-file',
    name: d.name, signature: d.signature, chain: d.chain, key: d.key, line: d.line, start: d.start, end: d.end,
    container: !!d.container, full: d.full, inner: d.innerTokens, innerNoMembers: d.innerNoMembers, memberOrder: d.memberOrder,
    parentKey: d.parent ? d.parent.key : null, index: 0,
  }));
  decls.forEach((d, i) => { d.index = i; });
  const partial = (sf.parseDiagnostics ?? []).length > 0;
  return { file: path, module: c.module, decls, partial };
}

// ---------------------------------------------------------------------------
// The rule.

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const sortedEq = (a, b) => eq([...a].sort(), [...b].sort());

/** Compare two versions of one declaration with the same identity. */
function compareMatched(b, a) {
  if (eq(b.full.w, a.full.w)) return { label: 'stable' };
  if (eq(b.full.f, a.full.f)) return { judgement: 'formatting' };
  if (!eq(b.inner.f, a.inner.f)) {
    if (b.container && eq(b.innerNoMembers, a.innerNoMembers) && sortedEq(b.memberOrder, a.memberOrder)
      && !eq(b.memberOrder, a.memberOrder)) {
      // Only the order of the members differs; if the header also differs it is still a judgement.
      return { judgement: 'member-order' };
    }
    return { label: 'changed', change: 'body' };
  }
  return { judgement: 'header' };
}

function identityReason(b, added) {
  const same = (x, k) => x.module === b.module && x.chain.join('.') === b.chain.join('.') && x.kind === b.kind && x.name === b.name && k(x);
  const sig = added.filter(x => same(x, y => y.signature !== b.signature));
  if (sig.length > 0) {
    const tokens = s => s.split(/(?=[(),:<>|&[\]{}])|(?<=[(),:<>|&[\]{}])|\s+/).filter(Boolean);
    if (sig.length === 1 && sig[0].signature.length === b.signature.length && sortedEq(tokens(sig[0].signature), tokens(b.signature))) {
      return { judgement: 'signature-order' };
    }
    return { reason: 'signature' };
  }
  if (added.some(x => x.module !== b.module && x.kind === b.kind && x.name === b.name && x.signature === b.signature && x.chain.join('.') === b.chain.join('.'))) {
    return { reason: 'moved' };
  }
  if (added.some(x => x.module === b.module && x.kind === b.kind && x.name === b.name && x.signature === b.signature)) {
    return { reason: 'parent-changed' };
  }
  if (!b.isFile && added.some(x => x.module === b.module && x.chain.join('.') === b.chain.join('.') && x.kind === b.kind && x.name !== b.name && x.signature === b.signature && eq(x.full.f, b.full.f))) {
    return { reason: 'renamed' };
  }
  return { reason: 'removed' };
}

/**
 * Label one commit pair.
 *
 * `files` lists the touched TypeScript files as `{ before, after }` paths
 * (`null` when the file is added or deleted; different paths when it moved),
 * and `read(side, path)` returns a file's text on side `'before'` or `'after'`.
 * Returns the label records (earlier-version declarations, in file and source
 * order), the number of declarations only the later version has, and the edit
 * kinds the pair exercises.
 */
export function labelPair(files, read) {
  const before = [];
  const after = [];
  const partialBefore = new Set();
  const partialAfter = new Set();
  const moves = [];
  for (const f of files) {
    if (f.before) {
      const r = declarationsOf(f.before, read('before', f.before));
      if (r.partial) partialBefore.add(f.before);
      before.push(...r.decls);
    }
    if (f.after) {
      const r = declarationsOf(f.after, read('after', f.after));
      if (r.partial) partialAfter.add(f.after);
      after.push(...r.decls);
    }
    if (f.before && f.after && f.before !== f.after) moves.push(f);
  }
  const afterOf = new Map(files.filter(f => f.before).map(f => [f.before, f.after]));
  const group = list => {
    const m = new Map();
    for (const d of list) {
      const g = m.get(d.key);
      if (g) g.push(d); else m.set(d.key, [d]);
    }
    return m;
  };
  const bKeys = group(before);
  const aKeys = group(after);
  const added = after.filter(d => !bKeys.has(d.key));

  const out = new Map(); // before decl -> record
  for (const b of before) {
    const rec = {
      file: b.file, kind: b.kind, name: b.name, chain: b.chain.join('.'), signature: b.signature,
      line: b.line, start: b.start, end: b.end,
      label: null, change: null, reason: null, judgement: null, after: null,
    };
    const partners = aKeys.get(b.key) ?? [];
    if (partialBefore.has(b.file) || partialAfter.has(afterOf.get(b.file))) {
      rec.judgement = 'parse-error';
    } else if (bKeys.get(b.key).length > 1 || partners.length > 1) {
      rec.judgement = 'duplicate';
    } else if (partners.length === 1) {
      const a = partners[0];
      rec.after = { file: a.file, line: a.line, start: a.start, end: a.end };
      Object.assign(rec, compareMatched(b, a));
      rec._a = a;
    } else {
      const r = identityReason(b, added);
      if (r.judgement) rec.judgement = r.judgement;
      else Object.assign(rec, { label: 'changed', change: 'identity', reason: r.reason });
    }
    out.set(b, rec);
  }
  // A member whose header (or signature spelling) changed may count against
  // its container instead: the container is a judgement too.
  for (const b of before) {
    const rec = out.get(b);
    if ((rec.judgement !== 'header' && rec.judgement !== 'signature-order') || b.parentKey === null) continue;
    const parent = before.find(p => p.key === b.parentKey && p.file === b.file);
    const prec = parent && out.get(parent);
    if (prec && prec.label !== null) {
      prec.label = null; prec.change = null; prec.judgement = 'member-header';
    }
  }

  const kinds = new Set();
  const recs = [...out.values()];
  for (const r of recs) {
    if (r.change === 'body') kinds.add('body');
    if (r.reason === 'signature' || r.judgement === 'signature-order') kinds.add('signature');
    if (r.reason === 'renamed') kinds.add('rename');
    if (r.reason === 'moved') kinds.add('move');
    if (r.reason === 'removed') kinds.add('remove');
    if (r.judgement === 'member-order') kinds.add('reorder');
  }
  if (moves.length > 0) kinds.add('move');
  if (added.length > 0) kinds.add('add');
  // Whitespace and comments: a stable declaration whose text differs.
  for (const [b, r] of out) {
    if (r.label === 'stable' && r._a && r._a.full.r !== b.full.r) kinds.add('format');
    if (r.judgement === 'formatting') kinds.add('format');
  }
  // Reorder: matched members of one container whose relative order flipped.
  const byParent = new Map();
  for (const [b, r] of out) {
    if (!r._a || b.parentKey === null) continue;
    const k = b.file + '\u0000' + b.parentKey;
    const g = byParent.get(k);
    if (g) g.push([b, r._a]); else byParent.set(k, [[b, r._a]]);
  }
  for (const g of byParent.values()) {
    g.sort((x, y) => x[0].index - y[0].index);
    for (let i = 1; i < g.length; i++) {
      if (g[i][1].file === g[i - 1][1].file && g[i][1].index < g[i - 1][1].index) { kinds.add('reorder'); break; }
    }
  }

  const records = recs.map(r => {
    const { _a, ...rest } = r;
    return rest;
  });
  records.sort((x, y) => (x.file < y.file ? -1 : x.file > y.file ? 1 : x.start - y.start || x.line - y.line || cmp(x.name, y.name) || cmp(x.kind, y.kind)));
  return { records, added: added.length, kinds: [...kinds].sort() };
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Counts by outcome over label records. */
export function summarize(records) {
  const s = { declarations: records.length, stable: 0, body: 0, identity: 0, judgement: 0 };
  for (const r of records) {
    if (r.judgement) s.judgement++;
    else if (r.label === 'stable') s.stable++;
    else if (r.change === 'body') s.body++;
    else s.identity++;
  }
  return s;
}
