/**
 * Runtime-registration extractor (issue #15 — Phases 1, 2, 3).
 *
 * Recognises framework registration patterns where a handler is wired into a
 * dispatch table at module-load time. Static call extraction sees the
 * registration call/decorator but not the edge from registrar → handler.
 *
 * Downstream consumers (e.g. dead-code reachability) read
 * `ir.runtime_registrations` and add each resolved handler as a virtual entry
 * root, eliminating "unreachable" false positives for framework handlers.
 *
 * Phase 1 — JS/TS Express-family (shipped 3.32.0):
 *   - HTTP routes: `app.METHOD(path?, ...handlers)` for METHOD ∈ HTTP_VERBS
 *   - Middleware: `app.use(...handlers)`
 *   - Event listeners: `emitter.on('event', handler)` on express-shaped receivers
 *
 * Phase 2 — Python decorators (3.33.0):
 *   - Every `@decorator` on a function emits a registration with handler =
 *     decorated function. Known frameworks are tagged (flask, fastapi,
 *     django, click, pytest, celery, numba); built-in (property,
 *     staticmethod, etc.) is tagged `stdlib`. Routing-style decorators
 *     (`@app.route`, `@app.get`, `@router.post`) are classified as
 *     `kind: 'http_route'` so downstream consumers can treat JS routes and
 *     Python routes uniformly.
 *
 * Phase 3 — Rust trait dispatch (3.34.0):
 *   - `impl Trait for Type { fn method(...) }` emits one `trait_impl`
 *     registration per method, recording the Self type as `receiver`, the
 *     trait path as `path`, and the method as both `registrar.method` and
 *     `handler.name`. Stdlib traits (Display, Debug, Iterator, …) are tagged
 *     `framework: 'stdlib'`; known web/async/serde frameworks (actix, axum,
 *     rocket, tokio, serde) are tagged accordingly.
 *   - `inventory::submit! { … }` and `#[linkme::distributed_slice]` emit
 *     `trait_impl` registrations with framework `'inventory'` / `'linkme'`.
 *
 * Out of scope:
 *   - Subapp mounting (`app.use('/api', subApp)`) handler resolution.
 *   - Cross-file trait → impl resolution scoped by `Cargo.toml` reachability
 *     (file-local impls only at extraction time; project-level resolution is
 *     deferred to a later cross-file pass).
 */

import type { Node, Tree } from 'web-tree-sitter';
import type { RuntimeRegistration, ImportInfo } from '../../types/index.js';
import { getNodeText, getNodesFromCache, type NodeCache } from '../parser.js';
import type { SupportedLanguage } from '../parser.js';

/** HTTP verb methods recognised on Express-family routers. */
const HTTP_VERB_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete',
  'head', 'options', 'all',
]);

/** Middleware registration methods. */
const MIDDLEWARE_METHODS = new Set(['use']);

/** Event-listener methods (Node EventEmitter / WebSocket-style). */
const EVENT_LISTENER_METHODS = new Set(['on', 'once', 'ws']);

/** Receivers heuristically treated as express-family routers. */
const EXPRESS_RECEIVER_NAMES = new Set([
  'app', 'router', 'server', 'apiRouter',
  // common framework instances
  'fastify', 'koa', 'express',
]);

/** Module specifiers that, when imported, signal an Express-family framework. */
const FRAMEWORK_MODULE_PATTERNS = [
  /^express$/, /^@?fastify(\/.*)?$/, /^koa$/, /^restify$/, /^hapi$/,
  /^@nestjs\/common$/, /^@nestjs\/core$/,
];

/**
 * Extract runtime-registration patterns from a parsed file.
 *
 * Phase 1 covers JavaScript/TypeScript. Phase 2 adds Python decorators.
 * Phase 3 adds Rust trait dispatch (`impl Trait for Type`, `inventory::submit!`,
 * `#[linkme::distributed_slice]`). Returns `[]` for any other language.
 */
export function extractRuntimeRegistrations(
  tree: Tree,
  cache: NodeCache | undefined,
  language: SupportedLanguage | string,
  imports?: ImportInfo[],
): RuntimeRegistration[] {
  if (language === 'javascript' || language === 'typescript' || language === 'tsx') {
    return extractJSRuntimeRegistrations(tree, cache, imports);
  }
  if (language === 'python') {
    return extractPythonRuntimeRegistrations(tree, cache, imports);
  }
  if (language === 'rust') {
    return extractRustRuntimeRegistrations(tree, cache);
  }
  return [];
}

/**
 * Lookup of locally-declared function/identifier-bound function expressions.
 * Used to record handler `line/column` when a named identifier is passed in.
 */
interface HandlerIndex {
  /** name -> first declaration site (line/column 1-based / 0-based) */
  declarations: Map<string, { line: number; column: number }>;
  /** Whether any framework module appears in imports — boosts confidence. */
  hasFrameworkImport: boolean;
}

function buildHandlerIndex(tree: Tree, cache: NodeCache | undefined, imports?: ImportInfo[]): HandlerIndex {
  const decls = new Map<string, { line: number; column: number }>();

  const recordDeclaration = (name: string, node: Node) => {
    if (!decls.has(name)) {
      decls.set(name, {
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
      });
    }
  };

  // function foo() {...}
  for (const fn of getNodesFromCache(tree.rootNode, 'function_declaration', cache)) {
    const nameNode = fn.childForFieldName('name');
    if (nameNode) recordDeclaration(getNodeText(nameNode), fn);
  }

  // const foo = (...) => ... ; const foo = function () { ... }
  const collectVarDeclarators = (parentType: string) => {
    for (const decl of getNodesFromCache(tree.rootNode, parentType, cache)) {
      for (let i = 0; i < decl.childCount; i++) {
        const child = decl.child(i);
        if (!child || child.type !== 'variable_declarator') continue;
        const nameNode = child.childForFieldName('name');
        const valueNode = child.childForFieldName('value');
        if (!nameNode || !valueNode) continue;
        if (
          valueNode.type === 'arrow_function' ||
          valueNode.type === 'function_expression' ||
          valueNode.type === 'function'
        ) {
          recordDeclaration(getNodeText(nameNode), child);
        }
      }
    }
  };
  collectVarDeclarators('lexical_declaration');
  collectVarDeclarators('variable_declaration');

  let hasFrameworkImport = false;
  if (imports) {
    for (const imp of imports) {
      const mod = imp.from_package ?? '';
      if (mod && FRAMEWORK_MODULE_PATTERNS.some(re => re.test(mod))) {
        hasFrameworkImport = true;
        break;
      }
    }
  }

  return { declarations: decls, hasFrameworkImport };
}

function extractJSRuntimeRegistrations(
  tree: Tree,
  cache: NodeCache | undefined,
  imports?: ImportInfo[],
): RuntimeRegistration[] {
  const out: RuntimeRegistration[] = [];
  const index = buildHandlerIndex(tree, cache, imports);

  const callExpressions = getNodesFromCache(tree.rootNode, 'call_expression', cache);

  for (const call of callExpressions) {
    const fnNode = call.childForFieldName('function');
    if (!fnNode || fnNode.type !== 'member_expression') continue;

    const objectNode = fnNode.childForFieldName('object');
    const propertyNode = fnNode.childForFieldName('property');
    if (!objectNode || !propertyNode) continue;

    const method = getNodeText(propertyNode);
    const receiver = getNodeText(objectNode);

    const kind = classifyMethod(method);
    if (!kind) continue;

    // Receiver filtering: keep noise out. Either:
    //  - the receiver name is a known router-ish identifier, OR
    //  - a framework module is imported (relaxed: any member call with the
    //    right method shape is considered).
    if (!isExpressShapedReceiver(receiver) && !index.hasFrameworkImport) {
      continue;
    }

    const argsNode = call.childForFieldName('arguments');
    if (!argsNode) continue;

    const argNodes = getRealArgs(argsNode);
    if (argNodes.length === 0) continue;

    // Path (literal first argument) is optional. Determine arg slice for handlers.
    let path: string | undefined;
    let handlerStart = 0;
    const first = argNodes[0];
    if (first.type === 'string') {
      path = stripQuotes(getNodeText(first));
      handlerStart = 1;
    } else if (first.type === 'template_string' && !hasTemplateSubstitution(first)) {
      path = stripBackticks(getNodeText(first));
      handlerStart = 1;
    }

    // For `.use(handler)` / `.on('event', handler)` / `.get('/p', h1, h2)` etc.
    // Every remaining positional argument that is a function-like is a handler.
    for (let i = handlerStart; i < argNodes.length; i++) {
      const handlerNode = argNodes[i];
      const handler = resolveHandler(handlerNode, index);
      if (!handler) continue;

      out.push({
        kind,
        framework: inferFramework(receiver, index.hasFrameworkImport),
        registrar: {
          method,
          receiver,
          line: call.startPosition.row + 1,
          column: call.startPosition.column,
        },
        ...(path !== undefined ? { path } : {}),
        handler,
      });
    }
  }

  return out;
}

function classifyMethod(method: string): RuntimeRegistration['kind'] | null {
  if (HTTP_VERB_METHODS.has(method)) return 'http_route';
  if (MIDDLEWARE_METHODS.has(method)) return 'middleware';
  if (EVENT_LISTENER_METHODS.has(method)) return 'event_listener';
  return null;
}

function isExpressShapedReceiver(receiver: string): boolean {
  if (EXPRESS_RECEIVER_NAMES.has(receiver)) return true;
  // Common naming: `apiRouter`, `userRouter`, `<x>Router`, `<x>App`
  if (/(?:Router|App|Server)$/.test(receiver)) return true;
  return false;
}

function inferFramework(receiver: string, hasFrameworkImport: boolean): RuntimeRegistration['framework'] {
  if (receiver === 'fastify') return 'fastify';
  if (receiver === 'koa') return 'koa';
  if (receiver === 'express') return 'express';
  // Default heuristic: known express-shaped receivers default to express when
  // a framework import is present; otherwise unknown.
  return hasFrameworkImport ? 'express' : 'unknown';
}

/** Skip punctuation children inside `arguments` */
function getRealArgs(argsNode: Node): Node[] {
  const out: Node[] = [];
  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child) continue;
    if (child.type === '(' || child.type === ')' || child.type === ',') continue;
    out.push(child);
  }
  return out;
}

function stripQuotes(s: string): string {
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]) {
    return s.slice(1, -1);
  }
  return s;
}

function stripBackticks(s: string): string {
  if (s.length >= 2 && s[0] === '`' && s[s.length - 1] === '`') {
    return s.slice(1, -1);
  }
  return s;
}

function hasTemplateSubstitution(node: Node): boolean {
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child && child.type === 'template_substitution') return true;
  }
  return false;
}

function resolveHandler(
  node: Node,
  index: HandlerIndex,
): RuntimeRegistration['handler'] | null {
  // Inline arrow / function expression — name=null, location is the lambda site.
  if (
    node.type === 'arrow_function' ||
    node.type === 'function_expression' ||
    node.type === 'function'
  ) {
    return {
      name: null,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    };
  }

  // Named identifier — look up declaration site if available, else use call site.
  if (node.type === 'identifier') {
    const name = getNodeText(node);
    const decl = index.declarations.get(name);
    if (decl) {
      return { name, line: decl.line, column: decl.column };
    }
    return {
      name,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    };
  }

  // Member expression (e.g. controller.handle) — record the textual reference.
  if (node.type === 'member_expression') {
    return {
      name: getNodeText(node),
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    };
  }

  // Anything else (object literals, complex expressions): not a handler.
  return null;
}

// =============================================================================
// Python — Phase 2
// =============================================================================

/** HTTP-route decorator method names (after the dotted prefix). */
const PY_HTTP_ROUTE_METHODS = new Set([
  // Flask/Blueprint: app.route, blueprint.route, api.route
  'route',
  // FastAPI / Starlette / DRF method-specific
  'get', 'post', 'put', 'patch', 'delete', 'head', 'options',
  // Flask aliases (Flask 2.x): app.get/post/...
]);

/** Flask middleware-style decorators. */
const PY_MIDDLEWARE_METHODS = new Set([
  'before_request', 'after_request', 'teardown_request',
  'before_first_request', 'teardown_appcontext',
  // Starlette / FastAPI
  'middleware',
]);

/** Event/lifecycle-style decorators. */
const PY_EVENT_METHODS = new Set([
  'errorhandler', 'on_event', 'exception_handler',
  // Celery beat etc — not strictly events but lifecycle
]);

/** Python stdlib / built-in decorators that don't register externally. */
const PY_STDLIB_DECORATORS = new Set([
  'property', 'staticmethod', 'classmethod', 'abstractmethod', 'cached_property',
  'dataclass', 'cache', 'lru_cache', 'singledispatch', 'singledispatchmethod',
  'contextmanager', 'asynccontextmanager', 'final', 'override',
  'wraps',
]);

interface PyImportSummary {
  hasFlask: boolean;
  hasFastApi: boolean;
  hasCelery: boolean;
  hasNumba: boolean;
  hasClick: boolean;
  hasPytest: boolean;
}

function summarisePythonImports(imports?: ImportInfo[]): PyImportSummary {
  const s: PyImportSummary = {
    hasFlask: false, hasFastApi: false, hasCelery: false,
    hasNumba: false, hasClick: false, hasPytest: false,
  };
  if (!imports) return s;
  for (const imp of imports) {
    const mod = imp.from_package ?? '';
    if (!mod) continue;
    if (/^flask(\b|\.)/.test(mod)) s.hasFlask = true;
    if (/^fastapi(\b|\.)/.test(mod) || /^starlette(\b|\.)/.test(mod)) s.hasFastApi = true;
    if (/^celery(\b|\.)/.test(mod)) s.hasCelery = true;
    if (/^numba(\b|\.)/.test(mod)) s.hasNumba = true;
    if (/^click(\b|\.)/.test(mod)) s.hasClick = true;
    if (/^pytest(\b|\.)/.test(mod)) s.hasPytest = true;
  }
  return s;
}

function extractPythonRuntimeRegistrations(
  tree: Tree,
  cache: NodeCache | undefined,
  imports?: ImportInfo[],
): RuntimeRegistration[] {
  const out: RuntimeRegistration[] = [];
  const importSummary = summarisePythonImports(imports);

  const decoratedDefs = getNodesFromCache(tree.rootNode, 'decorated_definition', cache);

  for (const dd of decoratedDefs) {
    // Find the function_definition child (skip class_definition for now —
    // class-level decorators are not the dead-code use case).
    let fnNode: Node | null = null;
    const decorators: Node[] = [];
    for (let i = 0; i < dd.childCount; i++) {
      const child = dd.child(i);
      if (!child) continue;
      if (child.type === 'decorator') {
        decorators.push(child);
      } else if (child.type === 'function_definition' || child.type === 'async_function_definition') {
        fnNode = child;
      }
    }
    if (!fnNode || decorators.length === 0) continue;

    const handler = pythonHandlerFromFunctionDef(fnNode);
    if (!handler) continue;

    for (const dec of decorators) {
      const parsed = parsePythonDecorator(dec);
      if (!parsed) continue;

      const { receiver, method, path, line, column } = parsed;
      const { kind, framework } = classifyPythonDecorator(
        receiver, method, importSummary,
      );

      out.push({
        kind,
        framework,
        registrar: { method, receiver, line, column },
        ...(path !== undefined ? { path } : {}),
        handler,
      });
    }
  }

  return out;
}

function pythonHandlerFromFunctionDef(fn: Node): RuntimeRegistration['handler'] | null {
  const nameNode = fn.childForFieldName('name');
  if (!nameNode) return null;
  return {
    name: getNodeText(nameNode),
    line: fn.startPosition.row + 1,
    column: fn.startPosition.column,
  };
}

interface ParsedPythonDecorator {
  receiver: string;
  method: string;
  path?: string;
  line: number;
  column: number;
}

/**
 * Parse a `decorator` node into receiver/method/path components.
 * The decorator wraps one of: `identifier`, `attribute`, or `call`.
 */
function parsePythonDecorator(dec: Node): ParsedPythonDecorator | null {
  // Skip the leading `@` token; take the first non-trivial child.
  let target: Node | null = null;
  for (let i = 0; i < dec.childCount; i++) {
    const child = dec.child(i);
    if (!child || child.type === '@') continue;
    target = child;
    break;
  }
  if (!target) return null;

  const line = dec.startPosition.row + 1;
  const column = dec.startPosition.column;

  // @bare_decorator
  if (target.type === 'identifier') {
    return { receiver: '', method: getNodeText(target), line, column };
  }

  // @pkg.attr  (no call)
  if (target.type === 'attribute') {
    const { receiver, method } = splitDottedAttribute(target);
    return { receiver, method, line, column };
  }

  // @pkg.attr(...) or @bare_decorator(...)
  if (target.type === 'call') {
    const fnNode = target.childForFieldName('function');
    if (!fnNode) return null;
    let receiver = '';
    let method = '';
    if (fnNode.type === 'identifier') {
      method = getNodeText(fnNode);
    } else if (fnNode.type === 'attribute') {
      const split = splitDottedAttribute(fnNode);
      receiver = split.receiver;
      method = split.method;
    } else {
      // Complex expression like `make_decorator()(...)` — record textual.
      method = getNodeText(fnNode);
    }

    // Look at first positional arg for a literal string path.
    const path = extractFirstStringArg(target);

    return { receiver, method, path, line, column };
  }

  return null;
}

/** Split `a.b.c` into receiver=`a.b`, method=`c`. */
function splitDottedAttribute(attr: Node): { receiver: string; method: string } {
  const objectNode = attr.childForFieldName('object');
  const attrNode = attr.childForFieldName('attribute');
  const method = attrNode ? getNodeText(attrNode) : '';
  const receiver = objectNode ? getNodeText(objectNode) : '';
  return { receiver, method };
}

/** Extract first positional argument as a literal string if present. */
function extractFirstStringArg(call: Node): string | undefined {
  const argsNode = call.childForFieldName('arguments');
  if (!argsNode) return undefined;
  for (let i = 0; i < argsNode.childCount; i++) {
    const child = argsNode.child(i);
    if (!child) continue;
    if (child.type === '(' || child.type === ')' || child.type === ',') continue;
    // First real argument
    if (child.type === 'string') {
      return stripPythonStringQuotes(getNodeText(child));
    }
    // Anything else as first positional arg → no path
    return undefined;
  }
  return undefined;
}

function stripPythonStringQuotes(s: string): string {
  // Handle prefixes like b'', r'', u'', f'' — we don't need their semantics here.
  const m = s.match(/^[bBrRuUfF]{0,2}(['"])(.*)\1$/s);
  if (m) return m[2];
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * Classify a Python decorator into kind + framework.
 *
 * The classification cascade:
 *   1. stdlib built-in (property, staticmethod, ...) → kind=decorator, framework=stdlib
 *   2. `@<framework>.<method>` where framework is recognised
 *   3. `@app.<http_verb>` / `@router.<http_verb>` / `@app.route` → http_route
 *   4. Middleware / event hooks on Flask-like receivers
 *   5. Generic decorator → kind=decorator, framework=unknown
 */
function classifyPythonDecorator(
  receiver: string,
  method: string,
  imp: PyImportSummary,
): { kind: RuntimeRegistration['kind']; framework: RuntimeRegistration['framework'] } {
  // 1. stdlib built-ins (bare decorators, e.g. @property)
  if (!receiver && PY_STDLIB_DECORATORS.has(method)) {
    return { kind: 'decorator', framework: 'stdlib' };
  }

  // 2. Framework-prefixed decorators
  if (receiver) {
    const head = receiver.split('.')[0];
    // pytest.fixture / pytest.mark.parametrize
    if (head === 'pytest') {
      return { kind: 'decorator', framework: 'pytest' };
    }
    if (head === 'click') {
      return { kind: 'decorator', framework: 'click' };
    }
    if (head === 'numba' || head === 'nb') {
      return { kind: 'decorator', framework: 'numba' };
    }
    if (head === 'celery') {
      return { kind: 'decorator', framework: 'celery' };
    }
  }

  // 3. HTTP-route decorators on app/router/blueprint/api receivers
  if (receiver && PY_HTTP_ROUTE_METHODS.has(method)) {
    const isRoutey = isPyRouterReceiver(receiver);
    if (isRoutey) {
      // Framework inference: import-driven
      let framework: RuntimeRegistration['framework'] = 'unknown';
      if (imp.hasFlask) framework = 'flask';
      else if (imp.hasFastApi) framework = 'fastapi';
      else if (method === 'route') framework = 'flask';   // Flask hallmark
      else framework = 'fastapi';                          // verbs alone bias to FastAPI
      return { kind: 'http_route', framework };
    }
  }

  // 4. Middleware-style decorators
  if (receiver && PY_MIDDLEWARE_METHODS.has(method)) {
    return { kind: 'middleware', framework: imp.hasFlask ? 'flask' : (imp.hasFastApi ? 'fastapi' : 'unknown') };
  }

  // 5. Event-style decorators
  if (receiver && PY_EVENT_METHODS.has(method)) {
    return { kind: 'event_listener', framework: imp.hasFlask ? 'flask' : (imp.hasFastApi ? 'fastapi' : 'unknown') };
  }

  // 6. app.task / @<x>.task — celery if celery imported
  if (method === 'task' && imp.hasCelery) {
    return { kind: 'decorator', framework: 'celery' };
  }

  // 7. Django auth/method decorators (bare)
  if (!receiver && (method === 'login_required' || method === 'require_http_methods' || method === 'api_view')) {
    return { kind: 'decorator', framework: 'django' };
  }

  // Fallthrough
  return { kind: 'decorator', framework: 'unknown' };
}

/** Names commonly used for Flask/FastAPI app/router/blueprint instances. */
function isPyRouterReceiver(receiver: string): boolean {
  const head = receiver.split('.')[0];
  if (!head) return false;
  if (['app', 'router', 'blueprint', 'bp', 'api', 'application'].includes(head)) return true;
  // Suffix conventions: my_router, user_bp, etc.
  if (/_(router|bp|blueprint|app|api)$/.test(head)) return true;
  return false;
}

// =============================================================================
// Phase 3 — Rust trait dispatch
// =============================================================================

/**
 * Standard-library traits whose `impl` blocks are tagged `framework: 'stdlib'`.
 * Match is by last segment of the trait path, so both `Display` and
 * `std::fmt::Display` classify the same way.
 */
const RUST_STDLIB_TRAITS = new Set([
  // Formatting
  'Display', 'Debug', 'Write',
  // Conversion
  'From', 'Into', 'TryFrom', 'TryInto', 'AsRef', 'AsMut', 'ToString', 'FromStr',
  // Iteration
  'Iterator', 'IntoIterator', 'FromIterator', 'DoubleEndedIterator',
  'ExactSizeIterator', 'FusedIterator',
  // Comparison + hashing
  'PartialEq', 'Eq', 'PartialOrd', 'Ord', 'Hash',
  // Markers + defaults
  'Default', 'Copy', 'Clone', 'Send', 'Sync', 'Unpin', 'Sized', 'Any',
  // Resource management
  'Drop',
  // Async
  'Future', 'IntoFuture',
  // Operators
  'Add', 'Sub', 'Mul', 'Div', 'Rem', 'Neg', 'Not',
  'AddAssign', 'SubAssign', 'MulAssign', 'DivAssign', 'RemAssign',
  'BitAnd', 'BitOr', 'BitXor', 'Shl', 'Shr',
  'Deref', 'DerefMut', 'Index', 'IndexMut',
  // Closures
  'Fn', 'FnMut', 'FnOnce',
  // Error + I/O
  'Error', 'Read', 'Write', 'Seek', 'BufRead',
  // Misc
  'Borrow', 'BorrowMut', 'ToOwned',
]);

/**
 * Trait-path module prefixes → framework tag. Matched against the leading
 * segments of `impl PathSegment::… for Type`. Longer prefixes win.
 */
const RUST_TRAIT_FRAMEWORK_PREFIXES: Array<{
  prefix: RegExp;
  framework: NonNullable<RuntimeRegistration['framework']>;
}> = [
  { prefix: /^actix(_web)?(::|$)/, framework: 'actix' },
  { prefix: /^axum(::|$)/,         framework: 'axum'  },
  { prefix: /^rocket(::|$)/,       framework: 'rocket' },
  { prefix: /^tokio(::|$)/,        framework: 'tokio' },
  { prefix: /^serde(_\w+)?(::|$)/, framework: 'serde' },
  { prefix: /^std(::|$)/,          framework: 'stdlib' },
  { prefix: /^core(::|$)/,         framework: 'stdlib' },
  { prefix: /^alloc(::|$)/,        framework: 'stdlib' },
];

/**
 * Walk a Rust parse tree and emit one `RuntimeRegistration` per:
 *   - `impl Trait for Type` method (Self-type as receiver, trait as `path`)
 *   - `inventory::submit!` macro invocation
 *   - `#[…distributed_slice(…)]` attribute on a static/function item
 */
function extractRustRuntimeRegistrations(
  tree: Tree,
  cache: NodeCache | undefined,
): RuntimeRegistration[] {
  const regs: RuntimeRegistration[] = [];

  const implNodes = getNodesFromCache(tree.rootNode, 'impl_item', cache);
  for (const impl of implNodes) {
    collectRustImplRegistrations(impl, regs);
  }

  const macroNodes = getNodesFromCache(tree.rootNode, 'macro_invocation', cache);
  for (const macro of macroNodes) {
    const rec = parseInventorySubmit(macro);
    if (rec) regs.push(rec);
  }

  // Distributed-slice attributes — attribute_item is a top-level sibling of the
  // decorated static/function. Walk attribute_item nodes and look ahead.
  const attrNodes = getNodesFromCache(tree.rootNode, 'attribute_item', cache);
  for (const attr of attrNodes) {
    const rec = parseDistributedSliceAttribute(attr);
    if (rec) regs.push(rec);
  }

  return regs;
}

/** Emit one trait_impl registration per method in an `impl Trait for Type` block. */
function collectRustImplRegistrations(impl: Node, regs: RuntimeRegistration[]): void {
  const traitNode = impl.childForFieldName('trait');
  if (!traitNode) return; // inherent impl: skip
  const typeNode = impl.childForFieldName('type');
  if (!typeNode) return;

  const traitText = getNodeText(traitNode).trim();
  const traitLastSegment = lastRustPathSegment(stripRustGenerics(traitText));
  const selfType = getNodeText(typeNode).trim();
  const framework = classifyRustTrait(traitText);

  const body = impl.childForFieldName('body');
  if (!body) return;

  for (let i = 0; i < body.childCount; i++) {
    const child = body.child(i);
    if (!child || child.type !== 'function_item') continue;
    const nameNode = child.childForFieldName('name');
    if (!nameNode) continue;
    const methodName = getNodeText(nameNode);

    regs.push({
      kind: 'trait_impl',
      framework,
      registrar: {
        method: methodName,
        receiver: selfType,
        line: impl.startPosition.row + 1,
        column: impl.startPosition.column,
      },
      path: traitLastSegment || traitText,
      handler: {
        name: methodName,
        line: child.startPosition.row + 1,
        column: child.startPosition.column,
      },
    });
  }
}

/** Strip turbofish/generic arguments from a Rust trait path. */
function stripRustGenerics(text: string): string {
  // Drop everything starting at the first `<` so `Display<T>` → `Display`,
  // `std::fmt::Display<'a>` → `std::fmt::Display`.
  const idx = text.indexOf('<');
  return idx >= 0 ? text.slice(0, idx) : text;
}

/** Last `::`-delimited segment of a Rust path. */
function lastRustPathSegment(path: string): string {
  const parts = path.split('::');
  return parts[parts.length - 1] || path;
}

/** Classify a Rust trait path to a framework tag. */
function classifyRustTrait(traitText: string): NonNullable<RuntimeRegistration['framework']> {
  const stripped = stripRustGenerics(traitText).trim();
  const last = lastRustPathSegment(stripped);

  // Stdlib by last-segment match (covers bare `Display` import).
  if (RUST_STDLIB_TRAITS.has(last)) return 'stdlib';

  // Framework by leading module prefix.
  for (const { prefix, framework } of RUST_TRAIT_FRAMEWORK_PREFIXES) {
    if (prefix.test(stripped)) return framework;
  }

  return 'unknown';
}

/**
 * Recognise `inventory::submit! { Type::new(…) }` (or variations) and emit a
 * registration with framework `'inventory'`. The handler name is the first
 * identifier inside the token tree.
 */
function parseInventorySubmit(macro: Node): RuntimeRegistration | null {
  const macroName = macro.childForFieldName('macro');
  if (!macroName) return null;
  const name = getNodeText(macroName).trim();
  if (name !== 'inventory::submit' && name !== 'submit') return null;
  // Belt-and-braces: require an `inventory::` prefix unless the scoped form matches.
  if (name === 'submit') return null;

  // Find the token_tree (the macro body).
  let tokenTree: Node | null = null;
  for (let i = 0; i < macro.childCount; i++) {
    const c = macro.child(i);
    if (c && c.type === 'token_tree') { tokenTree = c; break; }
  }
  if (!tokenTree) return null;

  const handlerName = firstIdentifierInTokenTree(tokenTree);

  return {
    kind: 'trait_impl',
    framework: 'inventory',
    registrar: {
      method: 'submit',
      receiver: 'inventory',
      line: macro.startPosition.row + 1,
      column: macro.startPosition.column,
    },
    path: 'inventory::submit',
    handler: {
      name: handlerName,
      line: tokenTree.startPosition.row + 1,
      column: tokenTree.startPosition.column,
    },
  };
}

/** Walk a token_tree and return the first non-punctuation identifier text. */
function firstIdentifierInTokenTree(tokenTree: Node): string | null {
  for (let i = 0; i < tokenTree.childCount; i++) {
    const c = tokenTree.child(i);
    if (!c) continue;
    if (c.type === 'identifier' || c.type === 'scoped_identifier' || c.type === 'type_identifier') {
      return getNodeText(c).trim();
    }
  }
  return null;
}

/**
 * Recognise `#[linkme::distributed_slice(…)]` (or `#[distributed_slice(…)]`)
 * and emit a registration whose handler is the next sibling static/function.
 */
function parseDistributedSliceAttribute(attrItem: Node): RuntimeRegistration | null {
  // Find the inner `attribute` node carrying the path.
  let attr: Node | null = null;
  for (let i = 0; i < attrItem.childCount; i++) {
    const c = attrItem.child(i);
    if (c && c.type === 'attribute') { attr = c; break; }
  }
  if (!attr) return null;

  const pathNode = attr.child(0);
  if (!pathNode) return null;
  const pathText = getNodeText(pathNode).trim();
  // Accept either fully-qualified `linkme::distributed_slice` or bare
  // `distributed_slice` (common with `use linkme::distributed_slice;`).
  if (pathText !== 'linkme::distributed_slice' && pathText !== 'distributed_slice') return null;

  // Walk forward through following siblings of attrItem (under the same parent)
  // to find the decorated static_item or function_item.
  // web-tree-sitter returns fresh Node wrappers from `child(i)`, so compare by
  // node `.id` rather than reference identity.
  const parent = attrItem.parent;
  if (!parent) return null;
  let attrIndex = -1;
  for (let i = 0; i < parent.childCount; i++) {
    const c = parent.child(i);
    if (c && c.id === attrItem.id) { attrIndex = i; break; }
  }
  if (attrIndex < 0) return null;

  let handlerNode: Node | null = null;
  for (let j = attrIndex + 1; j < parent.childCount; j++) {
    const sib = parent.child(j);
    if (!sib) continue;
    if (sib.type === 'attribute_item') continue; // chained attributes
    if (sib.type === 'static_item' || sib.type === 'function_item') {
      handlerNode = sib;
    }
    break;
  }
  if (!handlerNode) return null;

  const nameNode = handlerNode.childForFieldName('name');
  const handlerName = nameNode ? getNodeText(nameNode).trim() : null;

  return {
    kind: 'trait_impl',
    framework: 'linkme',
    registrar: {
      method: 'distributed_slice',
      receiver: 'linkme',
      line: attrItem.startPosition.row + 1,
      column: attrItem.startPosition.column,
    },
    path: 'linkme::distributed_slice',
    handler: {
      name: handlerName,
      line: handlerNode.startPosition.row + 1,
      column: handlerNode.startPosition.column,
    },
  };
}
