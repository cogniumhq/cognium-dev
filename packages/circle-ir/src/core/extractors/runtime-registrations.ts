/**
 * Runtime-registration extractor (issue #15 — Phases 1 + 2).
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
 * Out of scope (Phase 3):
 *   - Rust trait dispatch (`impl Trait for Type`, `Box<dyn Trait>`,
 *     `inventory::submit!`, `linkme::distributed_slice`).
 *   - Subapp mounting (`app.use('/api', subApp)`) handler resolution.
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
 * Returns `[]` for any other language.
 */
export function extractRuntimeRegistrations(
  tree: Tree,
  cache: NodeCache | undefined,
  language: SupportedLanguage | string,
  imports?: ImportInfo[],
): RuntimeRegistration[] {
  if (language === 'javascript' || language === 'typescript') {
    return extractJSRuntimeRegistrations(tree, cache, imports);
  }
  if (language === 'python') {
    return extractPythonRuntimeRegistrations(tree, cache, imports);
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
