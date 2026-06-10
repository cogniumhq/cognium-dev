/**
 * Runtime-registration extractor (issue #15 — Phase 1).
 *
 * Recognises JS/TS framework registration patterns where a handler is wired
 * into a dispatch table at module-load time. Static call extraction sees the
 * registration call (`app.get(...)`) but not the edge from registrar → handler.
 *
 * Downstream consumers (e.g. dead-code reachability) read
 * `ir.runtime_registrations` and add each resolved handler as a virtual entry
 * root, eliminating "unreachable" false positives for framework handlers.
 *
 * Phase 1 covers:
 *   - Express-family HTTP routes: `app.METHOD(path?, ...handlers)`
 *     where METHOD ∈ HTTP_VERBS and receiver is express-shaped
 *   - Middleware: `app.use(...handlers)`
 *   - Event listeners: `emitter.on('event', handler)` (when receiver is
 *     express-shaped, otherwise skipped to avoid false-positive registrations)
 *
 * Out of scope for Phase 1:
 *   - NestJS / Python decorators (Phase 2)
 *   - Rust trait dispatch (Phase 3)
 *   - Subapp mounting (`app.use('/api', subApp)`) handler resolution
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
 * Returns `[]` for any language other than JavaScript/TypeScript in Phase 1.
 */
export function extractRuntimeRegistrations(
  tree: Tree,
  cache: NodeCache | undefined,
  language: SupportedLanguage | string,
  imports?: ImportInfo[],
): RuntimeRegistration[] {
  if (language !== 'javascript' && language !== 'typescript') {
    return [];
  }
  return extractJSRuntimeRegistrations(tree, cache, imports);
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
