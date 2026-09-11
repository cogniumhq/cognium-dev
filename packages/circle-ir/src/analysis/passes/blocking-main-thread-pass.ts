/**
 * Pass #83: blocking-main-thread (CWE-1050, category: performance)
 *
 * Detects synchronous/blocking operations inside HTTP request handlers
 * that stall the Node.js event loop, degrading latency under load.
 *
 * Scope: JavaScript / TypeScript only.
 *
 * Differentiation from SyncIoAsyncPass (#48):
 *   SyncIoAsyncPass catches *Sync calls inside any `async` function.
 *   This pass focuses specifically on request handler context
 *   (NestJS/Express/Koa/Fastify/Hono) and includes expensive crypto/hashing
 *   operations that are particularly harmful in synchronous handlers.
 *
 * Detection strategy:
 *   1. Identify request handler methods by:
 *      a. HTTP method decorators in annotations (Get, Post, Put, Patch, Delete)
 *      b. Common handler parameter names (req, res, ctx, c)
 *      c. Conventional handler method names (handle, handler)
 *   2. Within those method ranges, scan graph.ir.calls for:
 *      a. Blocking *Sync calls (readFileSync, execSync, spawnSync, etc.)
 *      b. Synchronous crypto operations (createHash, hashSync, pbkdf2Sync,
 *         scryptSync, generateKeyPairSync)
 *   3. Emit one warning per blocking call site.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** HTTP method decorator names (NestJS / Fastify / express-style, without the @ prefix). */
const HTTP_DECORATORS = new Set([
  'Get', 'Post', 'Put', 'Patch', 'Delete', 'All', 'Options', 'Head',
  'Route', 'Handler',
]);

/** Parameter names that indicate an HTTP request handler. */
const HANDLER_PARAM_NAMES = new Set([
  'req', 'res', 'request', 'response', 'ctx', 'c', 'event',
]);

/** Method names that strongly suggest HTTP request handling. */
const HANDLER_METHOD_NAMES = new Set([
  'handle', 'handler', 'dispatch', 'invoke', 'serve',
]);

/** Synchronous crypto operations that are expensive in the request path. */
const CRYPTO_BLOCKING_METHODS = new Set([
  'createHash', 'hashSync', 'pbkdf2Sync', 'scryptSync',
  'generateKeyPairSync', 'generateKeySync', 'deriveKeySync',
]);

const SYNC_SUFFIX_RE = /Sync$/;

/**
 * Router methods that mount an HTTP request handler (Express / Koa / Hono /
 * Fastify). Lowercase counterparts of HTTP_DECORATORS, plus `use` for
 * middleware — middleware runs in the request path, so a blocking call there
 * stalls the loop exactly as one in a route handler does.
 */
const ROUTER_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head', 'use',
]);

/**
 * Parameter list of a function passed as an argument, for the two shapes that
 * appear as route callbacks: `(req, res) => …` / `async (req, res) => …` /
 * `function (req, res) { … }` (group 1), and the single-parameter arrow
 * `ctx => …` (group 2).
 */
const FN_ARG_PARAMS_RE =
  /^(?:async\s+)?(?:function\s*[\w$]*\s*)?\(([^)]*)\)\s*(?:=>|\{)|^(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/;

export interface BlockingMainThreadResult {
  blockingInHandlers: Array<{
    line: number;
    method: string;
    handler: string;
    reason: 'sync-suffix' | 'crypto';
  }>;
}

export class BlockingMainThreadPass implements AnalysisPass<BlockingMainThreadResult> {
  readonly name = 'blocking-main-thread';
  readonly category = 'performance' as const;

  run(ctx: PassContext): BlockingMainThreadResult {
    const { graph, language } = ctx;

    if (language !== 'javascript' && language !== 'typescript') {
      return { blockingInHandlers: [] };
    }

    const file = graph.ir.meta.file;

    // Collect request handler method line ranges
    const handlerRanges: Array<{ start: number; end: number; name: string }> = [];
    for (const type of graph.ir.types) {
      for (const method of type.methods) {
        if (this.isRequestHandler(method)) {
          handlerRanges.push({
            start: method.start_line,
            end: method.end_line,
            name: method.name,
          });
        }
      }
    }

    // Inline route callbacks are invisible to the loop above: `app.get('/x',
    // (req, res) => …)` produces no entry in `graph.ir.types`, so it has no
    // method and no line range — which silently exempted the most common
    // Express/Koa shape in the ecosystem (cognium-dev#315). A named
    // `function handler(req, res)` was caught, because top-level functions do
    // land in the synthetic `<module>` type; an inline arrow did not.
    //
    // No line range is needed. The calls extractor already names the enclosing
    // function for this shape: an arrow or function-expression passed as an
    // argument to a member-expression call is tagged `<property>_handler` by
    // `findJSEnclosingFunction` (core/extractors/calls.ts), so a blocking call
    // inside `app.get(…)` carries `in_method === 'get_handler'`.
    const inlineHandlers = this.collectInlineHandlerNames(graph.ir.calls);

    if (handlerRanges.length === 0 && inlineHandlers.size === 0) {
      return { blockingInHandlers: [] };
    }

    const blockingInHandlers: BlockingMainThreadResult['blockingInHandlers'] = [];

    for (const call of graph.ir.calls) {
      const name = call.method_name;
      const isCrypto = CRYPTO_BLOCKING_METHODS.has(name);
      const isSyncSuffix = SYNC_SUFFIX_RE.test(name);
      if (!isCrypto && !isSyncSuffix) continue;

      const line = call.location.line;
      const enclosing = call.in_method ?? null;
      const range = handlerRanges.find(r => line >= r.start && line <= r.end)
        ?? (enclosing && inlineHandlers.has(enclosing)
          ? { start: line, end: line, name: enclosing }
          : undefined);
      if (!range) continue;

      const reason: 'sync-suffix' | 'crypto' = isCrypto ? 'crypto' : 'sync-suffix';
      blockingInHandlers.push({ line, method: name, handler: range.name, reason });

      ctx.addFinding({
        id: `blocking-main-thread-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1050',
        severity: 'medium',
        level: 'warning',
        message:
          `Blocking call \`${name}()\` inside request handler '${range.name}' ` +
          `stalls the event loop under concurrent load`,
        file,
        line,
        fix: 'Move to an async equivalent or offload to a worker thread',
        evidence: { handler: range.name, blocking_method: name, reason },
      });
    }

    return { blockingInHandlers };
  }

  /**
   * Synthetic `<verb>_handler` names that really do belong to an HTTP route.
   *
   * The extractor tags *any* function argument of *any* member-expression call
   * this way, so `items.map(x => …)` becomes `map_handler` and
   * `cache.get(k, () => …)` becomes `get_handler`. Accepting every
   * `*_handler` would pull ordinary callbacks into a pass that is explicitly
   * about the HTTP request path, so two conditions are required: the method is
   * a router verb, and the callback's own parameters look like a request
   * handler's — the same `HANDLER_PARAM_NAMES` test used for methods.
   *
   * Known limitation: `in_method` carries no receiver, so two callbacks that
   * share a verb in one file are indistinguishable. A file containing both
   * `app.get('/x', (req, res) => …)` and `cache.get(k, () => …)` will treat a
   * blocking call in the second as in-handler. Both conditions still have to
   * hold for the verb to register at all, which keeps that to files already
   * mounting a real route of the same verb.
   */
  private collectInlineHandlerNames(calls: readonly {
    method_name: string;
    arguments: Array<{ expression: string }>;
  }[]): Set<string> {
    const names = new Set<string>();

    for (const call of calls) {
      if (!ROUTER_METHODS.has(call.method_name)) continue;

      for (const arg of call.arguments) {
        const match = FN_ARG_PARAMS_RE.exec((arg.expression ?? '').trim());
        if (!match) continue;

        const params = (match[1] ?? match[2] ?? '')
          .split(',')
          .map(p => p.trim().toLowerCase())
          .filter(p => p.length > 0);

        if (params.some(p => HANDLER_PARAM_NAMES.has(p))) {
          names.add(`${call.method_name}_handler`);
          break;
        }
      }
    }

    return names;
  }

  private isRequestHandler(method: {
    name: string;
    annotations: string[];
    parameters: Array<{ name: string }>;
  }): boolean {
    // NestJS / Fastify HTTP decorators
    if (method.annotations.some(a => HTTP_DECORATORS.has(a))) return true;
    // Conventional handler method names
    if (HANDLER_METHOD_NAMES.has(method.name)) return true;
    // Express/Koa/Hono request handler patterns: (req, res) or (ctx)
    const paramNames = method.parameters.map(p => p.name.toLowerCase());
    return paramNames.some(n => HANDLER_PARAM_NAMES.has(n));
  }
}
