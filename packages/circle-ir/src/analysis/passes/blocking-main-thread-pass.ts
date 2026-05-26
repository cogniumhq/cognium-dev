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

    if (handlerRanges.length === 0) return { blockingInHandlers: [] };

    const blockingInHandlers: BlockingMainThreadResult['blockingInHandlers'] = [];

    for (const call of graph.ir.calls) {
      const name = call.method_name;
      const isCrypto = CRYPTO_BLOCKING_METHODS.has(name);
      const isSyncSuffix = SYNC_SUFFIX_RE.test(name);
      if (!isCrypto && !isSyncSuffix) continue;

      const line = call.location.line;
      const range = handlerRanges.find(r => line >= r.start && line <= r.end);
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
