/**
 * MCP server assembly — register every tool + resource on a fresh
 * `McpServer` instance. Transport wiring lives in `index.ts` so this
 * module stays transport-agnostic and testable.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ProjectCache } from './cache.js';
import type { ToolContext } from './tools/types.js';
import { registerResources } from './resources/index.js';

import { scanConfig, makeScanHandler } from './tools/scan.js';
import { explainFindingConfig, makeExplainFindingHandler } from './tools/explain-finding.js';
import { taintPathsConfig, makeTaintPathsHandler } from './tools/taint-paths.js';
import { listEntryPointsConfig, makeListEntryPointsHandler } from './tools/list-entry-points.js';
import { checkSanitizerConfig, makeCheckSanitizerHandler } from './tools/check-sanitizer.js';
import { describeSinkConfig, makeDescribeSinkHandler } from './tools/describe-sink.js';
import { describeSourceConfig, makeDescribeSourceHandler } from './tools/describe-source.js';
import { attackSurfaceSummaryConfig, makeAttackSurfaceSummaryHandler } from './tools/attack-surface-summary.js';
import { listReachableSinksConfig, makeListReachableSinksHandler } from './tools/list-reachable-sinks.js';
import { findSimilarConfig, makeFindSimilarHandler } from './tools/find-similar.js';
import { refreshConfig, makeRefreshHandler } from './tools/refresh.js';

export interface BuildServerOptions {
  /** Override the default cache capacity (3 projects). */
  cacheCapacity?: number;
}

export function buildServer(opts: BuildServerOptions = {}): McpServer {
  const cache = new ProjectCache(opts.cacheCapacity ?? 3);
  const ctx: ToolContext = { cache };

  const server = new McpServer({
    name: 'cognium-mcp-server',
    version: '0.1.0',
  });

  server.registerTool('scan', scanConfig, makeScanHandler(ctx) as never);
  server.registerTool('explain_finding', explainFindingConfig, makeExplainFindingHandler(ctx) as never);
  server.registerTool('taint_paths', taintPathsConfig, makeTaintPathsHandler(ctx) as never);
  server.registerTool('list_entry_points', listEntryPointsConfig, makeListEntryPointsHandler(ctx) as never);
  server.registerTool('check_sanitizer', checkSanitizerConfig, makeCheckSanitizerHandler(ctx) as never);
  server.registerTool('describe_sink', describeSinkConfig, makeDescribeSinkHandler(ctx) as never);
  server.registerTool('describe_source', describeSourceConfig, makeDescribeSourceHandler(ctx) as never);
  server.registerTool('attack_surface_summary', attackSurfaceSummaryConfig, makeAttackSurfaceSummaryHandler(ctx) as never);
  server.registerTool('list_reachable_sinks', listReachableSinksConfig, makeListReachableSinksHandler(ctx) as never);
  server.registerTool('find_similar', findSimilarConfig, makeFindSimilarHandler(ctx) as never);
  server.registerTool('refresh', refreshConfig, makeRefreshHandler(ctx) as never);

  registerResources(server);

  return server;
}
