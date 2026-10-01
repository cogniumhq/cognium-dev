/**
 * MCP server assembly — register every floor tool + resource on a fresh
 * `McpServer` instance, then let each optional module register its own.
 * Transport wiring lives in `bin.ts` so this module stays transport-agnostic
 * and testable, and `index.ts` exports it so a host can mount it over HTTP
 * without spawning a subprocess.
 */

import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ProjectCache } from './cache.js';
import type { ToolContext } from './tools/types.js';
import { registerResources } from './resources/index.js';
import { floorEnablement, enablementForProcess, type Enablement } from './enablement.js';
import {
  loadModules,
  circleIrVersion,
  type ToolModule,
  type ModuleRefusal,
} from './modules.js';

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

const require_ = createRequire(import.meta.url);

/**
 * Server name and version, from the manifest, in one place.
 *
 * They used to be string literals here, and had drifted to `0.1.0` while the
 * package was at `0.1.21`. The `initialize` result carries both, so every
 * transport has to report the same pair — otherwise two clients talking to
 * the same install disagree about what they are talking to.
 */
function identity(): { name: string; version: string } {
  try {
    const pkg = require_('../package.json') as { name: string; version: string };
    return { name: pkg.name, version: pkg.version };
  } catch {
    return { name: '@cognium/mcp-server', version: '0.0.0' };
  }
}

const IDENTITY = identity();

export const SERVER_NAME = IDENTITY.name;
export const SERVER_VERSION = IDENTITY.version;

export interface BuildServerOptions {
  /** Override the default cache capacity (3 projects). */
  cacheCapacity?: number;
  /**
   * Optional tool modules to register after the floor. Already loaded and
   * already checked — `buildServer` is synchronous and does no resolution of
   * its own; `discoverModules()` or `createServer()` do that.
   */
  modules?: readonly ToolModule[];
  /**
   * What this install may offer. Defaults to the floor, which is correct for
   * a server built with no modules.
   */
  enablement?: Enablement;
}

export function buildServer(opts: BuildServerOptions = {}): McpServer {
  const cache = new ProjectCache(opts.cacheCapacity ?? 3);
  const ctx: ToolContext = {
    cache,
    enablement: opts.enablement ?? floorEnablement(),
  };

  const server = new McpServer(IDENTITY);

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

  // A module that throws while registering is refused like any other bad
  // module: the tools it managed to register stay, the rest do not arrive,
  // and the server keeps serving. Losing the floor because an optional
  // extra misbehaved would be the worse outcome.
  for (const mod of opts.modules ?? []) {
    try {
      mod.register(server, ctx);
    } catch (err) {
      process.stderr.write(
        `[${SERVER_NAME}] module ${mod.id}@${mod.version} failed to register: ${(err as Error).message}\n`,
      );
    }
  }

  return server;
}

export interface Discovery {
  readonly modules: readonly ToolModule[];
  readonly refusals: readonly ModuleRefusal[];
  readonly enablement: Enablement;
  readonly circleIr: string;
}

let discovery: Promise<Discovery> | undefined;

/**
 * Resolve the optional modules and compute enablement, once per process.
 *
 * Memoized on the promise, not the result, so concurrent callers — the HTTP
 * host builds a server per request — share one resolution instead of racing
 * to import the same module several times.
 */
export function discoverModules(): Promise<Discovery> {
  discovery ??= (async (): Promise<Discovery> => {
    const circleIr = circleIrVersion();
    const { modules, refusals } = await loadModules({ installedCircleIr: circleIr });
    // The import happens first, so `installed` is a fact about what actually
    // loaded rather than a guess from whether a specifier might resolve.
    const enablement = enablementForProcess({ installed: modules.length > 0 });
    return { modules, refusals, enablement, circleIr };
  })();
  return discovery;
}

/** Drop the discovery memo. For tests; nothing in the server calls this. */
export function resetDiscoveryForTests(): void {
  discovery = undefined;
}

/**
 * The server a host should build: floor plus whatever optional modules this
 * install has, with enablement computed once.
 */
export async function createServer(
  opts: Omit<BuildServerOptions, 'modules' | 'enablement'> = {},
): Promise<{ server: McpServer; discovery: Discovery }> {
  const found = await discoverModules();
  const server = buildServer({
    ...opts,
    modules: found.modules,
    enablement: found.enablement,
  });
  return { server, discovery: found };
}
