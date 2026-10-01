/**
 * Optional tool modules — the one new seam.
 *
 * A module is a package that registers extra tools on this server over its
 * own library's functions. The server loads it, hands it the shared cache and
 * the computed enablement, and then stays out of the way: what a finding is,
 * and which of its own tools a module registers in a given state, are the
 * module's decisions, never the server's.
 *
 * The loader's contract is that **the server comes up either way**. A module
 * that is absent, broken, built against the wrong engine, or wrong in shape
 * is refused with one line on stderr, and the deterministic floor serves as
 * normal. There is no state in which a bad module takes the server down.
 */

import { createRequire } from 'node:module';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolContext } from './tools/types.js';

export interface ToolModule {
  /** Stable identifier, used in the startup line and refusal messages. */
  readonly id: string;
  /** The module's own version. */
  readonly version: string;
  /** SPDX-style licence identifier of the module's terms. */
  readonly licence: string;
  /**
   * The `circle-ir` the module was built against, as `major.minor` (a full
   * `major.minor.patch` is accepted and only its `major.minor` is compared).
   */
  readonly circleIrRange: string;
  /** Register the module's tools. Called once, synchronously. */
  register(server: McpServer, ctx: ToolContext): void;
}

export interface ModuleRefusal {
  /** The specifier that was tried, which may be all we know. */
  readonly specifier: string;
  /** One line, safe to print. */
  readonly reason: string;
}

/**
 * The specifier the server looks for by default. It is data, not a
 * dependency: nothing in this package's manifest requires it, and if it does
 * not resolve the server simply runs at the floor.
 */
export const DEFAULT_MODULE_SPECIFIERS: readonly string[] = ['circle-ir-ai/mcp'];

/** Override the specifier list. `none` or an empty value loads nothing. */
export const ENV_MODULES = 'COGNIUM_MCP_MODULES';

export function moduleSpecifiers(env: NodeJS.ProcessEnv = process.env): readonly string[] {
  const raw = env[ENV_MODULES];
  if (raw === undefined) return DEFAULT_MODULE_SPECIFIERS;
  const trimmed = raw.trim();
  if (trimmed === '' || trimmed === 'none') return [];
  return trimmed.split(',').map((s) => s.trim()).filter((s) => s !== '');
}

const require_ = createRequire(import.meta.url);

/** The `circle-ir` actually installed next to this server. */
export function circleIrVersion(): string {
  try {
    return (require_('circle-ir/package.json') as { version: string }).version;
  } catch {
    // circle-ir is a hard dependency, so this should be unreachable; if the
    // install is broken enough to make it reachable, say so rather than
    // claiming a version.
    return 'unknown';
  }
}

/** `4.9.29` → `4.9`; `4.9` → `4.9`; anything else → null. */
export function majorMinor(version: string): string | null {
  const m = /^(\d+)\.(\d+)(?:\.|$)/.exec(version.trim());
  return m ? `${m[1]}.${m[2]}` : null;
}

export function isToolModule(value: unknown): value is ToolModule {
  if (typeof value !== 'object' || value === null) return false;
  const m = value as Record<string, unknown>;
  return (
    typeof m.id === 'string' &&
    typeof m.version === 'string' &&
    typeof m.licence === 'string' &&
    typeof m.circleIrRange === 'string' &&
    typeof m.register === 'function'
  );
}

/**
 * Decide whether a module may load against the installed engine.
 *
 * The comparison is `major.minor`, which is what the published contract
 * promises. Two consequences worth being explicit about: a patch-level
 * difference is accepted here and is caught instead by the pin check at
 * release time; and a module that declares a range this function cannot
 * parse is refused rather than assumed compatible.
 */
export function checkCircleIrRange(
  declared: string,
  installed: string,
): { ok: true } | { ok: false; reason: string } {
  const want = majorMinor(declared);
  const have = majorMinor(installed);
  if (!want) return { ok: false, reason: `declares an unreadable circle-ir range "${declared}"` };
  if (!have) return { ok: false, reason: `the installed circle-ir version "${installed}" is unreadable` };
  if (want !== have) {
    return {
      ok: false,
      reason: `was built against circle-ir ${want}, but circle-ir ${installed} is installed`,
    };
  }
  return { ok: true };
}

/** Pull a `ToolModule` out of whatever the specifier exported. */
function moduleFrom(imported: unknown): ToolModule | null {
  if (isToolModule(imported)) return imported;
  const ns = imported as Record<string, unknown> | null;
  if (!ns) return null;
  for (const key of ['default', 'toolModule', 'module']) {
    if (isToolModule(ns[key])) return ns[key] as ToolModule;
  }
  return null;
}

export interface LoadModulesResult {
  readonly modules: readonly ToolModule[];
  readonly refusals: readonly ModuleRefusal[];
}

export interface LoadModulesOptions {
  readonly specifiers?: readonly string[];
  /** The installed engine version. Injected by the range tests. */
  readonly installedCircleIr?: string;
  /** Import hook. Injected by tests so no fixture package is needed. */
  readonly importer?: (specifier: string) => Promise<unknown>;
}

/**
 * Try each specifier in order. Never throws: everything that can go wrong
 * comes back as a refusal.
 */
export async function loadModules(opts: LoadModulesOptions = {}): Promise<LoadModulesResult> {
  const specifiers = opts.specifiers ?? moduleSpecifiers();
  const installed = opts.installedCircleIr ?? circleIrVersion();
  const importer = opts.importer ?? ((s: string) => import(/* @vite-ignore */ s));

  const modules: ToolModule[] = [];
  const refusals: ModuleRefusal[] = [];

  for (const specifier of specifiers) {
    let imported: unknown;
    try {
      imported = await importer(specifier);
    } catch (err) {
      const code = (err as { code?: string }).code;
      // Not installed is the ordinary case, not a fault: the floor is a
      // supported way to run, so it is not reported as a refusal.
      if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') continue;
      refusals.push({ specifier, reason: `failed to load: ${(err as Error).message}` });
      continue;
    }

    const mod = moduleFrom(imported);
    if (!mod) {
      refusals.push({ specifier, reason: 'does not export a tool module' });
      continue;
    }

    const range = checkCircleIrRange(mod.circleIrRange, installed);
    if (!range.ok) {
      refusals.push({ specifier, reason: `${mod.id}@${mod.version} ${range.reason}` });
      continue;
    }

    modules.push(mod);
  }

  return { modules, refusals };
}
