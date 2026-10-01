/**
 * The library entry for `@cognium/mcp-server`.
 *
 * Side-effect free by design: importing this package builds nothing, reads
 * nothing and connects nothing. A host that wants a server calls
 * `createServer()` (floor plus whatever optional modules are installed) or
 * `buildServer()` (exactly what it passes in). The stdio binary is `bin.ts`.
 */

export {
  buildServer,
  createServer,
  discoverModules,
  resetDiscoveryForTests,
  SERVER_NAME,
  SERVER_VERSION,
  type BuildServerOptions,
  type Discovery,
} from './server.js';

export { startupLines } from './startup.js';

export {
  loadModules,
  moduleSpecifiers,
  circleIrVersion,
  checkCircleIrRange,
  majorMinor,
  isToolModule,
  DEFAULT_MODULE_SPECIFIERS,
  ENV_MODULES,
  type ToolModule,
  type ModuleRefusal,
  type LoadModulesOptions,
  type LoadModulesResult,
} from './modules.js';

export {
  computeEnablement,
  enablementForProcess,
  resetEnablementForTests,
  floorEnablement,
  configDir,
  ENV_ENDPOINT,
  ENV_LICENSE,
  ENV_LICENSE_PUBKEY,
  ENV_CONFIG_DIR,
  type Enablement,
  type LicenceState,
} from './enablement.js';

export {
  verifyLicence,
  encodeLicence,
  parsePublicKeyEnv,
  TOKEN_PREFIX,
  BUILTIN_PUBLIC_KEYS,
  ANY_KID,
  type LicencePayload,
  type LicenceStatus,
  type LicenceVerdict,
  type VerifyOptions,
} from './licence.js';

export { canonicalise, canonicalBytes, JcsError } from './jcs.js';

export { ProjectCache, type ProjectScanOptions } from './cache.js';
export { type ToolContext, type ToolResult } from './tools/types.js';
