/**
 * Discovery and `createServer` — the process-level path the HTTP host and the
 * bin both take, exercised for real rather than through injected hooks.
 *
 * The environment is pinned to "nothing installed, no config dir" so the test
 * cannot pick up a token or a module from the machine it runs on.
 */

import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { discoverModules, createServer, resetDiscoveryForTests } from '../src/server.js';
import { resetEnablementForTests, ENV_CONFIG_DIR } from '../src/enablement.js';
import { loadModules, ENV_MODULES } from '../src/modules.js';

const original = {
  modules: process.env[ENV_MODULES],
  configDir: process.env[ENV_CONFIG_DIR],
};

beforeEach(() => {
  resetDiscoveryForTests();
  resetEnablementForTests();
  process.env[ENV_MODULES] = 'none';
  process.env[ENV_CONFIG_DIR] = '/nonexistent/cognium-discovery-test';
});

afterAll(() => {
  if (original.modules === undefined) delete process.env[ENV_MODULES];
  else process.env[ENV_MODULES] = original.modules;
  if (original.configDir === undefined) delete process.env[ENV_CONFIG_DIR];
  else process.env[ENV_CONFIG_DIR] = original.configDir;
  resetDiscoveryForTests();
  resetEnablementForTests();
});

describe('discoverModules', () => {
  it('reports the floor when no module is configured', async () => {
    const found = await discoverModules();
    expect(found.modules).toEqual([]);
    expect(found.refusals).toEqual([]);
    expect(found.enablement.state).toBe('floor');
    expect(found.circleIr).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('resolves once per process, so concurrent callers share one resolution', async () => {
    // Memoized on the promise, not the result: two request-scoped servers
    // starting at the same moment must not both import the module.
    const [a, b] = await Promise.all([discoverModules(), discoverModules()]);
    expect(a).toBe(b);
    expect(await discoverModules()).toBe(a);
  });

  it('recomputes after a reset', async () => {
    const first = await discoverModules();
    resetDiscoveryForTests();
    resetEnablementForTests();
    expect(await discoverModules()).not.toBe(first);
  });
});

describe('createServer', () => {
  it('returns a floor server and the discovery behind it', async () => {
    const { server, discovery } = await createServer();
    const names = Object.keys(
      (server as unknown as { _registeredTools?: Record<string, unknown> })._registeredTools ?? {},
    );
    expect(names).toHaveLength(11);
    expect(discovery.enablement.state).toBe('floor');
  });

  it('passes build options through', async () => {
    const { server } = await createServer({ cacheCapacity: 1 });
    expect(server).toBeTruthy();
  });
});

describe('the real import path', () => {
  it('treats a specifier that is genuinely not installed as the floor, not an error', async () => {
    // No importer hook here: this goes through the actual dynamic `import()`,
    // which is the line the injected-importer tests cannot reach.
    const result = await loadModules({
      specifiers: ['@cognium/definitely-not-a-real-module/mcp'],
      installedCircleIr: '4.9.29',
    });
    expect(result.modules).toEqual([]);
    expect(result.refusals).toEqual([]);
  });

  it('reads the specifier list from the environment when none is passed', async () => {
    const result = await loadModules({ installedCircleIr: '4.9.29' });
    expect(result.modules).toEqual([]);
  });
});
