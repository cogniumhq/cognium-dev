/**
 * The three-state matrix — `spec.md` §7's gating test, server side.
 *
 * Four rows, because the extended state has two shapes:
 *
 *   floor                    the server alone
 *   extended, no endpoint    module loaded, no endpoint configured
 *   extended, with endpoint  module loaded, endpoint configured
 *   commercial               the above plus a token that verifies
 *
 * Each row asserts the licence state, the exact tool list, and the startup
 * lines. The tool list is the API (`spec.md` §7 rule 1), so it is pinned
 * here by name: a tool that appears or disappears without a version decision
 * fails this test, which is the point.
 */

import { describe, it, expect } from 'vitest';
import { buildServer, SERVER_NAME, SERVER_VERSION, type Discovery } from '../src/server.js';
import { computeEnablement, ENV_ENDPOINT, ENV_LICENSE, ENV_LICENSE_PUBKEY, ENV_CONFIG_DIR } from '../src/enablement.js';
import { startupLines } from '../src/startup.js';
import { testKey, mint } from './fixtures/licence.js';
import { fakeModule, DETERMINISTIC_TOOL, ENDPOINT_BACKED_TOOL } from './fixtures/fake-module.js';

const FLOOR_TOOLS = [
  'scan',
  'explain_finding',
  'taint_paths',
  'list_entry_points',
  'check_sanitizer',
  'describe_sink',
  'describe_source',
  'attack_surface_summary',
  'list_reachable_sinks',
  'find_similar',
  'refresh',
];

function toolNames(server: ReturnType<typeof buildServer>): string[] {
  const registered = (server as unknown as { _registeredTools?: Record<string, unknown> })._registeredTools ?? {};
  return Object.keys(registered).sort();
}

/** A token that verifies, plus the `kid=key` the verifier needs for it. */
function commercialToken(expiry = '2099-01-01'): { token: string; publicKey: string } {
  const key = testKey('matrix-1');
  return { token: mint(key, { expiry }), publicKey: `${key.kid}=${key.publicKey}` };
}

/**
 * A config dir that does not exist, so a token file on the developer's own
 * machine can never leak into a test's expectations.
 */
const NO_CONFIG_DIR = { [ENV_CONFIG_DIR]: '/nonexistent/cognium-test-config' };

function discoveryFor(env: NodeJS.ProcessEnv, installed: boolean): Discovery {
  const modules = installed ? [fakeModule()] : [];
  const enablement = computeEnablement({ installed, env });
  return { modules, refusals: [], enablement, circleIr: '4.9.29' };
}

describe('three-state matrix', () => {
  it('state 0 — floor: the 11 deterministic tools, nothing else', () => {
    const found = discoveryFor({ ...NO_CONFIG_DIR }, false);
    expect(found.enablement.state).toBe('floor');
    expect(found.enablement.installed).toBe(false);
    expect(found.enablement.licence.status).toBe('absent');

    const server = buildServer({ modules: found.modules, enablement: found.enablement });
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS].sort());

    expect(startupLines(found)).toEqual([
      `[${SERVER_NAME}] ${SERVER_VERSION} · circle-ir 4.9.29 · licence floor · modules none`,
    ]);
  });

  it('state 1 — extended, no endpoint: the module\'s always-available tools only', () => {
    const found = discoveryFor({ ...NO_CONFIG_DIR }, true);
    expect(found.enablement.state).toBe('extended');
    expect(found.enablement.endpoint).toBeUndefined();

    const server = buildServer({ modules: found.modules, enablement: found.enablement });
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS, DETERMINISTIC_TOOL].sort());
    expect(toolNames(server)).not.toContain(ENDPOINT_BACKED_TOOL);

    const lines = startupLines(found);
    expect(lines[0]).toContain('licence extended');
    expect(lines[0]).toContain('fixture/mcp@1.0.0 (PolyForm-Noncommercial-1.0.0)');
    expect(lines[0]).not.toContain('endpoint configured');
    // The terms require one notice, and exactly one.
    expect(lines.filter((l) => l.includes('non-commercial'))).toHaveLength(1);
  });

  it('state 1 — extended, with endpoint: the endpoint-backed tool is listed too', () => {
    const found = discoveryFor({ ...NO_CONFIG_DIR, [ENV_ENDPOINT]: 'https://endpoint.example' }, true);
    expect(found.enablement.state).toBe('extended');
    expect(found.enablement.endpoint).toBe('https://endpoint.example');

    const server = buildServer({ modules: found.modules, enablement: found.enablement });
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS, DETERMINISTIC_TOOL, ENDPOINT_BACKED_TOOL].sort());

    const lines = startupLines(found);
    expect(lines[0]).toContain('endpoint configured');
    // Whether an endpoint is configured is reported; its value never is.
    expect(lines.join('\n')).not.toContain('endpoint.example');
  });

  it('state 2 — commercial: a token that verifies, and the same tool list as extended-with-endpoint', () => {
    const { token, publicKey } = commercialToken();
    const found = discoveryFor(
      {
        ...NO_CONFIG_DIR,
        [ENV_ENDPOINT]: 'https://endpoint.example',
        [ENV_LICENSE]: token,
        [ENV_LICENSE_PUBKEY]: publicKey,
      },
      true,
    );
    expect(found.enablement.state).toBe('commercial');
    expect(found.enablement.licence.status).toBe('valid');
    expect(found.enablement.licence.payload?.org).toBe('Example Ltd');

    const server = buildServer({ modules: found.modules, enablement: found.enablement });
    // The licence changes the terms, not the tools: commercial lists exactly
    // what extended-with-endpoint lists. No feature is gated on the token.
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS, DETERMINISTIC_TOOL, ENDPOINT_BACKED_TOOL].sort());

    const lines = startupLines(found);
    expect(lines[0]).toContain('licence commercial');
    // No non-commercial notice once the token verifies.
    expect(lines.join('\n')).not.toContain('non-commercial');
    // And never the token itself.
    expect(lines.join('\n')).not.toContain(token);
  });
});

describe('what the licence does not do', () => {
  it('an expired token serves as extended, not as floor, and says so once', () => {
    const { token, publicKey } = commercialToken('2020-01-01');
    const found = discoveryFor(
      { ...NO_CONFIG_DIR, [ENV_LICENSE]: token, [ENV_LICENSE_PUBKEY]: publicKey },
      true,
    );
    expect(found.enablement.state).toBe('extended');
    expect(found.enablement.licence.status).toBe('expired');

    const server = buildServer({ modules: found.modules, enablement: found.enablement });
    // Expiry removes commercial rights. It does not remove code the user has.
    expect(toolNames(server)).toContain(DETERMINISTIC_TOOL);

    const lines = startupLines(found);
    expect(lines.filter((l) => l.includes('expired'))).toHaveLength(1);
  });

  it('a token that verifies with nothing installed is not commercial', () => {
    const { token, publicKey } = commercialToken();
    const found = discoveryFor(
      { ...NO_CONFIG_DIR, [ENV_LICENSE]: token, [ENV_LICENSE_PUBKEY]: publicKey },
      false,
    );
    // Commercial is extended *plus* a token. With nothing extra installed
    // there is nothing extra to licence.
    expect(found.enablement.state).toBe('floor');
    expect(found.enablement.licence.status).toBe('valid');
  });

  it('a bad token never costs the user the floor', () => {
    const found = discoveryFor({ ...NO_CONFIG_DIR, [ENV_LICENSE]: 'garbage' }, false);
    expect(found.enablement.state).toBe('floor');
    expect(found.enablement.licence.status).toBe('malformed');

    const server = buildServer({ modules: found.modules, enablement: found.enablement });
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS].sort());
  });
});

describe('the floor survives a bad module', () => {
  it('keeps serving all 11 tools when a module throws while registering', () => {
    const found = discoveryFor({ ...NO_CONFIG_DIR }, true);
    const server = buildServer({
      modules: [fakeModule({ throwOnRegister: true })],
      enablement: found.enablement,
    });
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS].sort());
  });

  it('reports a refusal on the startup lines and says the floor is still served', () => {
    const found: Discovery = {
      ...discoveryFor({ ...NO_CONFIG_DIR }, false),
      refusals: [{ specifier: 'circle-ir-ai/mcp', reason: 'was built against circle-ir 4.8, but circle-ir 4.9.29 is installed' }],
    };
    const lines = startupLines(found);
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('refused circle-ir-ai/mcp');
    expect(lines[1]).toContain('Serving the deterministic floor only');
  });

  it('does not claim floor-only when another module did load', () => {
    const found: Discovery = {
      ...discoveryFor({ ...NO_CONFIG_DIR }, true),
      refusals: [{ specifier: 'other/mcp', reason: 'could not be loaded' }],
    };
    const lines = startupLines(found);
    const refusal = lines.find((l) => l.includes('refused other/mcp'));
    // The first line already names the loaded module and the extended state;
    // the refusal must not contradict it.
    expect(lines[0]).toContain('licence extended');
    expect(refusal).toContain('Still serving the deterministic floor and fixture/mcp');
    expect(refusal).not.toContain('floor only');
  });
});

describe('server identity', () => {
  it('comes from the manifest, so every door reports the same pair', () => {
    expect(SERVER_NAME).toBe('@cognium/mcp-server');
    // The literal this replaced had drifted to 0.1.0 while the package was
    // at 0.1.21. Clients read the version out of the `initialize` result, so
    // it has to track the manifest and not a hand-edited string.
    expect(SERVER_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('is what the built server announces', () => {
    const server = buildServer();
    const info = (server as unknown as { server?: { _serverInfo?: { name: string; version: string } } }).server?._serverInfo;
    if (info) {
      expect(info.name).toBe(SERVER_NAME);
      expect(info.version).toBe(SERVER_VERSION);
    }
  });
});

describe('a server built with no options', () => {
  it('is the floor, so a host that passes nothing cannot accidentally get more', () => {
    const server = buildServer();
    expect(toolNames(server)).toEqual([...FLOOR_TOOLS].sort());
  });
});
