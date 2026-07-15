/**
 * Server smoke test — verify `buildServer()` wires without throwing and
 * that the registered tool + resource sets match the MVP spec.
 */

import { describe, it, expect } from 'vitest';
import { buildServer } from '../src/server.js';

const EXPECTED_TOOLS = [
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

const EXPECTED_RESOURCES = [
  'cognium://sast-finding-schema',
  'cognium://sink-catalog',
  'cognium://source-catalog',
  'cognium://sanitizer-catalog',
  'cognium://passes',
];

describe('server assembly', () => {
  it('builds without throwing', () => {
    const server = buildServer();
    expect(server).toBeTruthy();
  });

  it('registers all 11 MVP tools', () => {
    const server = buildServer() as unknown as {
      _registeredTools?: Record<string, unknown>;
      _registeredResources?: Record<string, unknown>;
    };
    // The MCP SDK stores registrations on private fields; both shapes are
    // covered defensively so the test survives minor SDK refactors.
    const toolNames = Object.keys(server._registeredTools ?? {});
    for (const name of EXPECTED_TOOLS) {
      expect(toolNames, `missing tool: ${name}`).toContain(name);
    }
  });

  it('registers all 5 MVP resources', () => {
    const server = buildServer() as unknown as {
      _registeredResources?: Record<string, unknown>;
    };
    const resourceNames = Object.keys(server._registeredResources ?? {});
    for (const name of EXPECTED_RESOURCES) {
      expect(resourceNames, `missing resource: ${name}`).toContain(name);
    }
  });
});
