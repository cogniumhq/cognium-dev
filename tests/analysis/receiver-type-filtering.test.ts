/**
 * Tests for receiver-type-aware sink resolution (P0 FP precision).
 *
 * Verifies that classless sink patterns do NOT match known-safe receivers,
 * while still matching genuine dangerous calls.
 */

import { describe, it, expect } from 'vitest';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import type { CallInfo, TypeInfo } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCall(
  method: string,
  receiver: string | null,
  args: Array<{ expression: string; variable?: string; literal?: string | null }> = [],
  line = 10,
): CallInfo {
  return {
    method_name: method,
    receiver,
    arguments: args.map((a, i) => ({
      position: i,
      expression: a.expression,
      variable: a.variable ?? null,
      literal: a.literal ?? null,
    })),
    location: { line, column: 0 },
    in_method: 'testMethod',
  };
}

// ---------------------------------------------------------------------------
// P0-a: query() receiver filtering
// ---------------------------------------------------------------------------

describe('query() receiver-type filtering', () => {
  it('should NOT flag UriComponentsBuilder.query() as sql_injection', () => {
    const calls = [makeCall('query', 'UriComponentsBuilder', [{ expression: 'param' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks).toHaveLength(0);
  });

  it('should NOT flag urlBuilder.query() as sql_injection', () => {
    const calls = [makeCall('query', 'urlBuilder', [{ expression: 'q' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks).toHaveLength(0);
  });

  it('should NOT flag request.query() as sql_injection', () => {
    const calls = [makeCall('query', 'request', [{ expression: 'param' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks).toHaveLength(0);
  });

  it('should NOT flag document.query() as sql_injection', () => {
    const calls = [makeCall('query', 'document', [{ expression: 'selector' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks).toHaveLength(0);
  });

  it('should NOT flag graphql.query() as sql_injection', () => {
    const calls = [makeCall('query', 'graphql', [{ expression: 'gql' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks).toHaveLength(0);
  });

  it('should still flag db.query(tainted) as sql_injection', () => {
    const calls = [makeCall('query', 'db', [{ expression: 'userInput', variable: 'userInput' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
  });

  it('should still flag connection.query(tainted) as sql_injection', () => {
    const calls = [makeCall('query', 'connection', [{ expression: 'sql', variable: 'sql' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
  });

  it('should still flag pool.query(tainted) as sql_injection', () => {
    const calls = [makeCall('query', 'pool', [{ expression: 'sql', variable: 'sql' }])];
    const result = analyzeTaint(calls, []);
    const sqlSinks = result.sinks.filter(s => s.type === 'sql_injection');
    expect(sqlSinks.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// P0-b: authenticate() receiver filtering
// ---------------------------------------------------------------------------

describe('authenticate() receiver-type filtering', () => {
  it('should NOT flag auth.authenticate(token) as code_injection', () => {
    const calls = [makeCall('authenticate', 'auth', [{ expression: 'token' }])];
    const result = analyzeTaint(calls, []);
    const codeSinks = result.sinks.filter(s => s.type === 'code_injection');
    expect(codeSinks).toHaveLength(0);
  });

  it('should NOT flag authManager.authenticate(credentials) as code_injection', () => {
    const calls = [makeCall('authenticate', 'authManager', [{ expression: 'creds' }])];
    const result = analyzeTaint(calls, []);
    const codeSinks = result.sinks.filter(s => s.type === 'code_injection');
    expect(codeSinks).toHaveLength(0);
  });

  it('should NOT flag securityContext.authenticate(token) as code_injection', () => {
    const calls = [makeCall('authenticate', 'securityContext', [{ expression: 'token' }])];
    const result = analyzeTaint(calls, []);
    const codeSinks = result.sinks.filter(s => s.type === 'code_injection');
    expect(codeSinks).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// P0-c: add() receiver filtering
// ---------------------------------------------------------------------------

describe('add() receiver-type filtering', () => {
  it('should NOT flag list.add(item) as command_injection', () => {
    const calls = [makeCall('add', 'list', [{ expression: 'item' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should NOT flag registry.add(bean) as command_injection', () => {
    const calls = [makeCall('add', 'registry', [{ expression: 'bean' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should NOT flag builders.add(component) as command_injection', () => {
    const calls = [makeCall('add', 'builders', [{ expression: 'component' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should NOT flag handlers.add(handler) as command_injection', () => {
    const calls = [makeCall('add', 'handlers', [{ expression: 'h' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// P0-d: fromXML/unmarshal sink-type-aware filtering
// ---------------------------------------------------------------------------

describe('fromXML/unmarshal sink-type-aware filtering', () => {
  it('should NOT flag xstream.fromXML() as command_injection', () => {
    const calls = [makeCall('fromXML', 'xstream', [{ expression: 'input' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should still flag xstream.fromXML() as deserialization', () => {
    const calls = [makeCall('fromXML', 'xstream', [{ expression: 'input' }])];
    const result = analyzeTaint(calls, []);
    const deserSinks = result.sinks.filter(s => s.type === 'deserialization');
    expect(deserSinks.length).toBeGreaterThanOrEqual(1);
    expect(deserSinks[0].cwe).toBe('CWE-502');
  });

  it('should NOT flag XSTREAM2.fromXML() as command_injection', () => {
    const calls = [makeCall('fromXML', 'XSTREAM2', [{ expression: 'xmlData' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should still flag XSTREAM2.fromXML() as deserialization', () => {
    const calls = [makeCall('fromXML', 'XSTREAM2', [{ expression: 'xmlData' }])];
    const result = analyzeTaint(calls, []);
    const deserSinks = result.sinks.filter(s => s.type === 'deserialization');
    expect(deserSinks.length).toBeGreaterThanOrEqual(1);
  });

  it('should NOT flag unmarshaller.unmarshal() as command_injection', () => {
    const calls = [makeCall('unmarshal', 'unmarshaller', [{ expression: 'source' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// P0-e: exec() safe-receiver (existing behavior, regression check)
// ---------------------------------------------------------------------------

describe('exec() safe-receiver filtering (regression)', () => {
  it('should NOT flag regex.exec(str) as command_injection', () => {
    const calls = [makeCall('exec', 'regex', [{ expression: 'str' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should NOT flag pattern.exec(input) as command_injection', () => {
    const calls = [makeCall('exec', 'pattern', [{ expression: 'input' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks).toHaveLength(0);
  });

  it('should still flag runtime.exec(cmd) as command_injection', () => {
    const calls = [makeCall('exec', 'runtime', [{ expression: 'cmd', variable: 'cmd' }])];
    const result = analyzeTaint(calls, []);
    const cmdSinks = result.sinks.filter(s => s.type === 'command_injection');
    expect(cmdSinks.length).toBeGreaterThanOrEqual(1);
  });
});
