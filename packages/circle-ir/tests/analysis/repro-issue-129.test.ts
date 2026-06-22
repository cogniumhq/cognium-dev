/**
 * Repro for issue #129 — CWE-78 receiver-class allowlist (Sprint 34 / 3.86.0).
 *
 * `configs/sinks/command.yaml` ships unscoped catch-all sinks for `exec`,
 * `executeCommand`, `runCommand`, `system`, `shell`, `Process`, etc.
 * These match ANY receiver class that exposes the method name, including
 * `redis/jedis`'s `UnifiedJedis.executeCommand` (RESP protocol over TCP
 * — NOT shell). On Java OSS top-25 (3.85.1), this produced 1,680 of
 * 1,968 high `command_injection` findings (85.4% FP rate).
 *
 * 3.86.0 adds `CWE_78_RECEIVER_ALLOWLIST` in
 * `src/analysis/taint-matcher.ts:findSinks()` covering the framework-
 * shipped OS-command APIs (Runtime, ProcessBuilder, Process, CommandLine,
 * DefaultExecutor, Executor, Exec, Launcher, ProcStarter, ProcessExecutor,
 * RuntimeUtil). Receivers statically resolved to a non-allowlist class
 * are suppressed; unresolved receivers (typical for JS / Python / Go
 * module-binding calls) fall through to preserve recall.
 */

import { describe, it, expect } from 'vitest';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import type { CallInfo } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCall(opts: {
  method: string;
  receiver: string | null;
  receiver_type?: string | null;
  is_constructor?: boolean;
  args?: Array<{ expression: string; variable?: string; literal?: string | null }>;
  line?: number;
}): CallInfo {
  return {
    method_name: opts.method,
    receiver: opts.receiver,
    receiver_type: opts.receiver_type ?? null,
    is_constructor: opts.is_constructor ?? false,
    arguments: (opts.args ?? []).map((a, i) => ({
      position: i,
      expression: a.expression,
      variable: a.variable ?? null,
      literal: a.literal ?? null,
    })),
    location: { line: opts.line ?? 10, column: 0 },
    in_method: 'testMethod',
  };
}

const cmdSinks = (calls: CallInfo[]) =>
  analyzeTaint(calls, []).sinks.filter((s) => s.type === 'command_injection');

// ---------------------------------------------------------------------------
// Negative locks — non-OS receivers must NOT fire command_injection
// ---------------------------------------------------------------------------

describe('Issue #129 — CWE-78 receiver-class allowlist (negative locks)', () => {
  it('jedis_executeCommand — Jedis receiver suppressed', () => {
    // jedis.executeCommand(userCmd) — RESP over TCP, not shell.
    // receiver_type = Jedis ∉ allowlist → 0 command_injection sinks.
    const calls = [
      makeCall({
        method: 'executeCommand',
        receiver: 'jedis',
        receiver_type: 'Jedis',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls)).toHaveLength(0);
  });

  it('unified_jedis_executeCommand — UnifiedJedis receiver suppressed', () => {
    const calls = [
      makeCall({
        method: 'executeCommand',
        receiver: 'uj',
        receiver_type: 'UnifiedJedis',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls)).toHaveLength(0);
  });

  it('arbitrary_class_executeCommand — homegrown service receiver suppressed', () => {
    const calls = [
      makeCall({
        method: 'executeCommand',
        receiver: 'svc',
        receiver_type: 'MyService',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls)).toHaveLength(0);
  });

  it('httpentity_post — non-allowlist class with sink-like method suppressed', () => {
    // Sentinel-style mislabel: HttpEntity.post() is HTTP, not command.
    const calls = [
      makeCall({
        method: 'post',
        receiver: 'he',
        receiver_type: 'HttpEntity',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Recall locks — real OS-command APIs must STILL fire command_injection
// ---------------------------------------------------------------------------

describe('Issue #129 — CWE-78 receiver-class allowlist (recall locks)', () => {
  it('runtime_exec — Runtime receiver in allowlist fires', () => {
    const calls = [
      makeCall({
        method: 'exec',
        receiver: 'r',
        receiver_type: 'Runtime',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('process_builder_constructor — new ProcessBuilder(userCmd) fires', () => {
    // For constructors, method_name === class being constructed.
    // is_constructor branch checks method_name against allowlist.
    const calls = [
      makeCall({
        method: 'ProcessBuilder',
        receiver: null,
        is_constructor: true,
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('process_builder_command — pb.command(userCmd) fires (allowlist class)', () => {
    const calls = [
      makeCall({
        method: 'command',
        receiver: 'pb',
        receiver_type: 'ProcessBuilder',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('default_executor_execute — DefaultExecutor.execute(userCmd) fires', () => {
    const calls = [
      makeCall({
        method: 'execute',
        receiver: 'de',
        receiver_type: 'DefaultExecutor',
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    expect(cmdSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('nodejs_unresolved_exec — exec() with null receiver_type falls through', () => {
    // child_process.exec destructured to a bare `exec` call. receiver_type
    // is null (cannot statically resolve module binding). Allowlist gate
    // falls through to preserve recall.
    const calls = [
      makeCall({
        method: 'exec',
        receiver: null,
        receiver_type: null,
        args: [{ expression: 'userInput', variable: 'userInput' }],
      }),
    ];
    expect(cmdSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('python_subprocess_run — receiver_type null falls through', () => {
    const calls = [
      makeCall({
        method: 'run',
        receiver: 'subprocess',
        receiver_type: null,
        args: [{ expression: 'userCmd', variable: 'userCmd' }],
      }),
    ];
    // subprocess.run pattern matched as command_injection.
    expect(cmdSinks(calls).length).toBeGreaterThanOrEqual(1);
  });
});
