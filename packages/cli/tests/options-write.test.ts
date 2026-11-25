/**
 * `writeStdout` / `exitAfterFlush` flush behaviour (#1001): stdout must drain
 * before exit when the CLI writes a large pipe-bound payload.
 */
import { test, expect, afterAll } from 'bun:test';
import { join } from 'path';
import { writeStdout, exitAfterFlush } from '../src/utils/options';

const OPTIONS = join(import.meta.dir, '..', 'src', 'utils', 'options.ts');

async function runChild(script: string): Promise<{ code: number | null; stdout: string }> {
  const proc = Bun.spawn(['bun', '-e', script], { stdout: 'pipe', stderr: 'pipe' });
  const stdout = await new Response(proc.stdout).text();
  return { code: await proc.exited, stdout };
}

test('writeStdout registers once and prints to stdout', () => {
  const lines: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string | Uint8Array, ...args: unknown[]) => {
    lines.push(String(chunk));
    return orig(chunk, ...(args as Parameters<typeof orig>));
  }) as typeof process.stdout.write;
  try {
    writeStdout('line-one\n');
    writeStdout('line-two\n');
  } finally {
    process.stdout.write = orig;
  }
  expect(lines.join('')).toContain('line-one');
  expect(lines.join('')).toContain('line-two');
});

test('exitAfterFlush waits for stdout before exiting', async () => {
  const r = await runChild(`
    const { writeStdout, exitAfterFlush } = await import(${JSON.stringify(OPTIONS)});
    writeStdout('payload\\n');
    await exitAfterFlush(0);
  `);
  expect(r.code).toBe(0);
  expect(r.stdout).toBe('payload\n');
}, 10_000);

test('exitAfterFlush sets exit code after the stdout queue drains', async () => {
  let exited: number | undefined;
  const origExit = process.exit;
  const origExitCode = process.exitCode;
  process.exit = ((code?: number) => {
    exited = code;
  }) as typeof process.exit;
  try {
    writeStdout('queued\n');
    void exitAfterFlush(9);
    await new Promise((r) => setTimeout(r, 100));
    expect(exited).toBe(9);
    expect(process.exitCode).toBe(9);
  } finally {
    process.exit = origExit;
    // `bun test --coverage` exits with process.exitCode when the suite finishes.
    process.exitCode = origExitCode ?? 0;
  }
});

afterAll(() => {
  process.exitCode = 0;
});

test('writeStdout hooks drain when the kernel buffer is full', async () => {
  const origWrite = process.stdout.write.bind(process.stdout);
  let hookedDrain = false;
  process.stdout.write = ((chunk: string | Uint8Array, encodingOrCb?: BufferEncoding | ((err?: Error) => void), cb?: (err?: Error) => void) => {
    const callback = typeof encodingOrCb === 'function' ? encodingOrCb : cb;
    setTimeout(() => {
      hookedDrain = true;
      origWrite(chunk, callback as (err?: Error) => void);
    }, 0);
    return false;
  }) as typeof process.stdout.write;
  const origOnce = process.stdout.once.bind(process.stdout);
  process.stdout.once = ((event: string, listener: () => void) => {
    if (event === 'drain') setTimeout(listener, 5);
    return origOnce(event, listener);
  }) as typeof process.stdout.once;
  try {
    writeStdout('backpressure\n');
    await new Promise((r) => setTimeout(r, 50));
    expect(hookedDrain).toBe(true);
  } finally {
    process.stdout.write = origWrite;
    process.stdout.once = origOnce;
  }
});