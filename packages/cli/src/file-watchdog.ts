/**
 * S3: a hard bound on one file's analysis time under `--file-timeout-ms`.
 *
 * circle-ir checks the per-file limit between phases, so a single synchronous
 * step (a regular expression that backtracks, for one) can run far past it and
 * hold the scan for hours. Nothing on the main thread can interrupt that step,
 * so a small worker thread watches it from outside: the main thread writes a
 * heartbeat into shared memory every 100 ms, and circle-ir's `onFileStart` /
 * `onFileEnd` say which file is in flight. When a file is in flight and the
 * heartbeat is older than the bound, the worker names the file on stderr and
 * ends the process with SIGTERM (exit status 143). The bound is twice the file
 * limit, and at least the limit plus one second, so a file the cooperative
 * check would stop anyway is never cut off here.
 */

import { Worker } from 'worker_threads';

const NAME_BYTES = 4096;

/** The bound after which the watchdog stops the scan, for a given `--file-timeout-ms`. */
export function watchdogBoundMs(fileTimeoutMs: number): number {
  return Math.max(2 * fileTimeoutMs, fileTimeoutMs + 1000);
}

const WORKER_SOURCE = `
const { workerData } = require('worker_threads');
const { writeSync } = require('fs');
const clock = new Float64Array(workerData.sab, 0, 2);
const name = new Uint8Array(workerData.sab, 16, workerData.nameBytes);
const tick = () => {
  if (clock[1] > 0 && Date.now() - clock[0] > workerData.boundMs) {
    const end = name.indexOf(0);
    const file = Buffer.from(name.subarray(0, end < 0 ? name.length : end)).toString('utf8');
    writeSync(2, 'Error: analysis of ' + file + ' ran past --file-timeout-ms ' + workerData.limitMs
      + ' ms in a step that cannot be interrupted; stopping the scan after ' + workerData.boundMs + ' ms\\n');
    process.kill(process.pid, 'SIGTERM');
    return;
  }
  setTimeout(tick, 100);
};
tick();
`;

export interface FileWatchdog {
  /** circle-ir `onFileStart` / `onFileEnd`: pass both to `analyze()` / `analyzeProject()`. */
  onFileStart: (filePath: string) => void;
  onFileEnd: (filePath: string) => void;
  stop: () => void;
}

/** Start the watchdog for `--file-timeout-ms <fileTimeoutMs>`; `null` when the limit is off. */
export function startFileWatchdog(fileTimeoutMs: number): FileWatchdog | null {
  if (!(fileTimeoutMs > 0)) return null;
  const sab = new SharedArrayBuffer(16 + NAME_BYTES);
  // [0] last heartbeat (ms), [1] files in flight.
  const clock = new Float64Array(sab, 0, 2);
  const name = new Uint8Array(sab, 16, NAME_BYTES);
  const inFlight = new Map<string, number>();
  const encoder = new TextEncoder();
  const show = (): void => {
    const files = [...inFlight.keys()];
    const bytes = encoder.encode(files.length === 1 ? files[0] : `one of: ${files.join(', ')}`);
    name.fill(0);
    name.set(bytes.subarray(0, NAME_BYTES - 1));
    clock[1] = files.length;
  };
  clock[0] = Date.now();
  const beat = setInterval(() => { clock[0] = Date.now(); }, 100);
  beat.unref();
  const worker = new Worker(WORKER_SOURCE, {
    eval: true,
    workerData: { sab, nameBytes: NAME_BYTES, limitMs: fileTimeoutMs, boundMs: watchdogBoundMs(fileTimeoutMs) },
  });
  worker.unref();
  return {
    onFileStart: (filePath) => {
      inFlight.set(filePath, (inFlight.get(filePath) ?? 0) + 1);
      clock[0] = Date.now();
      show();
    },
    onFileEnd: (filePath) => {
      const n = (inFlight.get(filePath) ?? 1) - 1;
      if (n > 0) inFlight.set(filePath, n); else inFlight.delete(filePath);
      show();
    },
    stop: () => {
      clearInterval(beat);
      clock[1] = 0;
      void worker.terminate();
    },
  };
}
