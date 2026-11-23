/**
 * #1324: a worker_threads pool for the per-file phase of a directory scan.
 *
 * The main thread hands every file to the pool before `analyzeProject` runs,
 * and `analyzeProject` then awaits the pending results one at a time in input
 * order (its `analyzeFile` hook). So the work runs on `size` threads while the
 * merge, and everything after it, sees files in the same order as before.
 *
 * A task's error comes back as `{ name, message, ... }` and is rebuilt on the
 * main thread by `decodeError`, so the caller reports it as it would an error
 * thrown in-process. A worker that dies (it failed to start, crashed, or its
 * result could not be cloned) never decides a task's outcome: its task runs
 * again in-process with `runInProcess`, which is what the scan did before the
 * pool existed. When no worker is left, the remaining tasks run in-process too.
 */

import { Worker, parentPort } from 'worker_threads';
import { availableParallelism } from 'os';
import { AnalysisTimeoutError } from 'circle-ir';

/** Threads to use for `files` files at `--threads <threads>`; `1` means no pool. */
export function scanPoolSize(threads: number, files: number, cpus: number = availableParallelism()): number {
  return Math.max(1, Math.min(threads, cpus, files));
}

/** A task's error as it crosses the thread boundary. */
export interface SerializedTaskError {
  name: string;
  message: string;
  /** Extra fields an error class carries (e.g. `AnalysisTimeoutError`'s `elapsedMs`). */
  fields?: Record<string, unknown>;
}

/** A worker-side error back as the error `analyze()` would have thrown in-process. */
export function decodeScanError(e: SerializedTaskError): Error {
  const f = e.fields ?? {};
  if (e.name === 'AnalysisTimeoutError'
    && typeof f.file === 'string' && typeof f.elapsedMs === 'number' && typeof f.phase === 'string') {
    return new AnalysisTimeoutError(f.file, f.elapsedMs, f.phase);
  }
  const err = new Error(e.message);
  err.name = e.name;
  return err;
}

type WorkerReply<Res> =
  | { id: number; ok: true; value: Res }
  | { id: number; ok: false; error: SerializedTaskError }
  /** The worker could not return this task's result (e.g. it is not cloneable). */
  | { id: number; ok: false; fallback: true };

interface Task<Req, Res> {
  id: number;
  req: Req;
  resolve: (value: Res) => void;
  reject: (error: unknown) => void;
}

export interface ScanPoolOptions<Req, Res> {
  size: number;
  /** Module the workers run; it must call {@link serveScanWorker} when given `workerData`. */
  script: string | URL;
  workerData: unknown;
  /** Runs a task on the main thread when no worker can. */
  runInProcess: (req: Req) => Promise<Res>;
  /** Rebuilds a worker-side error as the error the in-process path would throw. */
  decodeError: (error: SerializedTaskError) => Error;
}

export class ScanPool<Req, Res> {
  private readonly queue: Array<Task<Req, Res>> = [];
  private readonly idle: Worker[] = [];
  private readonly busy = new Map<Worker, Task<Req, Res>>();
  private live = 0;
  private nextId = 0;
  private closed = false;

  constructor(private readonly opts: ScanPoolOptions<Req, Res>) {
    for (let i = 0; i < opts.size; i++) this.spawn();
  }

  /** Queue one task. Results resolve as workers finish, in any order. */
  run(req: Req): Promise<Res> {
    return new Promise<Res>((resolve, reject) => {
      this.queue.push({ id: this.nextId++, req, resolve, reject });
      this.dispatch();
    });
  }

  /** Stop every worker. Tasks not finished yet are rejected (the run is over). */
  close(): void {
    this.closed = true;
    for (const w of [...this.idle, ...this.busy.keys()]) void w.terminate();
    const unfinished = [...this.busy.values(), ...this.queue];
    this.idle.length = 0;
    this.busy.clear();
    this.queue.length = 0;
    this.live = 0;
    for (const task of unfinished) task.reject(new Error('scan pool closed'));
  }

  private spawn(): void {
    let worker: Worker;
    try {
      worker = new Worker(this.opts.script, { workerData: this.opts.workerData });
    } catch {
      return;
    }
    this.live++;
    this.idle.push(worker);
    worker.on('message', (reply: WorkerReply<Res>) => {
      const task = this.busy.get(worker);
      if (!task || task.id !== reply.id) return;
      this.busy.delete(worker);
      this.idle.push(worker);
      if (reply.ok) task.resolve(reply.value);
      else if ('fallback' in reply) this.fallback(task);
      else task.reject(this.opts.decodeError(reply.error));
      this.dispatch();
    });
    const lost = (): void => {
      if (this.closed) return;
      const idleAt = this.idle.indexOf(worker);
      const task = this.busy.get(worker);
      if (idleAt < 0 && !task) return; // already handled
      if (idleAt >= 0) this.idle.splice(idleAt, 1);
      this.busy.delete(worker);
      this.live--;
      void worker.terminate();
      if (task) this.fallback(task);
      if (this.live === 0) this.drainInProcess();
      else this.dispatch();
    };
    worker.on('error', lost);
    worker.on('exit', lost);
  }

  private dispatch(): void {
    if (this.live === 0) {
      this.drainInProcess();
      return;
    }
    while (this.queue.length > 0 && this.idle.length > 0) {
      const worker = this.idle.shift()!;
      const task = this.queue.shift()!;
      this.busy.set(worker, task);
      worker.postMessage({ id: task.id, req: task.req });
    }
  }

  private fallback(task: Task<Req, Res>): void {
    this.opts.runInProcess(task.req).then(task.resolve, task.reject);
  }

  private drainInProcess(): void {
    while (this.queue.length > 0) this.fallback(this.queue.shift()!);
  }
}

/**
 * Worker side: answer each task with `handler`. An error is sent with its
 * `name`, `message` and own enumerable fields; a result that cannot be cloned
 * asks the main thread to run the task itself.
 */
export function serveScanWorker<Req, Res>(handler: (req: Req) => Promise<Res>): void {
  const port = parentPort;
  if (!port) throw new Error('serveScanWorker must run in a worker thread');
  port.on('message', async ({ id, req }: { id: number; req: Req }) => {
    let reply: WorkerReply<Res>;
    try {
      reply = { id, ok: true, value: await handler(req) };
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      const fields: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(e)) {
        if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') fields[k] = v;
      }
      reply = { id, ok: false, error: { name: e.name, message: e.message, fields } };
    }
    try {
      port.postMessage(reply);
    } catch {
      port.postMessage({ id, ok: false, fallback: true });
    }
  });
}
