/**
 * Worker for tests/scan-threads.test.ts: answers like a scan worker, and fails
 * on purpose for the task names the test uses.
 */
import { threadId } from 'worker_threads';
import { AnalysisTimeoutError } from 'circle-ir';
import { serveScanWorker } from '../src/scan-pool';

serveScanWorker(async (req: { name: string }) => {
  if (req.name === 'throws') throw new Error('Failed to parse code');
  if (req.name === 'times-out') throw new AnalysisTimeoutError('src/slow.sh', 7, 'parse');
  if (req.name === 'crashes') {
    // An uncaught error kills the thread, as a crash in the engine would.
    await new Promise(() => { setTimeout(() => { throw new Error('worker crashed'); }, 0); });
  }
  return { name: req.name, where: threadId === 0 ? 'main' : 'worker' };
});
