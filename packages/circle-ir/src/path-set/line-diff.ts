/**
 * Line diff of two versions of a file (Myers' O((N+M)·D) algorithm): which
 * lines of the new version were inserted or changed, and, for every other new
 * line, the old line it was carried over from.
 */

export interface LineDiff {
  /** 1-based lines of the new version that are not carried over from the old one. */
  changed: number[];
  /** New line (1-based) → old line (1-based); absent for changed lines. */
  toOld: Map<number, number>;
}

/** Split text into lines the way an editor counts them (a trailing newline adds no line). */
export function splitLines(text: string): string[] {
  if (text === '') return [];
  const lines = text.split(/\r\n|\n|\r/);
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/**
 * Diff `oldLines` against `newLines`. Returns `null` when the edit distance
 * exceeds `maxD` (the caller then treats the whole file as changed).
 */
export function diffLines(oldLines: readonly string[], newLines: readonly string[], maxD = 4000): LineDiff | null {
  const n = oldLines.length;
  const m = newLines.length;
  // trim the common prefix and suffix: most edits are small
  let pre = 0;
  while (pre < n && pre < m && oldLines[pre] === newLines[pre]) pre++;
  let suf = 0;
  while (suf < n - pre && suf < m - pre && oldLines[n - 1 - suf] === newLines[m - 1 - suf]) suf++;
  const a = oldLines.slice(pre, n - suf);
  const b = newLines.slice(pre, m - suf);
  const toOld = new Map<number, number>();
  for (let i = 0; i < pre; i++) toOld.set(i + 1, i + 1);
  for (let k = 0; k < suf; k++) toOld.set(m - k, n - k);

  const N = a.length;
  const M = b.length;
  const changed: number[] = [];
  if (N === 0 || M === 0) {
    for (let j = 0; j < M; j++) changed.push(pre + j + 1);
    return { changed, toOld };
  }

  const max = N + M;
  const off = max;
  let v: Int32Array = new Int32Array(2 * max + 2);
  const trace: Int32Array[] = [];
  let found = -1;
  for (let d = 0; d <= Math.min(max, maxD); d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1] < v[off + k + 1]) ? v[off + k + 1] : v[off + k - 1] + 1;
      let y = x - k;
      while (x < N && y < M && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= N && y >= M) {
        found = d;
        break;
      }
    }
    if (found >= 0) break;
  }
  if (found < 0) return null;

  // walk the trace back, recording the diagonal (matching) moves
  let x = N;
  let y = M;
  for (let d = found; d > 0; d--) {
    v = trace[d];
    const k = x - y;
    const prevK = k === -d || (k !== d && v[off + k - 1] < v[off + k + 1]) ? k + 1 : k - 1;
    const prevX = v[off + prevK];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      toOld.set(pre + y, pre + x);
      x--;
      y--;
    }
    if (prevK === k + 1) changed.push(pre + y);
    x = prevX;
    y = prevY;
  }
  while (x > 0 && y > 0) {
    toOld.set(pre + y, pre + x);
    x--;
    y--;
  }
  changed.sort((p, q) => p - q);
  return { changed, toOld };
}
