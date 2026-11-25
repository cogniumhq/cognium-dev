/**
 * A scanned file name made safe to write to a terminal (#1305 R1): C0 and C1
 * control characters, DEL, bidirectional overrides, embeddings, isolates and
 * direction marks, and the Unicode line and paragraph separators are written
 * as `\xNN` or `\u{NNNN}`, so a file named with an escape sequence or a
 * newline cannot recolour, move the cursor, reorder the line or forge an
 * output line. Other text is unchanged. Text output only: JSON and SARIF keep
 * the raw name.
 *
 * In its own module so every text path (the formatters, the spinners, the
 * watchdog's message, the graph-facts reports) uses this one helper without
 * pulling in the formatters.
 */
export function termSafe(name: string): string {
  // eslint-disable-next-line no-control-regex
  return name.replace(/[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, c => {
    const n = c.charCodeAt(0);
    return n <= 0xff ? `\\x${n.toString(16).padStart(2, '0')}` : `\\u{${n.toString(16)}}`;
  });
}

/**
 * The scan and metrics spinners' file label: the path under the scan root,
 * escaped (`termSafe`) and only then cut to its last `maxLen` characters, so a
 * hostile name can't reach the terminal and the cut never splits an escape.
 */
export function spinnerFileLabel(relPath: string, maxLen = 80): string {
  const safe = termSafe(relPath);
  return safe.length > maxLen ? `...${safe.slice(-(maxLen - 3))}` : safe;
}
