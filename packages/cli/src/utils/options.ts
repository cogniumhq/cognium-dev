/**
 * Option validation and safe exit for the CLI (cognium-dev#1001, #1006, #1007).
 *
 * Options are checked BEFORE any file is read, so a typo fails in milliseconds
 * instead of after a whole scan, and an unknown output format is refused rather
 * than silently printed as text.
 */

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export const SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical'] as const;

/** `-f/--format`: the value (lower-cased) if allowed, else a UsageError. */
export function parseFormat<T extends string>(raw: unknown, allowed: readonly T[], fallback: T): T {
  if (raw === undefined) return fallback;
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new UsageError(`--format requires a value (${allowed.join('|')})`);
  }
  const v = raw.trim().toLowerCase();
  if (!(allowed as readonly string[]).includes(v)) {
    throw new UsageError(`unknown format '${raw}' (expected ${allowed.join('|')})`);
  }
  return v as T;
}

/** `--severity`: one level (minimum) or a comma list (exact); each must be known. */
export function parseSeverity(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new UsageError(`--severity requires a value. Valid levels: ${SEVERITY_LEVELS.join(', ')}`);
  }
  const parts = raw.split(',').map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0);
  if (parts.length === 0) {
    throw new UsageError(`--severity requires a value. Valid levels: ${SEVERITY_LEVELS.join(', ')}`);
  }
  for (const p of parts) {
    if (!(SEVERITY_LEVELS as readonly string[]).includes(p)) {
      throw new UsageError(`invalid severity level '${p}'. Must be one of: ${SEVERITY_LEVELS.join(', ')}`);
    }
  }
  return parts.join(',');
}

/** A whole number ≥ `min`, or `fallback` when the option is absent. */
export function parseWholeNumber(name: string, raw: unknown, fallback: number, min: number): number {
  if (raw === undefined) return fallback;
  if (typeof raw !== 'string' || !/^\d+$/.test(raw.trim())) {
    throw new UsageError(`--${name} must be a whole number${min > 0 ? ` ≥ ${min}` : ''}`);
  }
  const n = Number(raw.trim());
  if (!Number.isSafeInteger(n) || n < min) {
    throw new UsageError(`--${name} must be a whole number ≥ ${min}`);
  }
  return n;
}

/**
 * Exit only after stdout and stderr have drained (#1001).
 *
 * `process.exit()` right after a large `console.log` truncates the output when
 * stdout is a pipe (writes to pipes are asynchronous), which cut JSON off at
 * 64 KiB. An empty write's callback fires once everything queued before it
 * has been handed to the OS.
 */
export function exitAfterFlush(code: number): Promise<never> {
  process.exitCode = code;
  return new Promise<never>(() => {
    process.stdout.write('', () => {
      process.stderr.write('', () => process.exit(code));
    });
  });
}
