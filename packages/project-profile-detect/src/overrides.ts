/**
 * `profileOverrides` glob matcher.
 *
 * Caller supplies a `Record<glob, ProjectProfile>` from `cognium.config.json`.
 * For each scanned file we evaluate globs in the order they appear in the
 * object; the *first* matching glob wins (matches `include`/`exclude`
 * semantics elsewhere in the CLI).
 *
 * Minimal glob grammar supported (no runtime dependency on `micromatch`):
 *   `*`   → matches any sequence of characters except `/`
 *   `**`  → matches any sequence of characters including `/`
 *   `?`   → matches exactly one character except `/`
 *
 * Everything else is treated as a literal. Trailing `/` is optional.
 */

import type { ProfileOverrides, ProjectProfile } from './types.js';

function compileGlob(glob: string): RegExp {
  // Escape regex metacharacters except glob wildcards.
  let re = '';
  let i = 0;
  while (i < glob.length) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i += 2;
        // Consume a trailing slash so `**/foo` matches both `foo` and `a/foo`.
        if (glob[i] === '/') i++;
      } else {
        re += '[^/]*';
        i++;
      }
    } else if (c === '?') {
      re += '[^/]';
      i++;
    } else if (/[.+^${}()|[\]\\]/.test(c)) {
      re += '\\' + c;
      i++;
    } else {
      re += c;
      i++;
    }
  }
  return new RegExp('^' + re + '$');
}

/**
 * Pre-compile every glob in the override map so per-file matching is O(N
 * regex tests) per file, not O(N regex compilations).
 */
export function compileOverrides(
  overrides: ProfileOverrides | undefined,
): Array<{ re: RegExp; profile: ProjectProfile; glob: string }> {
  if (!overrides) return [];
  return Object.entries(overrides).map(([glob, profile]) => ({
    re: compileGlob(glob),
    profile,
    glob,
  }));
}

export type CompiledOverrides = ReturnType<typeof compileOverrides>;

/**
 * Apply the first matching override to `relativePath`. Returns `undefined`
 * if no override matches (caller should fall back to the detected profile).
 */
export function applyOverrides(
  relativePath: string,
  compiled: CompiledOverrides,
): { profile: ProjectProfile; glob: string } | undefined {
  // Normalize to forward-slash form for glob matching.
  const p = relativePath.replace(/\\/g, '/');
  for (const { re, profile, glob } of compiled) {
    if (re.test(p)) return { profile, glob };
  }
  return undefined;
}
