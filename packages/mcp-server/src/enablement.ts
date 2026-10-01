/**
 * Enablement — what this install is allowed to offer, computed once.
 *
 * Three states, and only three:
 *
 *   floor       the server alone. Deterministic tools, MIT, always.
 *   extended    an optional tool module resolved and loaded.
 *   commercial  extended, plus a licence token that verified.
 *
 * Two rules worth stating because they are easy to get wrong:
 *
 *   - A token that verifies but with no module loaded is **not** commercial.
 *     Commercial is extended *plus* a token; with nothing extra installed
 *     there is nothing extra to licence, so the state is floor and the token
 *     is simply recorded.
 *   - Past expiry the install behaves as `extended`, never worse. Expiry
 *     removes commercial rights; it does not take away code the user already
 *     has, and it does not switch anything off.
 *
 * `endpoint` is an opaque string. The server records only *whether* one is
 * configured and passes it through untouched; it never parses it, connects to
 * it, or learns what is on the other end. That is the module's business.
 *
 * Computed once per process and memoized, because the HTTP host builds a
 * fresh server per request (stateless transport) and so has no startup of its
 * own to compute this at. Recomputing per request would re-read the
 * environment and the config file on every call and could report two
 * different states inside one process.
 */

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { verifyLicence, parsePublicKeyEnv, type LicenceVerdict } from './licence.js';

export type LicenceState = 'floor' | 'extended' | 'commercial';

export interface Enablement {
  /** At least one optional tool module resolved and loaded. */
  readonly installed: boolean;
  /** A configured endpoint, verbatim and opaque, if there is one. */
  readonly endpoint?: string;
  /** The verdict on the configured token, or `absent` if there was none. */
  readonly licence: LicenceVerdict;
  readonly state: LicenceState;
}

/** Environment variables this module reads. Nothing else is consulted. */
export const ENV_ENDPOINT = 'COGNIUM_ENDPOINT';
export const ENV_LICENSE = 'COGNIUM_LICENSE';
export const ENV_LICENSE_PUBKEY = 'COGNIUM_LICENSE_PUBKEY';
export const ENV_CONFIG_DIR = 'COGNIUM_CONFIG_DIR';

/** Where `cognium license set` writes, when no config dir is given. */
export function configDir(env: NodeJS.ProcessEnv = process.env): string {
  return env[ENV_CONFIG_DIR] ?? join(homedir(), '.cognium');
}

function tokenFromDisk(env: NodeJS.ProcessEnv): string | undefined {
  try {
    const text = readFileSync(join(configDir(env), 'license'), 'utf8').trim();
    return text === '' ? undefined : text;
  } catch {
    // No file, no permission, a directory where a file should be — all mean
    // the same thing to us: no token on disk.
    return undefined;
  }
}

export interface ComputeEnablementInput {
  /** Whether an optional module loaded. Decided by the loader, not here. */
  readonly installed: boolean;
  readonly env?: NodeJS.ProcessEnv;
  /** Clock injection point for expiry tests. */
  readonly now?: Date;
}

/** Compute enablement from the environment and the user config dir. */
export function computeEnablement(input: ComputeEnablementInput): Enablement {
  const env = input.env ?? process.env;

  const rawEndpoint = env[ENV_ENDPOINT]?.trim();
  const endpoint = rawEndpoint === '' ? undefined : rawEndpoint;

  const token = env[ENV_LICENSE]?.trim() || tokenFromDisk(env);
  const licence = verifyLicence(token, {
    publicKeys: parsePublicKeyEnv(env[ENV_LICENSE_PUBKEY]),
    ...(input.now ? { now: input.now } : {}),
  });

  let state: LicenceState = 'floor';
  if (input.installed) {
    state = licence.status === 'valid' ? 'commercial' : 'extended';
  }

  return {
    installed: input.installed,
    ...(endpoint ? { endpoint } : {}),
    licence,
    state,
  };
}

let memoized: Enablement | undefined;

/**
 * The process-wide enablement. First call computes it; every later call —
 * including every request-scoped server the HTTP host builds — gets the same
 * object back.
 */
export function enablementForProcess(input: ComputeEnablementInput): Enablement {
  memoized ??= computeEnablement(input);
  return memoized;
}

/** Drop the memo. For tests; nothing in the server calls this. */
export function resetEnablementForTests(): void {
  memoized = undefined;
}

/** The floor state, for a server built with no modules at all. */
export function floorEnablement(): Enablement {
  return {
    installed: false,
    licence: { status: 'absent', detail: 'no licence token configured' },
    state: 'floor',
  };
}
