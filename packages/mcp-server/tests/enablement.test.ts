/**
 * Enablement: where the token comes from, and the memo that makes "computed
 * once at startup" true for a host that has no startup of its own.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  computeEnablement,
  enablementForProcess,
  resetEnablementForTests,
  floorEnablement,
  configDir,
  ENV_ENDPOINT,
  ENV_LICENSE,
  ENV_LICENSE_PUBKEY,
  ENV_CONFIG_DIR,
} from '../src/enablement.js';
import { testKey, mint } from './fixtures/licence.js';

const tempDirs: string[] = [];

function tempConfigDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'cognium-enablement-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  resetEnablementForTests();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

let keyCounter = 0;

/** A token and the `kid=key` entry a verifier needs for it. */
function mintToken(expiry = '2099-01-01'): { token: string; publicKey: string } {
  const key = testKey(`enablement-${++keyCounter}`);
  return { token: mint(key, { expiry }), publicKey: `${key.kid}=${key.publicKey}` };
}

const MISSING_DIR = { [ENV_CONFIG_DIR]: join(tmpdir(), 'cognium-does-not-exist') };

describe('configDir', () => {
  it('honours the override', () => {
    expect(configDir({ [ENV_CONFIG_DIR]: '/tmp/x' })).toBe('/tmp/x');
  });

  it('otherwise sits under the home directory', () => {
    expect(configDir({})).toMatch(/\.cognium$/);
  });
});

describe('where the token comes from', () => {
  it('reads it from the config dir when the environment has none', () => {
    const dir = tempConfigDir();
    const { token, publicKey } = mintToken();
    writeFileSync(join(dir, 'license'), `${token}\n`);

    const enablement = computeEnablement({
      installed: true,
      env: { [ENV_CONFIG_DIR]: dir, [ENV_LICENSE_PUBKEY]: publicKey },
    });
    expect(enablement.licence.status).toBe('valid');
    expect(enablement.state).toBe('commercial');
  });

  it('prefers the environment over the file', () => {
    const dir = tempConfigDir();
    // Both tokens claim the same key id, and the verifier is given only the
    // file token's key. So the file token would verify and the env one
    // cannot: `invalid-signature` proves the env token is the one that was
    // read, and nothing else produces that outcome here.
    const onDisk = testKey('contested');
    const inEnv = testKey('contested');
    writeFileSync(join(dir, 'license'), mint(onDisk));

    const enablement = computeEnablement({
      installed: true,
      env: {
        [ENV_CONFIG_DIR]: dir,
        [ENV_LICENSE]: mint(inEnv),
        [ENV_LICENSE_PUBKEY]: `${onDisk.kid}=${onDisk.publicKey}`,
      },
    });
    expect(enablement.licence.status).toBe('invalid-signature');
  });

  it('falls back to the file when the environment variable is blank', () => {
    const dir = tempConfigDir();
    const key = testKey('from-disk');
    writeFileSync(join(dir, 'license'), mint(key));

    const enablement = computeEnablement({
      installed: true,
      env: {
        [ENV_CONFIG_DIR]: dir,
        [ENV_LICENSE]: '   ',
        [ENV_LICENSE_PUBKEY]: `${key.kid}=${key.publicKey}`,
      },
    });
    expect(enablement.licence.status).toBe('valid');
  });

  it('is absent when there is no token anywhere', () => {
    const enablement = computeEnablement({ installed: true, env: { ...MISSING_DIR } });
    expect(enablement.licence.status).toBe('absent');
    expect(enablement.state).toBe('extended');
  });

  it('treats an empty token file as no token', () => {
    const dir = tempConfigDir();
    writeFileSync(join(dir, 'license'), '   \n');
    const enablement = computeEnablement({ installed: true, env: { [ENV_CONFIG_DIR]: dir } });
    expect(enablement.licence.status).toBe('absent');
  });

  it('survives a directory where the token file should be', () => {
    const dir = tempConfigDir();
    mkdirSync(join(dir, 'license'));
    expect(() => computeEnablement({ installed: true, env: { [ENV_CONFIG_DIR]: dir } })).not.toThrow();
  });
});

describe('the endpoint is opaque', () => {
  it('is passed through verbatim', () => {
    const enablement = computeEnablement({
      installed: true,
      env: { ...MISSING_DIR, [ENV_ENDPOINT]: '  https://endpoint.example/v1  ' },
    });
    expect(enablement.endpoint).toBe('https://endpoint.example/v1');
  });

  it('is undefined, not empty, when the variable is set but blank', () => {
    const enablement = computeEnablement({ installed: true, env: { ...MISSING_DIR, [ENV_ENDPOINT]: '   ' } });
    expect(enablement.endpoint).toBeUndefined();
  });

  it('does not by itself change the licence state', () => {
    const withEndpoint = computeEnablement({ installed: true, env: { ...MISSING_DIR, [ENV_ENDPOINT]: 'x' } });
    const without = computeEnablement({ installed: true, env: { ...MISSING_DIR } });
    expect(withEndpoint.state).toBe(without.state);
  });
});

describe('the process memo', () => {
  it('computes once and hands back the same object', () => {
    const first = enablementForProcess({ installed: true, env: { ...MISSING_DIR } });
    const second = enablementForProcess({ installed: false, env: { ...MISSING_DIR } });
    // The second call's different input is ignored on purpose: one process
    // reports one state, however many request-scoped servers ask.
    expect(second).toBe(first);
    expect(second.installed).toBe(true);
  });

  it('recomputes after a reset, so tests stay independent', () => {
    const first = enablementForProcess({ installed: true, env: { ...MISSING_DIR } });
    resetEnablementForTests();
    const second = enablementForProcess({ installed: false, env: { ...MISSING_DIR } });
    expect(second).not.toBe(first);
    expect(second.state).toBe('floor');
  });
});

describe('floorEnablement', () => {
  it('is the floor, with no token and nothing installed', () => {
    const floor = floorEnablement();
    expect(floor).toEqual({
      installed: false,
      licence: { status: 'absent', detail: 'no licence token configured' },
      state: 'floor',
    });
  });
});
