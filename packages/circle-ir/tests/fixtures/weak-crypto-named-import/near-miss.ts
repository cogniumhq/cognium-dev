/* eslint-disable @typescript-eslint/no-require-imports -- the CommonJS require shapes are what this fixture tests */
// Same names, not bound to Node's crypto module: zero weak-hash or
// weak-crypto findings.
import { createHash } from './local-hash';
import { createCipheriv as makeCipher } from 'some-cipher-lib';

const { createHmac } = require('./hmac-shim');
const hashing = require('hash-wasm');

function createCipher(mode: string, key: string): { mode: string; key: string } {
  return { mode, key };
}

export function localDigest(body: string): string {
  return createHash('md5').update(body).digest('hex');
}

export function shimSign(key: string, body: string): string {
  return createHmac('sha1', key).update(body).digest('hex');
}

export function otherLibCipher(key: Buffer): unknown {
  return makeCipher('des-ede3-cbc', key, null);
}

export function packageDigest(body: string): unknown {
  return hashing.createHash('md5').update(body);
}

export function localCipher(key: string): unknown {
  return createCipher('aes-128-ecb', key);
}
