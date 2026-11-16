/* eslint-disable @typescript-eslint/no-require-imports -- the CommonJS require shapes are what this fixture tests */
// Node crypto APIs reached through a named import, an aliased import, a
// destructured require, a module alias or an inline require. Every FLAG
// marker line gives exactly one weak-hash or weak-crypto finding.
import * as nodeCrypto from 'node:crypto';
import { createHash, createHash as digestWith, createCipheriv } from 'crypto';

const { createHmac, createCipher } = require('crypto');
const cryptoLib = require('crypto');

export function fingerprintPassword(password: string): string {
  return createHash('md5').update(password).digest('hex'); // FLAG weak-hash md5
}

export function legacyChecksum(body: string): string {
  return digestWith('sha1').update(body).digest('hex'); // FLAG weak-hash sha1
}

export function signPayload(key: string, body: string): string {
  return createHmac('sha1', key).update(body).digest('hex'); // FLAG weak-hash sha1
}

export function hashUserName(name: string): string {
  return nodeCrypto.createHash('md5').update(name).digest('hex'); // FLAG weak-hash md5
}

export function hashInvite(code: string): string {
  return cryptoLib.createHash('sha1').update(code).digest('hex'); // FLAG weak-hash sha1
}

export function hashLegacyId(id: string): string {
  return require('crypto').createHash('md5').update(id).digest('hex'); // FLAG weak-hash md5
}

export function sealRecord(key: Buffer, text: string): string {
  const c = createCipheriv('aes-128-ecb', key, null); // FLAG weak-crypto ecb
  return c.update(text, 'utf8', 'hex') + c.final('hex');
}

export function sealWithPassphrase(pass: string, text: string): string {
  const c = createCipher('aes-256-cbc', pass); // FLAG weak-crypto deprecated createCipher
  return c.update(text, 'utf8', 'hex') + c.final('hex');
}
