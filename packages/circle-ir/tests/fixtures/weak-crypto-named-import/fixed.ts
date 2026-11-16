/* eslint-disable @typescript-eslint/no-require-imports -- the CommonJS require shapes are what this fixture tests */
// The same functions as vulnerable.ts with strong algorithms: zero weak-hash
// or weak-crypto findings.
import * as nodeCrypto from 'node:crypto';
import { createHash, createHash as digestWith, createCipheriv, randomBytes, scryptSync } from 'crypto';

const { createHmac } = require('crypto');
const cryptoLib = require('crypto');

export function fingerprintPassword(password: string): string {
  const salt = randomBytes(16);
  return salt.toString('hex') + ':' + scryptSync(password, salt, 64).toString('hex');
}

export function legacyChecksum(body: string): string {
  return digestWith('sha256').update(body).digest('hex');
}

export function signPayload(key: string, body: string): string {
  return createHmac('sha256', key).update(body).digest('hex');
}

export function hashUserName(name: string): string {
  return nodeCrypto.createHash('sha256').update(name).digest('hex');
}

export function hashInvite(code: string): string {
  return cryptoLib.createHash('sha512').update(code).digest('hex');
}

export function hashLegacyId(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}

export function sealRecord(key: Buffer, text: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  return iv.toString('hex') + c.update(text, 'utf8', 'hex') + c.final('hex');
}

export function sealWithPassphrase(pass: string, text: string): string {
  const key = scryptSync(pass, randomBytes(16), 32);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  return iv.toString('hex') + c.update(text, 'utf8', 'hex') + c.final('hex');
}
