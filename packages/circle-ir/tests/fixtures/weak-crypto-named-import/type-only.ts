// Near miss: type-only imports bind no value, so a bare call of the same
// name is not Node's crypto API. Zero findings.
import type { createHash } from 'crypto';
import { type createHmac } from 'node:crypto';
import type * as cryptoTypes from 'crypto';

export function a(): unknown {
  return createHash('md5');
}

export function b(key: string): unknown {
  return createHmac('sha1', key);
}

export function c(): unknown {
  return cryptoTypes.createHash('md5');
}
