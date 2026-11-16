// Near miss: a parameter shadows a namespace import of `crypto`. Zero findings.
import * as nodeCrypto from 'crypto';

export function digestWith(nodeCrypto: { createHash(alg: string): string }): string {
  return nodeCrypto.createHash('md5');
}
