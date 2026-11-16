// Near miss (P1): a parameter shadows the `crypto` import. Zero findings.
import { createHash } from 'crypto';

export function digestWith(createHash: (alg: string) => { update(s: string): string }, body: string): string {
  return createHash('md5').update(body);
}
