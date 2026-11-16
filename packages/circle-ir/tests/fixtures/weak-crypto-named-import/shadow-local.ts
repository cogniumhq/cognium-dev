// Near miss (P2): a local `const` shadows the `crypto` import. Zero findings.
import { createHash } from 'crypto';

export function label(body: string): string {
  const createHash = (tag: string) => `${tag}:${body}`;
  return createHash('md5');
}
