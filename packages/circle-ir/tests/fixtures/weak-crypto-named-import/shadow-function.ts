// Near miss: an inner function declaration shadows the `crypto` import. Zero findings.
import { createHash } from 'node:crypto';

export function label(body: string): string {
  function createHash(tag: string): string {
    return `${tag}:${body}`;
  }
  return createHash('md5');
}
