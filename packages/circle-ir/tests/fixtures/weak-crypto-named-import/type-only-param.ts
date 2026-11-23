// Near miss (P5): `import type` binds no value, and a parameter of the same
// name is what gets called. Zero findings.
import type { createHash } from 'crypto';

export function digestWith(createHash: (alg: string) => string): string {
  return createHash('md5');
}
