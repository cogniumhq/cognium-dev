import { describe, it, expect } from 'vitest';
import { parseJavaArrayAccessExpression } from '../../src/analysis/java-array-element-keys.js';

describe('parseJavaArrayAccessExpression', () => {
  it('parses 2-D numeric access', () => {
    expect(parseJavaArrayAccessExpression('grid[0][0]')).toEqual({
      base: 'grid',
      arrayName: 'grid@0',
      indexKey: '0',
      displayVar: 'grid[0][0]',
    });
  });

  it('parses 1-D numeric access', () => {
    expect(parseJavaArrayAccessExpression('arr[0]')).toEqual({
      base: 'arr',
      arrayName: 'arr',
      indexKey: '0',
      displayVar: 'arr[0]',
    });
  });

  it('parses 1-D variable index (sink arg shape)', () => {
    expect(parseJavaArrayAccessExpression('params[i]')).toEqual({
      base: 'params',
      arrayName: 'params',
      indexKey: 'i',
      displayVar: 'params[i]',
    });
  });

  it('rejects nested non-numeric multi-dimensional access', () => {
    expect(parseJavaArrayAccessExpression('grid[i][0]')).toBeNull();
  });
});
