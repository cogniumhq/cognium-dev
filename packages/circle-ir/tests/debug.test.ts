import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse, walkTree } from '../src/core/parser.js';
import { extractTypes } from '../src/core/extractors/types.js';

describe('Debug utilities', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('walkTree traverses all nodes', async () => {
    const code = `public class Test {}`;
    const tree = await parse(code, 'java');

    const nodeTypes: string[] = [];
    walkTree(tree.rootNode, (node) => {
      nodeTypes.push(node.type);
    });

    expect(nodeTypes).toContain('program');
    expect(nodeTypes).toContain('class_declaration');
    expect(nodeTypes).toContain('identifier');
  });
});
