/**
 * Tests for JavaScript/TypeScript CFG (Control Flow Graph) builder
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildCFG } from '../../src/core/extractors/cfg.js';

describe('JavaScript CFG Builder', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Function Declarations', () => {
    it('should build CFG for simple function', async () => {
      const code = `
function greet(name) {
    console.log("Hello, " + name);
    return true;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      expect(cfg.blocks.length).toBeGreaterThanOrEqual(2);

      const entryBlock = cfg.blocks.find(b => b.type === 'entry');
      expect(entryBlock).toBeDefined();

      const exitBlock = cfg.blocks.find(b => b.type === 'exit');
      expect(exitBlock).toBeDefined();
    });

    it('should build CFG for function with multiple statements', async () => {
      const code = `
function process(data) {
    const x = data.value;
    const y = x + 1;
    const z = y * 2;
    return z;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      // Entry, 4 statements, exit
      expect(cfg.blocks.length).toBeGreaterThanOrEqual(4);
    });
  });

  describe('Arrow Functions', () => {
    it('should build CFG for arrow function with block body', async () => {
      const code = `
const add = (a, b) => {
    const sum = a + b;
    return sum;
};
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      expect(cfg.blocks.length).toBeGreaterThanOrEqual(2);
    });

    it('should build CFG for arrow function with expression body', async () => {
      const code = `
const double = x => x * 2;
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      // Expression body creates at least one block
      expect(cfg.blocks.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('If Statements', () => {
    it('should build CFG for if statement', async () => {
      const code = `
function check(x) {
    if (x > 0) {
        return true;
    }
    return false;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
      expect(conditionalBlock).toBeDefined();

      // Should have true edge
      const trueEdge = cfg.edges.find(e => e.type === 'true');
      expect(trueEdge).toBeDefined();
    });

    it('should build CFG for if-else statement', async () => {
      const code = `
function check(x) {
    if (x > 0) {
        return "positive";
    } else {
        return "non-positive";
    }
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const trueEdge = cfg.edges.find(e => e.type === 'true');
      expect(trueEdge).toBeDefined();

      const falseEdge = cfg.edges.find(e => e.type === 'false');
      expect(falseEdge).toBeDefined();
    });

    it('should build CFG for nested if statements', async () => {
      const code = `
function classify(x) {
    if (x > 0) {
        if (x > 100) {
            return "large";
        }
        return "positive";
    }
    return "non-positive";
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const conditionalBlocks = cfg.blocks.filter(b => b.type === 'conditional');
      expect(conditionalBlocks.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('For Loops', () => {
    it('should build CFG for for loop', async () => {
      const code = `
function sum(arr) {
    let total = 0;
    for (let i = 0; i < arr.length; i++) {
        total += arr[i];
    }
    return total;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const loopBlock = cfg.blocks.find(b => b.type === 'loop');
      expect(loopBlock).toBeDefined();

      // Should have back edge
      const backEdge = cfg.edges.find(e => e.type === 'back');
      expect(backEdge).toBeDefined();
    });

    it('should build CFG for for-of loop', async () => {
      const code = `
function sum(arr) {
    let total = 0;
    for (const item of arr) {
        total += item;
    }
    return total;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const loopBlock = cfg.blocks.find(b => b.type === 'loop');
      expect(loopBlock).toBeDefined();
    });

    it('should build CFG for for-in loop', async () => {
      const code = `
function keys(obj) {
    const result = [];
    for (const key in obj) {
        result.push(key);
    }
    return result;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const loopBlock = cfg.blocks.find(b => b.type === 'loop');
      expect(loopBlock).toBeDefined();
    });
  });

  describe('While Loops', () => {
    it('should build CFG for while loop', async () => {
      const code = `
function countdown(n) {
    while (n > 0) {
        console.log(n);
        n--;
    }
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const loopBlock = cfg.blocks.find(b => b.type === 'loop');
      expect(loopBlock).toBeDefined();
    });

    it('should build CFG for do-while loop', async () => {
      const code = `
function countdown(n) {
    do {
        console.log(n);
        n--;
    } while (n > 0);
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const loopBlock = cfg.blocks.find(b => b.type === 'loop');
      expect(loopBlock).toBeDefined();
    });
  });

  describe('Try-Catch-Finally', () => {
    it('should build CFG for try-catch', async () => {
      const code = `
function safeParse(json) {
    try {
        return JSON.parse(json);
    } catch (e) {
        return null;
    }
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      // Should have exception edge
      const exceptionEdge = cfg.edges.find(e => e.type === 'exception');
      expect(exceptionEdge).toBeDefined();
    });

    it('should build CFG for try-catch-finally', async () => {
      const code = `
function withCleanup(resource) {
    try {
        resource.use();
    } catch (e) {
        console.error(e);
    } finally {
        resource.close();
    }
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      expect(cfg.blocks.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Switch Statements', () => {
    it('should build CFG for switch statement', async () => {
      const code = `
function describe(x) {
    switch (x) {
        case 1:
            return "one";
        case 2:
            return "two";
        default:
            return "other";
    }
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
      expect(conditionalBlock).toBeDefined();
    });
  });

  describe('Express.js Route Handlers', () => {
    it('should build CFG for Express route handler', async () => {
      const code = `
app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    if (!id) {
        return res.status(400).send('Missing ID');
    }
    const user = db.find(id);
    if (!user) {
        return res.status(404).send('Not found');
    }
    res.json(user);
});
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const conditionalBlocks = cfg.blocks.filter(b => b.type === 'conditional');
      expect(conditionalBlocks.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Class Methods', () => {
    it('should build CFG for class methods', async () => {
      const code = `
class Calculator {
    add(a, b) {
        return a + b;
    }

    multiply(a, b) {
        let result = 0;
        for (let i = 0; i < b; i++) {
            result += a;
        }
        return result;
    }
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      // Should have blocks from multiple methods
      expect(cfg.blocks.length).toBeGreaterThanOrEqual(4);

      // multiply should have a loop
      const loopBlock = cfg.blocks.find(b => b.type === 'loop');
      expect(loopBlock).toBeDefined();
    });
  });

  describe('Edge Types', () => {
    it('should have sequential edges for normal flow', async () => {
      const code = `
function steps() {
    const a = 1;
    const b = 2;
    const c = 3;
}
`;
      const tree = await parse(code, 'javascript');
      const cfg = buildCFG(tree, 'javascript');

      const sequentialEdges = cfg.edges.filter(e => e.type === 'sequential');
      expect(sequentialEdges.length).toBeGreaterThan(0);
    });
  });
});
