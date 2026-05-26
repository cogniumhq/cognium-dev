/**
 * Tests for CFG builder
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildCFG } from '../../src/core/extractors/cfg.js';

describe('CFG Builder', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should create entry and exit blocks for simple method', async () => {
    const code = `
public class Test {
    public void method() {
        int x = 1;
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    expect(cfg.blocks.length).toBeGreaterThanOrEqual(2);

    const entryBlock = cfg.blocks.find(b => b.type === 'entry');
    const exitBlock = cfg.blocks.find(b => b.type === 'exit');

    expect(entryBlock).toBeDefined();
    expect(exitBlock).toBeDefined();
  });

  it('should handle if statement with both branches', async () => {
    const code = `
public class Test {
    public void method(boolean cond) {
        if (cond) {
            doA();
        } else {
            doB();
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have conditional block
    const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
    expect(conditionalBlock).toBeDefined();

    // Should have true and false edges from conditional
    const trueEdge = cfg.edges.find(
      e => e.from === conditionalBlock!.id && e.type === 'true'
    );
    const falseEdge = cfg.edges.find(
      e => e.from === conditionalBlock!.id && e.type === 'false'
    );

    expect(trueEdge).toBeDefined();
    expect(falseEdge).toBeDefined();
  });

  it('should handle for loop with back edge', async () => {
    const code = `
public class Test {
    public void method() {
        for (int i = 0; i < 10; i++) {
            doSomething();
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have loop block
    const loopBlock = cfg.blocks.find(b => b.type === 'loop');
    expect(loopBlock).toBeDefined();

    // Should have back edge
    const backEdge = cfg.edges.find(e => e.type === 'back');
    expect(backEdge).toBeDefined();
    expect(backEdge!.to).toBe(loopBlock!.id);
  });

  it('should handle while loop', async () => {
    const code = `
public class Test {
    public void method() {
        while (condition) {
            doSomething();
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    const loopBlock = cfg.blocks.find(b => b.type === 'loop');
    expect(loopBlock).toBeDefined();
  });

  it('should handle try-catch', async () => {
    const code = `
public class Test {
    public void method() {
        try {
            riskyOperation();
        } catch (Exception e) {
            handleError();
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have exception edge
    const exceptionEdge = cfg.edges.find(e => e.type === 'exception');
    expect(exceptionEdge).toBeDefined();
  });

  it('should handle nested control flow', async () => {
    const code = `
public class Test {
    public void method(int x) {
        if (x > 0) {
            for (int i = 0; i < x; i++) {
                if (i % 2 == 0) {
                    doEven();
                }
            }
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have multiple conditional blocks
    const conditionalBlocks = cfg.blocks.filter(b => b.type === 'conditional');
    expect(conditionalBlocks.length).toBeGreaterThanOrEqual(2);

    // Should have loop block
    const loopBlock = cfg.blocks.find(b => b.type === 'loop');
    expect(loopBlock).toBeDefined();
  });

  it('should connect blocks sequentially', async () => {
    const code = `
public class Test {
    public void method() {
        int a = 1;
        int b = 2;
        int c = 3;
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // All edges should be sequential (no control flow)
    const nonSequentialEdges = cfg.edges.filter(
      e => e.type !== 'sequential'
    );
    expect(nonSequentialEdges).toHaveLength(0);
  });

  it('should handle try-catch-finally', async () => {
    const code = `
public class Test {
    public void method() {
        try {
            riskyOperation();
        } catch (Exception e) {
            handleError();
        } finally {
            cleanup();
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have blocks for try, catch, and finally
    expect(cfg.blocks.length).toBeGreaterThanOrEqual(4);

    // Should have exception edge
    const exceptionEdge = cfg.edges.find(e => e.type === 'exception');
    expect(exceptionEdge).toBeDefined();
  });

  it('should handle switch statement', async () => {
    const code = `
public class Test {
    public void method(int x) {
        switch (x) {
            case 1:
                doOne();
                break;
            case 2:
                doTwo();
                break;
            default:
                doDefault();
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have conditional block for switch
    const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
    expect(conditionalBlock).toBeDefined();

    // Should have multiple edges from switch to cases
    const switchEdges = cfg.edges.filter(e => e.from === conditionalBlock!.id);
    expect(switchEdges.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle empty switch statement', async () => {
    const code = `
public class Test {
    public void method(int x) {
        switch (x) {
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should still have conditional block
    const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
    expect(conditionalBlock).toBeDefined();
  });

  it('should handle do-while loop', async () => {
    const code = `
public class Test {
    public void method() {
        do {
            doSomething();
        } while (condition);
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have loop block
    const loopBlock = cfg.blocks.find(b => b.type === 'loop');
    expect(loopBlock).toBeDefined();

    // Should have back edge
    const backEdge = cfg.edges.find(e => e.type === 'back');
    expect(backEdge).toBeDefined();
  });

  it('should handle return statement', async () => {
    const code = `
public class Test {
    public int method(int x) {
        if (x > 0) {
            return x;
        }
        return -x;
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have exit block
    const exitBlock = cfg.blocks.find(b => b.type === 'exit');
    expect(exitBlock).toBeDefined();

    // Should have edges going to exit
    const toExitEdges = cfg.edges.filter(e => e.to === exitBlock!.id);
    expect(toExitEdges.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle break statement in loop', async () => {
    const code = `
public class Test {
    public void method() {
        for (int i = 0; i < 10; i++) {
            if (i == 5) {
                break;
            }
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have loop and conditional blocks
    const loopBlock = cfg.blocks.find(b => b.type === 'loop');
    const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
    expect(loopBlock).toBeDefined();
    expect(conditionalBlock).toBeDefined();
  });

  it('should handle continue statement in loop', async () => {
    const code = `
public class Test {
    public void method() {
        for (int i = 0; i < 10; i++) {
            if (i % 2 == 0) {
                continue;
            }
            process(i);
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const cfg = buildCFG(tree);

    // Should have loop and conditional blocks
    const loopBlock = cfg.blocks.find(b => b.type === 'loop');
    const conditionalBlock = cfg.blocks.find(b => b.type === 'conditional');
    expect(loopBlock).toBeDefined();
    expect(conditionalBlock).toBeDefined();
  });
});
