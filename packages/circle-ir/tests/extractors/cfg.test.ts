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

describe('CFG Builder — C#', () => {
  beforeAll(async () => {
    await initParser();
  });

  const countType = (cfg: ReturnType<typeof buildCFG>, t: string) =>
    cfg.blocks.filter((b) => b.type === t).length;
  const countEdge = (cfg: ReturnType<typeof buildCFG>, t: string) =>
    cfg.edges.filter((e) => e.type === t).length;

  it('builds entry/exit for a C# method', async () => {
    const tree = await parse(`class C { int M() { int x = 1; return x; } }`, 'csharp');
    const cfg = buildCFG(tree, 'csharp');
    expect(cfg.blocks.find((b) => b.type === 'entry')).toBeDefined();
    expect(cfg.blocks.find((b) => b.type === 'exit')).toBeDefined();
  });

  it('captures a foreach as a loop with a back edge (the Java path dropped it)', async () => {
    const tree = await parse(
      `class C { void M(int[] xs) { foreach (var y in xs) { Use(y); } } }`,
      'csharp',
    );
    const cfg = buildCFG(tree, 'csharp');
    expect(countType(cfg, 'loop')).toBe(1);
    expect(countEdge(cfg, 'back')).toBe(1);
  });

  it('recovers all three C# loop forms (for / foreach / while)', async () => {
    const tree = await parse(
      `class C { void M(string s, int[] xs) {
        for (int i = 0; i < 10; i++) { A(i); }
        foreach (var y in xs) { B(y); }
        while (s.Length > 0) { s = s.Substring(1); }
      } }`,
      'csharp',
    );
    const cfg = buildCFG(tree, 'csharp');
    expect(countType(cfg, 'loop')).toBe(3);
    expect(countEdge(cfg, 'back')).toBe(3);
  });

  it('enumerates switch_section cases and branches an if', async () => {
    const tree = await parse(
      `class C { int M(string s) {
        if (s == "a") { return 1; } else { return 2; }
        switch (s) { case "p": return 3; case "q": return 4; default: return 5; }
      } }`,
      'csharp',
    );
    const cfg = buildCFG(tree, 'csharp');
    // if + switch => two conditional blocks; if contributes true+false edges.
    expect(countType(cfg, 'conditional')).toBe(2);
    expect(countEdge(cfg, 'true')).toBeGreaterThanOrEqual(1);
    expect(countEdge(cfg, 'false')).toBeGreaterThanOrEqual(1);
  });

  it('models try/catch/finally with an exception edge', async () => {
    const tree = await parse(
      `class C { void M() { try { Risky(); } catch (Exception e) { Log(e); } finally { Clean(); } } }`,
      'csharp',
    );
    const cfg = buildCFG(tree, 'csharp');
    expect(countEdge(cfg, 'exception')).toBeGreaterThanOrEqual(1);
  });

  it('flows through using/lock scoped blocks without adding branches', async () => {
    const tree = await parse(
      `class C { void M(object o) { using (var r = Open()) { r.Read(); } lock (o) { Touch(); } } }`,
      'csharp',
    );
    const cfg = buildCFG(tree, 'csharp');
    // no branches — but the nested statements are still captured as blocks.
    expect(countType(cfg, 'conditional')).toBe(0);
    expect(countType(cfg, 'loop')).toBe(0);
    expect(cfg.blocks.length).toBeGreaterThanOrEqual(3);
  });
});
