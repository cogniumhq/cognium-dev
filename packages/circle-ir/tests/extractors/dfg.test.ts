/**
 * Tests for DFG builder
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';

describe('DFG Builder', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract parameter definitions', async () => {
    const code = `
public class Test {
    public void method(String name, int count) {
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const paramDefs = dfg.defs.filter(d => d.kind === 'param');
    expect(paramDefs).toHaveLength(2);

    const nameDef = paramDefs.find(d => d.variable === 'name');
    expect(nameDef).toBeDefined();

    const countDef = paramDefs.find(d => d.variable === 'count');
    expect(countDef).toBeDefined();
  });

  it('should extract local variable definitions', async () => {
    const code = `
public class Test {
    public void method() {
        int x = 1;
        String s = "hello";
        double y = 2.0;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const localDefs = dfg.defs.filter(d => d.kind === 'local');
    expect(localDefs.length).toBeGreaterThanOrEqual(3);

    expect(localDefs.some(d => d.variable === 'x')).toBe(true);
    expect(localDefs.some(d => d.variable === 's')).toBe(true);
    expect(localDefs.some(d => d.variable === 'y')).toBe(true);
  });

  it('should extract field definitions', async () => {
    const code = `
public class Test {
    private String name;
    private int count;
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const fieldDefs = dfg.defs.filter(d => d.kind === 'field');
    expect(fieldDefs).toHaveLength(2);

    expect(fieldDefs.some(d => d.variable === 'name')).toBe(true);
    expect(fieldDefs.some(d => d.variable === 'count')).toBe(true);
  });

  it('should extract variable uses', async () => {
    const code = `
public class Test {
    public int method(int x) {
        int y = x + 1;
        return y;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have uses of x and y
    const xUses = dfg.uses.filter(u => u.variable === 'x');
    const yUses = dfg.uses.filter(u => u.variable === 'y');

    expect(xUses.length).toBeGreaterThanOrEqual(1);
    expect(yUses.length).toBeGreaterThanOrEqual(1);
  });

  it('should link uses to reaching definitions', async () => {
    const code = `
public class Test {
    public int method(int x) {
        int y = x + 1;
        return y;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Find the definition of x (parameter)
    const xDef = dfg.defs.find(d => d.variable === 'x' && d.kind === 'param');
    expect(xDef).toBeDefined();

    // Find the use of x in y = x + 1
    const xUse = dfg.uses.find(u => u.variable === 'x');
    expect(xUse).toBeDefined();
    expect(xUse!.def_id).toBe(xDef!.id);
  });

  it('should handle assignments as definitions', async () => {
    const code = `
public class Test {
    public void method() {
        int x = 1;
        x = 2;
        x = 3;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have 3 definitions of x
    const xDefs = dfg.defs.filter(d => d.variable === 'x');
    expect(xDefs.length).toBeGreaterThanOrEqual(3);
  });

  it('should handle increment/decrement as def and use', async () => {
    const code = `
public class Test {
    public void method() {
        int i = 0;
        i++;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // i++ is both a use and a def
    const iDefs = dfg.defs.filter(d => d.variable === 'i');
    const iUses = dfg.uses.filter(u => u.variable === 'i');

    expect(iDefs.length).toBeGreaterThanOrEqual(2); // declaration + increment
    expect(iUses.length).toBeGreaterThanOrEqual(1); // increment uses the value
  });

  it('should track line numbers', async () => {
    const code = `public class Test {
    public void method() {
        int x = 1;
        int y = x;
    }
}`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    const xDef = dfg.defs.find(d => d.variable === 'x');
    expect(xDef).toBeDefined();
    expect(xDef!.line).toBe(3);
  });

  it('should handle for loop variable', async () => {
    const code = `
public class Test {
    public void method() {
        for (int i = 0; i < 10; i++) {
            System.out.println(i);
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // For loop variables are tracked through uses at minimum
    // The variable i should appear in uses from the condition and body
    const iUses = dfg.uses.filter(u => u.variable === 'i');
    expect(iUses.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle enhanced for loop variable', async () => {
    const code = `
public class Test {
    public void method(List<String> items) {
        for (String item : items) {
            System.out.println(item);
        }
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have definition for item
    const itemDefs = dfg.defs.filter(d => d.variable === 'item');
    expect(itemDefs.length).toBeGreaterThanOrEqual(1);
  });

  it('should compute DFG chains', async () => {
    const code = `
public class Test {
    public int method(int x) {
        int y = x + 1;
        int z = y * 2;
        return z;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    // Should have chains
    expect(dfg.chains).toBeDefined();
    expect(dfg.chains!.length).toBeGreaterThanOrEqual(1);

    // Should have chain from x to y
    const xDef = dfg.defs.find(d => d.variable === 'x' && d.kind === 'param');
    const yDef = dfg.defs.find(d => d.variable === 'y');
    expect(xDef).toBeDefined();
    expect(yDef).toBeDefined();

    const xToYChain = dfg.chains!.find(
      c => c.from_def === xDef!.id && c.to_def === yDef!.id && c.via === 'x'
    );
    expect(xToYChain).toBeDefined();

    // Should have chain from y to z
    const zDef = dfg.defs.find(d => d.variable === 'z');
    expect(zDef).toBeDefined();

    const yToZChain = dfg.chains!.find(
      c => c.from_def === yDef!.id && c.to_def === zDef!.id && c.via === 'y'
    );
    expect(yToZChain).toBeDefined();
  });

  it('should handle chains with multiple uses in same definition', async () => {
    const code = `
public class Test {
    public int method(int a, int b) {
        int sum = a + b;
        return sum;
    }
}
`;
    const tree = await parse(code, 'java');
    const dfg = buildDFG(tree);

    expect(dfg.chains).toBeDefined();

    // Should have chains from a and b to sum
    const aDef = dfg.defs.find(d => d.variable === 'a');
    const bDef = dfg.defs.find(d => d.variable === 'b');
    const sumDef = dfg.defs.find(d => d.variable === 'sum');

    expect(aDef).toBeDefined();
    expect(bDef).toBeDefined();
    expect(sumDef).toBeDefined();

    const aToSumChain = dfg.chains!.find(
      c => c.from_def === aDef!.id && c.to_def === sumDef!.id
    );
    const bToSumChain = dfg.chains!.find(
      c => c.from_def === bDef!.id && c.to_def === sumDef!.id
    );

    expect(aToSumChain).toBeDefined();
    expect(bToSumChain).toBeDefined();
  });
});

describe('JavaScript DFG', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract top-level const/let declarations', async () => {
    const code = `const x = 5;\nlet y = x;`;
    const tree = await parse(code, 'javascript');
    const dfg = buildDFG(tree, undefined, 'javascript');

    const xDef = dfg.defs.find(d => d.variable === 'x');
    expect(xDef).toBeDefined();
    expect(xDef!.kind).toBe('local');

    const yDef = dfg.defs.find(d => d.variable === 'y');
    expect(yDef).toBeDefined();
    expect(yDef!.kind).toBe('local');
  });

  it('should track use of top-level variable in subsequent declaration', async () => {
    const code = `const x = 5;\nconst y = x + 1;`;
    const tree = await parse(code, 'javascript');
    const dfg = buildDFG(tree, undefined, 'javascript');

    const xDef = dfg.defs.find(d => d.variable === 'x');
    const xUse = dfg.uses.find(u => u.variable === 'x');

    expect(xDef).toBeDefined();
    expect(xUse).toBeDefined();
    expect(xUse!.def_id).toBe(xDef!.id);
  });

  it('should create def-use chain for top-level declarations', async () => {
    const code = `const x = 5;\nconst y = x;`;
    const tree = await parse(code, 'javascript');
    const dfg = buildDFG(tree, undefined, 'javascript');

    expect(dfg.chains).toBeDefined();
    const xDef = dfg.defs.find(d => d.variable === 'x');
    const yDef = dfg.defs.find(d => d.variable === 'y');

    const chain = dfg.chains!.find(c => c.from_def === xDef!.id && c.to_def === yDef!.id);
    expect(chain).toBeDefined();
    expect(chain!.via).toBe('x');
  });

  it('should extract object destructuring parameters', async () => {
    const code = `function handler({ name, age }) { return name; }`;
    const tree = await parse(code, 'javascript');
    const dfg = buildDFG(tree, undefined, 'javascript');

    const nameDef = dfg.defs.find(d => d.variable === 'name');
    expect(nameDef).toBeDefined();
    expect(nameDef!.kind).toBe('param');

    const ageDef = dfg.defs.find(d => d.variable === 'age');
    expect(ageDef).toBeDefined();
    expect(ageDef!.kind).toBe('param');
  });

  it('should extract for-in loop variable definition', async () => {
    const code = `function process(obj) { for (const key in obj) { console.log(key); } }`;
    const tree = await parse(code, 'javascript');
    const dfg = buildDFG(tree, undefined, 'javascript');

    const keyDef = dfg.defs.find(d => d.variable === 'key');
    expect(keyDef).toBeDefined();
    expect(keyDef!.kind).toBe('local');

    const keyUses = dfg.uses.filter(u => u.variable === 'key');
    expect(keyUses.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Python DFG', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should return a valid DFG structure for Python code', async () => {
    const code = `
def foo(x):
    y = x + 1
    return y
`;
    const tree = await parse(code, 'python');
    const dfg = buildDFG(tree, undefined, 'python');

    expect(dfg).toBeDefined();
    expect(Array.isArray(dfg.defs)).toBe(true);
    expect(Array.isArray(dfg.uses)).toBe(true);
  });

  it('should return empty defs for plain Python assignments (not yet supported)', async () => {
    const code = `x = 5\ny = x + 1`;
    const tree = await parse(code, 'python');
    const dfg = buildDFG(tree, undefined, 'python');

    // Python variable assignments are not currently extracted by the DFG builder
    expect(dfg.defs.length).toBe(0);
    expect(dfg.uses.length).toBe(0);
  });

  it('should return empty defs for Python function definitions (not yet supported)', async () => {
    const code = `
def greet(name):
    message = "Hello, " + name
    return message
`;
    const tree = await parse(code, 'python');
    const dfg = buildDFG(tree, undefined, 'python');

    // Python function params and local vars are not currently extracted
    expect(dfg.defs.length).toBe(0);
  });

  it('should return a valid chains array for Python code', async () => {
    const code = `z = 10`;
    const tree = await parse(code, 'python');
    const dfg = buildDFG(tree, undefined, 'python');

    expect(Array.isArray(dfg.chains)).toBe(true);
  });
});

describe('Rust DFG', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract function parameters as param defs', async () => {
    const code = `fn add(x: i32, y: i32) -> i32 { x + y }`;
    const tree = await parse(code, 'rust');
    const dfg = buildDFG(tree, undefined, 'rust');

    const xDef = dfg.defs.find(d => d.variable === 'x');
    expect(xDef).toBeDefined();
    expect(xDef!.kind).toBe('param');

    const yDef = dfg.defs.find(d => d.variable === 'y');
    expect(yDef).toBeDefined();
    expect(yDef!.kind).toBe('param');
  });

  it('should extract let bindings as local defs', async () => {
    const code = `fn process(input: i32) -> i32 {\n    let result = input + 1;\n    result\n}`;
    const tree = await parse(code, 'rust');
    const dfg = buildDFG(tree, undefined, 'rust');

    const inputDef = dfg.defs.find(d => d.variable === 'input');
    expect(inputDef).toBeDefined();
    expect(inputDef!.kind).toBe('param');

    const resultDef = dfg.defs.find(d => d.variable === 'result');
    expect(resultDef).toBeDefined();
    expect(resultDef!.kind).toBe('local');
  });

  it('should link uses to their reaching definitions', async () => {
    const code = `fn compute(a: i32) -> i32 {\n    let b = a + 1;\n    b\n}`;
    const tree = await parse(code, 'rust');
    const dfg = buildDFG(tree, undefined, 'rust');

    const aDef = dfg.defs.find(d => d.variable === 'a' && d.kind === 'param');
    expect(aDef).toBeDefined();

    const aUse = dfg.uses.find(u => u.variable === 'a');
    expect(aUse).toBeDefined();
    expect(aUse!.def_id).toBe(aDef!.id);
  });

  it('should extract mutable variable reassignment as new def', async () => {
    const code = `fn counter() {\n    let mut count = 0;\n    count = count + 1;\n}`;
    const tree = await parse(code, 'rust');
    const dfg = buildDFG(tree, undefined, 'rust');

    const countDefs = dfg.defs.filter(d => d.variable === 'count');
    expect(countDefs.length).toBeGreaterThanOrEqual(2);
  });

  it('should compute def-use chains for Rust let bindings', async () => {
    const code = `fn flow(x: i32) -> i32 {\n    let y = x;\n    let z = y + 1;\n    z\n}`;
    const tree = await parse(code, 'rust');
    const dfg = buildDFG(tree, undefined, 'rust');

    expect(dfg.chains).toBeDefined();
    expect(dfg.chains!.length).toBeGreaterThanOrEqual(1);

    const xDef = dfg.defs.find(d => d.variable === 'x');
    const yDef = dfg.defs.find(d => d.variable === 'y');
    expect(xDef).toBeDefined();
    expect(yDef).toBeDefined();

    const xToYChain = dfg.chains!.find(
      c => c.from_def === xDef!.id && c.to_def === yDef!.id && c.via === 'x'
    );
    expect(xToYChain).toBeDefined();
  });
});
