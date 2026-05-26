/**
 * Tests for JavaScript/TypeScript DFG (Data Flow Graph) builder
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';

describe('JavaScript DFG Builder', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Variable Declarations', () => {
    it('should extract const/let variable definitions', async () => {
      const code = `
const x = 10;
let y = 20;
var z = 30;
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      expect(dfg.defs.length).toBeGreaterThanOrEqual(3);

      const xDef = dfg.defs.find(d => d.variable === 'x');
      expect(xDef).toBeDefined();
      expect(xDef!.kind).toBe('local');

      const yDef = dfg.defs.find(d => d.variable === 'y');
      expect(yDef).toBeDefined();

      const zDef = dfg.defs.find(d => d.variable === 'z');
      expect(zDef).toBeDefined();
    });

    it('should track variable uses', async () => {
      const code = `
const x = 10;
const y = x + 5;
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const xDef = dfg.defs.find(d => d.variable === 'x');
      const xUse = dfg.uses.find(u => u.variable === 'x');

      expect(xDef).toBeDefined();
      expect(xUse).toBeDefined();
      expect(xUse!.def_id).toBe(xDef!.id);
    });
  });

  describe('Function Declarations', () => {
    it('should extract function parameters as definitions', async () => {
      const code = `
function greet(name, age) {
    console.log(name);
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const nameDef = dfg.defs.find(d => d.variable === 'name');
      expect(nameDef).toBeDefined();
      expect(nameDef!.kind).toBe('param');

      const ageDef = dfg.defs.find(d => d.variable === 'age');
      expect(ageDef).toBeDefined();
      expect(ageDef!.kind).toBe('param');
    });

    it('should extract local variables in function body', async () => {
      const code = `
function process(input) {
    const result = input + 1;
    return result;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const inputDef = dfg.defs.find(d => d.variable === 'input');
      expect(inputDef).toBeDefined();
      expect(inputDef!.kind).toBe('param');

      const resultDef = dfg.defs.find(d => d.variable === 'result');
      expect(resultDef).toBeDefined();
      expect(resultDef!.kind).toBe('local');
    });
  });

  describe('Arrow Functions', () => {
    it('should extract arrow function parameters', async () => {
      const code = `
const add = (a, b) => a + b;
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const aDef = dfg.defs.find(d => d.variable === 'a');
      expect(aDef).toBeDefined();
      expect(aDef!.kind).toBe('param');

      const bDef = dfg.defs.find(d => d.variable === 'b');
      expect(bDef).toBeDefined();
    });

    it('should extract variables in arrow function body', async () => {
      const code = `
const processData = (data) => {
    const processed = transform(data);
    return processed;
};
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const dataDef = dfg.defs.find(d => d.variable === 'data');
      expect(dataDef).toBeDefined();
      expect(dataDef!.kind).toBe('param');

      const processedDef = dfg.defs.find(d => d.variable === 'processed');
      expect(processedDef).toBeDefined();
    });
  });

  describe('Destructuring', () => {
    it('should extract object destructuring definitions', async () => {
      const code = `
function handler(req) {
    const { params, query, body } = req;
    return params;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const paramsDef = dfg.defs.find(d => d.variable === 'params');
      expect(paramsDef).toBeDefined();

      const queryDef = dfg.defs.find(d => d.variable === 'query');
      expect(queryDef).toBeDefined();

      const bodyDef = dfg.defs.find(d => d.variable === 'body');
      expect(bodyDef).toBeDefined();
    });

    it('should extract array destructuring definitions', async () => {
      const code = `
function process(arr) {
    const [first, second, ...rest] = arr;
    return first;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const firstDef = dfg.defs.find(d => d.variable === 'first');
      expect(firstDef).toBeDefined();

      const secondDef = dfg.defs.find(d => d.variable === 'second');
      expect(secondDef).toBeDefined();

      const restDef = dfg.defs.find(d => d.variable === 'rest');
      expect(restDef).toBeDefined();
    });
  });

  describe('Express.js Patterns', () => {
    it('should track data flow in Express route handlers', async () => {
      const code = `
app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    db.query('SELECT * FROM users WHERE id = ' + id);
});
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const reqDef = dfg.defs.find(d => d.variable === 'req');
      expect(reqDef).toBeDefined();
      expect(reqDef!.kind).toBe('param');

      const idDef = dfg.defs.find(d => d.variable === 'id');
      expect(idDef).toBeDefined();
    });
  });

  describe('Control Flow', () => {
    it('should track definitions in if statements', async () => {
      const code = `
function process(input) {
    let result;
    if (input > 0) {
        result = input * 2;
    } else {
        result = 0;
    }
    return result;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const resultDefs = dfg.defs.filter(d => d.variable === 'result');
      // Should have definitions in both branches
      expect(resultDefs.length).toBeGreaterThanOrEqual(2);
    });

    it('should track definitions in for-of loops', async () => {
      const code = `
function processItems(items) {
    for (const item of items) {
        console.log(item);
    }
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const itemDef = dfg.defs.find(d => d.variable === 'item');
      expect(itemDef).toBeDefined();
      expect(itemDef!.kind).toBe('local');
    });
  });

  describe('Assignment Expressions', () => {
    it('should track reassignments', async () => {
      const code = `
function process(x) {
    let y = x;
    y = y + 1;
    return y;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const yDefs = dfg.defs.filter(d => d.variable === 'y');
      expect(yDefs.length).toBeGreaterThanOrEqual(2);
    });

    it('should track update expressions (++/--)', async () => {
      const code = `
function counter(start) {
    let count = start;
    count++;
    return count;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const countDefs = dfg.defs.filter(d => d.variable === 'count');
      // Initial def + update def
      expect(countDefs.length).toBeGreaterThanOrEqual(2);

      const countUses = dfg.uses.filter(u => u.variable === 'count');
      expect(countUses.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Def-Use Chains', () => {
    it('should compute def-use chains', async () => {
      const code = `
function transform(input) {
    const x = input;
    const y = x + 1;
    return y;
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      expect(dfg.chains.length).toBeGreaterThan(0);

      const inputDef = dfg.defs.find(d => d.variable === 'input');
      const xDef = dfg.defs.find(d => d.variable === 'x');

      // Should have chain from input -> x
      const inputToXChain = dfg.chains.find(
        c => c.from_def === inputDef?.id && c.to_def === xDef?.id
      );
      expect(inputToXChain).toBeDefined();
    });
  });

  describe('Class Methods', () => {
    it('should extract definitions from class methods', async () => {
      const code = `
class UserService {
    getUser(id) {
        const user = this.db.find(id);
        return user;
    }
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const idDef = dfg.defs.find(d => d.variable === 'id');
      expect(idDef).toBeDefined();
      expect(idDef!.kind).toBe('param');

      const userDef = dfg.defs.find(d => d.variable === 'user');
      expect(userDef).toBeDefined();
    });
  });

  describe('Default Parameters', () => {
    it('should extract parameters with default values', async () => {
      const code = `
function greet(name = 'World', count = 1) {
    console.log(name);
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const nameDef = dfg.defs.find(d => d.variable === 'name');
      expect(nameDef).toBeDefined();
      expect(nameDef!.kind).toBe('param');

      const countDef = dfg.defs.find(d => d.variable === 'count');
      expect(countDef).toBeDefined();
    });
  });

  describe('Rest Parameters', () => {
    it('should extract rest parameters', async () => {
      const code = `
function sum(...numbers) {
    return numbers.reduce((a, b) => a + b, 0);
}
`;
      const tree = await parse(code, 'javascript');
      const dfg = buildDFG(tree, undefined, 'javascript');

      const numbersDef = dfg.defs.find(d => d.variable === 'numbers');
      expect(numbersDef).toBeDefined();
      expect(numbersDef!.kind).toBe('param');
    });
  });
});
