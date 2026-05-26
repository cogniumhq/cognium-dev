/**
 * Tests for JavaScript/TypeScript type extraction
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';

describe('JavaScript Type Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Class Extraction', () => {
    it('should extract class declarations', async () => {
      const code = `
class UserService {
    constructor(db) {
        this.db = db;
    }

    getUser(id) {
        return this.db.find(id);
    }

    saveUser(user) {
        return this.db.save(user);
    }
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const userService = types.find(t => t.name === 'UserService');
      expect(userService).toBeDefined();
      expect(userService!.kind).toBe('class');

      expect(userService!.methods.length).toBeGreaterThanOrEqual(3);

      const constructor = userService!.methods.find(m => m.name === 'constructor');
      expect(constructor).toBeDefined();

      const getUser = userService!.methods.find(m => m.name === 'getUser');
      expect(getUser).toBeDefined();
    });

    it('should extract class with extends', async () => {
      const code = `
class AdminUser extends User {
    constructor(name) {
        super(name);
        this.isAdmin = true;
    }
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const adminUser = types.find(t => t.name === 'AdminUser');
      expect(adminUser).toBeDefined();
      expect(adminUser!.extends).toBe('User');
    });

    it('should extract static methods', async () => {
      const code = `
class Utils {
    static formatDate(date) {
        return date.toISOString();
    }

    static parseJSON(str) {
        return JSON.parse(str);
    }
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const utils = types.find(t => t.name === 'Utils');
      expect(utils).toBeDefined();

      const formatDate = utils!.methods.find(m => m.name === 'formatDate');
      expect(formatDate).toBeDefined();
      expect(formatDate!.modifiers).toContain('static');
    });

    it('should extract getters and setters', async () => {
      const code = `
class Person {
    get fullName() {
        return this.firstName + ' ' + this.lastName;
    }

    set fullName(value) {
        const parts = value.split(' ');
        this.firstName = parts[0];
        this.lastName = parts[1];
    }
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const person = types.find(t => t.name === 'Person');
      expect(person).toBeDefined();

      const getter = person!.methods.find(m => m.name === 'fullName' && m.modifiers.includes('getter'));
      expect(getter).toBeDefined();

      const setter = person!.methods.find(m => m.name === 'fullName' && m.modifiers.includes('setter'));
      expect(setter).toBeDefined();
    });
  });

  describe('Function Extraction', () => {
    it('should extract function declarations', async () => {
      const code = `
function greet(name) {
    return "Hello, " + name;
}

function add(a, b) {
    return a + b;
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const greet = moduleType!.methods.find(m => m.name === 'greet');
      expect(greet).toBeDefined();
      expect(greet!.parameters.length).toBe(1);
      expect(greet!.parameters[0].name).toBe('name');

      const add = moduleType!.methods.find(m => m.name === 'add');
      expect(add).toBeDefined();
      expect(add!.parameters.length).toBe(2);
    });

    it('should extract async functions', async () => {
      const code = `
async function fetchData(url) {
    const response = await fetch(url);
    return response.json();
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const fetchData = moduleType!.methods.find(m => m.name === 'fetchData');
      expect(fetchData).toBeDefined();
      expect(fetchData!.modifiers).toContain('async');
    });

    it('should extract arrow functions assigned to const', async () => {
      const code = `
const multiply = (a, b) => a * b;

const processData = async (data) => {
    return transform(data);
};
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const multiply = moduleType!.methods.find(m => m.name === 'multiply');
      expect(multiply).toBeDefined();
      expect(multiply!.parameters.length).toBe(2);

      const processData = moduleType!.methods.find(m => m.name === 'processData');
      expect(processData).toBeDefined();
      expect(processData!.modifiers).toContain('async');
    });
  });

  describe('Parameter Extraction', () => {
    it('should extract default parameters', async () => {
      const code = `
function greet(name = 'World', count = 1) {
    return name.repeat(count);
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const greet = moduleType!.methods.find(m => m.name === 'greet');
      expect(greet).toBeDefined();
      expect(greet!.parameters.length).toBe(2);
      expect(greet!.parameters[0].name).toBe('name');
      expect(greet!.parameters[1].name).toBe('count');
    });

    it('should extract rest parameters', async () => {
      const code = `
function sum(...numbers) {
    return numbers.reduce((a, b) => a + b, 0);
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const sum = moduleType!.methods.find(m => m.name === 'sum');
      expect(sum).toBeDefined();
      expect(sum!.parameters.length).toBe(1);
      expect(sum!.parameters[0].name).toBe('...numbers');
    });

    it('should extract destructuring parameters', async () => {
      const code = `
function handler({ params, query }) {
    return params.id + query.filter;
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const handler = moduleType!.methods.find(m => m.name === 'handler');
      expect(handler).toBeDefined();
      expect(handler!.parameters.length).toBe(1);
    });
  });

  describe('Express.js Patterns', () => {
    it('should extract Express route handlers', async () => {
      const code = `
class UserController {
    async getUser(req, res) {
        const user = await this.userService.findById(req.params.id);
        res.json(user);
    }

    async createUser(req, res) {
        const user = await this.userService.create(req.body);
        res.status(201).json(user);
    }
}
`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const controller = types.find(t => t.name === 'UserController');
      expect(controller).toBeDefined();

      const getUser = controller!.methods.find(m => m.name === 'getUser');
      expect(getUser).toBeDefined();
      expect(getUser!.parameters.length).toBe(2);
      expect(getUser!.parameters[0].name).toBe('req');
      expect(getUser!.parameters[1].name).toBe('res');
    });
  });

  describe('Line Numbers', () => {
    it('should track line numbers for types and methods', async () => {
      const code = `class Test {
    method1() {}
    method2() {}
}`;
      const tree = await parse(code, 'javascript');
      const types = extractTypes(tree, undefined, 'javascript');

      const testClass = types.find(t => t.name === 'Test');
      expect(testClass).toBeDefined();
      expect(testClass!.start_line).toBe(1);

      const method1 = testClass!.methods.find(m => m.name === 'method1');
      expect(method1).toBeDefined();
      expect(method1!.start_line).toBe(2);

      const method2 = testClass!.methods.find(m => m.name === 'method2');
      expect(method2).toBeDefined();
      expect(method2!.start_line).toBe(3);
    });
  });
});
