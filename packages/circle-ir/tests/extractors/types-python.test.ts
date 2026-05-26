/**
 * Tests for Python type extraction
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';

describe('Python Type Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Class Extraction', () => {
    it('should extract class declarations', async () => {
      const code = `
class UserService:
    def __init__(self, db):
        self.db = db

    def get_user(self, id):
        return self.db.find(id)

    def save_user(self, user):
        return self.db.save(user)
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const userService = types.find(t => t.name === 'UserService');
      expect(userService).toBeDefined();
      expect(userService!.kind).toBe('class');

      expect(userService!.methods.length).toBeGreaterThanOrEqual(3);

      const init = userService!.methods.find(m => m.name === '__init__');
      expect(init).toBeDefined();

      const getUser = userService!.methods.find(m => m.name === 'get_user');
      expect(getUser).toBeDefined();
    });

    it('should extract class with inheritance', async () => {
      const code = `
class AdminUser(User):
    def __init__(self, name):
        super().__init__(name)
        self.is_admin = True
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const adminUser = types.find(t => t.name === 'AdminUser');
      expect(adminUser).toBeDefined();
      expect(adminUser!.extends).toBe('User');
    });

    it('should extract class with multiple inheritance', async () => {
      const code = `
class MyClass(Base1, Base2, Mixin):
    pass
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const myClass = types.find(t => t.name === 'MyClass');
      expect(myClass).toBeDefined();
      expect(myClass!.extends).toBe('Base1');
      expect(myClass!.implements).toContain('Base2');
      expect(myClass!.implements).toContain('Mixin');
    });

    it('should extract static methods', async () => {
      const code = `
class Utils:
    @staticmethod
    def format_date(date):
        return date.isoformat()

    @classmethod
    def from_string(cls, s):
        return cls(s)
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const utils = types.find(t => t.name === 'Utils');
      expect(utils).toBeDefined();

      const formatDate = utils!.methods.find(m => m.name === 'format_date');
      expect(formatDate).toBeDefined();
      expect(formatDate!.annotations).toContain('staticmethod');

      const fromString = utils!.methods.find(m => m.name === 'from_string');
      expect(fromString).toBeDefined();
      expect(fromString!.annotations).toContain('classmethod');
    });

    it('should extract properties', async () => {
      const code = `
class Person:
    @property
    def full_name(self):
        return self.first_name + ' ' + self.last_name

    @full_name.setter
    def full_name(self, value):
        parts = value.split(' ')
        self.first_name = parts[0]
        self.last_name = parts[1]
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const person = types.find(t => t.name === 'Person');
      expect(person).toBeDefined();

      const getter = person!.methods.find(m => m.name === 'full_name' && m.annotations.includes('property'));
      expect(getter).toBeDefined();
    });
  });

  describe('Function Extraction', () => {
    it('should extract function declarations', async () => {
      const code = `
def greet(name):
    return "Hello, " + name

def add(a, b):
    return a + b
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

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
async def fetch_data(url):
    response = await aiohttp.get(url)
    return await response.json()
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const fetchData = moduleType!.methods.find(m => m.name === 'fetch_data');
      expect(fetchData).toBeDefined();
      expect(fetchData!.modifiers).toContain('async');
    });

    it('should extract decorated functions', async () => {
      const code = `
@app.route('/users')
def get_users():
    return users

@login_required
@cache(timeout=60)
def get_profile():
    return profile
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const getUsers = moduleType!.methods.find(m => m.name === 'get_users');
      expect(getUsers).toBeDefined();

      const getProfile = moduleType!.methods.find(m => m.name === 'get_profile');
      expect(getProfile).toBeDefined();
    });
  });

  describe('Parameter Extraction', () => {
    it('should extract default parameters', async () => {
      const code = `
def greet(name='World', count=1):
    return name * count
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const greet = moduleType!.methods.find(m => m.name === 'greet');
      expect(greet).toBeDefined();
      expect(greet!.parameters.length).toBe(2);
      expect(greet!.parameters[0].name).toBe('name');
      expect(greet!.parameters[1].name).toBe('count');
    });

    it('should extract *args and **kwargs', async () => {
      const code = `
def flexible(*args, **kwargs):
    return args, kwargs
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const flexible = moduleType!.methods.find(m => m.name === 'flexible');
      expect(flexible).toBeDefined();
      expect(flexible!.parameters.length).toBe(2);
    });

    it('should extract type-annotated parameters', async () => {
      const code = `
def process(data: str, count: int = 1) -> str:
    return data * count
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const moduleType = types.find(t => t.name === '<module>');
      expect(moduleType).toBeDefined();

      const process = moduleType!.methods.find(m => m.name === 'process');
      expect(process).toBeDefined();
      expect(process!.parameters.length).toBe(2);
      expect(process!.return_type).toBe('str');
    });
  });

  describe('Flask Patterns', () => {
    it('should extract Flask route handlers', async () => {
      const code = `
class UserController:
    def get_user(self, request):
        user = self.user_service.find_by_id(request.args.get('id'))
        return jsonify(user)

    def create_user(self, request):
        user = self.user_service.create(request.json)
        return jsonify(user), 201
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const controller = types.find(t => t.name === 'UserController');
      expect(controller).toBeDefined();

      const getUser = controller!.methods.find(m => m.name === 'get_user');
      expect(getUser).toBeDefined();
      expect(getUser!.parameters.length).toBe(2); // self + request
      expect(getUser!.parameters[1].name).toBe('request');
    });
  });

  describe('Line Numbers', () => {
    it('should track line numbers for types and methods', async () => {
      const code = `class Test:
    def method1(self):
        pass
    def method2(self):
        pass`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const testClass = types.find(t => t.name === 'Test');
      expect(testClass).toBeDefined();
      expect(testClass!.start_line).toBe(1);

      const method1 = testClass!.methods.find(m => m.name === 'method1');
      expect(method1).toBeDefined();
      expect(method1!.start_line).toBe(2);

      const method2 = testClass!.methods.find(m => m.name === 'method2');
      expect(method2).toBeDefined();
      expect(method2!.start_line).toBe(4);
    });
  });

  describe('Fields Extraction', () => {
    it('should extract class-level fields', async () => {
      const code = `
class Config:
    DEBUG = True
    DATABASE_URL = "sqlite:///app.db"
    MAX_CONNECTIONS = 10
`;
      const tree = await parse(code, 'python');
      const types = extractTypes(tree, undefined, 'python');

      const config = types.find(t => t.name === 'Config');
      expect(config).toBeDefined();
      expect(config!.fields.length).toBeGreaterThanOrEqual(3);

      const debug = config!.fields.find(f => f.name === 'DEBUG');
      expect(debug).toBeDefined();
    });
  });
});
