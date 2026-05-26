/**
 * Tests for Type extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';

describe('Type Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('should extract class with methods and fields', async () => {
    const code = `
package com.example;

public class UserService {
    private String name;
    private int count;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    expect(types).toHaveLength(1);

    const userService = types[0];
    expect(userService.name).toBe('UserService');
    expect(userService.kind).toBe('class');
    expect(userService.package).toBe('com.example');

    // Check fields
    expect(userService.fields).toHaveLength(2);
    expect(userService.fields[0].name).toBe('name');
    expect(userService.fields[0].type).toBe('String');
    expect(userService.fields[0].modifiers).toContain('private');

    // Check methods
    expect(userService.methods).toHaveLength(2);
    expect(userService.methods[0].name).toBe('getName');
    expect(userService.methods[0].return_type).toBe('String');
    expect(userService.methods[1].name).toBe('setName');
    expect(userService.methods[1].parameters).toHaveLength(1);
    expect(userService.methods[1].parameters[0].name).toBe('name');
    expect(userService.methods[1].parameters[0].type).toBe('String');
  });

  it('should extract class with annotations', async () => {
    const code = `
@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {
        return null;
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    expect(types).toHaveLength(1);

    const controller = types[0];
    expect(controller.annotations).toContain('RestController');
    expect(controller.annotations.some(a => a.includes('RequestMapping'))).toBe(true);

    const method = controller.methods[0];
    expect(method.annotations.some(a => a.includes('GetMapping'))).toBe(true);
    expect(method.parameters[0].annotations).toContain('PathVariable');
  });

  it('should extract interface', async () => {
    const code = `
public interface UserRepository {
    User findById(Long id);
    List<User> findAll();
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    expect(types).toHaveLength(1);
    expect(types[0].kind).toBe('interface');
    expect(types[0].name).toBe('UserRepository');
    expect(types[0].methods).toHaveLength(2);
  });

  it('should extract enum', async () => {
    const code = `
public enum Status {
    ACTIVE,
    INACTIVE;

    public boolean isActive() {
        return this == ACTIVE;
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    expect(types).toHaveLength(1);
    expect(types[0].kind).toBe('enum');
    expect(types[0].name).toBe('Status');
  });

  it('should extract class hierarchy', async () => {
    const code = `
public class UserController extends BaseController implements Auditable {
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    expect(types).toHaveLength(1);
    expect(types[0].extends).toBe('BaseController');
    expect(types[0].implements).toContain('Auditable');
  });

  it('should extract constructor', async () => {
    const code = `
public class User {
    private String name;

    public User(String name) {
        this.name = name;
    }
}
`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    const methods = types[0].methods;
    expect(methods).toHaveLength(1);
    expect(methods[0].name).toBe('User');
    expect(methods[0].return_type).toBeNull();
  });

  it('should capture line numbers', async () => {
    const code = `public class Test {
    public void method() {
    }
}`;
    const tree = await parse(code, 'java');
    const types = extractTypes(tree);

    expect(types[0].start_line).toBe(1);
    expect(types[0].end_line).toBe(4);
    expect(types[0].methods[0].start_line).toBe(2);
    expect(types[0].methods[0].end_line).toBe(3);
  });
});

describe('Rust Type Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Struct Extraction', () => {
    it('should extract a public struct with fields', async () => {
      const code = `
pub struct User {
    pub name: String,
    age: u32,
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const user = types.find(t => t.name === 'User');
      expect(user).toBeDefined();
      expect(user!.kind).toBe('class');
      expect(user!.annotations).toContain('pub');

      expect(user!.fields).toHaveLength(2);
      const nameField = user!.fields.find(f => f.name === 'name');
      expect(nameField).toBeDefined();
      expect(nameField!.type).toBe('String');
      expect(nameField!.modifiers).toContain('pub');

      const ageField = user!.fields.find(f => f.name === 'age');
      expect(ageField).toBeDefined();
      expect(ageField!.type).toBe('u32');
    });

    it('should extract struct derives as annotations', async () => {
      const code = `
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    x: f64,
    y: f64,
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const point = types.find(t => t.name === 'Point');
      expect(point).toBeDefined();
      expect(point!.annotations).toContain('derive(Debug)');
      expect(point!.annotations).toContain('derive(Clone)');
      expect(point!.annotations).toContain('derive(PartialEq)');
    });

    it('should extract a private struct with no fields', async () => {
      const code = `
struct Empty {}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const empty = types.find(t => t.name === 'Empty');
      expect(empty).toBeDefined();
      expect(empty!.kind).toBe('class');
      expect(empty!.fields).toHaveLength(0);
      // No visibility modifier → not annotated with 'pub'
      expect(empty!.annotations).not.toContain('pub');
    });
  });

  describe('Enum Extraction', () => {
    it('should extract an enum with variants', async () => {
      const code = `
pub enum Direction {
    North,
    South,
    East,
    West,
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const dir = types.find(t => t.name === 'Direction');
      expect(dir).toBeDefined();
      expect(dir!.kind).toBe('enum');
      expect(dir!.annotations).toContain('pub');

      const fieldNames = dir!.fields.map(f => f.name);
      expect(fieldNames).toContain('North');
      expect(fieldNames).toContain('South');
      expect(fieldNames).toContain('East');
      expect(fieldNames).toContain('West');
    });

    it('should extract enum with derive macros', async () => {
      const code = `
#[derive(Debug, Clone)]
enum Status {
    Active,
    Inactive,
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const status = types.find(t => t.name === 'Status');
      expect(status).toBeDefined();
      expect(status!.kind).toBe('enum');
      expect(status!.annotations).toContain('derive(Debug)');
      expect(status!.annotations).toContain('derive(Clone)');

      expect(status!.fields.map(f => f.name)).toContain('Active');
      expect(status!.fields.map(f => f.name)).toContain('Inactive');
    });
  });

  describe('Trait Extraction', () => {
    it('should extract a trait as interface kind', async () => {
      const code = `
pub trait Greet {
    fn hello(&self) -> String;
    fn goodbye(&self) -> String;
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const greet = types.find(t => t.name === 'Greet');
      expect(greet).toBeDefined();
      expect(greet!.kind).toBe('interface');
      expect(greet!.methods).toHaveLength(2);

      const hello = greet!.methods.find(m => m.name === 'hello');
      expect(hello).toBeDefined();
      expect(hello!.return_type).toBe('String');
    });
  });

  describe('Impl Block Extraction', () => {
    it('should merge impl methods into the corresponding struct', async () => {
      const code = `
pub struct Counter {
    value: i32,
}

impl Counter {
    pub fn new() -> Self {
        Counter { value: 0 }
    }

    pub fn increment(&mut self) {
        self.value += 1;
    }

    pub fn get(&self) -> i32 {
        self.value
    }
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const counter = types.find(t => t.name === 'Counter');
      expect(counter).toBeDefined();
      expect(counter!.kind).toBe('class');

      const methodNames = counter!.methods.map(m => m.name);
      expect(methodNames).toContain('new');
      expect(methodNames).toContain('increment');
      expect(methodNames).toContain('get');
    });

    it('should record trait impl on the struct implements list', async () => {
      const code = `
pub struct MyStruct;

impl Display for MyStruct {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "MyStruct")
    }
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const myStruct = types.find(t => t.name === 'MyStruct');
      expect(myStruct).toBeDefined();
      expect(myStruct!.implements).toContain('Display');
    });

    it('should create a synthetic type for impl with no prior struct', async () => {
      const code = `
impl Standalone {
    fn do_thing(&self) {}
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const standalone = types.find(t => t.name === 'Standalone');
      expect(standalone).toBeDefined();
      expect(standalone!.kind).toBe('class');
      expect(standalone!.methods.map(m => m.name)).toContain('do_thing');
    });
  });

  describe('Standalone Functions', () => {
    it('should collect top-level functions into a <module> type', async () => {
      const code = `
fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn greet(name: &str) -> String {
    format!("Hello, {}", name)
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const module = types.find(t => t.name === '<module>');
      expect(module).toBeDefined();
      expect(module!.kind).toBe('class');

      const add = module!.methods.find(m => m.name === 'add');
      expect(add).toBeDefined();
      expect(add!.return_type).toBe('i32');
      expect(add!.parameters).toHaveLength(2);
      expect(add!.parameters[0].name).toBe('a');
      expect(add!.parameters[0].type).toBe('i32');

      const greet = module!.methods.find(m => m.name === 'greet');
      expect(greet).toBeDefined();
      expect(greet!.return_type).toBe('String');
    });

    it('should mark async functions with the async modifier', async () => {
      const code = `
async fn fetch(url: &str) -> Result<String, Error> {
    reqwest::get(url).await?.text().await
}
`;
      const tree = await parse(code, 'rust');
      const types = extractTypes(tree, undefined, 'rust');

      const module = types.find(t => t.name === '<module>');
      expect(module).toBeDefined();

      const fetch = module!.methods.find(m => m.name === 'fetch');
      expect(fetch).toBeDefined();
      expect(fetch!.modifiers).toContain('async');
    });
  });
});
