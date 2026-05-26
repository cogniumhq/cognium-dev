/**
 * Tests for Python Call extractor
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';

describe('Python Call Extractor', () => {
  beforeAll(async () => {
    await initParser();
  });

  describe('Basic Function Calls', () => {
    it('should extract simple function calls', async () => {
      const code = `
result = do_something()
print("hello")
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      expect(calls.length).toBeGreaterThanOrEqual(2);

      const doSomethingCall = calls.find(c => c.method_name === 'do_something');
      expect(doSomethingCall).toBeDefined();

      const printCall = calls.find(c => c.method_name === 'print');
      expect(printCall).toBeDefined();
    });

    it('should extract method calls with receiver', async () => {
      const code = `
id = request.args.get("id")
data = response.json()
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const getCall = calls.find(c => c.method_name === 'get');
      expect(getCall).toBeDefined();
      expect(getCall!.receiver).toBe('request.args');

      const jsonCall = calls.find(c => c.method_name === 'json');
      expect(jsonCall).toBeDefined();
      expect(jsonCall!.receiver).toBe('response');
    });

    it('should extract function call arguments', async () => {
      const code = `
do_something("literal", variable, obj.field)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      expect(calls).toHaveLength(1);
      expect(calls[0].arguments).toHaveLength(3);

      // First arg: string literal
      expect(calls[0].arguments[0].position).toBe(0);
      expect(calls[0].arguments[0].literal).toBe('literal');

      // Second arg: variable
      expect(calls[0].arguments[1].position).toBe(1);
      expect(calls[0].arguments[1].variable).toBe('variable');
    });
  });

  describe('Constructor Calls', () => {
    it('should extract class instantiations', async () => {
      const code = `
date = datetime.now()
arr = list()
obj = MyClass("arg1", arg2)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const nowCall = calls.find(c => c.method_name === 'now');
      expect(nowCall).toBeDefined();
      expect(nowCall!.receiver).toBe('datetime');

      const listCall = calls.find(c => c.method_name === 'list');
      expect(listCall).toBeDefined();

      const myClassCall = calls.find(c => c.method_name === 'MyClass');
      expect(myClassCall).toBeDefined();
      expect(myClassCall!.arguments).toHaveLength(2);
    });
  });

  describe('Flask Patterns', () => {
    it('should extract Flask route handler calls', async () => {
      const code = `
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/users/<id>')
def get_user(id):
    user = db.query("SELECT * FROM users WHERE id = " + id)
    return jsonify(user)

@app.route('/users', methods=['POST'])
def create_user():
    body = request.json
    return jsonify(body), 201
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const flaskCall = calls.find(c => c.method_name === 'Flask');
      expect(flaskCall).toBeDefined();

      const queryCall = calls.find(c => c.method_name === 'query');
      expect(queryCall).toBeDefined();
      expect(queryCall!.receiver).toBe('db');

      const jsonifyCalls = calls.filter(c => c.method_name === 'jsonify');
      expect(jsonifyCalls.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract database query calls', async () => {
      const code = `
def get_user(id):
    query = "SELECT * FROM users WHERE id = " + id
    cursor.execute(query)
    return cursor.fetchone()
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const executeCall = calls.find(c => c.method_name === 'execute');
      expect(executeCall).toBeDefined();
      expect(executeCall!.receiver).toBe('cursor');

      const fetchoneCall = calls.find(c => c.method_name === 'fetchone');
      expect(fetchoneCall).toBeDefined();
    });

    it('should extract subprocess calls', async () => {
      const code = `
import subprocess

def ping(host):
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True)
    return result.stdout
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const runCall = calls.find(c => c.method_name === 'run');
      expect(runCall).toBeDefined();
      expect(runCall!.receiver).toBe('subprocess');
    });

    it('should extract os.system and os.popen calls', async () => {
      const code = `
import os

def execute_command(cmd):
    os.system(cmd)
    result = os.popen(cmd).read()
    return result
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const systemCall = calls.find(c => c.method_name === 'system');
      expect(systemCall).toBeDefined();
      expect(systemCall!.receiver).toBe('os');

      const popenCall = calls.find(c => c.method_name === 'popen');
      expect(popenCall).toBeDefined();
      expect(popenCall!.receiver).toBe('os');
    });

    it('should extract file operations', async () => {
      const code = `
def read_file(filename):
    with open(filename) as f:
        return f.read()
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const openCall = calls.find(c => c.method_name === 'open');
      expect(openCall).toBeDefined();

      const readCall = calls.find(c => c.method_name === 'read');
      expect(readCall).toBeDefined();
    });
  });

  describe('Lambda and Comprehensions', () => {
    it('should extract calls in lambda functions', async () => {
      const code = `
process = lambda x: transform(x)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const transformCall = calls.find(c => c.method_name === 'transform');
      expect(transformCall).toBeDefined();
    });

    it('should extract calls in list comprehensions', async () => {
      const code = `
result = [process(x) for x in items]
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const processCall = calls.find(c => c.method_name === 'process');
      expect(processCall).toBeDefined();
    });
  });

  describe('Chained Method Calls', () => {
    it('should extract chained method calls', async () => {
      const code = `
result = (
    db.query()
    .filter(User.active == True)
    .order_by(User.name)
    .all()
)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const queryCall = calls.find(c => c.method_name === 'query');
      expect(queryCall).toBeDefined();

      const filterCall = calls.find(c => c.method_name === 'filter');
      expect(filterCall).toBeDefined();

      const allCall = calls.find(c => c.method_name === 'all');
      expect(allCall).toBeDefined();
    });
  });

  describe('Class Methods', () => {
    it('should extract calls from class methods', async () => {
      const code = `
class UserService:
    def __init__(self, db):
        self.db = db

    def get_user(self, id):
        return self.db.query('SELECT * FROM users WHERE id = ?', [id])

    def save_user(self, user):
        return self.db.insert('users', user)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const queryCall = calls.find(c => c.method_name === 'query');
      expect(queryCall).toBeDefined();
      expect(queryCall!.in_method).toBe('get_user');

      const insertCall = calls.find(c => c.method_name === 'insert');
      expect(insertCall).toBeDefined();
      expect(insertCall!.in_method).toBe('save_user');
    });
  });

  describe('Async/Await Patterns', () => {
    it('should extract calls in async functions', async () => {
      const code = `
async def fetch_data(url):
    response = await aiohttp.get(url)
    data = await response.json()
    return data
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const getCall = calls.find(c => c.method_name === 'get');
      expect(getCall).toBeDefined();
      expect(getCall!.in_method).toBe('fetch_data');

      const jsonCall = calls.find(c => c.method_name === 'json');
      expect(jsonCall).toBeDefined();
    });
  });

  describe('Dangerous Calls', () => {
    it('should extract eval and exec calls', async () => {
      const code = `
def dangerous(code):
    eval(code)
    exec(code)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const evalCall = calls.find(c => c.method_name === 'eval');
      expect(evalCall).toBeDefined();

      const execCall = calls.find(c => c.method_name === 'exec');
      expect(execCall).toBeDefined();
    });

    it('should extract pickle loads calls', async () => {
      const code = `
import pickle

def deserialize(data):
    return pickle.loads(data)
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      const loadsCall = calls.find(c => c.method_name === 'loads');
      expect(loadsCall).toBeDefined();
      expect(loadsCall!.receiver).toBe('pickle');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty function calls', async () => {
      const code = `
init()
setup()
teardown()
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      expect(calls.length).toBe(3);
      calls.forEach(call => {
        expect(call.arguments).toHaveLength(0);
      });
    });

    it('should handle keyword arguments', async () => {
      const code = `
connect(host="localhost", port=5432, user="admin")
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      expect(calls.length).toBe(1);
      expect(calls[0].arguments.length).toBe(3);
    });

    it('should handle f-strings in arguments', async () => {
      const code = `
print(f"Hello, {name}!")
db.query(f"SELECT * FROM users WHERE id = {id}")
`;
      const tree = await parse(code, 'python');
      const calls = extractCalls(tree, undefined, 'python');

      expect(calls.length).toBeGreaterThanOrEqual(2);
    });
  });
});
