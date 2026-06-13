/**
 * Tests for MyBatis mapper-interface call classification (#24a).
 *
 * MyBatis mapper-interface methods (e.g. `UserMapper.selectByExample(...)`)
 * are not direct SQL sinks — the actual SQL lives in the mapper's XML or
 * `@Select`/`@Update` annotation binding. The call-site is only vulnerable
 * when the binding uses `${...}` string interpolation rather than `#{...}`
 * parameter binding. Reporting these as raw `sql_injection` produces
 * false positives.
 *
 * circle-ir 3.42.0 reclassifies the configured `*Mapper.<method>` patterns
 * from `sql_injection` → `mybatis_mapper_call` so downstream consumers can
 * route them differently (resolve the binding, downgrade severity, …).
 *
 * Closes cognium-dev#24 (MyBatis half — JSqlParser visitor remains in #24b).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig } from '../../src/analysis/config-loader.js';

async function sinksFor(code: string) {
  const tree = await parse(code, 'java');
  const calls = extractCalls(tree);
  const types = extractTypes(tree);
  const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');
  return taint.sinks;
}

describe('MyBatis mapper-interface reclassification (#24a)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('userMapper.insert(user) emits mybatis_mapper_call, not sql_injection', async () => {
    const code = `
public class Svc {
    public void run(UserMapper userMapper, User user) {
        userMapper.insert(user);
    }
}
`;
    const sinks = await sinksFor(code);
    const insertSinks = sinks.filter(s => s.method === 'insert');
    expect(insertSinks.length).toBe(1);
    expect(insertSinks[0].type).toBe('mybatis_mapper_call');
    expect(insertSinks[0].cwe).toBe('CWE-89');
    // Must not also report as raw sql_injection on the same call.
    expect(sinks.find(s => s.method === 'insert' && s.type === 'sql_injection')).toBeUndefined();
  });

  it('orderMapper.selectByExample(criteria) emits mybatis_mapper_call', async () => {
    const code = `
public class Svc {
    public Object run(OrderMapper orderMapper, OrderExample criteria) {
        return orderMapper.selectByExample(criteria);
    }
}
`;
    const sinks = await sinksFor(code);
    const hits = sinks.filter(s => s.method === 'selectByExample');
    expect(hits.length).toBe(1);
    expect(hits[0].type).toBe('mybatis_mapper_call');
  });

  it.each([
    'insertSelective',
    'update',
    'updateByPrimaryKey',
    'updateByPrimaryKeySelective',
    'delete',
    'deleteByPrimaryKey',
    'selectOne',
    'selectList',
    'selectByPrimaryKey',
  ])('userMapper.%s() emits mybatis_mapper_call', async (method) => {
    const code = `
public class Svc {
    public Object run(UserMapper userMapper, Object arg) {
        return userMapper.${method}(arg);
    }
}
`;
    const sinks = await sinksFor(code);
    const hits = sinks.filter(s => s.method === method);
    expect(hits.length).toBe(1);
    expect(hits[0].type).toBe('mybatis_mapper_call');
  });

  it('upper-cased UserMapper.insert(...) static-style call also matches the wildcard', async () => {
    const code = `
public class Svc {
    public void run(User user) {
        UserMapper.insert(user);
    }
}
`;
    const sinks = await sinksFor(code);
    const hits = sinks.filter(s => s.method === 'insert');
    expect(hits.length).toBe(1);
    expect(hits[0].type).toBe('mybatis_mapper_call');
  });

  it('Dotted receiver org.example.userMapper.insert(...) matches via simple-name', async () => {
    const code = `
public class Svc {
    public void run(User user) {
        org.example.userMapper.insert(user);
    }
}
`;
    const sinks = await sinksFor(code);
    const hits = sinks.filter(s => s.method === 'insert');
    expect(hits.length).toBe(1);
    expect(hits[0].type).toBe('mybatis_mapper_call');
  });

  it('Regression: Statement.execute(sql) still emits sql_injection (not mapper_call)', async () => {
    const code = `
public class Svc {
    public void run(Statement stmt, String sql) throws Exception {
        stmt.execute(sql);
    }
}
`;
    const sinks = await sinksFor(code);
    const hits = sinks.filter(s => s.method === 'execute');
    expect(hits.length).toBe(1);
    expect(hits[0].type).toBe('sql_injection');
  });

  it('Regression: JdbcTemplate.update(sql) still emits sql_injection', async () => {
    const code = `
public class Svc {
    public void run(JdbcTemplate jdbcTemplate, String sql) {
        jdbcTemplate.update(sql);
    }
}
`;
    const sinks = await sinksFor(code);
    const hits = sinks.filter(s => s.method === 'update');
    expect(hits.length).toBe(1);
    expect(hits[0].type).toBe('sql_injection');
  });

  it('Receiver not ending in "Mapper" does not match the wildcard', async () => {
    const code = `
public class Svc {
    public void run(UserService userService, User user) {
        userService.insert(user);
    }
}
`;
    const sinks = await sinksFor(code);
    // No *Mapper sink should fire. The "insert" method is only a sink for
    // class=*Mapper receivers; userService should not trigger it.
    const hits = sinks.filter(s => s.method === 'insert' && s.type === 'mybatis_mapper_call');
    expect(hits.length).toBe(0);
  });

  it('Method not in the mapper sink list does not match (e.g. userMapper.findById)', async () => {
    const code = `
public class Svc {
    public Object run(UserMapper userMapper, Long id) {
        return userMapper.findById(id);
    }
}
`;
    const sinks = await sinksFor(code);
    // findById is not in the configured *Mapper method list — no sink emitted.
    expect(sinks.find(s => s.method === 'findById')).toBeUndefined();
  });
});
