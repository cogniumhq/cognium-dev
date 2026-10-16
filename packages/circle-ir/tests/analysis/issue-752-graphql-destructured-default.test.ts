/**
 * cognium-dev#752 (case 1) — destructured default must not constant-fold the param.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sqlLines(code: string): Promise<number[]> {
  const r = await analyze(code, 'catalog.js', 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort(
    (a, b) => a - b,
  );
}

const HEAD = `const { ApolloServer } = require("@apollo/server");
const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("shop.db");

const resolvers = {
  Query: {
`;
const TAIL = `  },
};

const server = new ApolloServer({ typeDefs: "", resolvers });
`;

describe('cognium-dev#752 — destructured default keeps flow through a local', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports when sort has a default and flows through q', async () => {
    const code = `${HEAD}    products: (_p, { sort = "name" }) => {
      let q = "SELECT * FROM products ORDER BY " + sort;
      return db.all(q);
    },
${TAIL}`;
    expect(await sqlLines(code)).toEqual([9]);
  });

  it('reports with direct concatenation in the call (control)', async () => {
    const code = `${HEAD}    products: (_p, { sort = "name" }) => {
      return db.all("SELECT * FROM products ORDER BY " + sort);
    },
${TAIL}`;
    expect(await sqlLines(code)).toEqual([8]);
  });

  it('reports when sort has no default and flows through q (control)', async () => {
    const code = `${HEAD}    products: (_p, { sort }) => {
      let q = "SELECT * FROM products ORDER BY " + sort;
      return db.all(q);
    },
${TAIL}`;
    expect(await sqlLines(code)).toEqual([9]);
  });

  it('parameterised resolver stays clean', async () => {
    const code = `${HEAD}    products: (_p, { sort = "name" }) => {
      return db.all("SELECT * FROM products ORDER BY ?", [sort]);
    },
${TAIL}`;
    expect(await sqlLines(code)).toEqual([]);
  });
});
