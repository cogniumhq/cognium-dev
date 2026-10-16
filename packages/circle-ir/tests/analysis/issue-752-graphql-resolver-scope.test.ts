/**
 * cognium-dev#752 (slice 2): GraphQL resolver arg seeds must not reach a
 * same-named local in a different recorded JS function.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sqlLines(code: string, file = 'catalog.js'): Promise<number[]> {
  const r = await analyze(code, file, 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort(
    (a, b) => a - b,
  );
}

const HEAD = `import { ApolloServer } from "@apollo/server";
import sqlite3 from "sqlite3";
const db = new sqlite3.Database("shop.db");
`;

describe('cognium-dev#752 — GraphQL resolver seed scoped to its function', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not report audit() when resolver uses a parameterised query', async () => {
    const code = `${HEAD}
const resolvers = {
  Query: {
    items: (_p, { order }) => {
      return db.all("SELECT * FROM items ORDER BY ?", [order]);
    },
  },
};
const server = new ApolloServer({ typeDefs: "", resolvers });

function audit(db) {
  const order = "name";
  return db.all("SELECT * FROM audits ORDER BY " + order);
}
`;
    expect(await sqlLines(code)).toEqual([]);
  });

  it('stays clean when the resolver body is a constant return', async () => {
    const code = `${HEAD}
const resolvers = {
  Query: {
    ping: (_p, { order }) => {
      return "x";
    },
  },
};
const server = new ApolloServer({ typeDefs: "", resolvers });

function audit(db) {
  const order = "name";
  return db.all("SELECT * FROM audits ORDER BY " + order);
}
`;
    expect(await sqlLines(code)).toEqual([]);
  });

  it('still reports when the resolver concatenates the arg', async () => {
    const code = `${HEAD}
const resolvers = {
  Query: {
    items: (_p, { order }) => {
      return db.all("SELECT * FROM items ORDER BY " + order);
    },
  },
};
const server = new ApolloServer({ typeDefs: "", resolvers });

function audit(db) {
  const order = "name";
  return db.all("SELECT * FROM audits ORDER BY " + order);
}
`;
    const resolverSink =
      code.split('\n').findIndex((l) => l.includes('FROM items ORDER BY " + order')) + 1;
    expect(await sqlLines(code)).toEqual([resolverSink]);
  });

  it('still reports for a map built inside a factory function', async () => {
    const code = `${HEAD}
function build() {
  const resolvers = {
    Query: {
      items: (_p, { order }) => {
        return db.all("SELECT * FROM items ORDER BY " + order);
      },
    },
  };
  return new ApolloServer({ typeDefs: "", resolvers });
}
`;
    const resolverSink = code.split('\n').findIndex((l) => l.includes('items ORDER BY " + order')) + 1;
    expect(await sqlLines(code)).toEqual([resolverSink]);
  });
});
