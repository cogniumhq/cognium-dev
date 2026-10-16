/**
 * cognium-dev#586 (slice) — GraphQL resolver-map `args` that arrive as a
 * destructured pattern and/or with TypeScript annotations. The second parameter of
 * a `Query` / `Mutation` / `Subscription` resolver is client-supplied: seed the
 * names it binds, in `.js` and `.ts`. `parent` (0) and `context` (2) are never
 * seeded, destructured or not.
 *
 * SAST regression fixtures — the resolvers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sqlLines(code: string, file: string, lang: 'javascript' | 'typescript'): Promise<number[]> {
  const r = await analyze(code, file, lang);
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const HEAD_TS = `import { ApolloServer } from "@apollo/server";
import sqlite3 from "sqlite3";

const db = new sqlite3.Database("shop.db");

const resolvers = {
  Query: {
`;
const TAIL_TS = `  },
};

const server = new ApolloServer({ typeDefs: "", resolvers });
`;
const HEAD_JS = `const { ApolloServer } = require("@apollo/server");
const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("shop.db");

const resolvers = {
  Query: {
`;

describe('cognium-dev#586 — destructured resolver args, TypeScript', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a typed destructured args parameter fires at both resolvers', async () => {
    const code = `${HEAD_TS}    product: (_parent: unknown, { sku }: { sku: string }) => {
      return db.all("SELECT * FROM products WHERE sku = '" + sku + "'");
    },
    vendor: (_parent: unknown, { code }: { code: string }, _ctx: unknown) => {
      return db.all("SELECT * FROM vendors WHERE code = '" + code + "'");
    },
${TAIL_TS}`;
    expect(await sqlLines(code, 'catalog_schema.ts', 'typescript')).toEqual([9, 12]);
  });

  it('a destructured context (third parameter) is not a source', async () => {
    const code = `${HEAD_TS}    region: (_parent: unknown, _args: unknown, { user }: { user: string }) => {
      return db.all("SELECT * FROM regions WHERE owner = '" + user + "'");
    },
${TAIL_TS}`;
    expect(await sqlLines(code, 'catalog_ctx.ts', 'typescript')).toEqual([]);
  });

  it('a typed identifier args parameter fires, and so does a method shorthand with a typed list', async () => {
    const code = `${HEAD_TS}    item: (parent: unknown, args: { id: string }) => {
      return db.all("SELECT * FROM items WHERE id = '" + args.id + "'");
    },
    shop(parent: unknown, args: Record<string, string>, ctx: Ctx): unknown {
      return db.all("SELECT * FROM shops WHERE id = '" + args.id + "'");
    },
${TAIL_TS}`;
    expect(await sqlLines(code, 'catalog_typed.ts', 'typescript')).toEqual([9, 12]);
  });

  it('an alias, a nested pattern and a rest binding are all bound names', async () => {
    const code = `${HEAD_TS}    aliased: (_p: unknown, { sku: s }: { sku: string }) => {
      return db.all("SELECT * FROM a WHERE sku = '" + s + "'");
    },
    nested: (_p: unknown, { filter: { name } }: { filter: { name: string } }) => {
      return db.all("SELECT * FROM n WHERE name = '" + name + "'");
    },
    rest: (_p: unknown, { first, ...others }: Record<string, string>) => {
      return db.all("SELECT * FROM r WHERE x = '" + others.x + "'");
    },
${TAIL_TS}`;
    expect(await sqlLines(code, 'catalog_forms.ts', 'typescript')).toEqual([9, 12, 15]);
  });

  it('a parameterised query on a destructured arg stays clean', async () => {
    const code = `${HEAD_TS}    safe: (_p: unknown, { sku }: { sku: string }) => {
      return db.all("SELECT * FROM products WHERE sku = ?", [sku]);
    },
${TAIL_TS}`;
    expect(await sqlLines(code, 'catalog_safe.ts', 'typescript')).toEqual([]);
  });

  it('a resolver map not wired to a server is not a source', async () => {
    const code = `import sqlite3 from "sqlite3";
const db = new sqlite3.Database("shop.db");
export const resolvers = {
  Query: {
    product: (_p: unknown, { sku }: { sku: string }) => {
      return db.all("SELECT * FROM products WHERE sku = '" + sku + "'");
    },
  },
};
`;
    expect(await sqlLines(code, 'catalog_unwired.ts', 'typescript')).toEqual([]);
  });

  it('a field resolver outside Query / Mutation / Subscription is not a source', async () => {
    const code = `import { ApolloServer } from "@apollo/server";
import sqlite3 from "sqlite3";
const db = new sqlite3.Database("shop.db");
const resolvers = {
  Product: {
    related: (_p: unknown, { sku }: { sku: string }) => {
      return db.all("SELECT * FROM products WHERE sku = '" + sku + "'");
    },
  },
};
const server = new ApolloServer({ typeDefs: "", resolvers });
`;
    expect(await sqlLines(code, 'catalog_field.ts', 'typescript')).toEqual([]);
  });

  it('a name the sibling resolvers bind from parent is ambiguous and not seeded', async () => {
    const code = `${HEAD_TS}    byArgs: (_p: unknown, { id }: { id: string }) => {
      return db.all("SELECT * FROM a WHERE id = '" + id + "'");
    },
    byParent: ({ id }: { id: string }, _args: unknown) => {
      return db.all("SELECT * FROM b WHERE id = '" + id + "'");
    },
${TAIL_TS}`;
    expect(await sqlLines(code, 'catalog_shared.ts', 'typescript')).toEqual([]);
  });
});

describe('cognium-dev#586 — destructured resolver args, JavaScript', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const tail = `  },
};

const server = new ApolloServer({ typeDefs: "", resolvers });
`;

  it('a destructured second parameter fires', async () => {
    const code = `${HEAD_JS}    user: (_, { id }) => {
      return db.all("SELECT * FROM users WHERE id = '" + id + "'");
    },
${tail}`;
    expect(await sqlLines(code, 'users_schema.js', 'javascript')).toEqual([8]);
  });

  it('a destructured parent (first parameter) with a plain args parameter seeds only args', async () => {
    const code = `${HEAD_JS}    owner: ({ ownerId }, args) => {
      return db.all("SELECT * FROM users WHERE id = '" + ownerId + "'");
    },
${tail}`;
    expect(await sqlLines(code, 'owner_schema.js', 'javascript')).toEqual([]);
  });

  it('the identifier form from #695 is unchanged', async () => {
    const code = `${HEAD_JS}    product: (parent, args, context) => {
      return db.all("SELECT * FROM products WHERE sku = '" + args.sku + "'");
    },
    region: (parent, args, context) => {
      return db.all("SELECT * FROM regions WHERE owner = '" + context.user + "'");
    },
${tail}`;
    expect(await sqlLines(code, 'catalog_ident.js', 'javascript')).toEqual([8]);
  });
});
