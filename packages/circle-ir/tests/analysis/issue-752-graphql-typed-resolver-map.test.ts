/**
 * cognium-dev#752 (slice 1, follow-up of #586): a resolver map declared with a type
 * annotation (`const resolvers: Resolvers = {…}`, `Resolvers<Context>`) is
 * discovered like the unannotated one, so the second parameter of its
 * `Query` / `Mutation` / `Subscription` functions is a client-supplied source.
 *
 * SAST regression fixtures — the resolvers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sqlLines(code: string, file = 'shop.ts'): Promise<number[]> {
  const r = await analyze(code, file, 'typescript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const HEAD = `import { ApolloServer } from "@apollo/server";
import sqlite3 from "sqlite3";
const db = new sqlite3.Database("shop.db");
`;

/** A one-resolver map with the given declaration head, ending in `new ApolloServer`. */
const map = (decl: string, sinkBody: string, serverOpts = '{ typeDefs: "", resolvers }') => `${HEAD}
${decl} {
  Query: {
    products: (_p, { sort }) => {
${sinkBody}
    },
  },
};

const server = new ApolloServer(${serverOpts});
`;

const BAD = '      return db.all("SELECT * FROM products ORDER BY " + sort);';
const SINK_LINE = 8;

describe('cognium-dev#752 — a type-annotated resolver map is discovered', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('control: the unannotated map reports (already worked)', async () => {
    expect(await sqlLines(map('const resolvers =', BAD))).toEqual([SINK_LINE]);
  });

  it.each([
    ['a plain type', 'const resolvers: Resolvers ='],
    ['a generic type', 'const resolvers: Resolvers<Context> ='],
    ['two type arguments', 'const resolvers: Resolvers<Context, Parent> ='],
    ['a nested generic', 'const resolvers: Resolvers<Ctx<User>> ='],
    ['a namespaced type', 'const resolvers: gql.Resolvers<Context> ='],
    ['let with a type', 'let resolvers: Resolvers ='],
    ['no space before the colon or equals', 'const resolvers:Resolvers<Context>='],
  ])('reports with %s', async (_n, decl) => {
    expect(await sqlLines(map(decl, BAD))).toEqual([SINK_LINE]);
  });

  it('is not keyed on names: renamed map, passed as `resolvers: <name>`', async () => {
    const code = map('const shopResolvers: Resolvers<Ctx> =', BAD, '{ typeDefs: "", resolvers: shopResolvers }');
    expect(await sqlLines(code, 'catalog.ts')).toEqual([SINK_LINE]);
  });

  it('a typed destructured args parameter inside a typed map', async () => {
    const code = `${HEAD}
const resolvers: Resolvers<Context> = {
  Query: {
    product: (_parent: unknown, { sku }: { sku: string }) => {
      return db.all("SELECT * FROM products WHERE sku = '" + sku + "'");
    },
  },
};
const server = new ApolloServer({ typeDefs: "", resolvers });
`;
    expect(await sqlLines(code)).toEqual([8]);
  });

  describe('stays clean', () => {
    it('a parameterised query in a typed map', async () => {
      const code = map('const resolvers: Resolvers =', '      return db.all("SELECT * FROM products ORDER BY ?", [sort]);');
      expect(await sqlLines(code)).toEqual([]);
    });

    it('a typed map that is never given to ApolloServer / makeExecutableSchema', async () => {
      const code = map('const resolvers: Resolvers =', BAD, '{ typeDefs: "" }');
      expect(await sqlLines(code)).toEqual([]);
    });

    it('a typed map handed to some other constructor', async () => {
      const code = map('const resolvers: Resolvers =', BAD).replace('new ApolloServer(', 'new Server(');
      expect(await sqlLines(code)).toEqual([]);
    });

    it('a typed object that is not the map ApolloServer receives', async () => {
      const code = map('const resolvers: Resolvers =', BAD, '{ typeDefs: "", resolvers: other }');
      expect(await sqlLines(code)).toEqual([]);
    });

    it('the context parameter (third) of a typed map is not a source', async () => {
      const code = `${HEAD}
const resolvers: Resolvers<Context> = {
  Query: {
    region: (_parent: unknown, _args: unknown, { user }: { user: string }) => {
      return db.all("SELECT * FROM regions WHERE owner = '" + user + "'");
    },
  },
};
const server = new ApolloServer({ typeDefs: "", resolvers });
`;
      expect(await sqlLines(code)).toEqual([]);
    });

    it('a same-named local constant outside the typed map', async () => {
      const code = `${map('const resolvers: Resolvers =', '      return db.all("SELECT * FROM products ORDER BY ?", [sort]);')}
function report() {
  const sort = "name";
  return db.all("SELECT * FROM reports ORDER BY " + sort);
}
`;
      const lines = await sqlLines(code);
      // the typed map's own parameterised resolver adds nothing; the constant in
      // `report` is reported or not exactly as for the unannotated map (#752 case 2)
      const unannotated = await sqlLines(code.replace('const resolvers: Resolvers =', 'const resolvers ='));
      expect(lines).toEqual(unannotated);
    });
  });
});
