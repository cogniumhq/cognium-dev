/**
 * cognium-dev#587 (Express destructured request parameter) and #586 (GraphQL
 * resolver-map `args`) — framework parameter sources, JS only (minimal slices).
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const routes = "const express = require(\"express\");\nconst { exec } = require(\"child_process\");\nconst server = express();\n\nserver.get(\"/dig\", ({ query }, res) => {\n  const domain = query.domain;\n  exec(\"dig \" + domain, (err, out) => res.send(out));\n});\n\nserver.get(\"/whois\", ({ params }, res) => {\n  exec(\"whois \" + params.domain, (err, out) => res.send(out));\n});\n\nserver.get(\"/ping\", ({ query: { target } }, res) => {\n  exec(\"ping -c 1 \" + target, (err, out) => res.send(out));\n});\n\nserver.get(\"/trace\", (req, res) => {\n  const hop = req.query.hop;\n  exec(\"traceroute \" + hop, (err, out) => res.send(out));\n});\n";
const safe = "const express = require(\"express\");\nconst { exec } = require(\"child_process\");\nconst server = express();\nconst runLater = (fn) => fn({ query: { domain: \"example.com\" } });\n\nserver.get(\"/env\", ({ app }, res) => {\n  exec(\"echo \" + app.get(\"env\"), (err, out) => res.send(out));\n});\n\nrunLater(({ query }) => {\n  exec(\"dig \" + query.domain, () => {});\n});\n";
const schema = "const { ApolloServer } = require(\"@apollo/server\");\nconst sqlite3 = require(\"sqlite3\");\nconst db = new sqlite3.Database(\"shop.db\");\n\nconst resolvers = {\n  Query: {\n    product: (parent, args, context) => {\n      return db.all(\"SELECT * FROM products WHERE sku = '\" + args.sku + \"'\");\n    },\n    vendor(parent, args) {\n      return db.all(\"SELECT * FROM vendors WHERE code = '\" + args.code + \"'\");\n    },\n    category: (parent, args, context) => {\n      return db.all(\"SELECT * FROM categories WHERE id = ?\", [args.id]);\n    },\n    region: (parent, args, context) => {\n      return db.all(\"SELECT * FROM regions WHERE owner = '\" + context.user + \"'\");\n    },\n  },\n};\n\nconst server = new ApolloServer({ typeDefs: \"\", resolvers });\n";
const unwired = "const { ApolloServer } = require(\"@apollo/server\");\nconst sqlite3 = require(\"sqlite3\");\nconst db = new sqlite3.Database(\"shop.db\");\n\nconst resolvers = {\n  Query: {\n    product: (parent, args, context) => {\n      return db.all(\"SELECT * FROM products WHERE sku = '\" + args.sku + \"'\");\n    },\n    vendor(parent, args) {\n      return db.all(\"SELECT * FROM vendors WHERE code = '\" + args.code + \"'\");\n    },\n    category: (parent, args, context) => {\n      return db.all(\"SELECT * FROM categories WHERE id = ?\", [args.id]);\n    },\n    region: (parent, args, context) => {\n      return db.all(\"SELECT * FROM regions WHERE owner = '\" + context.user + \"'\");\n    },\n  },\n};\n\nmodule.exports = resolvers;\n";

async function sinkLines(code: string, file: string, type: string) {
  const r = await analyze(code, file, 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('framework parameter sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('#587: destructured, nested and req.query handlers all fire command_injection', async () => {
    expect(await sinkLines(routes, 'lookup_routes.js', 'command_injection')).toEqual([7, 11, 15, 20]);
  });

  it('#587: a non-request key and a non-Express callback stay clean', async () => {
    expect(await sinkLines(safe, 'lookup_safe.js', 'command_injection')).toEqual([]);
  });

  it('#587: body destructuring in the handler body still fires', async () => {
    const code = `const express = require("express");
const { exec } = require("child_process");
const app = express();
app.post("/run", (req, res) => {
  const { cmd } = req.body;
  exec(cmd, () => res.end());
});
`;
    expect(await sinkLines(code, 'run.js', 'command_injection')).toEqual([6]);
  });

  it('#586: resolver args fire sql_injection at 8 and 11; parameterised (14) and context (17) stay clean', async () => {
    expect(await sinkLines(schema, 'catalog_schema.js', 'sql_injection')).toEqual([8, 11]);
  });

  it('#586: the same resolver map not passed to a schema/server is not a source', async () => {
    expect(await sinkLines(unwired, 'catalog_unwired.js', 'sql_injection')).toEqual([]);
  });
});
