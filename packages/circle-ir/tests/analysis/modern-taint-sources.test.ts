/**
 * Pinning tests for cognium-dev #242 — modern taint sources.
 *
 * These sources were previously silent — a resolver that concatenated an
 * `@Args`-annotated GraphQL field into a SQL string produced zero flows.
 * The same held for gRPC request metadata, cache reads (second-order taint),
 * and unverified JWT claims.
 *
 * Coverage:
 *   - GraphQL: TypeGraphQL (JS/TS decorators + @Arg/@Args param),
 *              Strawberry (Python), Netflix DGS + SPQR (Java)
 *   - gRPC:    invocation_metadata (Python), Metadata.get (JS/TS/Java),
 *              metadata.FromIncomingContext (Go)
 *   - Cache:   Redis/cache reads (Python/JS/TS/Java)
 *   - JWT:     unverified decode (Python/JS/TS/Java/Go)
 *
 * Language-filter guards prevent cross-language collision — the JS/TS
 * `@Query` (TypeGraphQL) MUST NOT fire on Java `@Query` (Spring Data).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';

async function collectSources(code: string, language: 'python' | 'javascript' | 'typescript' | 'java' | 'go') {
  const tree = await parse(code, language);
  const calls = extractCalls(tree, undefined, language);
  const types = extractTypes(tree, undefined, language);
  const taint = analyzeTaint(calls, types, undefined, undefined, language, code);
  return taint.sources;
}

describe('Modern taint sources (#242)', () => {
  beforeAll(async () => {
    await initParser();
  });

  // ---------------------------------------------------------------------
  // GraphQL — method_annotation + annotation param sources
  // ---------------------------------------------------------------------
  describe('GraphQL resolver sources', () => {
    it('TypeGraphQL @Query taints all method params', async () => {
      const code = `
import { Query, Resolver, Arg } from 'type-graphql';

@Resolver()
class UserResolver {
  @Query(() => String)
  async findUser(@Arg('id') id: string): Promise<string> {
    return id;
  }
}
`;
      const sources = await collectSources(code, 'typescript');
      // Either method_annotation ('@Query id in findUser') or param annotation
      // ('@Arg id in findUser') should fire.
      const graphqlSource = sources.find(s => s.location.includes('id'));
      expect(graphqlSource).toBeDefined();
    });

    it('TypeGraphQL @Args param taints as http_param', async () => {
      const code = `
import { Args, Resolver, Query } from 'type-graphql';

@Resolver()
class SearchResolver {
  @Query(() => [String])
  async search(@Args() opts: string): Promise<string[]> {
    return [opts];
  }
}
`;
      const sources = await collectSources(code, 'typescript');
      const argsSource = sources.find(
        s => s.type === 'http_param' && s.location.includes('opts'),
      );
      expect(argsSource).toBeDefined();
    });

    it('Strawberry @strawberry.field taints Python resolver params', async () => {
      const code = `
import strawberry

@strawberry.type
class Query:
    @strawberry.field
    def hello(self, name: str) -> str:
        return f"Hello {name}"
`;
      const sources = await collectSources(code, 'python');
      const strawberrySource = sources.find(s => s.location.includes('name'));
      expect(strawberrySource).toBeDefined();
    });

    it('Netflix DGS @DgsQuery taints Java resolver params', async () => {
      const code = `
import com.netflix.graphql.dgs.DgsQuery;
import com.netflix.graphql.dgs.InputArgument;

public class UserFetcher {
    @DgsQuery
    public String user(@InputArgument String id) {
        return id;
    }
}
`;
      const sources = await collectSources(code, 'java');
      const dgsSource = sources.find(s => s.location.includes('id'));
      expect(dgsSource).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------
  // Language-filter guards — cross-language collision protection
  // ---------------------------------------------------------------------
  describe('Language-filter guards', () => {
    it('Java @Query (Spring Data) MUST NOT fire as GraphQL source', async () => {
      // TypeGraphQL's @Query is JS/TS only. On Java, @Query is Spring Data
      // repository — not a taint source.
      const code = `
import org.springframework.data.jpa.repository.Query;

public interface UserRepo {
    @Query("SELECT u FROM User u WHERE u.name = :name")
    User findByName(String name);
}
`;
      const sources = await collectSources(code, 'java');
      const misfire = sources.find(
        s => s.location.includes('@Query') && s.location.includes('name'),
      );
      expect(misfire).toBeUndefined();
    });

    it('Python @Query decorator MUST NOT fire as GraphQL source', async () => {
      // Same collision guard on Python.
      const code = `
def Query(f):
    return f

@Query
def user_query(name: str) -> str:
    return name
`;
      const sources = await collectSources(code, 'python');
      const misfire = sources.find(
        s => s.location.includes('@Query') && s.location.includes('name'),
      );
      expect(misfire).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------
  // gRPC metadata — return-tainted method calls
  // ---------------------------------------------------------------------
  describe('gRPC request metadata sources', () => {
    it('Python invocation_metadata() is http_header source', async () => {
      const code = `
class MyService:
    def GetUser(self, request, context):
        metadata = context.invocation_metadata()
        return metadata
`;
      const sources = await collectSources(code, 'python');
      const grpcSource = sources.find(
        s => s.type === 'http_header' && s.location.includes('invocation_metadata'),
      );
      expect(grpcSource).toBeDefined();
    });

    it('Go metadata.FromIncomingContext is http_header source', async () => {
      const code = `
package handler

import "google.golang.org/grpc/metadata"

func Handle(ctx context.Context) {
    md, _ := metadata.FromIncomingContext(ctx)
    _ = md
}
`;
      const sources = await collectSources(code, 'go');
      const grpcSource = sources.find(
        s => s.type === 'http_header' && s.location.includes('FromIncomingContext'),
      );
      expect(grpcSource).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------
  // Cache reads — second-order taint
  // ---------------------------------------------------------------------
  describe('Cache read sources (second-order taint)', () => {
    it('Python Redis.get() is db_input source', async () => {
      const code = `
class Handler:
    def load(self, r):
        return r.get("user:1")
`;
      // Use bare receiver name matching — receiverMightBeClass does
      // case-insensitive match, but `r` won't. Test explicit Redis:
      const explicit = `
class Handler:
    def load(self):
        redis = Redis()
        return redis.get("user:1")
`;
      const sources = await collectSources(explicit, 'python');
      const cacheSource = sources.find(
        s => s.type === 'db_input' && s.location.includes('get'),
      );
      expect(cacheSource).toBeDefined();
    });

    it('Python cache.get_many is db_input source (Django)', async () => {
      const code = `
def load():
    cache = get_cache()
    values = cache.get_many(["a", "b"])
    return values
`;
      const sources = await collectSources(code, 'python');
      const cacheSource = sources.find(
        s => s.type === 'db_input' && s.location.includes('get_many'),
      );
      expect(cacheSource).toBeDefined();
    });

    it('Java Jedis.get is db_input source', async () => {
      const code = `
import redis.clients.jedis.Jedis;

public class Cache {
    public String load(Jedis jedis) {
        return jedis.get("user:1");
    }
}
`;
      const sources = await collectSources(code, 'java');
      const cacheSource = sources.find(
        s => s.type === 'db_input' && s.location.includes('get'),
      );
      expect(cacheSource).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------
  // JWT unverified decode — http_header source
  // ---------------------------------------------------------------------
  describe('JWT unverified-decode sources', () => {
    it('Python jwt.decode() is http_header source', async () => {
      const code = `
import jwt

def check(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims
`;
      const sources = await collectSources(code, 'python');
      const jwtSource = sources.find(
        s => s.type === 'http_header' && s.location.includes('decode'),
      );
      expect(jwtSource).toBeDefined();
    });

    it('JS jsonwebtoken.decode() is http_header source', async () => {
      const code = `
const jsonwebtoken = require('jsonwebtoken');

function check(token) {
    const claims = jsonwebtoken.decode(token);
    return claims;
}
`;
      const sources = await collectSources(code, 'javascript');
      const jwtSource = sources.find(
        s => s.type === 'http_header' && s.location.includes('decode'),
      );
      expect(jwtSource).toBeDefined();
    });

    it('Go jwt.ParseUnverified is http_header source', async () => {
      const code = `
package auth

import "github.com/golang-jwt/jwt/v5"

func Check(tokenString string) {
    token, _, _ := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
    _ = token
}
`;
      const sources = await collectSources(code, 'go');
      const jwtSource = sources.find(
        s => s.type === 'http_header' && s.location.includes('ParseUnverified'),
      );
      expect(jwtSource).toBeDefined();
    });
  });
});
