/**
 * Cross-file taint through dependency-injected receivers.
 *
 * A controller holds a service or repository it receives by injection (a
 * Spring constructor-injected, `@Autowired` or Lombok-generated field; a
 * TypeScript constructor parameter property). A call through that receiver
 * resolves to the receiver's declared type, so taint follows the request
 * parameter into the callee's parameter and on to the sink there. A receiver
 * of another type that happens to have a method of the same name does not
 * bind to it, and a callee that uses the value safely reports nothing.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';
import type { SupportedLanguage } from '../../src/index.js';

type Src = { filePath: string; code: string };

async function scan(language: SupportedLanguage, files: Src[]) {
  return analyzeProject(files.map(f => ({ ...f, language })));
}

type Project = Awaited<ReturnType<typeof scan>>;

function paths(r: Project, sinkType: string) {
  return (r.taint_paths ?? []).filter(p => p.sink.type === sinkType && p.source.file !== p.sink.file);
}

function escapesIn(r: Project, file: string) {
  return (r.files.find(f => f.file === file)?.analysis.taint.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape');
}

// ---------------------------------------------------------------------------
// Java / Spring
// ---------------------------------------------------------------------------

const CONTROLLER = 'src/main/java/demo/SearchController.java';
const REPOSITORY = 'src/main/java/demo/SearchRepository.java';

const springController = (fields: string, call = 'repo.find(q)', classAnnotations = '') => `package demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

${classAnnotations}@RestController
public class SearchController {
${fields}

  @GetMapping("/search")
  public List<?> search(@RequestParam String q) {
    return ${call};
  }
}
`;

const CTOR_INJECTED = `  private final SearchRepository repo;
  public SearchController(SearchRepository repo) { this.repo = repo; }`;

const searchRepository = (body: string, name = 'SearchRepository', header = '') => `package demo;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public class ${name}${header} {
  private final EntityManager em;
  private String kind = "book";
  public ${name}(EntityManager em) { this.em = em; }

  public List<?> find(String q) {
${body}
  }
}
`;

const CONCAT_QUERY = `    String sql = "SELECT * FROM product WHERE name LIKE '%" + q + "%'";
    return em.createNativeQuery(sql).getResultList();`;

describe('Java: calls through injected fields resolve to the declared type', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('constructor injection: @RequestParam reaches the repository query', async () => {
    const r = await scan('java', [
      { filePath: CONTROLLER, code: springController(CTOR_INJECTED) },
      { filePath: REPOSITORY, code: searchRepository(CONCAT_QUERY) },
    ]);
    const sqli = paths(r, 'sql_injection');
    expect(sqli).toHaveLength(1);
    expect(sqli[0].source).toMatchObject({ file: CONTROLLER, line: 14, type: 'http_param' });
    expect(sqli[0].sink).toMatchObject({ file: REPOSITORY, line: 15, cwe: 'CWE-89' });
    // The call is project code the cross-file path covers, not data leaving the program.
    expect(escapesIn(r, CONTROLLER)).toHaveLength(0);
    const call = r.cross_file_calls.find(c => c.from.file === CONTROLLER && c.from.line === 15);
    expect(call?.to.method).toBe('demo.SearchRepository.find');
    expect(call?.resolved).toBe(true);
  });

  it('`this.repo`, @Autowired fields and Lombok-generated constructors', async () => {
    const shapes: Array<[string, string, string]> = [
      [CTOR_INJECTED, 'this.repo.find(q)', ''],
      ['  @Autowired\n  private SearchRepository repo;', 'repo.find(q)', ''],
      ['  private final SearchRepository repo;', 'repo.find(q)', '@RequiredArgsConstructor\n'],
    ];
    for (const [fields, call, annotations] of shapes) {
      const r = await scan('java', [
        { filePath: CONTROLLER, code: springController(fields, call, annotations) },
        { filePath: REPOSITORY, code: searchRepository(CONCAT_QUERY) },
      ]);
      expect(paths(r, 'sql_injection').map(p => [p.source.line, p.sink.file]), `${annotations}${fields}`)
        .toEqual([[14, REPOSITORY]]);
    }
  });

  it('an interface with one implementing class resolves to that class', async () => {
    const r = await scan('java', [
      { filePath: 'src/main/java/demo/SearchStore.java', code: 'package demo;\nimport java.util.List;\npublic interface SearchStore {\n  List<?> find(String q);\n}\n' },
      { filePath: CONTROLLER, code: springController('  private final SearchStore repo;\n  public SearchController(SearchStore repo) { this.repo = repo; }') },
      { filePath: REPOSITORY, code: searchRepository(CONCAT_QUERY, 'SearchRepository', ' implements SearchStore') },
    ]);
    expect(paths(r, 'sql_injection').map(p => [p.source.file, p.sink.file, p.sink.line]))
      .toEqual([[CONTROLLER, REPOSITORY, 15]]);
  });

  it('controller → injected service → injected repository', async () => {
    const service = `package demo;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class SearchService {
  private final SearchRepository repo;
  public SearchService(SearchRepository repo) { this.repo = repo; }

  public List<?> find(String q) {
    return repo.find(q);
  }
}
`;
    const r = await scan('java', [
      { filePath: CONTROLLER, code: springController('  private final SearchService service;\n  public SearchController(SearchService service) { this.service = service; }', 'service.find(q)') },
      { filePath: 'src/main/java/demo/SearchService.java', code: service },
      { filePath: REPOSITORY, code: searchRepository(CONCAT_QUERY) },
    ]);
    expect(paths(r, 'sql_injection').map(p => [p.source.file, p.source.line, p.sink.file]))
      .toEqual([[CONTROLLER, 14, REPOSITORY]]);
  });

  it('negative: a parameterised query in the repository reports nothing', async () => {
    const r = await scan('java', [
      { filePath: CONTROLLER, code: springController(CTOR_INJECTED) },
      { filePath: REPOSITORY, code: searchRepository(`    return em.createNativeQuery("SELECT * FROM product WHERE name LIKE ?1")
        .setParameter(1, "%" + q + "%")
        .getResultList();`) },
    ]);
    expect(paths(r, 'sql_injection')).toHaveLength(0);
    expect(r.files.flatMap(f => f.analysis.taint.flows).filter(f => f.sink_type === 'sql_injection')).toHaveLength(0);
  });

  it('negative: a query built from a field, not the argument, is not credited', async () => {
    const r = await scan('java', [
      { filePath: CONTROLLER, code: springController(CTOR_INJECTED) },
      { filePath: REPOSITORY, code: searchRepository(`    System.out.println(q.length());
    return em.createNativeQuery("SELECT * FROM product WHERE kind = '" + kind + "'").getResultList();`) },
    ]);
    expect(paths(r, 'sql_injection')).toHaveLength(0);
  });

  it('negative: an injected receiver of another project type does not bind to a same-named method', async () => {
    const catalog = `package demo;

import java.util.List;
import java.util.ArrayList;

public class Catalog {
  private final List<String> names = new ArrayList<>();
  public Catalog() { }
  public List<?> find(String q) {
    return names.contains(q) ? names : new ArrayList<>();
  }
}
`;
    // The vulnerable repository is listed first, so a lookup by method name alone finds it.
    const r = await scan('java', [
      { filePath: REPOSITORY, code: searchRepository(CONCAT_QUERY) },
      { filePath: 'src/main/java/demo/Catalog.java', code: catalog },
      { filePath: CONTROLLER, code: springController('  private final Catalog catalog;\n  public SearchController(Catalog catalog) { this.catalog = catalog; }', 'catalog.find(q)') },
    ]);
    expect(paths(r, 'sql_injection')).toHaveLength(0);
    const call = r.cross_file_calls.find(c => c.from.file === CONTROLLER && c.from.line === 15);
    expect(call?.to.method).toBe('demo.Catalog.find');
  });

  it('negative: an injected library type does not bind to a project method of the same name', async () => {
    const controller = springController(
      '  private final SearchClient client;\n  public SearchController(SearchClient client) { this.client = client; }',
      'client.find(q)',
    ).replace('import java.util.List;', 'import java.util.List;\nimport com.example.search.SearchClient;');
    const r = await scan('java', [
      { filePath: REPOSITORY, code: searchRepository(CONCAT_QUERY) },
      { filePath: CONTROLLER, code: controller },
    ]);
    expect(paths(r, 'sql_injection')).toHaveLength(0);
    expect(r.cross_file_calls.filter(c => c.from.file === CONTROLLER)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// TypeScript / NestJS
// ---------------------------------------------------------------------------

const PING_CONTROLLER = 'src/ping/ping.controller.ts';
const PING_SERVICE = 'src/ping/ping.service.ts';

const nestController = (ctor: string, call = 'this.pingService.ping(host)', imports = "import { PingService } from './ping.service';") => `import { Controller, Get, Query } from '@nestjs/common';
${imports}

@Controller('ping')
export class PingController {
  ${ctor}

  @Get()
  ping(@Query('host') host: string) {
    return ${call};
  }
}
`;

const pingService = (body = 'return execSync(`ping -c 1 ${host}`).toString();', name = 'PingService') => `import { Injectable } from '@nestjs/common';
import { execSync } from 'child_process';

@Injectable()
export class ${name} {
  ping(host: string): string {
    ${body}
  }
}
`;

describe('TypeScript: calls through constructor parameter properties resolve to the declared type', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('`constructor(private svc: PingService)`: @Query reaches execSync in the service', async () => {
    const r = await scan('typescript', [
      { filePath: PING_CONTROLLER, code: nestController('constructor(private pingService: PingService) {}') },
      { filePath: PING_SERVICE, code: pingService() },
    ]);
    const cmdi = paths(r, 'command_injection');
    expect(cmdi).toHaveLength(1);
    expect(cmdi[0].source).toMatchObject({ file: PING_CONTROLLER, line: 9, type: 'http_param' });
    expect(cmdi[0].sink).toMatchObject({ file: PING_SERVICE, line: 7, cwe: 'CWE-78' });
  });

  it('`private readonly`, `public` and an explicit `this.svc = svc` assignment', async () => {
    const ctors = [
      'constructor(private readonly pingService: PingService) {}',
      'constructor(public pingService: PingService) {}',
      'private pingService: PingService;\n  constructor(svc: PingService) {\n    this.pingService = svc;\n  }',
    ];
    for (const ctor of ctors) {
      const r = await scan('typescript', [
        { filePath: PING_CONTROLLER, code: nestController(ctor) },
        { filePath: PING_SERVICE, code: pingService() },
      ]);
      expect(paths(r, 'command_injection').map(p => [p.source.file, p.sink.file, p.sink.line]), ctor)
        .toEqual([[PING_CONTROLLER, PING_SERVICE, 7]]);
    }
  });

  it('negative: a parameterised query in the service reports nothing', async () => {
    const service = `import { Injectable } from '@nestjs/common';
import { Pool } from 'pg';

@Injectable()
export class PingService {
  private readonly pool = new Pool();
  ping(host: string) {
    return this.pool.query('SELECT * FROM hosts WHERE name = $1', [host]);
  }
}
`;
    const r = await scan('typescript', [
      { filePath: PING_CONTROLLER, code: nestController('constructor(private pingService: PingService) {}') },
      { filePath: PING_SERVICE, code: service },
    ]);
    expect(r.taint_paths ?? []).toHaveLength(0);
    expect(r.files.flatMap(f => f.analysis.taint.flows)).toHaveLength(0);
  });

  it('negative: an injected service of another class does not bind to a same-named method', async () => {
    const audit = `import { Injectable } from '@nestjs/common';

@Injectable()
export class AuditService {
  private readonly seen: string[] = [];
  ping(host: string): string {
    this.seen.push(host);
    return 'ok';
  }
}
`;
    // The vulnerable service is listed first, so a lookup by method name alone finds it.
    const r = await scan('typescript', [
      { filePath: PING_SERVICE, code: pingService() },
      { filePath: 'src/ping/audit.service.ts', code: audit },
      { filePath: PING_CONTROLLER, code: nestController('constructor(private audit: AuditService) {}', 'this.audit.ping(host)', "import { AuditService } from './audit.service';") },
    ]);
    expect(paths(r, 'command_injection')).toHaveLength(0);
    const call = r.cross_file_calls.find(c => c.from.file === PING_CONTROLLER && c.from.line === 10);
    expect(call?.to.file).toBe('src/ping/audit.service.ts');
  });

  it('negative: an injected library type does not bind to a project method of the same name', async () => {
    const r = await scan('typescript', [
      { filePath: PING_SERVICE, code: pingService() },
      { filePath: PING_CONTROLLER, code: nestController('constructor(private readonly health: HealthCheckService) {}', 'this.health.ping(host)', "import { HealthCheckService } from '@nestjs/terminus';") },
    ]);
    expect(paths(r, 'command_injection')).toHaveLength(0);
    expect(r.cross_file_calls.filter(c => c.from.file === PING_CONTROLLER)).toHaveLength(0);
  });
});
