/**
 * Entry-point recognition data for Java (`entry-index@0.1`).
 *
 * Framework knowledge as tables: an annotation (by package and simple name)
 * marks a method or a class as an entry of some kind. A consumer may pass
 * its own tables to `buildJavaGraph`.
 */

import type { EntryKind } from './ts-entry-tables.js';

export interface JavaAnnotationRow {
  /** Packages the annotation may come from; an import, a wildcard or a qualified name must match one. */
  packages: readonly string[];
  names: readonly string[];
  kind: EntryKind;
  on: 'method' | 'class';
}

export interface JavaRouteRow {
  packages: readonly string[];
  /** Method annotation → HTTP method; `null` reads the method from a `method =` attribute (Spring `@RequestMapping`), else `ANY`. */
  verbs: Readonly<Record<string, string | null>>;
  /** The annotation carrying a path (class prefix, and on methods where the verb annotation has none). */
  pathAnnotation?: string;
  framework: string;
}

export interface JavaServletRow {
  packages: readonly string[];
  /** The supertype (simple name) that makes a class a servlet or filter. */
  supertype: string;
  /** Method name → HTTP method (`USE` for filters), or `lifecycle`. */
  methods: Readonly<Record<string, string>>;
  /** The class annotation whose `value` / `urlPatterns` give the path. */
  pathAnnotation: string;
  surface?: 'middleware';
  framework: string;
}

export interface JavaEntryTables {
  routes: readonly JavaRouteRow[];
  servlets: readonly JavaServletRow[];
  annotations: readonly JavaAnnotationRow[];
  /** Repository paths of test sources. */
  testFile: RegExp;
}

const SPRING_WEB = ['org.springframework.web.bind.annotation'];
const JAXRS = ['javax.ws.rs', 'jakarta.ws.rs'];

export const DEFAULT_JAVA_ENTRY_TABLES: JavaEntryTables = {
  routes: [
    {
      packages: SPRING_WEB,
      verbs: { GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', DeleteMapping: 'DELETE', PatchMapping: 'PATCH', RequestMapping: null },
      pathAnnotation: 'RequestMapping',
      framework: 'spring-web',
    },
    {
      packages: JAXRS,
      verbs: { GET: 'GET', POST: 'POST', PUT: 'PUT', DELETE: 'DELETE', PATCH: 'PATCH', HEAD: 'HEAD', OPTIONS: 'OPTIONS' },
      pathAnnotation: 'Path',
      framework: 'jax-rs',
    },
  ],
  servlets: [
    {
      packages: ['javax.servlet.http', 'jakarta.servlet.http'],
      supertype: 'HttpServlet',
      methods: { doGet: 'GET', doPost: 'POST', doPut: 'PUT', doDelete: 'DELETE', doHead: 'HEAD', doOptions: 'OPTIONS', doTrace: 'TRACE', service: 'ANY', init: 'lifecycle', destroy: 'lifecycle' },
      pathAnnotation: 'WebServlet',
      framework: 'servlet',
    },
    {
      packages: ['javax.servlet', 'jakarta.servlet'],
      supertype: 'Filter',
      methods: { doFilter: 'USE', init: 'lifecycle', destroy: 'lifecycle' },
      pathAnnotation: 'WebFilter',
      surface: 'middleware',
      framework: 'servlet',
    },
  ],
  annotations: [
    { packages: ['org.springframework.stereotype', 'org.springframework.web.bind.annotation', 'org.springframework.context.annotation'], names: ['Component', 'Service', 'Repository', 'Controller', 'RestController', 'Configuration', 'ControllerAdvice', 'RestControllerAdvice'], kind: 'bean', on: 'class' },
    { packages: ['org.springframework.context.annotation'], names: ['Bean'], kind: 'bean', on: 'method' },
    { packages: ['javax.annotation', 'jakarta.annotation'], names: ['PostConstruct', 'PreDestroy'], kind: 'lifecycle', on: 'method' },
    { packages: ['org.springframework.web.bind.annotation'], names: ['ExceptionHandler', 'InitBinder', 'ModelAttribute'], kind: 'lifecycle', on: 'method' },
    { packages: ['org.springframework.scheduling.annotation'], names: ['Scheduled'], kind: 'scheduled', on: 'method' },
    { packages: ['org.springframework.kafka.annotation'], names: ['KafkaListener'], kind: 'listener', on: 'method' },
    { packages: ['org.springframework.amqp.rabbit.annotation'], names: ['RabbitListener'], kind: 'listener', on: 'method' },
    { packages: ['org.springframework.jms.annotation'], names: ['JmsListener'], kind: 'listener', on: 'method' },
    { packages: ['org.springframework.context.event'], names: ['EventListener'], kind: 'listener', on: 'method' },
    { packages: ['org.junit', 'org.junit.jupiter.api', 'org.junit.jupiter.params', 'org.testng.annotations'], names: ['Test', 'ParameterizedTest', 'RepeatedTest', 'TestFactory', 'TestTemplate', 'Before', 'After', 'BeforeClass', 'AfterClass', 'BeforeEach', 'AfterEach', 'BeforeAll', 'AfterAll', 'BeforeMethod', 'AfterMethod', 'BeforeSuite', 'AfterSuite', 'BeforeTest', 'AfterTest'], kind: 'test', on: 'method' },
  ],
  testFile: /(?:(?:^|\/)src\/test\/)|(?:Tests?\.java$)|(?:IT\.java$)/,
};
