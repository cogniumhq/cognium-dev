/**
 * Entry-point recognition data for TypeScript/JavaScript (`entry-index@0.1`).
 *
 * Framework knowledge lives here as tables, not as branches in the
 * extractor: adding a framework is a row plus fixtures. A consumer may pass
 * its own tables to `buildTsCallGraph` in place of these defaults.
 */

export type EntryKind =
  | 'route' | 'listener' | 'scheduled' | 'main' | 'export' | 'bean' | 'reflection' | 'lifecycle' | 'test';

/** `declared` and `conventional` can close a path; `inferred` only keeps code alive. */
export type EntryCertainty = 'declared' | 'conventional' | 'inferred';

export interface RouteRegistrarTable {
  /** Packages whose default or named export creates a router or app. */
  packages: readonly string[];
  /** Method names on the router that register a handler under a path. */
  verbs: readonly string[];
  /** Method names that mount a router or middleware under an optional prefix (`app.use('/api', r)`). */
  mountVerbs?: readonly string[];
  /** Method name that scopes a path for chained verbs (`router.route('/x').get(h)`). */
  routeChain?: string;
}

export interface ReactRouterTable {
  packages: readonly string[];
  /** JSX elements that declare a route (`<Route path="/x" element={<Page/>}/>`). */
  routeElements: readonly string[];
  /** Functions taking an array of route objects (`createBrowserRouter([...])`). */
  routerFactories: readonly string[];
}

export interface FileRoutesTable {
  /** The dependency in `package.json` that turns the file conventions on. */
  dependency: string;
}

export interface DecoratorEntryRow {
  /** The package the decorator is imported from. */
  package: string;
  names: readonly string[];
  kind: EntryKind;
  /** What the decorator marks: a method is the entry, or the class (its constructor). */
  on: 'method' | 'class';
  /** For routes: the class decorator whose first string argument is the path prefix. */
  prefixFrom?: string;
}

export interface TestRunnerTable {
  /** Global functions whose function arguments the runner calls. */
  functions: readonly string[];
  /** Files the runner loads, by repository-relative path. */
  filePattern: RegExp;
}

export interface EntryTables {
  routes: RouteRegistrarTable;
  decorators: readonly DecoratorEntryRow[];
  tests: TestRunnerTable;
  /** React Router route declarations; absent turns them off. */
  reactRouter?: ReactRouterTable;
  /** Next.js file routes (`pages/`, `app/`, `middleware`); absent turns them off. */
  nextFileRoutes?: FileRoutesTable;
}

export const DEFAULT_ENTRY_TABLES: EntryTables = {
  routes: {
    packages: ['express', 'fastify', 'koa-router', '@koa/router', 'hono', 'restify', 'polka', 'router'],
    verbs: ['get', 'post', 'put', 'delete', 'del', 'patch', 'options', 'head', 'all'],
    mountVerbs: ['use'],
    routeChain: 'route',
  },
  decorators: [
    { package: '@nestjs/common', names: ['Get', 'Post', 'Put', 'Delete', 'Patch', 'Options', 'Head', 'All'], kind: 'route', on: 'method', prefixFrom: 'Controller' },
    { package: '@nestjs/microservices', names: ['MessagePattern', 'EventPattern'], kind: 'listener', on: 'method' },
    { package: '@nestjs/websockets', names: ['SubscribeMessage'], kind: 'listener', on: 'method' },
    { package: '@nestjs/schedule', names: ['Cron', 'Interval', 'Timeout'], kind: 'scheduled', on: 'method' },
    { package: '@nestjs/common', names: ['Injectable', 'Controller'], kind: 'bean', on: 'class' },
  ],
  tests: {
    functions: ['describe', 'it', 'test', 'suite', 'beforeEach', 'afterEach', 'beforeAll', 'afterAll', 'before', 'after'],
    filePattern: /(?:\.(?:test|spec)\.[cm]?[jt]sx?$)|(?:(?:^|\/)__tests__\/)/,
  },
  reactRouter: {
    packages: ['react-router', 'react-router-dom'],
    routeElements: ['Route'],
    routerFactories: ['createBrowserRouter', 'createHashRouter', 'createMemoryRouter', 'createStaticRouter', 'useRoutes'],
  },
  nextFileRoutes: { dependency: 'next' },
};
