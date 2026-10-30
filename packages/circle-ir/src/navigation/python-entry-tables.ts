/**
 * Entry-point recognition data for Python (`entry-index@0.1`).
 *
 * Framework knowledge as tables. A consumer may pass its own to
 * `buildPythonGraph`.
 */

export interface PythonRouterRow {
  /** The package the app or router class is imported from. */
  package: string;
  /** Callables that create an app or router (`Flask`, `Blueprint`, `FastAPI`, `APIRouter`). */
  factories: readonly string[];
  /** Decorator methods that register a route; `null` reads `methods=[...]` (default `GET`). */
  verbs: Readonly<Record<string, string | null>>;
  /** The factory keyword giving the router's own prefix. */
  prefixKeyword?: string;
  /** Methods that mount a child router: method → the keyword carrying the prefix. */
  mounts: Readonly<Record<string, string>>;
  /** `<int:id>` → `{id}` (Flask/Werkzeug converters). */
  converters?: boolean;
}

export interface PythonDecoratorRow {
  /** Packages the decorator (or its receiver) comes from. */
  packages: readonly string[];
  /** Decorator names: a bare name (`shared_task`) or the last attribute (`task`, `command`). */
  names: readonly string[];
  kind: 'main' | 'listener' | 'scheduled' | 'test' | 'lifecycle';
}

export interface PythonEntryTables {
  routers: readonly PythonRouterRow[];
  decorators: readonly PythonDecoratorRow[];
  /** Django-style URL configuration functions (`path`, `re_path`) and their package. */
  urlConf: { package: string; functions: readonly string[] };
  /** Test files by repository path. */
  testFile: RegExp;
}

export const DEFAULT_PYTHON_ENTRY_TABLES: PythonEntryTables = {
  routers: [
    {
      package: 'flask',
      factories: ['Flask', 'Blueprint'],
      verbs: { route: null, get: 'GET', post: 'POST', put: 'PUT', delete: 'DELETE', patch: 'PATCH' },
      prefixKeyword: 'url_prefix',
      mounts: { register_blueprint: 'url_prefix' },
      converters: true,
    },
    {
      package: 'fastapi',
      factories: ['FastAPI', 'APIRouter'],
      verbs: { get: 'GET', post: 'POST', put: 'PUT', delete: 'DELETE', patch: 'PATCH', head: 'HEAD', options: 'OPTIONS', api_route: null, websocket: 'WS' },
      prefixKeyword: 'prefix',
      mounts: { include_router: 'prefix' },
    },
  ],
  decorators: [
    { packages: ['click', 'typer'], names: ['command', 'group'], kind: 'main' },
    { packages: ['celery'], names: ['task', 'shared_task'], kind: 'listener' },
    { packages: ['pytest'], names: ['fixture'], kind: 'test' },
  ],
  urlConf: { package: 'django.urls', functions: ['path', 're_path', 'url'] },
  testFile: /(?:^|\/)(?:test_[^/]*|[^/]*_test|conftest)\.py$|(?:^|\/)tests?\//,
};
