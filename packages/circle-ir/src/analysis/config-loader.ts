/**
 * Configuration loader for taint source/sink definitions
 *
 * Loads YAML configs from configs/sources/ and configs/sinks/
 */

import type {
  SourceConfig,
  SinkConfig,
  SinkSemanticsConfig,
  SinkSemanticsEntry,
  TaintConfig,
  SourcePattern,
  SinkPattern,
  SanitizerPattern,
  HeaderRule,
} from '../types/config.js';

/**
 * Parse YAML/JSON configuration content.
 * Uses JSON since the config files are actually JSON despite .yaml extension.
 */
export function parseConfig<T>(content: string): T {
  return JSON.parse(content) as T;
}

/**
 * Load and merge multiple source configs.
 */
export function loadSourceConfigs(configs: SourceConfig[]): SourcePattern[] {
  const patterns: SourcePattern[] = [];

  for (const config of configs) {
    if (config.sources) {
      for (const source of config.sources) {
        // Normalise: property-based sources need property_tainted to be matched
        // by the taint-matcher. Auto-set it when property + object are defined.
        if (source.property && source.object && !source.property_tainted) {
          source.property_tainted = true;
        }
        patterns.push(source);
      }
    }
  }

  return patterns;
}

/**
 * Load and merge multiple sink configs.
 */
export function loadSinkConfigs(configs: SinkConfig[]): {
  sinks: SinkPattern[];
  sanitizers: SanitizerPattern[];
} {
  const sinks: SinkPattern[] = [];
  const sanitizers: SanitizerPattern[] = [];

  for (const config of configs) {
    if (config.sinks) {
      sinks.push(...config.sinks);
    }
    if (config.sanitizers) {
      sanitizers.push(...config.sanitizers);
    }
  }

  return { sinks, sanitizers };
}

/**
 * Load and merge sink-semantics registry entries from one or more
 * configs. Used by `SinkSemanticsPass` (cognium-dev #139 Tier A) to
 * drop sinks whose emitted `SinkType` label disagrees with the
 * registry's real-behavior classification.
 */
export function loadSinkSemanticsConfigs(
  configs: SinkSemanticsConfig[],
): SinkSemanticsEntry[] {
  const entries: SinkSemanticsEntry[] = [];
  for (const config of configs) {
    if (config.sinks) {
      entries.push(...config.sinks);
    }
  }
  return entries;
}

/**
 * Create a combined taint configuration from raw config contents.
 *
 * `sinkSemanticsContents` is optional to preserve backward
 * compatibility with existing callers; passing an empty array (or
 * omitting the argument) disables the sink-semantics gate.
 */
export function createTaintConfig(
  sourceContents: string[],
  sinkContents: string[],
  sinkSemanticsContents: string[] = [],
): TaintConfig {
  const sourceConfigs = sourceContents.map((c) => parseConfig<SourceConfig>(c));
  const sinkConfigs = sinkContents.map((c) => parseConfig<SinkConfig>(c));
  const sinkSemanticsConfigs = sinkSemanticsContents.map((c) =>
    parseConfig<SinkSemanticsConfig>(c),
  );

  const sources = loadSourceConfigs(sourceConfigs);
  const { sinks, sanitizers } = loadSinkConfigs(sinkConfigs);
  const sinkSemantics = loadSinkSemanticsConfigs(sinkSemanticsConfigs);

  return { sources, sinks, sanitizers, sinkSemantics };
}

/**
 * Embedded default configurations (subset for standalone use).
 * Full configs should be loaded from files when available.
 */
export const DEFAULT_SOURCES: SourcePattern[] = [
  // HTTP Sources (Servlet API)
  { method: 'getParameter', class: 'HttpServletRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getParameterValues', class: 'HttpServletRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getParameterMap', class: 'HttpServletRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getParameterNames', class: 'HttpServletRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getHeader', class: 'HttpServletRequest', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'getHeaders', class: 'HttpServletRequest', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'getHeaderNames', class: 'HttpServletRequest', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'getQueryString', class: 'HttpServletRequest', type: 'http_query', severity: 'high', return_tainted: true },
  { method: 'getCookies', class: 'HttpServletRequest', type: 'http_cookie', severity: 'high', return_tainted: true },
  { method: 'getInputStream', class: 'HttpServletRequest', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'getReader', class: 'HttpServletRequest', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'getPathInfo', class: 'HttpServletRequest', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'getRequestURI', class: 'HttpServletRequest', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'getRequestURL', class: 'HttpServletRequest', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'getServletPath', class: 'HttpServletRequest', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'getContextPath', class: 'HttpServletRequest', type: 'http_path', severity: 'medium', return_tainted: true },
  { method: 'getRemoteHost', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  { method: 'getRemoteAddr', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  // Apache Shiro WebUtils helpers — return URL-decoded request data. The internal
  // decodeRequestString → URLDecoder.decode chain can re-introduce ../ from
  // %2e%2e payloads that bypassed auth-time normalization. CVE-2023-34478,
  // CVE-2023-46749 (issue #8).
  { method: 'getPathWithinApplication', class: 'WebUtils', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'getRequestUri', class: 'WebUtils', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'decodeRequestString', class: 'WebUtils', type: 'http_path', severity: 'high', return_tainted: true },
  // cognium-dev #249 3.162.0: java.net.URLDecoder.decode reintroduces taint
  // by expanding %XX sequences into arbitrary bytes. This is the
  // decode-after-encode bypass pattern exercised by SecuriBench Micro
  // `sanitizers/Sanitizers5.java`: encode sanitizes `//evil.com` into
  // `%2F%2Fevil.com`, then decode restores the redirect payload before
  // it reaches `sendRedirect`. Registering as a source ensures the
  // reaching-def walk does not credit an upstream URLEncoder.encode
  // sanitizer for taint that has since been re-expanded.
  { method: 'decode', class: 'URLDecoder', type: 'http_path', severity: 'high', return_tainted: true },
  // Additional HTTP request methods that can be attacker-controlled
  { method: 'getProtocol', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  { method: 'getScheme', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  { method: 'getAuthType', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  { method: 'getRemoteUser', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  { method: 'getMethod', class: 'HttpServletRequest', type: 'http_header', severity: 'low', return_tainted: true },
  { method: 'getContentType', class: 'HttpServletRequest', type: 'http_header', severity: 'medium', return_tainted: true },
  { method: 'getCharacterEncoding', class: 'HttpServletRequest', type: 'http_header', severity: 'low', return_tainted: true },

  // Enumeration/Iterator sources (from request.getHeaders(), etc.)
  { method: 'nextElement', class: 'Enumeration', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'nextElement', type: 'http_header', severity: 'high', return_tainted: true },

  // Cookie sources
  { method: 'getValue', class: 'Cookie', type: 'http_cookie', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'Cookie', type: 'http_cookie', severity: 'high', return_tainted: true },

  // I/O Sources (Scanner, BufferedReader, etc.)
  { method: 'readLine', class: 'BufferedReader', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'readLine', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'nextLine', class: 'Scanner', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'next', class: 'Scanner', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'nextInt', class: 'Scanner', type: 'io_input', severity: 'high', return_tainted: true },

  // Database result sources
  { method: 'getString', class: 'ResultSet', type: 'db_input', severity: 'medium', return_tainted: true },
  { method: 'getObject', class: 'ResultSet', type: 'db_input', severity: 'medium', return_tainted: true },
  { method: 'getInt', class: 'ResultSet', type: 'db_input', severity: 'medium', return_tainted: true },

  // Spring annotations
  { annotation: 'RequestParam', type: 'http_param', severity: 'high', param_tainted: true },
  { annotation: 'RequestBody', type: 'http_body', severity: 'high', param_tainted: true },
  { annotation: 'PathVariable', type: 'http_path', severity: 'medium', param_tainted: true },
  { annotation: 'RequestHeader', type: 'http_header', severity: 'high', param_tainted: true },
  { annotation: 'CookieValue', type: 'http_cookie', severity: 'high', param_tainted: true },

  // JAX-RS annotations
  { annotation: 'QueryParam', type: 'http_param', severity: 'high', param_tainted: true },
  { annotation: 'FormParam', type: 'http_param', severity: 'high', param_tainted: true },
  { annotation: 'PathParam', type: 'http_path', severity: 'medium', param_tainted: true },
  { annotation: 'HeaderParam', type: 'http_header', severity: 'high', param_tainted: true },

  // Jenkins data-binding: every parameter of an annotated constructor is wired
  // from form/JSON user input at construction time. Method-level annotation —
  // all params tainted.
  { method_annotation: 'DataBoundConstructor', type: 'http_param', severity: 'high' },

  // Environment
  { method: 'getenv', class: 'System', type: 'env_input', severity: 'medium', return_tainted: true },
  { method: 'getProperty', class: 'System', type: 'env_input', severity: 'medium', return_tainted: true },

  // Note: Properties.getProperty is NOT included by default as it causes many false positives
  // in OWASP Benchmark. Include it via custom config if needed for specific analyses.

  // Servlet Configuration Parameters (can be attacker-influenced in some deployments)
  { method: 'getInitParameter', class: 'ServletConfig', type: 'http_param', severity: 'medium', return_tainted: true },
  { method: 'getInitParameter', class: 'ServletContext', type: 'http_param', severity: 'medium', return_tainted: true },
  { method: 'getInitParameter', class: 'FilterConfig', type: 'http_param', severity: 'medium', return_tainted: true },
  { method: 'getInitParameter', type: 'http_param', severity: 'medium', return_tainted: true },
  { method: 'getServletConfig', class: 'GenericServlet', type: 'http_param', severity: 'medium', return_tainted: true },

  // Vert.x Framework
  { method: 'getParam', class: 'RoutingContext', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getBodyAsString', class: 'RoutingContext', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'getBodyAsJson', class: 'RoutingContext', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'request', class: 'RoutingContext', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'pathParam', class: 'RoutingContext', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'queryParam', class: 'RoutingContext', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'path', class: 'HttpServerRequest', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'uri', class: 'HttpServerRequest', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'getParam', class: 'HttpServerRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getHeader', class: 'HttpServerRequest', type: 'http_header', severity: 'high', return_tainted: true },

  // Spark Framework (Spark Java)
  { method: 'params', class: 'Request', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'queryParams', class: 'Request', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'body', class: 'Request', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'headers', class: 'Request', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'pathInfo', class: 'Request', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'uri', class: 'Request', type: 'http_path', severity: 'high', return_tainted: true },

  // Apache Camel
  { method: 'getBody', class: 'Message', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'getBody', class: 'Exchange', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'getIn', class: 'Exchange', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'getHeader', class: 'Message', type: 'http_header', severity: 'high', return_tainted: true },

  // File name sources (common in path traversal vulnerabilities)
  { method: 'getFileName', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'File', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getPath', class: 'File', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getAbsolutePath', class: 'File', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'toString', class: 'Path', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'getFileName', class: 'Path', type: 'file_input', severity: 'high', return_tainted: true },

  // Multipart file uploads
  { method: 'getOriginalFilename', class: 'MultipartFile', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'MultipartFile', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getSubmittedFileName', class: 'Part', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'Part', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getFileName', class: 'Part', type: 'file_input', severity: 'high', return_tainted: true },

  // Email attachment sources (common in CVE-2018-8041 type vulnerabilities)
  { method: 'getFileName', class: 'BodyPart', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getFileName', class: 'MimeBodyPart', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getDisposition', class: 'Part', type: 'file_input', severity: 'medium', return_tainted: true },

  // Archive entry names (Zip-Slip / Tar-Slip CWE-22, issue #52)
  // entry.getName() returns a path that may contain ../ — flowing into File()/FileOutputStream()
  // is a classic Zip-Slip vulnerability.
  { method: 'getName', class: 'ZipEntry', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'ZipArchiveEntry', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'TarArchiveEntry', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'getName', class: 'ArchiveEntry', type: 'file_input', severity: 'high', return_tainted: true },

  // Command line arguments
  { method: 'getArgs', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getOptionValue', class: 'CommandLine', type: 'io_input', severity: 'high', return_tainted: true },

  // Retrofit/OkHttp
  { method: 'url', class: 'Request', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'body', class: 'RequestBody', type: 'http_body', severity: 'high', return_tainted: true },

  // XML/Deserialization sources (can contain attacker-controlled data)
  { method: 'fromXML', class: 'XStream', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'unmarshal', class: 'XStream', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'fromString', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'unmarshal', class: 'Unmarshaller', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'readValue', class: 'ObjectMapper', type: 'io_input', severity: 'high', return_tainted: true },

  // Jenkins/CI sources
  { method: 'getScript', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'getScriptPath', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'getCommand', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'getShell', type: 'io_input', severity: 'critical', return_tainted: true },

  // Wiki/CMS sources (JSPWiki, Confluence, etc.)
  { method: 'getText', class: 'WikiContext', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getPage', class: 'WikiContext', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getVariable', class: 'WikiContext', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getAttribute', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getValue', type: 'io_input', severity: 'high', return_tainted: true },

  // Map/Collection sources (plugin parameters, config values)
  { method: 'get', class: 'Map', type: 'plugin_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'HashMap', type: 'plugin_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'LinkedHashMap', type: 'plugin_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'TreeMap', type: 'plugin_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'ConcurrentHashMap', type: 'plugin_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'Hashtable', type: 'plugin_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'Properties', type: 'config_param', severity: 'high', return_tainted: true },

  // Message/Event sources
  { method: 'getText', class: 'Message', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getPayload', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getData', type: 'io_input', severity: 'high', return_tainted: true },

  // FHIR/HL7 sources (medical records can contain user-provided data)
  { method: 'getText', class: 'Questionnaire', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getLinkId', class: 'QuestionnaireItemComponent', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getText', class: 'QuestionnaireItemComponent', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getPrefix', class: 'QuestionnaireItemComponent', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getValueString', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getValue', class: 'PrimitiveType', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'asStringValue', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getDisplay', class: 'Coding', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getCode', class: 'Coding', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getText', class: 'CodeableConcept', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getExpression', class: 'Expression', type: 'io_input', severity: 'high', return_tainted: true },

  // XWiki/Wiki rendering sources
  { method: 'getContent', class: 'Block', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getParameters', class: 'Block', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getRawContent', type: 'io_input', severity: 'high', return_tainted: true },
  // XWiki request-bound sources (issue #10, CVE-2022-24897 / 2023-29201 / 2023-29528 /
  // 2023-36471 / 2023-37908). XWikiRequest.get(name) / .getParameter(name) /
  // XWikiContext.getRequest().get(...) all return URL/form data unchanged.
  { method: 'get', class: 'XWikiRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getParameter', class: 'XWikiRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getParameterValues', class: 'XWikiRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getParameterMap', class: 'XWikiRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'getHeader', class: 'XWikiRequest', type: 'http_header', severity: 'high', return_tainted: true },

  // SAX/XML parsing sources (data from parsed XML)
  { method: 'getAttributes', class: 'XMLReader', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getValue', class: 'Attributes', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getLocalName', class: 'Attributes', type: 'io_input', severity: 'high', return_tainted: true },

  // Validation framework sources
  { method: 'getValue', class: 'ConstraintValidatorContext', type: 'io_input', severity: 'medium', return_tainted: true },
  { method: 'getInvalidValue', type: 'io_input', severity: 'medium', return_tainted: true },

  // Shell/Command provider sources (NiFi, etc.)
  { method: 'getGroupMembers', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getCommandsProvider', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getUserByIdentity', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'refreshUsersAndGroups', type: 'io_input', severity: 'high', return_tainted: true },

  // Jenkins/CI pipeline sources
  { method: 'getScriptPath', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'getFilePathSuffix', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getPath', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'contentAsString', type: 'file_input', severity: 'critical', return_tainted: true },
  { method: 'readAsString', type: 'file_input', severity: 'critical', return_tainted: true },
  { method: 'content', type: 'file_input', severity: 'high', return_tainted: true },
  { method: 'retrieve', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'findResources', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'loadScripts', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'doRetrieve', type: 'io_input', severity: 'high', return_tainted: true },

  // ActiveMQ/Message broker sources
  { method: 'processControlCommand', type: 'io_input', severity: 'critical', return_tainted: true },
  { method: 'getCommand', class: 'ControlCommand', type: 'io_input', severity: 'critical', return_tainted: true },

  // Spring OAuth sources
  { method: 'authenticate', class: 'OAuth2RequestAuthenticator', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'getAccessToken', type: 'http_header', severity: 'high', return_tainted: true },

  // Struts/OGNL sources
  { method: 'addParametersToContext', type: 'http_param', severity: 'critical', return_tainted: true },
  { method: 'getParameters', class: 'ActionContext', type: 'http_param', severity: 'high', return_tainted: true },

  // Cron/Parser sources
  { method: 'parse', class: 'CronParser', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'isValid', class: 'CronValidator', type: 'io_input', severity: 'high', return_tainted: true },

  // Jenkins library/configuration sources
  { method: 'getName', class: 'LibraryRecord', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getVersion', class: 'LibraryRecord', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'name', class: 'LibraryRecord', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'version', class: 'LibraryRecord', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getLibrary', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getDefaultVersion', type: 'io_input', severity: 'high', return_tainted: true },
  // SCM/repository sources (can be attacker-controlled via fork/PR)
  { method: 'getRemote', class: 'RemoteConfig', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getURIs', class: 'RemoteConfig', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getBranch', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'getRepository', type: 'io_input', severity: 'high', return_tainted: true },

  // =========================================================================
  // Express.js / Node.js Sources (Property-based)
  // =========================================================================

  // Express.js Request Properties
  { property: 'params', object: 'req', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'query', object: 'req', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'body', object: 'req', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'headers', object: 'req', type: 'http_header', severity: 'high', property_tainted: true },
  { property: 'cookies', object: 'req', type: 'http_cookie', severity: 'high', property_tainted: true },
  { property: 'url', object: 'req', type: 'http_path', severity: 'high', property_tainted: true },
  { property: 'path', object: 'req', type: 'http_path', severity: 'high', property_tainted: true },
  { property: 'hostname', object: 'req', type: 'http_header', severity: 'medium', property_tainted: true },
  { property: 'ip', object: 'req', type: 'http_header', severity: 'medium', property_tainted: true },
  { property: 'ips', object: 'req', type: 'http_header', severity: 'medium', property_tainted: true },
  { property: 'protocol', object: 'req', type: 'http_header', severity: 'low', property_tainted: true },
  { property: 'originalUrl', object: 'req', type: 'http_path', severity: 'high', property_tainted: true },
  { property: 'baseUrl', object: 'req', type: 'http_path', severity: 'medium', property_tainted: true },
  { property: 'file', object: 'req', type: 'file_input', severity: 'high', property_tainted: true },
  { property: 'files', object: 'req', type: 'file_input', severity: 'high', property_tainted: true },

  // Also match 'request' (alternative naming)
  { property: 'params', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'query', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'body', object: 'request', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'headers', object: 'request', type: 'http_header', severity: 'high', property_tainted: true },

  // Node.js process (environment/args)
  { property: 'env', object: 'process', type: 'env_input', severity: 'medium', property_tainted: true },
  { property: 'argv', object: 'process', type: 'io_input', severity: 'high', property_tainted: true },

  // Koa.js (ctx.request, ctx.query, etc.)
  { property: 'query', object: 'ctx', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'params', object: 'ctx', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'request', object: 'ctx', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'headers', object: 'ctx', type: 'http_header', severity: 'high', property_tainted: true },

  // Browser DOM sources
  { property: 'referrer', object: 'document', type: 'http_header', severity: 'high', property_tainted: true },
  { property: 'hash', object: 'location', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'search', object: 'location', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'href', object: 'location', type: 'http_path', severity: 'high', property_tainted: true },
  { property: 'pathname', object: 'location', type: 'http_path', severity: 'medium', property_tainted: true },
  { property: 'data', object: 'event', type: 'dom_input', severity: 'high', property_tainted: true },
  { property: 'data', object: 'e', type: 'dom_input', severity: 'high', property_tainted: true },
  { property: 'data', object: 'msg', type: 'dom_input', severity: 'high', property_tainted: true },
  { property: 'data', object: 'message', type: 'dom_input', severity: 'high', property_tainted: true },

  // =========================================================================
  // Python / Flask / Django Sources
  // =========================================================================

  // Flask request object
  { method: 'get', class: 'args', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'form', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'headers', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'get', class: 'cookies', type: 'http_cookie', severity: 'high', return_tainted: true },
  { property: 'json', object: 'request', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'data', object: 'request', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'stream', object: 'request', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'path', object: 'request', type: 'http_path', severity: 'medium', property_tainted: true },
  { property: 'query_string', object: 'request', type: 'http_query', severity: 'high', property_tainted: true },
  // Flask request.get_data() — raw request bytes (method form, parallel to request.data property)
  { method: 'get_data', class: 'request', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'get_json', class: 'request', type: 'http_body', severity: 'high', return_tainted: true },

  // Django request object
  { method: 'get', class: 'GET', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'POST', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'get', class: 'META', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'get', class: 'COOKIES', type: 'http_cookie', severity: 'high', return_tainted: true },
  { property: 'body', object: 'request', type: 'http_body', severity: 'high', property_tainted: true },
  { property: 'path_info', object: 'request', type: 'http_path', severity: 'medium', property_tainted: true },

  // Python environment and I/O
  { method: 'getenv', class: 'os', type: 'env_input', severity: 'medium', return_tainted: true },
  { method: 'get', class: 'environ', type: 'env_input', severity: 'medium', return_tainted: true },
  { method: 'input', type: 'io_input', severity: 'high', return_tainted: true },
  { method: 'read', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'readline', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'readlines', type: 'file_input', severity: 'medium', return_tainted: true },

  // Python database sources
  { method: 'fetchone', type: 'db_input', severity: 'medium', return_tainted: true },
  { method: 'fetchall', type: 'db_input', severity: 'medium', return_tainted: true },
  { method: 'fetchmany', type: 'db_input', severity: 'medium', return_tainted: true },

  // Python network sources
  { method: 'recv', class: 'socket', type: 'network_input', severity: 'high', return_tainted: true },
  { method: 'recvfrom', class: 'socket', type: 'network_input', severity: 'high', return_tainted: true },

  // FastAPI sources (decorator-based, like Spring)
  { annotation: 'Path', type: 'http_path', severity: 'high', param_tainted: true },
  { annotation: 'Query', type: 'http_param', severity: 'high', param_tainted: true },
  { annotation: 'Body', type: 'http_body', severity: 'high', param_tainted: true },
  { annotation: 'Header', type: 'http_header', severity: 'high', param_tainted: true },
  { annotation: 'Cookie', type: 'http_cookie', severity: 'high', param_tainted: true },
  { annotation: 'Form', type: 'http_param', severity: 'high', param_tainted: true },
  { annotation: 'File', type: 'file_input', severity: 'high', param_tainted: true },
  // FastAPI Request object
  { method: 'json', class: 'Request', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'form', class: 'Request', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'body', class: 'Request', type: 'http_body', severity: 'high', return_tainted: true },
  { property: 'query_params', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'path_params', object: 'request', type: 'http_path', severity: 'high', property_tainted: true },

  // Additional Flask/Werkzeug patterns
  { method: 'values', class: 'request', type: 'http_param', severity: 'high', return_tainted: true },
  { property: 'args', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'form', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'files', object: 'request', type: 'file_input', severity: 'high', property_tainted: true },
  { property: 'headers', object: 'request', type: 'http_header', severity: 'high', property_tainted: true },
  { property: 'cookies', object: 'request', type: 'http_cookie', severity: 'high', property_tainted: true },
  { property: 'environ', object: 'request', type: 'http_header', severity: 'medium', property_tainted: true },

  // Additional Django patterns
  { property: 'GET', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'POST', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'FILES', object: 'request', type: 'file_input', severity: 'high', property_tainted: true },
  { property: 'META', object: 'request', type: 'http_header', severity: 'high', property_tainted: true },
  { property: 'COOKIES', object: 'request', type: 'http_cookie', severity: 'high', property_tainted: true },
  { method: 'getlist', class: 'QueryDict', type: 'http_param', severity: 'high', return_tainted: true },

  // Pyramid framework
  { property: 'params', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'matchdict', object: 'request', type: 'http_path', severity: 'high', property_tainted: true },
  { method: 'getall', class: 'MultiDict', type: 'http_param', severity: 'high', return_tainted: true },

  // aiohttp sources
  { method: 'json', class: 'Request', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'post', class: 'Request', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'text', class: 'Request', type: 'http_body', severity: 'high', return_tainted: true },
  { property: 'query', object: 'request', type: 'http_param', severity: 'high', property_tainted: true },
  { property: 'match_info', object: 'request', type: 'http_path', severity: 'high', property_tainted: true },

  // =========================================================================
  // Rust Sources (Actix-web, Rocket, Axum)
  // =========================================================================

  // Actix-web
  { method: 'query_string', class: 'HttpRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'match_info', class: 'HttpRequest', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'into_inner', class: 'Path', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'into_inner', class: 'Query', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'into_inner', class: 'Json', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'into_inner', class: 'Form', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'headers', class: 'HttpRequest', type: 'http_header', severity: 'high', return_tainted: true },
  { method: 'cookie', class: 'HttpRequest', type: 'http_cookie', severity: 'high', return_tainted: true },

  // Rocket
  { method: 'param', class: 'Request', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'cookies', class: 'Request', type: 'http_cookie', severity: 'high', return_tainted: true },

  // Axum extractors — Rust-only. The simple names `Json`/`Query`/`Path`/`Form`
  // collide with stdlib types in other ecosystems (notably Python's
  // `pathlib.Path` constructor and `flask.Form`), so they MUST be
  // language-scoped to Rust to avoid spurious source matches.
  { method: 'Json', type: 'http_body', severity: 'high', return_tainted: true, languages: ['rust'] },
  { method: 'Query', type: 'http_param', severity: 'high', return_tainted: true, languages: ['rust'] },
  { method: 'Path', type: 'http_path', severity: 'high', return_tainted: true, languages: ['rust'] },
  { method: 'Form', type: 'http_param', severity: 'high', return_tainted: true, languages: ['rust'] },

  // Rust std library
  { method: 'var', class: 'env', type: 'env_input', severity: 'medium', return_tainted: true },
  { method: 'var_os', class: 'env', type: 'env_input', severity: 'medium', return_tainted: true },
  { method: 'args', class: 'env', type: 'env_input', severity: 'medium', return_tainted: true },
  { method: 'read_to_string', class: 'File', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'read', class: 'File', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'read_line', class: 'BufReader', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'lines', class: 'BufReader', type: 'file_input', severity: 'medium', return_tainted: true },
  { method: 'read_to_string', class: 'stdin', type: 'io_input', severity: 'medium', return_tainted: true },
  { method: 'read_line', class: 'stdin', type: 'io_input', severity: 'medium', return_tainted: true },
  { method: 'lines', class: 'stdin', type: 'io_input', severity: 'medium', return_tainted: true },
  { method: 'recv', class: 'TcpStream', type: 'network_input', severity: 'high', return_tainted: true },
  { method: 'read', class: 'TcpStream', type: 'network_input', severity: 'high', return_tainted: true },
  { method: 'read_to_end', class: 'TcpStream', type: 'network_input', severity: 'high', return_tainted: true },
  { method: 'read_to_string', class: 'TcpStream', type: 'network_input', severity: 'high', return_tainted: true },

  // =========================================================================
  // Modern taint sources (cognium-dev #242 — 3.170.0)
  // GraphQL resolver args, gRPC request metadata, cache reads (second-order
  // taint), and JWT claims (unverified decode). These attacker-influenced
  // surfaces were previously silent — a resolver that concatenated an
  // `Args`-annotated field into a SQL string produced zero flows.
  // =========================================================================

  // --- GraphQL resolver argument sources (JS / TS — Apollo, TypeGraphQL, NestJS) ---
  // TypeGraphQL / NestJS annotate query/mutation/subscription methods; every
  // parameter on the annotated method carries attacker input from the GraphQL
  // POST body's `variables` field.
  { method_annotation: 'Query', type: 'http_body', severity: 'high', languages: ['javascript', 'typescript'] },
  { method_annotation: 'Mutation', type: 'http_body', severity: 'high', languages: ['javascript', 'typescript'] },
  { method_annotation: 'Subscription', type: 'http_body', severity: 'high', languages: ['javascript', 'typescript'] },
  { method_annotation: 'FieldResolver', type: 'http_body', severity: 'high', languages: ['javascript', 'typescript'] },
  { method_annotation: 'ResolveField', type: 'http_body', severity: 'high', languages: ['javascript', 'typescript'] },
  // Parameter-level: `@Arg('id') id: string`, `@Args('input') input: FooDto`.
  { annotation: 'Arg', type: 'http_param', severity: 'high', param_tainted: true, languages: ['javascript', 'typescript'] },
  { annotation: 'Args', type: 'http_param', severity: 'high', param_tainted: true, languages: ['javascript', 'typescript'] },

  // --- GraphQL resolver argument sources (Python — Strawberry, Graphene, Ariadne) ---
  { method_annotation: 'strawberry.field', type: 'http_body', severity: 'high', languages: ['python'] },
  { method_annotation: 'strawberry.mutation', type: 'http_body', severity: 'high', languages: ['python'] },
  { method_annotation: 'strawberry.subscription', type: 'http_body', severity: 'high', languages: ['python'] },

  // --- GraphQL resolver argument sources (Java — Netflix DGS, SPQR, graphql-java-annotations) ---
  { method_annotation: 'DgsQuery', type: 'http_body', severity: 'high', languages: ['java'] },
  { method_annotation: 'DgsMutation', type: 'http_body', severity: 'high', languages: ['java'] },
  { method_annotation: 'DgsSubscription', type: 'http_body', severity: 'high', languages: ['java'] },
  { method_annotation: 'DgsData', type: 'http_body', severity: 'high', languages: ['java'] },
  { method_annotation: 'GraphQLQuery', type: 'http_body', severity: 'high', languages: ['java'] },
  { method_annotation: 'GraphQLMutation', type: 'http_body', severity: 'high', languages: ['java'] },
  { annotation: 'InputArgument', type: 'http_param', severity: 'high', param_tainted: true, languages: ['java'] },
  { annotation: 'GraphQLArgument', type: 'http_param', severity: 'high', param_tainted: true, languages: ['java'] },

  // --- gRPC request metadata (Python — grpcio) ---
  // `context.invocation_metadata()` returns the caller-supplied metadata tuple.
  // No `class` filter — receiver names vary (`context`, `ctx`, `servicer_context`).
  { method: 'invocation_metadata', type: 'http_header', severity: 'high', return_tainted: true, languages: ['python'] },

  // --- gRPC request metadata (JS / TS — @grpc/grpc-js) ---
  // `call.metadata.get(key)` / `call.metadata.getMap()` inside a service handler.
  { method: 'get', class: 'Metadata', type: 'http_header', severity: 'high', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'getMap', class: 'Metadata', type: 'http_header', severity: 'high', return_tainted: true, languages: ['javascript', 'typescript'] },

  // --- gRPC request metadata (Go — google.golang.org/grpc/metadata) ---
  // `md, _ := metadata.FromIncomingContext(ctx)` pulls the caller's headers.
  { method: 'FromIncomingContext', class: 'metadata', type: 'http_header', severity: 'high', return_tainted: true, languages: ['go'] },

  // --- gRPC request metadata (Java — io.grpc.Metadata) ---
  // Server-side interceptor receives `Metadata headers`; `headers.get(KEY)`
  // returns caller-supplied header values.
  { method: 'get', class: 'Metadata', type: 'http_header', severity: 'high', return_tainted: true, languages: ['java'] },

  // --- Cache reads (second-order taint — Redis / Memcached / Django cache) ---
  // The cache round-trip is a canonical second-order sink: whatever was
  // written previously (potentially attacker-controlled) resurfaces on read.
  // Severity 'medium' — cache contents are usually filtered by the writer but
  // the read side often forgets that guarantee. Class-scoped to `Redis`,
  // `Jedis`, `cache` to avoid colliding with generic `Map.get()`.
  { method: 'get', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['python'] },
  { method: 'hget', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['python'] },
  { method: 'mget', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['python'] },
  { method: 'lrange', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['python'] },
  { method: 'get', class: 'cache', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['python'] },
  { method: 'get_many', class: 'cache', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['python'] },
  { method: 'get', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'hget', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'mget', class: 'Redis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'get', class: 'Jedis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['java'] },
  { method: 'hget', class: 'Jedis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['java'] },
  { method: 'mget', class: 'Jedis', type: 'db_input', severity: 'medium', return_tainted: true, languages: ['java'] },

  // --- Serverless transport channels (cognium-dev #213 first slice) ---
  //
  // AWS Lambda / API Gateway invocation-event properties. The Lambda
  // handler signature `(event, context) => …` (JS/TS) or
  // `def handler(event, context)` (Python) receives an `event` object
  // whose properties carry the untrusted HTTP-request-shaped payload:
  //
  //   event.body                              — request body (string)
  //   event.queryStringParameters             — `?a=b` params
  //   event.multiValueQueryStringParameters   — `?a=1&a=2` params
  //   event.pathParameters                    — path template captures
  //   event.headers                           — request headers
  //   event.multiValueHeaders                 — repeated headers
  //   event.requestContext                    — API Gateway request context
  //
  // Vercel Serverless Functions and Cloudflare Workers both use `req`
  // / `request` receivers that are already covered by the Express-
  // style patterns above (line ~398). This block specifically covers
  // the `event`-shaped API Gateway convention that those don't reach.
  { property: 'body',                            object: 'event', type: 'http_body',   severity: 'high', property_tainted: true, languages: ['javascript', 'typescript'] },
  { property: 'queryStringParameters',           object: 'event', type: 'http_query',  severity: 'high', property_tainted: true, languages: ['javascript', 'typescript'] },
  { property: 'multiValueQueryStringParameters', object: 'event', type: 'http_query',  severity: 'high', property_tainted: true, languages: ['javascript', 'typescript'] },
  { property: 'pathParameters',                  object: 'event', type: 'http_path',   severity: 'high', property_tainted: true, languages: ['javascript', 'typescript'] },
  { property: 'headers',                         object: 'event', type: 'http_header', severity: 'high', property_tainted: true, languages: ['javascript', 'typescript'] },
  { property: 'multiValueHeaders',               object: 'event', type: 'http_header', severity: 'high', property_tainted: true, languages: ['javascript', 'typescript'] },
  { property: 'body',                            object: 'event', type: 'http_body',   severity: 'high', property_tainted: true, languages: ['python'] },
  { property: 'queryStringParameters',           object: 'event', type: 'http_query',  severity: 'high', property_tainted: true, languages: ['python'] },
  { property: 'pathParameters',                  object: 'event', type: 'http_path',   severity: 'high', property_tainted: true, languages: ['python'] },
  { property: 'headers',                         object: 'event', type: 'http_header', severity: 'high', property_tainted: true, languages: ['python'] },

  // --- JWT claims (unverified decode — PyJWT / jose / jsonwebtoken / auth0 java-jwt / golang-jwt) ---
  // A JWT's payload is *always* attacker-authored. Even after verification
  // the *contents* of the claims (username, role, custom fields) are not
  // trusted for downstream flows into SQL, HTML, shell, etc. The `decode`
  // variants here return the parsed claims dictionary/object.
  { method: 'decode', class: 'jwt', type: 'http_header', severity: 'high', return_tainted: true, languages: ['python'] },
  { method: 'get_unverified_claims', class: 'jwt', type: 'http_header', severity: 'high', return_tainted: true, languages: ['python'] },
  { method: 'get_unverified_header', class: 'jwt', type: 'http_header', severity: 'high', return_tainted: true, languages: ['python'] },
  { method: 'decode', class: 'jwt', type: 'http_header', severity: 'high', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'decode', class: 'jsonwebtoken', type: 'http_header', severity: 'high', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'decodeJwt', class: 'jose', type: 'http_header', severity: 'high', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'decodeProtectedHeader', class: 'jose', type: 'http_header', severity: 'high', return_tainted: true, languages: ['javascript', 'typescript'] },
  { method: 'decode', class: 'JWT', type: 'http_header', severity: 'high', return_tainted: true, languages: ['java'] },
  { method: 'ParseUnverified', class: 'jwt', type: 'http_header', severity: 'high', return_tainted: true, languages: ['go'] },
];

// =========================================================================
// cognium-dev #240 ship 1 — extend open_redirect (CWE-601) framework coverage
//
// Extracted from DEFAULT_SINKS to keep the main-array literal within the
// TypeScript union-type inference complexity limit (TS2590). Spread into
// DEFAULT_SINKS below.
//
// Baseline (variant-coverage.md): 11 probes, 1 fires, 10 FN. Existing
// coverage: Java HttpServletResponse.sendRedirect, Node classless
// `redirect`, Go net/http.Redirect, Rust actix Redirect/HttpResponse.
// Adds Python (django/starlette/fastapi), JS/TS (koa/fastify/express
// location + next.js), Java (RedirectView + JAX-RS Response), Go
// (gin/echo/fiber).
// =========================================================================
const OPEN_REDIRECT_FRAMEWORK_SINKS: SinkPattern[] = [
  // --- Python: django / starlette / fastapi -------------------------------
  { method: 'HttpResponseRedirect',          type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['python'] },
  { method: 'HttpResponsePermanentRedirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['python'] },
  { method: 'RedirectResponse',              type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['python'] },

  // --- JS/TS: koa / fastify / express / next.js ---------------------------
  { method: 'redirect', class: 'Context',       type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'redirect', class: 'FastifyReply',  type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Express: res.location(url) sets Location header without redirect status,
  // still an open-redirect vector when combined with a downstream redirect.
  { method: 'location', class: 'Response',      type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Next.js App Router: NextResponse.redirect(url) — static method matched
  // by receiver-class name.
  { method: 'redirect', class: 'NextResponse',  type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // --- Java: Spring MVC RedirectView + JAX-RS Response --------------------
  { method: 'RedirectView',      class: 'RedirectView', type: 'open_redirect', cwe: 'CWE-601', severity: 'high',   arg_positions: [0], languages: ['java'] },
  { method: 'setUrl',            class: 'RedirectView', type: 'open_redirect', cwe: 'CWE-601', severity: 'high',   arg_positions: [0], languages: ['java'] },
  // JAX-RS Response builder — static factory methods that take a target URI.
  { method: 'seeOther',          class: 'Response',     type: 'open_redirect', cwe: 'CWE-601', severity: 'high',   arg_positions: [0], languages: ['java'] },
  { method: 'temporaryRedirect', class: 'Response',     type: 'open_redirect', cwe: 'CWE-601', severity: 'high',   arg_positions: [0], languages: ['java'] },

  // --- Go: gin / echo / fiber ---------------------------------------------
  // gin/echo: c.Redirect(302, url) — status at arg[0], url at arg[1].
  // fiber:   c.Redirect(url)         — url at arg[0].
  // These entries fire once Go local-receiver type resolution lands
  // (see taint-matcher.ts:2137 receiverMightBeClass — currently returns
  // false for `c` against 'Context'/'Ctx'). Until then, the
  // external_taint_escape fallback preserves recall on these call sites.
  // net/http.Redirect (class 'http') is unaffected — declares class 'http'
  // and matches via package receiver.
  { method: 'Redirect', class: 'Context', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [1], languages: ['go'] },
  { method: 'Redirect', class: 'Ctx',     type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['go'] },
];

// =========================================================================
// cognium-dev #240 ship 2 — extend deserialization (CWE-502) framework
// coverage across Python (pickle / marshal / dill / jsonpickle) and Go
// (encoding/gob, gopkg.in/yaml). Java coverage (readObject / XStream /
// ObjectMapper / Yaml SnakeYAML / Kryo / XMLDecoder) is already extensive
// via DEFAULT_SINKS below; JS/TS `node-serialize.unserialize` added here.
//
// Spread into DEFAULT_SINKS below (per the ship-1 pattern).
// =========================================================================
const DESERIALIZATION_FRAMEWORK_SINKS: SinkPattern[] = [
  // --- Python: stdlib + popular third-party --------------------------------
  // pickle: known-dangerous, any unpickle on untrusted bytes is RCE.
  { method: 'loads',  class: 'pickle',    type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'load',   class: 'pickle',    type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  // cPickle alias (Python 2 name, still around in older codebases).
  { method: 'loads',  class: 'cPickle',   type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'load',   class: 'cPickle',   type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  // marshal: stdlib code-object deserializer. Loading a tainted bytestring
  // as a code object followed by `exec` is arbitrary-code execution.
  { method: 'loads',  class: 'marshal',   type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'load',   class: 'marshal',   type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  // dill: pickle superset — same RCE profile.
  { method: 'loads',  class: 'dill',      type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'load',   class: 'dill',      type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  // jsonpickle: JSON wrapper around pickle — trusts `py/object` marker.
  { method: 'decode', class: 'jsonpickle', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },

  // --- Go: encoding/gob + yaml.Unmarshal -----------------------------------
  // gob.NewDecoder(r).Decode(&v): tainted io.Reader → arbitrary Go values.
  { method: 'Decode', class: 'Decoder', type: 'deserialization', cwe: 'CWE-502', severity: 'high',     arg_positions: [0], languages: ['go'] },
  // gopkg.in/yaml.v2 + v3 top-level function; interface{} target is unsafe.
  { method: 'Unmarshal', class: 'yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'high',     arg_positions: [0], languages: ['go'] },

  // --- JS/TS: node-serialize ------------------------------------------------
  // Known-dangerous — accepts embedded IIFE that runs during deserialize.
  { method: 'unserialize', class: 'nodeSerialize', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
];

// =========================================================================
// cognium-dev #240 ship 2 — extend nosql_injection (CWE-943) framework
// coverage. JS/TS MongoDB Collection + Mongoose Model are already covered
// at line 1776+. This ship adds Python (pymongo), Java (Spring Data
// MongoTemplate + native MongoCollection), and Go (mongo-driver Collection).
//
// Spread into DEFAULT_SINKS below.
// =========================================================================
const NOSQL_FRAMEWORK_SINKS: SinkPattern[] = [
  // --- Python: pymongo Collection ------------------------------------------
  // Every filter-taking Collection method; filter arg[0] is the query dict.
  { method: 'find',           class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'find_one',       class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'aggregate',      class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'update_one',     class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['python'] },
  { method: 'update_many',    class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['python'] },
  { method: 'delete_one',     class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'delete_many',    class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'count_documents',class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['python'] },

  // --- Java: Spring Data MongoTemplate + native MongoCollection ------------
  { method: 'find',    class: 'MongoTemplate',    type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'findOne', class: 'MongoTemplate',    type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'findAll', class: 'MongoTemplate',    type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'find',    class: 'MongoCollection',  type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'aggregate', class: 'MongoCollection',type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['java'] },

  // --- Go: go.mongodb.org/mongo-driver Collection --------------------------
  // These fire once Go local-receiver type resolution lands (see
  // taint-matcher.ts + #240 ship 2 Go receiver work). Same gate as the
  // gin/fiber Ctx sinks in ship 1.
  { method: 'Find',       class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [1], languages: ['go'] },
  { method: 'FindOne',    class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [1], languages: ['go'] },
  { method: 'UpdateOne',  class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [1, 2], languages: ['go'] },
  { method: 'UpdateMany', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [1, 2], languages: ['go'] },
  { method: 'DeleteOne',  class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [1], languages: ['go'] },
];

// =========================================================================
// cognium-dev #240 ship 1 — extend trust_boundary (CWE-501) framework coverage
//
// Extracted from DEFAULT_SINKS (see note above). Spread into DEFAULT_SINKS
// below.
//
// Baseline (variant-coverage.md): 16 probes, 0 fires, 16 FN. Existing
// coverage: Java HttpSession / ServletContext / HttpServletRequest
// setAttribute (issue #117), Python session.__setitem__. Adds Django
// cache, JS Storage.setItem, Express res.cookie, Java Cookie /
// SecurityContext / System.setProperty, Go http.SetCookie / gin.SetCookie.
//
// Severity `medium` unless the sink pollutes a process-wide store
// (System.setProperty → high).
// =========================================================================
const TRUST_BOUNDARY_FRAMEWORK_SINKS: SinkPattern[] = [
  // --- Python: Django cache write -----------------------------------------
  { method: 'set',      class: 'cache', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1], languages: ['python'] },
  { method: 'set_many', class: 'cache', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0], languages: ['python'] },

  // --- JS/TS: client-side Storage + Express cookie ------------------------
  // localStorage / sessionStorage — browser Storage.setItem(key, value).
  { method: 'setItem', class: 'Storage',  type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1], languages: ['javascript', 'typescript'] },
  // Express: res.cookie(name, value, opts) — cookie-jar write.
  { method: 'cookie',  class: 'Response', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1], languages: ['javascript', 'typescript'] },

  // --- Java: Cookie / SecurityContext / System.setProperty ----------------
  // `new Cookie(name, value)` — constructor with tainted value crosses the
  // client-server trust boundary via Set-Cookie.
  { method: 'Cookie',            class: 'Cookie',          type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1], languages: ['java'] },
  { method: 'setValue',          class: 'Cookie',          type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0], languages: ['java'] },
  // Spring Security: SecurityContext.setAuthentication(userSuppliedAuth) —
  // installs an untrusted principal into the request-scoped security
  // context; downstream authz decisions become attacker-controlled.
  { method: 'setAuthentication', class: 'SecurityContext', type: 'trust_boundary', cwe: 'CWE-501', severity: 'high',   arg_positions: [0], languages: ['java'] },
  // JVM-wide System property write with tainted value pollutes process
  // state observable to every thread.
  { method: 'setProperty',       class: 'System',          type: 'trust_boundary', cwe: 'CWE-501', severity: 'high',   arg_positions: [1], languages: ['java'] },

  // --- Go: http.SetCookie / gin.SetCookie ---------------------------------
  // Package-level `http.SetCookie(w, &http.Cookie{Value: tainted})` — sink
  // on arg[1] (the *Cookie) catches struct-literal composite tainting.
  { method: 'SetCookie', class: 'http',    type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1], languages: ['go'] },
  // gin: c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly).
  { method: 'SetCookie', class: 'Context', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1], languages: ['go'] },
];

export const DEFAULT_SINKS: SinkPattern[] = [
  // SQL Injection (CWE-89)
  { method: 'executeQuery', class: 'Statement', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'execute', class: 'Statement', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'executeUpdate', class: 'Statement', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'executeBatch', class: 'Statement', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'addBatch', class: 'Statement', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  // PreparedStatement/CallableStatement creation - SQL can be injected here
  { method: 'prepareStatement', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'prepareCall', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'createNativeQuery', class: 'EntityManager', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'createQuery', class: 'EntityManager', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  // Spring JdbcTemplate
  { method: 'query', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'queryForObject', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'queryForList', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'queryForMap', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'queryForRowSet', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'queryForLong', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'queryForInt', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'update', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'batchUpdate', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'execute', class: 'JdbcTemplate', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  // Without class (catch-all for method names)
  { method: 'queryForObject', type: 'sql_injection', cwe: 'CWE-89', severity: 'high', arg_positions: [0] },
  { method: 'queryForList', type: 'sql_injection', cwe: 'CWE-89', severity: 'high', arg_positions: [0] },
  { method: 'queryForLong', type: 'sql_injection', cwe: 'CWE-89', severity: 'high', arg_positions: [0] },

  // MyBatis mapper-interface methods (CWE-89, classified as mybatis_mapper_call)
  // The actual SQL lives in the mapper's XML or @Select/@Update annotation —
  // exploitability depends on whether the binding uses ${...} interpolation
  // vs #{...} parameter binding. Surface as a distinct sink type so consumers
  // can resolve the binding before reporting. See cognium-dev#24.
  // The `class: '*Mapper'` suffix wildcard matches userMapper, OrderMapper, …
  { method: 'insert', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'insertSelective', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'update', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'updateByPrimaryKey', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'updateByPrimaryKeySelective', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'delete', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'deleteByPrimaryKey', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'selectOne', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'selectList', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'selectByPrimaryKey', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },
  { method: 'selectByExample', class: '*Mapper', type: 'mybatis_mapper_call', cwe: 'CWE-89', severity: 'medium', arg_positions: [0], languages: ['java'] },

  // Command Injection (CWE-78)
  { method: 'exec', class: 'Runtime', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0, 1] },
  { method: 'start', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [] },
  // ProcessBuilder constructor
  { method: 'ProcessBuilder', class: 'constructor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'command', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Commons Exec
  // Note: bare class 'Executor' removed — it collided with java.util.concurrent.Executor
  // (Executor.execute(Runnable) is not command injection). Apache Commons Exec users
  // typically declare DefaultExecutor explicitly, so we match that instead. See issue #14.
  { method: 'execute', class: 'DefaultExecutor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'CommandLine', class: 'constructor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'parse', class: 'CommandLine', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // SSH/Shell execution
  { method: 'execCommand', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'runCommand', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'executeCommand', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Shell provider execution (NiFi, etc.)
  { method: 'execute', class: 'ShellRunner', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'run', class: 'ShellRunner', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'getGroupMembers', class: 'ShellCommands', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'onConfigured', class: 'ShellUserGroupProvider', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Jenkins pipeline execution
  { method: 'create', class: 'CpsScmFlowDefinition', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'checkout', class: 'SCM', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'retrieve', class: 'LibraryAdder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'add', class: 'LibraryAdder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Jenkins CPS Flow Execution (constructor)
  { method: 'CpsFlowExecution', class: 'constructor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'CpsFlowDefinition', class: 'constructor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'FlowExecution', class: 'constructor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // ActiveMQ control commands
  { method: 'processControlCommand', class: 'TransportConnection', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // XStream deserialization — classified as CWE-502 (deserialization), not CWE-78 (command injection).
  // The deserialization sink entries at lines ~1059 handle this correctly.
  { method: 'fromString', class: 'FileConverter', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Plexus command line
  { method: 'getPosition', class: 'Commandline', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'addArguments', class: 'Commandline', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Docker
  { method: 'imageName', class: 'DockerRegistryEndpoint', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'exec', class: 'DockerClient', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'createContainer', class: 'DockerClient', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'pull', class: 'DockerClient', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // SSH Command Execution
  { method: 'exec', class: 'Session', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'execCommand', class: 'Session', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'executeCommand', class: 'SSHClient', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'exec', class: 'ChannelExec', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'setCommand', class: 'ChannelExec', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'executeRemoteCommand', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Git Command Execution
  { method: 'clone', class: 'Git', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'fetch', class: 'Git', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'pull', class: 'Git', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'push', class: 'Git', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'setRemote', class: 'Git', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'cloneRepository', class: 'Git', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'setURI', class: 'CloneCommand', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Kubernetes/kubectl
  { method: 'exec', class: 'KubernetesClient', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'execInPod', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'command', class: 'ContainerExecDecorator', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Ant/Maven Build Execution
  { method: 'execute', class: 'ExecTask', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'setExecutable', class: 'ExecTask', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'setCommand', class: 'ExecTask', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'execute', class: 'Java', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Shell/Bash utilities — these are method-call sinks in host languages
  // (Java Runtime/ProcessBuilder, JS child_process spawn/exec, Python subprocess, etc.).
  // When the analyzed file IS a bash/shell script, the bash plugin's per-flag entries
  // (argPositions: [1] for `bash -c <cmd>`) MUST win. Restrict these generic entries
  // to non-shell languages so they don't collide on the dedup key
  // `${location}:${call.location.line}:${pattern.cwe}`.
  { method: 'bash', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'shell', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'sh', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // cognium-dev #187 Sprint 54: arg_positions [0, 1] so the JS shell-mode shape
  // `spawn('sh', ['-c', tainted])` / `execFile('/bin/sh', ['-c', tainted])`
  // surfaces taint at the argv-array position (arg[1]).
  { method: 'spawn', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0, 1] },
  { method: 'spawnSync', languages: ['javascript', 'typescript'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0, 1] },
  { method: 'execFile', languages: ['javascript', 'typescript'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0, 1] },
  { method: 'execFileSync', languages: ['javascript', 'typescript'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0, 1] },
  { method: 'fork', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'popen', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'system', languages: ['java', 'javascript', 'typescript', 'python', 'go', 'rust'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // execa (npm) — parses tainted shell-style strings into program+argv;
  // arg[0] is shell-injectable. cognium-dev #187 Sprint 54.
  { method: 'command', class: 'execa', languages: ['javascript', 'typescript'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'commandSync', class: 'execa', languages: ['javascript', 'typescript'], type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Apache Commons Exec
  // Note: bare class 'Executor' removed (see comment above) — DefaultExecutor matched explicitly.
  { method: 'setCommandline', class: 'DefaultExecutor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'parse', class: 'CommandLine', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'addArgument', class: 'CommandLine', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Process-related utilities — removed in 3.83.0 (#124):
  // - Process.waitFor() blocks on an already-spawned process; has no args,
  //   no command string flows into it.
  // - ProcessBuilder.inheritIO() takes no args.
  // - ProcessBuilder.redirectOutput/redirectInput take a File destination/source,
  //   not a command. If treated as sinks they would be path_traversal, not
  //   command_injection — and even then the threat model is marginal.
  // The actual command-execution sinks (Runtime.exec, ProcessBuilder.start,
  // ProcessBuilder.command, ProcessBuilder(constructor)) remain configured
  // elsewhere in this file / in configs/sinks/command.yaml.

  // Path Traversal (CWE-22)
  // File: covers both File(String pathname) and File(parent, child). The 2-arg
  // overload's child argument carries CVE-2018-8041 (Camel mail Content-Disposition
  // filename written to disk).
  { method: 'File', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1] },
  { method: 'FileInputStream', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileOutputStream', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileReader', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileWriter', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // NOTE: ClassLoader.getResource / Class.getResource were removed in
  // 3.153.0 (#233). Classpath resource resolution cannot escape the
  // classpath root via `../` (JAR entries are opaque). If reintroduced,
  // the correct CWE is CWE-829 (untrusted-classpath-resource), not
  // CWE-22 path traversal.
  // Paths.get can be used for path traversal
  { method: 'get', class: 'Paths', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'of', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'readAllBytes', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'readAllLines', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'write', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'delete', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'newInputStream', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'newOutputStream', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'newBufferedReader', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'newBufferedWriter', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'copy', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1] },
  { method: 'move', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1] },
  // NOTE: `Files.exists`, `Files.isDirectory`, `Files.isRegularFile`
  // were removed in 3.154.0 (#245 RC2). These NIO methods are pure
  // boolean queries — they read a filesystem attribute and cannot
  // cause traversal escape. A CWE-22 sink must consume the path to
  // open, read, write, delete, list, or link a filesystem entry;
  // check-only receivers reveal at most a boolean. Empirically
  // ~12 H+C FPs across the 10-repo Tier 2 cohort
  // (cognium-ai#189 §4). `java.io.File` instance methods
  // (`file.isDirectory()`, `file.exists()`, `file.canRead()`, …)
  // are already not registered as CWE-22 sinks.
  // RandomAccessFile
  { method: 'RandomAccessFile', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Framework-specific resource loading (Cocoon, Spring, etc.)
  { method: 'resolveURI', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'resolve', class: 'SourceResolver', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getSource', class: 'SourceResolver', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // NOTE: new URL(userInput) is SSRF (CWE-918), not path traversal — see ssrf section below
  // Servlet context resource loading
  { method: 'getResource', class: 'ServletContext', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getResourceAsStream', class: 'ServletContext', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getRealPath', class: 'ServletContext', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Jenkins SCM file system (CVE-2022-25175 — workflow-multibranch-plugin)
  { method: 'child', class: 'SCMFileSystem', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Static file handlers
  { method: 'externalStaticFileLocation', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'staticFileLocation', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Zip/archive handling
  { method: 'getEntry', class: 'ZipFile', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // ZipEntry.getName moved to file_sources.yaml as a taint SOURCE (type=archive_entry, issue #52)
  // Resource loading classes (various frameworks)
  { method: 'ClassPathResource', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileSystemResource', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'UrlResource', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'PathResource', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Additional resource/file patterns
  { method: 'forFile', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Java NIO `Path.resolve(other)` — joining with an untrusted `other` can
  // escape the parent directory. Language-scoped to Java because the simple
  // name `resolve` collides with Python `pathlib.Path.resolve()`
  // (a canonicalization SANITIZER, no argument), JS `Promise.resolve(...)`,
  // and Rust `Path::canonicalize` variants. Sprint 9 #48.2.
  { method: 'resolve', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'resolve', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'resolveSibling', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'relativize', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0], languages: ['java'] },
  // Static file configuration
  { method: 'staticFiles', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'setRoot', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'setWebRoot', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // File operations
  { method: 'createFile', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'createDirectory', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'createDirectories', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'list', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  { method: 'walk', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  // Unzip/archive extraction (Zip Slip)
  { method: 'unzip', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0, 1] },
  { method: 'extract', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0, 1] },
  { method: 'extractAll', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0, 1] },
  // Python zipfile/tarfile use lowercase extractall (PEP 8 naming)
  { method: 'extractall', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0], languages: ['python'] },
  // Python zipfile.ZipFile(path) — tainted archive path enables Zip-Slip via malicious archive
  { method: 'ZipFile', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['python'] },
  // Flask send_from_directory: untrusted filename can escape directory via ../
  { method: 'send_from_directory', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [1], languages: ['python'] },
  { method: 'unjar', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0, 1] },
  // Additional file constructors — BufferedReader(Reader) is NOT a path traversal sink; it wraps a Reader, not a file path
  { method: 'PrintWriter', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'Scanner', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Topic/queue names (for message queue systems - can be exploited for path traversal)
  { method: 'createTopic', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  // Apache SSHD SFTP operations
  { method: 'doStat', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doLStat', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doFStat', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doSetStat', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doRemove', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doRemoveFile', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doRemoveDirectory', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doMakeDirectory', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'doRealPath', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'validateRealPath', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'writeDirEntry', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getAttributes', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'setFileAttributes', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getLongName', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'resolveReportedFileAttributes', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'handleUnknownStatusFileAttributes', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'signalRemovalPreConditionFailure', class: 'AbstractSftpSubsystemHelper', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Apache SSHD FileSystem operations
  { method: 'getPath', class: 'BaseFileSystem', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getPathMatcher', class: 'BaseFileSystem', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getFileStores', class: 'RootedFileSystem', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // SftpFileSystemProvider
  { method: 'move', class: 'SftpFileSystemProvider', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1] },
  { method: 'copy', class: 'SftpFileSystemProvider', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1] },
  // Apache Camel mail attachments
  { method: 'extractAttachmentsFromMultipart', class: 'MailBinding', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'configureMessage', class: 'GenericFileEndpoint', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Apache Shiro path validation
  { method: 'isValid', class: 'InvalidRequestFilter', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'containsSemicolon', class: 'InvalidRequestFilter', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'isNormalized', class: 'InvalidRequestFilter', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'isAccessAllowed', class: 'InvalidRequestFilter', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'onAccessDenied', class: 'InvalidRequestFilter', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'setBlockSemicolon', class: 'InvalidRequestFilter', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Spring Cloud Config
  { method: 'getProfiles', class: 'Environment', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'isInvalidEncodedPath', class: 'GenericResourceRepository', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getProfilePaths', class: 'GenericResourceRepository', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'binary', class: 'ResourceController', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'resolveName', class: 'ResourceController', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'retrieve', class: 'ResourceController', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'checkNotModified', class: 'ResourceController', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Apache MyFaces resource handling
  { method: 'createResource', class: 'ResourceHandlerImpl', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'handleResourceRequest', class: 'ResourceHandlerImpl', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'libraryExists', class: 'ResourceHandlerImpl', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'validate', class: 'ResourceValidationUtils', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'isValidLibraryName', class: 'ResourceValidationUtils', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Spark framework resource handling
  { method: 'ClassPathResource', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getPath', class: 'ClassPathResource', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'equals', class: 'ClassPathResource', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  { method: 'getResource', class: 'ExternalResourceHandler', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'consumeWithFileResourceHandlers', class: 'StaticFilesConfiguration', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'setExpireTimeSeconds', class: 'StaticFilesConfiguration', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  { method: 'configureJarCase', class: 'StaticFilesConfiguration', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'toString', class: 'StringUtils', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  // Wildfly/Undertow servlet resource manager
  { method: 'getResource', class: 'ServletResourceManager', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Yamcs file system bucket
  { method: 'deleteObject', class: 'FileSystemBucket', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // RocketMQ validators
  { method: 'regularExpressionMatcher', class: 'Validators', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'checkMessage', class: 'Validators', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'checkTopic', class: 'Validators', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getSystemTopic', class: 'TopicConfigManager', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'msgCheck', class: 'AbstractSendMessageProcessor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'createPlainAccessConfig', class: 'MQClientAPIImpl', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // XWiki velocity introspector
  { method: 'SecureIntrospector', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },

  // XSS (CWE-79)
  { method: 'write', class: 'PrintWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'println', class: 'PrintWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'print', class: 'PrintWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'format', class: 'PrintWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'printf', class: 'PrintWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  // ServletOutputStream
  { method: 'write', class: 'ServletOutputStream', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'print', class: 'ServletOutputStream', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'println', class: 'ServletOutputStream', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // XSS in error messages (CWE-81)
  { method: 'sendError', class: 'HttpServletResponse', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  // Response header injection — re-categorised from `xss` to `crlf`
  // (CWE-113) in Sprint 6 of #86. Header injection is HTTP response
  // splitting / cache-poisoning / cookie forging; reflected XSS via header
  // reflection remains a downstream concern of body-writing sinks.
  { method: 'setHeader', class: 'HttpServletResponse', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1] },
  { method: 'addHeader', class: 'HttpServletResponse', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1] },
  // Cookie constructor + addCookie — HTTP response splitting via cookie
  // name/value (CWE-113). Reflects the #189 Sprint 92 V02SetCookie fixture
  // where `res.addCookie(new Cookie(name, req.getParameter("v")))` allows
  // CRLF injection into the Set-Cookie header. Both the ctor arg[1] (value)
  // and the addCookie arg[0] (Cookie handle) are flagged so intermediate-var
  // and inline-ctor shapes both surface.
  { method: 'Cookie', class: 'constructor', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [0, 1] },
  { method: 'addCookie', class: 'HttpServletResponse', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [0] },
  // Note: `sendRedirect` is primarily classified as `ssrf` / open-redirect
  // (CWE-601) further down — see entry near line 1195. CRLF via Location
  // header is a secondary concern; keeping the canonical SSRF entry avoids
  // double-emission that would mask the open-redirect chain.
  { method: 'setContentType', class: 'HttpServletResponse', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  // JSP output
  { method: 'setAttribute', class: 'PageContext', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  // Model attributes (Spring MVC)
  { method: 'addAttribute', class: 'Model', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  { method: 'addAttribute', class: 'ModelMap', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  { method: 'addObject', class: 'ModelAndView', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  // Class-less XSS patterns for cases where receiver type is inferred
  { method: 'println', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'print', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  // NOTE: the unscoped { method: 'write', type: 'xss' } entry was removed in
  // Sprint 28 (#110). It mistyped every non-XSS .write() across all languages
  // (fs.writeFile, open().write, bcrypt callbacks, credential file writes,
  // node ClientRequest.write, etc.) as xss. Real HTML writers are covered
  // by class-scoped entries: PrintWriter.write (line 843), ServletOutputStream.write
  // (line 849), JspWriter.write (xss.yaml), Response.write (nodejs.json).
  { method: 'append', class: 'StringBuilder', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'append', class: 'StringBuffer', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  // Wiki/CMS XSS sinks (JSPWiki, Confluence, etc.)
  { method: 'handleHyperlinks', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'handleDiv', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'handleImage', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'handleLink', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'render', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'renderHTML', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'parseHTML', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // HTML sanitizer/validator sinks (AntiSamy, OWASP HTML Sanitizer, etc.)
  { method: 'scan', class: 'AntiSamy', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isValid', class: 'SafeHtmlValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'sanitize', class: 'PolicyFactory', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'validate', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  // SAX handler sinks (can lead to XSS in parsed content)
  { method: 'startElement', class: 'ContentHandler', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2] },
  { method: 'characters', class: 'ContentHandler', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Template output sinks
  { method: 'output', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setOutput', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writeAttribute', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  // AntiSamy specific (SAX filters)
  { method: 'startElement', class: 'MagicSAXFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2] },
  { method: 'scan', class: 'AntiSamyDOMScanner', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'scan', class: 'AntiSamySAXScanner', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Hibernate Validator
  { method: 'getFragmentAsDocument', class: 'SafeHtmlValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // JSPWiki specific
  { method: 'handleLinks', class: 'ReferredPagesPlugin', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'execute', class: 'ReferredPagesPlugin', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getString', class: 'WysiwygEditingRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // CXF service list
  { method: 'writeRESTfulEndpoint', class: 'FormattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writeApiSpec', class: 'FormattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // JSON sanitizer
  { method: 'sanitize', class: 'JsonSanitizer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Keycloak/OIDC
  { method: 'doBrowserLogout', class: 'LogoutEndpoint', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // xxl-job
  { method: 'save', class: 'JobGroupController', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // XWiki
  { method: 'escape', class: 'XWiki', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // ESAPI DefaultValidator (validation library that processes user input)
  { method: 'isValidInput', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2] },
  { method: 'isValidSafeHTML', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'getValidInput', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2] },
  { method: 'getValidSafeHTML', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'isValidHTTPRequestParameterSet', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'assertValidHTTPRequestParameterSet', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'isValidFileName', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'getValidFileName', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'isValidFileContent', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getValidFileContent', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isValidFileUpload', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2] },
  { method: 'assertValidFileUpload', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2] },
  { method: 'isValidDirectoryPath', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'getValidDirectoryPath', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'isValidPrintable', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getValidPrintable', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'safeReadLine', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isValidInteger', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'getValidInteger', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'isValidDouble', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'getValidDouble', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'isValidNumber', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'getValidNumber', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'isValidDate', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'getValidDate', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'isValidCreditCard', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'getValidCreditCard', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'isValidListItem', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'getValidListItem', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0, 1] },
  { method: 'isValidURI', class: 'DefaultValidator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  // AntiSamy test/processing methods
  { method: 'scriptAttacks', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'imgAttacks', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'hrefAttacks', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'cssAttacks', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'IllegalXML', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'testIssue2', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'issue41', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'testGithubIssue151', class: 'AntiSamyTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'processStyleTag', class: 'AntiSamyDOMScanner', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // JSON Sanitizer
  { method: 'sanitizeString', class: 'JsonSanitizer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'testIssue13', class: 'JsonSanitizerTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'testSanitize', class: 'JsonSanitizerTest', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },

  // Thymeleaf Template Engine (XSS sinks)
  { method: 'process', class: 'TemplateEngine', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'process', class: 'SpringTemplateEngine', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'setVariable', class: 'Context', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  { method: 'setVariable', class: 'WebContext', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },

  // FreeMarker Template Engine (XSS sinks)
  { method: 'process', class: 'Template', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getTemplate', class: 'Configuration', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'put', class: 'SimpleHash', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },

  // Velocity Template Engine (XSS sinks)
  { method: 'merge', class: 'Template', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'put', class: 'VelocityContext', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },

  // JSP/JSTL (XSS sinks)
  { method: 'setAttribute', class: 'JspContext', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  { method: 'setAttribute', class: 'ServletContext', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  { method: 'setAttribute', class: 'HttpSession', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },
  { method: 'getWriter', class: 'JspWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [] },
  { method: 'include', class: 'RequestDispatcher', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'forward', class: 'RequestDispatcher', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },

  // Pebble Template Engine (XSS sinks)
  { method: 'evaluate', class: 'PebbleTemplate', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'getTemplate', class: 'PebbleEngine', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // Mustache/Handlebars (XSS sinks)
  { method: 'execute', class: 'Mustache', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'compile', class: 'Handlebars', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'apply', class: 'Template', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // JSON Response (XSS via JSON injection)
  { method: 'writeValueAsString', class: 'ObjectMapper', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'toJson', class: 'Gson', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'write', class: 'JsonGenerator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writeString', class: 'JsonGenerator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writeRaw', class: 'JsonGenerator', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // Additional Response Writers
  { method: 'setEntity', class: 'HttpResponse', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setBody', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'body', class: 'ResponseBuilder', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'entity', class: 'ResponseBuilder', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'ok', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // Code Injection (CWE-94)
  { method: 'eval', class: 'ScriptEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Pattern.compile removed in 3.83.0 (#124): regex compilation does not execute
  // code. The real risk from a tainted regex is ReDoS, covered by the
  // `Pattern.compile` -> `redos` rule below (line ~1945).
  // Expression Language injection (SpEL, OGNL, MVEL, EL)
  { method: 'parseExpression', class: 'ExpressionParser', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'parseExpression', class: 'SpelExpressionParser', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'getValue', class: 'Expression', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'setValue', class: 'Expression', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'getValue', class: 'Ognl', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'parseExpression', class: 'Ognl', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'compileExpression', class: 'MVEL', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'eval', class: 'MVEL', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'createValueExpression', class: 'ExpressionFactory', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [1] },
  { method: 'createMethodExpression', class: 'ExpressionFactory', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [1] },
  // Apache NiFi Expression Language (CVE-2023-36542, issue #11).
  // PropertyValue.evaluateAttributeExpressions(...) runs NiFi EL against
  // user-controlled property values — if the property is attacker-influenced
  // the EL evaluation is a code-injection sink.
  { method: 'evaluateAttributeExpressions', class: 'PropertyValue', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'evaluateAttributeExpressions', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // Groovy script execution
  { method: 'evaluate', class: 'GroovyShell', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'parse', class: 'GroovyShell', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'parseClass', class: 'GroovyClassLoader', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'run', class: 'GroovyScriptEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Jenkins script-security plugin — Groovy sandbox attack surface (issue #17, CVE-2023-24422).
  // The sandbox is a documented-bypassable security control; the dispatch points that
  // route tainted Groovy through the sandbox runtime are code-injection sinks, not
  // sanitizers. SandboxInterceptor.onNewInstance already lives in command_injection above;
  // these add the missing dispatch surface plus the parent GroovyInterceptor class and
  // the AST transformer / outer GroovySandbox wrapper.
  { method: 'onMethodCall', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onStaticCall', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onGetProperty', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onSetProperty', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onGetAttribute', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onSetAttribute', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onMethodPointer', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onSuperCall', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onSuperConstructor', class: 'SandboxInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // Parent class — some plugins extend GroovyInterceptor directly.
  { method: 'onMethodCall', class: 'GroovyInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onNewInstance', class: 'GroovyInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onStaticCall', class: 'GroovyInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onGetProperty', class: 'GroovyInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'onSetProperty', class: 'GroovyInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // AST transformer — converts unsafe Groovy AST into interceptor callbacks; bypasses target this.
  { method: 'call', class: 'SandboxTransformer', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // GroovySandbox.runInSandbox — Jenkins script-security outer wrapper (real API; the
  // "sandbox" entry in command.yaml is fictional).
  { method: 'runInSandbox', class: 'GroovySandbox', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // JavaScript engine (Nashorn/Rhino)
  { method: 'eval', class: 'Bindings', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'eval', class: 'ScriptContext', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Dynamic class loading (can lead to RCE)
  { method: 'forName', class: 'Class', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'loadClass', class: 'ClassLoader', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'defineClass', class: 'ClassLoader', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0, 1] },
  { method: 'newInstance', class: 'Class', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [] },
  // JNDI injection (leads to RCE via deserialization gadgets)
  { method: 'lookup', class: 'Context', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'lookup', class: 'InitialContext', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'lookup', class: 'NamingManager', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // BeanUtils/PropertyUtils (can trigger arbitrary method calls)
  { method: 'setProperty', class: 'BeanUtils', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [1, 2] },
  { method: 'populate', class: 'BeanUtils', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [1] },
  { method: 'setProperty', class: 'PropertyUtils', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [1, 2] },
  // Reflection-based invocation
  { method: 'invoke', class: 'Method', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0, 1] },
  { method: 'newInstance', class: 'Constructor', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Template engines
  { method: 'merge', class: 'VelocityEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0, 1] },
  { method: 'evaluate', class: 'Velocity', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [1] },
  { method: 'process', class: 'Template', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Configuration update (common RCE vector)
  { method: 'update', class: 'Configuration', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Jenkins/CI Pipeline execution
  { method: 'executeScript', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'runScript', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'evaluate', class: 'ScriptEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'execute', class: 'Script', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'run', class: 'Script', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'checkout', class: 'SCM', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // BeanShell/JShell
  { method: 'eval', class: 'Interpreter', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'source', class: 'Interpreter', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'eval', class: 'JShell', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // JavaScript engines
  { method: 'eval', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'invokeFunction', class: 'Invocable', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'invokeMethod', class: 'Invocable', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0, 1] },
  // Spring Expression Language
  { method: 'parseRaw', class: 'SpelExpressionParser', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'setVariable', class: 'EvaluationContext', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [1] },
  // Struts OGNL
  { method: 'setValue', class: 'OgnlValueStack', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'findValue', class: 'OgnlValueStack', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Additional template engines
  { method: 'render', class: 'Template', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'render', class: 'Pebble', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'render', class: 'Freemarker', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'compile', class: 'Handlebars', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'process', class: 'TemplateEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Nashorn/GraalJS
  { method: 'getEngineByName', class: 'ScriptEngineManager', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Spring Security OAuth expression
  { method: 'authenticate', class: 'DefaultOAuth2RequestAuthenticator', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Struts static parameters
  { method: 'addParametersToContext', class: 'StaticParametersInterceptor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'build', class: 'HttpParameters', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Cron expression parsing (DoS/ReDoS)
  { method: 'parse', class: 'CronParser', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'isValid', class: 'CronValidator', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // ff4j feature flags
  { method: 'check', class: 'FF4j', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Spring Cloud Gateway SpEL
  { method: 'getValue', class: 'StandardEvaluationContext', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Commons Text string substitution
  { method: 'replace', class: 'StringSubstitutor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'replaceIn', class: 'StringSubstitutor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // SQLite JDBC (native library loading)
  { method: 'extract', class: 'NativeLibraryLoader', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Apache Dubbo
  { method: 'doRefer', class: 'DubboProtocol', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // RocketMQ broker
  { method: 'processRequest', class: 'Broker', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // DolphinScheduler
  { method: 'execute', class: 'TaskExecuteThread', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Apache Commons JEXL (JEXL expression injection)
  { method: 'createExpression', class: 'JexlEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'createScript', class: 'JexlEngine', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'evaluate', class: 'JexlExpression', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  { method: 'execute', class: 'JexlScript', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // Janino expression evaluator (Calcite/Flink/Drill)
  { method: 'createFastEvaluator', class: 'ExpressionEvaluator', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'cook', class: 'ExpressionEvaluator', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'cook', class: 'ScriptEvaluator', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'cook', class: 'ClassBodyEvaluator', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'cook', class: 'SimpleCompiler', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Apache Camel Simple language (CVE-2018-8041 and similar)
  { method: 'createExpression', class: 'SimpleLanguage', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'createPredicate', class: 'SimpleLanguage', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // Thymeleaf StandardExpression (CVE-2023-38286 and similar)
  { method: 'parseExpression', class: 'StandardExpressionParser', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [1] },
  { method: 'getValue', class: 'StandardExpression', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // FreeMarker direct template construction (CVE-2022-26336 and similar)
  { method: 'Template', class: 'Template', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [1] },  // new Template(name, tainted)
  { method: 'getTemplate', class: 'Configuration', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Jinjava (Java Jinja template engine)
  { method: 'render', class: 'Jinjava', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  { method: 'renderForResult', class: 'Jinjava', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Spring Cloud Function RoutingFunction (CVE-2022-22963)
  { method: 'getRequestedBeanName', class: 'RoutingFunction', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [] },
  // Kotlin reflection (RCE via reflective construction)
  { method: 'createInstance', class: 'KClass', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [] },
  { method: 'callBy', class: 'KFunction', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
  // Struts 2 deep injection (CVE-2017-5638 and descendants)
  { method: 'translateVariables', class: 'TextParseUtil', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'evaluate', class: 'StrutsResultSupport', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },

  // Deserialization (CWE-502)
  { method: 'readObject', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [] },
  { method: 'readUnshared', class: 'ObjectInputStream', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [] },
  { method: 'fromXML', class: 'XStream', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0] },
  // Jackson ObjectMapper — the 1-arg `readValue(json)` form is polymorphic and
  // can deserialize attacker-controlled types (default-typing gadget chains).
  // The 2-arg typed form `readValue(json, User.class)` is safe because the
  // deserialized type is fixed at compile time; suppressed via
  // safe_if_class_literal_at. The `readValue(json, Class.forName(x))` shape
  // is NOT a class literal and remains a sink.
  { method: 'readValue', class: 'ObjectMapper', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0], safe_if_class_literal_at: 1 },
  // YAML deserialization — `Yaml.load(InputStream, Class<T>)` typed overload
  // is safe; `Yaml.load(InputStream)` and dynamic-class forms are not.
  { method: 'load', class: 'Yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], safe_if_class_literal_at: 1 },
  { method: 'loadAll', class: 'Yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0] },
  { method: 'loadAs', class: 'Yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], safe_if_class_literal_at: 1 },
  // JSON deserialization (Java FastJSON / Jackson — NOT JavaScript's safe JSON.parse)
  { method: 'parseObject', class: 'JSON', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0], safe_if_class_literal_at: 1 },
  { method: 'parseObject', class: 'JSONObject', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0], safe_if_class_literal_at: 1 },
  { method: 'fromJson', class: 'Gson', type: 'deserialization', cwe: 'CWE-502', severity: 'medium', arg_positions: [0], safe_if_class_literal_at: 1 },
  // Jackson ObjectReader — pre-configured reader; typed 2-arg overload is safe
  // when arg[1] is a class literal or TypeReference<>()/TypeToken<>() (handled
  // by argIsClassLiteral extension). Added 3.153.0 (cognium-dev #233).
  { method: 'readValue', class: 'ObjectReader', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0], safe_if_class_literal_at: 1 },
  // Jackson ObjectMapper.convertValue — same class-literal shape as readValue.
  { method: 'convertValue', class: 'ObjectMapper', type: 'deserialization', cwe: 'CWE-502', severity: 'medium', arg_positions: [0], safe_if_class_literal_at: 1 },
  // Kryo.readObject(input, User.class) — typed form is safe; polymorphic form
  // (Kryo.readClassAndObject or non-literal type) remains a sink.
  { method: 'readObject', class: 'Kryo', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0], safe_if_class_literal_at: 1 },
  // XMLDecoder
  { method: 'readObject', class: 'XMLDecoder', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [] },
  // Java serialization constructors
  { method: 'ObjectInputStream', class: 'constructor', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0] },

  // LDAP Injection (CWE-90)
  { method: 'search', class: 'DirContext', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 1] },
  { method: 'search', class: 'InitialDirContext', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 1] },
  { method: 'search', class: 'LdapContext', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 1] },
  { method: 'lookup', class: 'Context', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },
  { method: 'lookup', class: 'InitialContext', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },
  { method: 'list', class: 'DirContext', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },

  // XPath Injection (CWE-643)
  { method: 'evaluate', class: 'XPath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'compile', class: 'XPath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'selectNodes', class: 'Document', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'selectSingleNode', class: 'Document', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'selectNodes', class: 'Node', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'selectSingleNode', class: 'Node', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },

  // XXE - XML External Entity (CWE-611)
  { method: 'parse', class: 'DocumentBuilder', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'parse', class: 'SAXParser', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'parse', class: 'XMLReader', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'unmarshal', class: 'Unmarshaller', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'newTransformer', class: 'TransformerFactory', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'transform', class: 'Transformer', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },

  // SSRF - Server-Side Request Forgery (CWE-918) and Open Redirect (CWE-601)
  // Sprint 82 (#189): HttpServletResponse.sendRedirect is CWE-601 / open_redirect,
  // not ssrf. Re-typing so manifest sink_type='open_redirect' matches.
  { method: 'sendRedirect', class: 'HttpServletResponse', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'sendRedirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'openConnection', class: 'URL', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [] },
  { method: 'openStream', class: 'URL', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [] },
  // NOTE: URL/URI constructors removed — constructing a URL object doesn't make a network
  // request in any language. The real SSRF sinks are openConnection/openStream/execute/etc.
  { method: 'execute', class: 'HttpClient', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'send', class: 'HttpClient', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'getForObject', class: 'RestTemplate', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'getForEntity', class: 'RestTemplate', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'postForObject', class: 'RestTemplate', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'postForEntity', class: 'RestTemplate', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'exchange', class: 'RestTemplate', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'get', class: 'WebClient', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [] },
  { method: 'post', class: 'WebClient', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [] },

  // =============================================================================
  // Config / Absence Vulnerabilities (handled by dedicated pattern passes)
  // =============================================================================
  // weak_random  → WeakRandomPass        (src/analysis/passes/weak-random-pass.ts)
  // weak_hash    → WeakHashPass          (src/analysis/passes/weak-hash-pass.ts)
  // weak_crypto  → WeakCryptoPass        (src/analysis/passes/weak-crypto-pass.ts)
  // insecure_cookie → InsecureCookiePass (src/analysis/passes/insecure-cookie-pass.ts)
  // tls_verify_disabled → TlsVerifyDisabledPass
  // These patterns are detected by call-site literal inspection, not taint flow,
  // so they are NOT registered here as sinks (they could never match a "tainted
  // value flowing into a sink" because the bad value is a hard-coded constant).

  // Trust Boundary (CWE-501) — tainted VALUE crossing into shared session
  // state. OWASP/CWE-501 treats `session.setAttribute("k", taintedValue)` as
  // the violation: untrusted data enters server-side state where downstream
  // code reads it as if trusted. Both arg positions are flagged so either a
  // tainted key (rare) or tainted value (the OWASP shape, 83 cases) trips
  // the sink. (cognium-dev #117)
  { method: 'setAttribute', class: 'HttpSession', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0, 1] },
  { method: 'putValue', class: 'HttpSession', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0, 1] },
  // ServletContext + request scopes — same trust-boundary semantics.
  { method: 'setAttribute', class: 'ServletContext', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0, 1] },
  { method: 'setAttribute', class: 'HttpServletRequest', type: 'trust_boundary', cwe: 'CWE-501', severity: 'low', arg_positions: [0, 1] },

  // Additional XSS patterns (JDOM/XML output)
  { method: 'outputElementContent', class: 'XMLOutputter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'output', class: 'XMLOutputter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'outputString', class: 'XMLOutputter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // SAX/XNI character output
  { method: 'characters', class: 'XMLString', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'characters', class: 'DefaultFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'characters', class: 'XMLDocumentFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // XWiki HTML rendering
  { method: 'getDefaultConfiguration', class: 'DefaultHTMLCleaner', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getDefaultCleanerTransformations', class: 'DefaultHTMLCleaner', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getDefaultCleanerProperties', class: 'DefaultHTMLCleaner', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getSyntaxRenderer', class: 'HTMLMacroXHTMLRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getSyntaxRenderer', class: 'HTMLMacroAnnotatedHTML5Renderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getSyntaxRenderer', class: 'HTMLMacroAnnotatedXHTMLRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getSyntaxRenderer', class: 'HTMLMacroHTML5Renderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isAllowedValue', class: 'SecureHTMLElementSanitizer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isAttributeAllowed', class: 'SecureHTMLElementSanitizer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'cleanAttributes', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'printXMLElement', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'printXMLStartElement', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // XWiki rendering output sinks (issue #10, CVE-2022-24897 / 2023-29201 /
  // 2023-29528 / 2023-36471 / 2023-37908). WikiPrinter is the base output
  // interface; DefaultWikiPrinter and AnnotatedXHTMLWikiPrinter are the
  // concrete renderers that emit HTML into the response stream.
  { method: 'print', class: 'WikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'println', class: 'WikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'print', class: 'DefaultWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'println', class: 'DefaultWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'print', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'println', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'printXML', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'printXMLComment', class: 'XHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'print', class: 'AnnotatedXHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'println', class: 'AnnotatedXHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'printXMLElement', class: 'AnnotatedXHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'printXMLStartElement', class: 'AnnotatedXHTMLWikiPrinter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Block renderers — `render(block, printer)` writes the block content out.
  // The block argument carries the parsed (possibly tainted) wiki content.
  { method: 'render', class: 'BlockRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'render', class: 'AbstractBlockRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'render', class: 'DefaultBlockRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // XHTML renderer chains
  { method: 'initialize', class: 'HTML5Renderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'initialize', class: 'XHTMLRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'beginFormat', class: 'HTML5ChainingRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Additional forms/plugins
  { method: 'execute', class: 'FormOutput', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'execute', class: 'FormOpen', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'execute', class: 'CurrentTimePlugin', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'execute', class: 'BugReportHandler', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'execute', class: 'InsertPage', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'execute', class: 'Search', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Keycloak/Auth
  { method: 'createResponse', class: 'FreeMarkerLoginFormsProvider', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'exec', class: 'KeycloakSanitizerMethod', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'decodeRedirectUri', class: 'RedirectUtils', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'verifyRedirectUri', class: 'RedirectUtils', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // CXF additional patterns
  { method: 'getExtensionEndpointAddress', class: 'FormattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writerSoapEndpoint', class: 'FormattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writeUnformattedSOAPEndpoints', class: 'UnformattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'writeUnformattedRESTfulEndpoints', class: 'UnformattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setAddress', class: 'BaseUrlHelper', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getBaseURL', class: 'BaseUrlHelper', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'getAbsoluteAddress', class: 'FormattedServiceListWriter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'service', class: 'ServiceListGeneratorServlet', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Apache Sling XSS
  { method: 'getValidDimension', class: 'XSSAPIImpl', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'encodeForJSString', class: 'XSSAPIImpl', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Jolokia
  { method: 'doHandle', class: 'JolokiaHttpHandler', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'sendAllJSON', class: 'JolokiaHttpHandler', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // FHIR XhtmlNode rendering (HL7 FHIR renderers)
  { method: 'tx', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'addText', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setAttribute', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'addTag', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setContent', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'para', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'ah', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'img', class: 'XhtmlNode', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // FHIR Questionnaire renderers
  { method: 'renderTree', class: 'QuestionnaireRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'renderForm', class: 'QuestionnaireRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'renderLinks', class: 'QuestionnaireRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1] },
  { method: 'renderTreeItem', class: 'QuestionnaireRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2, 3] },
  { method: 'addTreeRoot', class: 'QuestionnaireRenderer', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0, 1, 2, 3] },
  // Shiro InvalidRequestFilter
  { method: 'blockSemicolon', class: 'InvalidRequestFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'blockBackslash', class: 'InvalidRequestFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'blockNonAscii', class: 'InvalidRequestFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isAccessAllowed', class: 'InvalidRequestFilter', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // Perfecto credentials
  { method: 'setUsername', class: 'PerfectoCredentials', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setPassword', class: 'PerfectoCredentials', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'setCloudName', class: 'PerfectoCredentials', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // MyFaces resource validation
  { method: 'isValidResourceName', class: 'ResourceValidationUtils', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'isValidLibraryName', class: 'ResourceValidationUtils', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // Additional Command Injection patterns (Jenkins)
  { method: 'child', class: 'FilePath', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'forGroup', class: 'FolderLibraries', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'parse', class: 'LibraryAdder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'findResources', class: 'LibraryAdder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'loadScripts', class: 'LibraryAdder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'doRetrieve', class: 'SCMSourceRetriever', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'suggestedConfigurations', class: 'LibraryResolver', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0] },
  { method: 'run', class: 'LibraryStep', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // XStream mapper (deserialization chain)
  { method: 'realClass', class: 'CachingMapper', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'flushCache', class: 'CachingMapper', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [] },
  // Bourne Shell patterns
  { method: 'getShellArgs', class: 'BourneShell', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [] },
  { method: 'getRawCommandLine', class: 'Shell', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [] },
  { method: 'getExecutionPreamble', class: 'Shell', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [] },
  { method: 'setQuotedArgumentsEnabled', class: 'Shell', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0] },
  // Sandbox/script security
  { method: 'onNewInstance', class: 'SandboxInterceptor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Java Log Injection (slf4j / logback / java.util.logging) — CWE-117
  //
  // Classification decision — cognium-dev #264: Logger receivers stay
  // as log_injection (CWE-117), NOT format_string (CWE-134). The real
  // vulnerability with tainted data flowing into Logger.log(fmt, ...)
  // is log-forgery via CRLF injection, not format-string exploitation.
  // A genuine format_string vulnerability requires the FORMAT STRING
  // itself to be attacker-controlled, which is virtually never the
  // case in Logger APIs (the format string is a literal at the call
  // site). Adding format_string sinks for these same receivers would
  // duplicate the existing log_injection findings on every call site
  // without adding real signal. The rare edge case where a caller
  // passes `taintedFmt` at arg[0] is still caught by these entries
  // (via arg_positions[0] on the SLF4J-family methods), classified as
  // log_injection.
  // Issue #44: log.info/warn/error/debug emit the message argument and any
  // {} format arguments to the log stream. Untrusted input forwarded into
  // these calls allows log forging (newline injection) and downstream log
  // analyzer pollution. Scoped to `java` so the generic method names don't
  // collide with JS console / Python logger entries below.
  { method: 'info',     class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'warn',     class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'error',    class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'debug',    class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'trace',    class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  // java.util.logging.Logger uses the same class name `Logger` — same entries above cover it.
  // Severity-tagged levels: SEVERE/WARNING/INFO/CONFIG/FINE/FINER/FINEST
  { method: 'severe',   class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0], languages: ['java'] },
  { method: 'warning',  class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0], languages: ['java'] },
  { method: 'config',   class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0], languages: ['java'] },
  { method: 'fine',     class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0], languages: ['java'] },
  { method: 'finer',    class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0], languages: ['java'] },
  { method: 'finest',   class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0], languages: ['java'] },
  { method: 'log',      class: 'Logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [1, 2, 3], languages: ['java'] },

  // =========================================================================
  // Node.js/Express Sinks
  // =========================================================================

  // Node.js Command Injection (child_process)
  { method: 'exec', class: 'child_process', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'execSync', class: 'child_process', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'spawn', class: 'child_process', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'spawnSync', class: 'child_process', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // Also match without receiver (destructured imports: const { exec } = require('child_process'))
  // `exec` is intentionally classless: catches Node.js child_process.exec AND
  // Java Runtime.exec (via `r.exec()` where heuristic can't resolve r → Runtime).
  { method: 'exec', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0] },
  // `execSync`/`spawn`/`spawnSync`/`execFile` are Node-specific — language-scope them.
  { method: 'execSync', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'spawn', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'spawnSync', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'execFile', type: 'command_injection', cwe: 'CWE-78', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Node.js File System (path traversal)
  { method: 'readFile', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'readFileSync', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'writeFile', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'writeFileSync', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'appendFile', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'readdir', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'unlink', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'rmdir', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'createReadStream', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'createWriteStream', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },

  // Node.js SQL (mysql, pg, sqlite, etc.)
  // Language-scoped: generic class names `Pool`/`Connection`/`Client` substring-match
  // unrelated Java identifiers like `cachedThreadPool`, `dbConnection`. See issue #14.
  { method: 'query', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'query', class: 'Pool',       type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'query', class: 'Client',     type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'execute', class: 'Pool',       type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'execute', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  // Note: classless { method: 'query' } removed — too many FPs (UriComponentsBuilder.query(), etc.)
  // SQL query calls are covered by class-specific patterns above (Connection, Pool, Client, JdbcTemplate)
  // Note: `raw` is shared with Python (Django ORM) — scoped to JS+TS to avoid leaking.
  { method: 'raw', type: 'sql_injection', cwe: 'CWE-89', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // sqlite3 (npm) — Database/Statement methods. The JS plugin resolves
  // `const db = new sqlite3.Database(...); db.all(sql)` to the resolution
  // target `Connection.all`, so class-scoped patterns matching `Connection`
  // hit (see #186 Sprint 55 matcher extension consulting call.resolution.target).
  // `exec`/`run`/`all`/`get`/`each` follow the same shape.
  { method: 'all',  class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'run',  class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'each', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'get',  class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },
  { method: 'exec', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'], allow_unresolved_receiver: true },

  // Browser DOM XSS sinks
  { method: 'setAttribute', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },

  // Angular DomSanitizer.bypassSecurityTrust* — CWE-79 (#184 Sprint 55).
  // These methods explicitly bypass Angular's built-in sanitizer; passing
  // tainted strings re-introduces DOM-injection risk. Distinctive method
  // names — classless + language-scoped is safe.
  { method: 'bypassSecurityTrustHtml',        type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'bypassSecurityTrustScript',      type: 'xss', cwe: 'CWE-79', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'bypassSecurityTrustStyle',       type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'bypassSecurityTrustUrl',         type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'bypassSecurityTrustResourceUrl', type: 'xss', cwe: 'CWE-79', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Express.js XSS (response methods)
  { method: 'send', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'write', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'end', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'html', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'render', class: 'Response', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [1] },

  // Node.js Code Injection (eval, vm, etc.)
  { method: 'eval', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'Function', class: 'constructor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'runInContext', class: 'vm', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'runInNewContext', class: 'vm', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'runInThisContext', class: 'vm', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  // `new vm.Script(taint)` — Node core `vm` module compiles strings. The
  // JS plugin emits method_name = 'vm.Script' for the constructor call;
  // the matcher's dotted-simple-name fallback (taint-matcher.ts:1664) lets
  // pattern.method = 'Script' hit on method_name = 'vm.Script'. The
  // `class: 'constructor'` short-circuit accepts the no-receiver shape.
  // (#188 Sprint 55)
  { method: 'Script', class: 'constructor', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // `setImmediate(taintedString)` — like setTimeout/setInterval, Node will
  // evaluate the first argument when it is a string. The callback-shape
  // suppression in taint-matcher.ts:1342 already covers setTimeout/
  // setInterval; the Sprint 55 fix extends that gate to setImmediate too.
  // (#188 Sprint 55)
  { method: 'setImmediate', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // protobufjs Root.parse(schemaText) compiles a textual schema into JS at runtime;
  // tainted schema → code execution (CVE-2026-41242). Issue #94.
  { method: 'parse', class: 'protobuf',   type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parse', class: 'protobufjs', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parse', class: 'Root',       type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Node.js NoSQL Injection (MongoDB native driver + mongoose) — CWE-943
  // Issue #45: the bare `class: 'Collection'` constraint missed mongoose's
  // fluent chains (mongoose.connection.db.collection('x').find({...})) and
  // Model.find calls because the call-site receiver type does not resolve
  // to `Collection`. Add classless+language-scoped entries for the
  // MongoDB-specific method names (findOne/aggregate/updateOne/etc.) and
  // mongoose `Model`/`Query` class entries. Bare `find` stays class-scoped
  // to avoid colliding with Array.prototype.find.
  { method: 'find', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0] },
  { method: 'findOne', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0] },
  { method: 'updateOne', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0] },
  { method: 'updateMany', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0] },
  { method: 'deleteOne', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0] },
  { method: 'deleteMany', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0] },
  // Mongoose Model/Query class entries — Model.find/findOne/etc.
  { method: 'find',                class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'findOne',             class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'findById',            class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'findOneAndUpdate',    class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'findOneAndDelete',    class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'findOneAndReplace',   class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'updateOne',           class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'updateMany',          class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'deleteOne',           class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'deleteMany',          class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'countDocuments',      class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'aggregate',           class: 'Model', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Mongoose Query class entries — chain methods returning Query
  { method: 'where',               class: 'Query', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'equals',              class: 'Query', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Classless MongoDB-specific method names (rare outside MongoDB APIs) —
  // language-scoped to JS/TS. Excludes plain `find` (Array.prototype.find FP).
  { method: 'findOne',           type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'findOneAndUpdate',  type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'findOneAndDelete',  type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'findOneAndReplace', type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'updateOne',         type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'updateMany',        type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0, 1], languages: ['javascript', 'typescript'] },
  { method: 'deleteOne',         type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'deleteMany',        type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'aggregate',         type: 'nosql_injection', cwe: 'CWE-943', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Node.js SSRF (HTTP clients)
  { method: 'get', class: 'axios', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'axios', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'request', class: 'axios', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'fetch', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'request', class: 'http', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'get', class: 'http', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'request', class: 'https', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'get', class: 'https', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  // needle library (used in NodeGoat)
  { method: 'get', class: 'needle', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'needle', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'request', class: 'needle', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  // got library
  { method: 'get', class: 'got', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'got', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  // got/request npm packages default-export a callable function:
  //   const got = require('got'); got(req.query.url)
  //   const request = require('request'); request(req.query.url, cb)
  // The classless method names are distinctive enough (`got`, `request`) that
  // the FP risk is acceptable; both are scoped to JS/TS so they don't leak
  // into other plugins. (#185 Sprint 55)
  { method: 'got',     type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'request', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // superagent
  { method: 'get', class: 'superagent', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'superagent', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  // node-fetch
  { method: 'default', class: 'node-fetch', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },

  // Node.js / JavaScript Log Injection (console.*) — CWE-117
  // Issue #44: console.log/warn/error/info with tainted template literals
  // allow log forging (newline-injection) and downstream log analyzer
  // pollution. Scoped to JS/TS so the bare class `console` doesn't collide
  // with Python `console` module or Java identifiers.
  { method: 'log',   class: 'console', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'warn',  class: 'console', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'error', class: 'console', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'info',  class: 'console', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'debug', class: 'console', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'trace', class: 'console', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },

  // Node.js / Express Open Redirect — CWE-601
  // Issue #46: `res.redirect(req.query.next)` did not fire because the
  // legacy `class: 'Response'` constraint depended on receiver type
  // resolution of the Express `res` parameter. Mirror Python's classless
  // pattern with a language-scoped classless entry. The method name
  // `redirect` is rare outside HTTP frameworks so the FP risk is low.
  { method: 'redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Node.js LDAP Injection (ldapjs) — CWE-90
  // cognium-dev#104 Sprint 22: receiver matches the canonical ldapjs
  // import name (`const ldap = require('ldapjs')` → ldap.search/...).
  { method: 'search',     class: 'ldap',   type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [1, 2], languages: ['javascript', 'typescript'] },
  { method: 'searchSync', class: 'ldap',   type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [1, 2], languages: ['javascript', 'typescript'] },
  { method: 'search',     class: 'ldapjs', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [1, 2], languages: ['javascript', 'typescript'] },
  { method: 'searchSync', class: 'ldapjs', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [1, 2], languages: ['javascript', 'typescript'] },

  // Node.js XPath Injection (xpath module) — CWE-643
  // cognium-dev#104 Sprint 22: `const xpath = require('xpath')` → xpath.select/select1/evaluate.
  { method: 'select',   class: 'xpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'select1',  class: 'xpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'evaluate', class: 'xpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parse',    class: 'xpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Node.js XXE (libxmljs, xmldom) — CWE-611
  // cognium-dev#104 Sprint 22: `const libxml = require('libxmljs')` (or 'libxml')
  // → libxml.parseXml(src, {noent: true}). xmldom DOMParser via parseFromString.
  { method: 'parseXml',        class: 'libxml',   type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parseXmlString',  class: 'libxml',   type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parseXml',        class: 'libxmljs', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parseXmlString',  class: 'libxmljs', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parseFromString', class: 'DOMParser', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'parseFromString', class: 'xmldom',    type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Node.js Server-Side Template Injection (SSTI) — CWE-94
  // cognium-dev#104 Sprint 22: ejs/handlebars/pug template render with
  // tainted templates → arbitrary JS execution. Uses `code_injection`
  // SinkType to mirror the Python Jinja2/Mako pattern above.
  { method: 'render',   class: 'ejs',        type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'compile',  class: 'ejs',        type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'render',   class: 'handlebars', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'compile',  class: 'handlebars', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'render',   class: 'pug',        type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'compile',  class: 'pug',        type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'render',   class: 'mustache',   type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'render',   class: 'nunjucks',   type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'renderString', class: 'nunjucks', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // =========================================================================
  // Python Sinks
  // =========================================================================

  // Python Command Injection
  { method: 'system', class: 'os', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'popen', class: 'os', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'run', class: 'subprocess', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'call', class: 'subprocess', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'check_output', class: 'subprocess', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'check_call', class: 'subprocess', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'Popen', class: 'subprocess', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Python Code Injection
  // Language-scoped: classless `exec`/`eval`/`compile` collide with Java/JS builtins
  // and Java util.concurrent (e.g. Executor.execute / future.compile).
  { method: 'eval', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'exec', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'compile', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: '__import__', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0], languages: ['python'] },
  // Python dynamic import — `importlib.import_module(taint)` parallels Java's
  // `Class.forName`. The bare `__import__` entry above also matches the
  // `importlib.__import__` form because the sink-matcher is class-agnostic
  // when a classless entry exists. Sprint 56 #183.
  { method: 'import_module', class: 'importlib', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0], languages: ['python'] },

  // Python Deserialization — language-scoped so the lowercase `yaml` / `pickle`
  // module names don't collide with Java locals named `yaml` (SnakeYAML usage).
  { method: 'loads', class: 'pickle', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'load', class: 'pickle', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'loads', class: 'marshal', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'load', class: 'yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'loads', class: 'yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['python'] },

  // Python SQL Injection
  // Language-scoped: classless `execute`/`raw` collide with Java util.concurrent
  // (Executor.execute, ThreadPool.execute) and other languages. See issue #14.
  { method: 'execute', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'executemany', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'raw', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'extra', type: 'sql_injection', cwe: 'CWE-89', severity: 'high', arg_positions: [0], languages: ['python'] },

  // Python Path Traversal
  // Language-scoped: classless `open` collides with Java I/O / JS DOM.
  { method: 'open', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'remove', class: 'os', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'unlink', class: 'os', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'rmdir', class: 'os', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'rmtree', class: 'shutil', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0] },
  { method: 'send_file', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['python'] },

  // Python XSS / SSTI
  // Issue #54: Flask's `render_template_string(template_str)` with an
  // attacker-controlled template string is Server-Side Template Injection
  // (Jinja2 SSTI → RCE), not reflected XSS. Classify as code_injection
  // (CWE-94) with critical severity to match `jinja2.Template().render()`
  // and `Template.from_string()` entries above.
  { method: 'render_template_string', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'Markup', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'mark_safe', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0], languages: ['python'] },

  // Python SSRF
  { method: 'get', class: 'requests', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'requests', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'urlopen', class: 'urllib.request', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },

  // Python Open Redirect
  { method: 'redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['python'] },

  // Python XPath Injection
  { method: 'xpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'find', class: 'etree', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'findall', class: 'etree', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'iterfind', class: 'etree', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  { method: 'XPath', class: 'lxml', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },
  // elementpath library (XPath 2.0/3.0)
  { method: 'select', class: 'elementpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [1] },
  { method: 'select', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'iter_select', class: 'elementpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [1] },
  { method: 'Selector', class: 'elementpath', type: 'xpath_injection', cwe: 'CWE-643', severity: 'high', arg_positions: [0] },

  // Python XXE
  { method: 'parse', class: 'etree', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'fromstring', class: 'etree', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'XML', class: 'etree', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'parseString', class: 'minidom', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'parse', class: 'sax', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },
  { method: 'XMLParser', class: 'lxml', type: 'xxe', cwe: 'CWE-611', severity: 'high', arg_positions: [0] },

  // Python LDAP Injection
  { method: 'search', class: 'ldap', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 2] },
  { method: 'search_s', class: 'ldap', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 2] },
  { method: 'search_ext', class: 'ldap', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 2] },
  { method: 'search_ext_s', class: 'ldap', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 2] },
  // ldap3 library (different API from python-ldap)
  { method: 'search', class: 'Connection', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0, 1] },
  { method: 'extend', class: 'Connection', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },
  { method: 'modify', class: 'Connection', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },
  { method: 'add', class: 'Connection', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },
  { method: 'delete', class: 'Connection', type: 'ldap_injection', cwe: 'CWE-90', severity: 'high', arg_positions: [0] },

  // Python Trust Boundary (CWE-501)
  // The vulnerability is storing untrusted data in session that gets trusted later
  { method: '__setitem__', class: 'session', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1] },
  { method: 'update', class: 'session', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0] },
  // Flask-specific session assignment
  { method: '__setitem__', class: 'flask.session', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1] },
  // Django session
  { method: '__setitem__', class: 'request.session', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [1] },

  // Python pathlib patterns
  { method: 'read_text', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [] },
  { method: 'read_bytes', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [] },
  { method: 'write_text', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'write_bytes', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'mkdir', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [] },
  { method: 'unlink', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [] },
  { method: 'rmdir', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [] },
  { method: 'joinpath', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },

  // Python NoSQL injection (MongoDB, etc.)
  { method: 'find', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0] },
  { method: 'find_one', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0] },
  { method: 'update_one', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0, 1] },
  { method: 'update_many', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0, 1] },
  { method: 'delete_one', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0] },
  { method: 'delete_many', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0] },
  { method: 'aggregate', class: 'Collection', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0] },
  // pymongo dynamic attribute-access pattern: `db.users.find({...})` — receiver
  // class isn't statically known. Method-only entries restricted to Python.
  // cognium-dev#104 Sprint 22, #194 Sprint 54 added `find`/`aggregate`.
  { method: 'find',        type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0],    languages: ['python'] },
  { method: 'aggregate',   type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0],    languages: ['python'] },
  { method: 'find_one',    type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0],    languages: ['python'] },
  { method: 'update_one',  type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0, 1], languages: ['python'] },
  { method: 'update_many', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0, 1] , languages: ['python'] },
  { method: 'delete_one',  type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0],    languages: ['python'] },
  { method: 'delete_many', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0],    languages: ['python'] },
  { method: 'replace_one', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0, 1], languages: ['python'] },
  { method: 'count_documents', type: 'nosql_injection', cwe: 'CWE-943', severity: 'critical', arg_positions: [0], languages: ['python'] },

  // Python Template Injection (Jinja2, Mako)
  { method: 'from_string', class: 'Template', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'Template', class: 'jinja2', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'Template', class: 'mako', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },

  // Python Log Injection — cognium-dev #193: positions [0, 1, 2, 3, 4]
  // cover both the format string (arg 0) and Python `logging`'s positional
  // *args (1..N), which get rendered into the log line via `%` substitution
  // (e.g. `log.warning("user=%s", user)` taints via arg 1). Five-arg cap
  // matches the established explicit-enumeration pattern used elsewhere in
  // this file.
  { method: 'info', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'warning', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'warn', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'error', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'debug', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'critical', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'fatal', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'exception', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'log', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [1, 2, 3, 4] },
  // Python `logging` module top-level functions (e.g. logging.info(...))
  // — cognium-dev#104 Sprint 22: OOP fixtures use `import logging; logging.info(self.msg)`.
  { method: 'info', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'warning', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'warn', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'error', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'debug', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'critical', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'fatal', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },
  { method: 'log', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [1, 2, 3, 4] },
  { method: 'exception', class: 'logging', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2, 3, 4] },

  // =========================================================================
  // Java CWE-Bench Enhancement Patterns (Collection/Builder)
  // =========================================================================

  // Collection-based command injection (ProcessBuilder with List)
  { method: 'command', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  // ProcessBuilder.inheritIO removed in 3.83.0 (#124): no args, no command
  // string flows into it. See note above next to the Process-related cluster.

  // Jenkins DSL patterns
  { method: 'step', class: 'StepExecution', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'invokeMethod', class: 'Script', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0, 1] },
  { method: 'evaluate', class: 'Script', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'parse', class: 'GroovyClassLoader', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },

  // XML-based deserialization leading to RCE
  { method: 'unmarshal', class: 'JAXBContext', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0] },
  { method: 'readObject', class: 'XMLDecoder', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [] },

  // JavaScript context XSS patterns
  { method: 'setContentType', class: 'HttpServletResponse', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },

  // Template context pollution
  { method: 'put', class: 'VelocityContext', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [1] },
  { method: 'setVariable', class: 'Context', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [1] },

  // HTML sanitizer bypass markers (known CVE patterns)
  { method: 'clean', class: 'AntiSamy', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
  { method: 'getValidSafeHTML', class: 'ESAPI', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },

  // Request/session attribute reflection XSS (return value is tainted)
  { method: 'getAttribute', class: 'HttpServletRequest', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [] },
  { method: 'getAttribute', class: 'HttpSession', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [] },

  // =========================================================================
  // Rust Sinks
  // =========================================================================

  // Rust Command Injection (std::process)
  { method: 'spawn', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'output', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'status', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'new', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'arg', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'args', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Rust SQL Injection (sqlx, diesel, rusqlite, tokio-postgres)
  // Language-scoped: generic class names `Pool`/`Connection`/`Client` substring-match
  // unrelated Java identifiers (cachedThreadPool, dbConnection). See issue #14.
  { method: 'query', class: 'Client', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'execute', class: 'Client', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'query', class: 'Pool', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'execute', class: 'Pool', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'sql_query', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'raw_sql', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'execute', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'query_row', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'prepare', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  // sqlx::query macro — use class-specific pattern
  { method: 'query', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  // rusqlite specific
  // Language-scoped: classless `execute`/`prepare`/`query_map` collide with
  // Java util.concurrent (Executor.execute, ExecutorService) and other languages.
  { method: 'prepare', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'execute', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'query_map', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['rust'] },

  // Rust Path Traversal
  { method: 'open', class: 'File', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'create', class: 'File', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // Language-scoped: classless std::fs helpers collide with Java/JS method names
  // (write, copy, rename, metadata, etc.) See issue #14.
  { method: 'read_dir', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'remove_file', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'remove_dir', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'remove_dir_all', type: 'path_traversal', cwe: 'CWE-22', severity: 'critical', arg_positions: [0], languages: ['rust'] },
  { method: 'copy', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1], languages: ['rust'] },
  { method: 'rename', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1], languages: ['rust'] },
  { method: 'write', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'read_to_string', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'create_dir', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'create_dir_all', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0], languages: ['rust'] },
  { method: 'metadata', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0], languages: ['rust'] },
  { method: 'symlink_metadata', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0], languages: ['rust'] },
  // Tokio async fs
  { method: 'read_to_string', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'write', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'create_dir_all', class: 'fs', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },

  // Rust Deserialization (serde, toml, ron, etc.)
  { method: 'from_str', class: 'serde_json', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_slice', class: 'serde_json', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_reader', class: 'serde_json', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_str', class: 'serde_yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_bytes', class: 'bincode', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0] },
  { method: 'deserialize', class: 'bincode', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0] },
  { method: 'from_str', class: 'toml', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_str', class: 'ron', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  // Generic deserialization patterns
  { method: 'from_str', type: 'deserialization', cwe: 'CWE-502', severity: 'medium', arg_positions: [0] },
  { method: 'from_slice', type: 'deserialization', cwe: 'CWE-502', severity: 'medium', arg_positions: [0] },

  // Rust XSS (actix-web, rocket, axum response body)
  { method: 'body', class: 'HttpResponseBuilder', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'body', class: 'HttpResponse', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'Html', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // Rust SSRF (reqwest, hyper, ureq)
  { method: 'get', class: 'Client', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'Client', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'request', class: 'Client', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'send', class: 'Request', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  // ureq library
  { method: 'get', class: 'ureq', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'ureq', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  // Hyper Uri parsing
  { method: 'parse', class: 'Uri', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },

  // Rust Open Redirect
  { method: 'redirect', class: 'HttpResponse', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0] },
  // Actix/warp `Redirect::to(url)` — scoped to Rust to avoid collision with
  // Go's `c.Redirect(status, url)` on gin/echo, which lives further down in
  // the OPEN_REDIRECT_FRAMEWORK_SINKS block with `arg_positions: [0, 1]`.
  { method: 'Redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0], languages: ['rust'] },
  { method: 'see_other', class: 'Redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'to', class: 'Redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'temporary', class: 'Redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'permanent', class: 'Redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'header', class: 'Response', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [1] },
  { method: 'insert_header', class: 'HttpResponse', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [1] },
  { method: 'append_header', class: 'HttpResponse', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [1] },
  { method: 'from_str', class: 'HeaderValue', type: 'open_redirect', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },

  // Rust Log Injection (log crate, tracing)
  { method: 'info!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  { method: 'warn!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  { method: 'error!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  { method: 'debug!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  { method: 'trace!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  { method: 'log!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  // Standard library logging
  { method: 'println!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  { method: 'eprintln!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2] },
  // log:: namespaced forms — the Rust macro extractor preserves the full
  // path prefix in `method_name` (`log::info!`), so the bare entries above
  // only match the imported form `use log::info; info!(...)`. Sprint 56 #182 Slice A.
  { method: 'log::info!',  type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2], languages: ['rust'] },
  { method: 'log::warn!',  type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2], languages: ['rust'] },
  { method: 'log::error!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2], languages: ['rust'] },
  { method: 'log::debug!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2], languages: ['rust'] },
  { method: 'log::trace!', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2], languages: ['rust'] },
  { method: 'log::log!',   type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0, 1, 2], languages: ['rust'] },

  // Rust sqlx SQL Injection
  { method: 'query', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'query_as', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'query_as', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'query_scalar', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'execute', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'fetch_one', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'fetch_all', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'fetch_optional', class: 'sqlx', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },

  // Rust Command Injection (std::process::Command)
  { method: 'arg', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'args', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'new', class: 'Command', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Rust reqwest SSRF
  { method: 'get', class: 'reqwest', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'reqwest', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'put', class: 'reqwest', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'delete', class: 'reqwest', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'get', class: 'Client', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post', class: 'Client', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },

  // Rust Actix-web XSS
  { method: 'body', class: 'HttpResponse', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'body', class: 'HttpResponseBuilder', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'body', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  // warp::reply::html
  { method: 'html', class: 'reply', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },
  { method: 'html', class: 'warp', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [0] },

  // Rust serde deserialization
  { method: 'from_str', class: 'serde_yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_reader', class: 'serde_yaml', type: 'deserialization', cwe: 'CWE-502', severity: 'high', arg_positions: [0] },
  { method: 'from_str', class: 'serde_json', type: 'deserialization', cwe: 'CWE-502', severity: 'medium', arg_positions: [0] },
  { method: 'from_slice', class: 'serde_json', type: 'deserialization', cwe: 'CWE-502', severity: 'medium', arg_positions: [0] },

  // =========================================================================
  // ReDoS sinks (CWE-1333) — issue #86 / Sprint 5
  // =========================================================================
  // First argument of regex compile/match functions is the pattern. Tainted
  // patterns enable catastrophic-backtracking DoS.
  // Python: re.{match,search,compile,findall,fullmatch,sub,subn,split}
  { method: 'match',     class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'search',    class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'fullmatch', class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'compile',   class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'findall',   class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'finditer',  class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'sub',       class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'subn',      class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'split',     class: 're', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['python'] },
  // Java: Pattern.compile / Pattern.matches; String.matches/replaceAll/replaceFirst/split
  { method: 'compile',     class: 'Pattern', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'matches',     class: 'Pattern', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'matches',     class: 'String',  type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'replaceAll',  class: 'String',  type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'replaceFirst',class: 'String',  type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'split',       class: 'String',  type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['java'] },
  // JS/TS: new RegExp(pat) ctor; receiver_type === 'RegExp'. Also string.match
  // and string.matchAll, replace, search take a regex/string pattern.
  { method: 'RegExp',  class: 'constructor', type: 'redos', cwe: 'CWE-1333', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Go: regexp.Compile / MustCompile / Match / MatchString
  { method: 'Compile',     class: 'regexp', type: 'redos', cwe: 'CWE-1333', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'MustCompile', class: 'regexp', type: 'redos', cwe: 'CWE-1333', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'Match',       class: 'regexp', type: 'redos', cwe: 'CWE-1333', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'MatchString', class: 'regexp', type: 'redos', cwe: 'CWE-1333', severity: 'medium', arg_positions: [0], languages: ['go'] },

  // =========================================================================
  // Format-string sinks (CWE-134) — issue #86 / Sprint 5
  // =========================================================================
  // First argument is the format string. Tainted format strings enable
  // information disclosure and (for C-style runtimes) memory writes.
  // Java: String.format / Formatter.format / printf / format on PrintStream
  // (note: printf/format on PrintWriter/PrintStream are already XSS sinks above)
  { method: 'format',  class: 'String',    type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'format',  class: 'Formatter', type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'printf',  class: 'System.out',type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  // cognium-dev #264 — extend the Java format-string surface.
  // MessageFormat.format(pattern, args) — same receiver-family as String.format
  // but on the java.text side. PrintStream/PrintWriter.{printf,format} —
  // arbitrary streams (not just System.out) also honour format-string
  // specifiers, so a tainted first arg is a genuine CWE-134 sink.
  { method: 'format',  class: 'MessageFormat', type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'printf',  class: 'PrintStream',   type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'format',  class: 'PrintStream',   type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'printf',  class: 'PrintWriter',   type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  { method: 'format',  class: 'PrintWriter',   type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['java'] },
  // NOTE: Python `userFmt.format(...)` and `userFmt % args` require
  // receiver-taint or operator-LHS-taint tracking — the format string is the
  // receiver, not an argument. Deferred to Sprint 6 (#86 follow-up).
  // C-style: printf / fprintf / sprintf / snprintf via ctypes/cffi.
  { method: 'printf',  type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [0], languages: ['python'] },
  { method: 'fprintf', type: 'format_string', cwe: 'CWE-134', severity: 'high', arg_positions: [1], languages: ['python'] },
  // Go: fmt.Sprintf/Printf/Fprintf/Errorf — format string is first/second arg
  { method: 'Sprintf', class: 'fmt', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'Printf',  class: 'fmt', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'Errorf',  class: 'fmt', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'Fprintf', class: 'fmt', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [1], languages: ['go'] },
  // cognium-dev #264 — Go stdlib `log` package format-string entry points.
  // log.Printf / Fatalf / Panicf take the format string at arg[0]; tainted
  // format string reaches the same fmt.Sprintf machinery internally.
  { method: 'Printf',  class: 'log', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'Fatalf',  class: 'log', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [0], languages: ['go'] },
  { method: 'Panicf',  class: 'log', type: 'format_string', cwe: 'CWE-134', severity: 'medium', arg_positions: [0], languages: ['go'] },

  // CRLF / HTTP response splitting (CWE-113) — Sprint 6, #86.
  // Node.js / Express response header / cookie sinks. The header *name* (arg 0)
  // is also CRLF-sensitive but is almost always a string literal; we model
  // arg 1 (the value) as the primary sink.
  { method: 'setHeader', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['javascript', 'typescript'] },
  { method: 'writeHead', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [2], languages: ['javascript', 'typescript'] },
  // Express: res.cookie(name, value, options) — value is CRLF-sensitive.
  { method: 'cookie',    type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['javascript', 'typescript'] },
  // Express: res.location(url) and res.redirect(url) — Location header.
  { method: 'location',  type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'redirect',  type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Go net/http: w.Header().Set(k, v) / Add(k, v) — first arg is the value
  // (Header is a map; the actual `value` is arg 1 of the call). We flag the
  // value position so a tainted variable is detected.
  { method: 'Set', class: 'Header', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['go'] },
  { method: 'Add', class: 'Header', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['go'] },

  // Python: Flask/Werkzeug/FastAPI/Django response header sinks (CWE-113).
  // Subscript assignment (`resp.headers['X-A'] = name`) is NOT covered because
  // the IR does not emit subscript writes as calls — a known limitation, see
  // cognium-dev #111. The method-call forms below ARE captured (receiver
  // suffix-match on `.headers` via receiverMightBeClass).
  { method: 'set',         class: 'headers', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['python'] },
  { method: 'add',         class: 'headers', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['python'] },
  { method: 'setdefault',  class: 'headers', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['python'] },
  { method: 'extend',      class: 'headers', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [0], languages: ['python'] },
  { method: '__setitem__', class: 'headers', type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['python'] },
  // Flask/Werkzeug response.set_cookie(name, value, ...) — value is CRLF-sensitive.
  { method: 'set_cookie',  type: 'crlf', cwe: 'CWE-113', severity: 'medium', arg_positions: [1], languages: ['python'] },

  // Mass-assignment (CWE-915 / CWE-1321) — Sprint 6, #86; cognium-dev #68 Sprint 10.
  // JS Object.assign(target, ...sources), `_.merge`, `_.extend`, `$.extend`,
  // `Object.defineProperty` — when fed an attacker-controlled bag, they write
  // arbitrary keys onto the target (or, for `__proto__`/`constructor.prototype`,
  // pollute the prototype chain). The CWE is CWE-1321 (Prototype Pollution),
  // which subsumes mass assignment for JS sinks operating on plain Objects.
  // We keep the existing `mass_assignment` SinkType so consumers route the
  // findings the same way; only the CWE shifts to flag prototype-pollution.
  { method: 'assign',           class: 'Object', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'defineProperty',   class: 'Object', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2], languages: ['javascript', 'typescript'] },
  { method: 'defineProperties', class: 'Object', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1], languages: ['javascript', 'typescript'] },
  // Lodash bulk-merge helpers behave identically. `_.merge` and `lodash.merge`
  // are aliases — match both receivers.
  { method: 'merge',  class: '_',      type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'merge',  class: 'lodash', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'extend', class: '_',      type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'extend', class: 'lodash', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'defaultsDeep', class: '_',      type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'defaultsDeep', class: 'lodash', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  // jQuery $.extend(target, source) (legacy).
  { method: 'extend', class: '$',      type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'extend', class: 'jQuery', type: 'mass_assignment', cwe: 'CWE-1321', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },

  // DOM-XSS via property assignment (CWE-79) — cognium-dev #68 Sprint 10.
  // `el.innerHTML = tainted` / `el.outerHTML = tainted`. The JS call extractor
  // emits a synthetic CallInfo with method=`innerHTML`/`outerHTML` for each
  // matching assignment_expression. These classless entries catch them.
  { method: 'innerHTML', type: 'xss', cwe: 'CWE-79', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'outerHTML', type: 'xss', cwe: 'CWE-79', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // node-serialize.unserialize (CWE-502) — cognium-dev #68 Sprint 10.
  // The node-serialize package evaluates `_$$ND_FUNC$$_` IIFE payloads on
  // decode, turning untrusted input into RCE. Match both receiver-bound
  // calls (`serialize.unserialize(x)`) and destructured imports
  // (`const { unserialize } = require('node-serialize')`).
  { method: 'unserialize', class: 'serialize',      type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'unserialize', class: 'node-serialize', type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'unserialize',                          type: 'deserialization', cwe: 'CWE-502', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // =========================================================================
  // cognium-dev #241 (non-Java) — real-world sink signatures
  // =========================================================================

  // Python SSRF — httpx (sync + async client + top-level module)
  { method: 'get',     class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'post',    class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'request', class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [1] },   // request(method, url, ...)
  { method: 'stream',  class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [1] },
  { method: 'delete',  class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'put',     class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'patch',   class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },
  { method: 'head',    class: 'httpx', type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0] },

  // Python SQLi — asyncpg Connection.*
  { method: 'execute',  class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'fetch',    class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'fetchrow', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  { method: 'fetchval', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0] },
  // Method-only python-scoped fallback (aliased connections, pool.acquire())
  { method: 'fetchrow', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['python'] },
  { method: 'fetchval', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['python'] },

  // Go Open Redirect — net/http.Redirect(w, r, url, code)
  { method: 'Redirect', class: 'http', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [2], languages: ['go'] },

  // Go SSRF — fasthttp Client instance methods (class 'Client' does not
  // fuzzy-collide with 'http', unlike class 'fasthttp' which would
  // suffix-match receiver 'http' via receiverMightBeClass's 40% length
  // heuristic. Package-level `fasthttp.Get/Post/GetTimeout` sinks live
  // in the Go plugin (`languages/plugins/go.ts::getBuiltinSinks()`) so
  // they iterate after net/http entries and don't hijack `http.Get`.
  { method: 'Do',         class: 'Client',   type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0], languages: ['go'] },   // *fasthttp.Client.Do(req)
  { method: 'DoTimeout',  class: 'Client',   type: 'ssrf', cwe: 'CWE-918', severity: 'high', arg_positions: [0], languages: ['go'] },

  // =========================================================================
  // cognium-dev #248 — prompt-injection sinks (CWE-1427)
  //
  // Tainted data reaching a generative-model prompt-construction API is
  // classified as `prompt_injection`. v1 uses broad positional matching
  // (arg_positions [0..3]) because these APIs are kwarg-heavy: Python
  // `openai.chat.completions.create(model=..., messages=...)` may pass the
  // messages arg at position 0 or 1 depending on caller order, and JS/TS
  // object-literal `{ messages: [...], model: '...' }` is a single
  // positional arg whose taint is inherited from any tainted property.
  // Argname-precise matching (messages=/prompt=/content=) and
  // sanitizer credit for prompt-template libraries (PromptTemplate,
  // ChatPromptTemplate) are follow-ups.
  //
  // Class-qualified entries prevent bare `create()` / `generate()` calls
  // with no receiver from matching (per taint-matcher.ts:1696 guard).
  // =========================================================================

  // --- Python: openai (v1 SDK) --------------------------------------------
  { method: 'create',  class: 'Completions', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'create',  class: 'Responses',   type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  // openai <1.0 legacy top-level API — `openai.ChatCompletion.create(...)` / `openai.Completion.create(...)`
  { method: 'create',  class: 'ChatCompletion', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'create',  class: 'Completion',     type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },

  // --- Python: anthropic ---------------------------------------------------
  { method: 'create',  class: 'Messages',    type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'stream',  class: 'Messages',    type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },

  // --- Python: litellm (bare functions from the litellm module) -----------
  { method: 'completion',  class: 'litellm',  type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'acompletion', class: 'litellm',  type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },

  // --- Python: langchain chat/llm models ----------------------------------
  // Common concrete classes; matching the class name catches typical usage
  // `ChatOpenAI().invoke(prompt)` where the receiver-type resolver identifies
  // the class from the constructor.
  { method: 'invoke',   class: 'ChatOpenAI',              type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'predict',  class: 'ChatOpenAI',              type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'stream',   class: 'ChatOpenAI',              type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'generate', class: 'ChatOpenAI',              type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'invoke',   class: 'ChatAnthropic',           type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'invoke',   class: 'ChatGoogleGenerativeAI',  type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'run',      class: 'LLMChain',                type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },
  { method: 'invoke',   class: 'LLMChain',                type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['python'] },

  // --- JS/TS: openai node SDK ---------------------------------------------
  { method: 'create',  class: 'Completions', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'create',  class: 'Responses',   type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },

  // --- JS/TS: @anthropic-ai/sdk -------------------------------------------
  { method: 'create',  class: 'Messages',    type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'stream',  class: 'Messages',    type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },

  // --- JS/TS: Vercel AI SDK (bare functions from the `ai` package) --------
  // generateText/streamText/generateObject take a single options object;
  // taint reaches the sink when a tainted variable flows into any property.
  { method: 'generateText',   type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'streamText',     type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'generateObject', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'streamObject',   type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // --- JS/TS: langchain.js ------------------------------------------------
  { method: 'invoke', class: 'ChatOpenAI',    type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'invoke', class: 'ChatAnthropic', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'stream', class: 'ChatOpenAI',    type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['javascript', 'typescript'] },

  // --- Java: LangChain4j --------------------------------------------------
  { method: 'generate', class: 'ChatLanguageModel',          type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'chat',     class: 'ChatLanguageModel',          type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'generate', class: 'StreamingChatLanguageModel', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'chat',     class: 'StreamingChatLanguageModel', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },

  // --- Java: Spring AI ----------------------------------------------------
  { method: 'prompt', class: 'ChatClient', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'call',   class: 'ChatClient', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'call',   class: 'ChatModel',  type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },

  // --- Java: OpenAI Java SDK (theokanning) --------------------------------
  { method: 'createChatCompletion', class: 'OpenAiService', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },
  { method: 'createCompletion',     class: 'OpenAiService', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['java'] },

  // --- Go: go-openai (sashabaranov/go-openai) -----------------------------
  { method: 'CreateChatCompletion', class: 'Client', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['go'] },
  { method: 'CreateCompletion',     class: 'Client', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['go'] },
  { method: 'CreateChatCompletionStream', class: 'Client', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['go'] },

  // --- Go: langchaingo ----------------------------------------------------
  { method: 'Call',     class: 'LLM', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['go'] },
  { method: 'Generate', class: 'LLM', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['go'] },
  { method: 'GenerateContent', class: 'Model', type: 'prompt_injection', cwe: 'CWE-1427', severity: 'high', arg_positions: [0, 1, 2, 3], languages: ['go'] },

  // cognium-dev #240 ship 1 — extended framework sinks for open_redirect
  // (CWE-601) and trust_boundary (CWE-501). Definitions extracted above
  // as OPEN_REDIRECT_FRAMEWORK_SINKS / TRUST_BOUNDARY_FRAMEWORK_SINKS to
  // keep the DEFAULT_SINKS literal within TypeScript's union-type
  // inference complexity limit (TS2590). See ~lines 661-752.
  ...OPEN_REDIRECT_FRAMEWORK_SINKS,
  ...TRUST_BOUNDARY_FRAMEWORK_SINKS,
  // cognium-dev #240 ship 2 — extended framework sinks for
  // deserialization (CWE-502) and nosql_injection (CWE-943). Same
  // pattern: constants defined near the ship-1 blocks and spread here.
  ...DESERIALIZATION_FRAMEWORK_SINKS,
  ...NOSQL_FRAMEWORK_SINKS,
];

export const DEFAULT_SANITIZERS: SanitizerPattern[] = [
  // SQL Injection - proper parameter binding sanitizes input
  // Note: prepareStatement alone is NOT a sanitizer - it's a sink when used with concatenation
  { method: 'setString', class: 'PreparedStatement', removes: ['sql_injection'] },
  { method: 'setInt', class: 'PreparedStatement', removes: ['sql_injection'] },
  { method: 'setLong', class: 'PreparedStatement', removes: ['sql_injection'] },
  { method: 'setParameter', class: 'Query', removes: ['sql_injection'] },
  { annotation: 'Param', removes: ['sql_injection'] },

  // XSS
  { method: 'escapeHtml', removes: ['xss'] },
  { method: 'encodeForHTML', removes: ['xss'] },
  { method: 'escapeXml', removes: ['xss'] },
  { method: 'htmlEscape', removes: ['xss'] },
  { method: 'escapeHtml4', removes: ['xss'] },  // Apache Commons StringEscapeUtils
  { method: 'escapeHtml3', removes: ['xss'] },  // Apache Commons StringEscapeUtils
  { method: 'htmlSpecialChars', removes: ['xss'] },  // PHP-style / common wrapper
  { method: 'forHtml', class: 'Encode', removes: ['xss'] },  // OWASP Java Encoder
  { method: 'forHtmlContent', class: 'Encode', removes: ['xss'] },
  { method: 'forHtmlAttribute', class: 'Encode', removes: ['xss'] },
  { method: 'forJavaScript', class: 'Encode', removes: ['xss'] },
  { method: 'encode_text', removes: ['xss'] },  // Rust html_escape crate
  { method: 'encode_safe', removes: ['xss'] },  // Rust html_escape crate
  { method: 'render', class: 'Template', removes: ['xss'] },  // Rust askama auto-escapes
  { method: 'encodeForJavaScript', removes: ['xss'] },
  { method: 'encodeForCSS', removes: ['xss'] },
  // cognium-dev #249 3.162.0: `open_redirect` restored to the URL-encoder
  // sanitizer cluster. Sprint 82 (#189) reclassified `sendRedirect` from
  // `ssrf` → `open_redirect` (config-loader.ts:1296-1299) without updating
  // this table; the drift surfaced as a SecuriBench Micro FP on
  // `sanitizers/Sanitizers3.java` (`URLEncoder.encode` + `sendRedirect`).
  { method: 'encodeForURL', removes: ['xss', 'ssrf', 'open_redirect'] },
  // URL encoding wrapper aliases (common patterns in benchmarks and real-world code)
  { method: 'encodeURL', removes: ['xss', 'ssrf', 'open_redirect'] },
  { method: 'urlEncode', removes: ['xss', 'ssrf', 'open_redirect'] },
  { method: 'escapeUrl', removes: ['xss', 'ssrf', 'open_redirect'] },
  { method: 'escapeURL', removes: ['xss', 'ssrf', 'open_redirect'] },

  // Path Traversal
  { method: 'normalize', class: 'Path', removes: ['path_traversal'] },
  { method: 'getCanonicalPath', class: 'File', removes: ['path_traversal'] },
  { method: 'toRealPath', class: 'Path', removes: ['path_traversal'] },
  // Rust path sanitizers
  { method: 'file_name', removes: ['path_traversal'] },  // Returns just filename, strips path
  { method: 'canonicalize', removes: ['path_traversal'] },  // Resolves symlinks and normalizes
  // Go path sanitizers (#51) — filepath.Base strips directory components
  // (fully sanitizes), filepath.Clean / path.Clean normalize away ../ segments
  // (defense-in-depth — mirrors Java getCanonicalPath in this table; the
  // stricter Clean+HasPrefix guard recognition is tracked separately).
  // EvalSymlinks is the Go equivalent of Java's Path.toRealPath.
  // Sprint 24 (#102 FP-27): broadened to cover external_taint_escape (CWE-668)
  // fallback so canonicalised paths don't trigger the synthetic sink.
  { method: 'Base', class: 'filepath', removes: ['path_traversal', 'external_taint_escape'] },
  { method: 'Base', class: 'path', removes: ['path_traversal', 'external_taint_escape'] },
  { method: 'Clean', class: 'filepath', removes: ['path_traversal', 'external_taint_escape'] },
  { method: 'Clean', class: 'path', removes: ['path_traversal', 'external_taint_escape'] },
  { method: 'EvalSymlinks', class: 'filepath', removes: ['path_traversal', 'external_taint_escape'] },

  // Go html/template escape helpers (#102 FP-27) — registered explicitly because
  // configs/sinks/golang.json is not loaded at runtime.
  { method: 'EscapeString', class: 'html', removes: ['xss', 'external_taint_escape', 'log_injection', 'open_redirect'] },
  { method: 'HTMLEscapeString', class: 'template', removes: ['xss', 'external_taint_escape', 'log_injection', 'open_redirect'] },
  { method: 'JSEscapeString', class: 'template', removes: ['xss', 'external_taint_escape', 'log_injection'] },
  { method: 'URLQueryEscaper', class: 'template', removes: ['xss', 'external_taint_escape', 'open_redirect'] },
  { method: 'QueryEscape', class: 'url', removes: ['xss', 'external_taint_escape', 'open_redirect'] },
  { method: 'PathEscape', class: 'url', removes: ['xss', 'external_taint_escape', 'open_redirect'] },

  // Log Injection sanitizers
  { method: 'replace', removes: ['log_injection'] },  // Used to remove newlines/control chars

  // LDAP Injection
  { method: 'encodeForLDAP', removes: ['ldap_injection'] },
  { method: 'encodeForDN', removes: ['ldap_injection'] },
  { method: 'escapeLDAPSearchFilter', removes: ['ldap_injection'] },

  // XPath Injection
  { method: 'compile', class: 'XPathFactory', removes: ['xpath_injection'] },

  // XXE
  { method: 'setFeature', class: 'DocumentBuilderFactory', removes: ['xxe'] },
  { method: 'setFeature', class: 'SAXParserFactory', removes: ['xxe'] },
  { method: 'setFeature', class: 'XMLReader', removes: ['xxe'] },
  { method: 'setProperty', class: 'XMLReader', removes: ['xxe'] },

  // SSRF / URL encoding
  // cognium-dev #249 3.162.0: `open_redirect` added — see rationale on the
  // `encodeForURL` cluster above. `java.net.URLEncoder.encode` is the specific
  // sanitizer used by SecuriBench Micro `sanitizers/Sanitizers3.java` before
  // `HttpServletResponse.sendRedirect` (Sprint 82 CWE-601 sink).
  { method: 'encode', class: 'URLEncoder', removes: ['ssrf', 'xss', 'path_traversal', 'open_redirect'] },
  { method: 'validateURL', removes: ['ssrf'] },
  { method: 'isAllowedHost', removes: ['ssrf'] },
  { method: 'isInternalHost', removes: ['ssrf'] },

  // Command Injection
  { method: 'escapeshellarg', removes: ['command_injection'] },
  { method: 'escapeshellcmd', removes: ['command_injection'] },

  // Deserialization
  { method: 'setObjectInputFilter', class: 'ObjectInputStream', removes: ['deserialization'] },

  // Regex consumption — passing tainted text to a compiled `Pattern.matcher()`
  // does not constitute a wrong-sphere escape: the matcher walks the string
  // in-process and produces match-state (booleans, captured groups, counts),
  // not a network/file/process exit. Class-agnostic so it covers receivers
  // that are Pattern-typed variables (e.g. `DIGITS.matcher(text)`). Sprint 60
  // (#113 FP-52). Note: this only suppresses the synthetic CWE-668 fallback;
  // real injection sinks downstream of the matched text still apply.
  { method: 'matcher', removes: ['external_taint_escape'] },

  // =========================================================================
  // Node.js / JavaScript Sanitizers
  // =========================================================================

  // XSS - encoding/escaping
  { method: 'encodeURIComponent', removes: ['xss', 'ssrf', 'path_traversal'] },
  { method: 'encodeURI', removes: ['xss', 'ssrf'] },
  { method: 'escape', removes: ['xss'] },
  { method: 'sanitize', removes: ['xss', 'sql_injection', 'nosql_injection'] },

  // DOMPurify and similar
  { method: 'sanitize', class: 'DOMPurify', removes: ['xss'] },
  { method: 'escape', class: 'validator', removes: ['xss'] },

  // JSON.parse (data is validated against JSON grammar, prevents XSS/code injection)
  { method: 'parse', class: 'JSON', removes: ['xss', 'code_injection'] },

  // Type coercion (removes string-based injections)
  // Sprint 29 (#113): include external_taint_escape — a numeric cast cannot
  // carry an unvalidated string payload across a function boundary.
  { method: 'parseInt', removes: ['sql_injection', 'nosql_injection', 'command_injection', 'xss', 'external_taint_escape', 'path_traversal', 'code_injection'] },
  { method: 'parseFloat', removes: ['sql_injection', 'nosql_injection', 'command_injection', 'external_taint_escape', 'path_traversal', 'code_injection'] },
  { method: 'Number', removes: ['sql_injection', 'nosql_injection', 'command_injection', 'external_taint_escape', 'path_traversal', 'code_injection'] },

  // Sprint 29 (#113): bounds-clamp Math.min / Math.max — when used to bound
  // a numeric/size value (e.g. `Math.min(size, MAX_BYTES)`), the result is
  // safely bounded and cannot resource-exhaust downstream. Only suppress
  // external_taint_escape — these helpers do NOT sanitize string injection.
  { method: 'min', class: 'Math', removes: ['external_taint_escape'] },
  { method: 'max', class: 'Math', removes: ['external_taint_escape'] },

  // Sprint 29 (#113): allow-list / membership guards — when an external value
  // is tested against an allow-list (`ALLOWED.includes(x)`, `set.has(x)`,
  // `list.contains(x)`) before being forwarded, it cannot escape unbounded.
  // Only suppress `external_taint_escape`; real string-injection sinks should
  // still rely on their own escaping.
  { method: 'includes', removes: ['external_taint_escape'] },
  { method: 'has', removes: ['external_taint_escape'] },
  { method: 'contains', removes: ['external_taint_escape'] },
  { method: 'indexOf', removes: ['external_taint_escape'] },

  // Path sanitization
  // Sprint 60 (#113 FP-46): include external_taint_escape — `path.basename()`
  // strips directory components and returns only the leaf filename, so a
  // tainted-but-basenamed value can no longer carry a traversal payload into
  // a downstream `fs.open*` / `fs.write*` call. Mirrors Go `filepath.Base`
  // (line 2187) which already includes external_taint_escape.
  { method: 'basename', class: 'path', removes: ['path_traversal', 'external_taint_escape'] },
  { method: 'normalize', class: 'path', removes: ['path_traversal'] },
  { method: 'resolve', class: 'path', removes: ['path_traversal'] },

  // SQL - parameterized queries (mysql, pg)
  { method: 'escape', class: 'mysql', removes: ['sql_injection'] },
  { method: 'escapeId', class: 'mysql', removes: ['sql_injection'] },
  { method: 'format', class: 'mysql', removes: ['sql_injection'] },

  // MongoDB - sanitization
  { method: 'sanitize', class: 'mongo', removes: ['nosql_injection'] },
  { method: 'escape', class: 'mongo', removes: ['nosql_injection'] },

  // Command injection - shell escaping
  { method: 'quote', class: 'shell', removes: ['command_injection'] },
  { method: 'escape', class: 'shell-escape', removes: ['command_injection'] },

  // =========================================================================
  // Python Sanitizers
  // =========================================================================

  // Python XSS
  { method: 'escape', class: 'markupsafe', removes: ['xss'] },
  { method: 'escape', class: 'html', removes: ['xss'] },
  { method: 'escape', class: 'cgi', removes: ['xss'] },
  { method: 'bleach', class: 'clean', removes: ['xss'] },
  { method: 'clean', class: 'bleach', removes: ['xss'] },

  // Python Command Injection
  { method: 'quote', class: 'shlex', removes: ['command_injection'] },
  { method: 'split', class: 'shlex', removes: ['command_injection'] },

  // Python Deserialization
  { method: 'safe_load', class: 'yaml', removes: ['deserialization'] },
  { method: 'safe_dump', class: 'yaml', removes: ['deserialization'] },

  // Python SQL - parameterized queries
  { method: 'mogrify', removes: ['sql_injection'] },
  { method: 'literal', class: 'MySQLdb', removes: ['sql_injection'] },

  // Python NoSQL
  { method: 'ObjectId', class: 'bson', removes: ['nosql_injection'] },

  // Python LDAP
  { method: 'filter_format', class: 'ldap', removes: ['ldap_injection'] },
  { method: 'escape_filter_chars', class: 'ldap', removes: ['ldap_injection'] },

  // Python XPath
  { method: 'escape', class: 'xpath', removes: ['xpath_injection'] },

  // Python XXE safe parsers
  { method: 'defusedxml', removes: ['xxe'] },
  { method: 'parse', class: 'defusedxml', removes: ['xxe'] },

  // Python Path Traversal
  { method: 'secure_filename', class: 'werkzeug.utils', removes: ['path_traversal'] },
  { method: 'basename', class: 'os.path', removes: ['path_traversal'] },
  { method: 'normpath', class: 'os.path', removes: ['path_traversal'] },
  // Issue #48 part 2: realpath/abspath are canonical Python path-canonicalization
  // functions (analogous to Java File.getCanonicalPath). Register on both
  // `os.path` and the bare `path` receiver to cover `import os.path as path`.
  { method: 'realpath', class: 'os.path', removes: ['path_traversal'] },
  { method: 'abspath', class: 'os.path', removes: ['path_traversal'] },
  { method: 'realpath', class: 'path', removes: ['path_traversal'] },
  { method: 'abspath', class: 'path', removes: ['path_traversal'] },
  // pathlib.Path.resolve() — canonicalizes path, resolves symlinks (Python 3)
  { method: 'resolve', class: 'Path', removes: ['path_traversal'] },

  // Python Type coercion
  { method: 'int', removes: ['sql_injection', 'command_injection', 'xss'] },
  { method: 'float', removes: ['sql_injection', 'command_injection'] },

  // =========================================================================
  // Rust Sanitizers
  // =========================================================================

  // Rust SQL - sqlx query! macro is compile-time checked (parameterized)
  { method: 'query!', removes: ['sql_injection'] },
  { method: 'query_as!', removes: ['sql_injection'] },
  { method: 'query_scalar!', removes: ['sql_injection'] },
  { method: 'query_unchecked!', removes: ['sql_injection'] },
  // Diesel DSL (type-safe query builder)
  { method: 'filter', class: 'diesel', removes: ['sql_injection'] },
  { method: 'eq', class: 'diesel', removes: ['sql_injection'] },

  // Rust Path Traversal - basename/file_name extracts just the filename
  { method: 'file_name', removes: ['path_traversal'] },
  { method: 'file_stem', removes: ['path_traversal'] },
  { method: 'extension', removes: ['path_traversal'] },
  { method: 'canonicalize', removes: ['path_traversal'] },  // Resolves symlinks, validates path exists

  // Rust Command Injection - allowlist validation
  { method: 'contains', removes: ['command_injection', 'ssrf', 'open_redirect'] },  // Used for allowlist checks
  { method: 'starts_with', removes: ['path_traversal', 'ssrf', 'open_redirect'] },  // Path/URL prefix validation
  { method: 'ends_with', removes: ['path_traversal', 'open_redirect'] },

  // Rust XSS - HTML escaping
  { method: 'escape', class: 'html_escape', removes: ['xss'] },
  { method: 'encode_text', class: 'html_escape', removes: ['xss'] },
  { method: 'encode_attribute', class: 'html_escape', removes: ['xss'] },
  { method: 'escape_html', removes: ['xss'] },

  // Rust Type coercion (parsing)
  { method: 'parse', removes: ['sql_injection', 'command_injection', 'xss'] },  // str.parse::<i32>()

  // =========================================================================
  // Type-cast taint barriers (#57)
  // Numeric/UUID casts cannot carry a string-injection payload.
  // =========================================================================

  // Java numeric parse — Integer.parseInt, Long.parseLong, etc.
  { method: 'parseInt', class: 'Integer', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'parseLong', class: 'Long', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'parseFloat', class: 'Float', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'parseDouble', class: 'Double', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'parseShort', class: 'Short', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'parseByte', class: 'Byte', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  // cognium-dev #238 A.3 — parseBoolean and expanded coercion coverage for XSS/CRLF/log/xpath/ldap/xxe.
  // A parsed boolean/numeric cannot carry a string-injection payload for any string-based sink.
  { method: 'parseBoolean', class: 'Boolean', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection', 'xss', 'crlf', 'log_injection', 'xpath_injection', 'ldap_injection', 'xxe'] },
  // Java UUID parse — UUID.fromString rejects non-UUID strings
  { method: 'fromString', class: 'UUID', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },

  // JavaScript numeric coercion (Number/parseInt/parseFloat already covered above; add path_traversal/code_injection)
  { method: 'BigInt', removes: ['sql_injection', 'nosql_injection', 'command_injection', 'path_traversal', 'code_injection'] },

  // Go numeric parse — strconv.Atoi, ParseInt, ParseFloat, ParseUint, ParseBool
  { method: 'Atoi', class: 'strconv', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'ParseInt', class: 'strconv', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'ParseFloat', class: 'strconv', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'ParseUint', class: 'strconv', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'ParseBool', class: 'strconv', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  // Go UUID parse
  { method: 'Parse', class: 'uuid', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'MustParse', class: 'uuid', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },

  // Python — int/float already covered above; add bool + UUID/Decimal casts
  { method: 'bool', removes: ['sql_injection', 'command_injection', 'xss', 'code_injection'] },
  { method: 'UUID', class: 'uuid', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },
  { method: 'Decimal', class: 'decimal', removes: ['sql_injection', 'command_injection', 'path_traversal', 'code_injection'] },

  // =========================================================================
  // Cipher output taint barriers (#239 C4 residual)
  // Symmetric/AEAD cipher output is high-entropy ciphertext bytes. The
  // encoded form (hex / base64) cannot carry a text-injection payload:
  // an attacker would need the plaintext to encrypt to a valid HTML /
  // SQL / shell / path token, which is not achievable against a keyed
  // block cipher. Applies to Node.js crypto.Cipher / Java javax.crypto.Cipher
  // (both expose .update() and .final() / .doFinal()) — receiver-name
  // heuristic in receiverMightBeClass() matches conventional `cipher`
  // variable names as well as typed Cipher receivers.
  // =========================================================================
  { method: 'update', class: 'Cipher', removes: ['xss', 'sql_injection', 'command_injection', 'path_traversal', 'code_injection', 'crlf', 'log_injection', 'ldap_injection', 'xpath_injection'] },
  { method: 'final', class: 'Cipher', removes: ['xss', 'sql_injection', 'command_injection', 'path_traversal', 'code_injection', 'crlf', 'log_injection', 'ldap_injection', 'xpath_injection'] },
  { method: 'doFinal', class: 'Cipher', removes: ['xss', 'sql_injection', 'command_injection', 'path_traversal', 'code_injection', 'crlf', 'log_injection', 'ldap_injection', 'xpath_injection'] },
];

/**
 * Embedded default sink-semantics registry (cognium-dev #139 Tier A).
 * Mirrors `configs/sink-semantics.json` so the default gate is active
 * in browser/Node.js callers that never call `createTaintConfig`.
 *
 * Each entry maps a `<ClassName>#<methodName>` receiver signature to
 * the `SinkType` labels that should be dropped when the taint-matcher
 * emits that signature with a mismatched label. Class match is
 * simple-name and case-sensitive against `TaintSink.class`.
 */
export const DEFAULT_SINK_SEMANTICS: SinkSemanticsEntry[] = [
  {
    signature: 'Jedis#executeCommand',
    real_class: 'db_protocol',
    overrides: ['command_injection', 'code_injection'],
    note: 'Redis wire-protocol serialization, not OS exec',
  },
  {
    signature: 'Connection#executeCommand',
    real_class: 'db_protocol',
    overrides: ['command_injection', 'code_injection'],
    note: 'Jedis abstract Connection base',
  },
  {
    signature: 'JedisCluster#executeCommand',
    real_class: 'db_protocol',
    overrides: ['command_injection', 'code_injection'],
    note: 'Jedis cluster client',
  },
  {
    signature: 'Func1#exec',
    real_class: 'functional_dispatch',
    overrides: ['command_injection', 'code_injection'],
    note: 'RxJava functional dispatch, not OS exec',
  },
  {
    signature: 'Action0#call',
    real_class: 'functional_dispatch',
    overrides: ['command_injection'],
    note: 'RxJava Action0 dispatch',
  },
  {
    signature: 'Action1#call',
    real_class: 'functional_dispatch',
    overrides: ['command_injection'],
    note: 'RxJava Action1 dispatch',
  },
  {
    signature: 'Unsafe#defineAnonymousClass',
    real_class: 'jdk_internal',
    overrides: ['code_injection'],
    note: 'sun.misc.Unsafe JDK-internal reflective bridge',
  },
  {
    signature: 'MethodHandle#invokeExact',
    real_class: 'jdk_internal',
    overrides: ['code_injection'],
    note: 'java.lang.invoke.MethodHandle — JDK-internal',
  },
];

/**
 * Get the default taint configuration.
 */
export function getDefaultConfig(): TaintConfig {
  return {
    sources: DEFAULT_SOURCES,
    sinks: DEFAULT_SINKS,
    sanitizers: DEFAULT_SANITIZERS,
    sinkSemantics: DEFAULT_SINK_SEMANTICS,
  };
}

// ============================================================================
// Security Headers Rules (consumed by SecurityHeadersPass)
// ============================================================================

/**
 * Default rule table for HTTP response security headers. Each rule is
 * evaluated against setHeader/addHeader calls and (for kind='missing')
 * against the absence of any such call on handler files.
 *
 * Covers clickjacking (CWE-1021) and CORS misconfiguration (CWE-346 /
 * CWE-942). Adding a new rule here is enough to surface a finding — no
 * pass code changes required.
 */
export const DEFAULT_HEADER_RULES: HeaderRule[] = [
  // -------------------------------------------------------------------------
  // Clickjacking (CWE-1021)
  // -------------------------------------------------------------------------

  {
    rule_id: 'missing-x-frame-options',
    cwe: 'CWE-1021',
    level: 'warning',
    severity: 'medium',
    header: 'X-Frame-Options',
    kind: 'missing',
    requiresHandler: true,
    message: 'HTTP handler does not set X-Frame-Options — vulnerable to clickjacking',
    fix: "Set response.setHeader('X-Frame-Options', 'DENY') or use a CSP frame-ancestors directive",
    note: 'Defense against UI redress / clickjacking attacks',
  },

  {
    rule_id: 'x-frame-options-allow-from',
    cwe: 'CWE-1021',
    level: 'warning',
    severity: 'medium',
    header: 'X-Frame-Options',
    kind: 'weak-value',
    valuePattern: /^allow-from\b/i,
    message: 'X-Frame-Options: ALLOW-FROM is deprecated and unsupported by modern browsers',
    fix: "Use CSP frame-ancestors directive instead: Content-Security-Policy: frame-ancestors 'self'",
  },

  {
    rule_id: 'missing-csp-frame-ancestors',
    cwe: 'CWE-1021',
    level: 'note',
    severity: 'low',
    header: 'Content-Security-Policy',
    kind: 'missing',
    requiresHandler: true,
    message: 'HTTP handler does not set Content-Security-Policy — frame-ancestors unset',
    fix: "Set Content-Security-Policy: frame-ancestors 'self' for defense-in-depth clickjacking protection",
    note: 'Informational; paired with missing-x-frame-options',
  },

  // -------------------------------------------------------------------------
  // CORS Misconfiguration (CWE-346, CWE-942)
  // -------------------------------------------------------------------------

  {
    rule_id: 'cors-wildcard-origin',
    cwe: 'CWE-942',
    level: 'error',
    severity: 'high',
    header: 'Access-Control-Allow-Origin',
    kind: 'weak-value',
    valuePattern: /^\*$/,
    message: "Access-Control-Allow-Origin: '*' permits cross-origin requests from any site",
    fix: 'Restrict to a specific trusted origin or use an allowlist',
  },

  {
    rule_id: 'cors-null-origin',
    cwe: 'CWE-346',
    level: 'error',
    severity: 'high',
    header: 'Access-Control-Allow-Origin',
    kind: 'weak-value',
    valuePattern: /^null$/i,
    message: "Access-Control-Allow-Origin: 'null' is exploitable via sandboxed iframes and data: URIs",
    fix: 'Restrict to a specific trusted origin',
  },

  {
    rule_id: 'cors-http-origin',
    cwe: 'CWE-346',
    level: 'warning',
    severity: 'medium',
    header: 'Access-Control-Allow-Origin',
    kind: 'weak-value',
    valuePattern: /^http:\/\//i,
    message: 'Access-Control-Allow-Origin uses insecure http:// scheme',
    fix: 'Use https:// for the allowed origin',
  },

  {
    rule_id: 'cors-reflected-origin',
    cwe: 'CWE-346',
    level: 'error',
    severity: 'high',
    header: 'Access-Control-Allow-Origin',
    kind: 'unsafe-value',
    message: 'Access-Control-Allow-Origin set to a dynamic value — possible origin reflection',
    fix: 'Validate the Origin request header against an allowlist before echoing it back',
    note: 'Fires when the value is not a string literal (likely reflected from request)',
  },
];
