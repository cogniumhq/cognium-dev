/**
 * Configuration loader for taint source/sink definitions
 *
 * Loads YAML configs from configs/sources/ and configs/sinks/
 */

import type {
  SourceConfig,
  SinkConfig,
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
 * Create a combined taint configuration from raw config contents.
 */
export function createTaintConfig(
  sourceContents: string[],
  sinkContents: string[]
): TaintConfig {
  const sourceConfigs = sourceContents.map((c) => parseConfig<SourceConfig>(c));
  const sinkConfigs = sinkContents.map((c) => parseConfig<SinkConfig>(c));

  const sources = loadSourceConfigs(sourceConfigs);
  const { sinks, sanitizers } = loadSinkConfigs(sinkConfigs);

  return { sources, sinks, sanitizers };
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
  { property: 'path', object: 'request', type: 'http_path', severity: 'medium', property_tainted: true },
  { property: 'query_string', object: 'request', type: 'http_query', severity: 'high', property_tainted: true },

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

  // Axum extractors
  { method: 'Json', type: 'http_body', severity: 'high', return_tainted: true },
  { method: 'Query', type: 'http_param', severity: 'high', return_tainted: true },
  { method: 'Path', type: 'http_path', severity: 'high', return_tainted: true },
  { method: 'Form', type: 'http_param', severity: 'high', return_tainted: true },

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

  // Shell/Bash utilities
  { method: 'bash', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'shell', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'sh', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'spawn', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'fork', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'popen', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'system', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Apache Commons Exec
  // Note: bare class 'Executor' removed (see comment above) — DefaultExecutor matched explicitly.
  { method: 'setCommandline', class: 'DefaultExecutor', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'parse', class: 'CommandLine', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'addArgument', class: 'CommandLine', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },

  // Process-related utilities
  { method: 'waitFor', class: 'Process', type: 'command_injection', cwe: 'CWE-78', severity: 'medium', arg_positions: [] },
  { method: 'inheritIO', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'medium', arg_positions: [] },
  { method: 'redirectOutput', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'medium', arg_positions: [0] },
  { method: 'redirectInput', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'medium', arg_positions: [0] },

  // Path Traversal (CWE-22)
  // File: covers both File(String pathname) and File(parent, child). The 2-arg
  // overload's child argument carries CVE-2018-8041 (Camel mail Content-Disposition
  // filename written to disk).
  { method: 'File', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0, 1] },
  { method: 'FileInputStream', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileOutputStream', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileReader', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'FileWriter', class: 'constructor', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  // ClassLoader/Class resource loading (can be abused for path traversal)
  { method: 'getResource', class: 'ClassLoader', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getResourceAsStream', class: 'ClassLoader', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getResource', class: 'Class', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'getResourceAsStream', class: 'Class', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
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
  { method: 'exists', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  { method: 'isDirectory', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
  { method: 'isRegularFile', class: 'Files', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
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
  { method: 'resolve', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'resolve', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'resolveSibling', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'high', arg_positions: [0] },
  { method: 'relativize', class: 'Path', type: 'path_traversal', cwe: 'CWE-22', severity: 'medium', arg_positions: [0] },
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
  { method: 'write', type: 'xss', cwe: 'CWE-79', severity: 'medium', arg_positions: [0] },
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
  { method: 'compile', class: 'Pattern', type: 'code_injection', cwe: 'CWE-94', severity: 'high', arg_positions: [0] },
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
  { method: 'sendRedirect', class: 'HttpServletResponse', type: 'ssrf', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
  { method: 'sendRedirect', type: 'ssrf', cwe: 'CWE-601', severity: 'high', arg_positions: [0] },
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

  // Trust Boundary (CWE-501) - using untrusted data as session attribute NAME
  // The vulnerability is attacker controlling which key to use, not the value
  { method: 'setAttribute', class: 'HttpSession', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0] },
  { method: 'putValue', class: 'HttpSession', type: 'trust_boundary', cwe: 'CWE-501', severity: 'medium', arg_positions: [0] },

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
  { method: 'query', class: 'Connection', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'query', class: 'Pool', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  { method: 'query', class: 'Client', type: 'sql_injection', cwe: 'CWE-89', severity: 'critical', arg_positions: [0], languages: ['javascript', 'typescript'] },
  // Note: classless { method: 'query' } removed — too many FPs (UriComponentsBuilder.query(), etc.)
  // SQL query calls are covered by class-specific patterns above (Connection, Pool, Client, JdbcTemplate)
  // Note: `raw` is shared with Python (Django ORM) — scoped to JS+TS to avoid leaking.
  { method: 'raw', type: 'sql_injection', cwe: 'CWE-89', severity: 'high', arg_positions: [0], languages: ['javascript', 'typescript'] },

  // Browser DOM XSS sinks
  { method: 'setAttribute', type: 'xss', cwe: 'CWE-79', severity: 'high', arg_positions: [1] },

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

  // Python Template Injection (Jinja2, Mako)
  { method: 'from_string', class: 'Template', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'Template', class: 'jinja2', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },
  { method: 'Template', class: 'mako', type: 'code_injection', cwe: 'CWE-94', severity: 'critical', arg_positions: [0] },

  // Python Log Injection
  { method: 'info', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0] },
  { method: 'warning', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0] },
  { method: 'error', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0] },
  { method: 'debug', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0] },
  { method: 'critical', class: 'logger', type: 'log_injection', cwe: 'CWE-117', severity: 'low', arg_positions: [0] },

  // =========================================================================
  // Java CWE-Bench Enhancement Patterns (Collection/Builder)
  // =========================================================================

  // Collection-based command injection (ProcessBuilder with List)
  { method: 'command', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [0] },
  { method: 'inheritIO', class: 'ProcessBuilder', type: 'command_injection', cwe: 'CWE-78', severity: 'critical', arg_positions: [] },

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
  { method: 'Redirect', type: 'open_redirect', cwe: 'CWE-601', severity: 'medium', arg_positions: [0] },
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

  // Mass-assignment (CWE-915) — Sprint 6, #86.
  // JS Object.assign(target, ...sources) — sources are arg 1..N, and if any
  // source is request-tainted, every key gets written onto the target. We
  // flag the source positions; the analyzer only needs one tainted to fire.
  { method: 'assign', class: 'Object', type: 'mass_assignment', cwe: 'CWE-915', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  // Lodash bulk-merge helpers behave identically.
  { method: 'merge',  class: '_',      type: 'mass_assignment', cwe: 'CWE-915', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  { method: 'extend', class: '_',      type: 'mass_assignment', cwe: 'CWE-915', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
  // jQuery $.extend(target, source) (legacy).
  { method: 'extend', class: '$',      type: 'mass_assignment', cwe: 'CWE-915', severity: 'high', arg_positions: [1, 2, 3], languages: ['javascript', 'typescript'] },
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
  { method: 'encodeForURL', removes: ['xss', 'ssrf'] },
  // URL encoding wrapper aliases (common patterns in benchmarks and real-world code)
  { method: 'encodeURL', removes: ['xss', 'ssrf'] },
  { method: 'urlEncode', removes: ['xss', 'ssrf'] },
  { method: 'escapeUrl', removes: ['xss', 'ssrf'] },
  { method: 'escapeURL', removes: ['xss', 'ssrf'] },

  // Path Traversal
  { method: 'normalize', class: 'Path', removes: ['path_traversal'] },
  { method: 'getCanonicalPath', class: 'File', removes: ['path_traversal'] },
  { method: 'toRealPath', class: 'Path', removes: ['path_traversal'] },
  // Rust path sanitizers
  { method: 'file_name', removes: ['path_traversal'] },  // Returns just filename, strips path
  { method: 'canonicalize', removes: ['path_traversal'] },  // Resolves symlinks and normalizes

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
  { method: 'encode', class: 'URLEncoder', removes: ['ssrf', 'xss', 'path_traversal'] },
  { method: 'validateURL', removes: ['ssrf'] },
  { method: 'isAllowedHost', removes: ['ssrf'] },
  { method: 'isInternalHost', removes: ['ssrf'] },

  // Command Injection
  { method: 'escapeshellarg', removes: ['command_injection'] },
  { method: 'escapeshellcmd', removes: ['command_injection'] },

  // Deserialization
  { method: 'setObjectInputFilter', class: 'ObjectInputStream', removes: ['deserialization'] },

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
  { method: 'parseInt', removes: ['sql_injection', 'nosql_injection', 'command_injection', 'xss'] },
  { method: 'parseFloat', removes: ['sql_injection', 'nosql_injection', 'command_injection'] },
  { method: 'Number', removes: ['sql_injection', 'nosql_injection', 'command_injection'] },

  // Path sanitization
  { method: 'basename', class: 'path', removes: ['path_traversal'] },
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
];

/**
 * Get the default taint configuration.
 */
export function getDefaultConfig(): TaintConfig {
  return {
    sources: DEFAULT_SOURCES,
    sinks: DEFAULT_SINKS,
    sanitizers: DEFAULT_SANITIZERS,
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
