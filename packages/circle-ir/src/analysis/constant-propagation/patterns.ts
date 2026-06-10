/**
 * Taint source patterns, sanitizer methods, and propagator methods.
 */

// =============================================================================
// Taint Source Patterns
// =============================================================================

export const TAINT_PATTERNS = [
  // HTTP Sources (Servlet API)
  'request.getParameter',
  'request.getHeader',
  'request.getHeaders',
  'request.getCookies',
  'request.getInputStream',
  'request.getQueryString',
  'request.getPathInfo',
  'request.getRequestURI',
  'request.getParameterMap',
  'request.getReader',
  '.getParameter(',
  '.getParameterValues(',
  '.getParameterMap(',
  '.getHeader(',
  '.getHeaders(',
  '.getValue(',  // Cookie.getValue()
  '.getCookies(',
  '.getReader(',

  // Enumeration iteration (from request.getHeaders(), etc.)
  'headers.nextElement(',
  'names.nextElement(',
  '.nextElement(',

  // I/O Sources
  '.readLine(',
  '.readUTF(',
  '.nextLine(',
  '.next(',
  '.readPassword(',
  'System.getenv(',
  'System.getProperty(',
  '.getProperty(',

  // Network Sources
  'socket.getInputStream(',
  '.openStream(',

  // Database Sources
  '.getString(',
  '.getObject(',

  // File Sources
  'Files.readAllLines(',
  'Files.readString(',
  'Files.readAllBytes(',

  // JavaScript / Browser DOM Sources
  'location.hash',
  'location.search',
  'location.href',
  'location.pathname',
  'document.cookie',
  'document.referrer',
  'document.URL',
  'document.documentURI',
  'window.name',
  'window.status',
  'document.title',
  'history.state',
  'localStorage.getItem(',
  'sessionStorage.getItem(',
];

// Compile patterns into a single regex for faster matching
export const TAINT_PATTERN_REGEX = new RegExp(
  TAINT_PATTERNS.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')
);

// =============================================================================
// Sanitizer Methods
// =============================================================================

export const SANITIZER_METHODS = new Set([
  // ESAPI
  'encodeForHTML', 'encodeForHTMLAttribute', 'encodeForJavaScript',
  'encodeForCSS', 'encodeForURL', 'encodeForXML', 'encodeForXMLAttribute',
  'encodeForLDAP', 'encodeForDN', 'encodeForXPath', 'encodeForSQL',
  'encodeForOS', 'encodeForBase64', 'canonicalize',

  // OWASP Java Encoder
  'forHtml', 'forHtmlAttribute', 'forHtmlContent', 'forHtmlUnquotedAttribute',
  'forJavaScript', 'forJavaScriptBlock', 'forJavaScriptAttribute',
  'forJavaScriptSource', 'forCssString', 'forCssUrl', 'forUri', 'forUriComponent',
  'forXml', 'forXmlAttribute', 'forXmlContent', 'forXmlComment', 'forCDATA',

  // Apache Commons
  'escapeHtml', 'escapeHtml4', 'escapeHtml3', 'escapeXml', 'escapeXml10', 'escapeXml11',
  'escapeEcmaScript', 'escapeJson', 'escapeCsv', 'escapeJava', 'escapeSql',

  // Spring HtmlUtils
  'htmlEscape', 'htmlEscapeDecimal', 'htmlEscapeHex',

  // PreparedStatement
  'setString', 'setInt', 'setLong', 'setDouble', 'setFloat', 'setBoolean',
  'setDate', 'setTimestamp', 'setObject', 'setBytes', 'setBigDecimal',

  // Path Traversal Prevention
  'getCanonicalPath', 'normalize', 'toRealPath',

  // JavaScript/TypeScript URL Encoding
  'encodeURIComponent', 'encodeURI',

  // JavaScript/TypeScript String Validation
  'match', 'test', 'startsWith', 'includes',

  // Path Validation and Normalization
  'normalizePath', 'normalizeLineEndings', 'isPathWithin', 'isPathWithinAllowedDirectories',
  'isPathAllowed', 'resolve', 'relative', 'join',

  // General
  'sanitize', 'encode', 'escape', 'clean', 'filter', 'validate', 'validatePath',
  'validateCityName', 'validateInput', 'sanitizeInput',
]);

// =============================================================================
// Anti-Sanitizer Methods
// These methods REVERSE sanitization - calling them on sanitized input produces tainted output
// =============================================================================

export const ANTI_SANITIZER_METHODS = new Set([
  // URL decoding (reverses URL encoding)
  'decode',           // URLDecoder.decode()
  'decodeURIComponent',
  'decodeURI',

  // Base64 decoding (reverses base64 encoding)
  'decodeBase64',
  'decode',           // Base64.getDecoder().decode()

  // HTML unescaping (reverses HTML escaping)
  'unescapeHtml', 'unescapeHtml4', 'unescapeHtml3',
  'unescapeXml',
  'unescapeEcmaScript',
  'unescapeJson',
  'unescapeJava',

  // Apache Shiro WebUtils helpers (CVE-2023-34478, CVE-2023-46749 — issue #8).
  // These internally call URLDecoder.decode, so a value that passed a
  // string-level path sanitizer (e.g. Paths.normalize) becomes tainted again
  // after Shiro re-decodes %2e%2e → "..".
  'getPathWithinApplication',
  'getRequestUri',
  'decodeRequestString',

  // General decoders
  'unescape',
  'decompress',
]);

// =============================================================================
// Propagator Methods
// These static factory methods propagate taint from any argument to return value
// =============================================================================

export const PROPAGATOR_METHODS = new Set([
  // Path/File construction
  'get',            // Paths.get(string), Path.of(string)
  'of',             // Path.of(string), etc.
  'resolve',        // Path.resolve(other)
  'resolveSibling', // Path.resolveSibling(other)
  'relativize',     // Path.relativize(other)

  // URI/URL
  'create',         // URI.create(string)
  'toUri',          // File.toUri()
  'toURL',          // URI.toURL()
  'toPath',         // URI.toPath(), File.toPath()

  // String utilities
  'valueOf',        // String.valueOf(x)
  'format',         // String.format(...)
  'join',           // String.join(...)
  'concat',         // String.concat(other)

  // Object utilities
  'requireNonNull', // Objects.requireNonNull(obj)

  // Apache Shiro WebUtils — propagate taint from string arg through the wrapper
  // back into the return value (e.g. `WebUtils.decodeRequestString(req, tainted)`).
  // Also covered by ANTI_SANITIZER_METHODS for sanitized-arg re-tainting and by
  // configs/sources/http_sources.yaml for the request-bound overloads. Issue #8.
  'getPathWithinApplication',
  'getRequestUri',
  'decodeRequestString',
]);
