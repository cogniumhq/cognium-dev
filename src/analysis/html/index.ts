/**
 * HTML Analysis Module
 *
 * Provides web extraction preprocessing for HTML files:
 * - Script block and event handler extraction
 * - Attribute-level security checks
 * - Result merging for multi-script HTML files
 */

export {
  extractHtmlContent,
  type HtmlScriptBlock,
  type HtmlEventHandler,
  type HtmlExtractionResult,
} from './html-extractor.js';

export { runHtmlAttributeSecurityChecks } from './html-attribute-security-pass.js';

export {
  mergeHtmlResults,
  type ScriptBlockResult,
} from './html-merge.js';
