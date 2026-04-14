/**
 * Language Plugins - Concrete implementations
 *
 * Exports all language plugins and provides initialization helpers.
 */

export { JavaPlugin } from './java.js';
export { JavaScriptPlugin } from './javascript.js';
export { PythonPlugin } from './python.js';
export { RustPlugin } from './rust.js';
export { BashPlugin } from './bash.js';
export { HtmlPlugin } from './html.js';

import { registerLanguage } from '../registry.js';
import { JavaPlugin } from './java.js';
import { JavaScriptPlugin } from './javascript.js';
import { PythonPlugin } from './python.js';
import { RustPlugin } from './rust.js';
import { BashPlugin } from './bash.js';
import { HtmlPlugin } from './html.js';

/**
 * Register all built-in language plugins with the global registry.
 * Call this during analyzer initialization.
 */
export function registerBuiltinPlugins(): void {
  registerLanguage(new JavaPlugin());
  registerLanguage(new JavaScriptPlugin());
  registerLanguage(new PythonPlugin());
  registerLanguage(new RustPlugin());
  registerLanguage(new BashPlugin());
  registerLanguage(new HtmlPlugin());
}
