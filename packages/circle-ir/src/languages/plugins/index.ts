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
export { VuePlugin } from './vue.js';
export { GoPlugin } from './go.js';
export { CSharpPlugin } from './csharp.js';

import { registerLanguage } from '../registry.js';
import type { LanguagePlugin } from '../types.js';
import { JavaPlugin } from './java.js';
import { JavaScriptPlugin } from './javascript.js';
import { PythonPlugin } from './python.js';
import { RustPlugin } from './rust.js';
import { BashPlugin } from './bash.js';
import { HtmlPlugin } from './html.js';
import { VuePlugin } from './vue.js';
import { GoPlugin } from './go.js';
import { CSharpPlugin } from './csharp.js';

/**
 * Fresh instances of every built-in language plugin, unregistered. The single
 * list both `registerBuiltinPlugins` and registry-wide enumerations (e.g. the
 * modelled-CWE export) read, so a new plugin cannot be added to one and missed
 * by the other.
 */
export function createBuiltinPlugins(): LanguagePlugin[] {
  return [
    new JavaPlugin(),
    new JavaScriptPlugin(),
    new PythonPlugin(),
    new RustPlugin(),
    new BashPlugin(),
    new HtmlPlugin(),
    new VuePlugin(),
    new GoPlugin(),
    new CSharpPlugin(),
  ];
}

/**
 * Register all built-in language plugins with the global registry.
 * Call this during analyzer initialization.
 */
export function registerBuiltinPlugins(): void {
  for (const plugin of createBuiltinPlugins()) registerLanguage(plugin);
}
