/**
 * Unresolved item detector
 *
 * Identifies code patterns that require LLM assistance to resolve:
 * - Virtual dispatch (interface methods)
 * - Taint propagation through collections
 * - Reflection calls
 * - Dynamic method invocations
 */

import type { CallInfo, TypeInfo, DFG, UnresolvedItem } from '../types/index.js';

/**
 * Detect unresolved items that would benefit from LLM analysis.
 */
export function detectUnresolved(
  calls: CallInfo[],
  types: TypeInfo[],
  dfg: DFG
): UnresolvedItem[] {
  const unresolved: UnresolvedItem[] = [];

  // Detect virtual dispatch (unresolved interface/abstract method calls)
  unresolved.push(...detectVirtualDispatch(calls));

  // Detect reflection patterns
  unresolved.push(...detectReflection(calls));

  // Detect taint propagation uncertainty (collections, etc.)
  unresolved.push(...detectTaintPropagationUncertainty(calls, dfg));

  // Detect dynamic calls
  unresolved.push(...detectDynamicCalls(calls));

  return unresolved;
}

/**
 * Detect virtual dispatch - interface method calls that can't be statically resolved.
 */
function detectVirtualDispatch(calls: CallInfo[]): UnresolvedItem[] {
  const items: UnresolvedItem[] = [];

  for (const call of calls) {
    if (call.resolution?.status === 'interface_method') {
      items.push({
        type: 'virtual_dispatch',
        call_id: calls.indexOf(call),
        reason: 'interface_method_unknown_impl',
        context: {
          code: formatCallCode(call),
          line: call.location.line,
          candidates: call.resolution.candidates,
        },
        llm_question: `Which implementation of ${call.method_name} is called when invoked on ${call.receiver}? Consider the context and common patterns.`,
      });
    }
  }

  return items;
}

/**
 * Detect reflection patterns that need runtime analysis.
 */
function detectReflection(calls: CallInfo[]): UnresolvedItem[] {
  const items: UnresolvedItem[] = [];

  const reflectionMethods = new Set([
    'forName',      // Class.forName
    'newInstance',  // Class.newInstance
    'invoke',       // Method.invoke
    'get',          // Field.get
    'set',          // Field.set
    'getMethod',    // Class.getMethod
    'getDeclaredMethod',
    'getField',
    'getDeclaredField',
    'getConstructor',
  ]);

  const reflectionReceivers = new Set([
    'Class',
    'Method',
    'Field',
    'Constructor',
  ]);

  for (const call of calls) {
    const isReflectionMethod = reflectionMethods.has(call.method_name);
    const isReflectionReceiver = call.receiver && reflectionReceivers.has(call.receiver);

    if (isReflectionMethod || isReflectionReceiver) {
      items.push({
        type: 'reflection',
        call_id: calls.indexOf(call),
        reason: 'reflection_call',
        context: {
          code: formatCallCode(call),
          line: call.location.line,
        },
        llm_question: `What class/method is being accessed via reflection at ${formatCallCode(call)}? What are the security implications?`,
      });
    }
  }

  return items;
}

/**
 * Detect taint propagation uncertainty through collections and complex data flows.
 */
function detectTaintPropagationUncertainty(calls: CallInfo[], dfg: DFG): UnresolvedItem[] {
  const items: UnresolvedItem[] = [];

  // Collection methods that might propagate or lose taint
  const collectionMethods = new Map<string, string>([
    ['add', 'collection_add'],
    ['put', 'map_put'],
    ['get', 'collection_get'],
    ['remove', 'collection_remove'],
    ['addAll', 'collection_addAll'],
    ['putAll', 'map_putAll'],
    ['toArray', 'collection_toArray'],
    ['stream', 'collection_stream'],
    ['iterator', 'collection_iterator'],
  ]);

  // Receivers that are likely collections
  const collectionPatterns = [
    /list/i,
    /set/i,
    /map/i,
    /collection/i,
    /array/i,
    /queue/i,
    /stack/i,
    /vector/i,
  ];

  for (const call of calls) {
    if (!collectionMethods.has(call.method_name)) continue;

    // Check if receiver looks like a collection
    const isCollection = call.receiver && collectionPatterns.some(p => p.test(call.receiver!));
    if (!isCollection && call.receiver) continue;

    const methodType = collectionMethods.get(call.method_name)!;

    // For add/put, check if argument might be tainted
    if (methodType === 'collection_add' || methodType === 'map_put') {
      const hasVariableArg = call.arguments.some(arg => arg.variable !== null);
      if (hasVariableArg) {
        items.push({
          type: 'taint_propagation',
          call_id: calls.indexOf(call),
          reason: 'collection_taint_in',
          context: {
            code: formatCallCode(call),
            line: call.location.line,
          },
          llm_question: `Does taint propagate into ${call.receiver} when ${call.method_name} is called? Will subsequent retrievals from this collection be tainted?`,
        });
      }
    }

    // For get operations, question if result carries taint
    if (methodType === 'collection_get' || methodType === 'collection_toArray') {
      items.push({
        type: 'taint_propagation',
        call_id: calls.indexOf(call),
        reason: 'collection_taint_out',
        context: {
          code: formatCallCode(call),
          line: call.location.line,
        },
        llm_question: `Does the value retrieved from ${call.receiver}.${call.method_name}() carry taint from previously added elements?`,
      });
    }
  }

  return items;
}

/**
 * Detect dynamic method calls that can't be statically analyzed.
 */
function detectDynamicCalls(calls: CallInfo[]): UnresolvedItem[] {
  const items: UnresolvedItem[] = [];

  // Patterns that suggest dynamic dispatch
  const dynamicPatterns = [
    { method: 'execute', reason: 'command_pattern' },
    { method: 'handle', reason: 'handler_pattern' },
    { method: 'process', reason: 'processor_pattern' },
    { method: 'dispatch', reason: 'dispatcher_pattern' },
    { method: 'run', reason: 'runnable_pattern' },
    { method: 'call', reason: 'callable_pattern' },
    { method: 'apply', reason: 'function_pattern' },
    { method: 'accept', reason: 'consumer_pattern' },
  ];

  for (const call of calls) {
    // Skip if already resolved
    if (call.resolved) continue;

    const pattern = dynamicPatterns.find(p => p.method === call.method_name);
    if (pattern) {
      items.push({
        type: 'dynamic_call',
        call_id: calls.indexOf(call),
        reason: pattern.reason,
        context: {
          code: formatCallCode(call),
          line: call.location.line,
        },
        llm_question: `What concrete implementation handles this ${call.method_name}() call? Analyze the code context to determine the actual target.`,
      });
    }
  }

  return items;
}

/**
 * Format a call for display in context.
 */
function formatCallCode(call: CallInfo): string {
  const args = call.arguments.map(a => a.expression).join(', ');
  if (call.receiver) {
    return `${call.receiver}.${call.method_name}(${args})`;
  }
  return `${call.method_name}(${args})`;
}
