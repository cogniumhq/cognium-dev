/**
 * Test setup file
 *
 * This file runs before all tests to set up the testing environment.
 */

import { beforeAll, afterAll } from 'vitest';
import { initParser, resetParser } from '../src/core/parser.js';

// Initialize parser once for all tests
beforeAll(async () => {
  await initParser();
});

// Clean up after all tests
afterAll(() => {
  resetParser();
});
