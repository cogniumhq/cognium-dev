#!/usr/bin/env npx tsx
/**
 * Node.js Example - Circle-IR Core Library
 *
 * This example demonstrates how to use circle-ir to:
 * 1. Parse Java code
 * 2. Extract IR components (types, calls, CFG, DFG)
 * 3. Detect taint sources and sinks
 * 4. Find source-to-sink flows
 *
 * Setup:
 *   npm install circle-ir
 *
 * Run:
 *   npx tsx node-example.ts
 */

import {
  initParser,
  parse,
  collectAllNodes,
  extractMeta,
  extractTypes,
  extractCalls,
  buildCFG,
  buildDFG,
  analyzeTaint,
  propagateTaint,
  analyzeConstantPropagation,
  isFalsePositive,
  getDefaultConfig,
} from 'circle-ir/core';

// Sample vulnerable Java code
const vulnerableCode = `
package com.example;

import javax.servlet.http.*;
import java.sql.*;

public class UserController extends HttpServlet {

    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        // SOURCE: User input from HTTP parameter
        String userId = request.getParameter("id");

        // No sanitization - direct use in SQL query
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
            Statement stmt = conn.createStatement();

            // SINK: SQL injection vulnerability
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
`;

// Sample safe Java code (uses PreparedStatement)
const safeCode = `
package com.example;

import javax.servlet.http.*;
import java.sql.*;

public class SafeUserController extends HttpServlet {

    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");

            // SAFE: Using PreparedStatement with parameterized query
            PreparedStatement stmt = conn.prepareStatement(
                "SELECT * FROM users WHERE id = ?"
            );
            stmt.setString(1, userId);

            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                response.getWriter().println(rs.getString("name"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
`;

// Node types needed for analysis
const NODE_TYPES = new Set([
  'method_invocation',
  'object_creation_expression',
  'class_declaration',
  'method_declaration',
  'constructor_declaration',
  'field_declaration',
  'import_declaration',
  'interface_declaration',
  'enum_declaration',
]);

async function analyzeCode(code: string, filename: string): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Analyzing: ${filename}`);
  console.log('='.repeat(60));

  // Parse the code
  const tree = await parse(code, 'java');
  const nodeCache = collectAllNodes(tree.rootNode, NODE_TYPES);

  // Extract IR components
  const meta = extractMeta(code, tree, filename, 'java');
  const types = extractTypes(tree, nodeCache);
  const calls = extractCalls(tree, nodeCache);
  const cfg = buildCFG(tree);
  const dfg = buildDFG(tree, nodeCache);

  console.log(`\nIR Summary:`);
  console.log(`  Lines of code: ${meta.loc}`);
  console.log(`  Classes: ${types.length}`);
  console.log(`  Method calls: ${calls.length}`);
  console.log(`  CFG blocks: ${cfg.blocks.length}`);
  console.log(`  DFG definitions: ${dfg.defs.length}`);

  // Analyze taint
  const config = getDefaultConfig();
  const taint = analyzeTaint(calls, types, config);

  console.log(`\nTaint Analysis:`);
  console.log(`  Sources: ${taint.sources.length}`);
  taint.sources.forEach(s => {
    console.log(`    - Line ${s.line}: ${s.type} (${s.location})`);
  });

  console.log(`  Sinks: ${taint.sinks.length}`);
  taint.sinks.forEach(s => {
    console.log(`    - Line ${s.line}: ${s.type} (${s.location})`);
  });

  console.log(`  Sanitizers: ${taint.sanitizers.length}`);
  taint.sanitizers.forEach(s => {
    console.log(`    - Line ${s.line}: ${s.type} (${s.method})`);
  });

  // Find taint flows
  const propagationResult = propagateTaint(
    dfg,
    calls,
    taint.sources,
    taint.sinks,
    taint.sanitizers ?? []
  );

  // Run constant propagation for false positive elimination
  const constPropResult = analyzeConstantPropagation(tree, code);

  // Filter false positives
  const verifiedFlows = propagationResult.flows.filter(flow => {
    // Check each step in the path - if any variable has a constant value, it's a FP
    for (const step of flow.path) {
      const fpCheck = isFalsePositive(constPropResult, step.line, step.variable);
      if (fpCheck.isFalsePositive) {
        return false;
      }
    }
    return true;
  });

  console.log(`\nVulnerability Detection:`);
  if (verifiedFlows.length > 0) {
    console.log(`  Found ${verifiedFlows.length} potential vulnerabilities:`);
    verifiedFlows.forEach((flow, i) => {
      console.log(`\n  [${i + 1}] ${flow.sink.type.toUpperCase()}`);
      console.log(`      Source: Line ${flow.source.line} (${flow.source.type})`);
      console.log(`      Sink: Line ${flow.sink.line} (${flow.sink.type})`);
      console.log(`      Confidence: ${(flow.confidence * 100).toFixed(0)}%`);
      if (flow.path.length > 0) {
        console.log(`      Path:`);
        flow.path.forEach(step => {
          console.log(`        -> ${step.variable} (line ${step.line})`);
        });
      }
    });
  } else {
    console.log(`  No vulnerabilities detected.`);
  }
}

async function main(): Promise<void> {
  console.log('Circle-IR Core Library - Node.js Example');
  console.log('=========================================\n');

  // Initialize the parser
  console.log('Initializing parser...');
  await initParser();
  console.log('Parser initialized.\n');

  // Analyze vulnerable code
  await analyzeCode(vulnerableCode, 'VulnerableController.java');

  // Analyze safe code
  await analyzeCode(safeCode, 'SafeUserController.java');

  console.log('\n' + '='.repeat(60));
  console.log('Analysis complete.');
}

main().catch(console.error);
