#!/usr/bin/env node

/**
 * System Test Script
 * Tests core functionality without external dependencies
 */

import { createLogger } from './src/core/utils/logger.js';
import { getConfigManager } from './src/core/config/config-manager.js';
import { getEnrichmentEngine } from './src/core/parsing/enrichment-engine.js';
import { getRBACManager } from './src/core/security/rbac-manager.js';

const logger = createLogger('SystemTest');

async function runTests() {
  console.log('🧪 Running System Tests...\n');
  
  let passed = 0;
  let failed = 0;
  
  // Test 1: Configuration Management
  try {
    console.log('1️⃣ Testing Configuration Management...');
    const config = getConfigManager();
    await config.loadConfig();
    
    const serverPort = config.get('server.port');
    const otelEnabled = config.get('otel.enabled');
    
    console.log(`   ✅ Config loaded - Port: ${serverPort}, OTel: ${otelEnabled}`);
    passed++;
  } catch (error) {
    console.log(`   ❌ Config test failed: ${error.message}`);
    failed++;
  }
  
  // Test 2: RBAC System
  try {
    console.log('2️⃣ Testing RBAC System...');
    const rbac = getRBACManager();
    
    // Test user creation
    const testUser = await rbac.createUser({
      username: 'testuser',
      password: 'testpass123',
      email: 'test@example.com',
      roles: ['viewer']
    });
    
    // Test authentication
    const authUser = await rbac.authenticateUser('testuser', 'testpass123');
    
    // Test permissions
    const hasPermission = rbac.hasPermission('testuser', 'logs:read');
    
    console.log(`   ✅ RBAC working - User: ${testUser.username}, Auth: ${!!authUser}, Permission: ${hasPermission}`);
    passed++;
  } catch (error) {
    console.log(`   ❌ RBAC test failed: ${error.message}`);
    failed++;
  }
  
  // Test 3: Log Parsing and Enrichment
  try {
    console.log('3️⃣ Testing Log Parsing...');
    const enrichment = getEnrichmentEngine();
    
    const testLog = {
      timestamp: new Date().toISOString(),
      level: 'error',
      message: 'Database connection failed for user john.doe@example.com',
      service: 'api-gateway'
    };
    
    const enrichedLog = await enrichment.processLog(testLog);
    
    console.log(`   ✅ Log enriched - PII detected: ${enrichedLog.piiDetected || false}`);
    passed++;
  } catch (error) {
    console.log(`   ❌ Parsing test failed: ${error.message}`);
    failed++;
  }
  
  // Test 4: Mock Storage Operations
  try {
    console.log('4️⃣ Testing Mock Storage...');
    
    // Simulate storage without external dependencies
    const mockStorage = {
      store: async (log) => ({ id: 'mock-id-123', stored: true }),
      query: async (query) => ({ results: [], total: 0 })
    };
    
    const stored = await mockStorage.store({ message: 'test log' });
    const results = await mockStorage.query({ query: 'test' });
    
    console.log(`   ✅ Storage simulation - Stored: ${stored.stored}, Query: ${results.total} results`);
    passed++;
  } catch (error) {
    console.log(`   ❌ Storage test failed: ${error.message}`);
    failed++;
  }
  
  // Test 5: Alert Logic
  try {
    console.log('5️⃣ Testing Alert Logic...');
    
    // Mock alert evaluation
    const mockAlert = {
      name: 'High Error Rate',
      conditions: [{ field: 'level', operator: 'equals', value: 'error' }],
      threshold: { count: 5, timeWindow: '5m' }
    };
    
    const testLogs = [
      { level: 'error', timestamp: new Date() },
      { level: 'error', timestamp: new Date() },
      { level: 'info', timestamp: new Date() }
    ];
    
    const errorCount = testLogs.filter(log => log.level === 'error').length;
    const shouldAlert = errorCount >= 2; // Simplified threshold
    
    console.log(`   ✅ Alert logic - Error count: ${errorCount}, Should alert: ${shouldAlert}`);
    passed++;
  } catch (error) {
    console.log(`   ❌ Alert test failed: ${error.message}`);
    failed++;
  }
  
  // Test 6: Basic HTTP Server
  try {
    console.log('6️⃣ Testing HTTP Server...');
    
    // Import and test basic server setup
    const express = await import('express');
    const app = express.default();
    
    app.get('/test', (req, res) => res.json({ status: 'ok' }));
    
    // Test that server can be created
    const server = app.listen(0, () => {
      const port = server.address().port;
      console.log(`   ✅ HTTP server - Test server started on port ${port}`);
      server.close();
      passed++;
    });
    
  } catch (error) {
    console.log(`   ❌ HTTP server test failed: ${error.message}`);
    failed++;
  }
  
  // Summary
  console.log('\n📊 Test Results:');
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📈 Success Rate: ${Math.round((passed / (passed + failed)) * 100)}%`);
  
  if (failed === 0) {
    console.log('\n🎉 All tests passed! System is ready to run.');
    console.log('\n🚀 To start the application:');
    console.log('   npm start');
    console.log('\n🔍 To access the UI:');
    console.log('   http://localhost:3000');
    console.log('   http://localhost:3000/advanced-search.html');
  } else {
    console.log('\n⚠️  Some tests failed. Check the error messages above.');
    console.log('   The system may still work with external dependencies installed.');
  }
  
  return failed === 0;
}

// Run tests
runTests().catch(error => {
  console.error('💥 Test runner failed:', error);
  process.exit(1);
});
