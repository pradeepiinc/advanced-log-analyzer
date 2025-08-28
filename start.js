#!/usr/bin/env node

/**
 * Startup script for Production Log Analyzer
 * Initializes all modules and starts the server
 */

import { getConfigManager } from './src/core/config/config-manager.js';
import { createLogger } from './src/core/utils/logger.js';
import { getOTelCollector } from './src/core/ingestion/otel-collector.js';
import { getTransportManager } from './src/core/ingestion/transport-manager.js';
import { getEnrichmentEngine } from './src/core/parsing/enrichment-engine.js';
import { getStorageManager } from './src/core/storage/storage-manager.js';
import { getQueryEngine } from './src/core/query/query-engine.js';
import { getAnomalyDetector } from './src/core/ml/anomaly-detector.js';
import { getServiceTopology } from './src/core/correlation/service-topology.js';
import { getAlertManager } from './src/core/alerting/alert-manager.js';
import { getRBACManager } from './src/core/security/rbac-manager.js';
import { getIntegrationManager } from './src/core/integrations/integration-manager.js';

const logger = createLogger('Startup');

async function startApplication() {
  try {
    logger.info('🚀 Starting Advanced Production Log Analyzer...');
    
    // 1. Load configuration
    logger.info('📋 Loading configuration...');
    const config = getConfigManager();
    await config.loadConfig();
    
    // 2. Initialize core modules
    logger.info('🔧 Initializing core modules...');
    
    // Security and RBAC
    const rbac = getRBACManager();
    logger.info('✅ RBAC Manager initialized');
    
    // Storage layer
    const storage = getStorageManager();
    await storage.initialize();
    logger.info('✅ Storage Manager initialized');
    
    // Parsing and enrichment
    const enrichment = getEnrichmentEngine();
    logger.info('✅ Enrichment Engine initialized');
    
    // Query engine
    const query = getQueryEngine();
    logger.info('✅ Query Engine initialized');
    
    // ML and anomaly detection
    const anomalyDetector = getAnomalyDetector();
    logger.info('✅ Anomaly Detector initialized');
    
    // Service topology and correlation
    const topology = getServiceTopology();
    logger.info('✅ Service Topology initialized');
    
    // Alerting system
    const alertManager = getAlertManager();
    logger.info('✅ Alert Manager initialized');
    
    // Integrations
    const integrations = getIntegrationManager();
    logger.info('✅ Integration Manager initialized');
    
    // Transport and ingestion
    const transport = getTransportManager();
    await transport.initialize();
    logger.info('✅ Transport Manager initialized');
    
    // OpenTelemetry collector
    const otel = getOTelCollector();
    await otel.initialize();
    logger.info('✅ OTel Collector initialized');
    
    // 3. Start main server
    logger.info('🌐 Starting web server...');
    const { default: app } = await import('./src/server.js');
    
    const port = config.get('server.port', 3000);
    const host = config.get('server.host', 'localhost');
    
    app.listen(port, host, () => {
      logger.info(`🎉 Production Log Analyzer started successfully!`);
      logger.info(`📊 Web Interface: http://${host}:${port}`);
      logger.info(`🔍 Advanced Search: http://${host}:${port}/advanced-search.html`);
      logger.info(`📈 Health Check: http://${host}:${port}/api/health`);
      
      // Print configuration summary
      const summary = config.getConfigSummary();
      logger.info('📋 Configuration Summary:', summary);
    });
    
    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      logger.info('🛑 Shutting down gracefully...');
      
      await transport.shutdown();
      await storage.shutdown();
      await integrations.shutdown();
      
      logger.info('👋 Shutdown complete');
      process.exit(0);
    });
    
  } catch (error) {
    logger.error('💥 Failed to start application:', error);
    process.exit(1);
  }
}

// Start the application
startApplication().catch(error => {
  console.error('Fatal startup error:', error);
  process.exit(1);
});
