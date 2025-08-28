/**
 * Configuration Management System
 * Centralized configuration with environment-based overrides and validation
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Joi from 'joi';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class ConfigManager extends EventEmitter {
  constructor(configPath = null) {
    super();
    this.logger = createLogger('ConfigManager');
    this.config = {};
    this.schema = null;
    this.configPath = configPath || path.join(__dirname, '../../../config');
    this.watchers = new Map();
    
    this.initializeSchema();
  }

  initializeSchema() {
    // Define configuration schema for validation
    this.schema = Joi.object({
      server: Joi.object({
        port: Joi.number().port().default(3000),
        host: Joi.string().default('localhost'),
        environment: Joi.string().valid('development', 'staging', 'production').default('development'),
        logLevel: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
        sessionSecret: Joi.string().min(32),
        adminUser: Joi.string().default('admin'),
        adminPass: Joi.string().min(8).default('admin123')
      }).default(),

      security: Joi.object({
        enableHelmet: Joi.boolean().default(true),
        enableRateLimit: Joi.boolean().default(true),
        rateLimitWindow: Joi.number().default(900000), // 15 minutes
        rateLimitMax: Joi.number().default(1000),
        enableCors: Joi.boolean().default(true),
        corsOrigins: Joi.array().items(Joi.string()).default(['*'])
      }).default(),

      otel: Joi.object({
        enabled: Joi.boolean().default(true),
        serviceName: Joi.string().default('production-log-analyzer'),
        serviceVersion: Joi.string().default('2.0.0'),
        jaegerEndpoint: Joi.string().uri().default('http://localhost:14268/api/traces'),
        prometheusPort: Joi.number().port().default(9464),
        enableAutoInstrumentation: Joi.boolean().default(true)
      }).default(),

      transport: Joi.object({
        http: Joi.object({
          enabled: Joi.boolean().default(true),
          port: Joi.number().port().default(8080),
          maxPayloadSize: Joi.string().default('50mb'),
          timeout: Joi.number().default(30000)
        }).default(),
        syslog: Joi.object({
          enabled: Joi.boolean().default(true),
          port: Joi.number().port().default(514),
          protocol: Joi.string().valid('udp', 'tcp').default('udp')
        }).default(),
        kafka: Joi.object({
          enabled: Joi.boolean().default(false),
          brokers: Joi.array().items(Joi.string()).default(['localhost:9092']),
          topics: Joi.array().items(Joi.string()).default(['logs', 'metrics', 'traces']),
          groupId: Joi.string().default('log-analyzer')
        }).default(),
        redis: Joi.object({
          enabled: Joi.boolean().default(false),
          host: Joi.string().default('localhost'),
          port: Joi.number().port().default(6379),
          streams: Joi.array().items(Joi.string()).default(['logs:stream', 'metrics:stream', 'traces:stream'])
        }).default()
      }).default(),

      enrichment: Joi.object({
        timezone: Joi.string().default('UTC'),
        enablePiiDetection: Joi.boolean().default(true),
        piiRedactionMode: Joi.string().valid('hash', 'mask', 'remove').default('hash'),
        enableGeoEnrichment: Joi.boolean().default(true),
        enableUserSessionEnrichment: Joi.boolean().default(true),
        customGrokPatterns: Joi.object().default({})
      }).default(),

      storage: Joi.object({
        tiers: Joi.object({
          hot: Joi.object({
            enabled: Joi.boolean().default(true),
            type: Joi.string().valid('elasticsearch').default('elasticsearch'),
            retention: Joi.string().default('7d'),
            elasticsearch: Joi.object({
              node: Joi.string().uri().default('http://localhost:9200'),
              index: Joi.string().default('logs-hot'),
              maxRetries: Joi.number().default(3),
              requestTimeout: Joi.number().default(30000)
            }).default()
          }).default(),
          warm: Joi.object({
            enabled: Joi.boolean().default(false),
            type: Joi.string().valid('clickhouse').default('clickhouse'),
            retention: Joi.string().default('30d'),
            clickhouse: Joi.object({
              host: Joi.string().default('localhost'),
              port: Joi.number().port().default(8123),
              database: Joi.string().default('logs'),
              table: Joi.string().default('logs_warm')
            }).default()
          }).default(),
          cold: Joi.object({
            enabled: Joi.boolean().default(false),
            type: Joi.string().valid('s3').default('s3'),
            retention: Joi.string().default('365d'),
            s3: Joi.object({
              bucket: Joi.string().default('logs-cold-storage'),
              region: Joi.string().default('us-east-1'),
              accessKeyId: Joi.string(),
              secretAccessKey: Joi.string()
            }).default()
          }).default()
        }).default(),
        cache: Joi.object({
          enabled: Joi.boolean().default(true),
          type: Joi.string().valid('redis').default('redis'),
          ttl: Joi.number().default(3600),
          redis: Joi.object({
            host: Joi.string().default('localhost'),
            port: Joi.number().port().default(6379),
            db: Joi.number().default(0)
          }).default()
        }).default()
      }).default(),

      query: Joi.object({
        maxResults: Joi.number().default(10000),
        defaultTimeRange: Joi.string().default('24h'),
        enableRegex: Joi.boolean().default(true),
        enableSql: Joi.boolean().default(true),
        cacheResults: Joi.boolean().default(true),
        cacheTtl: Joi.number().default(300)
      }).default(),

      anomalyDetection: Joi.object({
        windowSize: Joi.number().default(100),
        sensitivity: Joi.number().min(0).max(1).default(0.95),
        minSamples: Joi.number().default(10),
        algorithms: Joi.object({
          statistical: Joi.boolean().default(true),
          clustering: Joi.boolean().default(true),
          timeSeries: Joi.boolean().default(true),
          logPatterns: Joi.boolean().default(true)
        }).default(),
        thresholds: Joi.object({
          errorRate: Joi.number().default(0.05),
          latencyP95: Joi.number().default(1000),
          throughputDrop: Joi.number().default(0.3)
        }).default()
      }).default(),

      serviceTopology: Joi.object({
        maxNodes: Joi.number().default(1000),
        maxEdges: Joi.number().default(5000),
        correlationWindow: Joi.number().default(300000),
        minCorrelationStrength: Joi.number().default(0.3),
        enableAutoDiscovery: Joi.boolean().default(true)
      }).default(),

      alerting: Joi.object({
        maxActiveAlerts: Joi.number().default(1000),
        dedupWindow: Joi.number().default(300000),
        groupingWindow: Joi.number().default(600000),
        escalationLevels: Joi.array().items(Joi.string()).default(['info', 'warning', 'critical']),
        sloDefaults: Joi.object({
          errorBudget: Joi.number().default(0.001),
          burnRateThreshold: Joi.number().default(2.0)
        }).default(),
        notifications: Joi.object({
          email: Joi.object({
            enabled: Joi.boolean().default(false),
            smtp: Joi.object({
              host: Joi.string(),
              port: Joi.number().port().default(587),
              secure: Joi.boolean().default(false),
              auth: Joi.object({
                user: Joi.string(),
                pass: Joi.string()
              })
            })
          }).default(),
          slack: Joi.object({
            enabled: Joi.boolean().default(false),
            webhookUrl: Joi.string().uri(),
            channel: Joi.string().default('#alerts')
          }).default(),
          webhook: Joi.object({
            enabled: Joi.boolean().default(false),
            url: Joi.string().uri(),
            headers: Joi.object().default({})
          }).default()
        }).default()
      }).default(),

      integrations: Joi.object({
        grafana: Joi.object({
          enabled: Joi.boolean().default(false),
          url: Joi.string().uri(),
          apiKey: Joi.string()
        }).default(),
        serviceNow: Joi.object({
          enabled: Joi.boolean().default(false),
          instance: Joi.string(),
          username: Joi.string(),
          password: Joi.string()
        }).default(),
        jira: Joi.object({
          enabled: Joi.boolean().default(false),
          url: Joi.string().uri(),
          username: Joi.string(),
          apiToken: Joi.string()
        }).default()
      }).default()
    });
  }

  async loadConfig() {
    try {
      // Load base configuration
      const baseConfig = await this.loadConfigFile('default.json');
      
      // Load environment-specific configuration
      const env = process.env.NODE_ENV || 'development';
      const envConfig = await this.loadConfigFile(`${env}.json`);
      
      // Load local overrides (not tracked in git)
      const localConfig = await this.loadConfigFile('local.json');
      
      // Merge configurations (environment variables take precedence)
      this.config = this.mergeConfigs(baseConfig, envConfig, localConfig);
      
      // Apply environment variable overrides
      this.applyEnvironmentOverrides();
      
      // Validate configuration
      await this.validateConfig();
      
      this.logger.info('Configuration loaded successfully');
      this.emit('config-loaded', this.config);
      
      return this.config;
      
    } catch (error) {
      this.logger.error('Failed to load configuration:', error);
      throw error;
    }
  }

  async loadConfigFile(filename) {
    const filePath = path.join(this.configPath, filename);
    
    try {
      if (fs.existsSync(filePath)) {
        const content = await fs.promises.readFile(filePath, 'utf8');
        return JSON.parse(content);
      }
    } catch (error) {
      this.logger.warn(`Failed to load config file ${filename}:`, error.message);
    }
    
    return {};
  }

  mergeConfigs(...configs) {
    return configs.reduce((merged, config) => {
      return this.deepMerge(merged, config || {});
    }, {});
  }

  deepMerge(target, source) {
    const result = { ...target };
    
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    
    return result;
  }

  applyEnvironmentOverrides() {
    // Map environment variables to config paths
    const envMappings = {
      'PORT': 'server.port',
      'HOST': 'server.host',
      'NODE_ENV': 'server.environment',
      'LOG_LEVEL': 'server.logLevel',
      'SESSION_SECRET': 'server.sessionSecret',
      'ADMIN_USER': 'server.adminUser',
      'ADMIN_PASS': 'server.adminPass',
      
      'ELASTICSEARCH_URL': 'storage.tiers.hot.elasticsearch.node',
      'CLICKHOUSE_HOST': 'storage.tiers.warm.clickhouse.host',
      'CLICKHOUSE_PORT': 'storage.tiers.warm.clickhouse.port',
      'CLICKHOUSE_ENABLED': 'storage.tiers.warm.enabled',
      
      'REDIS_HOST': 'transport.redis.host',
      'REDIS_PORT': 'transport.redis.port',
      'REDIS_ENABLED': 'transport.redis.enabled',
      
      'KAFKA_BROKERS': 'transport.kafka.brokers',
      'KAFKA_ENABLED': 'transport.kafka.enabled',
      
      'S3_BUCKET': 'storage.tiers.cold.s3.bucket',
      'S3_REGION': 'storage.tiers.cold.s3.region',
      'S3_ACCESS_KEY_ID': 'storage.tiers.cold.s3.accessKeyId',
      'S3_SECRET_ACCESS_KEY': 'storage.tiers.cold.s3.secretAccessKey',
      'S3_ENABLED': 'storage.tiers.cold.enabled',
      
      'JAEGER_ENDPOINT': 'otel.jaegerEndpoint',
      'PROMETHEUS_PORT': 'otel.prometheusPort',
      
      'SLACK_WEBHOOK_URL': 'alerting.notifications.slack.webhookUrl',
      'SLACK_ENABLED': 'alerting.notifications.slack.enabled',
      
      'GRAFANA_URL': 'integrations.grafana.url',
      'GRAFANA_API_KEY': 'integrations.grafana.apiKey',
      'GRAFANA_ENABLED': 'integrations.grafana.enabled'
    };

    for (const [envVar, configPath] of Object.entries(envMappings)) {
      const envValue = process.env[envVar];
      if (envValue !== undefined) {
        this.setConfigValue(configPath, this.parseEnvValue(envValue));
      }
    }
  }

  parseEnvValue(value) {
    // Parse boolean values
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
    
    // Parse numeric values
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    if (/^\d*\.\d+$/.test(value)) return parseFloat(value);
    
    // Parse JSON arrays/objects
    if (value.startsWith('[') || value.startsWith('{')) {
      try {
        return JSON.parse(value);
      } catch {
        // Return as string if JSON parsing fails
      }
    }
    
    // Parse comma-separated arrays
    if (value.includes(',')) {
      return value.split(',').map(v => v.trim());
    }
    
    return value;
  }

  setConfigValue(path, value) {
    const keys = path.split('.');
    let current = this.config;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = value;
  }

  async validateConfig() {
    try {
      const { error, value } = this.schema.validate(this.config, {
        allowUnknown: true,
        stripUnknown: false
      });
      
      if (error) {
        throw new Error(`Configuration validation failed: ${error.message}`);
      }
      
      this.config = value;
      this.logger.info('Configuration validation passed');
      
    } catch (error) {
      this.logger.error('Configuration validation failed:', error);
      throw error;
    }
  }

  get(path, defaultValue = undefined) {
    const keys = path.split('.');
    let current = this.config;
    
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = current[key];
      } else {
        return defaultValue;
      }
    }
    
    return current;
  }

  set(path, value) {
    this.setConfigValue(path, value);
    this.emit('config-changed', { path, value });
  }

  getAll() {
    return { ...this.config };
  }

  async saveConfig(filename = null) {
    try {
      const targetFile = filename || `${this.get('server.environment', 'development')}.json`;
      const filePath = path.join(this.configPath, targetFile);
      
      // Ensure config directory exists
      await fs.promises.mkdir(this.configPath, { recursive: true });
      
      // Write configuration
      await fs.promises.writeFile(
        filePath,
        JSON.stringify(this.config, null, 2),
        'utf8'
      );
      
      this.logger.info(`Configuration saved to ${targetFile}`);
      this.emit('config-saved', { filename: targetFile, config: this.config });
      
    } catch (error) {
      this.logger.error('Failed to save configuration:', error);
      throw error;
    }
  }

  watchConfig(callback) {
    const watchId = Date.now().toString();
    this.watchers.set(watchId, callback);
    
    this.on('config-changed', callback);
    
    return () => {
      this.watchers.delete(watchId);
      this.off('config-changed', callback);
    };
  }

  async reloadConfig() {
    try {
      await this.loadConfig();
      this.emit('config-reloaded', this.config);
      this.logger.info('Configuration reloaded');
    } catch (error) {
      this.logger.error('Failed to reload configuration:', error);
      throw error;
    }
  }

  getConfigSummary() {
    return {
      environment: this.get('server.environment'),
      version: this.get('otel.serviceVersion'),
      modules: {
        otel: this.get('otel.enabled'),
        elasticsearch: this.get('storage.tiers.hot.enabled'),
        clickhouse: this.get('storage.tiers.warm.enabled'),
        s3: this.get('storage.tiers.cold.enabled'),
        kafka: this.get('transport.kafka.enabled'),
        redis: this.get('transport.redis.enabled'),
        anomalyDetection: this.get('anomalyDetection.algorithms.statistical'),
        alerting: true,
        integrations: {
          grafana: this.get('integrations.grafana.enabled'),
          serviceNow: this.get('integrations.serviceNow.enabled'),
          jira: this.get('integrations.jira.enabled')
        }
      },
      security: {
        helmet: this.get('security.enableHelmet'),
        rateLimit: this.get('security.enableRateLimit'),
        cors: this.get('security.enableCors')
      }
    };
  }
}

// Singleton instance
let configManager = null;

export function getConfigManager(configPath = null) {
  if (!configManager) {
    configManager = new ConfigManager(configPath);
  }
  return configManager;
}

export { ConfigManager };
