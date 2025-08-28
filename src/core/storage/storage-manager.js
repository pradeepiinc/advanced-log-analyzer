/**
 * Storage Manager with Hot/Warm/Cold tier architecture
 * Supports Elasticsearch, ClickHouse, and S3/cloud storage
 */

import { EventEmitter } from 'events';
import { Client } from '@elastic/elasticsearch';
import { ClickHouse } from 'clickhouse';
import Redis from 'ioredis';
import { createLogger } from '../utils/logger.js';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';

class StorageManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      tiers: {
        hot: {
          enabled: true,
          type: 'elasticsearch',
          retention: '7d',
          elasticsearch: {
            node: 'http://localhost:9200',
            index: 'logs-hot',
            ...config.tiers?.hot?.elasticsearch
          }
        },
        warm: {
          enabled: true,
          type: 'clickhouse',
          retention: '30d',
          clickhouse: {
            host: 'localhost',
            port: 8123,
            database: 'logs',
            table: 'logs_warm',
            ...config.tiers?.warm?.clickhouse
          }
        },
        cold: {
          enabled: true,
          type: 's3',
          retention: '365d',
          s3: {
            bucket: 'logs-cold-storage',
            region: 'us-east-1',
            ...config.tiers?.cold?.s3
          }
        }
      },
      cache: {
        enabled: true,
        type: 'redis',
        ttl: 3600,
        redis: {
          host: 'localhost',
          port: 6379,
          ...config.cache?.redis
        }
      },
      ...config
    };

    this.logger = createLogger('StorageManager');
    this.clients = new Map();
    this.cache = null;
    this.stats = {
      stored: { hot: 0, warm: 0, cold: 0 },
      retrieved: { hot: 0, warm: 0, cold: 0 },
      errors: 0
    };
  }

  async initialize() {
    try {
      // Initialize hot tier (Elasticsearch)
      if (this.config.tiers.hot.enabled) {
        await this.initializeElasticsearch();
      }

      // Initialize warm tier (ClickHouse)
      if (this.config.tiers.warm.enabled) {
        await this.initializeClickHouse();
      }

      // Initialize cache
      if (this.config.cache.enabled) {
        await this.initializeCache();
      }

      this.logger.info('Storage Manager initialized successfully');
      this.emit('initialized');

    } catch (error) {
      this.logger.error('Failed to initialize Storage Manager:', error);
      throw error;
    }
  }

  async initializeElasticsearch() {
    const esClient = new Client({
      node: this.config.tiers.hot.elasticsearch.node
    });

    // Test connection
    await esClient.ping();

    // Create index template
    await this.createElasticsearchTemplate(esClient);

    this.clients.set('elasticsearch', esClient);
    this.logger.info('Elasticsearch client initialized');
  }

  async createElasticsearchTemplate(client) {
    const template = {
      index_patterns: ['logs-*'],
      template: {
        settings: {
          number_of_shards: 3,
          number_of_replicas: 1,
          'index.lifecycle.name': 'logs-policy',
          'index.lifecycle.rollover_alias': 'logs-hot'
        },
        mappings: {
          properties: {
            '@timestamp': { type: 'date' },
            timestamp: { type: 'date' },
            level: { type: 'keyword' },
            message: { type: 'text', analyzer: 'standard' },
            service: { type: 'keyword' },
            version: { type: 'keyword' },
            environment: { type: 'keyword' },
            userId: { type: 'keyword' },
            traceId: { type: 'keyword' },
            spanId: { type: 'keyword' },
            clientip: { type: 'ip' },
            response_time: { type: 'long' },
            status_code: { type: 'integer' },
            geo: {
              properties: {
                location: { type: 'geo_point' },
                country: { type: 'keyword' },
                region: { type: 'keyword' },
                city: { type: 'keyword' }
              }
            }
          }
        }
      }
    };

    await client.indices.putIndexTemplate({
      name: 'logs-template',
      body: template
    });
  }

  async initializeClickHouse() {
    const chClient = new ClickHouse({
      host: this.config.tiers.warm.clickhouse.host,
      port: this.config.tiers.warm.clickhouse.port,
      database: this.config.tiers.warm.clickhouse.database
    });

    // Create database if not exists
    await chClient.query(`CREATE DATABASE IF NOT EXISTS ${this.config.tiers.warm.clickhouse.database}`);

    // Create table
    await this.createClickHouseTable(chClient);

    this.clients.set('clickhouse', chClient);
    this.logger.info('ClickHouse client initialized');
  }

  async createClickHouseTable(client) {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS ${this.config.tiers.warm.clickhouse.table} (
        id String,
        timestamp DateTime64(3),
        level LowCardinality(String),
        message String,
        service LowCardinality(String),
        version LowCardinality(String),
        environment LowCardinality(String),
        userId String,
        traceId String,
        spanId String,
        clientip IPv4,
        response_time UInt32,
        status_code UInt16,
        geo_country LowCardinality(String),
        geo_region LowCardinality(String),
        geo_city LowCardinality(String),
        attributes String,
        raw String,
        created_at DateTime DEFAULT now()
      ) ENGINE = MergeTree()
      PARTITION BY toYYYYMM(timestamp)
      ORDER BY (timestamp, service, level)
      TTL timestamp + INTERVAL 30 DAY
    `;

    await client.query(createTableQuery);
  }

  async initializeCache() {
    this.cache = new Redis(this.config.cache.redis);
    await this.cache.ping();
    this.logger.info('Redis cache initialized');
  }

  /**
   * Store log entry with automatic tier selection
   */
  async store(logEntry) {
    try {
      const entryAge = this.getEntryAge(logEntry.timestamp);
      const tier = this.selectTier(entryAge);
      
      let result;
      switch (tier) {
        case 'hot':
          result = await this.storeInHotTier(logEntry);
          break;
        case 'warm':
          result = await this.storeInWarmTier(logEntry);
          break;
        case 'cold':
          result = await this.storeInColdTier(logEntry);
          break;
        default:
          result = await this.storeInHotTier(logEntry);
      }

      this.stats.stored[tier]++;
      this.emit('stored', { tier, entry: logEntry, result });
      
      return { tier, ...result };

    } catch (error) {
      this.stats.errors++;
      this.logger.error('Failed to store log entry:', error);
      throw error;
    }
  }

  selectTier(age) {
    const hotRetention = this.parseRetention(this.config.tiers.hot.retention);
    const warmRetention = this.parseRetention(this.config.tiers.warm.retention);

    if (age <= hotRetention) return 'hot';
    if (age <= warmRetention) return 'warm';
    return 'cold';
  }

  parseRetention(retention) {
    const match = retention.match(/(\d+)([hdwmy])/);
    if (!match) return 0;

    const [, value, unit] = match;
    const multipliers = { h: 3600, d: 86400, w: 604800, m: 2592000, y: 31536000 };
    return parseInt(value) * (multipliers[unit] || 86400) * 1000; // Convert to milliseconds
  }

  getEntryAge(timestamp) {
    return Date.now() - new Date(timestamp).getTime();
  }

  async storeInHotTier(logEntry) {
    const client = this.clients.get('elasticsearch');
    const index = `${this.config.tiers.hot.elasticsearch.index}-${moment().format('YYYY.MM.DD')}`;
    
    const doc = {
      '@timestamp': logEntry.timestamp,
      ...logEntry,
      tier: 'hot'
    };

    const result = await client.index({
      index,
      id: logEntry.id || uuidv4(),
      body: doc
    });

    return { id: result.body._id, index: result.body._index };
  }

  async storeInWarmTier(logEntry) {
    const client = this.clients.get('clickhouse');
    
    const values = {
      id: logEntry.id || uuidv4(),
      timestamp: logEntry.timestamp,
      level: logEntry.level || 'INFO',
      message: logEntry.message || '',
      service: logEntry.service || 'unknown',
      version: logEntry.version || '',
      environment: logEntry.environment || '',
      userId: logEntry.userId || '',
      traceId: logEntry.traceId || '',
      spanId: logEntry.spanId || '',
      clientip: logEntry.clientip || '0.0.0.0',
      response_time: logEntry.response_time || 0,
      status_code: logEntry.status_code || 0,
      geo_country: logEntry.geo?.country || '',
      geo_region: logEntry.geo?.region || '',
      geo_city: logEntry.geo?.city || '',
      attributes: JSON.stringify(logEntry.attributes || {}),
      raw: JSON.stringify(logEntry)
    };

    await client.insert(`INSERT INTO ${this.config.tiers.warm.clickhouse.table}`, [values]);
    
    return { id: values.id, table: this.config.tiers.warm.clickhouse.table };
  }

  async storeInColdTier(logEntry) {
    // Mock S3 storage - implement actual S3 client
    const key = `logs/${moment(logEntry.timestamp).format('YYYY/MM/DD')}/${logEntry.id || uuidv4()}.json`;
    
    // In real implementation, use AWS SDK to upload to S3
    this.logger.info(`Would store in S3: ${key}`);
    
    return { key, bucket: this.config.tiers.cold.s3.bucket };
  }

  /**
   * Query across all tiers
   */
  async query(queryParams) {
    const { timeRange, filters, limit = 100, offset = 0 } = queryParams;
    
    // Determine which tiers to query based on time range
    const tiersToQuery = this.determineTiersForQuery(timeRange);
    
    const results = [];
    
    for (const tier of tiersToQuery) {
      try {
        let tierResults;
        switch (tier) {
          case 'hot':
            tierResults = await this.queryHotTier(queryParams);
            break;
          case 'warm':
            tierResults = await this.queryWarmTier(queryParams);
            break;
          case 'cold':
            tierResults = await this.queryColdTier(queryParams);
            break;
        }
        
        if (tierResults) {
          results.push(...tierResults);
          this.stats.retrieved[tier] += tierResults.length;
        }
      } catch (error) {
        this.logger.error(`Failed to query ${tier} tier:`, error);
      }
    }

    // Sort and limit results
    return results
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(offset, offset + limit);
  }

  determineTiersForQuery(timeRange) {
    if (!timeRange) return ['hot', 'warm', 'cold'];
    
    const { start, end } = timeRange;
    const now = Date.now();
    const startAge = now - new Date(start).getTime();
    const endAge = now - new Date(end).getTime();
    
    const hotRetention = this.parseRetention(this.config.tiers.hot.retention);
    const warmRetention = this.parseRetention(this.config.tiers.warm.retention);
    
    const tiers = [];
    
    if (endAge <= hotRetention) tiers.push('hot');
    if (startAge <= warmRetention && endAge > hotRetention) tiers.push('warm');
    if (startAge > warmRetention) tiers.push('cold');
    
    return tiers.length > 0 ? tiers : ['hot'];
  }

  async queryHotTier(queryParams) {
    const client = this.clients.get('elasticsearch');
    const { timeRange, filters, limit = 100 } = queryParams;
    
    const query = {
      bool: {
        must: [],
        filter: []
      }
    };

    // Add time range filter
    if (timeRange) {
      query.bool.filter.push({
        range: {
          '@timestamp': {
            gte: timeRange.start,
            lte: timeRange.end
          }
        }
      });
    }

    // Add other filters
    if (filters) {
      for (const [field, value] of Object.entries(filters)) {
        if (Array.isArray(value)) {
          query.bool.filter.push({ terms: { [field]: value } });
        } else {
          query.bool.filter.push({ term: { [field]: value } });
        }
      }
    }

    const result = await client.search({
      index: 'logs-*',
      body: {
        query,
        size: limit,
        sort: [{ '@timestamp': { order: 'desc' } }]
      }
    });

    return result.body.hits.hits.map(hit => ({
      ...hit._source,
      _tier: 'hot',
      _id: hit._id,
      _index: hit._index
    }));
  }

  async queryWarmTier(queryParams) {
    const client = this.clients.get('clickhouse');
    const { timeRange, filters, limit = 100 } = queryParams;
    
    let whereClause = '1=1';
    const params = [];

    if (timeRange) {
      whereClause += ' AND timestamp >= ? AND timestamp <= ?';
      params.push(timeRange.start, timeRange.end);
    }

    if (filters) {
      for (const [field, value] of Object.entries(filters)) {
        whereClause += ` AND ${field} = ?`;
        params.push(value);
      }
    }

    const query = `
      SELECT * FROM ${this.config.tiers.warm.clickhouse.table}
      WHERE ${whereClause}
      ORDER BY timestamp DESC
      LIMIT ${limit}
    `;

    const result = await client.query(query, { params });
    
    return result.data.map(row => ({
      ...row,
      _tier: 'warm',
      attributes: JSON.parse(row.attributes || '{}')
    }));
  }

  async queryColdTier(queryParams) {
    // Mock cold tier query - implement actual S3 query
    this.logger.info('Querying cold tier (S3)');
    return [];
  }

  /**
   * Get storage statistics
   */
  getStats() {
    return {
      ...this.stats,
      tiers: {
        hot: {
          enabled: this.config.tiers.hot.enabled,
          retention: this.config.tiers.hot.retention,
          connected: this.clients.has('elasticsearch')
        },
        warm: {
          enabled: this.config.tiers.warm.enabled,
          retention: this.config.tiers.warm.retention,
          connected: this.clients.has('clickhouse')
        },
        cold: {
          enabled: this.config.tiers.cold.enabled,
          retention: this.config.tiers.cold.retention,
          connected: true // Mock
        }
      },
      cache: {
        enabled: this.config.cache.enabled,
        connected: this.cache !== null
      }
    };
  }

  async shutdown() {
    for (const [name, client] of this.clients) {
      try {
        if (name === 'elasticsearch') {
          await client.close();
        }
        // ClickHouse doesn't need explicit close
      } catch (error) {
        this.logger.error(`Error closing ${name} client:`, error);
      }
    }

    if (this.cache) {
      this.cache.disconnect();
    }

    this.logger.info('Storage Manager shutdown completed');
    this.emit('shutdown');
  }
}

export { StorageManager };
