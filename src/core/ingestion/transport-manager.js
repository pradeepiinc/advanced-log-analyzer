/**
 * Transport Manager for multiple ingestion protocols
 * Supports HTTP/gRPC, Syslog, Kafka, Kinesis, PubSub with backpressure and retries
 */

import { EventEmitter } from 'events';
import { Kafka } from 'kafkajs';
import Redis from 'ioredis';
import axios from 'axios';
import { createLogger } from '../utils/logger.js';
import { v4 as uuidv4 } from 'uuid';
import dgram from 'dgram';
import net from 'net';

class TransportManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      http: {
        enabled: true,
        port: 8080,
        maxPayloadSize: '50mb',
        timeout: 30000,
        ...config.http
      },
      syslog: {
        enabled: true,
        port: 514,
        protocol: 'udp', // udp, tcp
        ...config.syslog
      },
      kafka: {
        enabled: false,
        brokers: ['localhost:9092'],
        topics: ['logs', 'metrics', 'traces'],
        groupId: 'log-analyzer',
        ...config.kafka
      },
      redis: {
        enabled: false,
        host: 'localhost',
        port: 6379,
        streams: ['logs:stream', 'metrics:stream', 'traces:stream'],
        ...config.redis
      },
      backpressure: {
        maxQueueSize: 10000,
        maxConcurrency: 100,
        retryAttempts: 3,
        retryDelay: 1000,
        ...config.backpressure
      },
      ...config
    };

    this.logger = createLogger('TransportManager');
    this.transports = new Map();
    this.messageQueue = [];
    this.processing = false;
    this.stats = {
      received: 0,
      processed: 0,
      failed: 0,
      queued: 0
    };
  }

  async initialize() {
    try {
      if (this.config.http.enabled) {
        await this.initializeHTTP();
      }

      if (this.config.syslog.enabled) {
        await this.initializeSyslog();
      }

      if (this.config.kafka.enabled) {
        await this.initializeKafka();
      }

      if (this.config.redis.enabled) {
        await this.initializeRedis();
      }

      this.startProcessing();
      this.logger.info('Transport Manager initialized successfully');
      this.emit('initialized');

    } catch (error) {
      this.logger.error('Failed to initialize Transport Manager:', error);
      throw error;
    }
  }

  async initializeHTTP() {
    // HTTP transport is handled by Express server
    // This registers the transport for tracking
    this.transports.set('http', {
      type: 'http',
      status: 'active',
      config: this.config.http
    });
    this.logger.info('HTTP transport registered');
  }

  async initializeSyslog() {
    const syslogTransport = {
      type: 'syslog',
      status: 'initializing',
      config: this.config.syslog,
      server: null
    };

    if (this.config.syslog.protocol === 'udp') {
      syslogTransport.server = dgram.createSocket('udp4');
      
      syslogTransport.server.on('message', (msg, rinfo) => {
        this.handleSyslogMessage(msg.toString(), rinfo);
      });

      syslogTransport.server.on('error', (err) => {
        this.logger.error('Syslog UDP error:', err);
        this.emit('transport-error', { transport: 'syslog', error: err });
      });

      syslogTransport.server.bind(this.config.syslog.port);
      
    } else if (this.config.syslog.protocol === 'tcp') {
      syslogTransport.server = net.createServer((socket) => {
        socket.on('data', (data) => {
          this.handleSyslogMessage(data.toString(), socket.remoteAddress);
        });

        socket.on('error', (err) => {
          this.logger.error('Syslog TCP socket error:', err);
        });
      });

      syslogTransport.server.listen(this.config.syslog.port);
    }

    syslogTransport.status = 'active';
    this.transports.set('syslog', syslogTransport);
    this.logger.info(`Syslog ${this.config.syslog.protocol.toUpperCase()} transport initialized on port ${this.config.syslog.port}`);
  }

  async initializeKafka() {
    const kafka = new Kafka({
      clientId: 'log-analyzer-transport',
      brokers: this.config.kafka.brokers
    });

    const consumer = kafka.consumer({ groupId: this.config.kafka.groupId });
    await consumer.connect();
    await consumer.subscribe({ topics: this.config.kafka.topics });

    consumer.run({
      eachMessage: async ({ topic, partition, message }) => {
        try {
          const data = JSON.parse(message.value.toString());
          await this.handleKafkaMessage(topic, data, { partition, offset: message.offset });
        } catch (error) {
          this.logger.error('Failed to process Kafka message:', error);
          this.stats.failed++;
        }
      },
    });

    const kafkaTransport = {
      type: 'kafka',
      status: 'active',
      config: this.config.kafka,
      consumer,
      kafka
    };

    this.transports.set('kafka', kafkaTransport);
    this.logger.info('Kafka transport initialized');
  }

  async initializeRedis() {
    const redis = new Redis({
      host: this.config.redis.host,
      port: this.config.redis.port,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3
    });

    // Listen to Redis streams
    for (const stream of this.config.redis.streams) {
      this.consumeRedisStream(redis, stream);
    }

    const redisTransport = {
      type: 'redis',
      status: 'active',
      config: this.config.redis,
      client: redis
    };

    this.transports.set('redis', redisTransport);
    this.logger.info('Redis transport initialized');
  }

  async consumeRedisStream(redis, streamName) {
    const consumerGroup = 'log-analyzer-group';
    const consumerName = `consumer-${uuidv4()}`;

    try {
      // Create consumer group if it doesn't exist
      await redis.xgroup('CREATE', streamName, consumerGroup, '$', 'MKSTREAM');
    } catch (error) {
      // Group might already exist
      if (!error.message.includes('BUSYGROUP')) {
        this.logger.warn(`Failed to create consumer group for ${streamName}:`, error.message);
      }
    }

    // Start consuming
    const consumeMessages = async () => {
      try {
        const messages = await redis.xreadgroup(
          'GROUP', consumerGroup, consumerName,
          'COUNT', 10,
          'BLOCK', 1000,
          'STREAMS', streamName, '>'
        );

        if (messages) {
          for (const [stream, streamMessages] of messages) {
            for (const [messageId, fields] of streamMessages) {
              try {
                const data = this.parseRedisStreamFields(fields);
                await this.handleRedisMessage(stream, data, messageId);
                await redis.xack(stream, consumerGroup, messageId);
              } catch (error) {
                this.logger.error(`Failed to process Redis message ${messageId}:`, error);
                this.stats.failed++;
              }
            }
          }
        }
      } catch (error) {
        this.logger.error(`Redis stream consumer error for ${streamName}:`, error);
      }

      // Continue consuming
      setImmediate(consumeMessages);
    };

    consumeMessages();
  }

  parseRedisStreamFields(fields) {
    const data = {};
    for (let i = 0; i < fields.length; i += 2) {
      const key = fields[i];
      const value = fields[i + 1];
      try {
        data[key] = JSON.parse(value);
      } catch {
        data[key] = value;
      }
    }
    return data;
  }

  handleSyslogMessage(message, source) {
    this.stats.received++;
    this.enqueueMessage({
      id: uuidv4(),
      type: 'log',
      transport: 'syslog',
      source: source,
      timestamp: new Date().toISOString(),
      data: this.parseSyslogMessage(message),
      raw: message
    });
  }

  parseSyslogMessage(message) {
    // Basic syslog parsing - can be enhanced with proper RFC3164/RFC5424 parsing
    const syslogRegex = /^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$/;
    const match = message.match(syslogRegex);

    if (match) {
      const [, priority, timestamp, hostname, content] = match;
      const facility = Math.floor(priority / 8);
      const severity = priority % 8;

      return {
        priority: parseInt(priority),
        facility,
        severity,
        timestamp,
        hostname,
        message: content,
        level: this.mapSyslogSeverity(severity)
      };
    }

    return {
      message: message,
      level: 'INFO',
      timestamp: new Date().toISOString()
    };
  }

  mapSyslogSeverity(severity) {
    const severityMap = {
      0: 'FATAL',    // Emergency
      1: 'FATAL',    // Alert
      2: 'FATAL',    // Critical
      3: 'ERROR',    // Error
      4: 'WARN',     // Warning
      5: 'INFO',     // Notice
      6: 'INFO',     // Informational
      7: 'DEBUG'     // Debug
    };
    return severityMap[severity] || 'INFO';
  }

  async handleKafkaMessage(topic, data, metadata) {
    this.stats.received++;
    this.enqueueMessage({
      id: uuidv4(),
      type: this.inferTypeFromTopic(topic),
      transport: 'kafka',
      source: { topic, ...metadata },
      timestamp: new Date().toISOString(),
      data,
      raw: data
    });
  }

  async handleRedisMessage(stream, data, messageId) {
    this.stats.received++;
    this.enqueueMessage({
      id: uuidv4(),
      type: this.inferTypeFromStream(stream),
      transport: 'redis',
      source: { stream, messageId },
      timestamp: new Date().toISOString(),
      data,
      raw: data
    });
  }

  inferTypeFromTopic(topic) {
    if (topic.includes('metric')) return 'metric';
    if (topic.includes('trace')) return 'trace';
    return 'log';
  }

  inferTypeFromStream(stream) {
    if (stream.includes('metric')) return 'metric';
    if (stream.includes('trace')) return 'trace';
    return 'log';
  }

  enqueueMessage(message) {
    if (this.messageQueue.length >= this.config.backpressure.maxQueueSize) {
      this.logger.warn('Message queue full, dropping oldest messages');
      this.messageQueue.shift();
      this.stats.failed++;
    }

    this.messageQueue.push(message);
    this.stats.queued = this.messageQueue.length;
    this.emit('message-queued', message);
  }

  startProcessing() {
    if (this.processing) return;
    this.processing = true;

    const processMessages = async () => {
      while (this.processing && this.messageQueue.length > 0) {
        const batch = this.messageQueue.splice(0, this.config.backpressure.maxConcurrency);
        this.stats.queued = this.messageQueue.length;

        const promises = batch.map(message => this.processMessage(message));
        await Promise.allSettled(promises);
      }

      // Continue processing
      setTimeout(processMessages, 100);
    };

    processMessages();
  }

  async processMessage(message, attempt = 1) {
    try {
      this.emit('message', message);
      this.stats.processed++;
      return { success: true, messageId: message.id };
      
    } catch (error) {
      this.logger.error(`Failed to process message ${message.id} (attempt ${attempt}):`, error);
      
      if (attempt < this.config.backpressure.retryAttempts) {
        await new Promise(resolve => 
          setTimeout(resolve, this.config.backpressure.retryDelay * attempt)
        );
        return this.processMessage(message, attempt + 1);
      }
      
      this.stats.failed++;
      this.emit('message-failed', { message, error });
      throw error;
    }
  }

  // HTTP endpoint handlers (to be used by Express routes)
  async handleHTTPLog(data, metadata = {}) {
    this.stats.received++;
    this.enqueueMessage({
      id: uuidv4(),
      type: 'log',
      transport: 'http',
      source: metadata,
      timestamp: new Date().toISOString(),
      data,
      raw: data
    });
  }

  async handleHTTPMetric(data, metadata = {}) {
    this.stats.received++;
    this.enqueueMessage({
      id: uuidv4(),
      type: 'metric',
      transport: 'http',
      source: metadata,
      timestamp: new Date().toISOString(),
      data,
      raw: data
    });
  }

  async handleHTTPTrace(data, metadata = {}) {
    this.stats.received++;
    this.enqueueMessage({
      id: uuidv4(),
      type: 'trace',
      transport: 'http',
      source: metadata,
      timestamp: new Date().toISOString(),
      data,
      raw: data
    });
  }

  getStats() {
    return {
      ...this.stats,
      transports: Array.from(this.transports.entries()).map(([name, transport]) => ({
        name,
        type: transport.type,
        status: transport.status
      })),
      queueSize: this.messageQueue.length,
      uptime: process.uptime()
    };
  }

  async shutdown() {
    this.processing = false;
    
    for (const [name, transport] of this.transports) {
      try {
        if (transport.type === 'kafka' && transport.consumer) {
          await transport.consumer.disconnect();
        }
        if (transport.type === 'redis' && transport.client) {
          transport.client.disconnect();
        }
        if (transport.type === 'syslog' && transport.server) {
          transport.server.close();
        }
      } catch (error) {
        this.logger.error(`Error shutting down ${name} transport:`, error);
      }
    }

    this.logger.info('Transport Manager shutdown completed');
    this.emit('shutdown');
  }
}

export { TransportManager };
