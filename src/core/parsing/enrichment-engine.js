/**
 * Advanced Parsing and Enrichment Engine
 * Supports JSON, logfmt, regex/grok, multiline parsing with PII detection and enrichment
 */

import { EventEmitter } from 'events';
import grok from 'grok-js';
import moment from 'moment-timezone';
import { v4 as uuidv4 } from 'uuid';
import { createLogger } from '../utils/logger.js';
import natural from 'natural';
import crypto from 'crypto';

class EnrichmentEngine extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      timezone: config.timezone || 'UTC',
      enablePiiDetection: config.enablePiiDetection !== false,
      piiRedactionMode: config.piiRedactionMode || 'hash', // hash, mask, remove
      enableGeoEnrichment: config.enableGeoEnrichment !== false,
      enableUserSessionEnrichment: config.enableUserSessionEnrichment !== false,
      multilinePatterns: config.multilinePatterns || [],
      customGrokPatterns: config.customGrokPatterns || {},
      enrichmentSources: config.enrichmentSources || {},
      ...config
    };

    this.logger = createLogger('EnrichmentEngine');
    this.grokPatterns = new Map();
    this.piiPatterns = new Map();
    this.multilineBuffers = new Map();
    this.enrichmentCache = new Map();
    
    this.initializePatterns();
    this.initializePiiDetection();
  }

  initializePatterns() {
    // Common log format patterns
    const commonPatterns = {
      APACHE_COMMON: '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)',
      NGINX_ACCESS: '%{IPORHOST:remote_addr} - %{DATA:remote_user} \\[%{HTTPDATE:time_local}\\] "%{WORD:method} %{URIPATH:path}(?:%{URIPARAM:params})? HTTP/%{NUMBER:http_version}" %{INT:status} %{INT:body_bytes_sent} "%{DATA:http_referer}" "%{DATA:http_user_agent}"',
      JAVA_STACKTRACE: '(?m)^%{TIMESTAMP_ISO8601:timestamp}\\s+%{LOGLEVEL:level}\\s+\\[%{DATA:thread}\\]\\s+%{JAVACLASS:class}\\s*:\\s*%{GREEDYDATA:message}',
      SYSLOG: '%{SYSLOGTIMESTAMP:timestamp} (?:%{IPORHOST:logsource} )?%{PROG:program}(?:\\[%{POSINT:pid}\\])?:\\s*%{GREEDYDATA:message}',
      JSON_LOG: '\\{.*\\}',
      KUBERNETES: '%{TIMESTAMP_ISO8601:timestamp} %{WORD:stream} %{WORD:log_type} %{GREEDYDATA:message}',
      DOCKER: '%{TIMESTAMP_ISO8601:timestamp} %{WORD:level} %{GREEDYDATA:message}',
      ...this.config.customGrokPatterns
    };

    for (const [name, pattern] of Object.entries(commonPatterns)) {
      try {
        this.grokPatterns.set(name, grok(pattern));
      } catch (error) {
        this.logger.warn(`Failed to compile grok pattern ${name}:`, error.message);
      }
    }
  }

  initializePiiDetection() {
    // PII detection patterns
    const piiPatterns = {
      EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      PHONE: /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
      SSN: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
      CREDIT_CARD: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      IP_ADDRESS: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
      MAC_ADDRESS: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g,
      API_KEY: /\b[A-Za-z0-9]{32,}\b/g,
      JWT_TOKEN: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/g,
      UUID: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
      PASSWORD: /(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s]+/g,
      USERNAME: /(?i)\b(?:username|user|login)\s*[:=]\s*[^\s]+/g
    };

    for (const [name, pattern] of Object.entries(piiPatterns)) {
      this.piiPatterns.set(name, pattern);
    }
  }

  /**
   * Parse and enrich log entry
   */
  async parseAndEnrich(logEntry) {
    try {
      const startTime = Date.now();
      
      // Step 1: Parse the log entry
      const parsed = await this.parseLogEntry(logEntry);
      
      // Step 2: Handle multiline logs
      const processed = await this.handleMultiline(parsed);
      if (!processed) {
        return null; // Still buffering multiline
      }
      
      // Step 3: Extract and normalize timestamp
      processed.timestamp = this.normalizeTimestamp(processed.timestamp || processed.time);
      
      // Step 4: Extract log level
      processed.level = this.extractLogLevel(processed);
      
      // Step 5: PII detection and redaction
      if (this.config.enablePiiDetection) {
        processed.pii = this.detectAndRedactPii(processed);
      }
      
      // Step 6: Static enrichment
      await this.applyStaticEnrichment(processed);
      
      // Step 7: Dynamic enrichment
      await this.applyDynamicEnrichment(processed);
      
      // Step 8: Add processing metadata
      processed._enrichment = {
        processingTime: Date.now() - startTime,
        engineVersion: '2.0.0',
        timestamp: new Date().toISOString()
      };
      
      this.emit('enriched', processed);
      return processed;
      
    } catch (error) {
      this.logger.error('Failed to parse and enrich log entry:', error);
      this.emit('error', { error, logEntry });
      throw error;
    }
  }

  /**
   * Parse log entry using various formats
   */
  async parseLogEntry(logEntry) {
    const raw = typeof logEntry === 'string' ? logEntry : JSON.stringify(logEntry);
    
    // Try JSON parsing first
    if (raw.trim().startsWith('{')) {
      try {
        const jsonParsed = JSON.parse(raw);
        return {
          ...jsonParsed,
          _format: 'json',
          _raw: raw
        };
      } catch (error) {
        // Not valid JSON, continue with other parsers
      }
    }
    
    // Try grok patterns
    for (const [name, pattern] of this.grokPatterns) {
      try {
        const match = pattern.parse(raw);
        if (match) {
          return {
            ...match,
            _format: name.toLowerCase(),
            _raw: raw
          };
        }
      } catch (error) {
        // Pattern didn't match, continue
      }
    }
    
    // Try logfmt parsing
    const logfmtParsed = this.parseLogfmt(raw);
    if (logfmtParsed && Object.keys(logfmtParsed).length > 1) {
      return {
        ...logfmtParsed,
        _format: 'logfmt',
        _raw: raw
      };
    }
    
    // Fallback to raw message
    return {
      message: raw,
      _format: 'raw',
      _raw: raw
    };
  }

  /**
   * Parse logfmt format (key=value pairs)
   */
  parseLogfmt(text) {
    const result = {};
    const regex = /(\w+)=(?:"([^"]*)"|([^\s]+))/g;
    let match;
    
    while ((match = regex.exec(text)) !== null) {
      const key = match[1];
      const value = match[2] || match[3];
      result[key] = this.coerceValue(value);
    }
    
    return result;
  }

  /**
   * Coerce string values to appropriate types
   */
  coerceValue(value) {
    if (value === 'true') return true;
    if (value === 'false') return false;
    if (value === 'null') return null;
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    if (/^\d*\.\d+$/.test(value)) return parseFloat(value);
    return value;
  }

  /**
   * Handle multiline log entries (e.g., Java stack traces)
   */
  async handleMultiline(parsed) {
    const sourceKey = parsed._source || 'default';
    
    // Check if this looks like a multiline continuation
    const isMultilineContinuation = this.isMultilineContinuation(parsed);
    
    if (isMultilineContinuation && this.multilineBuffers.has(sourceKey)) {
      // Append to existing buffer
      const buffer = this.multilineBuffers.get(sourceKey);
      buffer.message += '\n' + (parsed.message || parsed._raw);
      buffer.lines.push(parsed);
      return null; // Still buffering
    }
    
    // Check if this starts a new multiline entry
    const isMultilineStart = this.isMultilineStart(parsed);
    
    if (isMultilineStart) {
      // Flush any existing buffer first
      const existingBuffer = this.multilineBuffers.get(sourceKey);
      if (existingBuffer) {
        this.multilineBuffers.delete(sourceKey);
        // Process the buffered entry
        setTimeout(() => this.emit('enriched', existingBuffer), 0);
      }
      
      // Start new buffer
      this.multilineBuffers.set(sourceKey, {
        ...parsed,
        lines: [parsed],
        _multiline: true
      });
      
      // Set timeout to flush buffer
      setTimeout(() => {
        if (this.multilineBuffers.has(sourceKey)) {
          const buffer = this.multilineBuffers.get(sourceKey);
          this.multilineBuffers.delete(sourceKey);
          this.emit('enriched', buffer);
        }
      }, 5000); // 5 second timeout
      
      return null; // Still buffering
    }
    
    return parsed;
  }

  isMultilineStart(parsed) {
    const message = parsed.message || parsed._raw || '';
    
    // Java exception patterns
    if (/Exception|Error|Caused by:|at\s+\w+\./i.test(message)) {
      return true;
    }
    
    // Custom multiline patterns
    for (const pattern of this.config.multilinePatterns) {
      if (new RegExp(pattern.start).test(message)) {
        return true;
      }
    }
    
    return false;
  }

  isMultilineContinuation(parsed) {
    const message = parsed.message || parsed._raw || '';
    
    // Java stack trace continuation
    if (/^\s+at\s+|^\s+\.\.\.\s+\d+\s+more|^\s+Caused by:/i.test(message)) {
      return true;
    }
    
    // Generic indented continuation
    if (/^\s+/.test(message)) {
      return true;
    }
    
    return false;
  }

  /**
   * Normalize timestamp to ISO format
   */
  normalizeTimestamp(timestamp) {
    if (!timestamp) {
      return new Date().toISOString();
    }
    
    try {
      // Try parsing with moment for various formats
      const parsed = moment.tz(timestamp, this.config.timezone);
      if (parsed.isValid()) {
        return parsed.utc().toISOString();
      }
    } catch (error) {
      this.logger.warn('Failed to parse timestamp:', timestamp);
    }
    
    return new Date().toISOString();
  }

  /**
   * Extract log level from various fields
   */
  extractLogLevel(parsed) {
    const levelFields = ['level', 'severity', 'loglevel', 'priority'];
    
    for (const field of levelFields) {
      if (parsed[field]) {
        return this.normalizeLogLevel(parsed[field]);
      }
    }
    
    // Try to extract from message
    const message = parsed.message || parsed._raw || '';
    const levelMatch = message.match(/\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b/i);
    if (levelMatch) {
      return this.normalizeLogLevel(levelMatch[1]);
    }
    
    return 'INFO';
  }

  normalizeLogLevel(level) {
    const levelMap = {
      'TRACE': 'TRACE',
      'DEBUG': 'DEBUG',
      'INFO': 'INFO',
      'INFORMATION': 'INFO',
      'WARN': 'WARN',
      'WARNING': 'WARN',
      'ERROR': 'ERROR',
      'ERR': 'ERROR',
      'FATAL': 'FATAL',
      'CRITICAL': 'FATAL',
      'CRIT': 'FATAL'
    };
    
    return levelMap[String(level).toUpperCase()] || 'INFO';
  }

  /**
   * Detect and redact PII information
   */
  detectAndRedactPii(parsed) {
    const piiFound = [];
    const redactedFields = {};
    
    const processField = (key, value) => {
      if (typeof value !== 'string') return value;
      
      let redactedValue = value;
      
      for (const [piiType, pattern] of this.piiPatterns) {
        const matches = value.match(pattern);
        if (matches) {
          piiFound.push({
            type: piiType,
            field: key,
            count: matches.length,
            positions: matches.map(match => value.indexOf(match))
          });
          
          // Apply redaction based on mode
          switch (this.config.piiRedactionMode) {
            case 'hash':
              redactedValue = redactedValue.replace(pattern, (match) => 
                `[${piiType}_${crypto.createHash('sha256').update(match).digest('hex').substring(0, 8)}]`
              );
              break;
            case 'mask':
              redactedValue = redactedValue.replace(pattern, (match) => 
                `[${piiType}_${'*'.repeat(Math.min(match.length, 8))}]`
              );
              break;
            case 'remove':
              redactedValue = redactedValue.replace(pattern, `[${piiType}_REDACTED]`);
              break;
          }
        }
      }
      
      if (redactedValue !== value) {
        redactedFields[key] = redactedValue;
      }
      
      return redactedValue;
    };
    
    // Process all string fields
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value === 'string') {
        parsed[key] = processField(key, value);
      } else if (typeof value === 'object' && value !== null) {
        // Recursively process nested objects
        for (const [nestedKey, nestedValue] of Object.entries(value)) {
          if (typeof nestedValue === 'string') {
            value[nestedKey] = processField(`${key}.${nestedKey}`, nestedValue);
          }
        }
      }
    }
    
    return {
      detected: piiFound,
      redacted: Object.keys(redactedFields).length > 0,
      redactedFields: redactedFields
    };
  }

  /**
   * Apply static enrichment (metadata, tags, etc.)
   */
  async applyStaticEnrichment(parsed) {
    // Add standard metadata
    parsed._enrichment = parsed._enrichment || {};
    parsed._enrichment.ingestionTime = new Date().toISOString();
    parsed._enrichment.source = 'enrichment-engine';
    
    // Extract service information
    if (!parsed.service && parsed.serviceName) {
      parsed.service = parsed.serviceName;
    }
    
    // Extract version information
    if (!parsed.version && (parsed.serviceVersion || parsed.app_version)) {
      parsed.version = parsed.serviceVersion || parsed.app_version;
    }
    
    // Extract environment
    if (!parsed.environment && (parsed.env || parsed.stage)) {
      parsed.environment = parsed.env || parsed.stage;
    }
    
    // Add computed fields
    parsed.hour = moment(parsed.timestamp).hour();
    parsed.dayOfWeek = moment(parsed.timestamp).day();
    parsed.isWeekend = parsed.dayOfWeek === 0 || parsed.dayOfWeek === 6;
    
    // Message analysis
    if (parsed.message) {
      parsed.messageLength = parsed.message.length;
      parsed.wordCount = parsed.message.split(/\s+/).length;
      
      // Sentiment analysis (basic)
      try {
        const sentiment = natural.SentimentAnalyzer.getSentiment(
          natural.WordTokenizer.tokenize(parsed.message)
            .map(token => natural.PorterStemmer.stem(token))
        );
        parsed.sentiment = sentiment;
      } catch (error) {
        // Sentiment analysis failed, skip
      }
    }
  }

  /**
   * Apply dynamic enrichment (external lookups, etc.)
   */
  async applyDynamicEnrichment(parsed) {
    // IP geolocation enrichment
    if (this.config.enableGeoEnrichment && parsed.clientip) {
      const geoData = await this.getGeoLocation(parsed.clientip);
      if (geoData) {
        parsed.geo = geoData;
      }
    }
    
    // User session enrichment
    if (this.config.enableUserSessionEnrichment && parsed.userId) {
      const sessionData = await this.getUserSession(parsed.userId);
      if (sessionData) {
        parsed.session = sessionData;
      }
    }
    
    // Service metadata enrichment
    if (parsed.service) {
      const serviceMetadata = await this.getServiceMetadata(parsed.service);
      if (serviceMetadata) {
        parsed.serviceMetadata = serviceMetadata;
      }
    }
  }

  async getGeoLocation(ip) {
    const cacheKey = `geo:${ip}`;
    
    if (this.enrichmentCache.has(cacheKey)) {
      return this.enrichmentCache.get(cacheKey);
    }
    
    try {
      // Mock geo enrichment - replace with actual service
      const geoData = {
        ip,
        country: 'US',
        region: 'CA',
        city: 'San Francisco',
        lat: 37.7749,
        lon: -122.4194,
        timezone: 'America/Los_Angeles'
      };
      
      this.enrichmentCache.set(cacheKey, geoData);
      return geoData;
      
    } catch (error) {
      this.logger.warn('Geo enrichment failed:', error.message);
      return null;
    }
  }

  async getUserSession(userId) {
    const cacheKey = `session:${userId}`;
    
    if (this.enrichmentCache.has(cacheKey)) {
      return this.enrichmentCache.get(cacheKey);
    }
    
    try {
      // Mock session enrichment - replace with actual service
      const sessionData = {
        userId,
        sessionId: uuidv4(),
        startTime: new Date().toISOString(),
        userAgent: 'Unknown',
        platform: 'web'
      };
      
      this.enrichmentCache.set(cacheKey, sessionData);
      return sessionData;
      
    } catch (error) {
      this.logger.warn('Session enrichment failed:', error.message);
      return null;
    }
  }

  async getServiceMetadata(serviceName) {
    const cacheKey = `service:${serviceName}`;
    
    if (this.enrichmentCache.has(cacheKey)) {
      return this.enrichmentCache.get(cacheKey);
    }
    
    try {
      // Mock service metadata - replace with actual service registry
      const serviceData = {
        name: serviceName,
        version: '1.0.0',
        team: 'platform',
        repository: `https://github.com/company/${serviceName}`,
        documentation: `https://docs.company.com/${serviceName}`
      };
      
      this.enrichmentCache.set(cacheKey, serviceData);
      return serviceData;
      
    } catch (error) {
      this.logger.warn('Service metadata enrichment failed:', error.message);
      return null;
    }
  }

  /**
   * Get engine statistics
   */
  getStats() {
    return {
      patternsLoaded: this.grokPatterns.size,
      piiPatternsLoaded: this.piiPatterns.size,
      multilineBuffers: this.multilineBuffers.size,
      cacheSize: this.enrichmentCache.size,
      config: {
        timezone: this.config.timezone,
        enablePiiDetection: this.config.enablePiiDetection,
        piiRedactionMode: this.config.piiRedactionMode,
        enableGeoEnrichment: this.config.enableGeoEnrichment,
        enableUserSessionEnrichment: this.config.enableUserSessionEnrichment
      }
    };
  }

  /**
   * Clear caches and buffers
   */
  clearCaches() {
    this.enrichmentCache.clear();
    this.multilineBuffers.clear();
    this.logger.info('Enrichment caches cleared');
  }
}

export { EnrichmentEngine };
