/**
 * Advanced Query Engine with DSL, SQL, and regex support
 * Google-like search with fielded queries, time-shift, and saved searches
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import moment from 'moment';
import { v4 as uuidv4 } from 'uuid';

class QueryEngine extends EventEmitter {
  constructor(storageManager, config = {}) {
    super();
    this.storageManager = storageManager;
    this.config = {
      maxResults: config.maxResults || 10000,
      defaultTimeRange: config.defaultTimeRange || '24h',
      enableRegex: config.enableRegex !== false,
      enableSql: config.enableSql !== false,
      cacheResults: config.cacheResults !== false,
      cacheTtl: config.cacheTtl || 300, // 5 minutes
      ...config
    };

    this.logger = createLogger('QueryEngine');
    this.savedQueries = new Map();
    this.queryCache = new Map();
    this.queryStats = {
      total: 0,
      cached: 0,
      errors: 0,
      avgLatency: 0
    };
  }

  /**
   * Execute query with automatic format detection
   */
  async executeQuery(queryString, options = {}) {
    const startTime = Date.now();
    const queryId = uuidv4();
    
    try {
      this.logger.info(`Executing query ${queryId}: ${queryString}`);
      
      // Parse query and determine type
      const parsedQuery = this.parseQuery(queryString, options);
      
      // Check cache first
      const cacheKey = this.generateCacheKey(parsedQuery, options);
      if (this.config.cacheResults && this.queryCache.has(cacheKey)) {
        this.queryStats.cached++;
        const cached = this.queryCache.get(cacheKey);
        this.logger.debug(`Cache hit for query ${queryId}`);
        return { ...cached, fromCache: true, queryId };
      }
      
      // Execute query based on type
      let results;
      switch (parsedQuery.type) {
        case 'dsl':
          results = await this.executeDSLQuery(parsedQuery, options);
          break;
        case 'sql':
          results = await this.executeSQLQuery(parsedQuery, options);
          break;
        case 'fulltext':
          results = await this.executeFullTextQuery(parsedQuery, options);
          break;
        case 'fielded':
          results = await this.executeFieldedQuery(parsedQuery, options);
          break;
        default:
          results = await this.executeFullTextQuery(parsedQuery, options);
      }
      
      // Add query metadata
      const response = {
        queryId,
        query: parsedQuery,
        results: results.hits || results,
        total: results.total || results.length,
        took: Date.now() - startTime,
        fromCache: false,
        aggregations: results.aggregations,
        facets: results.facets
      };
      
      // Cache results
      if (this.config.cacheResults && response.total < 1000) {
        this.queryCache.set(cacheKey, response);
        setTimeout(() => this.queryCache.delete(cacheKey), this.config.cacheTtl * 1000);
      }
      
      // Update stats
      this.queryStats.total++;
      this.queryStats.avgLatency = (this.queryStats.avgLatency + response.took) / 2;
      
      this.emit('query-executed', response);
      return response;
      
    } catch (error) {
      this.queryStats.errors++;
      this.logger.error(`Query ${queryId} failed:`, error);
      this.emit('query-error', { queryId, error, query: queryString });
      throw error;
    }
  }

  /**
   * Parse query string and determine type
   */
  parseQuery(queryString, options = {}) {
    const trimmed = queryString.trim();
    
    // SQL query detection
    if (this.config.enableSql && /^(SELECT|WITH|SHOW)\s+/i.test(trimmed)) {
      return {
        type: 'sql',
        raw: queryString,
        sql: trimmed
      };
    }
    
    // DSL query detection (JSON-like)
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const dsl = JSON.parse(trimmed);
        return {
          type: 'dsl',
          raw: queryString,
          dsl
        };
      } catch (error) {
        // Not valid JSON, treat as text
      }
    }
    
    // Fielded query detection (field:value pairs)
    if (this.containsFieldedSyntax(trimmed)) {
      return {
        type: 'fielded',
        raw: queryString,
        ...this.parseFieldedQuery(trimmed, options)
      };
    }
    
    // Default to full-text search
    return {
      type: 'fulltext',
      raw: queryString,
      text: trimmed,
      timeRange: this.parseTimeRange(options.timeRange || this.config.defaultTimeRange)
    };
  }

  containsFieldedSyntax(query) {
    // Check for field:value patterns
    return /\w+:\S+/.test(query) || 
           /\w+\s*[><=!]+\s*\S+/.test(query) ||
           /\w+\s+IN\s+\[/.test(query);
  }

  parseFieldedQuery(query, options = {}) {
    const fields = {};
    const filters = [];
    const textParts = [];
    
    // Parse field:value pairs
    const fieldRegex = /(\w+):((?:"[^"]*")|(?:\[[^\]]*\])|(?:\S+))/g;
    let match;
    let lastIndex = 0;
    
    while ((match = fieldRegex.exec(query)) !== null) {
      // Add text before this match
      if (match.index > lastIndex) {
        textParts.push(query.substring(lastIndex, match.index).trim());
      }
      
      const [, field, value] = match;
      fields[field] = this.parseFieldValue(value);
      lastIndex = match.index + match[0].length;
    }
    
    // Add remaining text
    if (lastIndex < query.length) {
      textParts.push(query.substring(lastIndex).trim());
    }
    
    // Parse comparison operators
    const comparisonRegex = /(\w+)\s*([><=!]+)\s*(\S+)/g;
    while ((match = comparisonRegex.exec(query)) !== null) {
      const [, field, operator, value] = match;
      filters.push({
        field,
        operator: this.normalizeOperator(operator),
        value: this.parseFieldValue(value)
      });
    }
    
    // Parse IN clauses
    const inRegex = /(\w+)\s+IN\s+\[([^\]]+)\]/gi;
    while ((match = inRegex.exec(query)) !== null) {
      const [, field, values] = match;
      fields[field] = values.split(',').map(v => v.trim().replace(/['"]/g, ''));
    }
    
    return {
      fields,
      filters,
      text: textParts.filter(t => t).join(' '),
      timeRange: this.parseTimeRange(options.timeRange || this.config.defaultTimeRange)
    };
  }

  parseFieldValue(value) {
    // Remove quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      return value.slice(1, -1);
    }
    
    // Parse arrays
    if (value.startsWith('[') && value.endsWith(']')) {
      return value.slice(1, -1).split(',').map(v => v.trim().replace(/['"]/g, ''));
    }
    
    // Parse numbers
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    if (/^\d*\.\d+$/.test(value)) return parseFloat(value);
    
    // Parse booleans
    if (value === 'true') return true;
    if (value === 'false') return false;
    
    return value;
  }

  normalizeOperator(operator) {
    const opMap = {
      '=': 'eq',
      '==': 'eq',
      '!=': 'ne',
      '<>': 'ne',
      '>': 'gt',
      '>=': 'gte',
      '<': 'lt',
      '<=': 'lte'
    };
    return opMap[operator] || operator;
  }

  parseTimeRange(timeRange) {
    if (!timeRange) return null;
    
    if (typeof timeRange === 'object' && timeRange.start && timeRange.end) {
      return timeRange;
    }
    
    // Parse relative time ranges (e.g., "24h", "7d", "1w")
    const relativeMatch = timeRange.match(/^(\d+)([hdwmy])$/);
    if (relativeMatch) {
      const [, value, unit] = relativeMatch;
      const duration = parseInt(value);
      const end = moment();
      const start = moment().subtract(duration, unit);
      
      return {
        start: start.toISOString(),
        end: end.toISOString()
      };
    }
    
    // Parse absolute time ranges
    const parts = timeRange.split(' TO ');
    if (parts.length === 2) {
      return {
        start: moment(parts[0]).toISOString(),
        end: moment(parts[1]).toISOString()
      };
    }
    
    return null;
  }

  /**
   * Execute DSL query (Elasticsearch-like)
   */
  async executeDSLQuery(parsedQuery, options = {}) {
    const { dsl } = parsedQuery;
    
    // Convert DSL to storage manager query
    const queryParams = {
      timeRange: this.extractTimeRangeFromDSL(dsl),
      filters: this.extractFiltersFromDSL(dsl),
      limit: options.limit || this.config.maxResults,
      offset: options.offset || 0
    };
    
    const results = await this.storageManager.query(queryParams);
    
    return {
      hits: results,
      total: results.length,
      aggregations: await this.executeAggregations(dsl.aggs, results)
    };
  }

  /**
   * Execute SQL query
   */
  async executeSQLQuery(parsedQuery, options = {}) {
    const { sql } = parsedQuery;
    
    // Parse SQL to extract components
    const sqlParts = this.parseSQL(sql);
    
    const queryParams = {
      timeRange: sqlParts.timeRange,
      filters: sqlParts.filters,
      limit: sqlParts.limit || options.limit || this.config.maxResults,
      offset: sqlParts.offset || options.offset || 0
    };
    
    const results = await this.storageManager.query(queryParams);
    
    // Apply SQL-specific transformations
    return {
      hits: this.applySQLProjection(results, sqlParts.select),
      total: results.length
    };
  }

  parseSQL(sql) {
    // Basic SQL parsing - can be enhanced with proper SQL parser
    const parts = {
      select: ['*'],
      filters: {},
      timeRange: null,
      limit: null,
      offset: null
    };
    
    // Extract SELECT clause
    const selectMatch = sql.match(/SELECT\s+(.*?)\s+FROM/i);
    if (selectMatch) {
      parts.select = selectMatch[1].split(',').map(s => s.trim());
    }
    
    // Extract WHERE clause
    const whereMatch = sql.match(/WHERE\s+(.*?)(?:\s+ORDER|\s+GROUP|\s+LIMIT|$)/i);
    if (whereMatch) {
      parts.filters = this.parseWhereClause(whereMatch[1]);
    }
    
    // Extract LIMIT
    const limitMatch = sql.match(/LIMIT\s+(\d+)/i);
    if (limitMatch) {
      parts.limit = parseInt(limitMatch[1], 10);
    }
    
    // Extract OFFSET
    const offsetMatch = sql.match(/OFFSET\s+(\d+)/i);
    if (offsetMatch) {
      parts.offset = parseInt(offsetMatch[1], 10);
    }
    
    return parts;
  }

  parseWhereClause(whereClause) {
    const filters = {};
    
    // Simple parsing for common patterns
    const conditions = whereClause.split(/\s+AND\s+/i);
    
    for (const condition of conditions) {
      const match = condition.match(/(\w+)\s*([><=!]+)\s*'?([^']+)'?/);
      if (match) {
        const [, field, operator, value] = match;
        filters[field] = { operator: this.normalizeOperator(operator), value };
      }
    }
    
    return filters;
  }

  applySQLProjection(results, selectFields) {
    if (selectFields.includes('*')) {
      return results;
    }
    
    return results.map(result => {
      const projected = {};
      for (const field of selectFields) {
        if (result[field] !== undefined) {
          projected[field] = result[field];
        }
      }
      return projected;
    });
  }

  /**
   * Execute full-text search
   */
  async executeFullTextQuery(parsedQuery, options = {}) {
    const { text, timeRange } = parsedQuery;
    
    const queryParams = {
      timeRange,
      filters: { message: text }, // Simple text search
      limit: options.limit || this.config.maxResults,
      offset: options.offset || 0
    };
    
    const results = await this.storageManager.query(queryParams);
    
    // Apply text relevance scoring
    const scoredResults = this.scoreTextResults(results, text);
    
    return {
      hits: scoredResults,
      total: results.length,
      facets: await this.generateFacets(results)
    };
  }

  /**
   * Execute fielded query
   */
  async executeFieldedQuery(parsedQuery, options = {}) {
    const { fields, filters, text, timeRange } = parsedQuery;
    
    const queryParams = {
      timeRange,
      filters: { ...fields },
      limit: options.limit || this.config.maxResults,
      offset: options.offset || 0
    };
    
    // Add text search if present
    if (text) {
      queryParams.filters.message = text;
    }
    
    const results = await this.storageManager.query(queryParams);
    
    return {
      hits: results,
      total: results.length,
      facets: await this.generateFacets(results)
    };
  }

  scoreTextResults(results, searchText) {
    const terms = searchText.toLowerCase().split(/\s+/);
    
    return results.map(result => {
      let score = 0;
      const message = (result.message || '').toLowerCase();
      
      // Simple TF scoring
      for (const term of terms) {
        const occurrences = (message.match(new RegExp(term, 'g')) || []).length;
        score += occurrences;
      }
      
      return { ...result, _score: score };
    }).sort((a, b) => b._score - a._score);
  }

  async generateFacets(results) {
    const facets = {};
    const facetFields = ['level', 'service', 'environment', 'status_code'];
    
    for (const field of facetFields) {
      const counts = {};
      for (const result of results) {
        const value = result[field];
        if (value !== undefined) {
          counts[value] = (counts[value] || 0) + 1;
        }
      }
      
      facets[field] = Object.entries(counts)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([value, count]) => ({ value, count }));
    }
    
    return facets;
  }

  /**
   * Save query for reuse
   */
  saveQuery(name, queryString, options = {}) {
    const savedQuery = {
      id: uuidv4(),
      name,
      query: queryString,
      options,
      created: new Date().toISOString(),
      lastUsed: null,
      useCount: 0
    };
    
    this.savedQueries.set(name, savedQuery);
    this.logger.info(`Saved query: ${name}`);
    
    return savedQuery;
  }

  /**
   * Get saved query
   */
  getSavedQuery(name) {
    const query = this.savedQueries.get(name);
    if (query) {
      query.lastUsed = new Date().toISOString();
      query.useCount++;
    }
    return query;
  }

  /**
   * List saved queries
   */
  listSavedQueries() {
    return Array.from(this.savedQueries.values())
      .sort((a, b) => new Date(b.created) - new Date(a.created));
  }

  generateCacheKey(parsedQuery, options) {
    return JSON.stringify({ query: parsedQuery, options });
  }

  extractTimeRangeFromDSL(dsl) {
    // Extract time range from Elasticsearch DSL
    if (dsl.query?.bool?.filter) {
      for (const filter of dsl.query.bool.filter) {
        if (filter.range?.timestamp || filter.range?.['@timestamp']) {
          const range = filter.range.timestamp || filter.range['@timestamp'];
          return {
            start: range.gte || range.from,
            end: range.lte || range.to
          };
        }
      }
    }
    return null;
  }

  extractFiltersFromDSL(dsl) {
    const filters = {};
    
    if (dsl.query?.bool?.filter) {
      for (const filter of dsl.query.bool.filter) {
        if (filter.term) {
          Object.assign(filters, filter.term);
        }
        if (filter.terms) {
          Object.assign(filters, filter.terms);
        }
      }
    }
    
    return filters;
  }

  async executeAggregations(aggs, results) {
    if (!aggs) return null;
    
    const aggregations = {};
    
    for (const [name, agg] of Object.entries(aggs)) {
      if (agg.terms) {
        aggregations[name] = this.executeTermsAggregation(agg.terms, results);
      } else if (agg.date_histogram) {
        aggregations[name] = this.executeDateHistogram(agg.date_histogram, results);
      }
    }
    
    return aggregations;
  }

  executeTermsAggregation(terms, results) {
    const { field, size = 10 } = terms;
    const buckets = {};
    
    for (const result of results) {
      const value = result[field];
      if (value !== undefined) {
        buckets[value] = (buckets[value] || 0) + 1;
      }
    }
    
    return {
      buckets: Object.entries(buckets)
        .sort(([,a], [,b]) => b - a)
        .slice(0, size)
        .map(([key, doc_count]) => ({ key, doc_count }))
    };
  }

  executeDateHistogram(dateHisto, results) {
    const { field, interval } = dateHisto;
    const buckets = {};
    
    for (const result of results) {
      const timestamp = result[field];
      if (timestamp) {
        const bucket = moment(timestamp).startOf(interval).toISOString();
        buckets[bucket] = (buckets[bucket] || 0) + 1;
      }
    }
    
    return {
      buckets: Object.entries(buckets)
        .sort(([a], [b]) => new Date(a) - new Date(b))
        .map(([key, doc_count]) => ({ key, doc_count }))
    };
  }

  getStats() {
    return {
      ...this.queryStats,
      savedQueries: this.savedQueries.size,
      cacheSize: this.queryCache.size,
      config: {
        maxResults: this.config.maxResults,
        enableRegex: this.config.enableRegex,
        enableSql: this.config.enableSql,
        cacheResults: this.config.cacheResults
      }
    };
  }

  clearCache() {
    this.queryCache.clear();
    this.logger.info('Query cache cleared');
  }
}

export { QueryEngine };
