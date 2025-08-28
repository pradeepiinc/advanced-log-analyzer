/**
 * OpenTelemetry-first ingestion module
 * Supports logs, metrics, traces, and events with unified collection
 */

import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { logs, SeverityNumber } from '@opentelemetry/api-logs';
import { trace, metrics } from '@opentelemetry/api';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import { createLogger } from '../utils/logger.js';

class OTelCollector extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      serviceName: config.serviceName || 'production-log-analyzer',
      serviceVersion: config.serviceVersion || '2.0.0',
      environment: config.environment || 'production',
      jaegerEndpoint: config.jaegerEndpoint || 'http://localhost:14268/api/traces',
      prometheusPort: config.prometheusPort || 9464,
      enableAutoInstrumentation: config.enableAutoInstrumentation !== false,
      ...config
    };
    
    this.logger = createLogger('OTelCollector');
    this.sdk = null;
    this.tracer = null;
    this.meter = null;
    this.loggerProvider = null;
    this.isInitialized = false;
    
    // Metrics
    this.ingestedLogsCounter = null;
    this.ingestedMetricsCounter = null;
    this.ingestedTracesCounter = null;
    this.ingestionLatencyHistogram = null;
    
    this.init();
  }

  async init() {
    try {
      // Create resource with service information
      const resource = new Resource({
        [SemanticResourceAttributes.SERVICE_NAME]: this.config.serviceName,
        [SemanticResourceAttributes.SERVICE_VERSION]: this.config.serviceVersion,
        [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: this.config.environment,
      });

      // Initialize SDK
      this.sdk = new NodeSDK({
        resource,
        traceExporter: new JaegerExporter({
          endpoint: this.config.jaegerEndpoint,
        }),
        metricReader: new PrometheusExporter({
          port: this.config.prometheusPort,
        }),
        instrumentations: this.config.enableAutoInstrumentation 
          ? [getNodeAutoInstrumentations()] 
          : [],
      });

      await this.sdk.start();

      // Get providers
      this.tracer = trace.getTracer(this.config.serviceName, this.config.serviceVersion);
      this.meter = metrics.getMeter(this.config.serviceName, this.config.serviceVersion);
      
      // Initialize metrics
      this.initializeMetrics();
      
      this.isInitialized = true;
      this.logger.info('OTel Collector initialized successfully');
      this.emit('initialized');
      
    } catch (error) {
      this.logger.error('Failed to initialize OTel Collector:', error);
      this.emit('error', error);
      throw error;
    }
  }

  initializeMetrics() {
    this.ingestedLogsCounter = this.meter.createCounter('ingested_logs_total', {
      description: 'Total number of logs ingested',
    });

    this.ingestedMetricsCounter = this.meter.createCounter('ingested_metrics_total', {
      description: 'Total number of metrics ingested',
    });

    this.ingestedTracesCounter = this.meter.createCounter('ingested_traces_total', {
      description: 'Total number of traces ingested',
    });

    this.ingestionLatencyHistogram = this.meter.createHistogram('ingestion_latency_ms', {
      description: 'Latency of data ingestion in milliseconds',
      boundaries: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
    });
  }

  /**
   * Ingest log data with OTel format
   */
  async ingestLog(logData) {
    const startTime = Date.now();
    const span = this.tracer.startSpan('ingest_log');
    
    try {
      const processedLog = this.processLogData(logData);
      
      // Emit structured log event
      this.emit('log', {
        id: uuidv4(),
        timestamp: processedLog.timestamp || new Date().toISOString(),
        severity: this.mapSeverity(processedLog.level),
        body: processedLog.message || processedLog.body,
        attributes: {
          'service.name': processedLog.service || this.config.serviceName,
          'service.version': processedLog.version || this.config.serviceVersion,
          'log.level': processedLog.level || 'INFO',
          'trace.id': span.spanContext().traceId,
          'span.id': span.spanContext().spanId,
          ...processedLog.attributes
        },
        resource: processedLog.resource || {},
        raw: processedLog
      });

      this.ingestedLogsCounter.add(1, {
        service: processedLog.service || this.config.serviceName,
        level: processedLog.level || 'INFO'
      });

      span.setStatus({ code: 1 }); // OK
      return { success: true, id: processedLog.id };
      
    } catch (error) {
      span.recordException(error);
      span.setStatus({ code: 2, message: error.message }); // ERROR
      this.logger.error('Failed to ingest log:', error);
      throw error;
    } finally {
      const latency = Date.now() - startTime;
      this.ingestionLatencyHistogram.record(latency, { operation: 'ingest_log' });
      span.end();
    }
  }

  /**
   * Ingest metric data
   */
  async ingestMetric(metricData) {
    const startTime = Date.now();
    const span = this.tracer.startSpan('ingest_metric');
    
    try {
      const processedMetric = this.processMetricData(metricData);
      
      this.emit('metric', {
        id: uuidv4(),
        timestamp: processedMetric.timestamp || new Date().toISOString(),
        name: processedMetric.name,
        value: processedMetric.value,
        type: processedMetric.type || 'gauge',
        unit: processedMetric.unit,
        attributes: processedMetric.attributes || {},
        resource: processedMetric.resource || {},
        raw: processedMetric
      });

      this.ingestedMetricsCounter.add(1, {
        metric_name: processedMetric.name,
        type: processedMetric.type || 'gauge'
      });

      span.setStatus({ code: 1 });
      return { success: true, id: processedMetric.id };
      
    } catch (error) {
      span.recordException(error);
      span.setStatus({ code: 2, message: error.message });
      this.logger.error('Failed to ingest metric:', error);
      throw error;
    } finally {
      const latency = Date.now() - startTime;
      this.ingestionLatencyHistogram.record(latency, { operation: 'ingest_metric' });
      span.end();
    }
  }

  /**
   * Ingest trace data
   */
  async ingestTrace(traceData) {
    const startTime = Date.now();
    const span = this.tracer.startSpan('ingest_trace');
    
    try {
      const processedTrace = this.processTraceData(traceData);
      
      this.emit('trace', {
        id: uuidv4(),
        traceId: processedTrace.traceId,
        spanId: processedTrace.spanId,
        parentSpanId: processedTrace.parentSpanId,
        operationName: processedTrace.operationName,
        startTime: processedTrace.startTime,
        endTime: processedTrace.endTime,
        duration: processedTrace.duration,
        tags: processedTrace.tags || {},
        logs: processedTrace.logs || [],
        process: processedTrace.process || {},
        raw: processedTrace
      });

      this.ingestedTracesCounter.add(1, {
        service: processedTrace.process?.serviceName || this.config.serviceName,
        operation: processedTrace.operationName
      });

      span.setStatus({ code: 1 });
      return { success: true, id: processedTrace.id };
      
    } catch (error) {
      span.recordException(error);
      span.setStatus({ code: 2, message: error.message });
      this.logger.error('Failed to ingest trace:', error);
      throw error;
    } finally {
      const latency = Date.now() - startTime;
      this.ingestionLatencyHistogram.record(latency, { operation: 'ingest_trace' });
      span.end();
    }
  }

  /**
   * Process and normalize log data
   */
  processLogData(logData) {
    if (typeof logData === 'string') {
      return {
        id: uuidv4(),
        message: logData,
        timestamp: new Date().toISOString(),
        level: 'INFO'
      };
    }

    return {
      id: logData.id || uuidv4(),
      timestamp: logData.timestamp || logData.time || new Date().toISOString(),
      level: logData.level || logData.severity || 'INFO',
      message: logData.message || logData.msg || logData.body,
      service: logData.service || logData.serviceName,
      version: logData.version || logData.serviceVersion,
      attributes: {
        ...logData.attributes,
        ...logData.labels,
        ...logData.tags
      },
      resource: logData.resource || {},
      ...logData
    };
  }

  /**
   * Process and normalize metric data
   */
  processMetricData(metricData) {
    return {
      id: metricData.id || uuidv4(),
      timestamp: metricData.timestamp || metricData.time || new Date().toISOString(),
      name: metricData.name || metricData.metricName,
      value: metricData.value,
      type: metricData.type || 'gauge',
      unit: metricData.unit,
      attributes: metricData.attributes || metricData.labels || {},
      resource: metricData.resource || {},
      ...metricData
    };
  }

  /**
   * Process and normalize trace data
   */
  processTraceData(traceData) {
    return {
      id: traceData.id || uuidv4(),
      traceId: traceData.traceId || traceData.traceID,
      spanId: traceData.spanId || traceData.spanID,
      parentSpanId: traceData.parentSpanId || traceData.parentSpanID,
      operationName: traceData.operationName || traceData.operation,
      startTime: traceData.startTime || traceData.start,
      endTime: traceData.endTime || traceData.end,
      duration: traceData.duration || (traceData.endTime - traceData.startTime),
      tags: traceData.tags || traceData.attributes || {},
      logs: traceData.logs || [],
      process: traceData.process || {},
      ...traceData
    };
  }

  /**
   * Map log level to OTel severity number
   */
  mapSeverity(level) {
    const levelMap = {
      'TRACE': SeverityNumber.TRACE,
      'DEBUG': SeverityNumber.DEBUG,
      'INFO': SeverityNumber.INFO,
      'WARN': SeverityNumber.WARN,
      'WARNING': SeverityNumber.WARN,
      'ERROR': SeverityNumber.ERROR,
      'FATAL': SeverityNumber.FATAL,
      'CRITICAL': SeverityNumber.FATAL
    };
    
    return levelMap[level?.toUpperCase()] || SeverityNumber.INFO;
  }

  /**
   * Batch ingest multiple items
   */
  async ingestBatch(items) {
    const results = [];
    const span = this.tracer.startSpan('ingest_batch', {
      attributes: { 'batch.size': items.length }
    });

    try {
      for (const item of items) {
        try {
          let result;
          switch (item.type) {
            case 'log':
              result = await this.ingestLog(item.data);
              break;
            case 'metric':
              result = await this.ingestMetric(item.data);
              break;
            case 'trace':
              result = await this.ingestTrace(item.data);
              break;
            default:
              result = await this.ingestLog(item.data);
          }
          results.push({ ...result, originalIndex: item.index });
        } catch (error) {
          results.push({ 
            success: false, 
            error: error.message, 
            originalIndex: item.index 
          });
        }
      }

      span.setStatus({ code: 1 });
      return results;
      
    } catch (error) {
      span.recordException(error);
      span.setStatus({ code: 2, message: error.message });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Get ingestion statistics
   */
  getStats() {
    return {
      initialized: this.isInitialized,
      serviceName: this.config.serviceName,
      serviceVersion: this.config.serviceVersion,
      environment: this.config.environment,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      // Additional stats would come from metric readers
    };
  }

  /**
   * Shutdown the collector
   */
  async shutdown() {
    try {
      if (this.sdk) {
        await this.sdk.shutdown();
      }
      this.logger.info('OTel Collector shutdown completed');
      this.emit('shutdown');
    } catch (error) {
      this.logger.error('Error during shutdown:', error);
      throw error;
    }
  }
}

export { OTelCollector };
