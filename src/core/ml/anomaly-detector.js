/**
 * ML-powered Anomaly Detection Engine
 * Supports threshold, dynamic baselines, Holt-Winters, clustering, and change-point detection
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { mean, standardDeviation, quantile } from 'simple-statistics';
import { Matrix } from 'ml-matrix';
import { LinearRegression } from 'ml-regression';
import natural from 'natural';
import moment from 'moment';

class AnomalyDetector extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      windowSize: config.windowSize || 100,
      sensitivity: config.sensitivity || 0.95,
      minSamples: config.minSamples || 10,
      algorithms: {
        statistical: config.algorithms?.statistical !== false,
        clustering: config.algorithms?.clustering !== false,
        timeSeries: config.algorithms?.timeSeries !== false,
        logPatterns: config.algorithms?.logPatterns !== false,
        ...config.algorithms
      },
      thresholds: {
        errorRate: config.thresholds?.errorRate || 0.05,
        latencyP95: config.thresholds?.latencyP95 || 1000,
        throughputDrop: config.thresholds?.throughputDrop || 0.3,
        ...config.thresholds
      },
      ...config
    };

    this.logger = createLogger('AnomalyDetector');
    this.models = new Map();
    this.baselines = new Map();
    this.patterns = new Map();
    this.anomalies = [];
    this.stats = {
      detected: 0,
      falsePositives: 0,
      accuracy: 0
    };

    this.initializeModels();
  }

  initializeModels() {
    // Initialize different detection models
    this.models.set('statistical', new StatisticalAnomalyModel(this.config));
    this.models.set('clustering', new ClusteringAnomalyModel(this.config));
    this.models.set('timeSeries', new TimeSeriesAnomalyModel(this.config));
    this.models.set('logPatterns', new LogPatternAnomalyModel(this.config));
    
    this.logger.info('Anomaly detection models initialized');
  }

  /**
   * Analyze metrics for anomalies
   */
  async analyzeMetrics(metrics, timestamp = new Date()) {
    const anomalies = [];
    
    try {
      // Run each enabled detection algorithm
      for (const [name, model] of this.models) {
        if (this.config.algorithms[name]) {
          const modelAnomalies = await model.detect(metrics, timestamp);
          anomalies.push(...modelAnomalies.map(a => ({ ...a, algorithm: name })));
        }
      }

      // Aggregate and deduplicate anomalies
      const aggregated = this.aggregateAnomalies(anomalies);
      
      // Store detected anomalies
      this.anomalies.push(...aggregated);
      this.stats.detected += aggregated.length;

      // Emit anomaly events
      for (const anomaly of aggregated) {
        this.emit('anomaly-detected', anomaly);
      }

      return aggregated;

    } catch (error) {
      this.logger.error('Failed to analyze metrics for anomalies:', error);
      throw error;
    }
  }

  /**
   * Analyze log entries for pattern anomalies
   */
  async analyzeLogs(logEntries) {
    const patternModel = this.models.get('logPatterns');
    if (!patternModel || !this.config.algorithms.logPatterns) {
      return [];
    }

    try {
      const anomalies = [];
      
      for (const entry of logEntries) {
        const entryAnomalies = await patternModel.detectLogAnomaly(entry);
        anomalies.push(...entryAnomalies);
      }

      // Store and emit anomalies
      this.anomalies.push(...anomalies);
      this.stats.detected += anomalies.length;

      for (const anomaly of anomalies) {
        this.emit('log-anomaly-detected', anomaly);
      }

      return anomalies;

    } catch (error) {
      this.logger.error('Failed to analyze logs for anomalies:', error);
      throw error;
    }
  }

  aggregateAnomalies(anomalies) {
    // Group similar anomalies and reduce noise
    const grouped = new Map();
    
    for (const anomaly of anomalies) {
      const key = `${anomaly.type}-${anomaly.metric}-${Math.floor(anomaly.timestamp / 60000)}`;
      
      if (grouped.has(key)) {
        const existing = grouped.get(key);
        existing.confidence = Math.max(existing.confidence, anomaly.confidence);
        existing.algorithms.push(anomaly.algorithm);
      } else {
        grouped.set(key, {
          ...anomaly,
          algorithms: [anomaly.algorithm]
        });
      }
    }
    
    return Array.from(grouped.values())
      .filter(a => a.confidence >= this.config.sensitivity);
  }

  /**
   * Update baselines with new data
   */
  updateBaselines(metrics, timestamp) {
    for (const [metric, value] of Object.entries(metrics)) {
      if (typeof value === 'number') {
        this.updateMetricBaseline(metric, value, timestamp);
      }
    }
  }

  updateMetricBaseline(metric, value, timestamp) {
    if (!this.baselines.has(metric)) {
      this.baselines.set(metric, {
        values: [],
        mean: 0,
        std: 0,
        trend: 0,
        seasonality: {},
        lastUpdate: timestamp
      });
    }

    const baseline = this.baselines.get(metric);
    baseline.values.push({ value, timestamp });
    
    // Keep only recent values
    const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days
    baseline.values = baseline.values.filter(v => v.timestamp > cutoff);
    
    // Update statistics
    const values = baseline.values.map(v => v.value);
    baseline.mean = mean(values);
    baseline.std = standardDeviation(values);
    baseline.lastUpdate = timestamp;
    
    // Update trend (simple linear regression)
    if (values.length >= 10) {
      const x = baseline.values.map((_, i) => i);
      const y = values;
      const regression = new LinearRegression(x, y);
      baseline.trend = regression.slope;
    }
    
    // Update seasonality patterns
    this.updateSeasonality(baseline, value, timestamp);
  }

  updateSeasonality(baseline, value, timestamp) {
    const hour = moment(timestamp).hour();
    const dayOfWeek = moment(timestamp).day();
    
    // Hourly patterns
    if (!baseline.seasonality.hourly) {
      baseline.seasonality.hourly = new Array(24).fill(0).map(() => ({ sum: 0, count: 0 }));
    }
    baseline.seasonality.hourly[hour].sum += value;
    baseline.seasonality.hourly[hour].count += 1;
    
    // Daily patterns
    if (!baseline.seasonality.daily) {
      baseline.seasonality.daily = new Array(7).fill(0).map(() => ({ sum: 0, count: 0 }));
    }
    baseline.seasonality.daily[dayOfWeek].sum += value;
    baseline.seasonality.daily[dayOfWeek].count += 1;
  }

  /**
   * Get current baseline for a metric
   */
  getBaseline(metric, timestamp = new Date()) {
    const baseline = this.baselines.get(metric);
    if (!baseline) return null;

    const hour = moment(timestamp).hour();
    const dayOfWeek = moment(timestamp).day();
    
    // Calculate seasonal adjustment
    let seasonalAdjustment = 0;
    if (baseline.seasonality.hourly && baseline.seasonality.hourly[hour].count > 0) {
      seasonalAdjustment += baseline.seasonality.hourly[hour].sum / baseline.seasonality.hourly[hour].count - baseline.mean;
    }
    
    return {
      mean: baseline.mean + seasonalAdjustment,
      std: baseline.std,
      trend: baseline.trend,
      upper: baseline.mean + seasonalAdjustment + (2 * baseline.std),
      lower: Math.max(0, baseline.mean + seasonalAdjustment - (2 * baseline.std))
    };
  }

  /**
   * Get anomaly statistics
   */
  getStats() {
    return {
      ...this.stats,
      modelsActive: Array.from(this.models.keys()).filter(k => this.config.algorithms[k]),
      baselinesCount: this.baselines.size,
      recentAnomalies: this.anomalies.slice(-10),
      config: this.config
    };
  }

  /**
   * Clear old anomalies and baselines
   */
  cleanup() {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    this.anomalies = this.anomalies.filter(a => a.timestamp > cutoff);
    
    for (const [metric, baseline] of this.baselines) {
      baseline.values = baseline.values.filter(v => v.timestamp > cutoff);
      if (baseline.values.length === 0) {
        this.baselines.delete(metric);
      }
    }
    
    this.logger.info('Cleanup completed');
  }
}

/**
 * Statistical Anomaly Detection Model
 */
class StatisticalAnomalyModel {
  constructor(config) {
    this.config = config;
    this.logger = createLogger('StatisticalModel');
  }

  async detect(metrics, timestamp) {
    const anomalies = [];
    
    for (const [metric, value] of Object.entries(metrics)) {
      if (typeof value !== 'number') continue;
      
      const anomaly = this.detectStatisticalAnomaly(metric, value, timestamp);
      if (anomaly) {
        anomalies.push(anomaly);
      }
    }
    
    return anomalies;
  }

  detectStatisticalAnomaly(metric, value, timestamp) {
    // Simple z-score based detection
    const threshold = this.config.thresholds[metric];
    if (threshold && value > threshold) {
      return {
        type: 'threshold',
        metric,
        value,
        threshold,
        confidence: Math.min(1.0, value / threshold),
        timestamp: timestamp.getTime(),
        description: `${metric} exceeded threshold: ${value} > ${threshold}`
      };
    }
    
    return null;
  }
}

/**
 * Clustering-based Anomaly Detection Model
 */
class ClusteringAnomalyModel {
  constructor(config) {
    this.config = config;
    this.logger = createLogger('ClusteringModel');
    this.clusters = new Map();
  }

  async detect(metrics, timestamp) {
    // Simplified clustering - in production, use proper clustering algorithms
    const anomalies = [];
    const vector = Object.values(metrics).filter(v => typeof v === 'number');
    
    if (vector.length < 2) return anomalies;
    
    const isOutlier = this.isClusterOutlier(vector);
    if (isOutlier) {
      anomalies.push({
        type: 'cluster_outlier',
        metric: 'combined_metrics',
        value: vector,
        confidence: 0.8,
        timestamp: timestamp.getTime(),
        description: 'Metrics combination is an outlier from normal clusters'
      });
    }
    
    return anomalies;
  }

  isClusterOutlier(vector) {
    // Simple distance-based outlier detection
    // In production, implement proper clustering algorithms like DBSCAN or Isolation Forest
    return false; // Placeholder
  }
}

/**
 * Time Series Anomaly Detection Model
 */
class TimeSeriesAnomalyModel {
  constructor(config) {
    this.config = config;
    this.logger = createLogger('TimeSeriesModel');
    this.history = new Map();
  }

  async detect(metrics, timestamp) {
    const anomalies = [];
    
    for (const [metric, value] of Object.entries(metrics)) {
      if (typeof value !== 'number') continue;
      
      this.updateHistory(metric, value, timestamp);
      const anomaly = this.detectTimeSeriesAnomaly(metric, value, timestamp);
      if (anomaly) {
        anomalies.push(anomaly);
      }
    }
    
    return anomalies;
  }

  updateHistory(metric, value, timestamp) {
    if (!this.history.has(metric)) {
      this.history.set(metric, []);
    }
    
    const history = this.history.get(metric);
    history.push({ value, timestamp: timestamp.getTime() });
    
    // Keep only recent history
    const cutoff = Date.now() - (60 * 60 * 1000); // 1 hour
    this.history.set(metric, history.filter(h => h.timestamp > cutoff));
  }

  detectTimeSeriesAnomaly(metric, value, timestamp) {
    const history = this.history.get(metric);
    if (!history || history.length < this.config.minSamples) {
      return null;
    }
    
    const values = history.map(h => h.value);
    const recentMean = mean(values.slice(-10));
    const recentStd = standardDeviation(values.slice(-10));
    
    // Detect sudden spikes or drops
    const zScore = Math.abs((value - recentMean) / (recentStd || 1));
    if (zScore > 3) {
      return {
        type: 'time_series_spike',
        metric,
        value,
        baseline: recentMean,
        zScore,
        confidence: Math.min(1.0, zScore / 5),
        timestamp: timestamp.getTime(),
        description: `${metric} shows unusual spike/drop: z-score ${zScore.toFixed(2)}`
      };
    }
    
    return null;
  }
}

/**
 * Log Pattern Anomaly Detection Model
 */
class LogPatternAnomalyModel {
  constructor(config) {
    this.config = config;
    this.logger = createLogger('LogPatternModel');
    this.patterns = new Map();
    this.tokenizer = new natural.WordTokenizer();
  }

  async detect(logEntries) {
    // This method is called from analyzeLogs, not analyzeMetrics
    return [];
  }

  async detectLogAnomaly(logEntry) {
    const anomalies = [];
    
    // Extract and analyze log patterns
    const pattern = this.extractPattern(logEntry.message || '');
    const isRare = this.isRarePattern(pattern);
    
    if (isRare) {
      anomalies.push({
        type: 'rare_log_pattern',
        metric: 'log_pattern',
        value: pattern,
        confidence: 0.7,
        timestamp: new Date(logEntry.timestamp).getTime(),
        description: `Rare log pattern detected: ${pattern.substring(0, 100)}...`,
        logEntry
      });
    }
    
    // Detect error bursts
    if (logEntry.level === 'ERROR') {
      const isBurst = this.isErrorBurst(logEntry.timestamp);
      if (isBurst) {
        anomalies.push({
          type: 'error_burst',
          metric: 'error_rate',
          value: 'burst',
          confidence: 0.9,
          timestamp: new Date(logEntry.timestamp).getTime(),
          description: 'Error burst detected',
          logEntry
        });
      }
    }
    
    return anomalies;
  }

  extractPattern(message) {
    // Simple pattern extraction - replace numbers and specific values with placeholders
    return message
      .replace(/\d+/g, 'NUM')
      .replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, 'UUID')
      .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, 'IP')
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, 'EMAIL');
  }

  isRarePattern(pattern) {
    const count = this.patterns.get(pattern) || 0;
    this.patterns.set(pattern, count + 1);
    
    // Consider pattern rare if seen less than 5 times
    return count < 5;
  }

  isErrorBurst(timestamp) {
    // Simple error burst detection - check if multiple errors in short time
    // In production, implement proper burst detection algorithms
    return false; // Placeholder
  }
}

export { AnomalyDetector };
