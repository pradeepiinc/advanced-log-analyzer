/**
 * Advanced Alerting System with Multi-condition Support
 * SLO/error budget burn, anomalies, outlier patterns, dedup, grouping
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';
import cron from 'node-cron';

class AlertManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      maxActiveAlerts: config.maxActiveAlerts || 1000,
      dedupWindow: config.dedupWindow || 300000, // 5 minutes
      groupingWindow: config.groupingWindow || 600000, // 10 minutes
      escalationLevels: config.escalationLevels || ['info', 'warning', 'critical'],
      sloDefaults: {
        errorBudget: 0.001, // 99.9% availability
        burnRateThreshold: 2.0,
        ...config.sloDefaults
      },
      ...config
    };

    this.logger = createLogger('AlertManager');
    this.rules = new Map();
    this.activeAlerts = new Map();
    this.alertHistory = [];
    this.slos = new Map();
    this.suppressions = new Map();
    this.notifications = new Map();
    
    this.stats = {
      alertsGenerated: 0,
      alertsResolved: 0,
      alertsSuppressed: 0,
      notificationsSent: 0
    };

    this.initializeDefaultRules();
    this.startPeriodicTasks();
  }

  initializeDefaultRules() {
    // Default alerting rules
    const defaultRules = [
      {
        name: 'high_error_rate',
        condition: 'error_rate > 0.05',
        severity: 'critical',
        description: 'Error rate exceeded 5%',
        enabled: true
      },
      {
        name: 'high_latency_p95',
        condition: 'latency_p95 > 1000',
        severity: 'warning',
        description: 'P95 latency exceeded 1000ms',
        enabled: true
      },
      {
        name: 'low_throughput',
        condition: 'throughput < baseline * 0.5',
        severity: 'warning',
        description: 'Throughput dropped below 50% of baseline',
        enabled: true
      }
    ];

    for (const rule of defaultRules) {
      this.addRule(rule);
    }
  }

  startPeriodicTasks() {
    // Check SLO burn rates every minute
    cron.schedule('* * * * *', () => {
      this.checkSLOBurnRates();
    });

    // Cleanup old alerts every hour
    cron.schedule('0 * * * *', () => {
      this.cleanupOldAlerts();
    });

    // Process alert grouping every 30 seconds
    cron.schedule('*/30 * * * * *', () => {
      this.processAlertGrouping();
    });
  }

  /**
   * Add alerting rule
   */
  addRule(ruleConfig) {
    const rule = {
      id: ruleConfig.id || uuidv4(),
      name: ruleConfig.name,
      condition: ruleConfig.condition,
      severity: ruleConfig.severity || 'warning',
      description: ruleConfig.description || '',
      enabled: ruleConfig.enabled !== false,
      labels: ruleConfig.labels || {},
      annotations: ruleConfig.annotations || {},
      for: ruleConfig.for || '0s', // Duration condition must be true
      evaluationInterval: ruleConfig.evaluationInterval || 60000, // 1 minute
      lastEvaluation: null,
      lastTriggered: null,
      triggerCount: 0,
      created: new Date()
    };

    this.rules.set(rule.id, rule);
    this.logger.info(`Added alert rule: ${rule.name}`);
    return rule;
  }

  /**
   * Evaluate metrics against all rules
   */
  async evaluateMetrics(metrics, timestamp = new Date()) {
    const triggeredAlerts = [];

    for (const [ruleId, rule] of this.rules) {
      if (!rule.enabled) continue;

      try {
        const shouldTrigger = await this.evaluateRule(rule, metrics, timestamp);
        
        if (shouldTrigger) {
          const alert = await this.createAlert(rule, metrics, timestamp);
          if (alert) {
            triggeredAlerts.push(alert);
          }
        }

        rule.lastEvaluation = timestamp;

      } catch (error) {
        this.logger.error(`Failed to evaluate rule ${rule.name}:`, error);
      }
    }

    return triggeredAlerts;
  }

  async evaluateRule(rule, metrics, timestamp) {
    // Parse and evaluate condition
    const condition = rule.condition;
    
    // Simple condition evaluation - can be enhanced with proper expression parser
    if (condition.includes('error_rate')) {
      const errorRate = metrics.errorRate || 0;
      const threshold = this.extractThreshold(condition, 'error_rate');
      return this.compareValues(errorRate, threshold, condition);
    }
    
    if (condition.includes('latency_p95')) {
      const latencyP95 = metrics.latency?.p95 || 0;
      const threshold = this.extractThreshold(condition, 'latency_p95');
      return this.compareValues(latencyP95, threshold, condition);
    }
    
    if (condition.includes('throughput')) {
      const throughput = metrics.throughputRps || 0;
      const baseline = await this.getMetricBaseline('throughput', timestamp);
      
      if (condition.includes('baseline')) {
        const factor = this.extractBaselineFactor(condition);
        const threshold = baseline * factor;
        return this.compareValues(throughput, threshold, condition);
      }
    }

    return false;
  }

  extractThreshold(condition, metric) {
    const regex = new RegExp(`${metric}\\s*([><=!]+)\\s*(\\d+(?:\\.\\d+)?)`);
    const match = condition.match(regex);
    return match ? parseFloat(match[2]) : 0;
  }

  extractBaselineFactor(condition) {
    const match = condition.match(/baseline\s*\*\s*([\d.]+)/);
    return match ? parseFloat(match[1]) : 1.0;
  }

  compareValues(actual, threshold, condition) {
    if (condition.includes('>')) return actual > threshold;
    if (condition.includes('<')) return actual < threshold;
    if (condition.includes('>=')) return actual >= threshold;
    if (condition.includes('<=')) return actual <= threshold;
    if (condition.includes('==')) return actual === threshold;
    if (condition.includes('!=')) return actual !== threshold;
    return false;
  }

  async getMetricBaseline(metric, timestamp) {
    // Mock baseline calculation - integrate with anomaly detector
    return 100; // Placeholder
  }

  async createAlert(rule, metrics, timestamp) {
    const alertKey = `${rule.name}-${JSON.stringify(rule.labels)}`;
    
    // Check for existing active alert (deduplication)
    if (this.activeAlerts.has(alertKey)) {
      const existing = this.activeAlerts.get(alertKey);
      existing.lastSeen = timestamp;
      existing.count++;
      return null; // Deduplicated
    }

    // Check suppression rules
    if (this.isAlertSuppressed(rule, metrics, timestamp)) {
      this.stats.alertsSuppressed++;
      return null;
    }

    const alert = {
      id: uuidv4(),
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      status: 'firing',
      description: rule.description,
      labels: { ...rule.labels },
      annotations: { ...rule.annotations },
      metrics: { ...metrics },
      startsAt: timestamp,
      endsAt: null,
      lastSeen: timestamp,
      count: 1,
      fingerprint: this.generateFingerprint(rule, metrics)
    };

    // Add contextual information
    alert.annotations.summary = this.generateAlertSummary(alert, metrics);
    alert.annotations.runbook = this.getRunbookUrl(rule.name);

    this.activeAlerts.set(alertKey, alert);
    this.alertHistory.push({ ...alert });
    this.stats.alertsGenerated++;

    rule.lastTriggered = timestamp;
    rule.triggerCount++;

    this.emit('alert-created', alert);
    await this.sendNotifications(alert);

    this.logger.warn(`Alert created: ${alert.ruleName} - ${alert.description}`);
    return alert;
  }

  generateAlertSummary(alert, metrics) {
    const { ruleName, severity } = alert;
    
    switch (ruleName) {
      case 'high_error_rate':
        return `Error rate is ${(metrics.errorRate * 100).toFixed(2)}% (threshold: 5%)`;
      case 'high_latency_p95':
        return `P95 latency is ${metrics.latency?.p95 || 0}ms (threshold: 1000ms)`;
      case 'low_throughput':
        return `Throughput is ${metrics.throughputRps?.toFixed(2) || 0} RPS`;
      default:
        return `${ruleName} alert triggered`;
    }
  }

  getRunbookUrl(ruleName) {
    const runbooks = {
      'high_error_rate': 'https://runbooks.company.com/high-error-rate',
      'high_latency_p95': 'https://runbooks.company.com/high-latency',
      'low_throughput': 'https://runbooks.company.com/low-throughput'
    };
    return runbooks[ruleName] || 'https://runbooks.company.com/general';
  }

  generateFingerprint(rule, metrics) {
    const data = {
      ruleName: rule.name,
      labels: rule.labels,
      service: metrics.service || 'unknown'
    };
    return Buffer.from(JSON.stringify(data)).toString('base64').substring(0, 16);
  }

  isAlertSuppressed(rule, metrics, timestamp) {
    for (const [suppressionId, suppression] of this.suppressions) {
      if (suppression.enabled && this.matchesSuppression(suppression, rule, metrics, timestamp)) {
        return true;
      }
    }
    return false;
  }

  matchesSuppression(suppression, rule, metrics, timestamp) {
    // Check time window
    if (suppression.startTime && suppression.endTime) {
      const time = timestamp.getTime();
      if (time < suppression.startTime || time > suppression.endTime) {
        return false;
      }
    }

    // Check rule matching
    if (suppression.rules && !suppression.rules.includes(rule.name)) {
      return false;
    }

    // Check label matching
    if (suppression.labels) {
      for (const [key, value] of Object.entries(suppression.labels)) {
        if (rule.labels[key] !== value) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertKey, timestamp = new Date()) {
    if (!this.activeAlerts.has(alertKey)) {
      return null;
    }

    const alert = this.activeAlerts.get(alertKey);
    alert.status = 'resolved';
    alert.endsAt = timestamp;

    this.activeAlerts.delete(alertKey);
    this.stats.alertsResolved++;

    this.emit('alert-resolved', alert);
    await this.sendNotifications(alert);

    this.logger.info(`Alert resolved: ${alert.ruleName}`);
    return alert;
  }

  /**
   * Add SLO definition
   */
  addSLO(sloConfig) {
    const slo = {
      id: sloConfig.id || uuidv4(),
      name: sloConfig.name,
      service: sloConfig.service,
      objective: sloConfig.objective || 0.999, // 99.9%
      errorBudget: sloConfig.errorBudget || (1 - sloConfig.objective),
      window: sloConfig.window || '30d',
      burnRateThreshold: sloConfig.burnRateThreshold || this.config.sloDefaults.burnRateThreshold,
      indicators: sloConfig.indicators || [],
      created: new Date(),
      ...sloConfig
    };

    this.slos.set(slo.id, slo);
    this.logger.info(`Added SLO: ${slo.name} for service ${slo.service}`);
    return slo;
  }

  /**
   * Check SLO burn rates
   */
  async checkSLOBurnRates() {
    for (const [sloId, slo] of this.slos) {
      try {
        const burnRate = await this.calculateBurnRate(slo);
        
        if (burnRate > slo.burnRateThreshold) {
          await this.createSLOAlert(slo, burnRate);
        }

      } catch (error) {
        this.logger.error(`Failed to check SLO burn rate for ${slo.name}:`, error);
      }
    }
  }

  async calculateBurnRate(slo) {
    // Mock burn rate calculation - integrate with metrics storage
    // Burn rate = (error rate) / (error budget rate)
    const errorRate = 0.001; // Mock current error rate
    const errorBudgetRate = slo.errorBudget / this.parseTimeWindow(slo.window);
    
    return errorRate / errorBudgetRate;
  }

  parseTimeWindow(window) {
    const match = window.match(/(\d+)([hdwmy])/);
    if (!match) return 30; // Default 30 days
    
    const [, value, unit] = match;
    const multipliers = { h: 1/24, d: 1, w: 7, m: 30, y: 365 };
    return parseInt(value) * (multipliers[unit] || 1);
  }

  async createSLOAlert(slo, burnRate) {
    const alert = {
      id: uuidv4(),
      type: 'slo_burn_rate',
      sloId: slo.id,
      sloName: slo.name,
      service: slo.service,
      severity: burnRate > 10 ? 'critical' : 'warning',
      burnRate,
      threshold: slo.burnRateThreshold,
      description: `SLO burn rate exceeded threshold for ${slo.name}`,
      timestamp: new Date()
    };

    this.emit('slo-alert', alert);
    this.logger.warn(`SLO burn rate alert: ${slo.name} burn rate ${burnRate.toFixed(2)}x`);
  }

  /**
   * Process alert grouping
   */
  async processAlertGrouping() {
    const now = Date.now();
    const groups = new Map();

    // Group alerts by similarity
    for (const [alertKey, alert] of this.activeAlerts) {
      const groupKey = this.getGroupKey(alert);
      
      if (!groups.has(groupKey)) {
        groups.set(groupKey, []);
      }
      groups.get(groupKey).push(alert);
    }

    // Process groups with multiple alerts
    for (const [groupKey, alerts] of groups) {
      if (alerts.length > 1) {
        await this.createGroupedAlert(groupKey, alerts);
      }
    }
  }

  getGroupKey(alert) {
    // Group by service and severity
    return `${alert.labels.service || 'unknown'}-${alert.severity}`;
  }

  async createGroupedAlert(groupKey, alerts) {
    const groupedAlert = {
      id: uuidv4(),
      type: 'grouped',
      groupKey,
      severity: this.getHighestSeverity(alerts),
      alertCount: alerts.length,
      alerts: alerts.map(a => a.id),
      description: `${alerts.length} alerts grouped for ${groupKey}`,
      timestamp: new Date()
    };

    this.emit('grouped-alert', groupedAlert);
  }

  getHighestSeverity(alerts) {
    const severityOrder = { info: 1, warning: 2, critical: 3 };
    return alerts.reduce((highest, alert) => {
      return severityOrder[alert.severity] > severityOrder[highest] ? alert.severity : highest;
    }, 'info');
  }

  /**
   * Add notification channel
   */
  addNotificationChannel(channelConfig) {
    const channel = {
      id: channelConfig.id || uuidv4(),
      name: channelConfig.name,
      type: channelConfig.type, // email, slack, webhook, pagerduty
      config: channelConfig.config,
      enabled: channelConfig.enabled !== false,
      filters: channelConfig.filters || {},
      created: new Date()
    };

    this.notifications.set(channel.id, channel);
    this.logger.info(`Added notification channel: ${channel.name} (${channel.type})`);
    return channel;
  }

  /**
   * Send notifications for alert
   */
  async sendNotifications(alert) {
    for (const [channelId, channel] of this.notifications) {
      if (!channel.enabled) continue;

      try {
        if (this.shouldNotify(channel, alert)) {
          await this.sendNotification(channel, alert);
          this.stats.notificationsSent++;
        }
      } catch (error) {
        this.logger.error(`Failed to send notification via ${channel.name}:`, error);
      }
    }
  }

  shouldNotify(channel, alert) {
    // Check severity filter
    if (channel.filters.severity) {
      const severityOrder = { info: 1, warning: 2, critical: 3 };
      const minSeverity = severityOrder[channel.filters.severity];
      const alertSeverity = severityOrder[alert.severity];
      
      if (alertSeverity < minSeverity) {
        return false;
      }
    }

    // Check service filter
    if (channel.filters.services) {
      const service = alert.labels.service || alert.metrics.service;
      if (!channel.filters.services.includes(service)) {
        return false;
      }
    }

    return true;
  }

  async sendNotification(channel, alert) {
    const message = this.formatNotificationMessage(channel, alert);
    
    switch (channel.type) {
      case 'email':
        await this.sendEmailNotification(channel, alert, message);
        break;
      case 'slack':
        await this.sendSlackNotification(channel, alert, message);
        break;
      case 'webhook':
        await this.sendWebhookNotification(channel, alert, message);
        break;
      case 'pagerduty':
        await this.sendPagerDutyNotification(channel, alert, message);
        break;
    }
  }

  formatNotificationMessage(channel, alert) {
    const status = alert.status === 'firing' ? '🔥 FIRING' : '✅ RESOLVED';
    
    return {
      title: `${status}: ${alert.ruleName}`,
      description: alert.description,
      severity: alert.severity,
      service: alert.labels.service || 'unknown',
      timestamp: alert.startsAt,
      runbook: alert.annotations.runbook,
      summary: alert.annotations.summary
    };
  }

  async sendEmailNotification(channel, alert, message) {
    // Mock email sending - integrate with actual email service
    this.logger.info(`Email notification sent: ${message.title}`);
  }

  async sendSlackNotification(channel, alert, message) {
    // Mock Slack notification - integrate with Slack API
    this.logger.info(`Slack notification sent: ${message.title}`);
  }

  async sendWebhookNotification(channel, alert, message) {
    // Mock webhook - integrate with HTTP client
    this.logger.info(`Webhook notification sent: ${message.title}`);
  }

  async sendPagerDutyNotification(channel, alert, message) {
    // Mock PagerDuty - integrate with PagerDuty API
    this.logger.info(`PagerDuty notification sent: ${message.title}`);
  }

  /**
   * Get active alerts
   */
  getActiveAlerts() {
    return Array.from(this.activeAlerts.values());
  }

  /**
   * Get alert history
   */
  getAlertHistory(limit = 100) {
    return this.alertHistory
      .sort((a, b) => new Date(b.startsAt) - new Date(a.startsAt))
      .slice(0, limit);
  }

  /**
   * Get alerting statistics
   */
  getStats() {
    return {
      ...this.stats,
      activeAlerts: this.activeAlerts.size,
      rules: this.rules.size,
      slos: this.slos.size,
      notifications: this.notifications.size,
      suppressions: this.suppressions.size
    };
  }

  /**
   * Cleanup old alerts
   */
  cleanupOldAlerts() {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    
    this.alertHistory = this.alertHistory.filter(alert => 
      new Date(alert.startsAt).getTime() > cutoff
    );
    
    this.logger.info('Alert cleanup completed');
  }
}

export { AlertManager };
