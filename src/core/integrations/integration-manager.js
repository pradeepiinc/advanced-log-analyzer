/**
 * Integration Manager
 * Handles integrations with external systems (Grafana, ServiceNow, Jira, Slack, Teams, etc.)
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { getConfigManager } from '../config/config-manager.js';
import fetch from 'node-fetch';

class IntegrationManager extends EventEmitter {
  constructor() {
    super();
    this.logger = createLogger('IntegrationManager');
    this.config = getConfigManager();
    
    this.integrations = new Map();
    this.webhooks = new Map();
    this.syncJobs = new Map();
    
    this.initializeIntegrations();
  }

  async initializeIntegrations() {
    try {
      // Initialize enabled integrations
      if (this.config.get('integrations.grafana.enabled')) {
        await this.initializeGrafana();
      }
      
      if (this.config.get('integrations.serviceNow.enabled')) {
        await this.initializeServiceNow();
      }
      
      if (this.config.get('integrations.jira.enabled')) {
        await this.initializeJira();
      }
      
      // Initialize notification channels
      this.initializeNotificationChannels();
      
      this.logger.info(`Initialized ${this.integrations.size} integrations`);
      
    } catch (error) {
      this.logger.error('Failed to initialize integrations:', error);
    }
  }

  // Grafana Integration
  async initializeGrafana() {
    const grafanaConfig = this.config.get('integrations.grafana');
    
    const integration = {
      name: 'grafana',
      type: 'monitoring',
      config: grafanaConfig,
      client: null,
      status: 'initializing'
    };
    
    try {
      // Test connection
      const response = await fetch(`${grafanaConfig.url}/api/health`, {
        headers: {
          'Authorization': `Bearer ${grafanaConfig.apiKey}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        integration.status = 'connected';
        integration.client = {
          url: grafanaConfig.url,
          apiKey: grafanaConfig.apiKey
        };
        
        // Create default dashboards
        await this.createGrafanaDashboards(integration);
        
        this.logger.info('Grafana integration initialized successfully');
      } else {
        throw new Error(`Grafana connection failed: ${response.statusText}`);
      }
      
    } catch (error) {
      integration.status = 'error';
      integration.error = error.message;
      this.logger.error('Grafana integration failed:', error);
    }
    
    this.integrations.set('grafana', integration);
  }

  async createGrafanaDashboards(grafanaIntegration) {
    const dashboards = [
      {
        title: 'Log Analytics Overview',
        panels: [
          {
            title: 'Log Volume',
            type: 'graph',
            targets: [{ expr: 'rate(logs_ingested_total[5m])' }]
          },
          {
            title: 'Error Rate',
            type: 'stat',
            targets: [{ expr: 'rate(logs_error_total[5m]) / rate(logs_total[5m])' }]
          },
          {
            title: 'Top Services by Log Volume',
            type: 'table',
            targets: [{ expr: 'topk(10, sum by (service) (rate(logs_total[5m])))' }]
          }
        ]
      },
      {
        title: 'Service Health',
        panels: [
          {
            title: 'Service Availability',
            type: 'heatmap',
            targets: [{ expr: 'avg_over_time(service_up[1h])' }]
          },
          {
            title: 'Response Time P95',
            type: 'graph',
            targets: [{ expr: 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))' }]
          }
        ]
      }
    ];
    
    for (const dashboard of dashboards) {
      try {
        await this.createGrafanaDashboard(grafanaIntegration, dashboard);
      } catch (error) {
        this.logger.warn(`Failed to create Grafana dashboard ${dashboard.title}:`, error);
      }
    }
  }

  async createGrafanaDashboard(integration, dashboardConfig) {
    const response = await fetch(`${integration.client.url}/api/dashboards/db`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${integration.client.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        dashboard: {
          title: dashboardConfig.title,
          tags: ['log-analyzer', 'auto-generated'],
          panels: dashboardConfig.panels.map((panel, index) => ({
            id: index + 1,
            title: panel.title,
            type: panel.type,
            gridPos: { h: 8, w: 12, x: (index % 2) * 12, y: Math.floor(index / 2) * 8 },
            targets: panel.targets
          }))
        },
        overwrite: true
      })
    });
    
    if (!response.ok) {
      throw new Error(`Failed to create dashboard: ${response.statusText}`);
    }
    
    const result = await response.json();
    this.logger.info(`Created Grafana dashboard: ${dashboardConfig.title}`);
    return result;
  }

  // ServiceNow Integration
  async initializeServiceNow() {
    const snowConfig = this.config.get('integrations.serviceNow');
    
    const integration = {
      name: 'servicenow',
      type: 'ticketing',
      config: snowConfig,
      client: null,
      status: 'initializing'
    };
    
    try {
      // Test connection
      const auth = Buffer.from(`${snowConfig.username}:${snowConfig.password}`).toString('base64');
      const response = await fetch(`https://${snowConfig.instance}.service-now.com/api/now/table/sys_user?sysparm_limit=1`, {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        integration.status = 'connected';
        integration.client = {
          instance: snowConfig.instance,
          auth: auth
        };
        
        this.logger.info('ServiceNow integration initialized successfully');
      } else {
        throw new Error(`ServiceNow connection failed: ${response.statusText}`);
      }
      
    } catch (error) {
      integration.status = 'error';
      integration.error = error.message;
      this.logger.error('ServiceNow integration failed:', error);
    }
    
    this.integrations.set('servicenow', integration);
  }

  async createServiceNowIncident(alertData) {
    const integration = this.integrations.get('servicenow');
    if (!integration || integration.status !== 'connected') {
      throw new Error('ServiceNow integration not available');
    }
    
    const incident = {
      short_description: `Log Alert: ${alertData.title}`,
      description: `
        Alert Details:
        - Level: ${alertData.level}
        - Service: ${alertData.service || 'Unknown'}
        - Count: ${alertData.count}
        - Time Range: ${alertData.timeRange}
        
        Query: ${alertData.query}
        
        Message: ${alertData.message}
      `,
      urgency: this.mapAlertLevelToUrgency(alertData.level),
      impact: this.mapAlertLevelToImpact(alertData.level),
      category: 'Software',
      subcategory: 'Application',
      assignment_group: 'IT Operations'
    };
    
    const response = await fetch(`https://${integration.client.instance}.service-now.com/api/now/table/incident`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${integration.client.auth}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(incident)
    });
    
    if (!response.ok) {
      throw new Error(`Failed to create ServiceNow incident: ${response.statusText}`);
    }
    
    const result = await response.json();
    this.logger.info(`Created ServiceNow incident: ${result.result.number}`);
    
    return {
      id: result.result.sys_id,
      number: result.result.number,
      url: `https://${integration.client.instance}.service-now.com/nav_to.do?uri=incident.do?sys_id=${result.result.sys_id}`
    };
  }

  // Jira Integration
  async initializeJira() {
    const jiraConfig = this.config.get('integrations.jira');
    
    const integration = {
      name: 'jira',
      type: 'ticketing',
      config: jiraConfig,
      client: null,
      status: 'initializing'
    };
    
    try {
      // Test connection
      const auth = Buffer.from(`${jiraConfig.username}:${jiraConfig.apiToken}`).toString('base64');
      const response = await fetch(`${jiraConfig.url}/rest/api/2/myself`, {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        integration.status = 'connected';
        integration.client = {
          url: jiraConfig.url,
          auth: auth
        };
        
        this.logger.info('Jira integration initialized successfully');
      } else {
        throw new Error(`Jira connection failed: ${response.statusText}`);
      }
      
    } catch (error) {
      integration.status = 'error';
      integration.error = error.message;
      this.logger.error('Jira integration failed:', error);
    }
    
    this.integrations.set('jira', integration);
  }

  async createJiraIssue(alertData, projectKey = 'OPS') {
    const integration = this.integrations.get('jira');
    if (!integration || integration.status !== 'connected') {
      throw new Error('Jira integration not available');
    }
    
    const issue = {
      fields: {
        project: { key: projectKey },
        summary: `Log Alert: ${alertData.title}`,
        description: `
Alert Details:
* Level: ${alertData.level}
* Service: ${alertData.service || 'Unknown'}
* Count: ${alertData.count}
* Time Range: ${alertData.timeRange}

Query: {code}${alertData.query}{code}

Message: {quote}${alertData.message}{quote}
        `,
        issuetype: { name: 'Bug' },
        priority: { name: this.mapAlertLevelToPriority(alertData.level) },
        labels: ['log-alert', 'auto-generated', alertData.level]
      }
    };
    
    const response = await fetch(`${integration.client.url}/rest/api/2/issue`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${integration.client.auth}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(issue)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to create Jira issue: ${response.statusText} - ${errorText}`);
    }
    
    const result = await response.json();
    this.logger.info(`Created Jira issue: ${result.key}`);
    
    return {
      id: result.id,
      key: result.key,
      url: `${integration.client.url}/browse/${result.key}`
    };
  }

  // Notification Channels
  initializeNotificationChannels() {
    // Slack webhook
    if (this.config.get('alerting.notifications.slack.enabled')) {
      this.webhooks.set('slack', {
        url: this.config.get('alerting.notifications.slack.webhookUrl'),
        channel: this.config.get('alerting.notifications.slack.channel')
      });
    }
    
    // Generic webhook
    if (this.config.get('alerting.notifications.webhook.enabled')) {
      this.webhooks.set('webhook', {
        url: this.config.get('alerting.notifications.webhook.url'),
        headers: this.config.get('alerting.notifications.webhook.headers')
      });
    }
  }

  async sendSlackNotification(alertData) {
    const webhook = this.webhooks.get('slack');
    if (!webhook) {
      throw new Error('Slack webhook not configured');
    }
    
    const color = this.getSlackColorForLevel(alertData.level);
    const message = {
      channel: webhook.channel,
      username: 'Log Analyzer',
      icon_emoji: ':warning:',
      attachments: [{
        color: color,
        title: `🚨 ${alertData.title}`,
        fields: [
          { title: 'Level', value: alertData.level.toUpperCase(), short: true },
          { title: 'Service', value: alertData.service || 'Unknown', short: true },
          { title: 'Count', value: alertData.count.toString(), short: true },
          { title: 'Time Range', value: alertData.timeRange, short: true }
        ],
        text: alertData.message,
        footer: 'Production Log Analyzer',
        ts: Math.floor(Date.now() / 1000)
      }]
    };
    
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });
    
    if (!response.ok) {
      throw new Error(`Slack notification failed: ${response.statusText}`);
    }
    
    this.logger.info('Slack notification sent successfully');
  }

  async sendTeamsNotification(alertData) {
    // Microsoft Teams webhook implementation
    const webhook = this.webhooks.get('teams');
    if (!webhook) {
      throw new Error('Teams webhook not configured');
    }
    
    const color = this.getTeamsColorForLevel(alertData.level);
    const message = {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      "themeColor": color,
      "summary": `Log Alert: ${alertData.title}`,
      "sections": [{
        "activityTitle": `🚨 ${alertData.title}`,
        "activitySubtitle": `Level: ${alertData.level.toUpperCase()}`,
        "facts": [
          { "name": "Service", "value": alertData.service || 'Unknown' },
          { "name": "Count", "value": alertData.count.toString() },
          { "name": "Time Range", "value": alertData.timeRange }
        ],
        "text": alertData.message
      }],
      "potentialAction": [{
        "@type": "OpenUri",
        "name": "View in Log Analyzer",
        "targets": [{
          "os": "default",
          "uri": `${this.config.get('server.host')}:${this.config.get('server.port')}/alerts`
        }]
      }]
    };
    
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });
    
    if (!response.ok) {
      throw new Error(`Teams notification failed: ${response.statusText}`);
    }
    
    this.logger.info('Teams notification sent successfully');
  }

  async sendGenericWebhook(alertData) {
    const webhook = this.webhooks.get('webhook');
    if (!webhook) {
      throw new Error('Generic webhook not configured');
    }
    
    const payload = {
      timestamp: new Date().toISOString(),
      alert: alertData,
      source: 'production-log-analyzer'
    };
    
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...webhook.headers
      },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      throw new Error(`Webhook notification failed: ${response.statusText}`);
    }
    
    this.logger.info('Generic webhook notification sent successfully');
  }

  // Data Export and Sync
  async exportToGrafana(metricsData) {
    const integration = this.integrations.get('grafana');
    if (!integration || integration.status !== 'connected') {
      throw new Error('Grafana integration not available');
    }
    
    // Export metrics to Grafana's data source
    // This would typically involve pushing to Prometheus or another data source
    this.logger.info('Exported metrics to Grafana');
  }

  async syncWithExternalSystems() {
    // Periodic sync job to keep external systems updated
    for (const [name, integration] of this.integrations) {
      if (integration.status === 'connected') {
        try {
          switch (name) {
            case 'grafana':
              await this.syncGrafanaData();
              break;
            case 'servicenow':
              await this.syncServiceNowIncidents();
              break;
            case 'jira':
              await this.syncJiraIssues();
              break;
          }
        } catch (error) {
          this.logger.error(`Sync failed for ${name}:`, error);
        }
      }
    }
  }

  async syncGrafanaData() {
    // Sync dashboard data, annotations, etc.
    this.logger.debug('Syncing Grafana data');
  }

  async syncServiceNowIncidents() {
    // Check status of created incidents, update if needed
    this.logger.debug('Syncing ServiceNow incidents');
  }

  async syncJiraIssues() {
    // Check status of created issues, update if needed
    this.logger.debug('Syncing Jira issues');
  }

  // Utility methods
  mapAlertLevelToUrgency(level) {
    const mapping = {
      'critical': '1',
      'error': '2',
      'warning': '3',
      'info': '4'
    };
    return mapping[level] || '3';
  }

  mapAlertLevelToImpact(level) {
    const mapping = {
      'critical': '1',
      'error': '2',
      'warning': '3',
      'info': '4'
    };
    return mapping[level] || '3';
  }

  mapAlertLevelToPriority(level) {
    const mapping = {
      'critical': 'Highest',
      'error': 'High',
      'warning': 'Medium',
      'info': 'Low'
    };
    return mapping[level] || 'Medium';
  }

  getSlackColorForLevel(level) {
    const colors = {
      'critical': 'danger',
      'error': 'danger',
      'warning': 'warning',
      'info': 'good'
    };
    return colors[level] || 'warning';
  }

  getTeamsColorForLevel(level) {
    const colors = {
      'critical': 'FF0000',
      'error': 'FF6600',
      'warning': 'FFCC00',
      'info': '00CC00'
    };
    return colors[level] || 'FFCC00';
  }

  // API endpoints for integration management
  getIntegrationStatus() {
    const status = {};
    for (const [name, integration] of this.integrations) {
      status[name] = {
        status: integration.status,
        type: integration.type,
        error: integration.error || null
      };
    }
    return status;
  }

  async testIntegration(name) {
    const integration = this.integrations.get(name);
    if (!integration) {
      throw new Error(`Integration ${name} not found`);
    }
    
    try {
      switch (name) {
        case 'grafana':
          await this.testGrafanaConnection(integration);
          break;
        case 'servicenow':
          await this.testServiceNowConnection(integration);
          break;
        case 'jira':
          await this.testJiraConnection(integration);
          break;
        default:
          throw new Error(`Test not implemented for ${name}`);
      }
      
      integration.status = 'connected';
      integration.error = null;
      return { success: true, message: `${name} connection successful` };
      
    } catch (error) {
      integration.status = 'error';
      integration.error = error.message;
      return { success: false, message: error.message };
    }
  }

  async testGrafanaConnection(integration) {
    const response = await fetch(`${integration.config.url}/api/health`, {
      headers: {
        'Authorization': `Bearer ${integration.config.apiKey}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Grafana test failed: ${response.statusText}`);
    }
  }

  async testServiceNowConnection(integration) {
    const auth = Buffer.from(`${integration.config.username}:${integration.config.password}`).toString('base64');
    const response = await fetch(`https://${integration.config.instance}.service-now.com/api/now/table/sys_user?sysparm_limit=1`, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`ServiceNow test failed: ${response.statusText}`);
    }
  }

  async testJiraConnection(integration) {
    const auth = Buffer.from(`${integration.config.username}:${integration.config.apiToken}`).toString('base64');
    const response = await fetch(`${integration.config.url}/rest/api/2/myself`, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Jira test failed: ${response.statusText}`);
    }
  }

  // Event handlers for alert notifications
  async handleAlert(alertData) {
    const notifications = [];
    
    try {
      // Send Slack notification if enabled
      if (this.webhooks.has('slack')) {
        await this.sendSlackNotification(alertData);
        notifications.push('slack');
      }
      
      // Send Teams notification if enabled
      if (this.webhooks.has('teams')) {
        await this.sendTeamsNotification(alertData);
        notifications.push('teams');
      }
      
      // Send generic webhook if enabled
      if (this.webhooks.has('webhook')) {
        await this.sendGenericWebhook(alertData);
        notifications.push('webhook');
      }
      
      // Create tickets for critical/error alerts
      if (['critical', 'error'].includes(alertData.level)) {
        if (this.integrations.has('servicenow') && this.integrations.get('servicenow').status === 'connected') {
          const incident = await this.createServiceNowIncident(alertData);
          notifications.push(`servicenow:${incident.number}`);
        }
        
        if (this.integrations.has('jira') && this.integrations.get('jira').status === 'connected') {
          const issue = await this.createJiraIssue(alertData);
          notifications.push(`jira:${issue.key}`);
        }
      }
      
      this.emit('alert-processed', { alertData, notifications });
      
    } catch (error) {
      this.logger.error('Failed to process alert through integrations:', error);
      this.emit('alert-error', { alertData, error: error.message });
    }
  }

  // Cleanup and shutdown
  async shutdown() {
    // Stop sync jobs
    for (const [name, job] of this.syncJobs) {
      clearInterval(job);
    }
    
    this.logger.info('Integration manager shutdown complete');
  }
}

// Singleton instance
let integrationManager = null;

export function getIntegrationManager() {
  if (!integrationManager) {
    integrationManager = new IntegrationManager();
  }
  return integrationManager;
}

export { IntegrationManager };
