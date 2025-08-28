/**
 * Service Topology and Correlation Graph
 * Maps service dependencies, traces relationships, and provides RCA capabilities
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';

class ServiceTopology extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = {
      maxNodes: config.maxNodes || 1000,
      maxEdges: config.maxEdges || 5000,
      correlationWindow: config.correlationWindow || 300000, // 5 minutes
      minCorrelationStrength: config.minCorrelationStrength || 0.3,
      enableAutoDiscovery: config.enableAutoDiscovery !== false,
      ...config
    };

    this.logger = createLogger('ServiceTopology');
    this.services = new Map();
    this.dependencies = new Map();
    this.correlations = new Map();
    this.deployEvents = [];
    this.incidents = new Map();
    
    this.stats = {
      servicesDiscovered: 0,
      dependenciesFound: 0,
      correlationsDetected: 0
    };
  }

  /**
   * Process trace data to build service topology
   */
  async processTrace(traceData) {
    try {
      const { traceId, spans } = traceData;
      
      if (!spans || !Array.isArray(spans)) {
        return;
      }

      // Extract service information from spans
      for (const span of spans) {
        await this.processSpan(span, traceId);
      }

      // Build dependencies from span relationships
      await this.buildDependenciesFromSpans(spans, traceId);
      
      this.emit('trace-processed', { traceId, serviceCount: spans.length });

    } catch (error) {
      this.logger.error('Failed to process trace:', error);
    }
  }

  async processSpan(span, traceId) {
    const serviceName = span.process?.serviceName || span.serviceName || 'unknown';
    const operationName = span.operationName || span.name || 'unknown';
    
    // Register or update service
    if (!this.services.has(serviceName)) {
      const service = {
        name: serviceName,
        id: uuidv4(),
        operations: new Set(),
        endpoints: new Set(),
        versions: new Set(),
        firstSeen: new Date(),
        lastSeen: new Date(),
        spanCount: 0,
        errorCount: 0,
        avgDuration: 0,
        tags: new Set()
      };
      
      this.services.set(serviceName, service);
      this.stats.servicesDiscovered++;
      this.emit('service-discovered', service);
    }

    const service = this.services.get(serviceName);
    service.operations.add(operationName);
    service.lastSeen = new Date();
    service.spanCount++;
    
    // Update service metadata from span
    if (span.tags) {
      for (const tag of span.tags) {
        if (tag.key === 'version' || tag.key === 'service.version') {
          service.versions.add(tag.value);
        }
        if (tag.key === 'http.url' || tag.key === 'http.route') {
          service.endpoints.add(tag.value);
        }
        service.tags.add(`${tag.key}:${tag.value}`);
      }
    }
    
    // Track errors
    if (span.tags?.some(tag => tag.key === 'error' && tag.value === true)) {
      service.errorCount++;
    }
    
    // Update average duration
    if (span.duration) {
      service.avgDuration = (service.avgDuration + span.duration) / 2;
    }
  }

  async buildDependenciesFromSpans(spans, traceId) {
    // Build parent-child relationships
    const spanMap = new Map();
    spans.forEach(span => spanMap.set(span.spanId, span));
    
    for (const span of spans) {
      if (span.parentSpanId && spanMap.has(span.parentSpanId)) {
        const parentSpan = spanMap.get(span.parentSpanId);
        const parentService = parentSpan.process?.serviceName || 'unknown';
        const childService = span.process?.serviceName || 'unknown';
        
        if (parentService !== childService) {
          await this.addDependency(parentService, childService, {
            traceId,
            operation: span.operationName,
            duration: span.duration,
            timestamp: span.startTime
          });
        }
      }
    }
  }

  async addDependency(fromService, toService, metadata = {}) {
    const depKey = `${fromService}->${toService}`;
    
    if (!this.dependencies.has(depKey)) {
      const dependency = {
        id: uuidv4(),
        from: fromService,
        to: toService,
        type: 'service_call',
        strength: 1,
        callCount: 0,
        errorCount: 0,
        avgLatency: 0,
        firstSeen: new Date(),
        lastSeen: new Date(),
        operations: new Set(),
        traces: new Set()
      };
      
      this.dependencies.set(depKey, dependency);
      this.stats.dependenciesFound++;
      this.emit('dependency-discovered', dependency);
    }
    
    const dependency = this.dependencies.get(depKey);
    dependency.callCount++;
    dependency.lastSeen = new Date();
    dependency.strength = Math.min(10, dependency.strength + 0.1);
    
    if (metadata.operation) {
      dependency.operations.add(metadata.operation);
    }
    if (metadata.traceId) {
      dependency.traces.add(metadata.traceId);
    }
    if (metadata.duration) {
      dependency.avgLatency = (dependency.avgLatency + metadata.duration) / 2;
    }
  }

  /**
   * Process log entries to enhance topology
   */
  async processLogEntry(logEntry) {
    try {
      const serviceName = logEntry.service || this.extractServiceFromLog(logEntry);
      
      if (serviceName) {
        // Update service info from logs
        await this.updateServiceFromLog(serviceName, logEntry);
        
        // Detect correlations with other services
        await this.detectLogCorrelations(logEntry);
      }

    } catch (error) {
      this.logger.error('Failed to process log entry:', error);
    }
  }

  extractServiceFromLog(logEntry) {
    const message = logEntry.message || '';
    
    // Try to extract service name from various patterns
    const patterns = [
      /service[=:](\w+)/i,
      /app[=:](\w+)/i,
      /component[=:](\w+)/i
    ];
    
    for (const pattern of patterns) {
      const match = message.match(pattern);
      if (match) {
        return match[1];
      }
    }
    
    return null;
  }

  async updateServiceFromLog(serviceName, logEntry) {
    if (!this.services.has(serviceName)) {
      // Auto-discover service from logs
      const service = {
        name: serviceName,
        id: uuidv4(),
        operations: new Set(),
        endpoints: new Set(),
        versions: new Set(),
        firstSeen: new Date(logEntry.timestamp),
        lastSeen: new Date(logEntry.timestamp),
        spanCount: 0,
        errorCount: 0,
        avgDuration: 0,
        tags: new Set(),
        discoveredFrom: 'logs'
      };
      
      this.services.set(serviceName, service);
      this.stats.servicesDiscovered++;
    }
    
    const service = this.services.get(serviceName);
    service.lastSeen = new Date(logEntry.timestamp);
    
    if (logEntry.level === 'ERROR') {
      service.errorCount++;
    }
  }

  async detectLogCorrelations(logEntry) {
    const timestamp = new Date(logEntry.timestamp).getTime();
    const windowStart = timestamp - this.config.correlationWindow;
    const windowEnd = timestamp + this.config.correlationWindow;
    
    // Find other log entries in correlation window
    // This would typically query the storage layer
    // For now, we'll emit an event for external correlation detection
    this.emit('correlation-candidate', {
      logEntry,
      windowStart,
      windowEnd
    });
  }

  /**
   * Record deployment event
   */
  recordDeployment(deploymentData) {
    const deployment = {
      id: uuidv4(),
      service: deploymentData.service,
      version: deploymentData.version,
      environment: deploymentData.environment,
      timestamp: new Date(deploymentData.timestamp || Date.now()),
      type: deploymentData.type || 'deployment',
      metadata: deploymentData.metadata || {}
    };
    
    this.deployEvents.push(deployment);
    
    // Keep only recent deployments
    const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days
    this.deployEvents = this.deployEvents.filter(d => d.timestamp.getTime() > cutoff);
    
    this.emit('deployment-recorded', deployment);
    this.logger.info(`Recorded deployment: ${deployment.service} v${deployment.version}`);
  }

  /**
   * Analyze blast radius for an incident
   */
  async analyzeBlastRadius(incidentData) {
    const { service, timestamp, type } = incidentData;
    const incidentTime = new Date(timestamp).getTime();
    
    const blastRadius = {
      primaryService: service,
      affectedServices: new Set([service]),
      impactedDependencies: [],
      correlatedEvents: [],
      severity: 'low'
    };
    
    // Find downstream dependencies
    for (const [depKey, dependency] of this.dependencies) {
      if (dependency.from === service) {
        blastRadius.affectedServices.add(dependency.to);
        blastRadius.impactedDependencies.push(dependency);
      }
    }
    
    // Find recent deployments that might be related
    const recentDeployments = this.deployEvents.filter(d => 
      Math.abs(d.timestamp.getTime() - incidentTime) < (60 * 60 * 1000) && // 1 hour
      (d.service === service || blastRadius.affectedServices.has(d.service))
    );
    
    blastRadius.correlatedEvents.push(...recentDeployments);
    
    // Calculate severity based on blast radius size
    if (blastRadius.affectedServices.size > 10) {
      blastRadius.severity = 'critical';
    } else if (blastRadius.affectedServices.size > 5) {
      blastRadius.severity = 'high';
    } else if (blastRadius.affectedServices.size > 2) {
      blastRadius.severity = 'medium';
    }
    
    this.emit('blast-radius-analyzed', blastRadius);
    return blastRadius;
  }

  /**
   * Get service topology graph
   */
  getTopologyGraph() {
    const nodes = Array.from(this.services.values()).map(service => ({
      id: service.name,
      label: service.name,
      type: 'service',
      metadata: {
        operations: Array.from(service.operations),
        endpoints: Array.from(service.endpoints),
        versions: Array.from(service.versions),
        spanCount: service.spanCount,
        errorCount: service.errorCount,
        avgDuration: service.avgDuration,
        lastSeen: service.lastSeen
      }
    }));
    
    const edges = Array.from(this.dependencies.values()).map(dep => ({
      id: dep.id,
      source: dep.from,
      target: dep.to,
      type: dep.type,
      weight: dep.strength,
      metadata: {
        callCount: dep.callCount,
        errorCount: dep.errorCount,
        avgLatency: dep.avgLatency,
        operations: Array.from(dep.operations)
      }
    }));
    
    return { nodes, edges };
  }

  /**
   * Find critical path between services
   */
  findCriticalPath(fromService, toService) {
    const graph = this.getTopologyGraph();
    const visited = new Set();
    const path = [];
    
    const dfs = (current, target, currentPath) => {
      if (current === target) {
        return [...currentPath, current];
      }
      
      if (visited.has(current)) {
        return null;
      }
      
      visited.add(current);
      
      const edges = graph.edges.filter(e => e.source === current);
      for (const edge of edges) {
        const result = dfs(edge.target, target, [...currentPath, current]);
        if (result) {
          return result;
        }
      }
      
      visited.delete(current);
      return null;
    };
    
    return dfs(fromService, toService, []);
  }

  /**
   * Get service health summary
   */
  getServiceHealth() {
    const health = {};
    
    for (const [name, service] of this.services) {
      const errorRate = service.spanCount > 0 ? service.errorCount / service.spanCount : 0;
      const isHealthy = errorRate < 0.05 && service.avgDuration < 1000;
      
      health[name] = {
        status: isHealthy ? 'healthy' : 'degraded',
        errorRate,
        avgDuration: service.avgDuration,
        lastSeen: service.lastSeen,
        spanCount: service.spanCount
      };
    }
    
    return health;
  }

  /**
   * Get topology statistics
   */
  getStats() {
    return {
      ...this.stats,
      services: this.services.size,
      dependencies: this.dependencies.size,
      deployEvents: this.deployEvents.length,
      incidents: this.incidents.size,
      config: this.config
    };
  }

  /**
   * Export topology data
   */
  exportTopology() {
    return {
      services: Array.from(this.services.entries()).map(([name, service]) => ({
        name,
        ...service,
        operations: Array.from(service.operations),
        endpoints: Array.from(service.endpoints),
        versions: Array.from(service.versions),
        tags: Array.from(service.tags)
      })),
      dependencies: Array.from(this.dependencies.values()).map(dep => ({
        ...dep,
        operations: Array.from(dep.operations),
        traces: Array.from(dep.traces)
      })),
      deployEvents: this.deployEvents,
      exportedAt: new Date().toISOString()
    };
  }

  /**
   * Clear old data
   */
  cleanup() {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    
    // Remove old services that haven't been seen recently
    for (const [name, service] of this.services) {
      if (service.lastSeen.getTime() < cutoff) {
        this.services.delete(name);
      }
    }
    
    // Remove dependencies for deleted services
    for (const [depKey, dependency] of this.dependencies) {
      if (!this.services.has(dependency.from) || !this.services.has(dependency.to)) {
        this.dependencies.delete(depKey);
      }
    }
    
    this.logger.info('Topology cleanup completed');
  }
}

export { ServiceTopology };
