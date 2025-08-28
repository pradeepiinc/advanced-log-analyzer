import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import session from 'express-session';
import crypto from 'crypto';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import { createServer } from 'http';
import dotenv from 'dotenv';

// Import advanced modules
import { OTelCollector } from './core/ingestion/otel-collector.js';
import { TransportManager } from './core/ingestion/transport-manager.js';
import { EnrichmentEngine } from './core/parsing/enrichment-engine.js';
import { StorageManager } from './core/storage/storage-manager.js';
import { QueryEngine } from './core/query/query-engine.js';
import { AnomalyDetector } from './core/ml/anomaly-detector.js';
import { ServiceTopology } from './core/correlation/service-topology.js';
import { AlertManager } from './core/alerting/alert-manager.js';
import { createLogger } from './core/utils/logger.js';
import { analyzeLogsFromText } from './analyzer.js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
const port = process.env.PORT || 3000;
const logger = createLogger('Server');

const dataDir = path.join(__dirname, '..', 'data');
const logsDir = path.join(dataDir, 'logs');

// Ensure directories exist
fs.mkdirSync(logsDir, { recursive: true });

// Initialize advanced modules
let otelCollector, transportManager, enrichmentEngine, storageManager, queryEngine, anomalyDetector, serviceTopology, alertManager;

// Module initialization flag
let modulesInitialized = false;

// Security and performance middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable for development
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.text({ type: ['text/*', 'application/log'], limit: '50mb' }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Sessions for simple auth
app.use(
  session({
    name: 'pla.sid',
    secret: process.env.SESSION_SECRET || crypto.randomBytes(16).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' }
  })
);

// Simple auth helpers
const ensureAuthedPage = (req, res, next) => {
  if (req.session?.user) return next();
  return res.redirect('/login.html');
};

const ensureAuthedApi = (req, res, next) => {
  if (req.session?.user) return next();
  return res.status(401).json({ error: 'Unauthorized' });
};

// Public assets
app.use('/login.html', express.static(path.join(__dirname, '..', 'public', 'login.html')));
app.use('/styles.css', express.static(path.join(__dirname, '..', 'public', 'styles.css')));
app.use('/main.js', express.static(path.join(__dirname, '..', 'public', 'main.js')));
app.use('/auth.js', express.static(path.join(__dirname, '..', 'public', 'auth.js')));
app.use('/logs.js', express.static(path.join(__dirname, '..', 'public', 'logs.js')));
app.use('/analysis.js', express.static(path.join(__dirname, '..', 'public', 'analysis.js')));
app.use('/requirements.js', express.static(path.join(__dirname, '..', 'public', 'requirements.js')));
app.use('/alerts.html', express.static(path.join(__dirname, '..', 'public', 'alerts.html')));            //ADDED
app.use('/alerts.js', express.static(path.join(__dirname, '..', 'public', 'alerts.js')));             

app.get('/alerts.html', ensureAuthedPage, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'alerts.html'));
}); // Till here


// Protect application pages
app.get(['/', '/index.html', '/logs.html', '/analysis.html', '/requirements.html', '/alerts.html'], ensureAuthedPage, (req, res) => {
  const file = req.path === '/' ? 'index.html' : req.path.replace('/', '');
  res.sendFile(path.join(__dirname, '..', 'public', file));
});

// Fallback static (assets/images etc.)
app.use(express.static(path.join(__dirname, '..', 'public')));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });


// Auth routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const expectedUser = process.env.ADMIN_USER || 'admin';
  const expectedPass = process.env.ADMIN_PASS || 'admin123';
  if (username === expectedUser && password === expectedPass) {
    req.session.user = { username };
    return res.json({ message: 'ok' });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'ok' });
  });
});

app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: Boolean(req.session?.user), user: req.session?.user || null });
});

// Initialize advanced modules function
async function initializeAdvancedModules() {
  try {
    logger.info('Initializing advanced production log analyzer modules...');
    
    // Initialize OTel Collector
    otelCollector = new OTelCollector({
      serviceName: 'production-log-analyzer',
      serviceVersion: '2.0.0',
      environment: process.env.NODE_ENV || 'development'
    });
    
    // Initialize Transport Manager
    transportManager = new TransportManager({
      http: { enabled: true, port: port + 1 },
      syslog: { enabled: true, port: 514 },
      kafka: { enabled: process.env.KAFKA_ENABLED === 'true' },
      redis: { enabled: process.env.REDIS_ENABLED === 'true' }
    });
    
    // Initialize Enrichment Engine
    enrichmentEngine = new EnrichmentEngine({
      enablePiiDetection: true,
      piiRedactionMode: 'hash',
      enableGeoEnrichment: true
    });
    
    // Initialize Storage Manager
    storageManager = new StorageManager({
      tiers: {
        hot: {
          enabled: true,
          elasticsearch: {
            node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200'
          }
        },
        warm: {
          enabled: process.env.CLICKHOUSE_ENABLED === 'true',
          clickhouse: {
            host: process.env.CLICKHOUSE_HOST || 'localhost'
          }
        },
        cold: {
          enabled: process.env.S3_ENABLED === 'true'
        }
      }
    });
    
    // Initialize Query Engine
    queryEngine = new QueryEngine(storageManager, {
      enableSql: true,
      enableRegex: true,
      cacheResults: true
    });
    
    // Initialize Anomaly Detector
    anomalyDetector = new AnomalyDetector({
      algorithms: {
        statistical: true,
        clustering: true,
        timeSeries: true,
        logPatterns: true
      }
    });
    
    // Initialize Service Topology
    serviceTopology = new ServiceTopology({
      enableAutoDiscovery: true,
      maxNodes: 1000
    });
    
    // Initialize Alert Manager
    alertManager = new AlertManager({
      sloDefaults: {
        errorBudget: 0.001,
        burnRateThreshold: 2.0
      }
    });
    
    // Initialize storage and transport
    await storageManager.initialize();
    await transportManager.initialize();
    
    // Set up event handlers
    setupEventHandlers();
    
    modulesInitialized = true;
    logger.info('All advanced modules initialized successfully');
    
  } catch (error) {
    logger.error('Failed to initialize advanced modules:', error);
    throw error;
  }
}

// Setup event handlers between modules
function setupEventHandlers() {
  // Transport Manager -> Enrichment Engine
  transportManager.on('message', async (message) => {
    try {
      const enriched = await enrichmentEngine.parseAndEnrich(message.data);
      if (enriched) {
        await processEnrichedData(enriched, message);
      }
    } catch (error) {
      logger.error('Failed to process transport message:', error);
    }
  });
  
  // OTel Collector -> Service Topology
  otelCollector.on('trace', async (traceData) => {
    await serviceTopology.processTrace(traceData);
  });
  
  otelCollector.on('log', async (logData) => {
    await serviceTopology.processLogEntry(logData);
  });
  
  // Anomaly Detector -> Alert Manager
  anomalyDetector.on('anomaly-detected', async (anomaly) => {
    const metrics = { [anomaly.metric]: anomaly.value };
    await alertManager.evaluateMetrics(metrics, new Date(anomaly.timestamp));
  });
  
  // Alert Manager -> WebSocket notifications
  alertManager.on('alert-created', (alert) => {
    io.emit('alert', { type: 'created', alert });
  });
  
  alertManager.on('alert-resolved', (alert) => {
    io.emit('alert', { type: 'resolved', alert });
  });
  
  // Real-time log streaming
  setupLogStreaming();
}

// Process enriched data through the pipeline
async function processEnrichedData(enrichedData, originalMessage) {
  try {
    // Store in appropriate tier
    const storageResult = await storageManager.store(enrichedData);
    
    // Extract metrics for anomaly detection
    const metrics = extractMetricsFromLog(enrichedData);
    if (Object.keys(metrics).length > 0) {
      await anomalyDetector.analyzeMetrics(metrics, new Date(enrichedData.timestamp));
      await anomalyDetector.updateBaselines(metrics, new Date(enrichedData.timestamp));
    }
    
    // Analyze for log pattern anomalies
    await anomalyDetector.analyzeLogs([enrichedData]);
    
    // Update service topology
    await serviceTopology.processLogEntry(enrichedData);
    
    // Emit to real-time subscribers
    io.emit('log-entry', enrichedData);
    
  } catch (error) {
    logger.error('Failed to process enriched data:', error);
  }
}

// Extract metrics from log entry
function extractMetricsFromLog(logEntry) {
  const metrics = {};
  
  if (logEntry.response_time) {
    metrics.latency_p95 = logEntry.response_time;
  }
  
  if (logEntry.level === 'ERROR') {
    metrics.errorRate = 1;
  } else {
    metrics.errorRate = 0;
  }
  
  if (logEntry.status_code) {
    metrics.status_code = logEntry.status_code;
  }
  
  return metrics;
}

// Setup real-time log streaming
function setupLogStreaming() {
  io.on('connection', (socket) => {
    logger.info(`Client connected: ${socket.id}`);
    
    socket.on('subscribe-logs', (filters) => {
      socket.join('log-stream');
      logger.info(`Client ${socket.id} subscribed to log stream`);
    });
    
    socket.on('unsubscribe-logs', () => {
      socket.leave('log-stream');
      logger.info(`Client ${socket.id} unsubscribed from log stream`);
    });
    
    socket.on('disconnect', () => {
      logger.info(`Client disconnected: ${socket.id}`);
    });
  });
}

let alerts = [];
let alertHistory = [];

// Advanced API endpoints

// Health check with module status
app.get('/api/health', (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    modules: {
      initialized: modulesInitialized,
      otelCollector: otelCollector ? 'active' : 'inactive',
      transportManager: transportManager ? 'active' : 'inactive',
      storageManager: storageManager ? 'active' : 'inactive',
      queryEngine: queryEngine ? 'active' : 'inactive',
      anomalyDetector: anomalyDetector ? 'active' : 'inactive',
      serviceTopology: serviceTopology ? 'active' : 'inactive',
      alertManager: alertManager ? 'active' : 'inactive'
    }
  };
  res.json(health);
});

// Advanced query endpoint
app.post('/api/query', ensureAuthedApi, async (req, res) => {
  try {
    if (!queryEngine) {
      return res.status(503).json({ error: 'Query engine not initialized' });
    }
    
    const { query, options = {} } = req.body;
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }
    
    const result = await queryEngine.executeQuery(query, options);
    res.json(result);
    
  } catch (error) {
    logger.error('Query execution failed:', error);
    res.status(500).json({ error: error.message });
  }
});

// Service topology endpoint
app.get('/api/topology', ensureAuthedApi, (req, res) => {
  try {
    if (!serviceTopology) {
      return res.status(503).json({ error: 'Service topology not initialized' });
    }
    
    const topology = serviceTopology.getTopologyGraph();
    res.json(topology);
    
  } catch (error) {
    logger.error('Failed to get topology:', error);
    res.status(500).json({ error: error.message });
  }
});

// Service health endpoint
app.get('/api/services/health', ensureAuthedApi, (req, res) => {
  try {
    if (!serviceTopology) {
      return res.status(503).json({ error: 'Service topology not initialized' });
    }
    
    const health = serviceTopology.getServiceHealth();
    res.json(health);
    
  } catch (error) {
    logger.error('Failed to get service health:', error);
    res.status(500).json({ error: error.message });
  }
});

// Anomaly detection endpoint
app.get('/api/anomalies', ensureAuthedApi, (req, res) => {
  try {
    if (!anomalyDetector) {
      return res.status(503).json({ error: 'Anomaly detector not initialized' });
    }
    
    const stats = anomalyDetector.getStats();
    res.json(stats);
    
  } catch (error) {
    logger.error('Failed to get anomalies:', error);
    res.status(500).json({ error: error.message });
  }
});

// Alert management endpoints
app.get('/api/alerts', ensureAuthedApi, (req, res) => {
  try {
    if (!alertManager) {
      return res.json({ alerts, history: alertHistory }); // Fallback to legacy
    }
    
    const activeAlerts = alertManager.getActiveAlerts();
    const alertHistory = alertManager.getAlertHistory();
    
    res.json({ alerts: activeAlerts, history: alertHistory });
    
  } catch (error) {
    logger.error('Failed to get alerts:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/alerts/rules', ensureAuthedApi, (req, res) => {
  try {
    if (!alertManager) {
      return res.status(503).json({ error: 'Alert manager not initialized' });
    }
    
    const rule = alertManager.addRule(req.body);
    res.json({ message: 'Alert rule added', rule });
    
  } catch (error) {
    logger.error('Failed to add alert rule:', error);
    res.status(500).json({ error: error.message });
  }
});

// SLO management
app.post('/api/slo', ensureAuthedApi, (req, res) => {
  try {
    if (!alertManager) {
      return res.status(503).json({ error: 'Alert manager not initialized' });
    }
    
    const slo = alertManager.addSLO(req.body);
    res.json({ message: 'SLO added', slo });
    
  } catch (error) {
    logger.error('Failed to add SLO:', error);
    res.status(500).json({ error: error.message });
  }
});

// OTel ingestion endpoints
app.post('/api/otel/logs', ensureAuthedApi, async (req, res) => {
  try {
    if (!otelCollector) {
      return res.status(503).json({ error: 'OTel collector not initialized' });
    }
    
    const result = await otelCollector.ingestLog(req.body);
    res.json(result);
    
  } catch (error) {
    logger.error('OTel log ingestion failed:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/otel/metrics', ensureAuthedApi, async (req, res) => {
  try {
    if (!otelCollector) {
      return res.status(503).json({ error: 'OTel collector not initialized' });
    }
    
    const result = await otelCollector.ingestMetric(req.body);
    res.json(result);
    
  } catch (error) {
    logger.error('OTel metric ingestion failed:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/otel/traces', ensureAuthedApi, async (req, res) => {
  try {
    if (!otelCollector) {
      return res.status(503).json({ error: 'OTel collector not initialized' });
    }
    
    const result = await otelCollector.ingestTrace(req.body);
    res.json(result);
    
  } catch (error) {
    logger.error('OTel trace ingestion failed:', error);
    res.status(500).json({ error: error.message });
  }
});

// Legacy alerts endpoint for backward compatibility
app.get('/Public/alerts', ensureAuthedApi, (req, res) => {
  res.json({ alerts, history: alertHistory });
});

app.post('/alerts', ensureAuthedApi, (req, res) => {
  const { condition, threshold } = req.body;
  if (!condition || !threshold) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const alert = { condition, threshold: Number(threshold) };
  alerts.push(alert);
  alertHistory.push({
    timestamp: new Date().toISOString(),
    message: `Alert created: ${condition} ≥ ${threshold}`
  });
  res.json({ message: 'Alert added', alert });
});

app.post('/api/notifications', ensureAuthedApi, (req, res) => {
  const { email, webhook, slack } = req.body;
  // You can store or log these settings as needed
  res.json({ message: 'Notification settings saved', settings: { email, webhook, slack } });
});


app.get('/api/logs', ensureAuthedApi, async (req, res) => {
  try {
    const files = await fs.promises.readdir(logsDir);
    const stats = await Promise.all(
      files.map(async (filename) => {
        const stat = await fs.promises.stat(path.join(logsDir, filename));
        return { filename, sizeBytes: stat.size, modifiedAt: stat.mtimeMs };
      })
    );
    res.json({ files: stats.sort((a, b) => b.modifiedAt - a.modifiedAt) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logs/upload', ensureAuthedApi, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const safeBase = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9_.-]/g, '_');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${timestamp}-${safeBase || 'upload.log'}`;
    const dest = path.join(logsDir, filename);
    await fs.promises.writeFile(dest, req.file.buffer);
    res.json({ message: 'Uploaded', filename });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logs/ingest', ensureAuthedApi, async (req, res) => {
  try {
    const text = typeof req.body === 'string' ? req.body : req.body?.text;
    if (!text || text.length === 0) {
      return res.status(400).json({ error: 'Missing log text' });
    }
    const name = (req.body && req.body.filename) || 'ingest.log';
    const safeBase = path.basename(name).replace(/[^a-zA-Z0-9_.-]/g, '_');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${timestamp}-${safeBase}`;
    const dest = path.join(logsDir, filename);
    await fs.promises.writeFile(dest, text, { encoding: 'utf-8' });
    res.json({ message: 'Ingested', filename });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/analysis', ensureAuthedApi, async (req, res) => {
  try {
    const files = await fs.promises.readdir(logsDir);
    if (files.length === 0) {
      return res.json({ message: 'No logs available', metrics: null, recommendations: null });
    }
    const texts = await Promise.all(files.map(async (f) => fs.promises.readFile(path.join(logsDir, f), 'utf-8')));
    const combined = texts.join('\n');
    const result = analyzeLogsFromText(combined);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Utility: parse log lines into entries
function parseLogEntries(text) {
  const lines = text.split(/\r?\n/);
  const entries = [];
  const lineRegex = /(\d{4}-\d{2}-\d{2}T[^\s]+)\s+(INFO|WARN|ERROR)\s+\[.*?\]\s+(GET|POST|PUT|DELETE)?\s*([^\s]*)?.*?(\b(\d{1,4})ms\b|response_time=(\d+)ms)?\s*(.*)?/i;
  for (const line of lines) {
    const m = lineRegex.exec(line);
    if (m) {
      const ts = m[1] || null;
      const level = (m[2] || 'INFO').toUpperCase();
      const endpoint = m[4] || '';
      const rt = Number(m[6] || m[7] || 0);
      const message = (m[8] || '').trim();
      entries.push({ timestamp: ts, level, endpoint, response_time: rt, message });
    }
  }
  return entries;
}

// Logs entries API with filters & pagination
app.get('/api/logs/entries', ensureAuthedApi, async (req, res) => {
  try {
    const { level, endpoint, start, end, q, page = 1, pageSize = 50 } = req.query;
    const files = await fs.promises.readdir(logsDir);
    const texts = await Promise.all(files.map(async (f) => fs.promises.readFile(path.join(logsDir, f), 'utf-8')));
    let entries = parseLogEntries(texts.join('\n'));

    // Filters
    if (level) {
      const lv = String(level).toUpperCase();
      entries = entries.filter(e => e.level === lv);
    }
    if (endpoint) {
      entries = entries.filter(e => e.endpoint && e.endpoint.includes(String(endpoint)));
    }
    if (start) {
      const s = new Date(start).getTime();
      entries = entries.filter(e => e.timestamp && new Date(e.timestamp).getTime() >= s);
    }
    if (end) {
      const en = new Date(end).getTime();
      entries = entries.filter(e => e.timestamp && new Date(e.timestamp).getTime() <= en);
    }
    if (q) {
      const needle = String(q).toLowerCase();
      entries = entries.filter(e => (e.message||'').toLowerCase().includes(needle));
    }

    // Pagination
    const p = Number(page) || 1;
    const ps = Math.min(500, Number(pageSize) || 50);
    const total = entries.length;
    const startIdx = (p - 1) * ps;
    const slice = entries.slice(startIdx, startIdx + ps);
    res.json({ total, page: p, pageSize: ps, items: slice });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Export API
app.get('/api/logs/export', ensureAuthedApi, async (req, res) => {
  try {
    const { type = 'raw', format = 'csv' } = req.query;
    const files = await fs.promises.readdir(logsDir);
    const texts = await Promise.all(files.map(async (f) => fs.promises.readFile(path.join(logsDir, f), 'utf-8')));
    const combined = texts.join('\n');

    if (type === 'raw') {
      const entries = parseLogEntries(combined);
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        return res.send(JSON.stringify(entries));
      }
      const header = 'timestamp,level,endpoint,response_time,message\n';
      const rows = entries.map(e => `${e.timestamp||''},${e.level},${e.endpoint||''},${e.response_time||0},"${(e.message||'').replace(/"/g,'\"')}"`).join('\n');
      res.setHeader('Content-Type', 'text/csv');
      return res.send(header + rows + '\n');
    }

    if (type === 'analysis') {
      const result = analyzeLogsFromText(combined);
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        return res.send(JSON.stringify(result));
      }
      // CSV flatten
      const { metrics = {}, system = {}, nfr = [] } = result || {};
      const header = 'metric,value\n';
      const flat = [];
      flat.push(['requests', metrics.requests||0]);
      flat.push(['errors', metrics.errors||0]);
      flat.push(['errorRate', metrics.errorRate||0]);
      flat.push(['throughputRps', metrics.throughputRps||0]);
      if (metrics.latency) {
        Object.entries(metrics.latency).forEach(([k,v])=>flat.push([`latency_${k}`, v]));
      }
      if (system) {
        Object.entries(system).forEach(([k,v])=>flat.push([`system_${k}`, v??'']));
      }
      nfr.forEach((r,i)=>flat.push([`nfr_${i+1}`, `${r.category}: ${r.requirement} | ${r.current}`]));
      const rows = flat.map(([k,v])=>`${k},${v}`).join('\n');
      res.setHeader('Content-Type', 'text/csv');
      return res.send(header + rows + '\n');
    }

    if (type === 'nfr') {
      const { nfr = [] } = analyzeLogsFromText(combined) || {};
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        return res.send(JSON.stringify(nfr));
      }
      const header = 'category,requirement,current\n';
      const rows = nfr.map(r=>`${r.category},"${r.requirement.replace(/"/g,'\"')}","${r.current.replace(/"/g,'\"')}"`).join('\n');
      res.setHeader('Content-Type', 'text/csv');
      return res.send(header + rows + '\n');
    }

    return res.status(400).json({ error: 'Unsupported export type' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Enhanced log ingestion with advanced processing
app.post('/api/logs/ingest', ensureAuthedApi, async (req, res) => {
  try {
    const text = typeof req.body === 'string' ? req.body : req.body?.text;
    if (!text || text.length === 0) {
      return res.status(400).json({ error: 'Missing log text' });
    }
    
    // Use transport manager for advanced processing if available
    if (transportManager) {
      await transportManager.handleHTTPLog({
        message: text,
        timestamp: new Date().toISOString(),
        source: 'http_ingest'
      }, {
        userAgent: req.get('User-Agent'),
        ip: req.ip
      });
    }
    
    // Fallback to legacy processing
    const name = (req.body && req.body.filename) || 'ingest.log';
    const safeBase = path.basename(name).replace(/[^a-zA-Z0-9_.-]/g, '_');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${timestamp}-${safeBase}`;
    const dest = path.join(logsDir, filename);
    await fs.promises.writeFile(dest, text, { encoding: 'utf-8' });
    
    res.json({ message: 'Ingested', filename, advanced: !!transportManager });
    
  } catch (err) {
    logger.error('Log ingestion failed:', err);
    res.status(500).json({ error: err.message });
  }
});

// System statistics endpoint
app.get('/api/stats', ensureAuthedApi, (req, res) => {
  try {
    const stats = {
      server: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: '2.0.0'
      },
      modules: {}
    };
    
    if (otelCollector) stats.modules.otelCollector = otelCollector.getStats();
    if (transportManager) stats.modules.transportManager = transportManager.getStats();
    if (storageManager) stats.modules.storageManager = storageManager.getStats();
    if (queryEngine) stats.modules.queryEngine = queryEngine.getStats();
    if (anomalyDetector) stats.modules.anomalyDetector = anomalyDetector.getStats();
    if (serviceTopology) stats.modules.serviceTopology = serviceTopology.getStats();
    if (alertManager) stats.modules.alertManager = alertManager.getStats();
    
    res.json(stats);
    
  } catch (error) {
    logger.error('Failed to get stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// Graceful shutdown handler
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  
  try {
    if (otelCollector) await otelCollector.shutdown();
    if (transportManager) await transportManager.shutdown();
    if (storageManager) await storageManager.shutdown();
    
    server.close(() => {
      logger.info('Server closed');
      process.exit(0);
    });
  } catch (error) {
    logger.error('Error during shutdown:', error);
    process.exit(1);
  }
});

// Start server and initialize modules
async function startServer() {
  try {
    // Initialize advanced modules
    await initializeAdvancedModules();
    
    // Start server
    server.listen(port, () => {
      logger.info(`🚀 Advanced Production Log Analyzer started on http://localhost:${port}`);
      logger.info('Features enabled:');
      logger.info('  ✅ OpenTelemetry-first ingestion');
      logger.info('  ✅ Multi-transport support (HTTP, Syslog, Kafka, Redis)');
      logger.info('  ✅ Advanced parsing with PII detection');
      logger.info('  ✅ Hot/Warm/Cold storage tiers');
      logger.info('  ✅ Google-like search with DSL/SQL support');
      logger.info('  ✅ ML-powered anomaly detection');
      logger.info('  ✅ Service topology mapping');
      logger.info('  ✅ Advanced alerting with SLO monitoring');
      logger.info('  ✅ Real-time WebSocket streaming');
    });
    
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();


