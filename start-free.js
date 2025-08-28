#!/usr/bin/env node

/**
 * Free Tier Startup Script
 * Optimized for free hosting with minimal resource usage
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import { createLogger } from './src/core/utils/logger.js';
import { getConfigManager } from './src/core/config/config-manager.js';
import { getRBACManager } from './src/core/security/rbac-manager.js';
import { createServer } from 'http';
import { Server } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = createLogger('FreeTierApp');
const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Free tier optimizations
const PORT = process.env.PORT || 10000;
const isProduction = process.env.NODE_ENV === 'production';

// Basic middleware for free tier
app.use(helmet({
  contentSecurityPolicy: false // Simplified for free tier
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting for free tier
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Session management (in-memory for free tier)
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-for-free-tier',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage for free tier
const logs = [];
const alerts = [];
const users = new Map();

// Initialize RBAC
let rbac;
try {
  rbac = getRBACManager();
} catch (error) {
  logger.warn('RBAC initialization failed, using basic auth');
}

// Basic authentication middleware
const basicAuth = (req, res, next) => {
  if (req.session.authenticated) {
    return next();
  }
  
  const { username, password } = req.body;
  if (username === (process.env.ADMIN_USER || 'admin') && 
      password === (process.env.ADMIN_PASS || 'admin123')) {
    req.session.authenticated = true;
    req.session.username = username;
    return next();
  }
  
  res.status(401).json({ error: 'Authentication required' });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/advanced-search.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'advanced-search.html'));
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '2.0.0-free',
    tier: 'free',
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Authentication
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === (process.env.ADMIN_USER || 'admin') && 
      password === (process.env.ADMIN_PASS || 'admin123')) {
    req.session.authenticated = true;
    req.session.username = username;
    res.json({ 
      success: true, 
      user: { username, roles: ['admin'] },
      token: 'free-tier-session-token'
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Log ingestion (simplified for free tier)
app.post('/api/logs/ingest', (req, res) => {
  try {
    const logEntry = {
      id: Date.now().toString(),
      timestamp: req.body.timestamp || new Date().toISOString(),
      level: req.body.level || 'info',
      message: req.body.message || '',
      service: req.body.service || 'unknown',
      ...req.body
    };
    
    // Store in memory (limit to 1000 logs for free tier)
    logs.unshift(logEntry);
    if (logs.length > 1000) {
      logs.splice(1000);
    }
    
    // Emit to connected clients
    io.emit('log-stream', logEntry);
    
    // Simple anomaly detection
    if (logEntry.level === 'error') {
      const recentErrors = logs.filter(log => 
        log.level === 'error' && 
        new Date(log.timestamp) > new Date(Date.now() - 5 * 60 * 1000)
      ).length;
      
      if (recentErrors > 5) {
        const alert = {
          id: Date.now().toString(),
          title: 'High Error Rate',
          level: 'warning',
          count: recentErrors,
          timestamp: new Date().toISOString()
        };
        alerts.unshift(alert);
        io.emit('alert', alert);
      }
    }
    
    res.json({ success: true, id: logEntry.id });
  } catch (error) {
    logger.error('Log ingestion error:', error);
    res.status(500).json({ error: 'Ingestion failed' });
  }
});

// Search logs (simplified)
app.post('/api/search', (req, res) => {
  try {
    const { query, filters = {}, page = 1, pageSize = 50 } = req.body;
    
    let filteredLogs = logs;
    
    // Apply filters
    if (filters.level) {
      filteredLogs = filteredLogs.filter(log => log.level === filters.level);
    }
    
    if (filters.service) {
      filteredLogs = filteredLogs.filter(log => 
        log.service && log.service.includes(filters.service)
      );
    }
    
    if (query) {
      filteredLogs = filteredLogs.filter(log =>
        log.message && log.message.toLowerCase().includes(query.toLowerCase())
      );
    }
    
    // Time range filter
    if (filters.timeRange) {
      const now = new Date();
      let startTime;
      
      switch (filters.timeRange) {
        case '15m':
          startTime = new Date(now - 15 * 60 * 1000);
          break;
        case '1h':
          startTime = new Date(now - 60 * 60 * 1000);
          break;
        case '24h':
          startTime = new Date(now - 24 * 60 * 60 * 1000);
          break;
        default:
          startTime = new Date(now - 24 * 60 * 60 * 1000);
      }
      
      filteredLogs = filteredLogs.filter(log => 
        new Date(log.timestamp) >= startTime
      );
    }
    
    // Pagination
    const total = filteredLogs.length;
    const startIndex = (page - 1) * pageSize;
    const results = filteredLogs.slice(startIndex, startIndex + pageSize);
    
    // Simple facets
    const facets = {
      levels: {},
      services: {}
    };
    
    filteredLogs.forEach(log => {
      facets.levels[log.level] = (facets.levels[log.level] || 0) + 1;
      facets.services[log.service] = (facets.services[log.service] || 0) + 1;
    });
    
    res.json({
      results,
      total,
      facets,
      page,
      pageSize
    });
  } catch (error) {
    logger.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get alerts
app.get('/api/alerts', (req, res) => {
  res.json({
    alerts: alerts.slice(0, 100), // Limit for free tier
    total: alerts.length
  });
});

// System status
app.get('/api/status', (req, res) => {
  res.json({
    status: 'running',
    tier: 'free',
    logs: logs.length,
    alerts: alerts.length,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    features: {
      logIngestion: true,
      search: true,
      alerts: true,
      realTime: true,
      ml: false, // Disabled for free tier
      integrations: false // Disabled for free tier
    }
  });
});

// WebSocket connections
io.on('connection', (socket) => {
  logger.info('Client connected to WebSocket');
  
  socket.on('subscribe-logs', (filters) => {
    socket.join('logs');
    logger.info('Client subscribed to log stream');
  });
  
  socket.on('unsubscribe-logs', () => {
    socket.leave('logs');
    logger.info('Client unsubscribed from log stream');
  });
  
  socket.on('disconnect', () => {
    logger.info('Client disconnected from WebSocket');
  });
});

// Error handling
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  logger.info(`🎉 Advanced Production Log Analyzer (Free Tier) started!`);
  logger.info(`📊 Server: http://0.0.0.0:${PORT}`);
  logger.info(`🔍 Advanced Search: http://0.0.0.0:${PORT}/advanced-search.html`);
  logger.info(`💚 Health Check: http://0.0.0.0:${PORT}/api/health`);
  logger.info(`👤 Login: admin / ${process.env.ADMIN_PASS || 'admin123'}`);
  logger.info(`🆓 Tier: FREE (In-memory storage, 1000 log limit)`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

export default app;
