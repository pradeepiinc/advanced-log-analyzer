import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import session from 'express-session';
import crypto from 'crypto';
import { analyzeLogsFromText } from './analyzer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

const dataDir = path.join(__dirname, '..', 'data');
const logsDir = path.join(dataDir, 'logs');

// Ensure directories exist
fs.mkdirSync(logsDir, { recursive: true });

app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.text({ type: ['text/*', 'application/log'], limit: '50mb' }));
app.use(morgan('dev'));

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

// Protect application pages
app.get(['/', '/index.html', '/logs.html', '/analysis.html', '/requirements.html'], ensureAuthedPage, (req, res) => {
  const file = req.path === '/' ? 'index.html' : req.path.replace('/', '');
  res.sendFile(path.join(__dirname, '..', 'public', file));
});

// Fallback static (assets/images etc.)
app.use(express.static(path.join(__dirname, '..', 'public')));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

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

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});


