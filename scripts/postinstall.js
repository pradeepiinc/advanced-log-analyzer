import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

try {
  const logsDir = path.join(__dirname, '..', 'data', 'logs');
  fs.mkdirSync(logsDir, { recursive: true });
  // eslint-disable-next-line no-console
  console.log('[postinstall] Ensured data/logs directory exists');
} catch (err) {
  // eslint-disable-next-line no-console
  console.warn('[postinstall] Failed to create data/logs:', err.message);
}


